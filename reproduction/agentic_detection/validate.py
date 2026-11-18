"""Layered, bounded validation. Curator and scorer run outside detection workers."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import subprocess
import signal
import sys
import time
from pathlib import Path


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def command(args, log, *, env=None, timeout=900):
    with log.open("ab") as stream:
        process = subprocess.Popen(args, stdout=stream, stderr=subprocess.STDOUT, env=env,
                                   start_new_session=os.name == "posix")
        try:
            exit_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait()
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            raise
    if exit_code:
        raise RuntimeError(f"Command failed with exit {exit_code}. See {log.name}.")


def tree_hash(path):
    digest = hashlib.sha256()
    for source in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(source.relative_to(path).as_posix().encode() + b"\0")
        digest.update(source.read_bytes())
    return digest.hexdigest()


def http_fixtures(exp):
    source_text = """import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;

public class Endpoint implements HttpHandler {
  public static void main(String[] args) throws IOException {
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/", new Endpoint());
    server.start();
  }
  public void handle(HttpExchange exchange) throws IOException {
    String value = exchange.getRequestURI().getQuery();
    if (value == null) {
      value = "";
    }
    String output = OUTPUT_EXPRESSION;
    byte[] body = output.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
    exchange.sendResponseHeaders(200, body.length);
    try (OutputStream response = exchange.getResponseBody()) {
      response.write(body);
    }
  }
  private String encode(String value) {
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
  }
}
"""
    records = []
    for index, expression in enumerate(("value", "encode(value)")):
        key = f"http_fixture_{index + 1}"
        source = exp / "sources" / key
        source.mkdir(parents=True, exist_ok=True)
        endpoint = source / "Endpoint.java"
        content = source_text.replace("OUTPUT_EXPRESSION", expression)
        if endpoint.exists() and endpoint.read_text(encoding="utf-8") != content:
            raise ValueError("Synthetic source changed since preparation.")
        endpoint.write_text(content, encoding="utf-8")
        records.append({"key": key, "source": str(source), "tree_sha256": tree_hash(source),
                        "split": "synthetic", "expected": "vulnerable" if index == 0 else "safe"})
    return records


def prepare(base, exp):
    private = exp / "private"
    private.mkdir(exist_ok=True)
    selection = private / "selection.json"
    if selection.exists():
        manifest = json.loads(selection.read_text())
        if not any(row["key"] == "http_fixture_1" for row in manifest):
            # Preserve the interface-only diagnostic fixtures and original selection.
            (private / "selection-interface-fixtures.json").write_bytes(selection.read_bytes())
            for row in manifest:
                if row["split"] == "synthetic":
                    row["split"] = "diagnostic"
            manifest.extend(http_fixtures(exp))
            write(selection, manifest)
        return manifest
    # Selection uses project size and CWE metadata only. Detection receives neither.
    ids = (55, 66, 87, 114)
    with (base / "dataset/metadata/project_info.csv").open(encoding="utf-8-sig") as stream:
        projects = {int(row["id"]): row for row in csv.DictReader(stream)}
    manifest = []
    for index, sample in enumerate(ids):
        project = projects[sample]
        source = exp / "sources" / f"project_{index + 1}"
        source.mkdir(parents=True)
        upstream = base / "dataset/project-sources" / project["project_slug"]
        commit = subprocess.check_output(["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True).strip()
        if commit != project["buggy_commit_id"]:
            raise ValueError("Prepared source commit differs from the dataset receipt.")
        archive = private / f"project_{index + 1}.tar"
        command(["git", "-C", str(upstream), "archive", "--format=tar", "-o", str(archive), commit],
                private / "prepare.log")
        command(["tar", "-xf", str(archive), "-C", str(source)], private / "prepare.log")
        manifest.append({"key": f"project_{index + 1}", "sample": sample, "project": project,
                         "source": str(source), "tree_sha256": tree_hash(source), "split": "held_out"})
    manifest.extend(http_fixtures(exp))
    write(selection, manifest)
    return manifest


def prepare_path_cohort(base, exp, previous):
    selection = exp / "private/selection.json"
    if selection.exists():
        raise ValueError("The validation cohort is already fixed.")
    old = json.loads((previous / "private/selection.json").read_text())
    indexed = {item["key"]: item for item in old}
    manifest = [{**indexed[key], "reuse_static": str(previous / "static" / key)}
                for key in ("http_fixture_1", "http_fixture_2", "project_1")]
    # Select a fresh cached revision by tracked Java file count before any model run.
    excluded = {1, 32, 78, *(item["sample"] for item in old if "sample" in item)}
    choices = []
    with (base / "dataset/metadata/project_info.csv").open(encoding="utf-8-sig") as stream:
        for project in csv.DictReader(stream):
            sample = int(project["id"])
            upstream = base / "dataset/project-sources" / project["project_slug"]
            if sample in excluded or not (upstream / ".git").exists():
                continue
            if int(project["cwe_id"].split("-")[-1]) not in {78, 94}:
                continue
            commit = project["buggy_commit_id"]
            listed = subprocess.run(["git", "-C", str(upstream), "ls-tree", "-r", "--name-only", commit],
                                    capture_output=True, text=True, timeout=30)
            if listed.returncode == 0:
                size = sum(path.endswith(".java") for path in listed.stdout.splitlines())
                if size:
                    choices.append((size, sample, project, upstream))
    if not choices:
        raise ValueError("No fresh cached Java revision satisfies the holdout selection.")
    size, sample, project, upstream = min(choices, key=lambda row: row[:2])
    source = exp / "sources/project_fresh"
    source.mkdir(parents=True)
    private = selection.parent
    private.mkdir(exist_ok=True)
    archive = private / "project_fresh.tar"
    command(["git", "-C", str(upstream), "archive", "--format=tar", "-o", str(archive),
             project["buggy_commit_id"]], private / "prepare.log")
    command(["tar", "-xf", str(archive), "-C", str(source)], private / "prepare.log")
    manifest.append({"key": "project_fresh", "split": "held_out", "sample": sample, "project": project,
                     "source": str(source), "tree_sha256": tree_hash(source), "java_file_count": size})
    write(selection, manifest)
    print(json.dumps({"prepared": [item["key"] for item in manifest], "fresh_java_files": size}), flush=True)


class StaticDatabaseError(ValueError):
    pass


def check_database(database, source):
    descriptor = database / "codeql-database.yml"
    data = {}
    if descriptor.is_file():
        for line in descriptor.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition(":")
            if sep and key in {"primaryLanguage", "finalised", "sourceLocationPrefix"}:
                data[key] = value.strip().strip("'\"")
    if (data.get("primaryLanguage") != "java" or data.get("finalised") != "true"
            or not (database / "db-java/semmlecode.dbscheme").is_file()
            or not (database / "db-java/default").is_dir()
            or not (database / "src.zip").is_file()):
        raise StaticDatabaseError("CodeQL Java database is missing or unfinalized.")
    if Path(data.get("sourceLocationPrefix", "")).resolve() != source.resolve():
        raise StaticDatabaseError("CodeQL database belongs to another source root.")


def static_analysis(item, exp, codeql):
    directory = exp / "static" / item["key"]
    directory.mkdir(parents=True, exist_ok=True)
    receipt = directory / "receipt.json"
    source = Path(item["source"])
    if tree_hash(source) != item["tree_sha256"]:
        raise ValueError("Source tree changed before static analysis.")
    if item.get("reuse_static"):
        cached = Path(item["reuse_static"])
        data = json.loads((cached / "receipt.json").read_text())
        database, graph = cached / "database", cached / "graph.csv"
        check_database(database, source)
        query = exp / "code/codeql/work1_agent/RepositorySiteGraph.ql"
        if (data["source_tree_sha256"] != item["tree_sha256"]
                or hashlib.sha256(graph.read_bytes()).hexdigest() != data["graph_sha256"]
                or hashlib.sha256(query.read_bytes()).hexdigest() != data["query_sha256"]):
            raise ValueError("Cached static graph has a different source or query binding.")
        return {**data, "graph": str(graph), "database": str(database)}
    if receipt.exists():
        data = json.loads(receipt.read_text())
        graph = directory / "graph.csv"
        query = exp / "code/codeql/work1_agent/RepositorySiteGraph.ql"
        if (data["source_tree_sha256"] != item["tree_sha256"]
                or Path(data["graph"]).resolve() != graph.resolve()
                or hashlib.sha256(graph.read_bytes()).hexdigest() != data["graph_sha256"]
                or hashlib.sha256(query.read_bytes()).hexdigest() != data["query_sha256"]):
            raise ValueError("Static receipt no longer matches its source, graph or query.")
        check_database(Path(data["database"]), source)
        return data
    database = directory / "database"
    if not database.exists():
        command([str(codeql), "database", "create", str(database), "--language=java",
                 "--build-mode=none", "--threads=2", "--ram=4096", f"--source-root={source}"],
                directory / "database.log", timeout=1200)
    check_database(database, source)
    bqrs = directory / "graph.bqrs"
    query = exp / "code/codeql/work1_agent/RepositorySiteGraph.ql"
    graph = directory / "graph.csv"
    command([str(codeql), "query", "run", str(query), f"--database={database}", f"--output={bqrs}",
             "--threads=2", "--ram=4096"], directory / "query.log", timeout=900)
    command([str(codeql), "bqrs", "decode", str(bqrs), "--format=csv", f"--output={graph}"],
            directory / "query.log")
    data = {"source_tree_sha256": item["tree_sha256"], "graph": str(graph),
            "graph_sha256": hashlib.sha256(graph.read_bytes()).hexdigest(),
            "query_sha256": hashlib.sha256(query.read_bytes()).hexdigest(),
            "database": str(database), "build_mode": "none",
            "native_alerts": None, "note": "Navigation export. Native vulnerability queries were not run."}
    write(receipt, data)
    return data


def value_analysis(item, static, exp, codeql):
    directory = exp / "static" / item["key"]
    query = exp / "code/codeql/work1_agent/ValueBridges.ql"
    output = directory / "value-bridges.csv"
    receipt = directory / "value-receipt.json"
    binding = {"source_tree_sha256": item["tree_sha256"], "graph_sha256": static["graph_sha256"],
               "query_sha256": hashlib.sha256(query.read_bytes()).hexdigest()}
    if receipt.exists():
        data = json.loads(receipt.read_text())
        if (any(data[key] != value for key, value in binding.items())
                or data["sha256"] != hashlib.sha256(output.read_bytes()).hexdigest()):
            raise ValueError("Value graph does not match its receipt.")
        return data
    bqrs = directory / "value-bridges.bqrs"
    command([str(codeql), "query", "run", str(query), f"--database={static['database']}",
             f"--output={bqrs}", "--threads=2", "--ram=2200"], directory / "value-query.log", timeout=480)
    command([str(codeql), "bqrs", "decode", str(bqrs), "--format=csv", f"--output={output}"],
            directory / "value-query.log")
    data = {**binding, "path": str(output), "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}
    write(receipt, data)
    return data


def native_analysis(item, static, exp, codeql):
    """Run the same installed CWE query set for every source snapshot."""
    config_path = exp / 'detector-config.json'
    config = json.loads(config_path.read_text()) if config_path.exists() else {}
    if config.get('native_discovery'):
        data = json.loads((exp / 'native-inputs' / item['key'] / 'native-receipt.json').read_text())
        if data.get('status') != 'complete' or data.get('source_tree_sha256') != item['tree_sha256']:
            raise ValueError('R13 native analysis was not successfully executed for this source.')
        for path_key, hash_key in [('report', 'report_sha256'), ('sarif', 'sarif_sha256')]:
            if hashlib.sha256(Path(data[path_key]).read_bytes()).hexdigest() != data[hash_key]:
                raise ValueError('R13 native artifact binding mismatch.')
        for query in data['queries']:
            if hashlib.sha256(Path(query['path']).read_bytes()).hexdigest() != query['sha256']:
                raise ValueError('R13 native query changed.')
        return data
    directory = exp / "static" / item["key"]
    receipt = (Path(item["reuse_static"]) if item.get("reuse_static") else directory) / "native-receipt.json"
    if receipt.exists():
        data = json.loads(receipt.read_text())
        if data["status"] == "complete":
            report = Path(data["report"])
            if (data.get("source_tree_sha256") != item["tree_sha256"]
                    or hashlib.sha256(report.read_bytes()).hexdigest() != data["report_sha256"]):
                raise ValueError("Native report changed after preparation.")
        return data
    started = time.time()
    try:
        packs = json.loads(subprocess.check_output(
            [str(codeql), "resolve", "qlpacks", "--format=json"], text=True, timeout=60))
        package = Path(packs["codeql/java-queries"][0])
        categories = {"CWE-022", "CWE-078", "CWE-079", "CWE-094"}
        queries = sorted(path for path in package.rglob("*.ql") if categories.intersection(path.parts))
        if not queries:
            raise ValueError("No installed native queries for the declared CWE scope.")
        raw = directory / "native.sarif"
        command([str(codeql), "database", "analyze", static["database"],
                 *map(str, queries), "--format=sarif-latest", f"--output={raw}",
                 "--threads=2", "--ram=4096"], directory / "native.log", timeout=1200)
        from vecho_experiment.inputs import sarif
        findings = sarif(json.loads(raw.read_text()), "CodeQL", item["source"])
        report = directory / "native.canonical.json"
        write(report, {"vulnerabilities": findings})
        data = {"status": "complete", "alerts": len(findings), "report": str(report),
                "report_sha256": hashlib.sha256(report.read_bytes()).hexdigest(),
                "sarif_sha256": hashlib.sha256(raw.read_bytes()).hexdigest(),
                "source_tree_sha256": item["tree_sha256"], "query_pack": str(package),
                "queries": [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                            for path in queries]}
    except (OSError, ValueError, KeyError, TypeError, ImportError, RuntimeError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        data = {"status": "failed", "error": str(error), "error_type": type(error).__name__}
    data["elapsed_seconds"] = round(time.time() - started, 3)
    write(directory / "native-receipt.json", data)
    return data


def detect(item, base, exp, codeql, *, retry_failed=False):
    from java_vuln_research.work1_agent.experiment_policy import exclusive_run
    job = exp / "runs" / item["key"]
    job.mkdir(parents=True, exist_ok=True)
    try:
        with exclusive_run(job / "supervisor.lock"):
            return detect_locked(item, base, exp, codeql, retry_failed=retry_failed)
    except BlockingIOError:
        return {"key": item["key"], "status": "already_running"}


def detect_locked(item, base, exp, codeql, *, retry_failed=False):
    job = exp / "runs" / item["key"]
    job.mkdir(parents=True, exist_ok=True)
    outcome = job / "outcome.json"
    if outcome.exists():
        previous = json.loads(outcome.read_text())
        if previous["status"] == "complete" or not retry_failed:
            return previous
        number = len(list(job.glob("outcome-attempt-*.json"))) + 1
        outcome.replace(job / f"outcome-attempt-{number:04d}.json")
    started = time.time()
    phase = "STATIC_PREPARATION"
    try:
        config_path = exp / "detector-config.json"
        config = json.loads(config_path.read_text()) if config_path.exists() else {}
        if config not in ({}, {"general_evp": True}, {"benchmark_first": True}, {"benchmark_first": True, "native_discovery": True},
                           {'benchmark_first':True,'fasttrack':'A1'}, {'benchmark_first':True,'fasttrack':'A2'}):
            raise ValueError("Unsupported detector config; choose general_evp:true or benchmark_first:true.")
        benchmark_first = config.get("benchmark_first", False)
        static = static_analysis(item, exp, codeql)
        native = native_analysis(item, static, exp, codeql)
        if config.get('native_discovery'):
            static = {**static, 'native_alerts': native['alerts'], 'note': 'Native security queries executed on an independent copy of the same database.'}
        values = ({"status": "not_required_benchmark_navigation"} if benchmark_first
                  else value_analysis(item, static, exp, codeql))
        phase = "DETECTION"
        source = Path(item["source"])
        if tree_hash(source) != item["tree_sha256"]:
            raise ValueError("Source tree changed before detection.")
        env = os.environ.copy()
        from dotenv import dotenv_values
        key = env.get("OPENLUX_API_KEY") or dotenv_values(base / "vEcho/.env").get("OPENLUX_API_KEY")
        if not key:
            raise ValueError("OpenLux credential unavailable.")
        env["OPENLUX_API_KEY"] = key
        output = job / f"attempt-{len(list(job.glob('attempt-*'))) + 1:04d}"
        args = [sys.executable, "-B", "-m", "java_vuln_research.work1_agent.run_dag",
                "--repository", str(source), "--output", str(output), "--static-graph", static["graph"],
                "--endpoint", "https://api.openlux.ai/v1/chat/completions", "--model", "gpt-6.1-sol",
                "--request-journal", str(job / "request-journal.jsonl"), "--max-physical-requests", "16",
                "--max-tokens", "150000", "--max-seconds", "1200", "--max-model-calls", "24",
                "--max-tool-calls", "64", "--max-output-tokens", "1536", "--rounds", "4"]
        if not benchmark_first:
            args += ["--static-value-bridges", values["path"]]
        if config.get("general_evp"):
            args += ["--general-evp"]
            args[args.index("--rounds") + 1] = "6"
            args[args.index("--max-output-tokens") + 1] = "4096"
        if benchmark_first:
            args += ["--benchmark-first"]
            if config.get('fasttrack'):
                args += ['--fasttrack',config['fasttrack'],'--r12-implementation',str(exp/'code/frozen-r12-benchmark.py'),
                         '--exact-prefix-journal',str(exp.parent/'baseline-journals'/item['key']/'request-journal.jsonl')]
            for flag, value in (("--max-physical-requests", "28"), ("--max-tokens", "300000"),
                                ("--max-tool-calls", "128"), ("--max-model-calls", "28"),
                                ("--max-output-tokens", "4096")):
                args[args.index(flag) + 1] = value
        if native["status"] == "complete":
            args += ["--static-report", native["report"]]
        command(args, job / "detector.log", env=env, timeout=1320)
        run = json.loads((output / "run.json").read_text())
        if tree_hash(source) != item["tree_sha256"]:
            raise ValueError("Source tree changed during detection.")
        frozen = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in output.iterdir() if p.is_file()}
        write(job / "frozen.json", {"output": str(output), "sha256": frozen,
                                   "source_tree_sha256": item["tree_sha256"]})
        result = {"status": "complete", "output": str(output), "summary": run, "static": static, "values": values,
                  "native": native}
    except (OSError, ValueError, KeyError, TypeError, ImportError, RuntimeError,
            subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        result = {"status": "failed", "error": str(error), "error_type": type(error).__name__,
                  "failure_class": "CODEQL_DATABASE_INCOMPLETE" if isinstance(error, StaticDatabaseError) else phase}
        attempts = sorted(job.glob("attempt-*"))
        if attempts and (attempts[-1] / "run.json").exists():
            result["summary"] = json.loads((attempts[-1] / "run.json").read_text())
            result["output"] = str(attempts[-1])
        journal_path = job / "request-journal.jsonl"
        if journal_path.exists():
            records = [json.loads(line) for line in journal_path.read_text().splitlines() if line]
            result["physical_requests"] = sum(row["event"] == "request_started" for row in records)
            result["reported_tokens"] = sum(row["charged_tokens"] for row in records if row["event"] == "response")
    result.update({"key": item["key"], "elapsed_seconds": round(time.time() - started, 3)})
    write(outcome, result)
    return result


def read_jsonl(path):
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def frozen_output(item, job):
    frozen = json.loads((job / "frozen.json").read_text(encoding="utf-8"))
    output = Path(frozen["output"])
    if (any(hashlib.sha256((output / name).read_bytes()).hexdigest() != digest
            for name, digest in frozen["sha256"].items())
            or tree_hash(Path(item["source"])) != frozen["source_tree_sha256"]
            or frozen["source_tree_sha256"] != item["tree_sha256"]):
        raise ValueError("Frozen output or source changed before offline scoring.")
    return output, frozen["sha256"]


def diagnose_hops(base, exp, output_dir, samples, chains_file=None, freeze_manifest=None):
    from java_vuln_research.evaluation.hop_diagnostics import HopDiagnostics
    from vecho_experiment.evaluation import labels

    output_dir = output_dir.resolve()
    if output_dir == exp.resolve() or output_dir.is_relative_to((exp / "runs").resolve()):
        raise ValueError("Use a separate output directory for the offline diagnosis.")
    if freeze_manifest is not None:
        for line in freeze_manifest.read_text(encoding="utf-8").splitlines():
            digest, name = line.split(maxsplit=1)
            path = (exp / name).resolve()
            if not path.is_relative_to(exp.resolve()) or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
                raise ValueError(f"Experiment freeze manifest mismatch: {name}")

    selection = json.loads((exp / "private/selection.json").read_text(encoding="utf-8"))
    selected = {}
    for sample in samples:
        matches = [item for item in selection
                   if sample == item["key"] or ("sample" in item and sample == f"sample_{item['sample']:04d}")]
        if len(matches) != 1 or "project" not in matches[0]:
            raise ValueError(f"Expected a unique annotated case for {sample}.")
        selected[matches[0]["key"]] = matches[0]

    rows = json.loads((exp / "validation-results.json").read_text(encoding="utf-8"))
    scores = {row["key"]: row for row in rows}
    annotations = None
    diagnostics = []
    for key, item in selected.items():
        job = exp / "runs" / key
        outcome = json.loads((job / "outcome.json").read_text(encoding="utf-8"))
        if key not in scores or scores[key]["status"] != outcome["status"]:
            raise ValueError(f"No matching offline score for {key}.")
        sample = f"sample_{item['sample']:04d}" if "sample" in item else key
        if outcome["status"] != "complete":
            detail = {field: None for field in ("source_recalled", "sink_recalled",
                                                "bridge_proposed_count", "max_connected_hops")}
            detail["annotation_status"] = "DETECTION_UNAVAILABLE"
        else:
            output, digests = frozen_output(item, job)
            required = {"run.json", "trace.jsonl", "candidates.jsonl", "reviews.jsonl"}
            if (output.resolve() != Path(outcome["output"]).resolve() or not required <= digests.keys()
                    or json.loads((output / "run.json").read_text(encoding="utf-8")) != outcome["summary"]):
                raise ValueError(f"Outcome and frozen detector output disagree for {key}.")
            graph, values = outcome["static"], outcome["values"]
            if (graph["source_tree_sha256"] != item["tree_sha256"]
                    or values["source_tree_sha256"] != item["tree_sha256"]
                    or values["graph_sha256"] != graph["graph_sha256"]
                    or hashlib.sha256(Path(graph["graph"]).read_bytes()).hexdigest() != graph["graph_sha256"]
                    or hashlib.sha256(Path(values["path"]).read_bytes()).hexdigest() != values["sha256"]):
                raise ValueError(f"Static export receipt mismatch for {key}.")
            cwe = f"CWE-{int(item['project']['cwe_id'].split('-')[-1])}"
            if chains_file is not None:
                if annotations is None:
                    annotations = json.loads(chains_file.read_text(encoding="utf-8"))
                chains = annotations.get(sample, annotations.get(key, []))
            else:
                chains = []
            fixes, _ = labels(base / "dataset", item["project"])
            analyzer = HopDiagnostics(Path(item["source"]), outcome, read_jsonl(output / "trace.jsonl"),
                                      read_jsonl(output / "candidates.jsonl"), read_jsonl(output / "reviews.jsonl"), cwe)
            detail = analyzer.diagnose(fixes, chains)
        diagnostics.append({"key": key, "sample": sample, **detail})
        scores[key].update({field: detail[field] for field in (
            "source_recalled", "sink_recalled", "bridge_proposed_count", "max_connected_hops", "annotation_status")})
    write(output_dir / "hop-diagnostics.json", diagnostics)
    write(output_dir / "validation-results.json", rows)
    return diagnostics


def score(manifest, exp, base):
    config_path = exp / "detector-config.json"
    if config_path.exists() and json.loads(config_path.read_text()).get("benchmark_first"):
        from agentic_detection.benchmark_track import audit
        report = audit(base, exp)
        write(exp / "benchmark-results.json", report)
        write(exp / "validation-results.json", report["cases"])
        print(json.dumps(report, indent=2))
        return
    from vecho_experiment.evaluation import evaluate, labels
    rows = []
    for item in manifest:
        job = exp / "runs" / item["key"]
        if not (job / "outcome.json").exists():
            continue
        outcome = json.loads((job / "outcome.json").read_text())
        row = {"key": item["key"], "split": item["split"], "status": outcome["status"],
               "elapsed_seconds": outcome["elapsed_seconds"]}
        journal_path = job / "request-journal.jsonl"
        ledger = ([json.loads(line) for line in journal_path.read_text().splitlines() if line]
                  if journal_path.exists() else [])
        settled = [entry for entry in ledger if entry["event"] == "response"]
        row["physical_requests"] = sum(entry["event"] == "request_started" for entry in ledger)
        row["tokens"] = sum(entry["charged_tokens"] for entry in settled)
        row["unsettled_requests"] = row["physical_requests"] - len(settled)
        row["estimated_usd_reference_rates"] = round(sum(
            entry["usage"].get("prompt_tokens", 0) * 0.000002
            + entry["usage"].get("completion_tokens", 0) * 0.000010 for entry in settled), 8)
        if item["split"] == "held_out":
            row.update({"sample": item["sample"], "cwe": item["project"]["cwe_id"]})
        if outcome["status"] != "complete":
            row["error"] = outcome["error"]
            row["stop_reason"] = outcome.get("summary", {}).get("stop_reason")
            row["failure_class"] = outcome.get("failure_class", "DETECTION")
            rows.append(row)
            continue
        output, _ = frozen_output(item, job)
        candidates = read_jsonl(output / "candidates.jsonl")
        supported = {(r["cwe"], r["candidate_path_id"]) for r in read_jsonl(output / "reviews.jsonl")
                     if r["verdict"] == "SUPPORTED"}
        verified = [c for c in candidates if (c["cwe"], c["candidate_path_id"]) in supported]
        row.update({"candidates": len(candidates), "verified": len(verified),
                    "protocol_failures": outcome["summary"]["protocol_failures"],
                    "protection_rejected": outcome["summary"].get("protection_rejected", 0),
                    "branch_outcomes": outcome["summary"].get("branch_outcomes", {})})
        if item["split"] == "synthetic":
            row["expected"] = item["expected"]
            row["passed"] = (any(c["cwe"] == "CWE-79" for c in verified) if item["expected"] == "vulnerable"
                             else not verified and row["protection_rejected"] > 0
                             and row["branch_outcomes"].get("CWE-79") == "PROTECTION_ESTABLISHED")
        else:
            fixes, selection = labels(base / "dataset", item["project"])
            expected = int(item["project"]["cwe_id"].split("-")[1])
            predictions = []
            for candidate in verified:
                if int(candidate["cwe"].split("-")[1]) != expected:
                    continue
                nodes = [{"file_path": n["repository_relative_path"], "line_number": n["start_line"]}
                         for n in candidate["ordered_nodes"] if n.get("repository_relative_path") and n.get("start_line")]
                predictions.append({"fingerprint": candidate["candidate_path_id"], "tainted_data_flow": [nodes]})
            metric = evaluate(Path(item["source"]), predictions, fixes)
            row["metric"] = metric
            row["classification"] = ("DETECTED" if metric.get("recall") else
                                     "VERIFIED_PATH_LABEL_MISS" if predictions else
                                     "NO_VERIFIED_CANDIDATE")
            row["other_cwe_verified"] = len(verified) - len(predictions)
            precision, recall = metric.get("precision"), metric.get("recall")
            row["f2"] = (None if precision is None or recall is None else
                         5 * precision * recall / (4 * precision + recall) if 4 * precision + recall else 0)
        rows.append(row)
    write(exp / "validation-results.json", rows)
    print(json.dumps(rows, indent=2))


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["diagnose-hops"]:
        parser = argparse.ArgumentParser(prog="validate.py diagnose-hops", description=(
            "Attribute hops after detection and scoring, with read-only access to the original experiment."))
        parser.add_argument("--base", type=Path, required=True, help="Root containing the private dataset")
        parser.add_argument("--experiment", type=Path, required=True, help="Frozen and scored experiment")
        parser.add_argument("--output-dir", type=Path, required=True, help="Separate offline results directory")
        parser.add_argument("--sample", action="append", required=True, help="Case key or sample_NNNN (repeatable)")
        parser.add_argument("--chains", type=Path, help="Private JSON keyed by sample or case key")
        parser.add_argument("--freeze-manifest", type=Path, help="Experiment SHA-256 manifest, if available")
        args = parser.parse_args(argv[1:])
        try:
            results = diagnose_hops(args.base, args.experiment, args.output_dir, args.sample,
                                    args.chains, args.freeze_manifest)
        except (OSError, ValueError, KeyError, TypeError) as error:
            parser.error(str(error))
        print(json.dumps({"cases": [row["key"] for row in results], "output": str(args.output_dir.resolve())}))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--experiment", type=Path, required=True)
    parser.add_argument("--codeql", type=Path, required=True)
    parser.add_argument("--stage", choices=("prepare", "path-cohort", "native", "synthetic", "held-out",
                                            "static-case", "case", "score"), required=True)
    parser.add_argument("--case", help="Opaque case key for a single run")
    parser.add_argument("--reuse-from", type=Path, help="Previous audit for the bounded path validation cohort")
    parser.add_argument("--retry-failed", action="store_true")
    args = parser.parse_args(argv)
    args.experiment.mkdir(parents=True, exist_ok=True)
    if args.stage == "path-cohort":
        if args.reuse_from is None:
            parser.error("--stage path-cohort requires --reuse-from")
        prepare_path_cohort(args.base.resolve(), args.experiment.resolve(), args.reuse_from.resolve())
        return
    manifest = prepare(args.base, args.experiment)
    if args.stage in {"case", "static-case"}:
        selected = [item for item in manifest if item["key"] == args.case]
        if len(selected) != 1:
            parser.error("--stage case requires one known --case key")
        item = selected[0]
        if args.stage == "static-case":
            static = static_analysis(item, args.experiment, args.codeql)
            print(json.dumps(value_analysis(item, static, args.experiment, args.codeql)), flush=True)
        else:
            result = detect(item, args.base, args.experiment, args.codeql, retry_failed=args.retry_failed)
            print(json.dumps({"key": item["key"], "status": result["status"],
                              "error": result.get("error"), "elapsed_seconds": result.get("elapsed_seconds"),
                              "stop_reason": result.get("summary", {}).get("stop_reason"),
                              "candidate_paths": result.get("summary", {}).get("candidate_paths"),
                              "verified": result.get("summary", {}).get("verifier_supported")}), flush=True)
    elif args.stage in {"synthetic", "held-out"}:
        split = "synthetic" if args.stage == "synthetic" else "held_out"
        for item in manifest:
            if item["split"] == split:
                print(json.dumps(detect(item, args.base, args.experiment, args.codeql,
                                        retry_failed=args.retry_failed)), flush=True)
    elif args.stage == "native":
        results = []
        for item in manifest:
            if item["split"] == "diagnostic":
                continue
            try:
                static = static_analysis(item, args.experiment, args.codeql)
                result = native_analysis(item, static, args.experiment, args.codeql)
            except (OSError, ValueError, KeyError, TypeError, ImportError, RuntimeError,
                    subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
                result = {"status": "failed", "error": str(error)}
            results.append({"key": item["key"], **result})
            write(args.experiment / "native-preparation.json", results)
            print(json.dumps({"key": item["key"], "status": result["status"],
                              "alerts": result.get("alerts")}), flush=True)
    elif args.stage == "score":
        score(manifest, args.experiment, args.base)


if __name__ == "__main__":
    main()
