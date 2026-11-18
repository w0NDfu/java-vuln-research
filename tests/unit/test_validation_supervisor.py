import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import time
import shutil
import hashlib
import json

import pytest


@pytest.fixture
def supervisor():
    path = Path(__file__).resolve().parents[2] / "reproduction/agentic_detection/validate.py"
    if not path.exists():
        pytest.skip("Validation supervisor is not included in this source-only deployment.")
    spec = importlib.util.spec_from_file_location("validation_supervisor", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(os.name != "posix", reason="The experiment server uses POSIX process groups.")
def test_timeout_terminates_descendants_even_when_parent_exits_first(tmp_path, supervisor):
    child = "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(60)"
    parent = (
        "import subprocess,sys,time; "
        f"child=subprocess.Popen([sys.executable,'-c',{child!r}]); "
        "print(child.pid,flush=True); time.sleep(60)"
    )
    log = tmp_path / "process.log"
    with pytest.raises(subprocess.TimeoutExpired):
        supervisor.command([sys.executable, "-c", parent], log, timeout=0.5)
    pid = int(log.read_text().strip())
    state = Path(f"/proc/{pid}/stat")
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        try:
            if state.read_text().split()[2] == "Z":
                return
        except FileNotFoundError:
            return
        time.sleep(0.01)
    pytest.fail("Timed-out descendant is still running.")


def test_synthetic_sources_have_real_http_entry_and_are_immutable(tmp_path, supervisor):
    rows = supervisor.http_fixtures(tmp_path)
    assert len(rows) == 2
    for row in rows:
        source = Path(row["source"]) / "Endpoint.java"
        content = source.read_text()
        assert "implements HttpHandler" in content
        assert "server.createContext" in content
        assert "getRequestURI().getQuery()" in content
        if shutil.which("javac"):
            classes = tmp_path / "classes" / row["key"]
            classes.mkdir(parents=True)
            subprocess.run(["javac", "-d", str(classes), str(source)], check=True, timeout=30,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert supervisor.http_fixtures(tmp_path) == rows
    source = Path(rows[0]["source"]) / "Endpoint.java"
    source.write_text("changed source")
    with pytest.raises(ValueError, match="source changed"):
        supervisor.http_fixtures(tmp_path)


@pytest.mark.parametrize("mutation", ["source", "graph", "query"])
def test_static_reuse_rejects_changed_provenance(tmp_path, supervisor, mutation):
    source = tmp_path / "source"
    source.mkdir()
    java = source / "Example.java"
    java.write_text("class Example {}\n")
    directory = tmp_path / "static/project"
    directory.mkdir(parents=True)
    graph = directory / "graph.csv"
    graph.write_text("kind,from_file,from_line,from_column,to_file,to_line,to_column\n")
    query = tmp_path / "code/codeql/work1_agent/RepositorySiteGraph.ql"
    query.parent.mkdir(parents=True)
    query.write_text("query contents")
    item = {"key": "project", "source": str(source), "tree_sha256": supervisor.tree_hash(source)}
    database = directory / "database"
    (database / "db-java/default").mkdir(parents=True)
    (database / "db-java/semmlecode.dbscheme").touch()
    (database / "src.zip").touch()
    (database / "codeql-database.yml").write_text(
        f"primaryLanguage: java\nfinalised: true\nsourceLocationPrefix: {source}\n")
    receipt = {"source_tree_sha256": item["tree_sha256"], "graph": str(graph),
               "database": str(database),
               "graph_sha256": hashlib.sha256(graph.read_bytes()).hexdigest(),
               "query_sha256": hashlib.sha256(query.read_bytes()).hexdigest()}
    supervisor.write(directory / "receipt.json", receipt)
    saved = (directory / "receipt.json").read_bytes()
    assert supervisor.static_analysis(item, tmp_path, Path("unused-codeql")) == receipt
    {"source": java, "graph": graph, "query": query}[mutation].write_text("changed")
    with pytest.raises(ValueError):
        supervisor.static_analysis(item, tmp_path, Path("unused-codeql"))
    assert (directory / "receipt.json").read_bytes() == saved


def test_incomplete_database_is_classified_before_query(tmp_path, supervisor):
    source = tmp_path / "source"
    source.mkdir()
    database = tmp_path / "static/project/database"
    database.mkdir(parents=True)
    (database / "codeql-database.yml").write_text("primaryLanguage: java\nfinalised: false\n")
    item = {"key": "project", "source": str(source), "tree_sha256": supervisor.tree_hash(source)}
    result = supervisor.detect_locked(item, tmp_path, tmp_path, Path("must-not-run"))
    assert result["failure_class"] == "CODEQL_DATABASE_INCOMPLETE"
    assert not (tmp_path / "runs/project/request-journal.jsonl").exists()

@pytest.fixture
def native_setup(tmp_path, supervisor, monkeypatch):
    pytest.importorskip("vecho_experiment.inputs")
    package = tmp_path / "java-queries"
    for category in ("CWE-022", "CWE-078", "CWE-079", "CWE-094"):
        query = package / "Security/CWE" / category / "Query.ql"
        query.parent.mkdir(parents=True)
        query.write_text("query contents")
    monkeypatch.setattr(supervisor.subprocess, "check_output",
                        lambda *args, **kwargs: json.dumps({"codeql/java-queries": [str(package)]}))
    item = {"key": "project", "source": str(tmp_path / "source"), "tree_sha256": "source-hash"}
    directory = tmp_path / "static/project"
    directory.mkdir(parents=True)
    calls = []

    def execute(args, log, **kwargs):
        calls.append(args)
        raw = Path(next(arg.split("=", 1)[1] for arg in args if arg.startswith("--output=")))
        raw.write_text(json.dumps({"version": "2.1.0", "runs": []}))

    monkeypatch.setattr(supervisor, "command", execute)
    return item, directory, calls


def test_native_scope_and_empty_success_are_explicit(tmp_path, supervisor, native_setup):
    item, directory, calls = native_setup
    data = supervisor.native_analysis(item, {"database": "database"}, tmp_path, Path("codeql"))
    assert data["status"] == "complete"
    assert data["alerts"] == 0
    assert len(data["queries"]) == 4
    assert supervisor.native_analysis(item, {"database": "database"}, tmp_path, Path("codeql")) == data
    assert len(calls) == 1


def test_failed_native_producer_cannot_be_empty_success(tmp_path, supervisor, native_setup, monkeypatch):
    item, directory, calls = native_setup
    def fail(*args, **kwargs):
        raise RuntimeError("Native producer failed.")
    monkeypatch.setattr(supervisor, "command", fail)
    data = supervisor.native_analysis(item, {"database": "database"}, tmp_path, Path("codeql"))
    assert data["status"] == "failed"
    assert "alerts" not in data
    assert not (directory / "native.canonical.json").exists()


def test_native_cache_is_bound_to_source_and_report(tmp_path, supervisor, native_setup):
    item, directory, calls = native_setup
    data = supervisor.native_analysis(item, {"database": "database"}, tmp_path, Path("codeql"))
    Path(data["report"]).write_text("changed")
    with pytest.raises(ValueError, match="Native report changed"):
        supervisor.native_analysis(item, {"database": "database"}, tmp_path, Path("codeql"))


def test_hop_diagnostics_uses_only_frozen_evidence_and_keeps_scores(tmp_path, supervisor, monkeypatch):
    pytest.importorskip("tree_sitter_java")
    evaluation = pytest.importorskip("vecho_experiment.evaluation")
    source = tmp_path / "source"
    source.mkdir()
    lines = [
        "class Fixture {",
        "  void a() {}",
        "  void b() { c(1); }",
        "  void c(int x) { d(x); }",
        "  void d(int x) { e(x); }",
        "  void e(int x) { f(x); }",
        "  void f(int x) {}",
        "}",
    ]
    (source / "Fixture.java").write_text("\n".join(lines))
    exp = tmp_path / "experiment"
    job = exp / "runs/project"
    output = job / "attempt-0001"
    output.mkdir(parents=True)
    source_hash = supervisor.tree_hash(source)
    item = {"key": "project", "sample": 55, "project": {"cwe_id": "CWE-079"},
            "source": str(source), "tree_sha256": source_hash}
    supervisor.write(exp / "private/selection.json", [item])
    graph = exp / "graph.csv"
    graph.write_text("kind,left,l,c,right,l,c\n"
                     "CODEQL_CALL,Fixture.java,3,14,Fixture.java,4,3\n"
                     "CODEQL_CALL,Fixture.java,6,19,Fixture.java,7,3\n")
    values = exp / "values.csv"
    values.write_text(",".join(map(str, range(17))) + "\n"
                      "Fixture.java,4,19,4,19,ARGUMENT,0,Fixture.java,5,3,5,25,PARAMETER,0,Fixture.java,4,4\n")

    def point(line):
        return {"file": "Fixture.java", "line": line}

    def trace_event(name, **data):
        return json.dumps({"event": name, "node": "reason:1:CWE-79", **data}) + "\n"

    reads = "".join(trace_event("action_result", action={"action": "inspect_entity"}, result={
        "lines": [{"text": lines[line - 1]}], "evidence": {"source_kind": "SOURCE_SNIPPET",
            "repository_relative_path": "Fixture.java", "start_line": line, "end_line": line}})
        for line in (2, 4, 5, 6, 7))
    (output / "trace.jsonl").write_text(
        reads + trace_event("model_input", role="reasoning", context={
            "value_paths": [{"id": "visible", "ports": [point(5), point(6)]}]})
        + trace_event("model_response", role="reasoning")
        + trace_event("value_paths_prompt_truncated", paths=[{"id": "omitted", "ports": [point(6), point(7)]}])
        + trace_event("model_input", role="reasoning", context={
            "value_paths": [{"id": "budget_denied", "ports": [point(2), point(3)]}]})
        + trace_event("verification_reserve_reached", role="reasoning")
        + 2 * trace_event("action_result", action={"action": "submit_bridge", "path_id": "visible"}, result={}))
    candidate = {"cwe": "CWE-79", "candidate_path_id": "candidate", "ordered_nodes": [point(5), point(6)]}
    (output / "candidates.jsonl").write_text(json.dumps(candidate) + "\n")
    (output / "reviews.jsonl").write_text(json.dumps({
        "cwe": "CWE-79", "candidate_path_id": "candidate", "verdict": "REJECTED"}) + "\n")
    summary = {"stop_reason": "GRAPH_COMPLETE"}
    supervisor.write(output / "run.json", summary)
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    supervisor.write(job / "frozen.json", {"output": str(output), "source_tree_sha256": source_hash,
                                            "sha256": {p.name: digest(p) for p in output.iterdir()}})
    supervisor.write(job / "outcome.json", {"output": str(output), "status": "complete", "summary": summary,
        "static": {"graph": str(graph), "graph_sha256": digest(graph), "source_tree_sha256": source_hash},
        "values": {"path": str(values), "sha256": digest(values), "graph_sha256": digest(graph),
                   "source_tree_sha256": source_hash}})
    original = [{"key": "project", "status": "complete", "classification": "NO_VERIFIED_CANDIDATE"}]
    supervisor.write(exp / "validation-results.json", original)
    calls = []
    monkeypatch.setattr(evaluation, "labels", lambda *args: (calls.append(args) or [], "fixture"))
    chains = tmp_path / "private-chains.json"
    supervisor.write(chains, {"sample_0055": [{"methods": [point(line) for line in range(2, 8)],
                                               "source": point(2), "sink": point(7)}]})
    report = tmp_path / "report"
    supervisor.main(["diagnose-hops", "--base", str(tmp_path), "--experiment", str(exp),
                     "--output-dir", str(report), "--sample", "sample_0055", "--chains", str(chains)])
    detail = json.loads((report / "hop-diagnostics.json").read_text())[0]
    row = json.loads((report / "validation-results.json").read_text())[0]
    assert row["classification"] == original[0]["classification"]
    assert row["source_recalled"] is row["sink_recalled"] is True
    assert row["bridge_proposed_count"] == row["max_connected_hops"] == 1
    assert [(hop["status"], hop["reason"]) for hop in detail["chains"][0]["hops"]] == [
        ("STATIC_MISSING", None), ("EXPORTED_NOT_RECALLED", None),
        ("RECALLED_NOT_SPLICED", "AST_MAPPING_FAILED"), ("SPLICED_UNVERIFIED", None),
        ("RECALLED_NOT_SPLICED", "PROMPT_RANKING_TRUNCATED")]
    assert detail["chains"][0]["hops"][3]["review_verdicts"] == ["REJECTED"]
    assert json.loads((exp / "validation-results.json").read_text()) == original

    graph.write_text("mutated export")
    with pytest.raises(ValueError, match="Static export receipt mismatch"):
        supervisor.diagnose_hops(tmp_path, exp, report, ["sample_0055"], chains)
    assert len(calls) == 1
