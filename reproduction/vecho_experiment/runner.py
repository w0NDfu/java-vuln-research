"""Sequential, resumable multi-source feedback experiment. No labels in workers."""
import csv
import json
import os
import signal
import shutil
import subprocess
import sys
from pathlib import Path
from . import inputs, snapshot, evaluation, runtime
from .config import identity
from .gateway import Ledger, Gateway
from .io import read, write, now, file_hash, tree_hash, digest, lock, inside
from .state import Stages
from . import memory


def command(argv, cwd, output, env=None, timeout=None):
    """Terminate our child group on cancellation, never unrelated services."""
    with Path(output).open("wb") as out:
        kwargs = {"start_new_session": True} if os.name != "nt" else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        proc = subprocess.Popen([str(x) for x in argv], cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT, **kwargs)
        try:
            status = proc.wait(timeout=timeout)
            if status: raise subprocess.CalledProcessError(status, [str(argv[0])])
        finally:
            if proc.poll() is None:
                if os.name != "nt": os.killpg(proc.pid, signal.SIGTERM)
                else: proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if os.name != "nt": os.killpg(proc.pid, signal.SIGKILL)
                    else: proc.kill()
                    proc.wait()


def projects(cfg):
    with (Path(cfg["dataset"]) / "metadata/project_info.csv").open(encoding="utf-8-sig") as f:
        rows = {int(r["id"]): r for r in csv.DictReader(f)}
    return [rows[i] for i in cfg["samples"]]


def import_static(cfg, row, stages, source):
    records = []
    for index, spec in enumerate(cfg["static_sources"]):
        path = Path(cfg["config_dir"]) / spec["path"].format(id=row["id"], sample=f"sample_{int(row['id']):04d}")
        external_hash = file_hash(path) if path.is_file() else None
        query_hashes = {str(p): file_hash(Path(cfg["config_dir"]) / p) for p in spec.get("query_files", [])}
        def collect(attempt):
            output = attempt / "report.json"
            if spec.get("commands"):
                values = {"source": str(source), "report": str(output), "work": str(attempt), "id": row["id"], "commit": row["buggy_commit_id"]}
                if not spec.get("version_command"):
                    raise ValueError("Generated static reports require a version_command")
                version = subprocess.check_output(spec["version_command"], text=True, stderr=subprocess.STDOUT)
                if spec["version"] not in version: raise ValueError("Static producer version differs from declared version")
                (attempt / "producer-version.txt").write_text(version, encoding="utf-8")
                for j, argv in enumerate(spec["commands"]):
                    command([x.format_map(values) for x in argv], source, attempt / f"command-{j}.log", timeout=spec.get("timeout_seconds", 7200))
            elif external_hash:
                output.write_bytes(path.read_bytes())
            elif spec.get("required", True):
                raise FileNotFoundError("Required static input absent")
            else:
                write(output, {"vulnerabilities": []})
                write(attempt / "omission.json", {"explicitly_optional": True, "source": spec["tool"]})
                return output
            data = read(output)
            source_root = spec.get("source_root", "").format(source=str(source), id=row["id"])
            if spec["format"] == "sarif": converted = inputs.sarif(data, spec["tool"], source_root)
            elif spec["format"] == "coverity-json": converted = inputs.coverity(data, spec["tool"], source_root)
            else: converted = inputs.canonical(data, source_root)
            write(attempt / "canonical.json", {"vulnerabilities": converted})
            write(attempt / "producer.json", {"tool": spec["tool"], "declared_version": spec["version"], "queries": spec["queries"],
                  "raw_sha256": file_hash(output), "path_count": sum(len(x["tainted_data_flow"]) for x in converted),
                  "producer_execution_verified": bool(spec.get("commands"))})
            return attempt / "canonical.json"
        p = stages.run(f"static-{index:02d}", {"spec": spec, "query_file_hashes": query_hashes, "external_sha256": external_hash, "commit": row["buggy_commit_id"]}, collect)
        records += read(p)["vulnerabilities"]
    return records


class Backend:
    def __init__(self, cfg, rt, gateway_url, token, memory_url, sample, target):
        self.cfg, self.rt, self.gateway, self.token = cfg, rt, gateway_url, token
        self.memory, self.sample, self.target = memory_url, sample, Path(target)

    def scan(self, stage, attempt, guidance, known):
        s = self.cfg["scanner"]
        argv = [self.rt["scanner_binary"], stage, "run", "--repo", str(self.target), "--language", "java",
                "--project-id", self.sample, "--project-name", self.sample, "--out", str(attempt / "scan"),
                "--model", self.cfg["models"]["scan"]["model"], "--base-url", self.gateway + "/scan/v1/chat/completions",
                "--context-concurrency", str(s["concurrency"]), "--max-turns-per-block", str(s["turns_per_block"]),
                "--max-context-steps-per-case", str(s["steps_per_case"]), "--max-context-turns-per-step", str(s["turns_per_step"]),
                "--max-context-tool-calls-per-case", str(s["tools_per_case"]), "--timeout", str(s["timeout_seconds"]) + "s"]
        if self.memory:
            argv += ["--memory-enabled", "--memory-url", self.memory, "--memory-project", self.sample, "--memory-timeout-seconds", "120"]
        if stage == "rescan":
            write(attempt / "bundle.json", {"project_id": self.sample, "repo_path": str(self.target), "known_vulnerabilities": known, "guidance": guidance})
            argv += ["--bundle", str(attempt / "bundle.json")]
        env = dict(os.environ, VECHO_SCAN_API_KEY=self.token)
        # Copy, then rebind transport/output paths only. Case/seed/source hashes
        # are checked by the installed scanner overlay before any reuse.
        previous = [p for p in sorted(attempt.parent.glob("attempt-*/scan/session.json")) if p.parent.parent != attempt]
        if previous:
            old = previous[-1]
            shutil.copytree(old.parent, attempt / "scan")
            meta = read(attempt / "scan/session.json")
            if meta["config"]["model"] != self.cfg["models"]["scan"]["model"] or meta["config"]["repo_path"] != str(self.target):
                raise ValueError("Scanner checkpoint model/source changed")
            before = {k: meta["config"].get(k) for k in ["out_dir", "base_url", "memory_mcp", "resume_session_dir"]}
            meta["out_dir"] = str(attempt / "scan")
            meta["config"].update(out_dir=str(attempt / "scan"), base_url=self.gateway + "/scan/v1/chat/completions", resume_session_dir=str(attempt / "scan"))
            if self.memory: meta["config"]["memory_mcp"]["url"] = self.memory
            write(attempt / "resume-rebind.json", {"previous_session_sha256": file_hash(old), "transport_and_output_fields_before": before,
                  "note": "No model, source, prompts or reasoning budgets changed; previous attempt preserved."})
            write(attempt / "scan/session.json", meta)
            argv = [self.rt["scanner_binary"], stage, "resume", "--session", str(attempt / "scan"), "--timeout", str(s["timeout_seconds"]) + "s"]
        command(argv, self.rt["artifact"], attempt / "scanner.log", env)
        directory = attempt / "scan"
        if read(directory / "session.json")["status"] != "completed": raise RuntimeError("Scanner did not complete")
        summary = read(directory / "contextaudit/results.json")
        if summary.get("failed_count", 0) or any(x.get("status") == "failed" for x in summary["results"]):
            raise RuntimeError("Scanner has unfinished cases")
        report = inputs.canonical(read(directory / "vecho/report.json"), vecho_paths=True)
        unresolved = []
        if self.cfg.get("analysis_policy") == "library-v1":
            for case in summary["results"]:
                if case.get("status") != "blocked": continue
                case_id = case["case_id"]
                saved = read(inside(directory / "contextaudit/cases", case_id + "/case.json"))
                if saved["case_id"] != case_id or saved["status"] != "blocked":
                    raise ValueError("Unresolved scanner case identity mismatch")
                loc = saved["seed"]["location"]
                source = inside(self.target, loc["file"])
                line = loc["line"]
                if type(line) is not int or not 1 <= line <= len(source.read_bytes().splitlines()):
                    raise ValueError("Unresolved scanner seed has an invalid source location")
                if not any(w["file"] == loc["file"] and w["start_line"] <= line <= w["end_line"]
                           and w.get("sha256") == file_hash(source) for w in saved.get("read_windows", [])):
                    raise ValueError("Unresolved scanner seed lacks a verified read window")
                unresolved.append({"description": "UNRESOLVED candidate, not a confirmed vulnerability. "
                    + saved["seed"].get("title", "") + ". Scanner limitation: " + saved.get("reason", ""),
                    "short_description": "Unresolved library evidence", "category": "unresolved-library-evidence",
                    "source_scanner": "vEcho-unresolved", "cwe": "", "severity": "",
                    "affected_files": [{"file_path": loc["file"], "line_numbers": [line]}],
                    "tainted_data_flow": [], "metadata": {"candidate_only": True, "case_id": case_id,
                    "original_status": "blocked", "path_evidence": "location_only"}})
            report += unresolved
            write(attempt / "unresolved-candidates.json", {"vulnerabilities": unresolved,
                  "note": "Candidates for Judge review only; not detected vulnerabilities or synthetic paths."})
        # Preserve blocked/unknown counts; completed transport != exhaustive audit.
        write(attempt / "coverage.json", {"case_total": summary["total"], "statuses": summary["by_status"],
                                         "unresolved_candidates_for_judge": len(unresolved)})
        write(attempt / "canonical.json", {"vulnerabilities": report})
        return attempt / "canonical.json"

    def judge(self, record, attempt):
        sys.path.insert(0, str(Path(self.rt["artifact"]) / "judge"))
        from vecho_judge.app.config import default_config
        from vecho_judge.adapters.canonical import normalize_canonical_payload
        from vecho_judge.memory_client import MemoryClient
        from vecho_judge.runtime import JudgeRuntimeConfig, run_llm_judge
        cfg = default_config()
        mem = MemoryClient(enabled=bool(self.memory), url=self.memory, project=self.sample, timeout_seconds=120, errors=[])
        runtime_cfg = JudgeRuntimeConfig(repo_root=self.target, model=self.cfg["models"]["judge"]["model"],
              base_url=self.gateway + "/judge/v1", api_key=self.token,
              prompt_path=Path(self.rt["artifact"]) / "judge/vecho_judge/prompts/prompt_judger.txt",
              max_turns=self.cfg["judge"]["max_turns"], project_name=self.sample, memory=mem)
        result = run_llm_judge(normalize_canonical_payload([record])[0], runtime_cfg)
        write(attempt / "transcript.json", result.transcript)
        write(attempt / "tool-calls.json", result.tool_calls)
        write(attempt / "usage.json", result.usage)
        if result.result.fingerprint != record["fingerprint"] or mem.errors:
            raise RuntimeError("Judge identity or memory operation failed")
        write(attempt / "result.json", {"result": result.result.to_dict(), "guidance": result.guidance.to_dict()})
        return attempt / "result.json"


def feedback(cfg, stages, initial, backend, redactor):
    pending, _ = inputs.merge_records(initial)
    seen, accepted, guidance, verdicts = set(), {}, [], []
    rounds, stale, stop = [], 0, "max_rescans"
    for number in range(cfg["loop"]["max_rescans"] + 1):
        if (Path(cfg["workspace"]) / "STOP").exists(): raise InterruptedError("Operator requested stop")
        if len(seen) + len(pending) > cfg["loop"]["max_new_candidates"]:
            raise RuntimeError("Candidate budget exceeded; incomplete, not silent truncation")
        current_guidance = []
        for record in pending:
            if (Path(cfg["workspace"]) / "STOP").exists(): raise InterruptedError("Operator requested stop")
            fp = record["fingerprint"]
            visible = redactor.report([record])[0]
            def judge_action(attempt, r=visible):
                return backend.judge(r, attempt)
            p = stages.run("judge-" + fp, {"candidate": visible, "round": number}, judge_action)
            output = read(p); result = output["result"]
            if result["fingerprint"] != fp or result["vuln_status"] not in {"true", "false", "unknown"}:
                raise ValueError("Invalid judge verdict")
            verdicts.append(result); seen.add(fp)
            if result["vuln_status"] == "true": accepted[fp] = record
            # Both positive and negative evidence can guide later discovery.
            # Unknowns remain visible and are never turned into false verdicts.
            if result["vuln_status"] != "unknown" and output.get("guidance", {}).get("content", "").strip():
                g = dict(output["guidance"]); g["content"] = redactor.mask(g["content"])
                current_guidance.append(g)
        guidance.extend(current_guidance)
        rounds.append({"round": number, "new_candidates": len(pending), "accepted_total": len(accepted), "judged_total": len(seen)})
        if number == cfg["loop"]["max_rescans"]: stop = "max_rescans"; break
        if not guidance: stop = "no_actionable_guidance"; break
        known = redactor.report(list(accepted.values()))
        scan_inputs = {"round": number + 1, "guidance": guidance, "known": known,
                       "analysis_policy": cfg.get("analysis_policy", "legacy")}
        p = stages.run(f"rescan-{number + 1:02d}", scan_inputs,
                       lambda attempt: backend.scan("rescan", attempt, guidance, known))
        candidates, excluded = inputs.merge_records(read(p)["vulnerabilities"])
        pending = [r for r in candidates if r["fingerprint"] not in seen]
        stale = stale + 1 if not pending else 0
        if stale >= cfg["loop"]["patience"]: stop = "no_new_candidates"; break
    return {"vulnerabilities": list(accepted.values()), "verdicts": verdicts, "rounds": rounds,
            "stop_reason": stop, "unknown_verdicts": sum(r["vuln_status"] == "unknown" for r in verdicts)}


def run_project(cfg, rt, row, root, gateway_url, token, resume, backend_factory=None):
    backend_factory = backend_factory or Backend
    sample = f"sample_{int(row['id']):04d}"
    source = Path(cfg["dataset"]) / "project-sources" / row["project_slug"]
    stages = Stages(root / "stages", resume)
    def prepare(attempt):
        snapshot.export(source, row["buggy_commit_id"], attempt / "source", attempt / "private", cfg["anonymization"], row)
        write(attempt / "output.json", {"source": str(attempt / "source"), "provenance": str(attempt / "private/snapshot.json")})
        return attempt / "output.json"
    p = stages.run("snapshot", {"commit": row["buggy_commit_id"], "policy": cfg["anonymization"]}, prepare)
    snap = read(p); provenance = read(snap["provenance"]); target = Path(snap["source"])
    if tree_hash(target) != provenance["tree_sha256"]: raise ValueError("Source snapshot changed")
    redactor = snapshot.Redactor(provenance["tokens"])
    initial = import_static(cfg, row, stages, source)
    directory = Path(cfg["workspace"]) / "knowledge" / ("campaign" if cfg["memory"]["scope"] == "campaign" else sample)
    with memory.serve({**cfg, "artifact": rt["artifact"]}, directory, gateway_url, token, sample, redactor) as memory_url:
        backend = backend_factory(cfg, rt, gateway_url, token, memory_url, sample, target)
        p = stages.run("initial-scan", {"scanner": cfg["scanner"], "target_tree": provenance["tree_sha256"],
                       "analysis_policy": cfg.get("analysis_policy", "legacy")},
                       lambda attempt: backend.scan("scan", attempt, [], []))
        initial += read(p)["vulnerabilities"]
        initial, excluded = inputs.merge_records(initial)
        write(root / "merged-inputs.private.json", {"vulnerabilities": initial, "excluded": excluded})
        outcome = feedback(cfg, stages, initial, backend, redactor)
    # Ground truth is accessed only after every analysis operation has finished.
    fixes, selection = evaluation.labels(cfg["dataset"], row)
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip() != row["buggy_commit_id"] or subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=source, text=True).strip():
        raise ValueError("Original scoring source changed during analysis")
    metric = evaluation.evaluate(source, outcome["vulnerabilities"], fixes)
    metric["label_selection"] = selection
    coverage = {}
    for receipt in (root / "stages").glob("*/receipt.json"):
        saved = read(receipt)
        if saved["status"] != "complete": continue
        p = (receipt.parent / saved["result"]).parent / "coverage.json"
        if p.exists(): coverage[receipt.parent.name] = read(p)
    write(root / "final-report.json", outcome)
    write(root / "evaluation.json", metric)
    return {"status": "complete", "sample_identity": {"slug": row["project_slug"], "commit": row["buggy_commit_id"]}, "finished_at": now(), "evaluation": metric,
            "stop_reason": outcome["stop_reason"], "unknown_verdicts": outcome["unknown_verdicts"], "rounds": outcome["rounds"],
            "scan_coverage": coverage, "coverage_note": "Blocked cases reached reasoning/tool limits; workflow completion does not mean exhaustive vulnerability inspection."}


def plan(cfg):
    return {"config_sha256": identity(cfg), "profile": cfg["profile"], "ordered_samples": cfg["samples"],
            "analysis_policy": cfg.get("analysis_policy", "legacy"),
            "models": {role: {k: v for k, v in model.items() if k != "key_env"} for role, model in cfg["models"].items()},
            "loop": cfg["loop"], "memory": cfg["memory"], "budget": cfg["budget"], "assumptions": cfg["assumptions"],
            "model_requests_started": False, "exact_author_reproduction": False}


def run(cfg, resume=False):
    rt = runtime.verify(cfg)
    # Read all required report paths before spending on the first project.
    # Production dependencies/credentials are checked below and by preflight;
    # importing the checker here would create a module cycle.
    for row in projects(cfg):
        for spec in cfg["static_sources"]:
            path = Path(cfg["config_dir"]) / spec["path"].format(id=row["id"], sample=f"sample_{int(row['id']):04d}")
            if not spec.get("commands") and spec.get("required", True) and not path.is_file():
                raise FileNotFoundError("Required static report missing before campaign: " + str(path))
            if "CONFIGURE" in spec["version"] or "CONFIGURE" in str(spec["queries"]):
                raise ValueError("Configure actual static producer and query provenance")
    root = Path(cfg["workspace"])
    # Prevent accidental run data/model-visible targets living in the input repo.
    for input_root in [cfg["artifact"], cfg["dataset"]]:
        p = Path(input_root).resolve()
        if root == p or root.is_relative_to(p) or p.is_relative_to(root): raise ValueError("Workspace must be disjoint from input repositories/dataset")
    rows = projects(cfg)
    meta_root = Path(cfg["dataset"]) / "metadata"
    experiment_identity = digest({"config": cfg, "runtime": rt, "driver": tree_hash(Path(__file__).parent),
          "dataset_project_info": file_hash(meta_root / "project_info.csv"), "dataset_fix_info": file_hash(meta_root / "fix_info.csv"),
          "knowledge_seed": tree_hash(cfg["memory"]["seed"]) if cfg["memory"]["seed"] else None})
    with lock(root / "campaign.lock"):
        manifest = root / "experiment.json"
        if manifest.exists():
            if not resume or read(manifest)["identity"] != experiment_identity: raise ValueError("Use explicit resume with byte-identical configuration/runtime/driver")
        else:
            write(manifest, {"identity": experiment_identity, "config": cfg, "runtime": rt, "started_at": now(), "status": "prepared"})
        if (root / "STOP").exists(): raise InterruptedError("STOP is set; remove it explicitly before resuming")
        if cfg["budget"]["limit_usd"] <= cfg["budget"]["opening_spend_usd"] or cfg["budget"]["max_requests"] < 1:
            raise ValueError("Live execution requires explicit positive remaining cumulative budget and request limit")
        for role, model in cfg["models"].items():
            if model["input_usd_per_million"] <= 0 or role != "embedding" and model["output_usd_per_million"] <= 0:
                raise ValueError("Configure actual positive model prices before live execution")
            if not os.environ.get(model["key_env"]): raise ValueError("Missing configured credential environment variable")
        ledger = Ledger(root / "budget.sqlite", cfg["budget"], cfg["models"])
        gateway = Gateway(cfg, ledger)
        status = "running"
        meta = read(manifest); meta.update(status=status, updated_at=now()); write(manifest, meta)
        try:
            with gateway.serve() as url:
                for row in rows:
                    if (root / "STOP").exists(): raise KeyboardInterrupt("Operator requested stop")
                    project_root = root / "projects" / f"sample_{int(row['id']):04d}"
                    project_root.mkdir(parents=True, exist_ok=True)
                    result_path = project_root / "result.json"
                    if result_path.exists() and read(result_path)["status"] == "complete":
                        checks = read(project_root / "result-receipt.json")
                        for relative, sha in checks.items():
                            if file_hash(project_root / relative) != sha: raise ValueError("Final experiment result changed")
                        # Verify checkpoint outputs even for finished projects.
                        for receipt in (project_root / "stages").glob("*/receipt.json"):
                            old = read(receipt)
                            if old["status"] == "complete":
                                for name, sha in old["outputs"].items():
                                    if file_hash(receipt.parent / name) != sha: raise ValueError("Completed experiment output modified")
                        continue
                    try:
                        outcome = run_project(cfg, rt, row, project_root, url, gateway.token, resume=resume)
                        write(result_path, outcome)
                        write(project_root / "result-receipt.json", {name: file_hash(project_root / name) for name in ["result.json", "final-report.json", "evaluation.json"]})
                    except Exception as exc:
                        write(result_path, {"status": "failed", "error_type": type(exc).__name__, "at": now()})
                        if cfg["memory"]["scope"] == "campaign":
                            break  # Preserve cross-project chronological order.
                    write(root / "summary.json", evaluation.summarize(root, cfg["samples"]))
            summary = evaluation.summarize(root, cfg["samples"])
            status = "complete" if summary["all_workflows_complete"] else "incomplete"
            write(root / "summary.json", summary)
            return summary
        except KeyboardInterrupt:
            status = "interrupted"; raise
        except BaseException:
            status = "failed"; raise
        finally:
            meta = read(manifest); meta.update(status=status, updated_at=now(), budget=ledger.summary())
            write(manifest, meta)
            summary = evaluation.summarize(root, cfg["samples"])
            summary.update(profile=cfg["profile"], replicate=cfg["replicate"], budget=ledger.summary(),
                           experiment_identity=experiment_identity, exact_author_reproduction=False)
            write(root / "summary.json", summary)
