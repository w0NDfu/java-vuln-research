"""Audit completed model stages and recover scoring without API requests."""
import argparse
import datetime
import hashlib
import importlib.metadata
import json
from pathlib import Path

from common import REPRO, samples, write_json
from evaluate import evaluate
from run import deduplicate


def read(path):
    return json.loads(path.read_text())


def recover(root):
    root = Path(root).resolve()
    assert root.is_relative_to((REPRO / "runs").resolve())
    run = read(root / "run.json")
    sample_id = int(run["sample"].split("_")[-1])
    row = next(x for x in samples() if int(x["id"]) == sample_id)
    assert run["initial_source"] == row["buggy_commit_id"]
    expected, audit = [], {"stages": {}, "judge": {}, "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}}
    for stage, judge in (("scan", "judge"), ("rescan", "rescan-judge")):
        session = read(root / stage / "session.json")
        assert session["status"] == "completed", f"{stage} incomplete"
        stage_events = [json.loads(line) for line in (root / stage / "events.ndjson").read_text().splitlines()]
        assert any(x["type"] == stage + "_completed" for x in stage_events)
        usage = read(root / stage / "usage.json")["total"]
        for key in audit["usage"]:
            audit["usage"][key] += usage.get(key, 0)
        from collections import Counter
        audit["stages"][stage] = {"case_statuses": dict(Counter(e.get("data", {}).get("status") for e in stage_events if e["type"] == "case_completed")), "tool_errors": sum(bool(e.get("error")) for e in stage_events), "usage": usage}
        directories = sorted((root / judge).glob("*/summary.json"))
        assert len(directories) == 1, "Ambiguous judge runs; inspect before recovery"
        directory = directories[0].parent
        summary = read(directory / "summary.json")
        assert not summary["failures"]
        results = [read(p) for p in sorted((directory / "results").glob("*.json"))]
        assert len(results) == summary["result_count"] == summary["normalized_count"]
        assert all(not r.get("judge_metadata", {}).get("memory_errors") for r in results)
        accepted = {r["fingerprint"] for r in results if r["vuln_status"] == "true"}
        expected.extend(r for r in read(directory / "inputs/normalized.json") if r["fingerprint"] in accepted)
        audit["judge"][judge] = {"status_counts": summary["status_counts"], "failures": summary["failures"], "usage": summary["usage"]}
        for key in audit["usage"]:
            audit["usage"][key] += summary["usage"].get(key, 0)
    final_path = root / "final-report.json"
    final = read(final_path)["vulnerabilities"]
    assert final == deduplicate(expected), "Final report does not match accepted, deduplicated judge inputs"
    before = hashlib.sha256(final_path.read_bytes()).hexdigest()
    target = REPRO / "targets" / run["sample"]
    result = evaluate(row["project_slug"], target, final_path, root / "evaluation.json")
    repeated = evaluate(row["project_slug"], target, final_path, root / "evaluation-repeat.json")
    assert repeated == result and not result["parse_error_files"]
    assert hashlib.sha256(final_path.read_bytes()).hexdigest() == before
    audit.update(recovered_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                 final_report_sha256=before, models_rerun=False, alerts=len(final), benchmark_recall=result["recall"],
                 parser_versions={n: importlib.metadata.version(n) for n in ("tree-sitter", "tree-sitter-java")})
    write_json(root / "recovery-audit.json", audit)
    run.update(status="complete", confirmed_alerts=len(final), recovery="Scoring recovered after evaluator repair; existing model outputs audited and preserved")
    write_json(root / "run.json", run)
    print(json.dumps(audit, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    recover(parser.parse_args().run)
