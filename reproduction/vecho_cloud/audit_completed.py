"""Audit completed workflows and re-score offline, preserving original outputs."""
import collections
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from batch import collect
from common import DATASET, REPRO, samples, write_json
from run import deduplicate


def read(path):
    return json.loads(path.read_text())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def audit_stage(root, stage):
    directory = root / stage
    session = read(directory / "session.json")
    require(session["status"] == "completed", stage + " session is incomplete")
    events = [json.loads(line) for line in (directory / "events.ndjson").read_text().splitlines()]
    # Earlier attempt events remain as evidence. Audit closures from the latest
    # ContextAudit pass, including checkpoints validated and reused by the engine.
    beginnings = [i for i, e in enumerate(events) if e["type"] == "contextaudit_started"]
    current = events[beginnings[-1]:] if beginnings else events
    require(any(e["type"] == stage + "_completed" for e in current), stage + " has no completion event")
    starts = [e["data"]["case_count"] for e in events if e["type"] == "contextaudit_started"]
    closed = [e["data"] for e in current if e["type"] in {"case_completed", "case_reused"}]
    planned = starts[-1] if starts else 0
    require(len(closed) == planned, stage + " case count does not match plan")
    require(len({c["case_id"] for c in closed}) == len(closed), stage + " duplicate case closures")
    require(all(c["status"] in {"confirmed", "dead_end", "blocked", "rejected"} for c in closed), stage + " has failed or unfinished cases")
    usage = read(directory / "usage.json")["total"]
    require(usage.get("prompt_tokens", 0) + usage.get("completion_tokens", 0) == usage.get("total_tokens", 0), stage + " inconsistent token totals")
    return {"session_id": session["session_id"], "planned_cases": planned, "closed_cases": len(closed),
            "case_statuses": dict(collections.Counter(c["status"] for c in closed)),
            "event_errors": sum(bool(e.get("error")) for e in events), "usage": usage,
            "reused_cases": sum(e["type"] == "case_reused" for e in current)}


def audit_judge(root, stage):
    attempts = sorted((root / stage).glob("*/summary.json"))
    require(bool(attempts), stage + " has no saved summary")
    directory = attempts[-1].parent
    summary = read(directory / "summary.json")
    inputs = read(directory / "inputs/normalized.json")
    results = [read(p) for p in sorted((directory / "results").glob("*.json"))]
    require(bool(inputs), stage + " discarded every scanner report")
    require(not summary["failures"], stage + " has failed records")
    require(len(inputs) == len(results) == summary["result_count"] == summary["normalized_count"], stage + " missing records")
    require(len({r["fingerprint"] for r in inputs}) == len(inputs), stage + " duplicate input fingerprints")
    require({r["fingerprint"] for r in inputs} == {r["fingerprint"] for r in results}, stage + " result fingerprints differ")
    require(all(r["vuln_status"] in {"true", "false", "unknown"} for r in results), stage + " invalid verdict")
    require(all(not r.get("judge_metadata", {}).get("memory_errors") for r in results), stage + " memory errors")
    counts = dict(collections.Counter(r["vuln_status"] for r in results))
    require(counts == summary["status_counts"], stage + " verdict summary differs")
    accepted = {r["fingerprint"] for r in results if r["vuln_status"] == "true"}
    checkpoint = directory / "checkpoint.json"
    detail = {"directory": str(directory), "attempts_retained": len(attempts), "status_counts": counts,
              "guidance_count": summary["guidance_count"], "usage": summary["usage"],
              "reused_fingerprints": read(checkpoint)["reused_fingerprints"] if checkpoint.exists() else []}
    return [r for r in inputs if r["fingerprint"] in accepted], detail


def audit_one(root, row):
    root = Path(root)
    run = read(root / "run.json")
    require(run["status"] == "complete", "workflow is not complete")
    require(run["initial_source"] == row["buggy_commit_id"], "source revision differs")
    original = DATASET / "project-sources" / row["project_slug"]
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=original, text=True).strip()
    require(actual == row["buggy_commit_id"], "original checkout revision differs")
    dirty = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=original, text=True)
    require(not dirty.strip(), "original tracked sources changed")
    marker = REPRO / "targets" / (run["sample"] + "-prepared.json")
    require(read(marker)["commit"] == actual, "prepared target revision marker differs")
    result = {"run_directory": str(root), "source_commit": actual, "stages": {"scan": audit_stage(root, "scan")}, "judges": {}}
    scan_report = root / "scan/vecho/report.json"
    report_paths = [root / "run.json", scan_report, root / "evaluation.json"]
    if not read(scan_report).get("vulnerabilities"):
        require(not (root / "rescan").exists(), "unexpected rescan after empty initial scan")
        final_path = scan_report
        expected = []
    else:
        expected, first = audit_judge(root, "judge")
        result["judges"]["judge"] = first
        require(bool(first["guidance_count"]) == (root / "rescan").exists(), "rescan does not match saved guidance")
        if (root / "rescan").exists():
            result["stages"]["rescan"] = audit_stage(root, "rescan")
            new_report = root / "rescan/vecho/report.json"
            report_paths.append(new_report)
            if read(new_report).get("vulnerabilities"):
                accepted, second = audit_judge(root, "rescan-judge")
                expected.extend(accepted)
                result["judges"]["rescan-judge"] = second
        expected = deduplicate(expected)
        final_path = root / "final-report.json"
        report_paths.append(final_path)
    require(read(final_path).get("vulnerabilities", []) == expected, "final report differs from accepted deduplicated inputs")
    hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in report_paths}
    old = read(root / "evaluation.json")
    require(Path(old["report"]).resolve() == final_path.resolve(), "evaluation uses a different report")
    directory = REPRO / "audits/completion" / run["sample"]
    directory.mkdir(parents=True, exist_ok=True)
    fresh_path = directory / "evaluation.json"
    with (directory / "evaluation.log").open("w") as log:
        subprocess.run([sys.executable, str(REPRO / "evaluate.py"), "--slug", row["project_slug"],
                        "--repo", str(REPRO / "targets" / run["sample"]), "--report", str(final_path),
                        "--out", str(fresh_path)], stdout=log, stderr=subprocess.STDOUT, check=True)
    fresh = read(fresh_path)
    require(all(fresh.get(k) == v for k, v in old.items()), "offline scoring changed original evaluation fields")
    require(not fresh.get("parse_error_files"), "offline scoring has parser errors")
    require(all(hashlib.sha256((root / p).read_bytes()).hexdigest() == digest for p, digest in hashes.items()), "original output changed during audit")
    result.update(status="verified", original_output_sha256=hashes, alerts=len(expected),
                  benchmark_recall=fresh["recall"], evaluation_status=fresh.get("evaluation_status", "available"), models_rerun=False)
    write_json(directory / "audit.json", result)
    return result


def main():
    rows = {"sample_" + str(int(r["id"])).zfill(4): r for r in samples()}
    require(set(rows) == {"sample_" + str(i).zfill(4) for i in range(1, 121)}, "benchmark scope differs from the authorized 120 samples")
    completed = collect()
    verified, errors = {}, []
    for name, item in completed.items():
        try:
            verified[name] = audit_one(item["directory"], rows[name])
        except Exception as exc:
            errors.append({"sample": name, "error": str(exc)})
    counts = collections.Counter()
    for item in verified.values():
        for stage in item["stages"].values():
            counts.update(stage["case_statuses"])
    report = {"checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "expected_samples": len(rows), "completed_candidates": len(completed), "verified_samples": len(verified),
              "pending_samples": sorted(set(rows) - set(completed)), "errors": errors,
              "all_workflows_verified": len(verified) == len(rows) and not errors,
              "all_benchmark_scores_available": len(verified) == len(rows) and all(v["evaluation_status"] == "available" for v in verified.values()),
              "case_statuses_on_verified_workflows": dict(counts), "models_rerun": False,
              "note": "Audit covers completed workflows only. Blocked cases remain unresolved. Usage excludes failed attempts and independent memory calls; it is not provider cost.",
              "verified": verified}
    write_json(REPRO / "completion-audit.json", report)
    print(json.dumps({k: v for k, v in report.items() if k not in {"verified", "pending_samples"}}, indent=2))
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
