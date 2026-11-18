"""Offline Benchmark Track adapter/audit. Never imported by the detector."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from vecho_experiment.evaluation import evaluate, labels
from agentic_detection.validate import frozen_output, read_jsonl, write


def predictions(candidates):
    """Preserve submitted order; do not fabricate a path from a location-only alert."""
    output = []
    for c in candidates:
        nodes = [{"file_path": n["repository_relative_path"], "line_number": n["start_line"]}
                 for n in c["ordered_nodes"] if n.get("repository_relative_path") and n.get("start_line")]
        if nodes:
            output.append({"fingerprint": c["candidate_path_id"], "tainted_data_flow": [nodes]})
    return output


def aggregate(metrics):
    valid = [m for m in metrics if m.get("status") == "available"]
    with_paths = [m for m in valid if m["paths"] > 0]
    return {"scorable": len(valid), "expected": len(metrics),
            "#Detected": sum(m["recall"] for m in valid),
            "AvgFDR": sum(1 - m["precision"] for m in with_paths) / len(with_paths) if with_paths else None,
            "AvgF1": sum(m["f1"] for m in valid) / len(valid) if valid else None,
            "fdr_denominator": len(with_paths), "failed_or_unscorable": len(metrics) - len(valid)}


def audit(base, experiment):
    selection = json.loads((experiment / "private/selection.json").read_text())
    hop_file = experiment / "hop-results/hop-diagnostics.json"
    hops = {r["key"]: r for r in json.loads(hop_file.read_text())} if hop_file.exists() else {}
    rows = []
    for item in selection:
        job = experiment / "runs" / item["key"]
        outcome_path = job / "outcome.json"
        if not outcome_path.exists():
            continue
        outcome = json.loads(outcome_path.read_text())
        row = {"key": item["key"], "status": outcome["status"], "split": item["split"]}
        journal = read_jsonl(job / "request-journal.jsonl") if (job / "request-journal.jsonl").exists() else []
        row.update(requests=sum(r["event"] == "request_started" for r in journal),
                   tokens=sum(r["charged_tokens"] for r in journal if r["event"] == "response"),
                   unsettled=sum(r["event"] == "request_started" for r in journal) - sum(r["event"] == "response" for r in journal))
        if outcome["status"] != "complete":
            rows.append(row); continue
        output, _ = frozen_output(item, job)
        candidates = read_jsonl(output / "candidates.jsonl")
        reviews = read_jsonl(output / "reviews.jsonl")
        supported = {r["candidate_path_id"] for r in reviews if r["verdict"] == "SUPPORTED"}
        strict = [c for c in candidates if c["candidate_path_id"] in supported]
        retained_file = output / "benchmark-candidates.jsonl"
        retained = read_jsonl(retained_file) if retained_file.exists() else strict
        row.update(candidates=len(candidates), retained=len(retained), strict_verified=len(strict),
                   stop_reason=outcome["summary"]["stop_reason"])
        if item["split"] == "synthetic":
            row.update(expected=item["expected"], passed=bool(retained) == (item["expected"] == "vulnerable"))
        else:
            fixes, _ = labels(base / "dataset", item["project"])
            row["metric"] = evaluate(item["source"], predictions(retained), fixes)
            row["pre_filter_metric"] = evaluate(item["source"], predictions(candidates), fixes)
            row["strict_metric"] = evaluate(item["source"], predictions(strict), fixes)
            target_cwe = "CWE-" + str(int(item["project"]["cwe_id"].split("-")[-1]))
            row["target_cwe_metric"] = evaluate(item["source"], predictions([c for c in retained if c["cwe"] == target_cwe]), fixes)
            # Target method recall is a diagnostic, never a submitted prediction.
            if (output / "source-evidence.jsonl").exists():
                proofs = read_jsonl(output / "source-evidence.jsonl")
                locations = [{"file_path": p["file"], "line_number": line}
                             for p in proofs for line in range(p["start_line"], p["end_line"] + 1)]
                covered = evaluate(item["source"], [{"fingerprint": "OFFLINE_RETRIEVAL_DIAGNOSTIC", "tainted_data_flow": [locations]}], fixes)
                hit_methods = {tuple(m) for d in covered["details"] for m in d["matched_methods"]}
                row["target_code_recall"] = {"recalled": len(hit_methods), "total": len(covered["targets"]),
                                              "methods": sorted(hit_methods)}
            elif item["key"] in hops:
                methods = hops[item["key"]]["patch_methods"]
                row["target_code_recall"] = {"recalled": sum(m["recalled"] is True for m in methods),
                    "total": len(methods), "unresolved": sum(m["recalled"] is None for m in methods)}
            if item["key"] in hops:
                row["earliest_failure"] = ("RETRIEVAL" if not all(m["recalled"] for m in hops[item["key"]]["patch_methods"])
                                            else "CANDIDATE_CONSTRUCTION" if not row["pre_filter_metric"]["recall"]
                                            else "STRICT_VERIFICATION_FILTER" if not row["metric"]["recall"] else "DETECTED")
        rows.append(row)
    return {"experiment": str(experiment), "scope": "DEVELOPMENT_DIAGNOSTICS_NOT_120_CVE_RESULT",
            "scorer": "tree-sitter method intersection; paper equations 1-7; not author executable",
            "candidate_status": "UNCONFIRMED unless separately strictly verified",
            "all_cwe_outputs_counted": True,
            "aggregate": aggregate([r.get("metric", {"status": "failed"}) for r in rows if r["split"] != "synthetic"]),
            "cases": rows}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", required=True, type=Path)
    p.add_argument("--experiment", action="append", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    result = [audit(args.base, e) for e in args.experiment]
    write(args.output, result)
    print(json.dumps([{k: r[k] for k in ("experiment", "aggregate")} for r in result], indent=2))


if __name__ == "__main__":
    main()
