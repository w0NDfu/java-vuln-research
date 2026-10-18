"""First pass over all samples; defer failures and preserve existing attempts."""
import datetime
import json
import subprocess
import sys
from pathlib import Path

from common import REPRO, samples, write_json


def collect(sample_names=None):
    done = {}
    for path in sorted((REPRO / "runs").glob("*/sample_*/run.json")):
        run = json.loads(path.read_text())
        if sample_names is not None and run["sample"] not in sample_names:
            continue
        evaluation = path.parent / "evaluation.json"
        if run.get("status") == "complete" and evaluation.exists():
            score = json.loads(evaluation.read_text())
            if score.get("parse_error_files"):
                continue
            done[run["sample"]] = {"directory": str(path.parent), "evaluation": score,
                                   "judge_adapter": run.get("judge_adapter", "original upstream judge"),
                                   "scan_model": run.get("scan_model"), "judge_model": run.get("judge_model")}
    return done


def summarize(done, total):
    scores = [x["evaluation"] for x in done.values()
              if x["evaluation"].get("evaluation_status", "available") == "available"]
    unscorable = [name for name, item in done.items()
                  if item["evaluation"].get("evaluation_status", "available") != "available"]
    hits = sum(x["recall"] for x in scores)
    tp = sum(x["tp_paths"] for x in scores)
    paths = sum(x["paths"] for x in scores)
    recall = hits / len(scores) if scores else 0
    precision = tp / paths if paths else 0
    groups = {}
    for item in done.values():
        key = item.get("judge_adapter", "original upstream judge")
        group = groups.setdefault(key, {"completed_samples": 0, "scored_samples": 0, "benchmark_detected_samples": 0})
        group["completed_samples"] += 1
        group["scored_samples"] += item["evaluation"].get("evaluation_status", "available") == "available"
        group["benchmark_detected_samples"] += item["evaluation"]["recall"] or 0
    return {"expected_samples": total, "completed_samples": len(done), "scored_samples": len(scores),
            "unscorable_samples": unscorable, "benchmark_detected_samples": hits,
            "judge_configuration_groups": groups, "mixed_judge_configurations": len(groups) > 1,
            "recall_on_completed_samples": recall, "tp_paths": tp, "paths": paths,
            "benchmark_path_precision": precision, "f1_on_completed_samples": 2 * recall * precision / (recall + precision) if recall + precision else 0,
            "full_dataset_complete": len(done) == total,
            "full_benchmark_evaluation_complete": len(scores) == total, "exact_iris_reproduction": False,
            "note": "Failed/unrun/unscorable samples excluded from metric denominators; completed_samples counts finished scan workflows. Unmatched paths are not proven false positives",
            "results": done}


def main(argv=None):
    import argparse
    import fcntl
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, help="Only run the first N sample IDs")
    args = parser.parse_args(argv)
    rows = sorted(samples(), key=lambda r: int(r["id"]))
    if args.limit is not None:
        if not 1 <= args.limit <= len(rows):
            parser.error("--limit must be between 1 and the dataset size")
        rows = rows[:args.limit]
    names = {"sample_" + str(int(row["id"])).zfill(4) for row in rows}
    lock = (REPRO / "batch.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    state = {"status": "running", "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
             "authorized_budget_usd": 15, "budget_control": "Existing provider token total quota is $8 as verified in UI; no quota increase or recharge. This is below the authorized $15 cap.",
             "current_sample": None, "failed_samples": [], "failure_details": {},
             "expected_samples": len(rows), "sample_ids": [int(row["id"]) for row in rows],
             "policy": "Attempt every sample once before repairing or retrying failures"}
    done = collect(names)
    write_json(REPRO / "batch-summary.json", summarize(done, len(rows)))
    for row in rows:
        name = "sample_" + str(int(row["id"])).zfill(4)
        if name in done:
            continue
        attempts = sorted((REPRO / "runs").glob("*/" + name + "/run.json"))
        if attempts:
            state["failed_samples"].append(name)
            state["failure_details"][name] = {"reason": "Existing incomplete or unscored attempt deferred until first pass ends", "directory": str(attempts[-1].parent)}
            state.update(attempted_samples=len(done) + len(state["failed_samples"]))
            write_json(REPRO / "batch-state.json", state)
            print("DEFER", name, "existing attempt preserved", flush=True)
            continue
        state.update(current_sample=name, completed_samples=len(done))
        write_json(REPRO / "batch-state.json", state)
        print("START", name, flush=True)
        log = REPRO / "logs" / ("batch-" + name + ".log")
        with log.open("a") as output:
            process = subprocess.run([sys.executable, "-u", str(REPRO / "run.py"), "--sample-id", row["id"]], stdout=output, stderr=subprocess.STDOUT)
        done = collect(names)
        write_json(REPRO / "batch-summary.json", summarize(done, len(rows)))
        if process.returncode or name not in done:
            state["failed_samples"].append(name)
            state["failure_details"][name] = {"exit_code": process.returncode, "failure_log": str(log)}
            state.update(completed_samples=len(done), attempted_samples=len(done) + len(state["failed_samples"]))
            write_json(REPRO / "batch-state.json", state)
            print("DEFER", name, "exit", process.returncode, "continue first pass", flush=True)
            continue
        print("DONE", name, "completed", len(done), "of", len(rows), flush=True)
    state.update(status="first_pass_complete" if state["failed_samples"] else "complete", current_sample=None, completed_samples=len(done), attempted_samples=len(rows), needs_repair=bool(state["failed_samples"]))
    write_json(REPRO / "batch-state.json", state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
