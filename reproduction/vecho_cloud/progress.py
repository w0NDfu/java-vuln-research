"""Compact, credential-safe snapshot of the latest pilot run."""
import collections
import json
from pathlib import Path

from common import REPRO


def read(path):
    return json.loads(path.read_text())


def snapshot():
    roots = sorted(p for p in (REPRO / "runs").glob("*/sample_*") if p.is_dir())
    if not roots:
        return {"state": "not_started"}
    root = roots[-1]
    result = {"run_directory": str(root), "run": read(root / "run.json") if (root / "run.json").exists() else None, "stages": {}}
    for stage in ("scan", "rescan"):
        path = root / stage / "events.ndjson"
        if not path.exists():
            continue
        events = []
        for line in path.read_text().splitlines():
            try:
                events.append(json.loads(line))
            except ValueError:
                pass
        counts = collections.Counter(x.get("type") for x in events)
        detail = {"events": len(events), "last_event": {k: events[-1].get(k) for k in ("type", "time")} if events else None,
                  "blocks_completed": counts["block_completed"], "seeds_found": counts["seed_found"], "cases_completed": counts["case_completed"],
                  "block_statuses": dict(collections.Counter(x.get("data", {}).get("status", "unknown") for x in events if x.get("type") == "block_completed")),
                  "case_statuses": dict(collections.Counter(x.get("data", {}).get("status", "unknown") for x in events if x.get("type") == "case_completed")),
                  "event_errors": sum(bool(x.get("error")) for x in events)}
        for event in events:
            if event.get("type") == "plan_created":
                detail["planned_blocks"] = len(event.get("data", {}).get("blocks", []))
            if event.get("type") == "contextaudit_started":
                detail["planned_cases"] = event.get("data", {}).get("case_count")
        result["stages"][stage] = detail
        if (root / stage / "usage.json").exists():
            detail["usage"] = read(root / stage / "usage.json")
    summaries = []
    for path in root.glob("**/summary.json"):
        if "judge" in str(path.relative_to(root)):
            summaries.append({"path": str(path.relative_to(root)), "summary": read(path)})
    result["judge_summaries"] = summaries
    if (root / "evaluation.json").exists():
        result["evaluation"] = read(root / "evaluation.json")
    return result


if __name__ == "__main__":
    print(json.dumps(snapshot(), indent=2, ensure_ascii=False))
