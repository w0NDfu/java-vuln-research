from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from .common.io import read_jsonl, write_csv, write_json, write_jsonl


METRIC_FIELDS = [
    "project",
    "status",
    "exit_code",
    "alert_count",
    "path_count",
    "runtime_seconds",
]


def _inventory_count(path: Path, predicate: tuple[str, str] | None = None) -> int | str:
    if not path.is_file():
        return "NOT_APPLICABLE"
    with path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if predicate is None:
        return len(rows)
    key, expected = predicate
    return sum(1 for row in rows if str(row.get(key, "")).lower() == expected.lower())


def generate_e0_report(
    *,
    raw_run_dir: str | Path,
    report_dir: str | Path,
) -> dict[str, Any]:
    raw_dir = Path(raw_run_dir)
    target = Path(report_dir)
    target.mkdir(parents=True, exist_ok=True)

    manifest_path = raw_dir / "run_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    baseline_path = raw_dir / "baseline" / "baseline_output.jsonl"
    rows = read_jsonl(baseline_path) if baseline_path.is_file() else []
    successes = [row for row in rows if row.get("status") == "SUCCESS"]
    failures = [row for row in rows if row.get("status") != "SUCCESS"]
    no_runnable_projects = int(manifest["projects_runnable"]) == 0
    infrastructure_failures = (
        [
            {
                "project": "infrastructure",
                "status": "FAILED",
                "stage": "DATASET_AND_DATABASE_INVENTORY",
                "exit_code": None,
                "error_class": "NO_RUNNABLE_PROJECTS",
            }
        ]
        if no_runnable_projects
        else []
    )
    failure_records = [*failures, *infrastructure_failures]

    alert_count = sum(int(row.get("alert_count", 0)) for row in successes)
    path_count = sum(int(row.get("path_count", 0)) for row in successes)
    summary = {
        "run_id": manifest["run_id"],
        "status": manifest["status"],
        "git_commit": manifest["git_commit"],
        "projects_requested": manifest["projects_requested"],
        "projects_runnable": manifest["projects_runnable"],
        "projects_success": len(successes),
        "projects_failed": len(failures),
        "baseline_alerts": alert_count,
        "baseline_paths": path_count,
        "new_inputs": "NOT_APPLICABLE",
        "new_effects": "NOT_APPLICABLE",
        "semantic_candidates": "NOT_APPLICABLE",
        "validated_candidates": "NOT_APPLICABLE",
        "new_strict_detections": "NOT_APPLICABLE",
    }

    write_json(target / "run_manifest.json", manifest)
    write_json(target / "summary.json", summary)
    write_csv(target / "metrics.csv", METRIC_FIELDS, rows)
    write_jsonl(target / "failures.jsonl", failure_records)

    inventory_dir = raw_dir / "inventory"
    dataset_inventory = inventory_dir / "dataset_inventory.csv"
    database_inventory = inventory_dir / "codeql_db_inventory.csv"
    dataset_count = _inventory_count(dataset_inventory)
    database_count = _inventory_count(database_inventory)
    ready_database_count = _inventory_count(database_inventory, ("db_ready", "true"))
    failure_lines = (
        "\n".join(
            f"- `{row.get('project')}`: {row.get('stage', 'UNKNOWN')} / "
            f"{row.get('error_class', 'UNKNOWN')} (exit={row.get('exit_code')})"
            for row in failure_records
        )
        if failure_records
        else "- None"
    )
    report = f"""# {manifest['run_id']} — MSA-P0-E0 frozen baseline

## Status

- Status: `{manifest['status']}`
- Git commit: `{manifest['git_commit']}`
- Git branch: `{manifest['git_branch']}`
- Started: `{manifest['timestamp_start']}`
- Finished: `{manifest['timestamp_end']}`

## Cloud environment

- CodeQL: `{manifest.get('codeql_version') or 'NOT_APPLICABLE'}`
- Java: `{manifest.get('java_version') or 'NOT_APPLICABLE'}`
- Maven: `{manifest.get('maven_version') or 'NOT_APPLICABLE'}`
- Gradle: `{manifest.get('gradle_version') or 'NOT_APPLICABLE'}`
- Python: `{manifest.get('python_version') or 'NOT_APPLICABLE'}`

## Inventory

- Dataset inventory rows: `{dataset_count}`
- CodeQL database inventory rows: `{database_count}`
- Ready CodeQL databases: `{ready_database_count}`

## Frozen baseline summary

- Projects requested: `{manifest['projects_requested']}`
- Projects runnable: `{manifest['projects_runnable']}`
- Projects succeeded: `{len(successes)}`
- Projects failed: `{len(failures)}`
- Native baseline alerts: `{alert_count}`
- Native baseline paths: `{path_count}`

## Failures

{failure_lines}

## Scientific interpretation

This run measures infrastructure reproducibility and a frozen native-CodeQL
reference point. It does not measure semantic-overlay gains and does not treat
failed projects as negative samples. Ground truth was not available to the
Detector.

## Next action

{('Resolve recorded execution failures and rerun the same frozen configuration.' if failure_records else 'Verify all eight E0 gates; only then create exp/msa-p0-a-discovery.')}
"""
    (target / "report.md").write_text(report, encoding="utf-8")
    return summary
