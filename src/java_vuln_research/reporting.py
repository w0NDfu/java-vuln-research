from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .common.io import read_jsonl, write_csv, write_json, write_jsonl
from .common.contracts import load_detector_manifest
from .common.provenance import utc_now
from .common.run_manifest import RunManifest


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


def generate_w1_e1_report(
    *,
    run_id: str,
    raw_run_dir: str | Path,
    baseline_raw_dir: str | Path,
    project_root: str | Path,
    dataset_name: str,
    dataset_revision: str,
    detector_manifest: str | Path,
    config: str | Path,
    started_at: str,
    command: str,
) -> dict[str, Any]:
    """Merge already-frozen detector and evaluator outputs into a W1-E1 report."""

    raw_dir = Path(raw_run_dir)
    detector = json.loads((raw_dir / "detector_metrics.json").read_text(encoding="utf-8"))
    coverage = json.loads((raw_dir / "coverage_metrics.json").read_text(encoding="utf-8"))
    sanity_path = raw_dir / "e0_evaluator_sanity.json"
    sanity = json.loads(sanity_path.read_text(encoding="utf-8")) if sanity_path.is_file() else {}
    baseline_rows = read_jsonl(
        Path(baseline_raw_dir) / "baseline" / "baseline_output.jsonl"
    )
    baseline_paths = sum(
        int(row.get("path_count", 0))
        for row in baseline_rows
        if row.get("status") == "SUCCESS"
    )
    candidate_paths = int(detector["candidate_paths_total"])
    expansion_factor: float | str = (
        round(candidate_paths / baseline_paths, 6) if baseline_paths else "NOT_EVALUABLE"
    )
    projects_runnable = int(detector["projects_runnable"])
    manifest_projects = load_detector_manifest(detector_manifest)
    manifest_builder = RunManifest(
        run_id=run_id,
        experiment="W1-E1-CANDIDATE-PATH-COVERAGE",
        project_root=Path(project_root),
        dataset_name=dataset_name,
        dataset_revision=dataset_revision,
        config_paths=[Path(config), Path(detector_manifest)],
        semantic_rule_paths=[Path(project_root) / "codeql" / "candidate_path"],
        prompt_paths=[],
    )
    manifest = manifest_builder.finish(
        raw_dir / "run_manifest.json",
        projects_requested=int(detector["projects_total"]),
        projects_runnable=projects_runnable,
        projects_build_failed="NOT_APPLICABLE",
        status=str(detector["status"]),
    )
    finished_at = utc_now()
    try:
        wall_clock_seconds: float | str = round(
            (
                datetime.fromisoformat(finished_at.replace("Z", "+00:00"))
                - datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            ).total_seconds(),
            3,
        )
    except ValueError:
        wall_clock_seconds = "NOT_AVAILABLE"
    manifest.update(
        {
            "timestamp_start": started_at,
            "timestamp_end": finished_at,
            "start_time": started_at,
            "end_time": finished_at,
            "wall_clock_seconds": wall_clock_seconds,
            "experiment_id": run_id,
            "projects": [
                {
                    "project_id": project["project"],
                    "revision": project["revision"],
                    "db_id": project["codeql_db_path"],
                }
                for project in manifest_projects
            ],
            "candidate_schema_version": 2,
            "analysis_anchor_schema_version": 1,
            "structural_frontier_schema_version": 1,
            "evaluator_version": "W1-E1-COVERAGE-v2",
            "detector_ground_truth_access": False,
            "command": command,
            "exit_code": 0 if detector["status"] == "SUCCESS" else 2,
        }
    )
    write_json(raw_dir / "run_manifest.json", manifest)
    summary = {
        **detector,
        "ground_truth_evaluable": coverage["ground_truth_evaluable"],
        "evaluable_vulnerabilities": coverage["evaluable_vulnerabilities"],
        "file_level_coverage": coverage["file_level_covered"],
        "method_level_coverage": coverage["method_level_covered"],
        "line_level_coverage": coverage["line_level_covered"],
        "baseline_coverage": coverage["baseline_coverage"],
        "e1_coverage": coverage["e1_coverage"],
        "baseline_miss_recovered": coverage["baseline_miss_recovered"],
        "recovered_case_ids": coverage["recovered_case_ids"],
        "candidate_expansion_factor": expansion_factor,
        "runtime_seconds": manifest["wall_clock_seconds"],
        "peak_memory": "NOT_AVAILABLE",
        "run_id": run_id,
        "detector_ground_truth_access": False,
        "e0_evaluator_sanity": sanity,
        "scientific_method_changed": detector.get("scientific_method_changed", "NO"),
    }
    write_json(raw_dir / "metrics.json", summary)
    report = f"""# {run_id} — W1-E1 Candidate Path Coverage

## Status

- Status: `{detector['status']}`
- Commit: `{manifest['git_commit']}`
- Projects runnable: `{projects_runnable}` / `{detector['projects_total']}`

## Candidate-path output

- External input candidates: `{detector['external_input_candidates']}`
- Security effect candidates: `{detector['security_effect_candidates']}`
- Input anchors mappable: `{detector.get('input_anchor_mappable', 'NOT_AVAILABLE')}`
- FW-active inputs: `{detector.get('fw_active_inputs', 'NOT_AVAILABLE')}`
- Effect anchors mappable: `{detector.get('effect_anchor_mappable', 'NOT_AVAILABLE')}`
- BW-active effects: `{detector.get('bw_active_effects', 'NOT_AVAILABLE')}`
- Static connected paths: `{detector['static_connected_paths']}`
- Frontier candidate paths: `{detector['frontier_candidate_paths']}`
- Structural frontier diagnostics: `{detector.get('structural_frontier_count', 0)}`
- Frontier reasons: `{detector['frontier_reason_counts']}`
- Failure taxonomy: `{detector.get('failure_taxonomy_counts', {})}`
- Candidate expansion factor: `{expansion_factor}`

## Independent coverage evaluation

- Ground-truth evaluable cases: `{coverage['ground_truth_evaluable']}`
- File-level coverage: `{coverage['file_level_covered']}`
- Method-level coverage: `{coverage['method_level_covered']}`
- Line-level coverage: `{coverage['line_level_covered']}`
- E0 coverage: `{coverage['baseline_coverage']}`
- W1-E1 coverage: `{coverage['e1_coverage']}`
- Baseline-miss recovery: `{coverage['baseline_miss_recovered']}`

## E0 evaluator sanity

- Native paths parsed: `{sanity.get('native_path_count', 'NOT_AVAILABLE')}`
- Same-file locations: `{sanity.get('same_file_count', 'NOT_AVAILABLE')}`
- Same-method locations: `{sanity.get('same_method_count_if_available', 'NOT_AVAILABLE')}`
- Exact-line overlaps: `{sanity.get('exact_line_overlap_count', 'NOT_AVAILABLE')}`
- Revision mismatches: `{sanity.get('revision_mismatch_count', 'NOT_AVAILABLE')}`

## Scientific-method boundary

- `scientific_method_changed = {detector.get('scientific_method_changed', 'NO')}`

## Boundary

The detector persisted `candidate_paths.jsonl` before the evaluator read
ground-truth files. `candidate_type_hypothesis` remains a hypothesis; this run
does not confirm vulnerabilities or CWE verdicts.
"""
    (raw_dir / "summary.md").write_text(report, encoding="utf-8")
    return summary
