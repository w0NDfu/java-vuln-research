from __future__ import annotations

from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

from ..common.contracts import load_detector_manifest
from ..common.io import read_jsonl, write_json
from ..common.paths import same_program_file
from .coverage import (
    NOT_EVALUABLE,
    CandidateCoverageError,
    _optional_int,
    _read_csv,
    _safe_name,
    _sarif_locations,
)


def _distance_to_interval(line: int, start: int, end: int) -> int:
    if start <= line <= end:
        return 0
    return start - line if line < start else line - end


def _distance_bucket(distance: int) -> str:
    if distance == 0:
        return "0"
    if distance <= 5:
        return "1-5"
    if distance <= 20:
        return "6-20"
    if distance <= 100:
        return "21-100"
    return ">100"


def evaluate_e0_sanity(
    *, detector_manifest: str | Path, project_info_csv: str | Path,
    fix_info_csv: str | Path, baseline_raw_dir: str | Path, output_root: str | Path,
) -> dict[str, Any]:
    """Audit E0 parsing and location matching without informing the detector."""

    projects = load_detector_manifest(detector_manifest)
    project_rows = _read_csv(
        project_info_csv, {"project_slug", "cve_id", "buggy_commit_id"}
    )
    fix_rows = _read_csv(
        fix_info_csv, {"project_slug", "cve_id", "file", "method_start", "method_end"}
    )
    dataset_by_revision = {
        row["buggy_commit_id"].strip().casefold(): row
        for row in project_rows
        if row["buggy_commit_id"].strip()
    }
    fixes_by_case: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in fix_rows:
        fixes_by_case[(row["project_slug"].strip(), row["cve_id"].strip())].append(row)

    baseline_root = Path(baseline_raw_dir)
    baseline_output = baseline_root / "baseline" / "baseline_output.jsonl"
    try:
        baseline_rows = read_jsonl(baseline_output)
    except (OSError, ValueError) as error:
        raise CandidateCoverageError(f"invalid E0 baseline output: {error}") from error
    native_path_count = sum(int(row.get("path_count", 0)) for row in baseline_rows)
    native_alert_count = sum(int(row.get("alert_count", 0)) for row in baseline_rows)

    project_results: list[dict[str, Any]] = []
    distances: list[int] = []
    same_file_count = 0
    same_method_count = 0
    exact_line_overlap_count = 0
    exact_line_evaluable = 0
    native_location_count = 0
    revision_match_count = 0
    revision_mismatch_count = 0
    not_evaluable_count = 0

    for project in projects:
        project_id, revision = project["project"], project["revision"]
        dataset = dataset_by_revision.get(revision.casefold())
        if dataset is None:
            revision_mismatch_count += 1
            not_evaluable_count += 1
            project_results.append(
                {"project_id": project_id, "status": "NOT_EVALUABLE", "reason": "REVISION_NOT_FOUND"}
            )
            continue
        revision_match_count += 1
        case_key = (dataset["project_slug"].strip(), dataset["cve_id"].strip())
        fixes = fixes_by_case.get(case_key, [])
        sarif = baseline_root / "baseline" / f"{_safe_name(project_id)}.sarif"
        locations = _sarif_locations(sarif)
        native_location_count += len(locations)
        if not fixes or not sarif.is_file():
            not_evaluable_count += 1
            project_results.append(
                {
                    "project_id": project_id,
                    "status": "NOT_EVALUABLE",
                    "reason": "FIX_INFO_MISSING" if not fixes else "SARIF_MISSING",
                    "native_location_count": len(locations),
                }
            )
            continue

        project_same_file = 0
        project_same_method = 0
        project_exact = 0
        project_exact_evaluable = 0
        project_distances: list[int] = []
        for location in locations:
            matching_fixes = [
                fix for fix in fixes if same_program_file(str(location["file"]), fix["file"])
            ]
            if not matching_fixes:
                continue
            project_same_file += 1
            same_file_count += 1
            for fix in matching_fixes:
                method_start = _optional_int(fix.get("method_start"), field="method_start")
                method_end = _optional_int(fix.get("method_end"), field="method_end")
                if method_start is None or method_end is None:
                    continue
                distance = _distance_to_interval(int(location["line"]), method_start, method_end)
                project_distances.append(distance)
                distances.append(distance)
                if distance == 0:
                    project_same_method += 1
                    same_method_count += 1

                line_start = _optional_int(
                    fix.get("line_start") or fix.get("start_line") or fix.get("line"),
                    field="line_start",
                )
                line_end = _optional_int(
                    fix.get("line_end") or fix.get("end_line") or fix.get("line"),
                    field="line_end",
                )
                if line_start is not None and line_end is not None:
                    project_exact_evaluable += 1
                    exact_line_evaluable += 1
                    if line_start <= int(location["line"]) <= line_end:
                        project_exact += 1
                        exact_line_overlap_count += 1
        project_results.append(
            {
                "project_id": project_id,
                "status": "EVALUABLE",
                "revision_match": True,
                "native_location_count": len(locations),
                "same_file_count": project_same_file,
                "same_method_count_if_available": project_same_method,
                "exact_line_overlap_count": project_exact if project_exact_evaluable else NOT_EVALUABLE,
                "nearest_line_distance": min(project_distances) if project_distances else NOT_EVALUABLE,
            }
        )

    distance_distribution = dict(
        sorted(Counter(_distance_bucket(distance) for distance in distances).items())
    )
    summary: dict[str, Any] = {
        "status": "SUCCESS",
        "projects_total": len(projects),
        "native_alert_count": native_alert_count,
        "native_path_count": native_path_count,
        "native_location_count": native_location_count,
        "same_file_count": same_file_count,
        "same_method_count_if_available": same_method_count if distances else NOT_EVALUABLE,
        "exact_line_overlap_count": exact_line_overlap_count if exact_line_evaluable else NOT_EVALUABLE,
        "nearest_line_distance_distribution": distance_distribution,
        "not_evaluable_count": not_evaluable_count,
        "revision_match_count": revision_match_count,
        "revision_mismatch_count": revision_mismatch_count,
        "path_normalization": "COMMON_URI_AND_SUFFIX_NORMALIZATION_V1",
        "sarif_locations_include_thread_flows": True,
        "detector_ground_truth_access": False,
        "projects": project_results,
    }
    target = Path(output_root)
    write_json(target / "e0_evaluator_sanity.json", summary)
    markdown = f"""# E0 evaluator sanity check

- Native alerts: `{native_alert_count}`
- Native paths: `{native_path_count}`
- Native SARIF locations parsed: `{native_location_count}`
- Same-file locations: `{same_file_count}`
- Same-method locations: `{summary['same_method_count_if_available']}`
- Exact-line overlaps: `{summary['exact_line_overlap_count']}`
- Nearest-line distance distribution: `{distance_distribution}`
- Not-evaluable projects: `{not_evaluable_count}`
- Revision matches/mismatches: `{revision_match_count}/{revision_mismatch_count}`

The check uses the same common URI/path normalizer and SARIF parser as the
coverage evaluator. It runs only after E0 and W1-E1 detector artifacts exist;
the detector does not read `project_info.csv`, `fix_info.csv`, or this report.
"""
    (target / "e0_evaluator_sanity.md").write_text(markdown, encoding="utf-8")
    return summary
