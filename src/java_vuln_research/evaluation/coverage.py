from __future__ import annotations

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..common.contracts import load_detector_manifest
from ..common.io import read_jsonl, write_json, write_jsonl


NOT_EVALUABLE = "NOT_EVALUABLE"


class CandidateCoverageError(ValueError):
    """Raised when a W1-E1 coverage result would be incomplete or ambiguous."""


def _read_csv(path: str | Path, required: set[str]) -> list[dict[str, str]]:
    source = Path(path)
    if not source.is_file():
        raise CandidateCoverageError(f"missing CSV: {source}")
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise CandidateCoverageError(f"CSV has no header: {source}")
        missing = required - set(reader.fieldnames)
        if missing:
            raise CandidateCoverageError(
                f"CSV {source} is missing required columns: {', '.join(sorted(missing))}"
            )
        return [dict(row) for row in reader]


def _normalise_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./").lower()


def _same_file(left: str, right: str) -> bool:
    left_path, right_path = _normalise_path(left), _normalise_path(right)
    return bool(left_path and right_path) and (
        left_path == right_path
        or left_path.endswith("/" + right_path)
        or right_path.endswith("/" + left_path)
    )


def _optional_int(value: str | None, *, field: str) -> int | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError as error:
        raise CandidateCoverageError(f"invalid {field}: {text!r}") from error


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "project"


def _physical_location(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    location = value.get("physicalLocation")
    if not isinstance(location, Mapping):
        return None
    artifact = location.get("artifactLocation")
    region = location.get("region")
    if not isinstance(artifact, Mapping) or not isinstance(region, Mapping):
        return None
    uri = artifact.get("uri")
    line = region.get("startLine")
    try:
        return {"file": str(uri), "line": int(line)}
    except (TypeError, ValueError):
        return None


def _sarif_locations(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidateCoverageError(f"invalid SARIF: {path}: {error}") from error
    result: list[dict[str, Any]] = []
    for run in document.get("runs", []):
        if not isinstance(run, Mapping):
            continue
        for finding in run.get("results", []) or []:
            if not isinstance(finding, Mapping):
                continue
            for location in finding.get("locations", []) or []:
                physical = _physical_location(location)
                if physical:
                    result.append(physical)
            for code_flow in finding.get("codeFlows", []) or []:
                if not isinstance(code_flow, Mapping):
                    continue
                for thread_flow in code_flow.get("threadFlows", []) or []:
                    if not isinstance(thread_flow, Mapping):
                        continue
                    for thread_location in thread_flow.get("locations", []) or []:
                        if not isinstance(thread_location, Mapping):
                            continue
                        physical = _physical_location(thread_location.get("location"))
                        if physical:
                            result.append(physical)
    return result


def _path_locations(candidate: Mapping[str, Any]) -> list[dict[str, Any]]:
    locations = candidate.get("source_locations")
    if not isinstance(locations, list) or not locations:
        raise CandidateCoverageError(
            f"candidate path {candidate.get('candidate_path_id', '<missing>')} has no source_locations"
        )
    result: list[dict[str, Any]] = []
    for location in locations:
        if not isinstance(location, Mapping):
            raise CandidateCoverageError("candidate source location must be an object")
        try:
            file_name, line = str(location["file"]), int(location["line"])
        except (KeyError, TypeError, ValueError) as error:
            raise CandidateCoverageError("candidate source location needs file and line") from error
        if not file_name or line < 1:
            raise CandidateCoverageError("candidate source location needs non-empty file and positive line")
        result.append({"file": file_name, "line": line})
    return result


def _coverage_for_locations(
    locations: Iterable[Mapping[str, Any]], fixes: Iterable[Mapping[str, str]]
) -> tuple[bool, bool | str, str]:
    file_covered = False
    method_evaluable = False
    method_covered = False
    for fix in fixes:
        method_start = _optional_int(fix.get("method_start"), field="method_start")
        method_end = _optional_int(fix.get("method_end"), field="method_end")
        if (method_start is None) != (method_end is None):
            raise CandidateCoverageError("fix_info method_start and method_end must be both present or absent")
        if method_start is not None and method_end is not None:
            method_evaluable = True
            if method_end < method_start:
                raise CandidateCoverageError("fix_info method_end precedes method_start")
        for location in locations:
            if not _same_file(str(location["file"]), fix["file"]):
                continue
            file_covered = True
            if method_start is not None and method_start <= int(location["line"]) <= method_end:
                method_covered = True
    return file_covered, method_covered if method_evaluable else NOT_EVALUABLE, NOT_EVALUABLE


def _count_true(rows: Iterable[Mapping[str, Any]], key: str) -> int:
    return sum(1 for row in rows if row.get(key) is True)


def _coverage_rate(covered: int, evaluable: int) -> float | str:
    return round(covered / evaluable, 6) if evaluable else NOT_EVALUABLE


def evaluate_candidate_coverage(
    *,
    candidate_paths_file: str | Path,
    detector_manifest: str | Path,
    project_info_csv: str | Path,
    fix_info_csv: str | Path,
    baseline_raw_dir: str | Path,
    output_root: str | Path,
) -> dict[str, Any]:
    """Evaluate frozen W1-E1 path output; never invoke or inform the detector."""

    try:
        candidate_paths = read_jsonl(candidate_paths_file)
    except (OSError, ValueError) as error:
        raise CandidateCoverageError(f"invalid candidate paths: {error}") from error
    projects = load_detector_manifest(detector_manifest)
    project_by_id = {project["project"]: project for project in projects}
    project_rows = _read_csv(project_info_csv, {"project_slug", "cve_id", "buggy_commit_id"})
    fix_rows = _read_csv(
        fix_info_csv,
        {"project_slug", "cve_id", "file", "method_start", "method_end"},
    )

    dataset_by_revision = {
        row["buggy_commit_id"].strip().lower(): row
        for row in project_rows
        if row["buggy_commit_id"].strip() and row["project_slug"].strip() and row["cve_id"].strip()
    }
    case_by_project: dict[str, dict[str, str]] = {}
    for project_id, project in project_by_id.items():
        row = dataset_by_revision.get(project["revision"].lower())
        if row:
            case_by_project[project_id] = row

    fixes_by_case: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in fix_rows:
        slug, cve = row["project_slug"].strip(), row["cve_id"].strip()
        if slug and cve:
            fixes_by_case[(slug, cve)].append(row)

    paths_by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in candidate_paths:
        project_id = str(path.get("project_id", ""))
        if project_id not in project_by_id:
            raise CandidateCoverageError(f"candidate path has unknown project_id: {project_id!r}")
        _path_locations(path)
        paths_by_project[project_id].append(path)

    baseline_root = Path(baseline_raw_dir)
    cases: list[dict[str, Any]] = []
    recoveries: list[dict[str, Any]] = []
    for project_id in sorted(case_by_project):
        dataset = case_by_project[project_id]
        slug, cve = dataset["project_slug"], dataset["cve_id"]
        fixes = fixes_by_case.get((slug, cve), [])
        if not fixes:
            continue
        path_rows = paths_by_project.get(project_id, [])
        candidate_locations = [location for path in path_rows for location in _path_locations(path)]
        e1_file, e1_method, e1_line = _coverage_for_locations(candidate_locations, fixes)

        baseline_sarif = baseline_root / "baseline" / f"{_safe_name(project_id)}.sarif"
        if baseline_sarif.is_file():
            baseline_file, baseline_method, baseline_line = _coverage_for_locations(
                _sarif_locations(baseline_sarif), fixes
            )
            baseline_status = "EVALUABLE"
        else:
            baseline_file = baseline_method = baseline_line = NOT_EVALUABLE
            baseline_status = "NOT_EVALUABLE"

        comparison_level = "METHOD" if e1_method != NOT_EVALUABLE else "FILE"
        e1_covered = e1_method if comparison_level == "METHOD" else e1_file
        baseline_covered = (
            baseline_method if comparison_level == "METHOD" else baseline_file
        )
        if baseline_status == "NOT_EVALUABLE":
            baseline_covered = NOT_EVALUABLE
        case = {
            "case_id": f"{slug}:{cve}",
            "project_id": project_id,
            "project_slug": slug,
            "cve_id": cve,
            "comparison_level": comparison_level,
            "file_level_covered": e1_file,
            "method_level_covered": e1_method,
            "line_level_covered": e1_line,
            "candidate_covered": e1_covered,
            "candidate_path_ids": sorted(
                str(path.get("candidate_path_id")) for path in path_rows
            ),
            "baseline_status": baseline_status,
            "baseline_file_level_covered": baseline_file,
            "baseline_method_level_covered": baseline_method,
            "baseline_line_level_covered": baseline_line,
            "baseline_covered": baseline_covered,
        }
        cases.append(case)
        if baseline_covered is False and e1_covered is True:
            recoveries.append(
                {
                    "case_id": case["case_id"],
                    "project_id": project_id,
                    "comparison_level": comparison_level,
                    "candidate_path_ids": case["candidate_path_ids"],
                    "reason": "E0_MISSED_AND_W1_E1_CANDIDATE_COVERED",
                }
            )

    method_evaluable = [row for row in cases if row["method_level_covered"] != NOT_EVALUABLE]
    baseline_evaluable = [row for row in cases if row["baseline_covered"] != NOT_EVALUABLE]
    candidate_covered = _count_true(cases, "candidate_covered")
    baseline_covered = _count_true(baseline_evaluable, "baseline_covered")
    summary: dict[str, Any] = {
        "status": "SUCCESS",
        "projects_total": len(projects),
        "projects_with_ground_truth": len(case_by_project),
        "ground_truth_evaluable": len(cases),
        "evaluable_vulnerabilities": len(cases),
        "file_level_covered": _count_true(cases, "file_level_covered"),
        "file_level_coverage_rate": _coverage_rate(_count_true(cases, "file_level_covered"), len(cases)),
        "method_level_covered": _count_true(method_evaluable, "method_level_covered"),
        "method_level_evaluable": len(method_evaluable),
        "method_level_coverage_rate": _coverage_rate(_count_true(method_evaluable, "method_level_covered"), len(method_evaluable)),
        "line_level_covered": NOT_EVALUABLE,
        "line_level_coverage_rate": NOT_EVALUABLE,
        "candidate_covered_total": candidate_covered,
        "candidate_coverage_rate": _coverage_rate(candidate_covered, len(cases)),
        "baseline_evaluable": len(baseline_evaluable),
        "baseline_coverage": baseline_covered,
        "e1_coverage": sum(1 for row in baseline_evaluable if row["candidate_covered"] is True),
        "baseline_missed": sum(1 for row in baseline_evaluable if row["baseline_covered"] is False),
        "baseline_miss_recovered": len(recoveries),
        "recovered_case_ids": [row["case_id"] for row in recoveries],
        "candidate_paths_total": len(candidate_paths),
        "evaluation_basis": "FIX_INFO_FILE_AND_METHOD_RANGE",
        "detector_ground_truth_access": False,
    }
    target = Path(output_root)
    write_json(target / "coverage_metrics.json", summary)
    write_json(target / "metrics.json", summary)
    write_jsonl(target / "coverage_cases.jsonl", cases)
    write_jsonl(target / "baseline_miss_recovery.jsonl", recoveries)
    return summary
