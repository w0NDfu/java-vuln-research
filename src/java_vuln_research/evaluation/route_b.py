from __future__ import annotations

import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..common.contracts import load_detector_manifest
from ..common.io import read_jsonl, write_json, write_jsonl


NOT_EVALUABLE = "NOT_EVALUABLE"


class RouteBEvaluationError(ValueError):
    """Raised when frozen Route B artifacts cannot be evaluated independently."""


def _read_csv(path: str | Path, required: set[str]) -> list[dict[str, str]]:
    source = Path(path)
    if not source.is_file():
        raise RouteBEvaluationError(f"missing CSV: {source}")
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise RouteBEvaluationError(f"CSV has no header: {source}")
        missing = required - set(reader.fieldnames)
        if missing:
            raise RouteBEvaluationError(
                f"CSV {source} is missing required columns: {', '.join(sorted(missing))}"
            )
        return [dict(row) for row in reader]


def _normalise_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./").lower()


def _same_file(candidate: str, fix: str) -> bool:
    candidate_path, fix_path = _normalise_path(candidate), _normalise_path(fix)
    return bool(candidate_path and fix_path) and (
        candidate_path == fix_path
        or candidate_path.endswith("/" + fix_path)
        or fix_path.endswith("/" + candidate_path)
    )


def _optional_int(value: str | None) -> int | None:
    text = (value or "").strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError as error:
        raise RouteBEvaluationError(f"invalid integer in fix data: {text!r}") from error


def _locations(path: Mapping[str, Any]) -> list[dict[str, Any]]:
    values = path.get("source_locations")
    if not isinstance(values, list) or not values:
        raise RouteBEvaluationError(
            f"candidate path {path.get('candidate_path_id', '<missing>')} has no locations"
        )
    result: list[dict[str, Any]] = []
    for value in values:
        if not isinstance(value, Mapping):
            raise RouteBEvaluationError("candidate path location must be an object")
        try:
            file_name, line = str(value["file"]), int(value["line"])
        except (KeyError, TypeError, ValueError) as error:
            raise RouteBEvaluationError("candidate path location needs file and line") from error
        if not file_name or line < 1:
            raise RouteBEvaluationError("candidate path location needs non-empty file and positive line")
        result.append({"file": file_name, "line": line})
    return result


def _path_coverage(
    paths: Iterable[Mapping[str, Any]], fixes: Iterable[Mapping[str, str]],
) -> tuple[bool, bool | str, list[str]]:
    fix_rows = list(fixes)
    file_covered = False
    method_evaluable = any(
        _optional_int(row.get("method_start")) is not None
        and _optional_int(row.get("method_end")) is not None
        for row in fix_rows
    )
    method_covered = False
    matching_path_ids: list[str] = []
    for path in paths:
        path_file_match = False
        path_method_match = False
        for fix in fix_rows:
            method_start = _optional_int(fix.get("method_start"))
            method_end = _optional_int(fix.get("method_end"))
            if (method_start is None) != (method_end is None):
                raise RouteBEvaluationError("method_start and method_end must both be present or absent")
            if method_start is not None and method_end is not None and method_end < method_start:
                raise RouteBEvaluationError("method_end precedes method_start")
            for location in _locations(path):
                if not _same_file(str(location["file"]), str(fix["file"])):
                    continue
                path_file_match = True
                if method_start is not None and method_end is not None and method_start <= int(location["line"]) <= method_end:
                    path_method_match = True
        file_covered = file_covered or path_file_match
        method_covered = method_covered or path_method_match
        if path_method_match if method_evaluable else path_file_match:
            matching_path_ids.append(str(path.get("candidate_path_id")))
    return file_covered, method_covered if method_evaluable else NOT_EVALUABLE, sorted(set(matching_path_ids))


def _rate(covered: int, evaluable: int) -> float | str:
    return round(covered / evaluable, 6) if evaluable else NOT_EVALUABLE


def _case_covered(file_covered: bool, method_covered: bool | str) -> tuple[bool, str]:
    if method_covered != NOT_EVALUABLE:
        return bool(method_covered), "METHOD"
    return file_covered, "FILE"


def _coverage_count(
    case_specs: Iterable[Mapping[str, Any]], paths_by_project: Mapping[str, list[dict[str, Any]]],
) -> int:
    covered = 0
    for case in case_specs:
        file_covered, method_covered, _ = _path_coverage(
            paths_by_project.get(str(case["project_id"]), []), case["fixes"]
        )
        value, _ = _case_covered(file_covered, method_covered)
        covered += value
    return covered


def evaluate_p0_b_route_b(
    *, native_pool_path: str | Path, unified_pool_path: str | Path,
    detector_manifest: str | Path, project_info_csv: str | Path,
    fix_info_csv: str | Path, output_root: str | Path,
) -> dict[str, Any]:
    """Post-hoc GT evaluator. Detector artifacts must already be frozen."""

    native_source = Path(native_pool_path)
    unified_source = Path(unified_pool_path)
    run_manifest_path = unified_source.parent / "run_manifest.json"
    if not run_manifest_path.is_file():
        raise RouteBEvaluationError("detector run_manifest.json must exist before GT evaluation")
    try:
        import json
        run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RouteBEvaluationError("invalid detector run_manifest.json") from error
    if run_manifest.get("detector_frozen") is not True:
        raise RouteBEvaluationError("detector artifacts are not marked frozen")
    if run_manifest.get("detector_ground_truth_access") is not False:
        raise RouteBEvaluationError("detector non-access boundary is not proven")

    native_paths = read_jsonl(native_source)
    unified_paths = read_jsonl(unified_source)
    native_ids = {str(row.get("candidate_path_id")) for row in native_paths}
    unified_ids = {str(row.get("candidate_path_id")) for row in unified_paths}
    if not native_ids <= unified_ids:
        raise RouteBEvaluationError("UnifiedPool does not retain every native path")
    static_paths = [row for row in unified_paths if row.get("path_origin") == "STATIC_AUGMENTED"]

    projects = load_detector_manifest(detector_manifest)
    project_by_id = {row["project"]: row for row in projects}
    project_rows = _read_csv(project_info_csv, {"project_slug", "cve_id", "buggy_commit_id"})
    fix_rows = _read_csv(fix_info_csv, {"project_slug", "cve_id", "file", "method_start", "method_end"})
    by_revision = {
        row["buggy_commit_id"].strip().lower(): row
        for row in project_rows if row["buggy_commit_id"].strip()
    }
    fixes_by_case: dict[tuple[str, str], list[dict[str, str]]] = defaultdict(list)
    for row in fix_rows:
        slug, cve = row["project_slug"].strip(), row["cve_id"].strip()
        if slug and cve:
            fixes_by_case[(slug, cve)].append(row)

    native_by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    unified_by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    static_by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in native_paths:
        native_by_project[str(row.get("project_id"))].append(row)
    for row in unified_paths:
        unified_by_project[str(row.get("project_id"))].append(row)
    for row in static_paths:
        static_by_project[str(row.get("project_id"))].append(row)

    case_specs: list[dict[str, Any]] = []
    for project_id, project in project_by_id.items():
        dataset = by_revision.get(project["revision"].lower())
        if dataset is None:
            continue
        slug, cve = dataset["project_slug"].strip(), dataset["cve_id"].strip()
        fixes = fixes_by_case.get((slug, cve), [])
        if not fixes:
            continue
        case_specs.append({
            "project_id": project_id,
            "project_slug": slug,
            "cve_id": cve,
            "cwe_id": (dataset.get("cwe_id") or dataset.get("cwe") or "").strip() or NOT_EVALUABLE,
            "fixes": fixes,
        })

    cases: list[dict[str, Any]] = []
    recoveries: list[dict[str, Any]] = []
    for spec in case_specs:
        project_id = str(spec["project_id"])
        native_file, native_method, native_matches = _path_coverage(native_by_project.get(project_id, []), spec["fixes"])
        unified_file, unified_method, unified_matches = _path_coverage(unified_by_project.get(project_id, []), spec["fixes"])
        native_covered, comparison_level = _case_covered(native_file, native_method)
        unified_covered, _ = _case_covered(unified_file, unified_method)
        case = {
            "case_id": f"{spec['project_slug']}:{spec['cve_id']}",
            "project_id": project_id,
            "project_slug": spec["project_slug"],
            "cve_id": spec["cve_id"],
            "cwe_id": spec["cwe_id"],
            "comparison_level": comparison_level,
            "native_file_level_covered": native_file,
            "native_method_level_covered": native_method,
            "native_line_level_covered": NOT_EVALUABLE,
            "native_candidate_covered": native_covered,
            "native_candidate_path_ids": native_matches,
            "unified_file_level_covered": unified_file,
            "unified_method_level_covered": unified_method,
            "unified_line_level_covered": NOT_EVALUABLE,
            "unified_candidate_covered": unified_covered,
            "unified_candidate_path_ids": unified_matches,
        }
        cases.append(case)
        if not native_covered and unified_covered:
            for path in static_by_project.get(project_id, []):
                file_match, method_match, path_matches = _path_coverage([path], spec["fixes"])
                path_covered, _ = _case_covered(file_match, method_match)
                if not path_covered:
                    continue
                provenance = path.get("provenance") or {}
                recoveries.append({
                    "case_id": case["case_id"],
                    "project": project_id,
                    "candidate_path_id": str(path["candidate_path_id"]),
                    "path_origin": path.get("path_origin"),
                    "augmentation_reason": path.get("augmentation_reason"),
                    "route_b_input_source": provenance.get("route_b_input"),
                    "route_b_effect_source": provenance.get("route_b_effect"),
                    "evidence": path.get("static_evidence"),
                    "provenance": provenance,
                    "matched_path_ids": path_matches,
                })

    native_covered = sum(row["native_candidate_covered"] is True for row in cases)
    unified_covered = sum(row["unified_candidate_covered"] is True for row in cases)
    baseline_misses = len(cases) - native_covered
    recovery_case_ids = sorted({str(row["case_id"]) for row in recoveries})

    by_reason: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in static_paths:
        by_reason[str(row.get("augmentation_reason") or "UNKNOWN")].append(row)
    ablation: dict[str, dict[str, Any]] = {}
    for reason, rows in sorted(by_reason.items()):
        paths_by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for path in native_paths:
            paths_by_project[str(path.get("project_id"))].append(path)
        for path in rows:
            paths_by_project[str(path.get("project_id"))].append(path)
        coverage = _coverage_count(case_specs, paths_by_project)
        ablation[reason] = {
            "candidate_paths": len(rows),
            "ground_truth_coverage": coverage,
            "gain_over_native": coverage - native_covered,
        }

    per_project = {
        row["project_id"]: {
            "native_covered": row["native_candidate_covered"],
            "native_plus_route_b_covered": row["unified_candidate_covered"],
            "recovered": (not row["native_candidate_covered"] and row["unified_candidate_covered"]),
        }
        for row in cases
    }
    cwe_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in cases:
        if row["cwe_id"] != NOT_EVALUABLE:
            cwe_groups[str(row["cwe_id"])].append(row)
    per_cwe: dict[str, Any] | str = {
        cwe: {
            "evaluable": len(rows),
            "native_covered": sum(row["native_candidate_covered"] is True for row in rows),
            "native_plus_route_b_covered": sum(row["unified_candidate_covered"] is True for row in rows),
        }
        for cwe, rows in sorted(cwe_groups.items())
    } if cwe_groups else NOT_EVALUABLE

    input_reason_gain = Counter()
    effect_reason_gain = Counter()
    augmentation_gain = Counter()
    for recovery in recoveries:
        input_source = recovery.get("route_b_input_source") or {}
        effect_source = recovery.get("route_b_effect_source") or {}
        input_reason_gain[str(input_source.get("structural_reason") or "UNKNOWN")] += 1
        effect_reason_gain[str(effect_source.get("structural_reason") or "UNKNOWN")] += 1
        augmentation_gain[str(recovery.get("augmentation_reason") or "UNKNOWN")] += 1
    attribution = {
        "ablation": ablation,
        "recovery_paths_by_augmentation_reason": dict(sorted(augmentation_gain.items())),
        "recovery_paths_by_input_reason": dict(sorted(input_reason_gain.items())),
        "recovery_paths_by_effect_reason": dict(sorted(effect_reason_gain.items())),
    }

    method_evaluable = [row for row in cases if row["native_method_level_covered"] != NOT_EVALUABLE]
    summary = {
        "status": "SUCCESS",
        "ground_truth_evaluable": len(cases),
        "native_ground_truth_candidate_coverage": native_covered,
        "native_ground_truth_candidate_coverage_rate": _rate(native_covered, len(cases)),
        "native_plus_route_b_ground_truth_candidate_coverage": unified_covered,
        "native_plus_route_b_ground_truth_candidate_coverage_rate": _rate(unified_covered, len(cases)),
        "static_aug_gain": unified_covered - native_covered,
        "baseline_misses": baseline_misses,
        "baseline_miss_recovery_count": len(recovery_case_ids),
        "baseline_miss_recovery_rate": _rate(len(recovery_case_ids), baseline_misses),
        "recovery_case_ids": recovery_case_ids,
        "native_file_level_covered": sum(row["native_file_level_covered"] is True for row in cases),
        "native_plus_route_b_file_level_covered": sum(row["unified_file_level_covered"] is True for row in cases),
        "native_method_level_covered": sum(row["native_method_level_covered"] is True for row in method_evaluable),
        "native_plus_route_b_method_level_covered": sum(row["unified_method_level_covered"] is True for row in method_evaluable),
        "method_level_evaluable": len(method_evaluable),
        "line_level_coverage": NOT_EVALUABLE,
        "per_project_coverage": per_project,
        "per_cwe_coverage": per_cwe,
        "route_b_gain_by_source_category": attribution,
        "detector_ground_truth_access": False,
        "evaluation_phase": "POST_HOC_AFTER_DETECTOR_FREEZE",
        "evaluation_basis": "FIX_INFO_FILE_AND_METHOD_RANGE",
    }
    target = Path(output_root)
    write_json(target / "gt_coverage_metrics.json", summary)
    write_json(target / "evaluation_summary.json", summary)
    write_jsonl(target / "gt_coverage_cases.jsonl", cases)
    write_jsonl(target / "baseline_miss_recovery.jsonl", recoveries)
    write_json(target / "route_b_source_attribution.json", attribution)
    return summary
