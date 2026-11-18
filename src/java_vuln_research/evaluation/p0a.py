from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from ..common.io import read_jsonl, write_json, write_jsonl


NOT_APPLICABLE = "NOT_APPLICABLE"


class P0AEvaluationError(ValueError):
    """Raised when P0-A detector output cannot be evaluated safely."""


def _read_csv(path: str | Path) -> list[dict[str, str]]:
    source = Path(path)
    if not source.is_file():
        raise P0AEvaluationError(f"missing CSV: {source}")
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise P0AEvaluationError(f"CSV has no header: {source}")
        return [dict(row) for row in reader]


def _required_columns(
    rows: list[dict[str, str]], required: set[str], path: str | Path
) -> None:
    if not rows:
        raise P0AEvaluationError(f"CSV has no data rows: {path}")
    missing = required - set(rows[0])
    if missing:
        raise P0AEvaluationError(
            f"CSV {path} is missing required columns: {', '.join(sorted(missing))}"
        )


def _normalise_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./").lower()


def _same_file(candidate: str, fix: str) -> bool:
    candidate_path = _normalise_path(candidate)
    fix_path = _normalise_path(fix)
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
        raise P0AEvaluationError(f"invalid integer in fix_info.csv: {text!r}") from error


def _candidate_location(candidate: dict[str, Any]) -> tuple[dict[str, Any], str, int]:
    evidence = candidate.get("evidence")
    if not isinstance(evidence, list) or not evidence or not isinstance(evidence[0], dict):
        raise P0AEvaluationError(
            f"candidate {candidate.get('candidate_id', '<missing>')} has no usable evidence"
        )
    primary = evidence[0]
    revision = str(primary.get("revision", "")).strip().lower()
    file_name = str(primary.get("file", "")).strip()
    try:
        line = int(primary.get("line"))
    except (TypeError, ValueError) as error:
        raise P0AEvaluationError(
            f"candidate {candidate.get('candidate_id', '<missing>')} has an invalid line"
        ) from error
    if not revision or not file_name:
        raise P0AEvaluationError(
            f"candidate {candidate.get('candidate_id', '<missing>')} has incomplete evidence"
        )
    return primary, revision, line


def evaluate_p0a(
    detector_output_dir: str | Path,
    project_info_csv: str | Path,
    fix_info_csv: str | Path,
    output_root: str | Path,
) -> dict[str, Any]:
    """Evaluate persisted detector candidates without feeding labels back to detection."""

    detector_root = Path(detector_output_dir)
    try:
        external_inputs = read_jsonl(detector_root / "external_inputs.jsonl")
        security_effects = read_jsonl(detector_root / "security_effects.jsonl")
    except (OSError, ValueError) as error:
        raise P0AEvaluationError(f"invalid detector output in {detector_root}: {error}") from error

    project_rows = _read_csv(project_info_csv)
    fix_rows = _read_csv(fix_info_csv)
    _required_columns(project_rows, {"project_slug", "buggy_commit_id"}, project_info_csv)
    _required_columns(
        fix_rows,
        {"project_slug", "file", "class", "method", "method_start", "method_end"},
        fix_info_csv,
    )

    revision_to_slug: dict[str, str] = {}
    for row in project_rows:
        revision = row["buggy_commit_id"].strip().lower()
        slug = row["project_slug"].strip()
        if revision and slug:
            revision_to_slug[revision] = slug

    fixes_by_project: dict[str, list[dict[str, str]]] = {}
    for row in fix_rows:
        slug = row["project_slug"].strip()
        if slug:
            fixes_by_project.setdefault(slug, []).append(row)

    candidates = [*external_inputs, *security_effects]
    adjudications: list[dict[str, Any]] = []
    observed_projects: set[str] = set()
    mapped_projects: set[str] = set()
    unmapped_projects: set[str] = set()

    for candidate in candidates:
        primary, revision, line = _candidate_location(candidate)
        neutral_project = str(primary.get("project", "")).strip()
        if neutral_project:
            observed_projects.add(neutral_project)
        project_slug = revision_to_slug.get(revision)
        if project_slug:
            if neutral_project:
                mapped_projects.add(neutral_project)
        elif neutral_project:
            unmapped_projects.add(neutral_project)

        matches: list[dict[str, Any]] = []
        for fix in fixes_by_project.get(project_slug or "", []):
            if not _same_file(str(primary["file"]), fix["file"]):
                continue
            method_start = _optional_int(fix.get("method_start"))
            method_end = _optional_int(fix.get("method_end"))
            if method_start is not None and line < method_start:
                continue
            if method_end is not None and line > method_end:
                continue
            matches.append(
                {
                    "file": fix["file"],
                    "class": fix["class"],
                    "method": fix["method"],
                    "method_start": method_start,
                    "method_end": method_end,
                }
            )

        adjudications.append(
            {
                "candidate_id": candidate.get("candidate_id"),
                "kind": candidate.get("kind"),
                "project": neutral_project,
                "decision": "UNKNOWN",
                "ground_truth_location_match": bool(matches),
                "matched_fix_locations": matches,
            }
        )

    wrapper_count = sum(
        1 for candidate in candidates if candidate.get("source") == "STATIC_DERIVED"
    )
    summary: dict[str, Any] = {
        "status": "SUCCESS" if not unmapped_projects else "PARTIAL",
        "native_source_count": NOT_APPLICABLE,
        "discovered_external_input_count": len(external_inputs),
        "new_external_input_count": NOT_APPLICABLE,
        "native_sink_count": NOT_APPLICABLE,
        "discovered_security_effect_count": len(security_effects),
        "new_security_effect_count": NOT_APPLICABLE,
        "wrapper_count": wrapper_count,
        "manual_confirmed_count": NOT_APPLICABLE,
        "false_candidate_count": NOT_APPLICABLE,
        "unknown_count": len(candidates),
        "projects_observed": len(observed_projects),
        "ground_truth_projects_mapped": len(mapped_projects),
        "unmapped_projects": sorted(unmapped_projects),
        "ground_truth_location_match_count": sum(
            1 for row in adjudications if row["ground_truth_location_match"]
        ),
        "evaluation_basis": "FIX_LOCATION_OVERLAP_ONLY",
        "manual_review_status": "NOT_PERFORMED",
    }

    target = Path(output_root)
    write_json(target / "summary.json", summary)
    write_jsonl(target / "candidate_evaluation.jsonl", adjudications)
    return summary
