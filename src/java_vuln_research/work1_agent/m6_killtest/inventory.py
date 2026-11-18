from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from .io import read_csv, read_jsonl, sha256_file, truthy, write_csv


BASELINE_KEYS = (
    "baseline_detected",
    "baseline_covered",
    "covered_by_baseline",
    "native_covered",
    "native_candidate_covered",
    "unified_candidate_covered",
    "covered",
)


def _case_id(row: Mapping[str, Any]) -> str:
    for key in ("case_id", "benchmark_case_id", "vulnerability_id", "advisory_id"):
        if row.get(key):
            return str(row[key])
    return f"{row.get('project_id', 'UNKNOWN')}:{row.get('cve', row.get('CVE', 'UNKNOWN'))}"


def _baseline_detected(row: Mapping[str, Any]) -> bool:
    for key in BASELINE_KEYS:
        if key in row and row[key] is not None:
            return truthy(row[key])
    return False


def _annotation_available(row: Mapping[str, Any], hint: Mapping[str, Any] | None) -> bool:
    if hint:
        return True
    if str(row.get("comparison_level", "")).upper() in {"METHOD", "FILE", "LINE"}:
        return True
    return any(row.get(key) for key in ("ground_truth", "annotation", "locations", "method_locations"))


def build_case_inventory(
    *,
    project_inventory_csv: str | Path,
    coverage_cases_jsonl: str | Path,
    diagnostic_hints_jsonl: str | Path,
    output_csv: str | Path,
) -> list[dict[str, Any]]:
    projects = {str(row["project_id"]): row for row in read_csv(project_inventory_csv)}
    hints = read_jsonl(diagnostic_hints_jsonl)
    hint_index = {(str(row["project_id"]), str(row["case_id"])): row for row in hints}
    rows: list[dict[str, Any]] = []
    for case in read_jsonl(coverage_cases_jsonl):
        project_id = str(case.get("project_id") or "")
        case_id = _case_id(case)
        project = projects.get(project_id, {})
        source_root = str(project.get("source_root") or project.get("project_root") or "")
        db_path = str(project.get("codeql_db_path") or project.get("db_path") or "")
        source_ready = truthy(project.get("source_ready", project.get("source_exists")))
        db_ready = truthy(project.get("codeql_db_ready", project.get("db_ready")))
        detected = _baseline_detected(case)
        hint = hint_index.get((project_id, case_id))
        annotation = _annotation_available(case, hint)
        eligible = source_ready and db_ready and not detected and annotation
        exclusions = []
        if not source_ready:
            exclusions.append("SOURCE_NOT_READY")
        if not db_ready:
            exclusions.append("CODEQL_DB_NOT_READY")
        if detected:
            exclusions.append("BASELINE_DETECTED")
        if not annotation:
            exclusions.append("BENCHMARK_ANNOTATION_UNAVAILABLE")
        rows.append(
            {
                "project_id": project_id,
                "case_id": case_id,
                "project_name": project.get("project_name", ""),
                "project_repository": project.get("project_name", ""),
                "source_revision": (hint or {}).get("annotation_revision", project.get("source_revision", "UNKNOWN")),
                "cwe": case.get("cwe") or case.get("CWE") or case.get("cwe_id") or "",
                "comparison_level": case.get("comparison_level", "UNKNOWN"),
                "source_root": source_root,
                "source_ready": source_ready,
                "codeql_db_path": db_path,
                "db_ready": db_ready,
                "baseline_detected": detected,
                "annotation_available": annotation,
                "diagnostic_hint_available": hint is not None,
                "eligible": eligible,
                "eligible_for_m6": eligible,
                "exclusion_reason": "|".join(exclusions),
            }
        )
    rows.sort(key=lambda item: (str(item["project_id"]), str(item["case_id"])))
    write_csv(output_csv, rows)
    return rows


def select_cases(rows: Sequence[Mapping[str, Any]], output_csv: str | Path) -> list[dict[str, Any]]:
    eligible = [dict(row) for row in rows if truthy(row.get("eligible"))]
    eligible.sort(key=lambda item: (str(item["project_id"]), str(item["case_id"])))
    selected = eligible if len(eligible) <= 12 else eligible[:12]
    for rank, row in enumerate(selected, 1):
        row["selection_rank"] = rank
        row["selection_rule"] = "ALL_ELIGIBLE" if len(eligible) <= 12 else "PROJECT_ID_THEN_CASE_ID_FIRST_12"
    write_csv(output_csv, selected)
    return selected


def inventory_lineage(*paths: str | Path) -> dict[str, str]:
    return {str(Path(path)): sha256_file(path) for path in paths}
