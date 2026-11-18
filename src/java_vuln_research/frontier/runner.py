from __future__ import annotations

import csv
import shutil
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..common.contracts import load_detector_manifest
from ..common.io import read_jsonl, write_json, write_jsonl
from ..common.provenance import git_metadata
from .analysis_anchor import (
    AnalysisAnchorError,
    build_analysis_anchors,
    build_funnel_records,
    build_structural_frontiers,
    candidate_location,
    candidate_reference,
    classify_candidate_diagnostics,
    funnel_summary,
    normalise_program_path,
)
from .candidate_path import CandidatePathError, build_candidate_path


ANCHOR_COLUMNS = (
    "candidate_side", "candidate_entity", "candidate_file", "candidate_line",
    "anchor_kind", "value_role", "method_identity", "call_identity",
    "argument_index", "anchor_file", "anchor_line", "mapping_status", "mapping_reason",
)
REACHABILITY_COLUMNS = (
    "candidate_entity", "candidate_file", "candidate_line", "node_kind",
    "node_entity", "node_file", "node_line", "node_method_identity",
)
CONNECTED_COLUMNS = (
    "input_candidate_entity", "input_candidate_file", "input_candidate_line",
    "effect_candidate_entity", "effect_candidate_file", "effect_candidate_line",
)
STRUCTURAL_COLUMNS = (
    "input_candidate_entity", "input_candidate_file", "input_candidate_line",
    "effect_candidate_entity", "effect_candidate_file", "effect_candidate_line",
    "fw_kind", "fw_entity", "fw_file", "fw_line", "fw_method_identity",
    "bw_kind", "bw_entity", "bw_file", "bw_line", "bw_method_identity",
    "structural_distance", "frontier_reason",
)


class CandidatePathRunError(RuntimeError):
    """Raised when the W1-E1 Data/Call detector cannot run safely."""


def _decode_csv(text: str, columns: tuple[str, ...]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for values in csv.reader(text.splitlines()):
        if not values:
            continue
        if len(values) != len(columns):
            raise CandidatePathRunError(
                f"unexpected query row width: expected {len(columns)}, got {len(values)}"
            )
        rows.append(dict(zip(columns, values, strict=True)))
    return rows


def _run_table_query(
    *, codeql: str, database: Path, query: Path, output: Path, log: Path,
    columns: tuple[str, ...], threads: int, ram_mb: int | None,
) -> tuple[list[dict[str, str]], float]:
    command = [
        codeql, "query", "run", str(query), f"--database={database}",
        f"--output={output}", f"--threads={threads}",
    ]
    if ram_mb is not None:
        command.append(f"--ram={ram_mb}")
    started = time.monotonic()
    completed = subprocess.run(
        command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False
    )
    log.write_text(completed.stdout or "", encoding="utf-8")
    if completed.returncode != 0:
        raise CandidatePathRunError(
            f"{query.name} failed with exit code {completed.returncode}"
        )
    decoded = subprocess.run(
        [codeql, "bqrs", "decode", "--format=csv", "--no-titles", str(output)],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
    )
    if decoded.returncode != 0:
        with log.open("a", encoding="utf-8") as handle:
            handle.write("\nBQRS DECODE ERROR\n" + (decoded.stderr or ""))
        raise CandidatePathRunError(
            f"{query.name} BQRS decode failed with exit code {decoded.returncode}"
        )
    return _decode_csv(decoded.stdout, columns), time.monotonic() - started


def _query_error_anchors(
    project_id: str, candidates: Iterable[Mapping[str, Any]], detail: str
) -> list[dict[str, Any]]:
    return [
        {
            "candidate_id": str(candidate["candidate_id"]),
            "project_id": project_id,
            "candidate_kind": str(candidate["kind"]),
            "candidate_evidence_location": candidate_location(candidate),
            "anchor_kind": None,
            "value_role": None,
            "method_identity": None,
            "call_identity": None,
            "argument_index": None,
            "location": None,
            "mapping_status": "ADAPTER_ERROR",
            "mapping_reason": detail,
            "query_status": "QUERY_ERROR",
            "schema_version": 1,
        }
        for candidate in sorted(candidates, key=lambda row: str(row["candidate_id"]))
    ]


def _ref_from_result(row: Mapping[str, Any], prefix: str, side: str) -> tuple[str, str, str, int]:
    try:
        return (
            side,
            str(row[f"{prefix}_candidate_entity"]),
            normalise_program_path(str(row[f"{prefix}_candidate_file"])),
            int(row[f"{prefix}_candidate_line"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise CandidatePathRunError(f"invalid {prefix} candidate reference") from error


def connected_paths_from_rows(
    *, project_id: str, rows: Iterable[Mapping[str, Any]],
    inputs: Iterable[Mapping[str, Any]], effects: Iterable[Mapping[str, Any]],
    anchors: Iterable[Mapping[str, Any]], detector_commit: str,
) -> tuple[list[dict[str, Any]], int]:
    """Map only CodeQL-proven global taint flows to frozen endpoint identities."""

    input_by_ref = {candidate_reference(row): dict(row) for row in inputs}
    effect_by_ref = {candidate_reference(row): dict(row) for row in effects}
    anchor_by_id = {str(row["candidate_id"]): dict(row) for row in anchors}
    paths: list[dict[str, Any]] = []
    unmapped = 0
    for row in rows:
        input_candidate = input_by_ref.get(_ref_from_result(row, "input", "INPUT"))
        effect_candidate = effect_by_ref.get(_ref_from_result(row, "effect", "EFFECT"))
        if input_candidate is None or effect_candidate is None:
            unmapped += 1
            continue
        input_anchor = anchor_by_id.get(str(input_candidate["candidate_id"]))
        effect_anchor = anchor_by_id.get(str(effect_candidate["candidate_id"]))
        if not input_anchor or not effect_anchor:
            unmapped += 1
            continue
        edge = {
            "from_node_id": f"input:{input_candidate['candidate_id']}",
            "to_node_id": f"effect:{effect_candidate['candidate_id']}",
            "mechanism": "DATA",
            "evidence": {"kind": "CODEQL_GLOBAL_TAINT_FLOW"},
        }
        try:
            paths.append(
                build_candidate_path(
                    project_id=project_id,
                    input_candidate=input_candidate,
                    effect_candidate=effect_candidate,
                    input_analysis_anchor=input_anchor,
                    effect_analysis_anchor=effect_anchor,
                    intermediate_nodes=[],
                    edges=[edge],
                    path_status="COMPLETE_STATIC",
                    detector_commit=detector_commit,
                    provenance={
                        "query": "candidate_path/DataCallConnected.ql",
                        "analysis_mode": "CODEQL_GLOBAL_TAINT_FLOW",
                        "path_graph": "UNAVAILABLE_IN_PACK_VERSION",
                    },
                )
            )
        except CandidatePathError as error:
            raise CandidatePathRunError(str(error)) from error
    return _deduplicate(paths), unmapped


def _deduplicate(rows: Iterable[Mapping[str, Any]], *, key: str = "candidate_path_id") -> list[dict[str, Any]]:
    by_id = {str(row[key]): dict(row) for row in rows}
    return [by_id[row_id] for row_id in sorted(by_id)]


def run_w1_e1_paths(
    *, detector_manifest: str | Path, endpoint_output_dir: str | Path,
    query_root: str | Path, output_root: str | Path, threads: int = 0,
    ram_mb: int | None = None, codeql_executable: str = "codeql",
) -> dict[str, Any]:
    """Run W1-E1 without reading evaluator or ground-truth data."""

    projects = load_detector_manifest(detector_manifest)
    codeql = shutil.which(codeql_executable)
    if codeql is None:
        raise CandidatePathRunError("CodeQL executable is unavailable")
    endpoint_root, query_path, output = (
        Path(endpoint_output_dir), Path(query_root), Path(output_root)
    )
    try:
        external = read_jsonl(endpoint_root / "external_inputs.jsonl")
        effects = read_jsonl(endpoint_root / "security_effects.jsonl")
    except (OSError, ValueError) as error:
        raise CandidatePathRunError(f"invalid endpoint output: {error}") from error

    query_specs = {
        "ANCHOR": ("AnalysisAnchors.ql", ANCHOR_COLUMNS),
        "FORWARD": ("InputForward.ql", REACHABILITY_COLUMNS),
        "BACKWARD": ("EffectBackward.ql", REACHABILITY_COLUMNS),
        "CONNECTED": ("DataCallConnected.ql", CONNECTED_COLUMNS),
        "STRUCTURAL": ("DataCallFrontier.ql", STRUCTURAL_COLUMNS),
    }
    for file_name, _ in query_specs.values():
        if not (query_path / "candidate_path" / file_name).is_file():
            raise CandidatePathRunError(f"missing W1-E1 query: {file_name}")

    detector_commit, _ = git_metadata(query_path.parent)
    bqrs_dir, logs_dir = output / "bqrs", output / "logs"
    bqrs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    all_anchors: list[dict[str, Any]] = []
    all_input_funnel: list[dict[str, Any]] = []
    all_effect_funnel: list[dict[str, Any]] = []
    all_paths: list[dict[str, Any]] = []
    all_frontiers: list[dict[str, Any]] = []
    all_diagnostics: list[dict[str, Any]] = []
    statuses: list[dict[str, Any]] = []
    total_query_time = 0.0
    total_adapter_errors = 0

    for project in projects:
        project_id, database = project["project"], Path(project["codeql_db_path"])
        project_inputs = [
            row for row in external
            if row.get("evidence", [{}])[0].get("project") == project_id
        ]
        project_effects = [
            row for row in effects
            if row.get("evidence", [{}])[0].get("project") == project_id
        ]
        candidates = [*project_inputs, *project_effects]
        started = time.monotonic()
        errors: list[dict[str, str]] = []
        status: dict[str, Any] = {
            "project_id": project_id,
            "revision": project["revision"],
            "external_input_candidates": len(project_inputs),
            "security_effect_candidates": len(project_effects),
        }
        if not database.is_dir():
            errors.append({"query": "DATABASE_PRECHECK", "detail": "DATABASE_UNAVAILABLE"})
            project_anchors = _query_error_anchors(project_id, candidates, "DATABASE_UNAVAILABLE")
            input_rows: list[dict[str, str]] = []
            effect_rows: list[dict[str, str]] = []
            connected_rows: list[dict[str, str]] = []
            structural_rows: list[dict[str, str]] = []
            forward_status = backward_status = "QUERY_ERROR"
        elif not candidates:
            project_anchors = []
            input_rows, effect_rows, connected_rows, structural_rows = [], [], [], []
            forward_status = backward_status = "SUCCESS"
        else:
            query_rows: dict[str, list[dict[str, str]]] = {}
            query_status: dict[str, str] = {}
            for query_name in ("ANCHOR", "FORWARD", "BACKWARD", "CONNECTED", "STRUCTURAL"):
                if query_name == "FORWARD" and not project_inputs:
                    query_rows[query_name], query_status[query_name] = [], "SUCCESS"
                    continue
                if query_name == "BACKWARD" and not project_effects:
                    query_rows[query_name], query_status[query_name] = [], "SUCCESS"
                    continue
                if query_name in {"CONNECTED", "STRUCTURAL"} and (not project_inputs or not project_effects):
                    query_rows[query_name], query_status[query_name] = [], "SUCCESS"
                    continue
                file_name, columns = query_specs[query_name]
                try:
                    rows, elapsed = _run_table_query(
                        codeql=codeql, database=database,
                        query=query_path / "candidate_path" / file_name,
                        output=bqrs_dir / f"{project_id}.{query_name.lower()}.bqrs",
                        log=logs_dir / f"{project_id}.{query_name.lower()}.codeql.log",
                        columns=columns, threads=threads, ram_mb=ram_mb,
                    )
                except CandidatePathRunError as error:
                    rows, query_status[query_name] = [], "QUERY_ERROR"
                    errors.append({"query": query_name, "detail": str(error)})
                else:
                    query_status[query_name] = "SUCCESS"
                    total_query_time += elapsed
                query_rows[query_name] = rows

            if query_status["ANCHOR"] == "QUERY_ERROR":
                project_anchors = _query_error_anchors(
                    project_id, candidates, errors[0]["detail"] if errors else "ANCHOR_QUERY_ERROR"
                )
            else:
                try:
                    project_anchors = build_analysis_anchors(
                        project_id=project_id, candidates=candidates, rows=query_rows["ANCHOR"]
                    )
                except AnalysisAnchorError as error:
                    errors.append({"query": "ANCHOR_ADAPTER", "detail": str(error)})
                    project_anchors = _query_error_anchors(project_id, candidates, str(error))
            input_rows, effect_rows = query_rows["FORWARD"], query_rows["BACKWARD"]
            connected_rows, structural_rows = query_rows["CONNECTED"], query_rows["STRUCTURAL"]
            forward_status, backward_status = query_status["FORWARD"], query_status["BACKWARD"]

        input_anchors = [row for row in project_anchors if row["candidate_kind"] == "EXTERNAL_INPUT"]
        effect_anchors = [row for row in project_anchors if row["candidate_kind"] == "SECURITY_EFFECT"]
        project_input_funnel = build_funnel_records(
            side="INPUT", anchors=input_anchors, candidates=project_inputs,
            rows=input_rows, query_status=forward_status,
        )
        project_effect_funnel = build_funnel_records(
            side="EFFECT", anchors=effect_anchors, candidates=project_effects,
            rows=effect_rows, query_status=backward_status,
        )
        try:
            project_paths, connected_unmapped = connected_paths_from_rows(
                project_id=project_id, rows=connected_rows, inputs=project_inputs,
                effects=project_effects, anchors=project_anchors, detector_commit=detector_commit,
            )
            project_frontiers, frontier_unmapped = build_structural_frontiers(
                project_id=project_id, rows=structural_rows, inputs=project_inputs,
                effects=project_effects, anchors=project_anchors,
            )
        except (CandidatePathRunError, AnalysisAnchorError) as error:
            errors.append({"query": "ADAPTER", "detail": str(error)})
            project_paths, project_frontiers = [], []
            connected_unmapped = frontier_unmapped = len(connected_rows) + len(structural_rows)
        adapter_errors = connected_unmapped + frontier_unmapped
        total_adapter_errors += adapter_errors

        project_diagnostics = classify_candidate_diagnostics(
            anchors=project_anchors, input_funnel=project_input_funnel,
            effect_funnel=project_effect_funnel, connected_paths=project_paths,
            structural_frontiers=project_frontiers,
        )
        if any(error["query"] in {"CONNECTED", "STRUCTURAL", "ADAPTER"} for error in errors):
            for diagnostic in project_diagnostics:
                if diagnostic["classification"] not in {"STATIC_CONNECTED"}:
                    diagnostic["classification"] = "QUERY_ERROR"

        project_funnel = funnel_summary(project_input_funnel, project_effect_funnel)
        status.update(
            status="FAILED" if errors else "SUCCESS",
            stage="QUERY_ERROR" if errors else "COMPLETE",
            query_errors=errors,
            input_funnel=project_funnel["external_input"],
            effect_funnel=project_funnel["security_effect"],
            static_connected_paths=len(project_paths),
            structural_frontiers=len(project_frontiers),
            adapter_error_count=adapter_errors,
            runtime_seconds=round(time.monotonic() - started, 3),
        )
        statuses.append(status)
        all_anchors.extend(project_anchors)
        all_input_funnel.extend(project_input_funnel)
        all_effect_funnel.extend(project_effect_funnel)
        all_paths.extend(project_paths)
        all_frontiers.extend(project_frontiers)
        all_diagnostics.extend(project_diagnostics)

    all_paths = _deduplicate(all_paths)
    all_frontiers = _deduplicate(all_frontiers, key="structural_frontier_id")
    all_anchors.sort(key=lambda row: str(row["candidate_id"]))
    all_input_funnel.sort(key=lambda row: str(row["candidate_id"]))
    all_effect_funnel.sort(key=lambda row: str(row["candidate_id"]))
    all_diagnostics.sort(key=lambda row: str(row["candidate_id"]))
    overall_funnel = funnel_summary(all_input_funnel, all_effect_funnel)
    reason_counts = dict(sorted(Counter(str(row["frontier_reason"]) for row in all_frontiers).items()))
    taxonomy_counts = dict(sorted(Counter(str(row["classification"]) for row in all_diagnostics).items()))
    successes = sum(row["status"] == "SUCCESS" for row in statuses)

    write_jsonl(output / "endpoint_candidates.jsonl", sorted([*external, *effects], key=lambda row: str(row["candidate_id"])))
    write_jsonl(output / "analysis_anchors.jsonl", all_anchors)
    write_jsonl(output / "input_forward_funnel.jsonl", all_input_funnel)
    write_jsonl(output / "effect_backward_funnel.jsonl", all_effect_funnel)
    write_jsonl(output / "candidate_paths.jsonl", all_paths)
    write_jsonl(output / "structural_frontiers.jsonl", all_frontiers)
    write_jsonl(output / "frontier_cases.jsonl", all_frontiers)
    write_jsonl(output / "candidate_diagnostics.jsonl", all_diagnostics)
    write_jsonl(output / "project_status.jsonl", statuses)

    summary = {
        "status": "SUCCESS" if statuses and successes == len(statuses) else "PARTIAL" if successes else "FAILED",
        "projects_total": len(statuses),
        "projects_runnable": successes,
        "external_input_candidates": len(external),
        "security_effect_candidates": len(effects),
        "input_anchor_mappable": overall_funnel["external_input"]["anchor_mappable"],
        "input_anchor_unmappable": overall_funnel["external_input"]["anchor_unmappable"],
        "fw_active_inputs": overall_funnel["external_input"]["fw_non_empty"],
        "fw_empty_inputs": overall_funnel["external_input"]["fw_empty"],
        "effect_anchor_mappable": overall_funnel["security_effect"]["anchor_mappable"],
        "effect_anchor_unmappable": overall_funnel["security_effect"]["anchor_unmappable"],
        "bw_active_effects": overall_funnel["security_effect"]["bw_non_empty"],
        "bw_empty_effects": overall_funnel["security_effect"]["bw_empty"],
        "candidate_paths_total": len(all_paths),
        "static_connected_paths": len(all_paths),
        "frontier_candidate_paths": 0,
        "structural_frontier_count": len(all_frontiers),
        "frontier_reason_counts": reason_counts,
        "candidate_paths_per_project": {
            row["project_id"]: row["static_connected_paths"] for row in statuses
        },
        "structural_frontiers_per_project": {
            row["project_id"]: row["structural_frontiers"] for row in statuses
        },
        "failure_taxonomy_counts": taxonomy_counts,
        "codeql_query_time": round(total_query_time, 3),
        "error_count": len(statuses) - successes,
        "adapter_error_count": total_adapter_errors,
        "unknown_count": 0,
        "scientific_method_changed": "NO",
    }
    write_json(output / "funnel_metrics.json", overall_funnel)
    write_json(output / "detector_metrics.json", summary)
    write_json(output / "metrics.json", summary)
    return summary
