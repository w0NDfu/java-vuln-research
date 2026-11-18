from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .common.contracts import load_detector_manifest
from .common.io import read_jsonl, write_json, write_jsonl
from .common.provenance import git_metadata, tool_versions
from .frontier.candidate_path import CandidatePathError, build_candidate_path
from .frontier.runner import CandidatePathRunError, _run_table_query


INPUT_COLUMNS = (
    "structural_reason",
    "entity",
    "method_identity",
    "call_identity",
    "value_role",
    "argument_index",
    "file",
    "line",
    "evidence_kind",
    "confidence_tier",
    "unresolved_semantics",
)
EFFECT_COLUMNS = (
    "structural_reason",
    "entity",
    "method_identity",
    "call_identity",
    "value_role",
    "argument_index",
    "file",
    "line",
    "evidence_kind",
    "confidence_tier",
    "effect_category",
)
PAIR_COLUMNS = (
    "input_entity",
    "input_file",
    "input_line",
    "input_reason",
    "effect_entity",
    "effect_file",
    "effect_line",
    "effect_reason",
    "gate_reason",
    "gate_distance",
)
CONFIDENCE_RANK = {"STRUCTURE_HIGH": 0, "STRUCTURE_MEDIUM": 1, "OPEN_CANDIDATE": 2}


class RouteBError(RuntimeError):
    """Raised when Route B cannot preserve its detector or baseline boundary."""


def _digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:24]


def _normalise_file(value: Any) -> str:
    return str(value).replace("\\", "/").lstrip("./")


def _positive_line(value: Any) -> int:
    try:
        line = int(value)
    except (TypeError, ValueError) as error:
        raise RouteBError(f"invalid source line: {value!r}") from error
    if line < 1:
        raise RouteBError(f"invalid source line: {value!r}")
    return line


def route_b_candidate_from_row(
    *, project_id: str, revision: str, candidate_kind: str,
    row: Mapping[str, Any], detector_commit: str,
) -> dict[str, Any]:
    """Adapt one seed-independent CodeQL row while preserving structural evidence."""

    if candidate_kind not in {"EXTERNAL_INPUT", "SECURITY_EFFECT"}:
        raise RouteBError(f"unsupported Route B candidate kind: {candidate_kind!r}")
    required = {
        "structural_reason", "entity", "method_identity", "value_role",
        "argument_index", "file", "line", "evidence_kind", "confidence_tier",
    }
    missing = sorted(required - set(row))
    if missing:
        raise RouteBError("Route B query row missing: " + ", ".join(missing))
    location = {"file": _normalise_file(row["file"]), "line": _positive_line(row["line"])}
    try:
        argument_index = int(row["argument_index"])
    except (TypeError, ValueError) as error:
        raise RouteBError("Route B argument_index must be an integer") from error
    confidence = str(row["confidence_tier"])
    if confidence not in CONFIDENCE_RANK:
        raise RouteBError(f"unsupported Route B confidence tier: {confidence!r}")
    role = "EXTERNAL_INPUT" if candidate_kind == "EXTERNAL_INPUT" else "SECURITY_EFFECT"
    identity = {
        "project_id": project_id,
        "candidate_kind": candidate_kind,
        "structural_reason": str(row["structural_reason"]),
        "entity": str(row["entity"]),
        "method_identity": str(row["method_identity"]),
        "call_identity": str(row.get("call_identity") or ""),
        "value_role": str(row["value_role"]),
        "argument_index": argument_index,
        "location": location,
    }
    prefix = "routeb-input" if candidate_kind == "EXTERNAL_INPUT" else "routeb-effect"
    candidate_id = f"{prefix}-{_digest(identity)}"
    evidence = {
        "project": project_id,
        "revision": revision,
        **location,
        "kind": str(row["evidence_kind"]),
        "structural_reason": str(row["structural_reason"]),
    }
    unresolved = str(row.get("unresolved_semantics") or "").strip()
    if candidate_kind == "SECURITY_EFFECT" and confidence == "OPEN_CANDIDATE":
        unresolved = unresolved or "SENSITIVE_EFFECT_SEMANTICS"
    return {
        "candidate_id": candidate_id,
        "project_id": project_id,
        "project": project_id,
        "kind": candidate_kind,
        "candidate_kind": candidate_kind,
        "candidate_role": role,
        "discovery_route": "ROUTE_B_STATIC",
        "source": "ROUTE_B_STATIC",
        "structural_reason": str(row["structural_reason"]),
        "entity": str(row["entity"]),
        "method_identity": str(row["method_identity"]),
        "call_identity": str(row.get("call_identity") or "") or None,
        "value_role": str(row["value_role"]),
        "argument_index": argument_index,
        "location": location,
        "effect_category": str(row.get("effect_category") or "") or None,
        "confidence_tier": confidence,
        "evidence": [evidence],
        "static_evidence": [dict(evidence)],
        "evidence_refs": [{"kind": str(row["evidence_kind"]), "location": location}],
        "provenance": {
            "query": "route_b/RouteBInputCandidates.ql" if candidate_kind == "EXTERNAL_INPUT" else "route_b/RouteBEffectCandidates.ql",
            "project_revision": revision,
            "detector_commit": detector_commit,
            "seed_independent": True,
        },
        "unresolved_semantics": [unresolved] if unresolved else [],
        "schema_version": 1,
    }


def _candidate_ref(candidate: Mapping[str, Any]) -> tuple[str, str, str, int]:
    location = candidate.get("location") or {}
    return (
        str(candidate.get("structural_reason", "")),
        str(candidate.get("entity", "")),
        _normalise_file(location.get("file", "")),
        _positive_line(location.get("line")),
    )


def _row_ref(row: Mapping[str, Any], side: str) -> tuple[str, str, str, int]:
    return (
        str(row[f"{side}_reason"]),
        str(row[f"{side}_entity"]),
        _normalise_file(row[f"{side}_file"]),
        _positive_line(row[f"{side}_line"]),
    )


def adapt_gated_pairs(
    rows: Iterable[Mapping[str, Any]], inputs: Iterable[Mapping[str, Any]],
    effects: Iterable[Mapping[str, Any]], *, connected_pairs: set[tuple[str, str]] | None = None,
) -> tuple[list[dict[str, Any]], int]:
    input_by_ref = {_candidate_ref(row): dict(row) for row in inputs}
    effect_by_ref = {_candidate_ref(row): dict(row) for row in effects}
    result: dict[tuple[str, str], dict[str, Any]] = {}
    unmapped = 0
    connected = connected_pairs or set()
    for row in rows:
        input_candidate = input_by_ref.get(_row_ref(row, "input"))
        effect_candidate = effect_by_ref.get(_row_ref(row, "effect"))
        if input_candidate is None or effect_candidate is None:
            unmapped += 1
            continue
        pair_key = (str(input_candidate["candidate_id"]), str(effect_candidate["candidate_id"]))
        material = {
            "input_candidate_id": pair_key[0],
            "effect_candidate_id": pair_key[1],
        }
        pair_id = "routeb-pair-" + _digest(material)
        gate_evidence = {
            "kind": "STRUCTURAL_GATE",
            "reason": str(row["gate_reason"]),
            "distance": int(row["gate_distance"]),
        }
        existing = result.get(pair_key)
        if existing is not None:
            existing["static_evidence"].append(gate_evidence)
            existing["static_evidence"].sort(
                key=lambda item: (int(item["distance"]), str(item["reason"]))
            )
            continue
        result[pair_key] = {
            "pair_id": pair_id,
            "project_id": input_candidate["project_id"],
            **material,
            "connected": pair_key in connected,
            "static_evidence": [gate_evidence],
        }
    return [result[key] for key in sorted(result)], unmapped


def _anchor(candidate: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "candidate_id": str(candidate["candidate_id"]),
        "mapping_status": "MAPPED",
        "anchor_kind": str(candidate["value_role"]),
        "value_role": str(candidate["value_role"]),
        "method_identity": str(candidate["method_identity"]),
        "call_identity": candidate.get("call_identity"),
        "argument_index": int(candidate["argument_index"]),
        "location": dict(candidate["location"]),
        "mapping_reason": str(candidate["structural_reason"]),
    }


def _path_endpoint_key(path: Mapping[str, Any]) -> tuple[str, str, int, str, int]:
    input_anchor = path.get("input_anchor") or path.get("input_analysis_anchor") or {}
    effect_anchor = path.get("effect_anchor") or path.get("effect_analysis_anchor") or {}
    input_location = input_anchor.get("location") or {}
    effect_location = effect_anchor.get("location") or {}
    return (
        str(path.get("project_id", "")),
        _normalise_file(input_location.get("file", "")),
        _positive_line(input_location.get("line")),
        _normalise_file(effect_location.get("file", "")),
        _positive_line(effect_location.get("line")),
    )


def classify_augmentation_reason(
    *, project_id: str, input_candidate: Mapping[str, Any], effect_candidate: Mapping[str, Any],
    native_input_locations: set[tuple[str, str, int]],
    native_effect_locations: set[tuple[str, str, int]],
    native_path_keys: set[tuple[str, str, int, str, int]],
) -> str:
    input_loc = input_candidate["location"]
    effect_loc = effect_candidate["location"]
    path_key = (
        project_id,
        _normalise_file(input_loc["file"]), int(input_loc["line"]),
        _normalise_file(effect_loc["file"]), int(effect_loc["line"]),
    )
    if path_key in native_path_keys:
        return "NATIVE_DUPLICATE"
    input_is_new = (project_id, path_key[1], path_key[2]) not in native_input_locations
    effect_is_new = (project_id, path_key[3], path_key[4]) not in native_effect_locations
    if input_is_new and effect_is_new:
        return "NEW_BOTH_ENDPOINTS"
    if input_is_new:
        return "NEW_BOUNDARY_CANDIDATE"
    if effect_is_new:
        return "NEW_EFFECT_CANDIDATE"
    return "STRUCTURAL_ROUTE_B_ASSOCIATION"


def static_paths_from_rows(
    *, project_id: str, rows: Iterable[Mapping[str, Any]],
    inputs: Iterable[Mapping[str, Any]], effects: Iterable[Mapping[str, Any]],
    detector_commit: str, native_paths: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], set[tuple[str, str]], int]:
    input_by_ref = {_candidate_ref(row): dict(row) for row in inputs}
    effect_by_ref = {_candidate_ref(row): dict(row) for row in effects}
    native_rows = [dict(row) for row in native_paths]
    native_path_keys = {_path_endpoint_key(row) for row in native_rows}
    native_input_locations = {(key[0], key[1], key[2]) for key in native_path_keys}
    native_effect_locations = {(key[0], key[3], key[4]) for key in native_path_keys}
    paths: list[dict[str, Any]] = []
    connected_pairs: set[tuple[str, str]] = set()
    unmapped = 0
    for row in rows:
        input_candidate = input_by_ref.get(_row_ref(row, "input"))
        effect_candidate = effect_by_ref.get(_row_ref(row, "effect"))
        if input_candidate is None or effect_candidate is None:
            unmapped += 1
            continue
        pair_key = (str(input_candidate["candidate_id"]), str(effect_candidate["candidate_id"]))
        connected_pairs.add(pair_key)
        reason = classify_augmentation_reason(
            project_id=project_id,
            input_candidate=input_candidate,
            effect_candidate=effect_candidate,
            native_input_locations=native_input_locations,
            native_effect_locations=native_effect_locations,
            native_path_keys=native_path_keys,
        )
        confidence = max(
            (str(input_candidate["confidence_tier"]), str(effect_candidate["confidence_tier"])),
            key=lambda value: CONFIDENCE_RANK[value],
        )
        unresolved = sorted({
            str(value)
            for candidate in (input_candidate, effect_candidate)
            for value in candidate.get("unresolved_semantics", [])
            if str(value)
        })
        edge = {
            "from_node_id": f"input:{input_candidate['candidate_id']}",
            "to_node_id": f"effect:{effect_candidate['candidate_id']}",
            "mechanism": "DATA",
            "evidence": {
                "kind": "CODEQL_BASE_GRAPH_FLOW",
                "gate_reason": str(row["gate_reason"]),
                "gate_distance": int(row["gate_distance"]),
            },
        }
        try:
            path = build_candidate_path(
                project_id=project_id,
                input_candidate=input_candidate,
                effect_candidate=effect_candidate,
                input_analysis_anchor=_anchor(input_candidate),
                effect_analysis_anchor=_anchor(effect_candidate),
                intermediate_nodes=[],
                edges=[edge],
                path_status="COMPLETE_STATIC",
                detector_commit=detector_commit,
                candidate_type_hypothesis=str(effect_candidate.get("effect_category") or "UNKNOWN"),
                provenance={
                    "query": "route_b/RouteBConnected.ql",
                    "analysis_mode": "CODEQL_BASE_GRAPH_TAINT_FLOW",
                    "structural_gate": {"reason": str(row["gate_reason"]), "distance": int(row["gate_distance"])},
                    "route_b_input": {
                        "candidate_id": input_candidate["candidate_id"],
                        "structural_reason": input_candidate["structural_reason"],
                        "evidence_refs": input_candidate["evidence_refs"],
                    },
                    "route_b_effect": {
                        "candidate_id": effect_candidate["candidate_id"],
                        "structural_reason": effect_candidate["structural_reason"],
                        "evidence_refs": effect_candidate["evidence_refs"],
                    },
                    "seed_independent": True,
                },
                path_origin="STATIC_AUGMENTED",
                discovery_route_override="ROUTE_B_STATIC",
                augmentation_reason=reason,
                confidence_tier=confidence,
                static_evidence=[
                    {"kind": "STRUCTURAL_GATE", "reason": str(row["gate_reason"]), "distance": int(row["gate_distance"])},
                    {"kind": "CODEQL_BASE_GRAPH_FLOW"},
                ],
                unresolved_semantics=unresolved,
            )
        except CandidatePathError as error:
            raise RouteBError(str(error)) from error
        paths.append(path)

    # Stable positional identity controls duplicate expansion independently of
    # which structural rule emitted the same endpoint pair.
    best_by_location: dict[tuple[str, str, int, str, int], dict[str, Any]] = {}
    for path in paths:
        key = _path_endpoint_key(path)
        old = best_by_location.get(key)
        if old is None:
            best_by_location[key] = path
            continue
        new_rank = (
            CONFIDENCE_RANK[str(path["confidence_tier"])],
            int(path["provenance"]["structural_gate"]["distance"]),
            str(path["candidate_path_id"]),
        )
        old_rank = (
            CONFIDENCE_RANK[str(old["confidence_tier"])],
            int(old["provenance"]["structural_gate"]["distance"]),
            str(old["candidate_path_id"]),
        )
        if new_rank < old_rank:
            best_by_location[key] = path
    return [best_by_location[key] for key in sorted(best_by_location)], connected_pairs, unmapped


def _codeql_version(codeql: str) -> str:
    try:
        result = subprocess.run(
            [codeql, "version"], text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return "UNKNOWN"
    return (result.stdout or "UNKNOWN").splitlines()[0].strip() or "UNKNOWN"


def _peak_child_rss_kb() -> int | str:
    try:
        import resource
        return int(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
    except (ImportError, OSError, ValueError):
        return "NOT_AVAILABLE"


def build_unified_pool(
    native_paths: Iterable[Mapping[str, Any]],
    static_paths: Iterable[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    """Preserve native objects and add only positionally new static paths."""

    native_rows = [dict(row) for row in native_paths]
    static_rows = [dict(row) for row in static_paths]
    native_candidate_ids = [str(row.get("candidate_path_id", "")) for row in native_rows]
    if not all(native_candidate_ids) or len(native_candidate_ids) != len(set(native_candidate_ids)):
        raise RouteBError("native candidate identities are missing or duplicated")
    native_keys = {_path_endpoint_key(row) for row in native_rows}
    duplicate_rows: list[dict[str, Any]] = []
    unique_by_key: dict[tuple[str, str, int, str, int], dict[str, Any]] = {}
    for row in static_rows:
        key = _path_endpoint_key(row)
        if row.get("augmentation_reason") == "NATIVE_DUPLICATE" or key in native_keys:
            row["augmentation_reason"] = "NATIVE_DUPLICATE"
            duplicate_rows.append(row)
            continue
        unique_by_key.setdefault(key, row)
    unique_static = [unique_by_key[key] for key in sorted(unique_by_key)]
    unified = [*native_rows, *unique_static]
    retained_ids = {
        str(row.get("candidate_path_id")) for row in unified
        if row.get("path_origin") == "CODEQL_NATIVE"
    }
    loss_ids = sorted(set(native_candidate_ids) - retained_ids)
    preservation = {
        "native_path_count": len(native_rows),
        "native_paths_retained": len(set(native_candidate_ids) & retained_ids),
        "native_preservation_rate": len(retained_ids) / len(native_rows) if native_rows else "NOT_EVALUABLE",
        "baseline_preservation_loss": len(loss_ids),
        "baseline_preservation_loss_ids": loss_ids,
        "native_pool_subset_unified_pool": set(native_candidate_ids) <= {str(row.get("candidate_path_id")) for row in unified},
        "native_objects_unchanged": unified[: len(native_rows)] == native_rows,
        "status": "PASS" if not loss_ids and unified[: len(native_rows)] == native_rows else "FAIL",
    }
    return unified, duplicate_rows, preservation


def run_p0_b_route_b(
    *, detector_manifest: str | Path, native_pool_path: str | Path,
    query_root: str | Path, output_root: str | Path, project_root: str | Path,
    run_id: str, threads: int = 0, ram_mb: int | None = None,
    codeql_executable: str = "codeql",
) -> dict[str, Any]:
    """Run seed-independent Route B and preserve the frozen native pool."""

    started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    wall_started = time.monotonic()
    projects = load_detector_manifest(detector_manifest)
    native_paths = read_jsonl(native_pool_path)
    if any(row.get("path_origin") != "CODEQL_NATIVE" for row in native_paths):
        raise RouteBError("native pool contains a non-CODEQL_NATIVE path")
    native_candidate_ids = [str(row.get("candidate_path_id", "")) for row in native_paths]
    native_path_ids = [str(row.get("native_path_id", "")) for row in native_paths]
    if not all(native_candidate_ids) or len(native_candidate_ids) != len(set(native_candidate_ids)):
        raise RouteBError("native pool candidate identities are missing or duplicated")
    if not all(native_path_ids) or len(native_path_ids) != len(set(native_path_ids)):
        raise RouteBError("native pool native identities are missing or duplicated")

    codeql = shutil.which(codeql_executable)
    if codeql is None:
        raise RouteBError("CodeQL executable is unavailable")
    query_path = Path(query_root)
    output = Path(output_root)
    bqrs_dir, logs_dir = output / "bqrs", output / "logs"
    bqrs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    query_specs = {
        "INPUT": ("RouteBInputCandidates.ql", INPUT_COLUMNS),
        "EFFECT": ("RouteBEffectCandidates.ql", EFFECT_COLUMNS),
        "GATE": ("RouteBGatedPairs.ql", PAIR_COLUMNS),
        "CONNECTED": ("RouteBConnected.ql", PAIR_COLUMNS),
    }
    for file_name, _ in query_specs.values():
        if not (query_path / "route_b" / file_name).is_file():
            raise RouteBError(f"missing Route B query: {file_name}")

    detector_commit, detector_branch = git_metadata(project_root)
    all_inputs: list[dict[str, Any]] = []
    all_effects: list[dict[str, Any]] = []
    all_pairs: list[dict[str, Any]] = []
    all_static_paths: list[dict[str, Any]] = []
    statuses: list[dict[str, Any]] = []
    total_query_time = 0.0
    total_unmapped = 0
    native_by_project: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for path in native_paths:
        native_by_project[str(path["project_id"])].append(path)

    for project in projects:
        project_id = project["project"]
        database = Path(project["codeql_db_path"])
        project_started = time.monotonic()
        errors: list[dict[str, str]] = []
        query_rows: dict[str, list[dict[str, str]]] = {name: [] for name in query_specs}
        query_times: dict[str, float] = {}
        if not database.is_dir():
            errors.append({"query": "DATABASE_PRECHECK", "detail": "DATABASE_UNAVAILABLE"})
        else:
            for name in ("INPUT", "EFFECT"):
                file_name, columns = query_specs[name]
                try:
                    rows, elapsed = _run_table_query(
                        codeql=codeql, database=database,
                        query=query_path / "route_b" / file_name,
                        output=bqrs_dir / f"{project_id}.{name.lower()}.bqrs",
                        log=logs_dir / f"{project_id}.{name.lower()}.codeql.log",
                        columns=columns, threads=threads, ram_mb=ram_mb,
                    )
                except CandidatePathRunError as error:
                    errors.append({"query": name, "detail": str(error)})
                    rows, elapsed = [], 0.0
                query_rows[name], query_times[name] = rows, round(elapsed, 3)
                total_query_time += elapsed

        project_inputs: list[dict[str, Any]] = []
        project_effects: list[dict[str, Any]] = []
        try:
            project_inputs = [
                route_b_candidate_from_row(
                    project_id=project_id, revision=project["revision"],
                    candidate_kind="EXTERNAL_INPUT", row=row, detector_commit=detector_commit,
                )
                for row in query_rows["INPUT"]
            ]
            project_effects = [
                route_b_candidate_from_row(
                    project_id=project_id, revision=project["revision"],
                    candidate_kind="SECURITY_EFFECT", row=row, detector_commit=detector_commit,
                )
                for row in query_rows["EFFECT"]
            ]
            project_inputs = list({row["candidate_id"]: row for row in project_inputs}.values())
            project_effects = list({row["candidate_id"]: row for row in project_effects}.values())
        except RouteBError as error:
            errors.append({"query": "CANDIDATE_ADAPTER", "detail": str(error)})
            project_inputs, project_effects = [], []

        if database.is_dir() and project_inputs and project_effects and not errors:
            for name in ("GATE", "CONNECTED"):
                file_name, columns = query_specs[name]
                try:
                    rows, elapsed = _run_table_query(
                        codeql=codeql, database=database,
                        query=query_path / "route_b" / file_name,
                        output=bqrs_dir / f"{project_id}.{name.lower()}.bqrs",
                        log=logs_dir / f"{project_id}.{name.lower()}.codeql.log",
                        columns=columns, threads=threads, ram_mb=ram_mb,
                    )
                except CandidatePathRunError as error:
                    errors.append({"query": name, "detail": str(error)})
                    rows, elapsed = [], 0.0
                query_rows[name], query_times[name] = rows, round(elapsed, 3)
                total_query_time += elapsed

        try:
            project_paths, connected_pairs, path_unmapped = static_paths_from_rows(
                project_id=project_id,
                rows=query_rows["CONNECTED"],
                inputs=project_inputs,
                effects=project_effects,
                detector_commit=detector_commit,
                native_paths=native_by_project.get(project_id, []),
            )
            project_pairs, pair_unmapped = adapt_gated_pairs(
                query_rows["GATE"], project_inputs, project_effects,
                connected_pairs=connected_pairs,
            )
        except (RouteBError, CandidatePathRunError) as error:
            errors.append({"query": "PATH_ADAPTER", "detail": str(error)})
            project_paths, project_pairs = [], []
            path_unmapped = pair_unmapped = len(query_rows["CONNECTED"]) + len(query_rows["GATE"])
        unmapped = path_unmapped + pair_unmapped
        total_unmapped += unmapped
        possible_pairs = len(project_inputs) * len(project_effects)
        statuses.append({
            "project_id": project_id,
            "revision": project["revision"],
            "status": "FAILED" if errors or unmapped else "SUCCESS",
            "route_b_input_candidates": len(project_inputs),
            "route_b_effect_candidates": len(project_effects),
            "possible_pairs_arithmetic_only": possible_pairs,
            "gated_pairs": len(project_pairs),
            "rejected_pairs": max(0, possible_pairs - len(project_pairs)),
            "static_augmented_paths": len(project_paths),
            "native_duplicate_paths": sum(row["augmentation_reason"] == "NATIVE_DUPLICATE" for row in project_paths),
            "query_time_seconds": round(sum(query_times.values()), 3),
            "query_times": query_times,
            "wall_clock_seconds": round(time.monotonic() - project_started, 3),
            "adapter_unmapped_rows": unmapped,
            "errors": errors,
        })
        all_inputs.extend(project_inputs)
        all_effects.extend(project_effects)
        all_pairs.extend(project_pairs)
        all_static_paths.extend(project_paths)

    all_inputs.sort(key=lambda row: str(row["candidate_id"]))
    all_effects.sort(key=lambda row: str(row["candidate_id"]))
    all_pairs.sort(key=lambda row: str(row["pair_id"]))
    all_static_paths.sort(key=lambda row: str(row["candidate_path_id"]))
    unified_pool, native_duplicates, baseline_preservation = build_unified_pool(
        native_paths, all_static_paths
    )
    unique_static = [row for row in unified_pool if row.get("path_origin") == "STATIC_AUGMENTED"]

    write_jsonl(output / "native_candidate_paths.jsonl", native_paths)
    write_jsonl(output / "route_b_input_candidates.jsonl", all_inputs)
    write_jsonl(output / "route_b_effect_candidates.jsonl", all_effects)
    write_jsonl(output / "route_b_gated_pairs.jsonl", all_pairs)
    write_jsonl(output / "static_augmented_paths.jsonl", all_static_paths)
    write_jsonl(output / "native_duplicate_paths.jsonl", native_duplicates)
    write_jsonl(output / "unified_candidate_pool.jsonl", unified_pool)
    write_jsonl(output / "project_status.jsonl", statuses)
    write_jsonl(
        output / "unresolved_candidates.jsonl",
        [row for row in [*all_inputs, *all_effects] if row.get("unresolved_semantics")],
    )

    persisted_native = read_jsonl(output / "native_candidate_paths.jsonl")
    baseline_preservation["native_objects_unchanged"] = persisted_native == native_paths
    if not baseline_preservation["native_objects_unchanged"]:
        baseline_preservation["status"] = "FAIL"
    write_json(output / "baseline_preservation.json", baseline_preservation)

    successes = sum(row["status"] == "SUCCESS" for row in statuses)
    possible_pairs = sum(int(row["possible_pairs_arithmetic_only"]) for row in statuses)
    gated_pairs = len(all_pairs)
    expansion = (len(unified_pool) - len(native_paths)) / len(native_paths) if native_paths else "NOT_EVALUABLE"
    summary = {
        "status": "SUCCESS" if successes == len(projects) and baseline_preservation["status"] == "PASS" else "PARTIAL" if successes else "FAILED",
        "run_id": run_id,
        "projects_total": len(projects),
        "projects_success": successes,
        "codeql_native_paths": len(native_paths),
        "native_paths_retained": baseline_preservation["native_paths_retained"],
        "native_preservation_rate": baseline_preservation["native_preservation_rate"],
        "route_b_input_candidates": len(all_inputs),
        "route_b_effect_candidates": len(all_effects),
        "route_b_gated_pairs": gated_pairs,
        "route_b_rejected_pairs": max(0, possible_pairs - gated_pairs),
        "static_augmented_paths": len(all_static_paths),
        "unique_new_candidate_paths": len(unique_static),
        "native_duplicate_paths": len(native_duplicates),
        "unified_pool_size": len(unified_pool),
        "incremental_candidate_expansion": expansion,
        "path_origin_counts": dict(Counter(str(row.get("path_origin")) for row in unified_pool)),
        "augmentation_reason_counts": dict(Counter(str(row.get("augmentation_reason")) for row in all_static_paths)),
        "route_b_input_reason_counts": dict(Counter(str(row["structural_reason"]) for row in all_inputs)),
        "route_b_effect_reason_counts": dict(Counter(str(row["structural_reason"]) for row in all_effects)),
        "codeql_query_time_seconds": round(total_query_time, 3),
        "wall_clock_seconds": round(time.monotonic() - wall_started, 3),
        "peak_child_rss_kb": _peak_child_rss_kb(),
        "adapter_unmapped_rows": total_unmapped,
        "detector_ground_truth_access": False,
        "scientific_method_changed": "NO",
        "codeql_database_reused": True,
        "codeql_database_rebuilt": False,
        "llm_used": False,
    }
    write_json(output / "detector_metrics.json", summary)
    write_json(output / "summary.json", summary)
    versions = tool_versions()
    write_json(output / "run_manifest.json", {
        "run_id": run_id,
        "experiment": "P0-B-ROUTE-B-STATIC",
        "timestamp_start": started_at,
        "timestamp_end": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "git_commit": detector_commit,
        "git_branch": detector_branch,
        "codeql_version": _codeql_version(codeql),
        "java_version": versions.get("java_version"),
        "projects_requested": len(projects),
        "projects_success": successes,
        "detector_frozen": True,
        "detector_ground_truth_access": False,
        "scientific_method_changed": "NO",
        "status": summary["status"],
    })
    (output / "summary.md").write_text(
        "\n".join([
            f"# {run_id} — Route B Static Augmentation",
            "",
            f"- Status: `{summary['status']}`",
            f"- Native retained: `{summary['native_paths_retained']}/{summary['codeql_native_paths']}`",
            f"- Route B inputs/effects: `{len(all_inputs)}/{len(all_effects)}`",
            f"- Gated pairs: `{gated_pairs}`",
            f"- Static augmented paths: `{len(all_static_paths)}`",
            f"- Native duplicates: `{len(native_duplicates)}`",
            f"- Unified pool: `{len(unified_pool)}`",
            f"- Incremental expansion: `{expansion}`",
            "- detector_ground_truth_access: `false`",
            "- scientific_method_changed: `NO`",
        ]) + "\n",
        encoding="utf-8",
    )
    return summary
