from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..common.paths import normalise_program_path, same_program_file


ANCHOR_KINDS = frozenset(
    {
        "CALL_RESULT",
        "METHOD_RETURN",
        "PARAMETER",
        "CALLBACK_PARAMETER",
        "FIELD",
        "RECEIVER",
        "CALL_ARGUMENT",
        "CONSTRUCTOR_ARGUMENT",
        "METHOD_PARAMETER",
    }
)
MAPPING_STATUSES = frozenset({"MAPPED", "UNMAPPABLE", "ADAPTER_ERROR"})
STRUCTURAL_REASONS = frozenset(
    {
        "SAME_METHOD",
        "CALL_ADJACENT",
        "SAME_RECEIVER",
        "FIELD_RELATED",
        "NEAR_CALL_REGION",
        "OTHER_STRUCTURAL",
    }
)


class AnalysisAnchorError(ValueError):
    """Raised when the endpoint/value adapter emits ambiguous evidence."""


def candidate_location(candidate: Mapping[str, Any]) -> dict[str, Any]:
    evidence = candidate.get("evidence")
    if not isinstance(evidence, list) or not evidence or not isinstance(evidence[0], Mapping):
        raise AnalysisAnchorError(f"candidate {candidate.get('candidate_id')!r} has no evidence")
    try:
        file_name, line = str(evidence[0]["file"]), int(evidence[0]["line"])
    except (KeyError, TypeError, ValueError) as error:
        raise AnalysisAnchorError(f"candidate {candidate.get('candidate_id')!r} has invalid evidence") from error
    if not file_name or line < 1:
        raise AnalysisAnchorError(f"candidate {candidate.get('candidate_id')!r} has invalid evidence")
    return {"file": file_name, "line": line}


def _candidate_side(candidate: Mapping[str, Any]) -> str:
    kind = str(candidate.get("kind", ""))
    if kind == "EXTERNAL_INPUT":
        return "INPUT"
    if kind == "SECURITY_EFFECT":
        return "EFFECT"
    raise AnalysisAnchorError(f"unsupported candidate kind: {kind!r}")


def candidate_reference(candidate: Mapping[str, Any]) -> tuple[str, str, str, int]:
    location = candidate_location(candidate)
    return (
        _candidate_side(candidate),
        str(candidate.get("entity", "")),
        normalise_program_path(location["file"]),
        int(location["line"]),
    )


def row_reference(row: Mapping[str, Any], *, side: str | None = None) -> tuple[str, str, str, int]:
    resolved_side = side or str(row.get("candidate_side", ""))
    try:
        return (
            resolved_side,
            str(row["candidate_entity"]),
            normalise_program_path(str(row["candidate_file"])),
            int(row["candidate_line"]),
        )
    except (KeyError, TypeError, ValueError) as error:
        raise AnalysisAnchorError("query row has an invalid candidate reference") from error


def _optional_index(value: Any) -> int | None:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _mapped_anchor(candidate: Mapping[str, Any], project_id: str, row: Mapping[str, Any]) -> dict[str, Any]:
    anchor_kind, value_role = str(row.get("anchor_kind", "")), str(row.get("value_role", ""))
    if anchor_kind not in ANCHOR_KINDS or value_role not in ANCHOR_KINDS:
        raise AnalysisAnchorError(f"unsupported analysis anchor role: {anchor_kind!r}/{value_role!r}")
    try:
        anchor_location = {"file": str(row["anchor_file"]), "line": int(row["anchor_line"])}
    except (KeyError, TypeError, ValueError) as error:
        raise AnalysisAnchorError("mapped analysis anchor needs a valid location") from error
    if not anchor_location["file"] or anchor_location["line"] < 1:
        raise AnalysisAnchorError("mapped analysis anchor needs a valid location")
    return {
        "candidate_id": str(candidate["candidate_id"]),
        "project_id": project_id,
        "candidate_kind": str(candidate["kind"]),
        "candidate_evidence_location": candidate_location(candidate),
        "anchor_kind": anchor_kind,
        "value_role": value_role,
        "method_identity": str(row.get("method_identity", "")),
        "call_identity": str(row.get("call_identity", "")) or None,
        "argument_index": _optional_index(row.get("argument_index")),
        "location": anchor_location,
        "mapping_status": "MAPPED",
        "mapping_reason": str(row.get("mapping_reason", "GENERIC_AST_VALUE_MATCH")),
        "query_status": "SUCCESS",
        "schema_version": 1,
    }


def build_analysis_anchors(
    *, project_id: str, candidates: Iterable[Mapping[str, Any]], rows: Iterable[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row_reference(row)].append(dict(row))
    result: list[dict[str, Any]] = []
    for candidate in sorted(candidates, key=lambda item: str(item.get("candidate_id", ""))):
        matches_by_value = {
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")): row
            for row in grouped.get(candidate_reference(candidate), [])
        }
        matches = list(matches_by_value.values())
        if not matches:
            result.append(
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
                    "mapping_status": "UNMAPPABLE",
                    "mapping_reason": "NO_GENERIC_AST_VALUE_MATCH",
                    "query_status": "SUCCESS",
                    "schema_version": 1,
                }
            )
        elif len(matches) > 1:
            result.append(
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
                    "mapping_reason": "AMBIGUOUS_GENERIC_AST_VALUE_MATCH",
                    "query_status": "SUCCESS",
                    "schema_version": 1,
                }
            )
        else:
            result.append(_mapped_anchor(candidate, project_id, matches[0]))
    return result


def _node_from_row(row: Mapping[str, Any]) -> dict[str, Any]:
    try:
        return {
            "kind": str(row["node_kind"]),
            "entity": str(row["node_entity"]),
            "location": {"file": str(row["node_file"]), "line": int(row["node_line"])},
            "method_identity": str(row.get("node_method_identity", "")),
        }
    except (KeyError, TypeError, ValueError) as error:
        raise AnalysisAnchorError("reachability row has an invalid representative node") from error


def build_funnel_records(
    *, side: str, anchors: Iterable[Mapping[str, Any]], candidates: Iterable[Mapping[str, Any]],
    rows: Iterable[Mapping[str, Any]], representative_limit: int = 5,
    query_status: str = "SUCCESS",
) -> list[dict[str, Any]]:
    if side not in {"INPUT", "EFFECT"}:
        raise AnalysisAnchorError(f"invalid funnel side: {side!r}")
    candidate_by_ref = {candidate_reference(item): dict(item) for item in candidates}
    nodes_by_id: dict[str, dict[str, dict[str, Any]]] = defaultdict(dict)
    for row in rows:
        ref = row_reference(row, side=side)
        candidate = candidate_by_ref.get(ref)
        if candidate is None:
            continue
        node = _node_from_row(row)
        node_key = json.dumps(node, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        nodes_by_id[str(candidate["candidate_id"])][node_key] = node
    records: list[dict[str, Any]] = []
    for anchor in sorted(anchors, key=lambda item: str(item["candidate_id"])):
        candidate_id = str(anchor["candidate_id"])
        nodes = [nodes_by_id[candidate_id][key] for key in sorted(nodes_by_id[candidate_id])]
        mapping_status = str(anchor["mapping_status"])
        if mapping_status == "UNMAPPABLE":
            funnel_status = "UNMAPPABLE_INPUT" if side == "INPUT" else "UNMAPPABLE_EFFECT"
        elif mapping_status == "ADAPTER_ERROR":
            funnel_status = "ADAPTER_ERROR"
        else:
            funnel_status = "ACTIVE" if nodes else ("EMPTY_FW" if side == "INPUT" else "EMPTY_BW")
        records.append(
            {
                "candidate_id": candidate_id,
                "project_id": str(anchor["project_id"]),
                "candidate_side": side,
                "analysis_anchor": dict(anchor) if mapping_status == "MAPPED" else None,
                "reachable_node_count": len(nodes),
                "representative_nodes": nodes[:representative_limit],
                "query_status": query_status,
                "funnel_status": "QUERY_ERROR" if query_status == "QUERY_ERROR" else funnel_status,
            }
        )
    return records


def funnel_summary(input_records: Iterable[Mapping[str, Any]], effect_records: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    inputs, effects = list(input_records), list(effect_records)
    return {
        "external_input": {
            "candidate_total": len(inputs),
            "anchor_mappable": sum(row["analysis_anchor"] is not None for row in inputs),
            "anchor_unmappable": sum(row["funnel_status"] == "UNMAPPABLE_INPUT" for row in inputs),
            "adapter_error": sum(row["funnel_status"] == "ADAPTER_ERROR" for row in inputs),
            "fw_non_empty": sum(row["reachable_node_count"] > 0 for row in inputs),
            "fw_empty": sum(row["funnel_status"] == "EMPTY_FW" for row in inputs),
        },
        "security_effect": {
            "candidate_total": len(effects),
            "anchor_mappable": sum(row["analysis_anchor"] is not None for row in effects),
            "anchor_unmappable": sum(row["funnel_status"] == "UNMAPPABLE_EFFECT" for row in effects),
            "adapter_error": sum(row["funnel_status"] == "ADAPTER_ERROR" for row in effects),
            "bw_non_empty": sum(row["reachable_node_count"] > 0 for row in effects),
            "bw_empty": sum(row["funnel_status"] == "EMPTY_BW" for row in effects),
        },
    }


def analysis_anchor_view(anchor: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: anchor.get(key)
        for key in (
            "candidate_id", "anchor_kind", "value_role", "method_identity", "call_identity",
            "argument_index", "location", "mapping_status", "mapping_reason"
        )
    }


def build_structural_frontiers(
    *, project_id: str, rows: Iterable[Mapping[str, Any]], inputs: Iterable[Mapping[str, Any]],
    effects: Iterable[Mapping[str, Any]], anchors: Iterable[Mapping[str, Any]]
) -> tuple[list[dict[str, Any]], int]:
    input_by_ref = {candidate_reference(row): dict(row) for row in inputs}
    effect_by_ref = {candidate_reference(row): dict(row) for row in effects}
    anchor_by_id = {str(row["candidate_id"]): dict(row) for row in anchors}
    by_id: dict[str, dict[str, Any]] = {}
    unmapped = 0
    for row in rows:
        input_candidate = input_by_ref.get(
            (
                "INPUT", str(row.get("input_candidate_entity", "")),
                normalise_program_path(str(row.get("input_candidate_file", ""))),
                int(row.get("input_candidate_line", 0)),
            )
        )
        effect_candidate = effect_by_ref.get(
            (
                "EFFECT", str(row.get("effect_candidate_entity", "")),
                normalise_program_path(str(row.get("effect_candidate_file", ""))),
                int(row.get("effect_candidate_line", 0)),
            )
        )
        if input_candidate is None or effect_candidate is None:
            unmapped += 1
            continue
        input_id, effect_id = str(input_candidate["candidate_id"]), str(effect_candidate["candidate_id"])
        input_anchor, effect_anchor = anchor_by_id.get(input_id), anchor_by_id.get(effect_id)
        if not input_anchor or not effect_anchor or input_anchor["mapping_status"] != "MAPPED" or effect_anchor["mapping_status"] != "MAPPED":
            unmapped += 1
            continue
        reason = str(row.get("frontier_reason", ""))
        if reason not in STRUCTURAL_REASONS:
            raise AnalysisAnchorError(f"invalid structural frontier reason: {reason!r}")
        fw_node = {
            "kind": str(row["fw_kind"]), "entity": str(row["fw_entity"]),
            "location": {"file": str(row["fw_file"]), "line": int(row["fw_line"])},
            "method_identity": str(row.get("fw_method_identity", "")),
        }
        bw_node = {
            "kind": str(row["bw_kind"]), "entity": str(row["bw_entity"]),
            "location": {"file": str(row["bw_file"]), "line": int(row["bw_line"])},
            "method_identity": str(row.get("bw_method_identity", "")),
        }
        identity = {
            "project_id": project_id, "input_candidate_id": input_id,
            "effect_candidate_id": effect_id, "fw_frontier_node": fw_node,
            "bw_frontier_node": bw_node, "structural_distance": int(row["structural_distance"]),
            "frontier_reason": reason,
        }
        digest = hashlib.sha256(
            json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()[:24]
        by_id[digest] = {
            "structural_frontier_id": f"frontier-{digest}",
            **identity,
            "input_analysis_anchor": analysis_anchor_view(input_anchor),
            "effect_analysis_anchor": analysis_anchor_view(effect_anchor),
            "diagnostic_only": True,
            "adds_propagation_edge": False,
            "classification": "STRUCTURAL_FRONTIER",
            "schema_version": 1,
        }
    return [by_id[key] for key in sorted(by_id)], unmapped


def classify_candidate_diagnostics(
    *, anchors: Iterable[Mapping[str, Any]], input_funnel: Iterable[Mapping[str, Any]],
    effect_funnel: Iterable[Mapping[str, Any]], connected_paths: Iterable[Mapping[str, Any]],
    structural_frontiers: Iterable[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    anchor_by_id = {str(row["candidate_id"]): dict(row) for row in anchors}
    funnel_by_id = {
        str(row["candidate_id"]): dict(row)
        for row in [*list(input_funnel), *list(effect_funnel)]
    }
    connected_ids = {
        str(value)
        for path in connected_paths
        for value in (path.get("input_candidate_id"), path.get("effect_candidate_id"))
    }
    frontier_ids = {
        str(value)
        for case in structural_frontiers
        for value in (case.get("input_candidate_id"), case.get("effect_candidate_id"))
    }
    result: list[dict[str, Any]] = []
    for candidate_id in sorted(anchor_by_id):
        anchor, funnel = anchor_by_id[candidate_id], funnel_by_id.get(candidate_id, {})
        if anchor.get("query_status") == "QUERY_ERROR" or funnel.get("query_status") == "QUERY_ERROR":
            classification = "QUERY_ERROR"
        elif candidate_id in connected_ids:
            classification = "STATIC_CONNECTED"
        elif candidate_id in frontier_ids:
            classification = "STRUCTURAL_FRONTIER"
        elif anchor["mapping_status"] == "UNMAPPABLE":
            classification = "UNMAPPABLE_INPUT" if anchor["candidate_kind"] == "EXTERNAL_INPUT" else "UNMAPPABLE_EFFECT"
        elif anchor["mapping_status"] == "ADAPTER_ERROR":
            classification = "ADAPTER_ERROR"
        elif funnel.get("reachable_node_count", 0) == 0:
            classification = "EMPTY_FW" if anchor["candidate_kind"] == "EXTERNAL_INPUT" else "EMPTY_BW"
        else:
            classification = "DIFFERENT_CALL_REGION"
        result.append(
            {
                "candidate_id": candidate_id,
                "project_id": str(anchor["project_id"]),
                "candidate_kind": str(anchor["candidate_kind"]),
                "classification": classification,
                "mapping_status": str(anchor["mapping_status"]),
                "reachable_node_count": int(funnel.get("reachable_node_count", 0)),
            }
        )
    return result
