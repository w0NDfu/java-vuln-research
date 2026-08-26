from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable, Mapping


SCHEMA_VERSION = 1
ROUTE_BY_SOURCE = {"STATIC": "ROUTE_A", "STATIC_DERIVED": "ROUTE_A"}
SUPPORTED_MECHANISMS = frozenset({"DATA", "CALL"})
PATH_STATUSES = frozenset({"COMPLETE_STATIC", "PARTIAL_STATIC", "FRONTIER_GAP"})
FRONTIER_REASONS = frozenset({"FIELD_STATE_UNKNOWN", "LIBRARY_WRAPPER_UNKNOWN", "FRAMEWORK_UNKNOWN", "OTHER"})


class CandidatePathError(ValueError):
    """Raised when a Work1 Candidate Path would violate its frozen boundary."""


def discovery_route(candidate: Mapping[str, Any]) -> str:
    """Map existing deterministic endpoint provenance to a Work1 route."""
    source = candidate.get("source")
    try:
        return ROUTE_BY_SOURCE[str(source)]
    except KeyError as error:
        raise CandidatePathError(f"unsupported endpoint source for W1-E1: {source!r}") from error


def _location(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        file_name = str(value["file"])
        line = int(value["line"])
    except (KeyError, TypeError, ValueError) as error:
        raise CandidatePathError("location must contain a non-empty file and integer line") from error
    if not file_name or line < 1:
        raise CandidatePathError("location must contain a non-empty file and positive line")
    return {"file": file_name, "line": line}


def endpoint_location(candidate: Mapping[str, Any]) -> dict[str, Any]:
    evidence = candidate.get("evidence")
    if not isinstance(evidence, list) or not evidence or not isinstance(evidence[0], Mapping):
        raise CandidatePathError(f"endpoint {candidate.get('candidate_id')!r} has no usable evidence")
    return _location(evidence[0])


def endpoint_node(candidate: Mapping[str, Any], *, side: str) -> dict[str, Any]:
    identifier, entity = str(candidate.get("candidate_id", "")), str(candidate.get("entity", ""))
    if not identifier or not entity:
        raise CandidatePathError("endpoint must have candidate_id and entity")
    return {"node_id": f"{side}:{identifier}", "entity": entity, "kind": str(candidate.get("kind", "ENDPOINT")), "location": endpoint_location(candidate)}


def _normalise_nodes(nodes: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in nodes:
        node_id, entity, kind = str(raw.get("node_id", "")), str(raw.get("entity", "")), str(raw.get("kind", ""))
        if not node_id or not entity or not kind:
            raise CandidatePathError("path nodes need node_id, entity, and kind")
        if node_id in seen:
            raise CandidatePathError(f"duplicate path node: {node_id}")
        seen.add(node_id)
        result.append({"node_id": node_id, "entity": entity, "kind": kind, "location": _location(raw["location"])})
    return result


def _normalise_edges(edges: Iterable[Mapping[str, Any]], node_ids: set[str]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for raw in edges:
        mechanism = str(raw.get("mechanism", ""))
        if mechanism not in SUPPORTED_MECHANISMS:
            raise CandidatePathError(f"W1-E1 supports only DATA/CALL edges, got {mechanism!r}")
        source, target = str(raw.get("from_node_id", "")), str(raw.get("to_node_id", ""))
        if source not in node_ids or target not in node_ids:
            raise CandidatePathError("path edge references an unknown node")
        evidence = raw.get("evidence")
        if not isinstance(evidence, Mapping):
            raise CandidatePathError("path edge must have object evidence")
        result.append({"from_node_id": source, "to_node_id": target, "mechanism": mechanism, "evidence": dict(evidence)})
    return result


def _path_id(material: Mapping[str, Any]) -> str:
    text = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "path-" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


def build_candidate_path(*, project_id: str, input_candidate: Mapping[str, Any], effect_candidate: Mapping[str, Any], intermediate_nodes: Iterable[Mapping[str, Any]], edges: Iterable[Mapping[str, Any]], path_status: str, detector_commit: str, unresolved_relations: Iterable[Mapping[str, Any]] = (), frontier_nodes: Iterable[Mapping[str, Any]] = (), frontier_reason: str | None = None, candidate_type_hypothesis: str = "UNKNOWN", provenance: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Build an immutable Work1 path without asserting a vulnerability verdict."""
    if not project_id or not detector_commit:
        raise CandidatePathError("project_id and detector_commit are required")
    if path_status not in PATH_STATUSES:
        raise CandidatePathError(f"unsupported path status: {path_status!r}")
    if path_status == "FRONTIER_GAP" and frontier_reason not in FRONTIER_REASONS:
        raise CandidatePathError("FRONTIER_GAP requires a known frontier_reason")
    if path_status != "FRONTIER_GAP" and frontier_reason is not None:
        raise CandidatePathError("only FRONTIER_GAP may have a frontier_reason")
    input_node, effect_node = endpoint_node(input_candidate, side="input"), endpoint_node(effect_candidate, side="effect")
    nodes = _normalise_nodes([input_node, *intermediate_nodes, effect_node])
    path_edges = _normalise_edges(edges, {node["node_id"] for node in nodes})
    mechanisms = sorted({edge["mechanism"] for edge in path_edges})
    if not mechanisms:
        raise CandidatePathError("candidate path must contain at least one DATA/CALL edge")
    normalised_frontier = _normalise_nodes(frontier_nodes)
    if path_status == "FRONTIER_GAP" and not normalised_frontier:
        raise CandidatePathError("FRONTIER_GAP requires frontier_nodes")
    if path_status != "FRONTIER_GAP" and normalised_frontier:
        raise CandidatePathError("only FRONTIER_GAP may have frontier_nodes")
    references = [
        {"candidate_id": str(input_candidate["candidate_id"]), "role": "INPUT_ANCHOR", "location": endpoint_location(input_candidate)},
        {"candidate_id": str(effect_candidate["candidate_id"]), "role": "EFFECT_ANCHOR", "location": endpoint_location(effect_candidate)},
    ]
    source_locations = [endpoint_location(input_candidate), endpoint_location(effect_candidate)]
    for node in nodes[1:-1]:
        if node["location"] not in source_locations:
            source_locations.append(node["location"])
    identity = {"project_id": project_id, "input_candidate_id": str(input_candidate["candidate_id"]), "effect_candidate_id": str(effect_candidate["candidate_id"]), "path_nodes": nodes, "path_edges": path_edges, "path_status": path_status, "frontier_nodes": normalised_frontier, "frontier_reason": frontier_reason}
    return {
        "candidate_path_id": _path_id(identity), "project_id": project_id,
        "input_candidate_id": str(input_candidate["candidate_id"]), "effect_candidate_id": str(effect_candidate["candidate_id"]),
        "input_entity": str(input_candidate["entity"]), "effect_entity": str(effect_candidate["entity"]),
        "input_discovery_route": discovery_route(input_candidate), "effect_discovery_route": discovery_route(effect_candidate),
        "path_nodes": nodes, "path_edges": path_edges, "semantic_mechanisms": mechanisms,
        "unresolved_relations": [dict(item) for item in unresolved_relations], "path_status": path_status,
        "frontier_nodes": normalised_frontier, "frontier_reason": frontier_reason,
        "candidate_type_hypothesis": candidate_type_hypothesis or "UNKNOWN", "evidence_refs": references,
        "source_locations": source_locations, "provenance": dict(provenance or {}),
        "schema_version": SCHEMA_VERSION, "detector_commit": detector_commit,
    }
