from __future__ import annotations

import pytest

from java_vuln_research.frontier import CandidatePathError, build_candidate_path


def _endpoint(candidate_id: str, kind: str, line: int) -> dict:
    return {"candidate_id": candidate_id, "kind": kind, "entity": f"demo.{candidate_id}", "source": "STATIC", "evidence": [{"project": "P001", "revision": "abc123", "file": "src/main/java/demo/A.java", "line": line}]}


def _anchor(candidate_id: str, role: str, line: int) -> dict:
    return {"candidate_id": candidate_id, "mapping_status": "MAPPED", "anchor_kind": role, "value_role": role, "method_identity": "demo.A.m/1", "call_identity": None, "argument_index": 0, "location": {"file": "src/main/java/demo/A.java", "line": line}, "mapping_reason": "TOY"}


def test_candidate_path_is_stable_and_not_a_vulnerability_verdict() -> None:
    input_candidate = _endpoint("ext-1", "EXTERNAL_INPUT", 10)
    effect_candidate = _endpoint("effect-1", "SECURITY_EFFECT", 30)
    middle = {"node_id": "call:demo.process", "entity": "demo.Service.process", "kind": "METHOD", "location": {"file": "src/main/java/demo/A.java", "line": 20}}
    edges = [
        {"from_node_id": "input:ext-1", "to_node_id": "call:demo.process", "mechanism": "DATA", "evidence": {"kind": "ARG_TO_PARAM"}},
        {"from_node_id": "call:demo.process", "to_node_id": "effect:effect-1", "mechanism": "CALL", "evidence": {"kind": "CALL"}},
    ]
    first = build_candidate_path(project_id="P001", input_candidate=input_candidate, effect_candidate=effect_candidate, input_analysis_anchor=_anchor("ext-1", "PARAMETER", 10), effect_analysis_anchor=_anchor("effect-1", "CALL_ARGUMENT", 30), intermediate_nodes=[middle], edges=edges, path_status="COMPLETE_STATIC", detector_commit="commit-1")
    second = build_candidate_path(project_id="P001", input_candidate=input_candidate, effect_candidate=effect_candidate, input_analysis_anchor=_anchor("ext-1", "PARAMETER", 10), effect_analysis_anchor=_anchor("effect-1", "CALL_ARGUMENT", 30), intermediate_nodes=[middle], edges=edges, path_status="COMPLETE_STATIC", detector_commit="commit-1")
    assert first == second
    assert first["candidate_path_id"].startswith("path-")
    assert first["semantic_mechanisms"] == ["CALL", "DATA"]
    assert first["candidate_type_hypothesis"] == "UNKNOWN"
    assert first["input_discovery_route"] == "ROUTE_A"
    assert "CONFIRMED_VULNERABILITY" not in first.values()


def test_frontier_path_requires_explicit_frontier_evidence() -> None:
    with pytest.raises(CandidatePathError, match="frontier_reason"):
        build_candidate_path(project_id="P001", input_candidate=_endpoint("ext-1", "EXTERNAL_INPUT", 10), effect_candidate=_endpoint("effect-1", "SECURITY_EFFECT", 30), input_analysis_anchor=_anchor("ext-1", "PARAMETER", 10), effect_analysis_anchor=_anchor("effect-1", "CALL_ARGUMENT", 30), intermediate_nodes=[], edges=[{"from_node_id": "input:ext-1", "to_node_id": "effect:effect-1", "mechanism": "DATA", "evidence": {"kind": "TOY"}}], path_status="FRONTIER_GAP", detector_commit="commit-1", frontier_nodes=[])
