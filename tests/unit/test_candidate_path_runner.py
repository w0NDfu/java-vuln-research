from __future__ import annotations

from java_vuln_research.frontier.analysis_anchor import (
    build_analysis_anchors,
    build_funnel_records,
    build_structural_frontiers,
    classify_candidate_diagnostics,
)
from java_vuln_research.frontier.runner import connected_paths_from_rows


def _endpoint(candidate_id: str, kind: str, entity: str, file_name: str, line: int) -> dict:
    return {
        "candidate_id": candidate_id,
        "kind": kind,
        "entity": entity,
        "source": "STATIC",
        "evidence": [
            {"project": "P001", "revision": "abc123", "file": file_name, "line": line}
        ],
    }


def _anchor_row(side: str, entity: str, file_name: str, line: int, role: str) -> dict:
    return {
        "candidate_side": side,
        "candidate_entity": entity,
        "candidate_file": file_name,
        "candidate_line": str(line),
        "anchor_kind": role,
        "value_role": role,
        "method_identity": "demo.Controller.entry/1",
        "call_identity": "" if role == "PARAMETER" else "demo.Effect.call@src/Toy.java:30",
        "argument_index": "0" if role in {"PARAMETER", "CALL_ARGUMENT"} else "-1",
        "anchor_file": file_name,
        "anchor_line": str(line),
        "mapping_status": "MAPPED",
        "mapping_reason": "TOY_GENERIC_VALUE_ROLE",
    }


def _reach_row(entity: str, candidate_line: int, node_line: int) -> dict:
    return {
        "candidate_entity": entity,
        "candidate_file": "src/Toy.java",
        "candidate_line": str(candidate_line),
        "node_kind": "CALL_ARGUMENT",
        "node_entity": f"demo.call argument {node_line}",
        "node_file": "src/Toy.java",
        "node_line": str(node_line),
        "node_method_identity": "demo.Controller.entry/1",
    }


def test_toy_a_connected_pipeline_has_mapped_active_anchors_and_static_path() -> None:
    input_candidate = _endpoint("ext-1", "EXTERNAL_INPUT", "demo.input", "src/Toy.java", 10)
    effect_candidate = _endpoint("eff-1", "SECURITY_EFFECT", "demo.effect", "src/Toy.java", 30)
    anchors = build_analysis_anchors(
        project_id="P001",
        candidates=[input_candidate, effect_candidate],
        rows=[
            _anchor_row("INPUT", "demo.input", "src/Toy.java", 10, "PARAMETER"),
            _anchor_row("EFFECT", "demo.effect", "src/Toy.java", 30, "CALL_ARGUMENT"),
        ],
    )
    anchor_by_id = {row["candidate_id"]: row for row in anchors}
    fw = build_funnel_records(
        side="INPUT", anchors=[anchor_by_id["ext-1"]], candidates=[input_candidate],
        rows=[_reach_row("demo.input", 10, 20)],
    )
    bw = build_funnel_records(
        side="EFFECT", anchors=[anchor_by_id["eff-1"]], candidates=[effect_candidate],
        rows=[_reach_row("demo.effect", 30, 25)],
    )
    paths, unmapped = connected_paths_from_rows(
        project_id="P001",
        rows=[{
            "input_candidate_entity": "demo.input", "input_candidate_file": "src/Toy.java",
            "input_candidate_line": "10", "effect_candidate_entity": "demo.effect",
            "effect_candidate_file": "src/Toy.java", "effect_candidate_line": "30",
        }],
        inputs=[input_candidate], effects=[effect_candidate], anchors=anchors,
        detector_commit="commit-1",
    )

    assert unmapped == 0
    assert anchor_by_id["ext-1"]["mapping_status"] == anchor_by_id["eff-1"]["mapping_status"] == "MAPPED"
    assert fw[0]["reachable_node_count"] == bw[0]["reachable_node_count"] == 1
    assert len(paths) == 1
    assert paths[0]["path_status"] == "COMPLETE_STATIC"
    assert paths[0]["semantic_mechanisms"] == ["DATA"]
    assert paths[0]["input_analysis_anchor"]["value_role"] == "PARAMETER"


def test_toy_b_disconnected_pipeline_has_no_static_path() -> None:
    input_candidate = _endpoint("ext-1", "EXTERNAL_INPUT", "demo.input", "src/Toy.java", 10)
    effect_candidate = _endpoint("eff-1", "SECURITY_EFFECT", "demo.effect", "src/Toy.java", 30)
    anchors = build_analysis_anchors(
        project_id="P001", candidates=[input_candidate, effect_candidate],
        rows=[
            _anchor_row("INPUT", "demo.input", "src/Toy.java", 10, "PARAMETER"),
            _anchor_row("EFFECT", "demo.effect", "src/Toy.java", 30, "CALL_ARGUMENT"),
        ],
    )
    anchor_by_id = {row["candidate_id"]: row for row in anchors}
    paths, unmapped = connected_paths_from_rows(
        project_id="P001", rows=[], inputs=[input_candidate], effects=[effect_candidate],
        anchors=anchors, detector_commit="commit-1",
    )
    assert unmapped == 0
    assert paths == []


def test_toy_c_structural_frontier_is_diagnostic_and_adds_no_edge() -> None:
    input_candidate = _endpoint("ext-1", "EXTERNAL_INPUT", "demo.input", "src/Toy.java", 10)
    effect_candidate = _endpoint("eff-1", "SECURITY_EFFECT", "demo.effect", "src/Toy.java", 30)
    anchors = build_analysis_anchors(
        project_id="P001", candidates=[input_candidate, effect_candidate],
        rows=[
            _anchor_row("INPUT", "demo.input", "src/Toy.java", 10, "PARAMETER"),
            _anchor_row("EFFECT", "demo.effect", "src/Toy.java", 30, "CALL_ARGUMENT"),
        ],
    )
    anchor_by_id = {row["candidate_id"]: row for row in anchors}
    frontiers, unmapped = build_structural_frontiers(
        project_id="P001",
        rows=[{
            "input_candidate_entity": "demo.input", "input_candidate_file": "src/Toy.java",
            "input_candidate_line": "10", "effect_candidate_entity": "demo.effect",
            "effect_candidate_file": "src/Toy.java", "effect_candidate_line": "30",
            "fw_kind": "CALL_ARGUMENT", "fw_entity": "demo.left", "fw_file": "src/Toy.java",
            "fw_line": "20", "fw_method_identity": "demo.entry/1",
            "bw_kind": "CALL_ARGUMENT", "bw_entity": "demo.right", "bw_file": "src/Toy.java",
            "bw_line": "25", "bw_method_identity": "demo.entry/1",
            "structural_distance": "0", "frontier_reason": "SAME_METHOD",
        }],
        inputs=[input_candidate], effects=[effect_candidate], anchors=anchors,
    )
    assert unmapped == 0
    assert len(frontiers) == 1
    assert frontiers[0]["classification"] == "STRUCTURAL_FRONTIER"
    assert frontiers[0]["diagnostic_only"] is True
    assert frontiers[0]["adds_propagation_edge"] is False

    fw = build_funnel_records(
        side="INPUT", anchors=[anchor_by_id["ext-1"]], candidates=[input_candidate],
        rows=[_reach_row("demo.input", 10, 20)],
    )
    bw = build_funnel_records(
        side="EFFECT", anchors=[anchor_by_id["eff-1"]], candidates=[effect_candidate],
        rows=[_reach_row("demo.effect", 30, 25)],
    )
    diagnostics = classify_candidate_diagnostics(
        anchors=anchors, input_funnel=fw, effect_funnel=bw,
        connected_paths=[], structural_frontiers=frontiers,
    )
    assert {row["classification"] for row in diagnostics} == {"STRUCTURAL_FRONTIER"}
