from __future__ import annotations

from java_vuln_research.work1_agent.m7_killtest.evaluator import (
    _causal_shape,
    _classify_failure,
    _path_matches,
)


def test_m7_post_freeze_match_requires_program_location_and_causal_shape() -> None:
    path = {
        "ordered_nodes": [
            {"entity_id": None},
            {"entity_id": "method-1", "repository_relative_path": "src/Foo.java", "start_line": 10, "end_line": 20},
            {"entity_id": None},
        ],
        "ordered_edges": [
            {"relation_kind": "EXTERNAL_INPUT"},
            {"relation_kind": "LIBRARY_FLOW"},
            {"relation_kind": "SECURITY_EFFECT"},
        ],
        "support_summary": {"proposal_edge_count": 3, "structural_edge_count": 1, "deterministic_edge_count": 0},
    }
    assert _path_matches(path, {"mapped_entity_id": "method-1"}) == (True, "METHOD")
    assert _causal_shape(path)


def test_m7_failure_taxonomy_is_multi_label_and_not_detection_metric() -> None:
    labels = _classify_failure(
        summary={"stop_reason": "NO_FURTHER_ACTION", "candidate_path_count": 0, "failures": []},
        proposals=[],
        gates=[],
        tools=[],
        recovered=False,
    )
    assert labels == [
        "AGENT_FAILED_TO_FIND_INPUT",
        "AGENT_FAILED_TO_FIND_EFFECT",
        "AGENT_FAILED_TO_FIND_SEMANTIC_RELATION",
        "MODEL_REASONING_STALLED",
    ]
