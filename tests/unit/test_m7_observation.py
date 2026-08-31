from __future__ import annotations

from pathlib import Path

from java_vuln_research.work1_agent.agent import AgentState
from java_vuln_research.work1_agent.agent.observation import (
    MAX_BOOTSTRAP_OBSERVATION_CHARS,
    MAX_OVERVIEW_PACKAGES,
    MAX_RECENT_ENTITIES,
    MAX_RECENT_EVIDENCE,
    MAX_RECENT_FEEDBACK,
    MAX_TOOL_GROUNDED_OBSERVATION_CHARS,
    build_repository_first_observation,
)
from java_vuln_research.work1_agent.repository.entity import ProgramEntity
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex


def _entity(index: int, kind: str = "METHOD") -> ProgramEntity:
    return ProgramEntity.create(
        kind=kind,
        repository_relative_path=f"src/F{index}.java",
        start_line=1,
        end_line=2,
        simple_name=f"m{index}",
        qualified_name=f"p.T{index}.m{index}",
        signature=f"m{index}()",
        provenance={"extractor": "test"},
    )


def test_initial_observation_starts_from_repository_with_empty_native_and_codeql(tmp_path: Path) -> None:
    entities = [_entity(0, "PACKAGE"), _entity(1, "TYPE"), _entity(2)]
    index = RepositoryIndex(tmp_path, entities, [], 3, 0.01)
    state = AgentState.create(project_id="P", repository_identity="repo@abc", provenance={"producer": "test"})
    state.budget.begin_round()
    observation = build_repository_first_observation(
        state=state,
        repository_index=index,
        codeql_status={"project_id": "P", "available": False, "status": "CODEQL_UNAVAILABLE"},
        native_baseline_summary={"available": True, "candidate_path_count": 0},
    )
    value = observation.to_dict()
    assert value["observation_level"] == "BOOTSTRAP"
    assert value["bootstrap"]["program_entity_count"] == 3
    assert value["bootstrap"]["native_baseline_summary"]["candidate_path_count"] == 0
    assert len(value["bootstrap"]["top_packages"]) <= MAX_OVERVIEW_PACKAGES
    assert all(set(item) == {"name", "purpose"} for item in value["bootstrap"]["tools"])
    assert value["runtime_rules"]["frontier_required"] is False
    assert value["runtime_rules"]["codeql_unavailable_means_no_relation"] is False
    assert len(value["bootstrap"]["tools"]) == 17
    assert value["observation_metrics"]["serialized_chars"] == len(observation.to_json())
    assert value["observation_metrics"]["serialized_chars"] <= MAX_BOOTSTRAP_OBSERVATION_CHARS


def test_observation_overview_and_feedback_are_bounded_and_stable(tmp_path: Path) -> None:
    entities = [_entity(index) for index in range(60)]
    index = RepositoryIndex(tmp_path, entities, [], 60, 0.01)
    state = AgentState.create(project_id="P", repository_identity="repo@abc", provenance={"producer": "test"})
    state.budget.begin_round()
    feedback = [{"sequence": index, "tool_name": "SEARCH_CODE", "status": "OK", "items": []} for index in range(20)]
    first = build_repository_first_observation(
        state=state,
        repository_index=index,
        codeql_status={"project_id": "P", "available": True, "status": "READY"},
        recent_feedback=feedback,
    )
    second = build_repository_first_observation(
        state=state,
        repository_index=index,
        codeql_status={"project_id": "P", "available": True, "status": "READY"},
        recent_feedback=feedback,
    )
    assert first.observation_id == second.observation_id
    assert first.payload["observation_level"] == "TOOL_GROUNDED"
    assert len(first.payload["recent_feedback"]) == MAX_RECENT_FEEDBACK
    assert first.payload["tool_grounded_context"]["last_tool_summary"]["tool_name"] == "SEARCH_CODE"
    assert len(first.to_json()) <= MAX_TOOL_GROUNDED_OBSERVATION_CHARS


def test_tool_grounded_observation_caps_entities_evidence_and_large_text(tmp_path: Path) -> None:
    entities = [_entity(index) for index in range(12)]
    index = RepositoryIndex(tmp_path, entities, [], 12, 0.01)
    state = AgentState.create(project_id="P", repository_identity="repo@abc", provenance={"producer": "test"})
    state.budget.begin_round()
    evidence = [
        {
            "evidence_id": f"evidence-{index:024x}",
            "entity_ids": [entity.entity_id],
            "tool_call_id": "toolcall-abc",
            "repository_relative_path": entity.repository_relative_path,
            "start_line": entity.start_line,
            "end_line": entity.end_line,
        }
        for index, entity in enumerate(entities)
    ]
    feedback = [
        {
            "tool_call_id": "toolcall-abc",
            "tool_name": "INSPECT_METHOD",
            "status": "OK",
            "items": [{"entity": entity.to_dict(), "content": "x" * 20000} for entity in entities],
            "evidence_refs": evidence,
        }
    ]

    observation = build_repository_first_observation(
        state=state,
        repository_index=index,
        codeql_status={"project_id": "P", "ready": True, "status": "READY"},
        recent_feedback=feedback,
    )

    context = observation.payload["tool_grounded_context"]
    assert len(context["recent_entities"]) == MAX_RECENT_ENTITIES
    assert len(context["recent_evidence_refs"]) == MAX_RECENT_EVIDENCE
    assert len(observation.payload["recent_feedback"][0]["items"]) == 3
    assert observation.payload["observation_metrics"]["serialized_chars"] == len(observation.to_json())
    assert len(observation.to_json()) <= MAX_TOOL_GROUNDED_OBSERVATION_CHARS


def test_observation_rejects_cross_project_codeql_status(tmp_path: Path) -> None:
    index = RepositoryIndex(tmp_path, [_entity(1)], [], 1, 0.01)
    state = AgentState.create(project_id="P", repository_identity="repo@abc", provenance={"producer": "test"})
    state.budget.begin_round()
    try:
        build_repository_first_observation(state=state, repository_index=index, codeql_status={"project_id": "OTHER"})
    except ValueError as error:
        assert "cross-project" in str(error)
    else:
        raise AssertionError("cross-project CodeQL status must be rejected")
