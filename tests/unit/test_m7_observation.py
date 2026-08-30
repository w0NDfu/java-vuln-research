from __future__ import annotations

from pathlib import Path

from java_vuln_research.work1_agent.agent import AgentState
from java_vuln_research.work1_agent.agent.observation import (
    MAX_OBSERVATION_CHARS,
    MAX_OVERVIEW_METHODS,
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
    assert value["repository_summary"]["program_entity_count"] == 3
    assert value["native_baseline_summary"]["candidate_path_count"] == 0
    assert value["runtime_rules"]["frontier_required"] is False
    assert value["runtime_rules"]["codeql_unavailable_means_no_relation"] is False
    assert len(value["tool_catalog"]) == 17


def test_observation_overview_and_feedback_are_bounded_and_stable(tmp_path: Path) -> None:
    entities = [_entity(index) for index in range(60)]
    index = RepositoryIndex(tmp_path, entities, [], 60, 0.01)
    state = AgentState.create(project_id="P", repository_identity="repo@abc", provenance={"producer": "test"})
    state.budget.begin_round()
    feedback = [{"sequence": index, "text": "x" * 100} for index in range(20)]
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
    assert len(first.payload["bounded_overview"]["methods"]) == MAX_OVERVIEW_METHODS
    assert len(first.payload["recent_feedback"]) == 10
    assert len(first.to_json()) <= MAX_OBSERVATION_CHARS


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
