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
    bounded_tool_catalog,
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


def test_bootstrap_tool_catalog_explains_literal_search_and_relation_followups() -> None:
    catalog = {item["name"]: item for item in bounded_tool_catalog()}
    assert "one case-insensitive literal substring" in catalog["SEARCH_CODE"]["purpose"]
    assert "do not bundle alternative terms" in catalog["SEARCH_SYMBOLS"]["purpose"]
    assert "TYPE or interface entity ID" in catalog["GET_IMPLEMENTATIONS"]["purpose"]
    assert "abstract, interface-only, or bodyless" in catalog["GET_OVERRIDES"]["purpose"]


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
    feedback_item = {
        "tool_call_id": "toolcall-abc",
        "tool_name": "INSPECT_METHOD",
        "status": "OK",
        "items": [{"entity": entity.to_dict(), "content": "x" * 20000} for entity in entities],
        "evidence_refs": evidence,
    }
    feedback = [dict(feedback_item, tool_call_id=f"toolcall-{index}") for index in range(3)]

    observation = build_repository_first_observation(
        state=state,
        repository_index=index,
        codeql_status={"project_id": "P", "ready": True, "status": "READY"},
        recent_feedback=feedback,
    )

    context = observation.payload["tool_grounded_context"]
    assert len(context["recent_entities"]) == MAX_RECENT_ENTITIES
    assert len(context["recent_evidence_refs"]) == MAX_RECENT_EVIDENCE
    assert all("items" not in row for row in observation.payload["recent_feedback"][:-1])
    assert len(observation.payload["recent_feedback"][-1]["items"]) == 3
    assert all(
        len(item["content"]) <= 1200
        for row in observation.payload["recent_feedback"]
        for item in row.get("items", [])
    )
    assert observation.payload["observation_metrics"]["serialized_chars"] == len(observation.to_json())
    assert len(observation.to_json()) <= MAX_TOOL_GROUNDED_OBSERVATION_CHARS


def test_compacted_search_feedback_keeps_owner_callable_for_call_hits(tmp_path: Path) -> None:
    call = _entity(1, "CALL")
    owner = _entity(2, "METHOD")
    index = RepositoryIndex(tmp_path, [call, owner], [], 1, 0.01)
    state = AgentState.create(project_id="P", repository_identity="repo@abc", provenance={"producer": "test"})
    state.budget.begin_round()
    feedback = [{
        "tool_call_id": "toolcall-owner",
        "tool_name": "SEARCH_CODE",
        "status": "OK",
        "items": [{
            "entity": {
                **call.to_dict(),
                "owner_callable": owner.to_dict(),
            },
            "snippet": "owner();",
        }],
    }]

    observation = build_repository_first_observation(
        state=state,
        repository_index=index,
        codeql_status={"project_id": "P", "ready": False, "status": "UNAVAILABLE"},
        recent_feedback=feedback,
    )

    compact = observation.payload["recent_feedback"][0]["items"][0]["entity"]
    assert compact["owner_callable"]["entity_id"] == owner.entity_id
    recent_ids = {
        item["entity_id"] for item in observation.payload["tool_grounded_context"]["recent_entities"]
    }
    assert owner.entity_id in recent_ids


def test_tool_grounded_observation_falls_back_to_latest_summary_when_needed(tmp_path: Path) -> None:
    entities = [_entity(index) for index in range(4)]
    index = RepositoryIndex(tmp_path, entities, [], 4, 0.01)
    state = AgentState.create(project_id="P", repository_identity="repo@abc", provenance={"producer": "test"})
    state.budget.begin_round()
    huge_items = [
        {
            "entity": entity.to_dict(),
            "content": "x" * 20000,
            "nodes": [{f"key-{n}": "y" * 500 for n in range(12)} for _ in range(5)],
        }
        for entity in entities
    ]
    feedback = [
        {
            "tool_call_id": f"toolcall-{index}",
            "tool_name": "INSPECT_METHOD",
            "status": "OK",
            "items": huge_items,
            "summary": {f"summary-{n}": "z" * 1000 for n in range(12)},
        }
        for index in range(3)
    ]

    observation = build_repository_first_observation(
        state=state,
        repository_index=index,
        codeql_status={"project_id": "P", "ready": True, "status": "READY"},
        recent_feedback=feedback,
    )

    assert len(observation.to_json()) <= MAX_TOOL_GROUNDED_OBSERVATION_CHARS
    if observation.payload["tool_grounded_context"].get("observation_compaction"):
        assert observation.payload["tool_grounded_context"]["observation_compaction"] == "LATEST_FEEDBACK_SUMMARY_ONLY"
        assert len(observation.payload["recent_feedback"]) == 1
        assert "items" not in observation.payload["recent_feedback"][0]


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
