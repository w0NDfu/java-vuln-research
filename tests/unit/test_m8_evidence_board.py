from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from java_vuln_research.work1_agent.m8_multiagent import (
    FindingType,
    SharedEvidenceBoard,
    SpecialistFinding,
    SpecialistResult,
    SpecialistResultStatus,
    SpecialistRole,
    SpecialistStopReason,
    SpecialistTaskSpec,
    read_board_snapshot,
    replay_board,
    write_board_events,
    write_board_snapshot,
)


ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas"


def _board(project_id: str = "P1") -> SharedEvidenceBoard:
    return SharedEvidenceBoard.create(
        project_id=project_id,
        repository_summary={"project_id": project_id, "java_file_count": 3, "entity_count": 20},
        codeql_status={"project_id": project_id, "ready": True, "database_identity": "db-sha"},
        budget_state={"coordinator_rounds_remaining": 12},
        round_state={"coordinator_round": 0},
        unresolved_questions=("Find an external-input candidate",),
    )


def _task(*, project_id: str = "P1", dispatch_index: int = 1, max_rounds: int = 4) -> SpecialistTaskSpec:
    return SpecialistTaskSpec.create(
        project_id=project_id,
        specialist_agent=SpecialistRole.INPUT,
        coordinator_round=dispatch_index,
        dispatch_index=dispatch_index,
        objective="Find input evidence",
        unresolved_question="Is entity-1 externally influenced?",
        allowed_tools=("INSPECT_METHOD",),
        remaining_specialist_budget={
            "max_internal_rounds": max_rounds,
            "max_tool_calls": 6,
            "max_finding_batches": 1,
        },
        provenance={"producer": "TEST_COORDINATOR", "benchmark_informed": False},
    )


def _finding(*, project_id: str = "P1", evidence_id: str = "evidence-1", tool_id: str = "tool-1") -> SpecialistFinding:
    return SpecialistFinding.create(
        project_id=project_id,
        specialist_agent=SpecialistRole.INPUT,
        finding_type=FindingType.INPUT,
        round=1,
        entity_ids=("entity-1",),
        tool_call_ids=(tool_id,),
        evidence_refs=(evidence_id,),
        summary="A framework callback parameter is externally supplied",
        details={"role": "PARAMETER", "role_index": 0, "recommended_scope": "CALLABLE_LOCAL"},
        provenance={"producer": "INPUT_AGENT", "benchmark_informed": False},
    )


def _result(
    task: SpecialistTaskSpec,
    *,
    finding: SpecialistFinding | None = None,
    tool: dict[str, object] | None = None,
    evidence: dict[str, object] | None = None,
    rounds_used: int = 2,
) -> SpecialistResult:
    selected_finding = finding or _finding(project_id=task.project_id)
    selected_tool = tool or {
        "tool_call_id": "tool-1",
        "project_id": task.project_id,
        "tool_name": "INSPECT_METHOD",
        "entity_ids": ["entity-1"],
    }
    selected_evidence = evidence or {
        "evidence_id": "evidence-1",
        "entity_ids": ["entity-1"],
        "tool_call_id": "tool-1",
        "provenance": {"project_id": task.project_id},
    }
    return SpecialistResult.create(
        task_id=task.task_id,
        project_id=task.project_id,
        specialist_agent=task.specialist_agent,
        status=SpecialistResultStatus.FINDINGS,
        findings=(selected_finding,),
        evidence_refs=(selected_evidence,),
        tool_calls=(selected_tool,),
        next_suggested_evidence=("Inspect the caller chain",),
        uncertainty=("No interprocedural flow evidence yet",),
        stop_reason=SpecialistStopReason.FINDING_BATCH_READY,
        rounds_used=rounds_used,
        provenance={"producer": "INPUT_AGENT", "task_id": task.task_id},
    )


def test_board_merge_tracks_structured_state_and_provenance() -> None:
    board = _board()
    task = _task()
    result = _result(task)
    event = board.merge_specialist_result(task, result)

    assert [item.finding_id for item in board.input_findings] == [result.findings[0].finding_id]
    assert not board.effect_findings and not board.bridge_findings
    assert board.inspected_entities == ["entity-1"]
    assert len(board.tool_calls) == len(board.evidence_refs) == 1
    assert board.agent_states[SpecialistRole.INPUT].dispatches == 1
    assert board.agent_states[SpecialistRole.INPUT].internal_rounds == 2
    assert board.agent_states[SpecialistRole.INPUT].tool_calls == 1
    assert event.sequence == 2
    assert event.provenance["benchmark_informed"] is False
    assert board.round_state["last_result_id"] == result.result_id


def test_board_snapshot_schema_and_replay_are_deterministic(tmp_path: Path) -> None:
    board = _board()
    board.merge_specialist_result(_task(), _result(_task()))
    snapshot = tmp_path / "board.json"
    events = tmp_path / "board_events.jsonl"
    write_board_snapshot(snapshot, board)
    write_board_events(events, board.event_log)

    finding_schema = json.loads((SCHEMAS / "m8_specialist_finding.schema.json").read_text(encoding="utf-8"))
    board_schema = json.loads((SCHEMAS / "m8_shared_evidence_board.schema.json").read_text(encoding="utf-8"))
    resolver = jsonschema.RefResolver.from_schema(
        board_schema,
        store={
            "m8_specialist_finding.schema.json": finding_schema,
            "m8_shared_evidence_board.schema.json": board_schema,
        },
    )
    jsonschema.validate(board.to_dict(), board_schema, resolver=resolver)

    assert read_board_snapshot(snapshot).to_dict() == board.to_dict()
    assert replay_board(events).to_dict() == board.to_dict()
    assert SharedEvidenceBoard.replay(board.event_log).to_dict() == board.to_dict()


def test_board_rejects_cross_project_result() -> None:
    board = _board("P1")
    task = _task(project_id="P2")
    with pytest.raises(ValueError, match="cross-project"):
        board.merge_specialist_result(task, _result(task))


def test_board_rejects_duplicate_task_merge() -> None:
    board = _board()
    task = _task()
    result = _result(task)
    board.merge_specialist_result(task, result)
    with pytest.raises(ValueError, match="already been merged"):
        board.merge_specialist_result(task, result)


def test_board_rejects_unknown_finding_artifacts() -> None:
    board = _board()
    task = _task()
    missing = _finding(evidence_id="missing-evidence", tool_id="missing-tool")
    result = _result(task, finding=missing)
    with pytest.raises(ValueError, match="unknown artifacts"):
        board.merge_specialist_result(task, result)


def test_board_rejects_artifact_collision_and_budget_overrun() -> None:
    board = _board()
    first_task = _task()
    board.merge_specialist_result(first_task, _result(first_task))

    second_task = _task(dispatch_index=2)
    conflicting = {
        "tool_call_id": "tool-1",
        "project_id": "P1",
        "tool_name": "SEARCH_CODE",
        "entity_ids": ["entity-1"],
    }
    with pytest.raises(ValueError, match="collision"):
        board.merge_specialist_result(second_task, _result(second_task, tool=conflicting))

    limited_task = _task(dispatch_index=3, max_rounds=1)
    with pytest.raises(ValueError, match="round budget"):
        _board().merge_specialist_result(limited_task, _result(limited_task, rounds_used=2))


def test_failed_specialist_result_is_replayable_failed_hypothesis() -> None:
    board = _board()
    task = _task()
    result = SpecialistResult.create(
        task_id=task.task_id,
        project_id=task.project_id,
        specialist_agent=task.specialist_agent,
        status=SpecialistResultStatus.NO_SUPPORTED_FINDING,
        next_suggested_evidence=("Try one CodeQL caller query",),
        uncertainty=("Repository evidence is insufficient",),
        stop_reason=SpecialistStopReason.NO_SUPPORTED_FINDING,
        rounds_used=1,
        provenance={"producer": "INPUT_AGENT", "task_id": task.task_id},
    )
    board.merge_specialist_result(task, result)
    assert board.failed_hypotheses[0]["status"] == "NO_SUPPORTED_FINDING"
    assert SharedEvidenceBoard.replay(board.event_log).to_dict() == board.to_dict()
