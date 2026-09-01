from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest

from java_vuln_research.work1_agent.m8_multiagent import (
    FindingType,
    SpecialistFinding,
    SpecialistResult,
    SpecialistResultStatus,
    SpecialistRole,
    SpecialistStopReason,
    SpecialistTaskSpec,
)


ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = ROOT / "schemas"


def _schema(name: str) -> dict[str, object]:
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def _task(*, project_id: str = "P1", role: SpecialistRole = SpecialistRole.INPUT) -> SpecialistTaskSpec:
    return SpecialistTaskSpec.create(
        project_id=project_id,
        specialist_agent=role,
        coordinator_round=1,
        dispatch_index=1,
        objective="Find one program-grounded candidate",
        seed_entity_ids=("entity-1",),
        known_findings=(),
        unresolved_question="Is the selected entity externally influenced?",
        allowed_tools=("SEARCH_SYMBOLS", "INSPECT_METHOD"),
        remaining_specialist_budget={
            "max_internal_rounds": 4,
            "max_tool_calls": 6,
            "max_finding_batches": 1,
        },
        provenance={"producer": "TEST_COORDINATOR", "benchmark_informed": False},
    )


def _finding(*, project_id: str = "P1", role: SpecialistRole = SpecialistRole.INPUT) -> SpecialistFinding:
    finding_type = {
        SpecialistRole.INPUT: FindingType.INPUT,
        SpecialistRole.EFFECT: FindingType.EFFECT,
        SpecialistRole.BRIDGE: FindingType.BRIDGE,
    }[role]
    return SpecialistFinding.create(
        project_id=project_id,
        specialist_agent=role,
        finding_type=finding_type,
        round=1,
        entity_ids=("entity-1",),
        tool_call_ids=("tool-1",),
        evidence_refs=("evidence-1",),
        summary="The inspected parameter has a supported boundary role",
        details={"role": "PARAMETER", "role_index": 0, "confidence": "ORDERING_ONLY"},
        uncertainties=("Caller-side propagation remains unverified",),
        provenance={"producer": role.value, "benchmark_informed": False},
    )


def _result(task: SpecialistTaskSpec, finding: SpecialistFinding) -> SpecialistResult:
    return SpecialistResult.create(
        task_id=task.task_id,
        project_id=task.project_id,
        specialist_agent=task.specialist_agent,
        status=SpecialistResultStatus.FINDINGS,
        findings=(finding,),
        evidence_refs=(
            {
                "evidence_id": "evidence-1",
                "entity_ids": ["entity-1"],
                "tool_call_id": "tool-1",
                "provenance": {"project_id": task.project_id},
            },
        ),
        tool_calls=(
            {
                "tool_call_id": "tool-1",
                "project_id": task.project_id,
                "tool_name": "INSPECT_METHOD",
                "entity_ids": ["entity-1"],
            },
        ),
        next_suggested_evidence=("Inspect one caller",),
        uncertainty=("Interprocedural origin not established",),
        stop_reason=SpecialistStopReason.FINDING_BATCH_READY,
        rounds_used=2,
        provenance={"producer": task.specialist_agent.value, "task_id": task.task_id},
    )


def test_task_finding_and_result_are_canonical_and_schema_valid() -> None:
    task = _task()
    finding = _finding()
    result = _result(task, finding)

    task_schema = _schema("m8_specialist_task_spec.schema.json")
    finding_schema = _schema("m8_specialist_finding.schema.json")
    result_schema = _schema("m8_specialist_result.schema.json")
    resolver = jsonschema.RefResolver.from_schema(
        result_schema,
        store={"m8_specialist_finding.schema.json": finding_schema},
    )
    jsonschema.validate(task.to_dict(), task_schema)
    jsonschema.validate(finding.to_dict(), finding_schema)
    jsonschema.validate(result.to_dict(), result_schema, resolver=resolver)

    assert SpecialistTaskSpec.from_dict(task.to_dict()) == task
    assert SpecialistFinding.from_dict(finding.to_dict()) == finding
    assert SpecialistResult.from_dict(result.to_dict()) == result


def test_contract_identity_is_stable_and_tampering_fails_closed() -> None:
    task = _task()
    assert _task().task_id == task.task_id
    tampered = task.to_dict()
    tampered["objective"] = "Changed objective"
    with pytest.raises(ValueError, match="task_id is not canonical"):
        SpecialistTaskSpec.from_dict(tampered)


def test_task_rejects_tool_prohibition_overlap_and_duplicate_seeds() -> None:
    with pytest.raises(ValueError, match="disjoint"):
        SpecialistTaskSpec.create(
            project_id="P1",
            specialist_agent=SpecialistRole.INPUT,
            coordinator_round=1,
            dispatch_index=1,
            objective="Find input",
            seed_entity_ids=(),
            unresolved_question="Any input?",
            allowed_tools=("SEARCH_CODE",),
            remaining_specialist_budget={"max_internal_rounds": 1, "max_tool_calls": 1, "max_finding_batches": 1},
            prohibited_actions=("SEARCH_CODE",),
            provenance={"producer": "TEST"},
        )
    with pytest.raises(ValueError, match="duplicates"):
        SpecialistTaskSpec.create(
            project_id="P1",
            specialist_agent=SpecialistRole.INPUT,
            coordinator_round=1,
            dispatch_index=1,
            objective="Find input",
            seed_entity_ids=("e", "e"),
            unresolved_question="Any input?",
            allowed_tools=("SEARCH_CODE",),
            remaining_specialist_budget={"max_internal_rounds": 1, "max_tool_calls": 1, "max_finding_batches": 1},
            provenance={"producer": "TEST"},
        )


def test_specialist_cannot_emit_another_roles_finding() -> None:
    with pytest.raises(ValueError, match="cannot emit"):
        SpecialistFinding.create(
            project_id="P1",
            specialist_agent=SpecialistRole.INPUT,
            finding_type=FindingType.EFFECT,
            round=1,
            entity_ids=("entity-1",),
            tool_call_ids=("tool-1",),
            evidence_refs=("evidence-1",),
            summary="Invalid cross-role finding",
            details={"effect_category": "NETWORK"},
            provenance={"producer": "TEST"},
        )


def test_non_findings_result_cannot_smuggle_findings() -> None:
    task = _task()
    with pytest.raises(ValueError, match="must not carry findings"):
        SpecialistResult.create(
            task_id=task.task_id,
            project_id=task.project_id,
            specialist_agent=task.specialist_agent,
            status=SpecialistResultStatus.NEED_MORE_EVIDENCE,
            findings=(_finding(),),
            stop_reason=SpecialistStopReason.NEED_MORE_EVIDENCE,
            rounds_used=1,
            provenance={"producer": "TEST"},
        )


def test_result_status_and_stop_reason_must_match() -> None:
    task = _task()
    with pytest.raises(ValueError, match="incompatible"):
        SpecialistResult.create(
            task_id=task.task_id,
            project_id=task.project_id,
            specialist_agent=task.specialist_agent,
            status=SpecialistResultStatus.NEED_MORE_EVIDENCE,
            stop_reason=SpecialistStopReason.ERROR,
            rounds_used=1,
            provenance={"producer": "TEST"},
        )


def test_one_finding_batch_may_contain_multiple_grounded_findings() -> None:
    task = _task()
    first = _finding()
    second = SpecialistFinding.create(
        project_id="P1",
        specialist_agent=SpecialistRole.INPUT,
        finding_type=FindingType.INPUT,
        round=2,
        entity_ids=("entity-2",),
        tool_call_ids=("tool-2",),
        evidence_refs=("evidence-2",),
        summary="A second independently grounded callback parameter",
        details={"role": "PARAMETER", "role_index": 1},
        provenance={"producer": "INPUT_AGENT"},
    )
    result = SpecialistResult.create(
        task_id=task.task_id,
        project_id=task.project_id,
        specialist_agent=task.specialist_agent,
        status=SpecialistResultStatus.FINDINGS,
        findings=(first, second),
        evidence_refs=(
            {"evidence_id": "evidence-1"},
            {"evidence_id": "evidence-2"},
        ),
        tool_calls=(
            {"tool_call_id": "tool-1", "project_id": "P1"},
            {"tool_call_id": "tool-2", "project_id": "P1"},
        ),
        stop_reason=SpecialistStopReason.FINDING_BATCH_READY,
        rounds_used=2,
        provenance={"producer": "INPUT_AGENT"},
    )
    assert len(result.findings) == 2
