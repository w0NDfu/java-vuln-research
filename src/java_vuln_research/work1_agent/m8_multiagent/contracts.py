"""Typed, replayable coordinator/specialist exchange contracts.

These contracts deliberately contain no LLM runtime.  They define the only
messages that M8 specialists may exchange with the coordinator through the
project-local SharedEvidenceBoard.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest


CONTRACT_SCHEMA_VERSION = 1
DEFAULT_PROHIBITED_ACTIONS = (
    "READ_BENCHMARK_ANSWER",
    "READ_EVALUATOR_ANNOTATION",
    "AUTHOR_ARBITRARY_QL",
    "BYPASS_EVIDENCE_GATE",
    "DECLARE_VULNERABILITY",
)


class SpecialistRole(str, Enum):
    INPUT = "INPUT_AGENT"
    EFFECT = "EFFECT_AGENT"
    BRIDGE = "BRIDGE_AGENT"


class FindingType(str, Enum):
    INPUT = "INPUT_FINDING"
    EFFECT = "EFFECT_FINDING"
    BRIDGE = "BRIDGE_FINDING"


ROLE_FINDING_TYPES = {
    SpecialistRole.INPUT: FindingType.INPUT,
    SpecialistRole.EFFECT: FindingType.EFFECT,
    SpecialistRole.BRIDGE: FindingType.BRIDGE,
}


class SpecialistResultStatus(str, Enum):
    FINDINGS = "FINDINGS"
    NEED_MORE_EVIDENCE = "NEED_MORE_EVIDENCE"
    NO_SUPPORTED_FINDING = "NO_SUPPORTED_FINDING"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    FAILED = "FAILED"


class SpecialistStopReason(str, Enum):
    FINDING_BATCH_READY = "FINDING_BATCH_READY"
    NEED_MORE_EVIDENCE = "NEED_MORE_EVIDENCE"
    NO_SUPPORTED_FINDING = "NO_SUPPORTED_FINDING"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    ERROR = "ERROR"


STATUS_STOP_REASONS = {
    SpecialistResultStatus.FINDINGS: SpecialistStopReason.FINDING_BATCH_READY,
    SpecialistResultStatus.NEED_MORE_EVIDENCE: SpecialistStopReason.NEED_MORE_EVIDENCE,
    SpecialistResultStatus.NO_SUPPORTED_FINDING: SpecialistStopReason.NO_SUPPORTED_FINDING,
    SpecialistResultStatus.BUDGET_EXHAUSTED: SpecialistStopReason.BUDGET_EXHAUSTED,
    SpecialistResultStatus.TOOL_UNAVAILABLE: SpecialistStopReason.TOOL_UNAVAILABLE,
    SpecialistResultStatus.FAILED: SpecialistStopReason.ERROR,
}


def _non_empty(value: str, name: str) -> str:
    text = str(value).strip()
    if not text:
        raise ValueError(f"{name} is required")
    return text


def _unique_strings(values: Sequence[str], name: str, *, required: bool = False) -> tuple[str, ...]:
    result = tuple(_non_empty(item, name) for item in values)
    if required and not result:
        raise ValueError(f"{name} requires at least one value")
    if len(result) != len(set(result)):
        raise ValueError(f"{name} must not contain duplicates")
    return result


def _json_mapping(value: Mapping[str, Any], name: str, *, required: bool = False) -> dict[str, Any]:
    result = dict(value)
    if required and not result:
        raise ValueError(f"{name} is required")
    canonical_json(result)
    return result


def _artifact_id(value: Mapping[str, Any], key: str) -> str:
    return _non_empty(str(value.get(key) or ""), key)


@dataclass(frozen=True, slots=True)
class SpecialistTaskSpec:
    task_id: str
    project_id: str
    specialist_agent: SpecialistRole
    coordinator_round: int
    dispatch_index: int
    objective: str
    seed_entity_ids: tuple[str, ...]
    known_findings: tuple[Mapping[str, Any], ...]
    unresolved_question: str
    allowed_tools: tuple[str, ...]
    remaining_specialist_budget: Mapping[str, int]
    prohibited_actions: tuple[str, ...]
    provenance: Mapping[str, Any]
    schema_version: int = CONTRACT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CONTRACT_SCHEMA_VERSION:
            raise ValueError("unsupported SpecialistTaskSpec schema version")
        _non_empty(self.project_id, "project_id")
        _non_empty(self.objective, "objective")
        _non_empty(self.unresolved_question, "unresolved_question")
        _unique_strings(self.seed_entity_ids, "seed_entity_ids")
        _unique_strings(self.allowed_tools, "allowed_tools", required=True)
        _unique_strings(self.prohibited_actions, "prohibited_actions", required=True)
        if set(self.allowed_tools).intersection(self.prohibited_actions):
            raise ValueError("allowed_tools and prohibited_actions must be disjoint")
        if self.coordinator_round < 1 or self.dispatch_index < 1:
            raise ValueError("coordinator_round and dispatch_index must be positive")
        required_budget = {"max_internal_rounds", "max_tool_calls", "max_finding_batches"}
        if set(self.remaining_specialist_budget) != required_budget:
            raise ValueError("remaining_specialist_budget has an invalid key set")
        if any(int(value) < 0 for value in self.remaining_specialist_budget.values()):
            raise ValueError("remaining specialist budget values must be non-negative")
        for finding in self.known_findings:
            _artifact_id(finding, "finding_id")
            canonical_json(dict(finding))
        _json_mapping(self.provenance, "provenance", required=True)
        if self.task_id != self.compute_id(self.identity_material()):
            raise ValueError("task_id is not canonical")

    def identity_material(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "specialist_agent": self.specialist_agent.value,
            "coordinator_round": self.coordinator_round,
            "dispatch_index": self.dispatch_index,
            "objective": self.objective,
            "seed_entity_ids": list(self.seed_entity_ids),
            "known_findings": [dict(item) for item in self.known_findings],
            "unresolved_question": self.unresolved_question,
            "allowed_tools": list(self.allowed_tools),
            "remaining_specialist_budget": dict(self.remaining_specialist_budget),
            "prohibited_actions": list(self.prohibited_actions),
        }

    @staticmethod
    def compute_id(material: Mapping[str, Any]) -> str:
        return stable_digest("m8task", dict(material))

    @classmethod
    def create(
        cls,
        *,
        project_id: str,
        specialist_agent: SpecialistRole | str,
        coordinator_round: int,
        dispatch_index: int,
        objective: str,
        seed_entity_ids: Sequence[str] = (),
        known_findings: Sequence[Mapping[str, Any]] = (),
        unresolved_question: str,
        allowed_tools: Sequence[str],
        remaining_specialist_budget: Mapping[str, int],
        prohibited_actions: Sequence[str] = DEFAULT_PROHIBITED_ACTIONS,
        provenance: Mapping[str, Any],
    ) -> "SpecialistTaskSpec":
        values = {
            "project_id": _non_empty(project_id, "project_id"),
            "specialist_agent": SpecialistRole(specialist_agent),
            "coordinator_round": int(coordinator_round),
            "dispatch_index": int(dispatch_index),
            "objective": _non_empty(objective, "objective"),
            "seed_entity_ids": _unique_strings(seed_entity_ids, "seed_entity_ids"),
            "known_findings": tuple(dict(item) for item in known_findings),
            "unresolved_question": _non_empty(unresolved_question, "unresolved_question"),
            "allowed_tools": _unique_strings(allowed_tools, "allowed_tools", required=True),
            "remaining_specialist_budget": {
                str(key): int(value) for key, value in remaining_specialist_budget.items()
            },
            "prohibited_actions": _unique_strings(prohibited_actions, "prohibited_actions", required=True),
            "provenance": _json_mapping(provenance, "provenance", required=True),
        }
        material = {
            **values,
            "specialist_agent": values["specialist_agent"].value,
            "seed_entity_ids": list(values["seed_entity_ids"]),
            "known_findings": [dict(item) for item in values["known_findings"]],
            "allowed_tools": list(values["allowed_tools"]),
            "prohibited_actions": list(values["prohibited_actions"]),
            "provenance": None,
        }
        material.pop("provenance")
        return cls(task_id=cls.compute_id(material), **values)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SpecialistTaskSpec":
        return cls(
            task_id=str(value["task_id"]),
            project_id=str(value["project_id"]),
            specialist_agent=SpecialistRole(value["specialist_agent"]),
            coordinator_round=int(value["coordinator_round"]),
            dispatch_index=int(value["dispatch_index"]),
            objective=str(value["objective"]),
            seed_entity_ids=tuple(str(item) for item in value["seed_entity_ids"]),
            known_findings=tuple(dict(item) for item in value["known_findings"]),
            unresolved_question=str(value["unresolved_question"]),
            allowed_tools=tuple(str(item) for item in value["allowed_tools"]),
            remaining_specialist_budget={str(key): int(item) for key, item in dict(value["remaining_specialist_budget"]).items()},
            prohibited_actions=tuple(str(item) for item in value["prohibited_actions"]),
            provenance=dict(value["provenance"]),
            schema_version=int(value.get("schema_version", CONTRACT_SCHEMA_VERSION)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "project_id": self.project_id,
            "specialist_agent": self.specialist_agent.value,
            "coordinator_round": self.coordinator_round,
            "dispatch_index": self.dispatch_index,
            "objective": self.objective,
            "seed_entity_ids": list(self.seed_entity_ids),
            "known_findings": [dict(item) for item in self.known_findings],
            "unresolved_question": self.unresolved_question,
            "allowed_tools": list(self.allowed_tools),
            "remaining_specialist_budget": dict(self.remaining_specialist_budget),
            "prohibited_actions": list(self.prohibited_actions),
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True, slots=True)
class SpecialistFinding:
    finding_id: str
    project_id: str
    specialist_agent: SpecialistRole
    finding_type: FindingType
    round: int
    entity_ids: tuple[str, ...]
    tool_call_ids: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    summary: str
    details: Mapping[str, Any]
    uncertainties: tuple[str, ...]
    provenance: Mapping[str, Any]
    schema_version: int = CONTRACT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CONTRACT_SCHEMA_VERSION:
            raise ValueError("unsupported SpecialistFinding schema version")
        _non_empty(self.project_id, "project_id")
        if self.round < 1:
            raise ValueError("finding round must be positive")
        if ROLE_FINDING_TYPES[self.specialist_agent] is not self.finding_type:
            raise ValueError("specialist role cannot emit this finding type")
        _unique_strings(self.entity_ids, "entity_ids", required=True)
        _unique_strings(self.tool_call_ids, "tool_call_ids", required=True)
        _unique_strings(self.evidence_refs, "evidence_refs", required=True)
        _non_empty(self.summary, "summary")
        _json_mapping(self.details, "details", required=True)
        _unique_strings(self.uncertainties, "uncertainties")
        _json_mapping(self.provenance, "provenance", required=True)
        if self.finding_id != self.compute_id(self.identity_material()):
            raise ValueError("finding_id is not canonical")

    def identity_material(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "specialist_agent": self.specialist_agent.value,
            "finding_type": self.finding_type.value,
            "round": self.round,
            "entity_ids": list(self.entity_ids),
            "tool_call_ids": list(self.tool_call_ids),
            "evidence_refs": list(self.evidence_refs),
            "summary": self.summary,
            "details": dict(self.details),
            "uncertainties": list(self.uncertainties),
        }

    @staticmethod
    def compute_id(material: Mapping[str, Any]) -> str:
        return stable_digest("m8finding", dict(material))

    @classmethod
    def create(
        cls,
        *,
        project_id: str,
        specialist_agent: SpecialistRole | str,
        finding_type: FindingType | str,
        round: int,
        entity_ids: Sequence[str],
        tool_call_ids: Sequence[str],
        evidence_refs: Sequence[str],
        summary: str,
        details: Mapping[str, Any],
        uncertainties: Sequence[str] = (),
        provenance: Mapping[str, Any],
    ) -> "SpecialistFinding":
        values = {
            "project_id": _non_empty(project_id, "project_id"),
            "specialist_agent": SpecialistRole(specialist_agent),
            "finding_type": FindingType(finding_type),
            "round": int(round),
            "entity_ids": _unique_strings(entity_ids, "entity_ids", required=True),
            "tool_call_ids": _unique_strings(tool_call_ids, "tool_call_ids", required=True),
            "evidence_refs": _unique_strings(evidence_refs, "evidence_refs", required=True),
            "summary": _non_empty(summary, "summary"),
            "details": _json_mapping(details, "details", required=True),
            "uncertainties": _unique_strings(uncertainties, "uncertainties"),
            "provenance": _json_mapping(provenance, "provenance", required=True),
        }
        material = {
            **values,
            "specialist_agent": values["specialist_agent"].value,
            "finding_type": values["finding_type"].value,
            "entity_ids": list(values["entity_ids"]),
            "tool_call_ids": list(values["tool_call_ids"]),
            "evidence_refs": list(values["evidence_refs"]),
            "uncertainties": list(values["uncertainties"]),
        }
        material.pop("provenance")
        return cls(finding_id=cls.compute_id(material), **values)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SpecialistFinding":
        return cls(
            finding_id=str(value["finding_id"]),
            project_id=str(value["project_id"]),
            specialist_agent=SpecialistRole(value["specialist_agent"]),
            finding_type=FindingType(value["finding_type"]),
            round=int(value["round"]),
            entity_ids=tuple(str(item) for item in value["entity_ids"]),
            tool_call_ids=tuple(str(item) for item in value["tool_call_ids"]),
            evidence_refs=tuple(str(item) for item in value["evidence_refs"]),
            summary=str(value["summary"]),
            details=dict(value["details"]),
            uncertainties=tuple(str(item) for item in value["uncertainties"]),
            provenance=dict(value["provenance"]),
            schema_version=int(value.get("schema_version", CONTRACT_SCHEMA_VERSION)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "finding_id": self.finding_id,
            "project_id": self.project_id,
            "specialist_agent": self.specialist_agent.value,
            "finding_type": self.finding_type.value,
            "round": self.round,
            "entity_ids": list(self.entity_ids),
            "tool_call_ids": list(self.tool_call_ids),
            "evidence_refs": list(self.evidence_refs),
            "summary": self.summary,
            "details": dict(self.details),
            "uncertainties": list(self.uncertainties),
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True, slots=True)
class SpecialistResult:
    result_id: str
    task_id: str
    project_id: str
    specialist_agent: SpecialistRole
    status: SpecialistResultStatus
    findings: tuple[SpecialistFinding, ...]
    evidence_refs: tuple[Mapping[str, Any], ...]
    tool_calls: tuple[Mapping[str, Any], ...]
    next_suggested_evidence: tuple[str, ...]
    uncertainty: tuple[str, ...]
    stop_reason: SpecialistStopReason
    rounds_used: int
    tool_calls_used: int
    provenance: Mapping[str, Any]
    schema_version: int = CONTRACT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != CONTRACT_SCHEMA_VERSION:
            raise ValueError("unsupported SpecialistResult schema version")
        _non_empty(self.task_id, "task_id")
        _non_empty(self.project_id, "project_id")
        if self.rounds_used < 0 or self.tool_calls_used < 0:
            raise ValueError("specialist usage must be non-negative")
        if self.tool_calls_used != len(self.tool_calls):
            raise ValueError("tool_calls_used must equal serialized tool_calls")
        if self.status is SpecialistResultStatus.FINDINGS and not self.findings:
            raise ValueError("FINDINGS status requires at least one finding")
        if self.status is not SpecialistResultStatus.FINDINGS and self.findings:
            raise ValueError("non-FINDINGS result must not carry findings")
        if self.stop_reason is not STATUS_STOP_REASONS[self.status]:
            raise ValueError("specialist status and stop_reason are incompatible")
        if self.findings and self.rounds_used < 1:
            raise ValueError("a finding batch requires at least one internal round")
        for finding in self.findings:
            if finding.project_id != self.project_id or finding.specialist_agent is not self.specialist_agent:
                raise ValueError("result contains a cross-project or cross-role finding")
        evidence_ids = [_artifact_id(item, "evidence_id") for item in self.evidence_refs]
        tool_ids = [_artifact_id(item, "tool_call_id") for item in self.tool_calls]
        if len(evidence_ids) != len(set(evidence_ids)) or len(tool_ids) != len(set(tool_ids)):
            raise ValueError("result artifacts must have unique IDs")
        for artifact in (*self.evidence_refs, *self.tool_calls):
            canonical_json(dict(artifact))
            artifact_project = artifact.get("project_id")
            if artifact_project is not None and str(artifact_project) != self.project_id:
                raise ValueError("result artifact is cross-project")
        _unique_strings(self.next_suggested_evidence, "next_suggested_evidence")
        _unique_strings(self.uncertainty, "uncertainty")
        _json_mapping(self.provenance, "provenance", required=True)
        if self.result_id != self.compute_id(self.identity_material()):
            raise ValueError("result_id is not canonical")

    def identity_material(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "project_id": self.project_id,
            "specialist_agent": self.specialist_agent.value,
            "status": self.status.value,
            "findings": [item.to_dict() for item in self.findings],
            "evidence_refs": [dict(item) for item in self.evidence_refs],
            "tool_calls": [dict(item) for item in self.tool_calls],
            "next_suggested_evidence": list(self.next_suggested_evidence),
            "uncertainty": list(self.uncertainty),
            "stop_reason": self.stop_reason.value,
            "rounds_used": self.rounds_used,
            "tool_calls_used": self.tool_calls_used,
        }

    @staticmethod
    def compute_id(material: Mapping[str, Any]) -> str:
        return stable_digest("m8result", dict(material))

    @classmethod
    def create(
        cls,
        *,
        task_id: str,
        project_id: str,
        specialist_agent: SpecialistRole | str,
        status: SpecialistResultStatus | str,
        findings: Sequence[SpecialistFinding] = (),
        evidence_refs: Sequence[Mapping[str, Any]] = (),
        tool_calls: Sequence[Mapping[str, Any]] = (),
        next_suggested_evidence: Sequence[str] = (),
        uncertainty: Sequence[str] = (),
        stop_reason: SpecialistStopReason | str,
        rounds_used: int,
        provenance: Mapping[str, Any],
    ) -> "SpecialistResult":
        values = {
            "task_id": _non_empty(task_id, "task_id"),
            "project_id": _non_empty(project_id, "project_id"),
            "specialist_agent": SpecialistRole(specialist_agent),
            "status": SpecialistResultStatus(status),
            "findings": tuple(findings),
            "evidence_refs": tuple(dict(item) for item in evidence_refs),
            "tool_calls": tuple(dict(item) for item in tool_calls),
            "next_suggested_evidence": _unique_strings(next_suggested_evidence, "next_suggested_evidence"),
            "uncertainty": _unique_strings(uncertainty, "uncertainty"),
            "stop_reason": SpecialistStopReason(stop_reason),
            "rounds_used": int(rounds_used),
            "tool_calls_used": len(tool_calls),
            "provenance": _json_mapping(provenance, "provenance", required=True),
        }
        material = {
            **values,
            "specialist_agent": values["specialist_agent"].value,
            "status": values["status"].value,
            "findings": [item.to_dict() for item in values["findings"]],
            "evidence_refs": [dict(item) for item in values["evidence_refs"]],
            "tool_calls": [dict(item) for item in values["tool_calls"]],
            "next_suggested_evidence": list(values["next_suggested_evidence"]),
            "uncertainty": list(values["uncertainty"]),
            "stop_reason": values["stop_reason"].value,
        }
        material.pop("provenance")
        return cls(result_id=cls.compute_id(material), **values)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SpecialistResult":
        return cls(
            result_id=str(value["result_id"]),
            task_id=str(value["task_id"]),
            project_id=str(value["project_id"]),
            specialist_agent=SpecialistRole(value["specialist_agent"]),
            status=SpecialistResultStatus(value["status"]),
            findings=tuple(SpecialistFinding.from_dict(item) for item in value["findings"]),
            evidence_refs=tuple(dict(item) for item in value["evidence_refs"]),
            tool_calls=tuple(dict(item) for item in value["tool_calls"]),
            next_suggested_evidence=tuple(str(item) for item in value["next_suggested_evidence"]),
            uncertainty=tuple(str(item) for item in value["uncertainty"]),
            stop_reason=SpecialistStopReason(value["stop_reason"]),
            rounds_used=int(value["rounds_used"]),
            tool_calls_used=int(value["tool_calls_used"]),
            provenance=dict(value["provenance"]),
            schema_version=int(value.get("schema_version", CONTRACT_SCHEMA_VERSION)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "result_id": self.result_id,
            "task_id": self.task_id,
            "project_id": self.project_id,
            "specialist_agent": self.specialist_agent.value,
            "status": self.status.value,
            "findings": [item.to_dict() for item in self.findings],
            "evidence_refs": [dict(item) for item in self.evidence_refs],
            "tool_calls": [dict(item) for item in self.tool_calls],
            "next_suggested_evidence": list(self.next_suggested_evidence),
            "uncertainty": list(self.uncertainty),
            "stop_reason": self.stop_reason.value,
            "rounds_used": self.rounds_used,
            "tool_calls_used": self.tool_calls_used,
            "provenance": dict(self.provenance),
        }
