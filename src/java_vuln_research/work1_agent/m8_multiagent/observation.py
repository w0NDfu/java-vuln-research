"""Role-minimal, measured specialist observations."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.agent.tool_adapter import AgentToolResult
from java_vuln_research.work1_agent.proposal.evidence import EvidenceRef
from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest
from java_vuln_research.work1_agent.repository.entity import ProgramEntity
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex

from .contracts import SpecialistRole, SpecialistTaskSpec


OBSERVATION_VERSION = 1
MAX_OBSERVATION_BYTES = 16 * 1024


def _bounded(value: Any, *, depth: int = 0) -> Any:
    if isinstance(value, str):
        return value if len(value) <= 1200 else value[:1199] + "..."
    if isinstance(value, Mapping):
        if depth >= 4:
            return {"summary": f"mapping[{len(value)}]"}
        return {
            str(key): _bounded(value[key], depth=depth + 1)
            for key in sorted(value, key=str)[:20]
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if depth >= 4:
            return {"summary": f"sequence[{len(value)}]"}
        return [_bounded(item, depth=depth + 1) for item in value[:10]]
    return value


def _entity(entity: ProgramEntity) -> dict[str, Any]:
    return {
        "entity_id": entity.entity_id,
        "kind": entity.kind.value,
        "qualified_name": entity.qualified_name,
        "signature": entity.signature,
        "repository_relative_path": entity.repository_relative_path,
        "start_line": entity.start_line,
        "end_line": entity.end_line,
        "enclosing_type": entity.enclosing_type,
        "enclosing_callable": entity.enclosing_callable,
        "codeql_identity_available": entity.codeql_identity is not None,
    }


def _tool_result(result: AgentToolResult) -> dict[str, Any]:
    return {
        "tool_call_id": result.tool_call_id,
        "tool_name": result.tool_name,
        "status": result.status.value,
        "summary": _bounded(result.summary),
        "warnings": list(result.warnings),
        "truncated": result.truncated,
        "failure": _bounded(result.failure),
    }


def _evidence(evidence: EvidenceRef) -> dict[str, Any]:
    return {
        "evidence_id": evidence.evidence_id,
        "source_kind": evidence.source_kind.value,
        "entity_ids": list(evidence.entity_ids),
        "tool_call_id": evidence.tool_call_id,
        "confidence": evidence.confidence.value,
        "repository_relative_path": evidence.repository_relative_path,
        "start_line": evidence.start_line,
        "end_line": evidence.end_line,
    }


def _duplicate_section_bytes(current: Mapping[str, Any], previous: Mapping[str, Any] | None) -> int:
    if previous is None:
        return 0
    return sum(
        len(canonical_json({key: current[key]}).encode("utf-8"))
        for key in current.keys() & previous.keys()
        if current[key] == previous[key]
    )


@dataclass(frozen=True, slots=True)
class SpecialistObservation:
    observation_id: str
    project_id: str
    specialist_agent: SpecialistRole
    internal_round: int
    payload: Mapping[str, Any]
    serialized_bytes: int
    estimated_input_tokens: int
    duplicated_observation_bytes: int
    schema_version: int = OBSERVATION_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "project_id": self.project_id,
            "specialist_agent": self.specialist_agent.value,
            "internal_round": self.internal_round,
            **dict(self.payload),
            "observation_metrics": {
                "serialized_bytes": self.serialized_bytes,
                "estimated_input_tokens": self.estimated_input_tokens,
                "token_estimate_method": "ceil(utf8_bytes/4)",
                "duplicated_observation_bytes": self.duplicated_observation_bytes,
                "duplicate_method": "identical_top_level_sections",
                "hard_ceiling_bytes": MAX_OBSERVATION_BYTES,
            },
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def build_specialist_observation(
    *,
    task: SpecialistTaskSpec,
    repository_index: RepositoryIndex,
    internal_round: int,
    tool_results: Sequence[AgentToolResult] = (),
    evidence_refs: Sequence[EvidenceRef] = (),
    previous_observation: SpecialistObservation | None = None,
) -> SpecialistObservation:
    if internal_round < 1:
        raise ValueError("specialist internal_round must be positive")
    entities = {item.entity_id: item for item in repository_index.entities}
    missing = sorted(set(task.seed_entity_ids) - set(entities))
    if missing:
        raise ValueError("TaskSpec contains seed entities outside RepositoryIndex: " + ",".join(missing))
    if any(result.project_id != task.project_id for result in tool_results):
        raise ValueError("specialist observation contains cross-project tool results")

    known = [_bounded(dict(item)) for item in task.known_findings[-8:]]
    role_context_key = {
        SpecialistRole.INPUT: "external_input_context",
        SpecialistRole.EFFECT: "security_effect_context",
        SpecialistRole.BRIDGE: "semantic_bridge_context",
    }[task.specialist_agent]
    role_context: dict[str, Any] = {
        "seed_entities": [_entity(entities[item]) for item in task.seed_entity_ids],
        "known_findings": known,
        "recent_tool_results": [_tool_result(item) for item in tool_results[-3:]],
        "recent_evidence_refs": [_evidence(item) for item in evidence_refs[-12:]],
    }
    if task.specialist_agent is SpecialistRole.BRIDGE:
        role_context["input_findings"] = [
            item for item in known if item.get("finding_type") == "INPUT_FINDING"
        ]
        role_context["effect_findings"] = [
            item for item in known if item.get("finding_type") == "EFFECT_FINDING"
        ]

    payload: dict[str, Any] = {
        "task": {
            "task_id": task.task_id,
            "coordinator_round": task.coordinator_round,
            "dispatch_index": task.dispatch_index,
            "objective": task.objective,
            "unresolved_question": task.unresolved_question,
            "allowed_tools": list(task.allowed_tools),
            "prohibited_actions": list(task.prohibited_actions),
        },
        role_context_key: role_context,
        "remaining_dispatch_budget": {
            "internal_rounds": max(0, int(task.remaining_specialist_budget["max_internal_rounds"]) - internal_round + 1),
            "tool_calls": max(0, int(task.remaining_specialist_budget["max_tool_calls"]) - len(tool_results)),
            "finding_batches": int(task.remaining_specialist_budget["max_finding_batches"]),
        },
        "runtime_rules": {
            "one_action_per_round": True,
            "finding_is_proposal": False,
            "candidate_path_is_vulnerability": False,
            "codeql_unavailable_is_negative": False,
        },
    }
    previous_payload = previous_observation.payload if previous_observation is not None else None
    duplicated = _duplicate_section_bytes(payload, previous_payload)
    identity = {
        "schema_version": OBSERVATION_VERSION,
        "project_id": task.project_id,
        "specialist_agent": task.specialist_agent.value,
        "internal_round": internal_round,
        "payload": payload,
    }
    observation_id = stable_digest("m8observation", identity)
    size = 0
    estimate = 0
    for _ in range(8):
        observation = SpecialistObservation(
            observation_id=observation_id,
            project_id=task.project_id,
            specialist_agent=task.specialist_agent,
            internal_round=internal_round,
            payload=payload,
            serialized_bytes=size,
            estimated_input_tokens=estimate,
            duplicated_observation_bytes=duplicated,
        )
        actual = len(observation.to_json().encode("utf-8"))
        next_estimate = math.ceil(actual / 4)
        if actual == size and next_estimate == estimate:
            break
        size, estimate = actual, next_estimate
    else:
        raise ValueError("specialist observation size accounting did not converge")
    if size > MAX_OBSERVATION_BYTES:
        raise ValueError("specialist observation exceeds hard byte ceiling")
    return observation
