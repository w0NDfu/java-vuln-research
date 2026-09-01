"""Compact, replay-derived M8 Coordinator observations."""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest

from .board import SharedEvidenceBoard


COORDINATOR_OBSERVATION_VERSION = 2
MAX_COORDINATOR_OBSERVATION_BYTES = 32 * 1024


def _select(value: Mapping[str, Any], names: Sequence[str]) -> dict[str, Any]:
    return {name: value[name] for name in names if name in value}


def _bounded(value: Any, *, depth: int = 0) -> Any:
    if isinstance(value, str):
        return value if len(value) <= 1600 else value[:1599] + "..."
    if isinstance(value, Mapping):
        if depth >= 5:
            return {"summary": f"mapping[{len(value)}]"}
        return {
            str(key): _bounded(value[key], depth=depth + 1)
            for key in sorted(value, key=str)[:24]
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if depth >= 5:
            return {"summary": f"sequence[{len(value)}]"}
        return [_bounded(item, depth=depth + 1) for item in value[:12]]
    return value


def _duplicate_bytes(current: Mapping[str, Any], previous: Mapping[str, Any] | None) -> int:
    if previous is None:
        return 0
    return sum(
        len(canonical_json({key: current[key]}).encode("utf-8"))
        for key in current.keys() & previous.keys()
        if current[key] == previous[key]
    )


def _compact_tool_call(value: Mapping[str, Any]) -> dict[str, Any]:
    return _bounded(
        _select(
            value,
            (
                "tool_call_id",
                "tool_name",
                "status",
                "truncated",
                "warnings",
                "failure",
                "summary",
            ),
        )
    )


def _compact_gate_result(value: Mapping[str, Any]) -> dict[str, Any]:
    # Resolved evidence is already represented by recent_evidence_refs. Repeating
    # its excerpts here can push late-round observations over the hard ceiling.
    return _bounded(
        _select(
            value,
            (
                "proposal_id",
                "status",
                "checks",
                "missing_evidence",
                "warnings",
                "rejection_reasons",
                "coordinator_round",
                "supporting_finding_ids",
            ),
        )
    )


def _exact_dispatch_tool_policy(
    value: Mapping[str, Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    keys = {
        "specialist_agent",
        "allowed_tools",
        "non_empty_subset_required",
        "canonical_names_case_sensitive",
    }
    for action_type in sorted(value):
        entry = value[action_type]
        if set(entry) != keys:
            raise ValueError("dispatch tool policy entry has an invalid key set")
        tools = entry["allowed_tools"]
        if not isinstance(tools, Sequence) or isinstance(
            tools, (str, bytes, bytearray)
        ):
            raise ValueError("dispatch allowed_tools must be an array of strings")
        if not tools or any(not isinstance(item, str) or not item for item in tools):
            raise ValueError("dispatch allowed_tools must contain non-empty strings")
        if len(tools) != len(set(tools)):
            raise ValueError("dispatch allowed_tools must be unique")
        result[str(action_type)] = {
            "specialist_agent": str(entry["specialist_agent"]),
            "allowed_tools": list(tools),
            "non_empty_subset_required": bool(entry["non_empty_subset_required"]),
            "canonical_names_case_sensitive": bool(
                entry["canonical_names_case_sensitive"]
            ),
        }
    return result


@dataclass(frozen=True, slots=True)
class CoordinatorObservation:
    observation_id: str
    project_id: str
    coordinator_round: int
    payload: Mapping[str, Any]
    serialized_bytes: int
    estimated_input_tokens: int
    duplicated_observation_bytes: int
    schema_version: int = COORDINATOR_OBSERVATION_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "project_id": self.project_id,
            "coordinator_round": self.coordinator_round,
            **dict(self.payload),
            "observation_metrics": {
                "serialized_bytes": self.serialized_bytes,
                "estimated_input_tokens": self.estimated_input_tokens,
                "token_estimate_method": "ceil(utf8_bytes/4)",
                "duplicated_observation_bytes": self.duplicated_observation_bytes,
                "duplicate_method": "identical_top_level_sections",
                "hard_ceiling_bytes": MAX_COORDINATOR_OBSERVATION_BYTES,
            },
        }


def build_coordinator_observation(
    *,
    board: SharedEvidenceBoard,
    coordinator_round: int,
    dispatch_tool_policy: Mapping[str, Mapping[str, Any]],
    previous_observation: CoordinatorObservation | None = None,
) -> CoordinatorObservation:
    if coordinator_round < 1:
        raise ValueError("coordinator_round must be positive")
    if not dispatch_tool_policy:
        raise ValueError("dispatch_tool_policy is required")
    repository = _select(
        board.repository_summary,
        (
            "project_id",
            "repository_identity",
            "java_file_count",
            "program_entity_count",
            "entity_count",
            "entity_kind_counts",
            "top_packages",
            "top_level_entities",
        ),
    )
    codeql = _select(
        board.codeql_status,
        ("project_id", "ready", "status", "database_identity", "failure_reason"),
    )
    payload: dict[str, Any] = {
        "project_overview": {"repository": _bounded(repository), "codeql": _bounded(codeql)},
        "evidence_board": {
            "finding_counts": {
                "input": len(board.input_findings),
                "effect": len(board.effect_findings),
                "bridge": len(board.bridge_findings),
            },
            "recent_findings": [
                _bounded(item.to_dict()) for item in board.all_findings()[-12:]
            ],
            "recent_evidence_refs": [_bounded(dict(item)) for item in board.evidence_refs[-16:]],
            "recent_tool_calls": [_compact_tool_call(item) for item in board.tool_calls[-12:]],
            "pending_proposals": [_bounded(dict(item)) for item in board.pending_proposals[-8:]],
            "recent_gate_results": [
                _compact_gate_result(item) for item in board.gate_results[-8:]
            ],
            "active_admissible_proposal_ids": [
                str(item["proposal_id"]) for item in board.active_admissible_proposals
            ],
            "candidate_path_ids": [
                str(item["candidate_path_id"]) for item in board.candidate_paths
            ],
            "unresolved_questions": list(board.unresolved_questions[-10:]),
            "failed_hypotheses": [_bounded(dict(item)) for item in board.failed_hypotheses[-8:]],
            "specialist_state": {
                role.value: state.to_dict() for role, state in board.agent_states.items()
            },
        },
        "budget_state": _bounded(board.budget_state),
        "decision_rules": {
            "one_action_per_round": True,
            "specialist_free_chat": False,
            "gate_may_be_bypassed": False,
            "codeql_unavailable_is_negative": False,
            "candidate_path_is_vulnerability": False,
        },
        # Capability names are an exact machine contract and must never pass
        # through the generic sequence truncation used for evidence context.
        "dispatch_tool_policy": _exact_dispatch_tool_policy(dispatch_tool_policy),
    }
    duplicated = _duplicate_bytes(
        payload,
        previous_observation.payload if previous_observation is not None else None,
    )
    identity = {
        "schema_version": COORDINATOR_OBSERVATION_VERSION,
        "project_id": board.project_id,
        "coordinator_round": coordinator_round,
        "payload": payload,
    }
    observation_id = stable_digest("m8coordobs", identity)
    size = 0
    estimate = 0
    for _ in range(8):
        observation = CoordinatorObservation(
            observation_id=observation_id,
            project_id=board.project_id,
            coordinator_round=coordinator_round,
            payload=payload,
            serialized_bytes=size,
            estimated_input_tokens=estimate,
            duplicated_observation_bytes=duplicated,
        )
        new_size = len(canonical_json(observation.to_dict()).encode("utf-8"))
        new_estimate = math.ceil(new_size / 4)
        if (new_size, new_estimate) == (size, estimate):
            break
        size, estimate = new_size, new_estimate
    observation = CoordinatorObservation(
        observation_id=observation_id,
        project_id=board.project_id,
        coordinator_round=coordinator_round,
        payload=payload,
        serialized_bytes=size,
        estimated_input_tokens=estimate,
        duplicated_observation_bytes=duplicated,
    )
    if observation.serialized_bytes > MAX_COORDINATOR_OBSERVATION_BYTES:
        raise ValueError("coordinator observation exceeds the frozen byte ceiling")
    return observation
