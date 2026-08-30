from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from java_vuln_research.work1_agent.proposal.model import SecurityProposal, canonical_json, stable_digest


ACTION_SCHEMA_VERSION = 1


class ActionType(str, Enum):
    SEARCH_CODE = "SEARCH_CODE"
    SEARCH_SYMBOLS = "SEARCH_SYMBOLS"
    INSPECT_METHOD = "INSPECT_METHOD"
    INSPECT_TYPE = "INSPECT_TYPE"
    READ_FILE_RANGE = "READ_FILE_RANGE"
    GET_CALLERS = "GET_CALLERS"
    GET_CALLEES = "GET_CALLEES"
    GET_IMPLEMENTATIONS = "GET_IMPLEMENTATIONS"
    GET_OVERRIDES = "GET_OVERRIDES"
    GET_FIELDS = "GET_FIELDS"
    GET_ANNOTATIONS = "GET_ANNOTATIONS"
    CODEQL_ENTITY_FACTS = "CODEQL_ENTITY_FACTS"
    CODEQL_CALLERS = "CODEQL_CALLERS"
    CODEQL_CALLEES = "CODEQL_CALLEES"
    CODEQL_LOCAL_FLOW = "CODEQL_LOCAL_FLOW"
    CODEQL_DATAFLOW_NEIGHBORS = "CODEQL_DATAFLOW_NEIGHBORS"
    CODEQL_CFG_NEIGHBORS = "CODEQL_CFG_NEIGHBORS"
    PROPOSE = "PROPOSE"
    STOP = "STOP"


REPOSITORY_ACTIONS = frozenset(
    {
        ActionType.SEARCH_CODE,
        ActionType.SEARCH_SYMBOLS,
        ActionType.INSPECT_METHOD,
        ActionType.INSPECT_TYPE,
        ActionType.READ_FILE_RANGE,
        ActionType.GET_CALLERS,
        ActionType.GET_CALLEES,
        ActionType.GET_IMPLEMENTATIONS,
        ActionType.GET_OVERRIDES,
        ActionType.GET_FIELDS,
        ActionType.GET_ANNOTATIONS,
    }
)
CODEQL_ACTIONS = frozenset(
    {
        ActionType.CODEQL_ENTITY_FACTS,
        ActionType.CODEQL_CALLERS,
        ActionType.CODEQL_CALLEES,
        ActionType.CODEQL_LOCAL_FLOW,
        ActionType.CODEQL_DATAFLOW_NEIGHBORS,
        ActionType.CODEQL_CFG_NEIGHBORS,
    }
)
TOOL_ACTIONS = REPOSITORY_ACTIONS | CODEQL_ACTIONS


class StopReason(str, Enum):
    PATH_FORMED = "PATH_FORMED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    NO_FURTHER_ACTION = "NO_FURTHER_ACTION"
    TOOL_UNAVAILABLE = "TOOL_UNAVAILABLE"
    OTHER = "OTHER"


@dataclass(frozen=True, slots=True)
class AgentAction:
    action_id: str
    project_id: str
    round: int
    action_type: ActionType
    arguments: Mapping[str, Any]
    reason: str
    provenance: Mapping[str, Any]
    proposal: Mapping[str, Any] | None = None
    stop_reason: StopReason | None = None
    schema_version: int = ACTION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ACTION_SCHEMA_VERSION:
            raise ValueError("unsupported action schema version")
        if not self.project_id or self.round < 1:
            raise ValueError("action requires project_id and positive round")
        if not self.reason.strip() or not self.provenance:
            raise ValueError("action requires reason and provenance")
        if self.action_type in TOOL_ACTIONS:
            if self.proposal is not None or self.stop_reason is not None:
                raise ValueError("tool action cannot contain proposal or stop_reason")
        elif self.action_type == ActionType.PROPOSE:
            if self.proposal is None or self.arguments or self.stop_reason is not None:
                raise ValueError("PROPOSE requires only a compatible M4 proposal payload")
            SecurityProposal.from_dict(self.proposal)
        elif self.action_type == ActionType.STOP:
            if self.stop_reason is None or self.arguments or self.proposal is not None:
                raise ValueError("STOP requires only stop_reason")
        expected = self.compute_id(
            project_id=self.project_id,
            round=self.round,
            action_type=self.action_type,
            arguments=self.arguments,
            proposal=self.proposal,
            stop_reason=self.stop_reason,
        )
        if self.action_id != expected:
            raise ValueError(f"action_id is not canonical; expected {expected}")

    @staticmethod
    def compute_id(
        *,
        project_id: str,
        round: int,
        action_type: ActionType | str,
        arguments: Mapping[str, Any] | None = None,
        proposal: Mapping[str, Any] | None = None,
        stop_reason: StopReason | str | None = None,
    ) -> str:
        return stable_digest(
            "action",
            {
                "schema_version": ACTION_SCHEMA_VERSION,
                "project_id": project_id,
                "round": int(round),
                "action_type": ActionType(action_type).value,
                "arguments": dict(arguments or {}),
                "proposal": dict(proposal) if proposal is not None else None,
                "stop_reason": StopReason(stop_reason).value if stop_reason is not None else None,
            },
        )

    @classmethod
    def create(
        cls,
        *,
        project_id: str,
        round: int,
        action_type: ActionType | str,
        reason: str,
        provenance: Mapping[str, Any],
        arguments: Mapping[str, Any] | None = None,
        proposal: SecurityProposal | Mapping[str, Any] | None = None,
        stop_reason: StopReason | str | None = None,
    ) -> "AgentAction":
        resolved_type = ActionType(action_type)
        proposal_dict = proposal.to_dict() if isinstance(proposal, SecurityProposal) else (dict(proposal) if proposal is not None else None)
        resolved_stop = StopReason(stop_reason) if stop_reason is not None else None
        resolved_arguments = dict(arguments or {})
        return cls(
            action_id=cls.compute_id(
                project_id=project_id,
                round=round,
                action_type=resolved_type,
                arguments=resolved_arguments,
                proposal=proposal_dict,
                stop_reason=resolved_stop,
            ),
            project_id=project_id,
            round=int(round),
            action_type=resolved_type,
            arguments=resolved_arguments,
            proposal=proposal_dict,
            stop_reason=resolved_stop,
            reason=reason,
            provenance=dict(provenance),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AgentAction":
        return cls(
            action_id=str(value["action_id"]),
            project_id=str(value["project_id"]),
            round=int(value["round"]),
            action_type=ActionType(value["action_type"]),
            arguments=dict(value.get("arguments") or {}),
            proposal=dict(value["proposal"]) if value.get("proposal") is not None else None,
            stop_reason=StopReason(value["stop_reason"]) if value.get("stop_reason") is not None else None,
            reason=str(value["reason"]),
            provenance=dict(value["provenance"]),
            schema_version=int(value.get("schema_version", ACTION_SCHEMA_VERSION)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "action_id": self.action_id,
            "project_id": self.project_id,
            "round": self.round,
            "action_type": self.action_type.value,
            "arguments": dict(self.arguments),
            "proposal": dict(self.proposal) if self.proposal is not None else None,
            "stop_reason": self.stop_reason.value if self.stop_reason is not None else None,
            "reason": self.reason,
            "provenance": dict(self.provenance),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())
