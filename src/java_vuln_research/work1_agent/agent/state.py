from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from java_vuln_research.work1_agent.proposal.model import canonical_json

from .actions import StopReason
from .budget import AgentBudgetLimits, BudgetTracker


STATE_SCHEMA_VERSION = 1


@dataclass(slots=True)
class AgentState:
    project_id: str
    repository_identity: str
    budget: BudgetTracker
    provenance: dict[str, Any]
    inspected_entity_ids: set[str] = field(default_factory=set)
    executed_tool_call_ids: list[str] = field(default_factory=list)
    evidence_refs: set[str] = field(default_factory=set)
    proposal_ids: list[str] = field(default_factory=list)
    gate_statuses: dict[str, str] = field(default_factory=dict)
    active_candidate_path_ids: set[str] = field(default_factory=set)
    failed_hypotheses: list[dict[str, Any]] = field(default_factory=list)
    unresolved_questions: list[str] = field(default_factory=list)
    current_exploration_focus: str | None = None
    stop_reason: StopReason | None = None
    schema_version: int = STATE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != STATE_SCHEMA_VERSION:
            raise ValueError("unsupported state schema version")
        if not self.project_id or not self.repository_identity or not self.provenance:
            raise ValueError("state requires project, repository identity, and provenance")

    @classmethod
    def create(
        cls,
        *,
        project_id: str,
        repository_identity: str,
        provenance: Mapping[str, Any],
        limits: AgentBudgetLimits | None = None,
    ) -> "AgentState":
        return cls(
            project_id=project_id,
            repository_identity=repository_identity,
            budget=BudgetTracker(limits or AgentBudgetLimits()),
            provenance=dict(provenance),
        )

    @property
    def current_round(self) -> int:
        return self.budget.current_round

    @property
    def stopped(self) -> bool:
        return self.stop_reason is not None

    def require_project(self, project_id: str) -> None:
        if project_id != self.project_id:
            raise ValueError("M7 state is project-local; cross-project data rejected")

    def record_tool_call(self, tool_call_id: str, *, project_id: str, entity_ids: tuple[str, ...] = ()) -> None:
        self.require_project(project_id)
        if not tool_call_id or tool_call_id in self.executed_tool_call_ids:
            raise ValueError("tool_call_id must be new and non-empty")
        self.executed_tool_call_ids.append(tool_call_id)
        self.inspected_entity_ids.update(entity_ids)

    def record_evidence(self, evidence_id: str, *, project_id: str) -> None:
        self.require_project(project_id)
        if not evidence_id:
            raise ValueError("evidence_id is required")
        self.evidence_refs.add(evidence_id)

    def record_proposal(self, proposal_id: str, *, project_id: str, gate_status: str | None = None) -> None:
        self.require_project(project_id)
        if proposal_id not in self.proposal_ids:
            self.proposal_ids.append(proposal_id)
        if gate_status is not None:
            self.gate_statuses[proposal_id] = gate_status

    def stop(self, reason: StopReason | str) -> None:
        self.stop_reason = StopReason(reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "project_id": self.project_id,
            "repository_identity": self.repository_identity,
            "current_round": self.current_round,
            "budget": self.budget.to_dict(),
            "inspected_entity_ids": sorted(self.inspected_entity_ids),
            "executed_tool_call_ids": list(self.executed_tool_call_ids),
            "evidence_refs": sorted(self.evidence_refs),
            "proposal_ids": list(self.proposal_ids),
            "gate_statuses": dict(sorted(self.gate_statuses.items())),
            "active_candidate_path_ids": sorted(self.active_candidate_path_ids),
            "failed_hypotheses": [dict(item) for item in self.failed_hypotheses],
            "unresolved_questions": list(self.unresolved_questions),
            "current_exploration_focus": self.current_exploration_focus,
            "stop_reason": self.stop_reason.value if self.stop_reason is not None else None,
            "provenance": dict(self.provenance),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AgentState":
        state = cls(
            project_id=str(value["project_id"]),
            repository_identity=str(value["repository_identity"]),
            budget=BudgetTracker.from_dict(value["budget"]),
            provenance=dict(value["provenance"]),
            inspected_entity_ids=set(str(item) for item in value.get("inspected_entity_ids", ())),
            executed_tool_call_ids=[str(item) for item in value.get("executed_tool_call_ids", ())],
            evidence_refs=set(str(item) for item in value.get("evidence_refs", ())),
            proposal_ids=[str(item) for item in value.get("proposal_ids", ())],
            gate_statuses={str(key): str(raw) for key, raw in dict(value.get("gate_statuses") or {}).items()},
            active_candidate_path_ids=set(str(item) for item in value.get("active_candidate_path_ids", ())),
            failed_hypotheses=[dict(item) for item in value.get("failed_hypotheses", ())],
            unresolved_questions=[str(item) for item in value.get("unresolved_questions", ())],
            current_exploration_focus=str(value["current_exploration_focus"]) if value.get("current_exploration_focus") is not None else None,
            stop_reason=StopReason(value["stop_reason"]) if value.get("stop_reason") is not None else None,
            schema_version=int(value.get("schema_version", STATE_SCHEMA_VERSION)),
        )
        if int(value.get("current_round", state.current_round)) != state.current_round:
            raise ValueError("state current_round does not match budget usage")
        return state
