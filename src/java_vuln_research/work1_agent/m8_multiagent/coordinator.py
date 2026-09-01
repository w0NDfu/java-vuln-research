"""Bounded M8 Coordinator runtime over specialists, M4 Gate, and M5 paths."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.agent.actions import (
    CODEQL_ACTIONS,
    ActionType,
    AgentAction,
    StopReason,
)
from java_vuln_research.work1_agent.agent.feedback import evidence_from_tool_result
from java_vuln_research.work1_agent.agent.graph_adapter import (
    AgentGraphPathAdapter,
    AgentGraphPathResult,
)
from java_vuln_research.work1_agent.agent.llm_client import (
    LLMClient,
    LLMRequest,
    LLMResponse,
    MockLLMClient,
    ModelCallError,
)
from java_vuln_research.work1_agent.agent.parser import validate_tool_arguments
from java_vuln_research.work1_agent.agent.structured_output import StructuredOutputNormalizer
from java_vuln_research.work1_agent.agent.tool_adapter import (
    AgentToolResult,
    RepositoryCodeQLToolAdapter,
)
from java_vuln_research.work1_agent.proposal import (
    EntityRoleRef,
    EvidenceGate,
    EvidenceGateResult,
    EvidenceRef,
    GateStatus,
    ProposalScope,
    ProposalType,
    SecurityProposal,
)
from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex

from .agent_registry import COORDINATOR_AGENT
from .board import SharedEvidenceBoard
from .contracts import FindingType, SpecialistFinding, SpecialistRole, SpecialistTaskSpec
from .coordinator_observation import CoordinatorObservation, build_coordinator_observation
from .prompts.coordinator import SYSTEM_PROMPT as COORDINATOR_SYSTEM_PROMPT
from .prompts.common import prompt_sha256
from .role_helper import ProposalAnchor, RoleOption, build_role_guidance
from .scope_helper import build_valid_scope
from .specialists import SpecialistAgentRuntime, SpecialistRuntimeRun


COORDINATOR_RUNTIME_VERSION = "M8_COORDINATOR_RUNTIME_V2"
_MIDDLE_PROPOSALS = frozenset(
    {
        ProposalType.WRAPPER_FLOW,
        ProposalType.LIBRARY_FLOW,
        ProposalType.FIELD_STATE,
        ProposalType.FRAMEWORK_RELATION,
        ProposalType.CALLBACK_RELATION,
    }
)
_DECISION_KEYS = {
    "action_type",
    "arguments",
    "proposal",
    "supporting_finding_ids",
    "stop_reason",
    "reason",
}


class CoordinatorActionType(str, Enum):
    DISPATCH_INPUT_AGENT = "DISPATCH_INPUT_AGENT"
    DISPATCH_EFFECT_AGENT = "DISPATCH_EFFECT_AGENT"
    DISPATCH_BRIDGE_AGENT = "DISPATCH_BRIDGE_AGENT"
    REQUEST_CODEQL_CORROBORATION = "REQUEST_CODEQL_CORROBORATION"
    SUBMIT_PROPOSAL = "SUBMIT_PROPOSAL"
    REQUEST_SCOPE_REPAIR = "REQUEST_SCOPE_REPAIR"
    REQUEST_ROLE_REPAIR = "REQUEST_ROLE_REPAIR"
    REBUILD_PATH = "REBUILD_PATH"
    STOP = "STOP"


_DISPATCH_ROLES = {
    CoordinatorActionType.DISPATCH_INPUT_AGENT: SpecialistRole.INPUT,
    CoordinatorActionType.DISPATCH_EFFECT_AGENT: SpecialistRole.EFFECT,
    CoordinatorActionType.DISPATCH_BRIDGE_AGENT: SpecialistRole.BRIDGE,
}


class CoordinatorConstraint(RuntimeError):
    def __init__(
        self,
        failure_class: str,
        message: str,
        next_required_action: str,
        *,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.failure_class = failure_class
        self.next_required_action = next_required_action
        self.details = dict(details or {})
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class CoordinatorBudgetLimits:
    max_coordinator_rounds: int = 12
    max_input_dispatches: int = 4
    max_effect_dispatches: int = 4
    max_bridge_dispatches: int = 5
    max_proposals: int = 10
    max_admissible_proposals: int = 8
    max_codeql_calls: int = 12

    def __post_init__(self) -> None:
        values = self.to_dict()
        if any(value < 1 for value in values.values()):
            raise ValueError("Coordinator budget limits must be positive")
        if self.max_coordinator_rounds > 100 or self.max_codeql_calls > 100:
            raise ValueError("Coordinator budget exceeds the M8 hard ceiling")
        if self.max_admissible_proposals > self.max_proposals:
            raise ValueError("admissible proposal budget exceeds proposal budget")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_coordinator_rounds": self.max_coordinator_rounds,
            "max_input_dispatches": self.max_input_dispatches,
            "max_effect_dispatches": self.max_effect_dispatches,
            "max_bridge_dispatches": self.max_bridge_dispatches,
            "max_proposals": self.max_proposals,
            "max_admissible_proposals": self.max_admissible_proposals,
            "max_codeql_calls": self.max_codeql_calls,
        }


@dataclass(slots=True)
class CoordinatorBudgetState:
    limits: CoordinatorBudgetLimits
    coordinator_rounds: int = 0
    model_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    dispatches: dict[SpecialistRole, int] = field(
        default_factory=lambda: {role: 0 for role in SpecialistRole}
    )
    proposals: int = 0
    admissible_proposals: int = 0
    codeql_calls: int = 0

    def begin_round(self) -> int:
        if self.coordinator_rounds >= self.limits.max_coordinator_rounds:
            raise CoordinatorConstraint(
                "BUDGET_EXHAUSTED",
                "Coordinator round budget exhausted",
                CoordinatorActionType.STOP.value,
            )
        self.coordinator_rounds += 1
        return self.coordinator_rounds

    def record_model_call(self, response: LLMResponse) -> None:
        self.model_calls += 1
        self.input_tokens += response.input_tokens
        self.output_tokens += response.output_tokens

    def record_dispatch(self, role: SpecialistRole) -> None:
        limit = {
            SpecialistRole.INPUT: self.limits.max_input_dispatches,
            SpecialistRole.EFFECT: self.limits.max_effect_dispatches,
            SpecialistRole.BRIDGE: self.limits.max_bridge_dispatches,
        }[role]
        if self.dispatches[role] >= limit:
            raise CoordinatorConstraint(
                "BUDGET_EXHAUSTED",
                f"{role.value} dispatch budget exhausted",
                CoordinatorActionType.STOP.value,
            )
        self.dispatches[role] += 1

    def record_proposal(self) -> None:
        if self.proposals >= self.limits.max_proposals:
            raise CoordinatorConstraint(
                "BUDGET_EXHAUSTED",
                "proposal budget exhausted",
                CoordinatorActionType.STOP.value,
            )
        self.proposals += 1

    def record_admissible(self) -> None:
        if self.admissible_proposals >= self.limits.max_admissible_proposals:
            raise CoordinatorConstraint(
                "BUDGET_EXHAUSTED",
                "admissible proposal budget exhausted",
                CoordinatorActionType.STOP.value,
            )
        self.admissible_proposals += 1

    def record_codeql(self) -> None:
        if self.codeql_calls >= self.limits.max_codeql_calls:
            raise CoordinatorConstraint(
                "BUDGET_EXHAUSTED",
                "CodeQL call budget exhausted",
                CoordinatorActionType.STOP.value,
            )
        self.codeql_calls += 1

    def to_dict(self) -> dict[str, Any]:
        dispatch_limits = {
            SpecialistRole.INPUT: self.limits.max_input_dispatches,
            SpecialistRole.EFFECT: self.limits.max_effect_dispatches,
            SpecialistRole.BRIDGE: self.limits.max_bridge_dispatches,
        }
        return {
            "limits": self.limits.to_dict(),
            "usage": {
                "coordinator_rounds": self.coordinator_rounds,
                "model_calls": self.model_calls,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "dispatches": {role.value: self.dispatches[role] for role in SpecialistRole},
                "proposals": self.proposals,
                "admissible_proposals": self.admissible_proposals,
                "codeql_calls": self.codeql_calls,
            },
            "remaining": {
                "coordinator_rounds": max(
                    0, self.limits.max_coordinator_rounds - self.coordinator_rounds
                ),
                "dispatches": {
                    role.value: max(0, dispatch_limits[role] - self.dispatches[role])
                    for role in SpecialistRole
                },
                "proposals": max(0, self.limits.max_proposals - self.proposals),
                "admissible_proposals": max(
                    0, self.limits.max_admissible_proposals - self.admissible_proposals
                ),
                "codeql_calls": max(0, self.limits.max_codeql_calls - self.codeql_calls),
            },
        }


@dataclass(frozen=True, slots=True)
class CoordinatorAction:
    action_id: str
    project_id: str
    coordinator_round: int
    action_type: CoordinatorActionType
    arguments: Mapping[str, Any]
    proposal: Mapping[str, Any] | None
    supporting_finding_ids: tuple[str, ...]
    stop_reason: StopReason | None
    reason: str
    provenance: Mapping[str, Any]

    @classmethod
    def create(
        cls,
        *,
        project_id: str,
        coordinator_round: int,
        action_type: CoordinatorActionType,
        arguments: Mapping[str, Any],
        proposal: Mapping[str, Any] | None,
        supporting_finding_ids: Sequence[str],
        stop_reason: StopReason | None,
        reason: str,
        provenance: Mapping[str, Any],
    ) -> "CoordinatorAction":
        material = {
            "project_id": project_id,
            "coordinator_round": coordinator_round,
            "action_type": action_type.value,
            "arguments": dict(arguments),
            "proposal": dict(proposal) if proposal is not None else None,
            "supporting_finding_ids": list(supporting_finding_ids),
            "stop_reason": stop_reason.value if stop_reason else None,
        }
        return cls(
            action_id=stable_digest("m8coordaction", material),
            project_id=project_id,
            coordinator_round=coordinator_round,
            action_type=action_type,
            arguments=dict(arguments),
            proposal=dict(proposal) if proposal is not None else None,
            supporting_finding_ids=tuple(supporting_finding_ids),
            stop_reason=stop_reason,
            reason=reason,
            provenance=dict(provenance),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_id": self.action_id,
            "project_id": self.project_id,
            "coordinator_round": self.coordinator_round,
            "action_type": self.action_type.value,
            "arguments": dict(self.arguments),
            "proposal": dict(self.proposal) if self.proposal is not None else None,
            "supporting_finding_ids": list(self.supporting_finding_ids),
            "stop_reason": self.stop_reason.value if self.stop_reason else None,
            "reason": self.reason,
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True, slots=True)
class CoordinatorFailure:
    failure_class: str
    message: str
    coordinator_round: int
    action_id: str | None = None
    retryable: bool = False
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "failure_class": self.failure_class,
            "message": self.message,
            "coordinator_round": self.coordinator_round,
            "action_id": self.action_id,
            "retryable": self.retryable,
            "details": dict(self.details),
        }


@dataclass(frozen=True, slots=True)
class CoordinatorRunResult:
    board: SharedEvidenceBoard
    actions: tuple[CoordinatorAction, ...]
    observations: tuple[CoordinatorObservation, ...]
    model_responses: tuple[Mapping[str, Any], ...]
    specialist_runs: tuple[SpecialistRuntimeRun, ...]
    proposals: tuple[SecurityProposal, ...]
    gate_results: tuple[EvidenceGateResult, ...]
    graph_results: tuple[AgentGraphPathResult, ...]
    codeql_results: tuple[AgentToolResult, ...]
    failures: tuple[CoordinatorFailure, ...]
    stop_reason: StopReason
    budget_state: Mapping[str, Any]
    scope_repairs_prepared: int
    scope_repairs_admitted: int
    role_repairs_prepared: int
    role_repairs_admitted: int

    def summary(self) -> dict[str, Any]:
        return {
            "coordinator_runtime_version": COORDINATOR_RUNTIME_VERSION,
            "project_id": self.board.project_id,
            "rounds": len(self.actions),
            "specialist_dispatches": len(self.specialist_runs),
            "proposals": len(self.proposals),
            "admissible_proposals": sum(
                item.status is GateStatus.ADMISSIBLE for item in self.gate_results
            ),
            "candidate_paths": len(self.board.candidate_paths),
            "codeql_calls": len(self.codeql_results),
            "codeql_tools": sorted({item.tool_name for item in self.codeql_results}),
            "scope_repairs_prepared": self.scope_repairs_prepared,
            "scope_repairs_admitted": self.scope_repairs_admitted,
            "role_repairs_prepared": self.role_repairs_prepared,
            "role_repairs_admitted": self.role_repairs_admitted,
            "stop_reason": self.stop_reason.value,
            "failures": [item.to_dict() for item in self.failures],
            "budget": dict(self.budget_state),
        }


def _strings(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be an array of strings")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"{name} must be an array of strings")
    result = tuple(item.strip() for item in value)
    if any(not item for item in result) or len(result) != len(set(result)):
        raise ValueError(f"{name} must contain unique non-empty strings")
    return result


def _parse_action(
    *,
    response: LLMResponse,
    project_id: str,
    coordinator_round: int,
    normalizer: StructuredOutputNormalizer,
) -> CoordinatorAction:
    raw = dict(normalizer.normalize(response).normalized_object)
    if set(raw) != _DECISION_KEYS:
        raise ValueError("Coordinator decision has an invalid key set")
    action_type = CoordinatorActionType(raw["action_type"])
    if not isinstance(raw["arguments"], Mapping):
        raise ValueError("Coordinator arguments must be an object")
    arguments = dict(raw["arguments"])
    proposal = dict(raw["proposal"]) if isinstance(raw["proposal"], Mapping) else None
    if raw["proposal"] is not None and proposal is None:
        raise ValueError("Coordinator proposal must be an object or null")
    findings = _strings(raw["supporting_finding_ids"], "supporting_finding_ids")
    if not isinstance(raw["reason"], str) or not raw["reason"].strip():
        raise ValueError("Coordinator reason is required")
    stop_reason = StopReason(raw["stop_reason"]) if raw["stop_reason"] is not None else None

    if action_type in _DISPATCH_ROLES:
        if set(arguments) != {
            "objective",
            "seed_entity_ids",
            "unresolved_question",
            "allowed_tools",
        }:
            raise ValueError("dispatch arguments have an invalid key set")
        _strings(arguments["seed_entity_ids"], "seed_entity_ids")
        _strings(arguments["allowed_tools"], "allowed_tools")
        if not str(arguments["objective"]).strip() or not str(arguments["unresolved_question"]).strip():
            raise ValueError("dispatch objective and unresolved_question are required")
        if proposal is not None or findings or stop_reason is not None:
            raise ValueError("dispatch cannot carry proposal, findings, or stop_reason")
    elif action_type is CoordinatorActionType.REQUEST_CODEQL_CORROBORATION:
        if not arguments.get("tool_name") or proposal is not None or findings or stop_reason is not None:
            raise ValueError("CodeQL request requires only fixed tool arguments")
    elif action_type is CoordinatorActionType.SUBMIT_PROPOSAL:
        inline = proposal is not None and not arguments and bool(findings)
        pending = proposal is None and set(arguments) == {"proposal_id"} and not findings
        if not (inline or pending) or stop_reason is not None:
            raise ValueError("SUBMIT_PROPOSAL must be inline or reference one pending proposal")
    elif action_type in {
        CoordinatorActionType.REQUEST_SCOPE_REPAIR,
        CoordinatorActionType.REQUEST_ROLE_REPAIR,
    }:
        if set(arguments) != {"proposal_id"} or proposal is not None or findings or stop_reason is not None:
            raise ValueError("repair action requires only proposal_id")
    elif action_type is CoordinatorActionType.REBUILD_PATH:
        if arguments or proposal is not None or findings or stop_reason is not None:
            raise ValueError("REBUILD_PATH must not carry extra fields")
    else:
        if arguments or proposal is not None or findings or stop_reason is None:
            raise ValueError("STOP requires only stop_reason")
    return CoordinatorAction.create(
        project_id=project_id,
        coordinator_round=coordinator_round,
        action_type=action_type,
        arguments=arguments,
        proposal=proposal,
        supporting_finding_ids=findings,
        stop_reason=stop_reason,
        reason=raw["reason"].strip(),
        provenance={
            "producer": COORDINATOR_RUNTIME_VERSION,
            "coordinator_agent": COORDINATOR_AGENT.id,
            "exact_model_id": COORDINATOR_AGENT.model_id,
            "model_call_id": response.model_call_id,
            "response_provider": response.provider,
            "response_model_id": response.model_id,
            "benchmark_informed": False,
        },
    )


_PROPOSAL_DRAFT_KEYS = {
    "proposal_type",
    "subject",
    "source",
    "target",
    "scope",
    "semantic_category",
    "evidence_refs",
    "reason",
    "model_confidence",
    "provenance",
}


def _proposal_from_model_draft(
    value: Mapping[str, Any],
    *,
    project_id: str,
) -> SecurityProposal:
    raw = dict(value)
    if "proposal_id" in raw:
        if set(raw) != _PROPOSAL_DRAFT_KEYS | {"proposal_id"}:
            raise ValueError("Coordinator proposal has an invalid key set")
        return SecurityProposal.from_dict(raw)
    if set(raw) != _PROPOSAL_DRAFT_KEYS:
        raise ValueError("Coordinator proposal draft has an invalid key set")
    scope = dict(raw["scope"])
    if scope.get("project_id") not in {None, project_id}:
        raise ValueError("Coordinator proposal draft is cross-project")
    scope["project_id"] = project_id
    provenance = dict(raw["provenance"])
    if provenance.get("benchmark_informed") not in {None, False}:
        raise ValueError("Coordinator proposal draft claims benchmark-informed provenance")
    return SecurityProposal.create(
        proposal_type=raw["proposal_type"],
        subject=EntityRoleRef.from_dict(raw["subject"]),
        source=EntityRoleRef.from_dict(raw["source"]) if raw["source"] else None,
        target=EntityRoleRef.from_dict(raw["target"]) if raw["target"] else None,
        scope=ProposalScope.from_dict(scope),
        semantic_category=raw["semantic_category"],
        evidence_refs=raw["evidence_refs"],
        reason=str(raw["reason"]),
        model_confidence=raw["model_confidence"],
        provenance=provenance or {"benchmark_informed": False},
    )


class CoordinatorRuntime:
    """Execute one bounded Coordinator action per round without free agent chat."""

    def __init__(
        self,
        *,
        project_id: str,
        repository_index: RepositoryIndex,
        board: SharedEvidenceBoard,
        llm_client: LLMClient,
        specialist_runtimes: Mapping[SpecialistRole, SpecialistAgentRuntime],
        tool_adapter: RepositoryCodeQLToolAdapter,
        evidence_gate: EvidenceGate,
        graph_path_adapter: AgentGraphPathAdapter,
        budget_limits: CoordinatorBudgetLimits | None = None,
        normalizer: StructuredOutputNormalizer | None = None,
    ) -> None:
        if not project_id:
            raise ValueError("Coordinator project_id is required")
        board.require_project(project_id)
        if tool_adapter.project_id != project_id or tool_adapter.index is not repository_index:
            raise ValueError("Coordinator tool components are cross-project")
        if evidence_gate.repository_root != repository_index.repository_root.resolve():
            raise ValueError("Coordinator and Evidence Gate repository roots differ")
        if graph_path_adapter.project_id != project_id or graph_path_adapter.evidence_gate is not evidence_gate:
            raise ValueError("Coordinator graph adapter is cross-project or uses another Gate")
        if set(specialist_runtimes) != set(SpecialistRole):
            raise ValueError("Coordinator requires exactly three specialist runtimes")
        for role, runtime in specialist_runtimes.items():
            if runtime.role is not role or runtime.project_id != project_id:
                raise ValueError("Coordinator specialist runtime is cross-role or cross-project")
            if runtime.repository_index is not repository_index or runtime.tool_adapter is not tool_adapter:
                raise ValueError("Coordinator and specialists must share repository/tool components")
        config = getattr(llm_client, "config", None)
        configured_model = getattr(config, "model_id", None)
        if configured_model is None and not isinstance(llm_client, MockLLMClient):
            raise ValueError("non-Mock Coordinator client must expose exact model configuration")
        if configured_model is not None and configured_model != COORDINATOR_AGENT.model_id:
            raise ValueError("Coordinator client model does not match the frozen role assignment")

        self.project_id = project_id
        self.repository_index = repository_index
        self.board = board
        self.llm_client = llm_client
        self.specialist_runtimes = dict(specialist_runtimes)
        self.tool_adapter = tool_adapter
        self.evidence_gate = evidence_gate
        self.graph_path_adapter = graph_path_adapter
        self.budget = CoordinatorBudgetState(budget_limits or CoordinatorBudgetLimits())
        self.normalizer = normalizer or StructuredOutputNormalizer()
        self.actions: list[CoordinatorAction] = []
        self.observations: list[CoordinatorObservation] = []
        self.model_responses: list[Mapping[str, Any]] = []
        self.specialist_runs: list[SpecialistRuntimeRun] = []
        self.proposals: list[SecurityProposal] = []
        self.proposal_attempts: dict[str, SecurityProposal] = {}
        self.proposal_support: dict[str, tuple[str, ...]] = {}
        self.pending: dict[str, Mapping[str, Any]] = {}
        self.gate_results: list[EvidenceGateResult] = []
        self.active_proposals: dict[str, SecurityProposal] = {}
        self.graph_results: list[AgentGraphPathResult] = []
        self.codeql_results: list[AgentToolResult] = []
        self.failures: list[CoordinatorFailure] = []
        self.stop_reason: StopReason | None = None
        self.scope_repairs_prepared = 0
        self.scope_repairs_admitted = 0
        self.role_repairs_prepared = 0
        self.role_repairs_admitted = 0
        self._sync_board_evidence()

    def _sync_board_evidence(self) -> None:
        tools = {str(item["tool_call_id"]): dict(item) for item in self.board.tool_calls}
        for raw in self.board.evidence_refs:
            evidence = EvidenceRef.from_dict(raw)
            artifact = tools.get(evidence.tool_call_id or "") if evidence.tool_call_id else None
            self.evidence_gate.register_evidence(evidence, tool_artifact=artifact)

    def _budget_event(self, coordinator_round: int) -> None:
        self.board.record_coordinator_event(
            event_type="BUDGET_UPDATED",
            coordinator_round=coordinator_round,
            payload={"budget_state": self.budget.to_dict()},
        )

    def _feedback(
        self,
        *,
        coordinator_round: int,
        failure_class: str,
        message: str,
        next_required_action: str,
        action_id: str | None,
        retryable: bool = True,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        failure = CoordinatorFailure(
            failure_class,
            message,
            coordinator_round,
            action_id,
            retryable,
            dict(details or {}),
        )
        self.failures.append(failure)
        self.board.record_coordinator_event(
            event_type="COORDINATOR_FEEDBACK_RECORDED",
            coordinator_round=coordinator_round,
            payload={
                "feedback": {
                    **failure.to_dict(),
                    "next_required_action": next_required_action,
                }
            },
        )

    def _stop(self, coordinator_round: int, reason: StopReason) -> None:
        self.stop_reason = reason
        self.board.record_coordinator_event(
            event_type="COORDINATOR_STOPPED",
            coordinator_round=coordinator_round,
            payload={"stop_reason": reason.value},
        )

    def _dispatch(self, action: CoordinatorAction) -> None:
        role = _DISPATCH_ROLES[action.action_type]
        runtime = self.specialist_runtimes[role]
        allowed = _strings(action.arguments["allowed_tools"], "allowed_tools")
        canonical_allowed = tuple(sorted(runtime.allowed_tools))
        invalid = tuple(sorted(set(allowed) - runtime.allowed_tools))
        if not allowed or invalid:
            details = {
                "specialist_agent": role.value,
                "requested_tools": list(allowed),
                "invalid_tools": list(invalid),
                "allowed_tools": list(canonical_allowed),
                "non_empty_required": True,
                "canonical_names_case_sensitive": True,
            }
            raise CoordinatorConstraint(
                "SPECIALIST_TOOL_RESTRICTION",
                f"{role.value} dispatch allowed_tools violate the role policy; "
                f"requested={canonical_json(list(allowed))}; "
                f"invalid={canonical_json(list(invalid))}; "
                f"allowed={canonical_json(list(canonical_allowed))}; "
                "non_empty_required=true; canonical_names_case_sensitive=true",
                action.action_type.value,
                details=details,
            )
        self.budget.record_dispatch(role)
        seeds = _strings(action.arguments["seed_entity_ids"], "seed_entity_ids")
        known = {
            SpecialistRole.INPUT: self.board.input_findings,
            SpecialistRole.EFFECT: self.board.effect_findings,
            SpecialistRole.BRIDGE: [*self.board.input_findings, *self.board.effect_findings],
        }[role]
        task = SpecialistTaskSpec.create(
            project_id=self.project_id,
            specialist_agent=role,
            coordinator_round=action.coordinator_round,
            dispatch_index=self.board.agent_states[role].dispatches + 1,
            objective=str(action.arguments["objective"]),
            seed_entity_ids=seeds,
            known_findings=[item.to_dict() for item in known],
            unresolved_question=str(action.arguments["unresolved_question"]),
            allowed_tools=allowed,
            remaining_specialist_budget={
                "max_internal_rounds": 4,
                "max_tool_calls": 6,
                "max_finding_batches": 1,
            },
            provenance={
                "producer": COORDINATOR_RUNTIME_VERSION,
                "coordinator_action_id": action.action_id,
                "benchmark_informed": False,
            },
        )
        run = runtime.run(task)
        self.board.merge_specialist_result(task, run.result)
        self.specialist_runs.append(run)
        tools = {str(item["tool_call_id"]): dict(item) for item in run.result.tool_calls}
        for raw in run.result.evidence_refs:
            evidence = EvidenceRef.from_dict(raw)
            artifact = tools.get(evidence.tool_call_id or "") if evidence.tool_call_id else None
            self.evidence_gate.register_evidence(evidence, tool_artifact=artifact)

    def _request_codeql(self, action: CoordinatorAction) -> None:
        self.budget.record_codeql()
        arguments = dict(action.arguments)
        try:
            tool = ActionType(str(arguments.pop("tool_name")))
        except ValueError as exc:
            raise CoordinatorConstraint(
                "CODEQL_TOOL_INVALID",
                "Coordinator requested a non-fixed CodeQL tool",
                CoordinatorActionType.REQUEST_CODEQL_CORROBORATION.value,
            ) from exc
        if tool not in CODEQL_ACTIONS:
            raise CoordinatorConstraint(
                "CODEQL_TOOL_INVALID",
                "Coordinator requested a non-CodeQL tool",
                CoordinatorActionType.REQUEST_CODEQL_CORROBORATION.value,
            )
        validate_tool_arguments(tool, arguments)
        tool_action = AgentAction.create(
            project_id=self.project_id,
            round=action.coordinator_round,
            action_type=tool,
            arguments=arguments,
            reason=action.reason,
            provenance={
                "producer": COORDINATOR_RUNTIME_VERSION,
                "coordinator_action_id": action.action_id,
                "benchmark_informed": False,
            },
        )
        result = self.tool_adapter.execute(tool_action)
        evidence = evidence_from_tool_result(result, self.repository_index)
        for item in evidence:
            self.evidence_gate.register_evidence(item, tool_artifact=result.to_dict())
        self.codeql_results.append(result)
        self.board.record_coordinator_event(
            event_type="CODEQL_CORROBORATION_RECORDED",
            coordinator_round=action.coordinator_round,
            payload={
                "tool_call": result.to_dict(),
                "evidence_refs": [item.to_dict() for item in evidence],
                "non_negative_limitation": result.status.value
                in {"EMPTY", "UNAVAILABLE", "ERROR", "ENTITY_NOT_MAPPED"},
            },
        )

    def _findings(self, finding_ids: Sequence[str]) -> tuple[SpecialistFinding, ...]:
        catalog = {item.finding_id: item for item in self.board.all_findings()}
        missing = sorted(set(finding_ids) - set(catalog))
        if missing:
            raise CoordinatorConstraint(
                "SPECIALIST_FINDING_NOT_FOUND",
                "proposal references unknown specialist findings: " + ",".join(missing),
                CoordinatorActionType.DISPATCH_INPUT_AGENT.value,
            )
        return tuple(catalog[item] for item in finding_ids)

    @staticmethod
    def _required_finding_type(proposal_type: ProposalType) -> FindingType:
        if proposal_type is ProposalType.EXTERNAL_INPUT:
            return FindingType.INPUT
        if proposal_type is ProposalType.SECURITY_EFFECT:
            return FindingType.EFFECT
        return FindingType.BRIDGE

    def _validate_proposal_support(
        self,
        proposal: SecurityProposal,
        finding_ids: Sequence[str],
    ) -> tuple[SpecialistFinding, ...]:
        findings = self._findings(finding_ids)
        required = self._required_finding_type(proposal.proposal_type)
        if not findings or not any(item.finding_type is required for item in findings):
            raise CoordinatorConstraint(
                "SPECIALIST_EVIDENCE_REQUIRED",
                f"{proposal.proposal_type.value} requires a {required.value}",
                {
                    FindingType.INPUT: CoordinatorActionType.DISPATCH_INPUT_AGENT.value,
                    FindingType.EFFECT: CoordinatorActionType.DISPATCH_EFFECT_AGENT.value,
                    FindingType.BRIDGE: CoordinatorActionType.DISPATCH_BRIDGE_AGENT.value,
                }[required],
            )
        support_entities = {entity for item in findings for entity in item.entity_ids}
        anchors = {
            item.entity_id
            for item in (proposal.subject, proposal.source, proposal.target)
            if item is not None
        }
        if not anchors.issubset(support_entities):
            raise CoordinatorConstraint(
                "PROPOSAL_ANCHOR_NOT_SPECIALIST_GROUNDED",
                "proposal anchors must be present in supporting specialist findings",
                {
                    FindingType.INPUT: CoordinatorActionType.DISPATCH_INPUT_AGENT.value,
                    FindingType.EFFECT: CoordinatorActionType.DISPATCH_EFFECT_AGENT.value,
                    FindingType.BRIDGE: CoordinatorActionType.DISPATCH_BRIDGE_AGENT.value,
                }[required],
            )
        support_evidence = {evidence for item in findings for evidence in item.evidence_refs}
        board_evidence = {
            str(item["evidence_id"]): EvidenceRef.from_dict(item)
            for item in self.board.evidence_refs
        }
        codeql_evidence = {
            evidence_id
            for evidence_id, item in board_evidence.items()
            if item.source_kind.value.startswith("CODEQL_")
        }
        if not set(proposal.evidence_refs).issubset(support_evidence | codeql_evidence):
            raise CoordinatorConstraint(
                "PROPOSAL_EVIDENCE_NOT_SPECIALIST_GROUNDED",
                "proposal contains evidence outside specialist findings and Coordinator CodeQL results",
                CoordinatorActionType.DISPATCH_BRIDGE_AGENT.value,
            )
        if not set(proposal.evidence_refs) & support_evidence:
            raise CoordinatorConstraint(
                "SPECIALIST_EVIDENCE_REQUIRED",
                "proposal must preserve at least one supporting specialist EvidenceRef",
                CoordinatorActionType.DISPATCH_BRIDGE_AGENT.value,
            )
        if proposal.proposal_type in _MIDDLE_PROPOSALS and proposal.source and proposal.target:
            input_entities = {entity for item in self.board.input_findings for entity in item.entity_ids}
            effect_entities = {entity for item in self.board.effect_findings for entity in item.entity_ids}
            if (
                proposal.source.entity_id in input_entities
                and proposal.target.entity_id in effect_entities
                and proposal.source.entity_id != proposal.target.entity_id
            ):
                raise CoordinatorConstraint(
                    "DIRECT_INPUT_EFFECT_SHORTCUT",
                    "semantic proposals must describe a minimal local bridge, not jump input to effect",
                    CoordinatorActionType.DISPATCH_BRIDGE_AGENT.value,
                )
        return findings

    def _codeql_attempted(self, entity_ids: set[str]) -> bool:
        for tool in self.board.tool_calls:
            if not str(tool.get("tool_name", "")).startswith("CODEQL_"):
                continue
            arguments = dict(tool.get("provenance", {})).get("arguments", {})
            if isinstance(arguments, Mapping) and entity_ids & {
                str(value)
                for key, value in arguments.items()
                if key.endswith("entity_id") and value
            }:
                return True
        return False

    def _enforce_codeql_policy(self, proposal: SecurityProposal) -> None:
        if not bool(self.board.codeql_status.get("ready")):
            return
        entities = {item.entity_id: item for item in self.repository_index.entities}
        refs = (
            (proposal.subject,)
            if proposal.proposal_type in {ProposalType.EXTERNAL_INPUT, ProposalType.SECURITY_EFFECT}
            else tuple(item for item in (proposal.source, proposal.target) if item is not None)
        )
        mapped = {
            item.entity_id
            for item in refs
            if entities[item.entity_id].codeql_identity is not None
        }
        if mapped and not self._codeql_attempted(mapped):
            raise CoordinatorConstraint(
                "CODEQL_CORROBORATION_REQUIRED",
                "mapped proposal anchors require one relevant fixed CodeQL attempt before Gate submission",
                CoordinatorActionType.REQUEST_CODEQL_CORROBORATION.value,
            )

    def _with_provenance(
        self,
        proposal: SecurityProposal,
        finding_ids: Sequence[str],
    ) -> SecurityProposal:
        return SecurityProposal.create(
            proposal_type=proposal.proposal_type,
            subject=proposal.subject,
            source=proposal.source,
            target=proposal.target,
            scope=proposal.scope,
            semantic_category=proposal.semantic_category,
            evidence_refs=proposal.evidence_refs,
            reason=proposal.reason,
            model_confidence=proposal.model_confidence,
            provenance={
                **dict(proposal.provenance),
                "producer": COORDINATOR_RUNTIME_VERSION,
                "coordinator_agent": COORDINATOR_AGENT.id,
                "specialist_finding_ids": list(finding_ids),
                "benchmark_informed": False,
            },
        )

    def _pending_entry(
        self,
        proposal: SecurityProposal,
        finding_ids: Sequence[str],
        *,
        repair_kind: str | None = None,
        original_proposal_id: str | None = None,
    ) -> dict[str, Any]:
        return {
            "proposal": proposal.to_dict(),
            "supporting_finding_ids": list(finding_ids),
            "repair_kind": repair_kind,
            "original_proposal_id": original_proposal_id,
        }

    def _record_pending(
        self,
        action: CoordinatorAction,
        proposal: SecurityProposal,
        finding_ids: Sequence[str],
        *,
        repair_kind: str | None = None,
        original_proposal_id: str | None = None,
    ) -> None:
        entry = self._pending_entry(
            proposal,
            finding_ids,
            repair_kind=repair_kind,
            original_proposal_id=original_proposal_id,
        )
        self.pending[proposal.proposal_id] = entry
        self.board.record_coordinator_event(
            event_type="PROPOSAL_REPAIR_PREPARED" if repair_kind else "PROPOSAL_PENDING",
            coordinator_round=action.coordinator_round,
            payload={"pending_proposal": entry},
        )

    def _rebuild_path(self, coordinator_round: int) -> AgentGraphPathResult:
        if not self.active_proposals:
            raise CoordinatorConstraint(
                "NO_ADMISSIBLE_PROPOSAL",
                "path rebuild requires at least one ADMISSIBLE proposal",
                CoordinatorActionType.SUBMIT_PROPOSAL.value,
            )
        result = self.graph_path_adapter.rebuild(
            proposals=tuple(self.active_proposals.values()),
            gate_results=tuple(self.gate_results),
        )
        self.graph_results.append(result)
        self.board.record_coordinator_event(
            event_type="PATH_REBUILT",
            coordinator_round=coordinator_round,
            payload={
                "path_summary": result.summary(),
                "candidate_paths": [
                    dict(item) for item in result.path_search.all_candidate_paths
                ],
            },
        )
        return result

    def _gate(
        self,
        action: CoordinatorAction,
        proposal: SecurityProposal,
        finding_ids: Sequence[str],
    ) -> None:
        self._validate_proposal_support(proposal, finding_ids)
        self._enforce_codeql_policy(proposal)
        self.budget.record_proposal()
        result = self.evidence_gate.evaluate(proposal)
        self.proposals.append(proposal)
        self.proposal_attempts[proposal.proposal_id] = proposal
        self.proposal_support[proposal.proposal_id] = tuple(finding_ids)
        self.gate_results.append(result)
        self.pending.pop(proposal.proposal_id, None)
        rejection = result.rejection_reasons or result.missing_evidence
        question = "; ".join(rejection) if rejection else None
        self.board.record_coordinator_event(
            event_type="GATE_RESULT_RECORDED",
            coordinator_round=action.coordinator_round,
            payload={
                "proposal": proposal.to_dict(),
                "gate_result": result.to_dict(),
                "supporting_finding_ids": list(finding_ids),
                "unresolved_question": question,
            },
        )
        if result.status is GateStatus.ADMISSIBLE:
            is_new = proposal.proposal_id not in self.active_proposals
            if is_new:
                self.budget.record_admissible()
                self.active_proposals[proposal.proposal_id] = proposal
                repair_kind = proposal.provenance.get("repair_kind")
                if repair_kind == "SCOPE":
                    self.scope_repairs_admitted += 1
                elif repair_kind == "ROLE":
                    self.role_repairs_admitted += 1
                self._rebuild_path(action.coordinator_round)

    def _submit(self, action: CoordinatorAction) -> None:
        if action.proposal is not None:
            proposal = self._with_provenance(
                _proposal_from_model_draft(action.proposal, project_id=self.project_id),
                action.supporting_finding_ids,
            )
            self._validate_proposal_support(proposal, action.supporting_finding_ids)
            self._record_pending(action, proposal, action.supporting_finding_ids)
            finding_ids = action.supporting_finding_ids
        else:
            proposal_id = str(action.arguments["proposal_id"])
            try:
                entry = self.pending[proposal_id]
            except KeyError as exc:
                raise CoordinatorConstraint(
                    "PENDING_PROPOSAL_NOT_FOUND",
                    "SUBMIT_PROPOSAL references an unknown pending proposal",
                    CoordinatorActionType.REQUEST_SCOPE_REPAIR.value,
                ) from exc
            proposal = SecurityProposal.from_dict(entry["proposal"])
            finding_ids = tuple(str(item) for item in entry["supporting_finding_ids"])
        self._gate(action, proposal, finding_ids)

    def _last_gate_result(self, proposal_id: str) -> EvidenceGateResult:
        matches = [item for item in self.gate_results if item.proposal_id == proposal_id]
        if not matches:
            raise CoordinatorConstraint(
                "GATE_RESULT_NOT_FOUND",
                "repair requires a prior Gate result",
                CoordinatorActionType.SUBMIT_PROPOSAL.value,
            )
        return matches[-1]

    @staticmethod
    def _clone_proposal(
        proposal: SecurityProposal,
        *,
        subject: EntityRoleRef | None = None,
        source: EntityRoleRef | None = None,
        target: EntityRoleRef | None = None,
        scope: Any = None,
        repair_kind: str,
    ) -> SecurityProposal:
        return SecurityProposal.create(
            proposal_type=proposal.proposal_type,
            subject=subject or proposal.subject,
            source=source if source is not None else proposal.source,
            target=target if target is not None else proposal.target,
            scope=scope or proposal.scope,
            semantic_category=proposal.semantic_category,
            evidence_refs=proposal.evidence_refs,
            reason=proposal.reason,
            model_confidence=proposal.model_confidence,
            provenance={
                **dict(proposal.provenance),
                "repair_kind": repair_kind,
                "repair_of": proposal.proposal_id,
                "security_semantics_changed": False,
            },
        )

    def _prepare_scope_repair(self, action: CoordinatorAction) -> None:
        proposal_id = str(action.arguments["proposal_id"])
        proposal = self.proposal_attempts.get(proposal_id)
        result = self._last_gate_result(proposal_id)
        if proposal is None or not any("SCOPE" in item for item in result.rejection_reasons):
            raise CoordinatorConstraint(
                "SCOPE_CONSTRUCTION_FAILED",
                "scope repair requires a scope-related Gate rejection",
                CoordinatorActionType.SUBMIT_PROPOSAL.value,
            )
        preview = build_valid_scope(
            self.repository_index,
            project_id=self.project_id,
            subject=proposal.subject,
            source=proposal.source,
            target=proposal.target,
            proposal_type=proposal.proposal_type,
            preferred_scope=proposal.scope.kind,
        )
        repaired = self._clone_proposal(
            proposal,
            scope=preview.scope,
            repair_kind="SCOPE",
        )
        finding_ids = self.proposal_support[proposal_id]
        self._validate_proposal_support(repaired, finding_ids)
        self._record_pending(
            action,
            repaired,
            finding_ids,
            repair_kind="SCOPE",
            original_proposal_id=proposal_id,
        )
        self.scope_repairs_prepared += 1

    @staticmethod
    def _declared_ref(
        findings: Sequence[SpecialistFinding],
        anchor: ProposalAnchor,
    ) -> EntityRoleRef | None:
        for finding in findings:
            details = dict(finding.details)
            if finding.finding_type in {FindingType.INPUT, FindingType.EFFECT}:
                if anchor is not ProposalAnchor.SUBJECT:
                    continue
                role = details.get("role")
                if role and finding.entity_ids:
                    value: dict[str, Any] = {
                        "entity_id": finding.entity_ids[0],
                        "role": role,
                    }
                    if details.get("role_index") is not None:
                        value["index"] = details["role_index"]
                    return EntityRoleRef.from_dict(value)
            elif anchor.value in {"source", "target"}:
                value = details.get(anchor.value)
                if isinstance(value, Mapping):
                    return EntityRoleRef.from_dict(value)
        return None

    def _repair_ref(
        self,
        *,
        proposal: SecurityProposal,
        current: EntityRoleRef,
        anchor: ProposalAnchor,
        findings: Sequence[SpecialistFinding],
    ) -> EntityRoleRef:
        preview = build_role_guidance(
            self.repository_index,
            entity=current.entity_id,
            proposal_type=proposal.proposal_type,
            observed_source_structure={"repair_of": proposal.proposal_id},
        )
        options = preview.legal_anchor_roles[anchor.value]
        valid = {(item.role, item.index) for item in options}
        if (current.role, current.index) in valid:
            return current
        declared = self._declared_ref(findings, anchor)
        if (
            declared is not None
            and declared.entity_id == current.entity_id
            and (declared.role, declared.index) in valid
        ):
            return declared
        if len(options) == 1:
            option: RoleOption = options[0]
            return option.to_ref(current.entity_id)
        raise CoordinatorConstraint(
            "ROLE_CONSTRUCTION_FAILED",
            f"role helper cannot deterministically repair {anchor.value} without semantic choice",
            {
                FindingType.INPUT: CoordinatorActionType.DISPATCH_INPUT_AGENT.value,
                FindingType.EFFECT: CoordinatorActionType.DISPATCH_EFFECT_AGENT.value,
                FindingType.BRIDGE: CoordinatorActionType.DISPATCH_BRIDGE_AGENT.value,
            }[self._required_finding_type(proposal.proposal_type)],
        )

    def _prepare_role_repair(self, action: CoordinatorAction) -> None:
        proposal_id = str(action.arguments["proposal_id"])
        proposal = self.proposal_attempts.get(proposal_id)
        result = self._last_gate_result(proposal_id)
        if proposal is None or not any(
            "ROLE" in item or "FIELD_STATE" in item for item in result.rejection_reasons
        ):
            raise CoordinatorConstraint(
                "ROLE_CONSTRUCTION_FAILED",
                "role repair requires a role-related Gate rejection",
                CoordinatorActionType.SUBMIT_PROPOSAL.value,
            )
        finding_ids = self.proposal_support[proposal_id]
        findings = self._findings(finding_ids)
        subject = self._repair_ref(
            proposal=proposal,
            current=proposal.subject,
            anchor=ProposalAnchor.SUBJECT,
            findings=findings,
        )
        source = (
            self._repair_ref(
                proposal=proposal,
                current=proposal.source,
                anchor=ProposalAnchor.SOURCE,
                findings=findings,
            )
            if proposal.source is not None
            else None
        )
        target = (
            self._repair_ref(
                proposal=proposal,
                current=proposal.target,
                anchor=ProposalAnchor.TARGET,
                findings=findings,
            )
            if proposal.target is not None
            else None
        )
        repaired = self._clone_proposal(
            proposal,
            subject=subject,
            source=source,
            target=target,
            repair_kind="ROLE",
        )
        self._validate_proposal_support(repaired, finding_ids)
        self._record_pending(
            action,
            repaired,
            finding_ids,
            repair_kind="ROLE",
            original_proposal_id=proposal_id,
        )
        self.role_repairs_prepared += 1

    def run(self) -> CoordinatorRunResult:
        while self.stop_reason is None:
            try:
                coordinator_round = self.budget.begin_round()
            except CoordinatorConstraint:
                coordinator_round = max(1, self.budget.coordinator_rounds)
                self._stop(coordinator_round, StopReason.BUDGET_EXHAUSTED)
                break
            observation = build_coordinator_observation(
                board=self.board,
                coordinator_round=coordinator_round,
                dispatch_tool_policy={
                    action_type.value: {
                        "specialist_agent": role.value,
                        "allowed_tools": sorted(
                            self.specialist_runtimes[role].allowed_tools
                        ),
                        "non_empty_subset_required": True,
                        "canonical_names_case_sensitive": True,
                    }
                    for action_type, role in _DISPATCH_ROLES.items()
                },
                previous_observation=self.observations[-1] if self.observations else None,
            )
            self.observations.append(observation)
            request = LLMRequest.create(
                project_id=self.project_id,
                round=coordinator_round,
                system_prompt=COORDINATOR_SYSTEM_PROMPT,
                observation=observation.to_dict(),
            )
            try:
                response = self.llm_client.complete(request)
                self.budget.record_model_call(response)
                action = _parse_action(
                    response=response,
                    project_id=self.project_id,
                    coordinator_round=coordinator_round,
                    normalizer=self.normalizer,
                )
            except (ModelCallError, KeyError, TypeError, ValueError) as exc:
                failure_class = (
                    exc.failure_class.value if isinstance(exc, ModelCallError) else "MODEL_OUTPUT_INVALID"
                )
                self._feedback(
                    coordinator_round=coordinator_round,
                    failure_class=failure_class,
                    message=str(exc),
                    next_required_action=CoordinatorActionType.STOP.value,
                    action_id=None,
                    retryable=False,
                )
                self._budget_event(coordinator_round)
                self._stop(coordinator_round, StopReason.OTHER)
                break
            self.model_responses.append(
                {
                    "request_id": request.request_id,
                    "observation_id": observation.observation_id,
                    "prompt_sha256": prompt_sha256(COORDINATOR_SYSTEM_PROMPT),
                    "response": response.to_dict(),
                }
            )
            self.actions.append(action)
            self.board.record_coordinator_event(
                event_type="COORDINATOR_ACTION_RECORDED",
                coordinator_round=coordinator_round,
                payload={"action": action.to_dict()},
            )
            try:
                if action.action_type in _DISPATCH_ROLES:
                    self._dispatch(action)
                elif action.action_type is CoordinatorActionType.REQUEST_CODEQL_CORROBORATION:
                    self._request_codeql(action)
                elif action.action_type is CoordinatorActionType.SUBMIT_PROPOSAL:
                    self._submit(action)
                elif action.action_type is CoordinatorActionType.REQUEST_SCOPE_REPAIR:
                    self._prepare_scope_repair(action)
                elif action.action_type is CoordinatorActionType.REQUEST_ROLE_REPAIR:
                    self._prepare_role_repair(action)
                elif action.action_type is CoordinatorActionType.REBUILD_PATH:
                    self._rebuild_path(coordinator_round)
                else:
                    assert action.stop_reason is not None
                    self._stop(coordinator_round, action.stop_reason)
            except CoordinatorConstraint as exc:
                self._feedback(
                    coordinator_round=coordinator_round,
                    failure_class=exc.failure_class,
                    message=str(exc),
                    next_required_action=exc.next_required_action,
                    action_id=action.action_id,
                    details=exc.details,
                )
                if exc.failure_class == "BUDGET_EXHAUSTED":
                    self._stop(coordinator_round, StopReason.BUDGET_EXHAUSTED)
            except (OSError, UnicodeError, ValueError) as exc:
                self._feedback(
                    coordinator_round=coordinator_round,
                    failure_class="COORDINATOR_EXECUTION_ERROR",
                    message=str(exc),
                    next_required_action=CoordinatorActionType.STOP.value,
                    action_id=action.action_id,
                    retryable=False,
                )
                self._stop(coordinator_round, StopReason.OTHER)
            self._budget_event(coordinator_round)

        assert self.stop_reason is not None
        return CoordinatorRunResult(
            board=self.board,
            actions=tuple(self.actions),
            observations=tuple(self.observations),
            model_responses=tuple(self.model_responses),
            specialist_runs=tuple(self.specialist_runs),
            proposals=tuple(self.proposals),
            gate_results=tuple(self.gate_results),
            graph_results=tuple(self.graph_results),
            codeql_results=tuple(self.codeql_results),
            failures=tuple(self.failures),
            stop_reason=self.stop_reason,
            budget_state=self.budget.to_dict(),
            scope_repairs_prepared=self.scope_repairs_prepared,
            scope_repairs_admitted=self.scope_repairs_admitted,
            role_repairs_prepared=self.role_repairs_prepared,
            role_repairs_admitted=self.role_repairs_admitted,
        )
