"""M7 project-local controller.

The same controller is feature-gated by injected deterministic components:
tool-only, Evidence Gate, then bounded graph/path feedback.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from java_vuln_research.work1_agent.proposal import (
    EvidenceGate,
    EvidenceGateResult,
    GateStatus,
    ProposalType,
    SecurityProposal,
)
from java_vuln_research.work1_agent.repository.entity import ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex

from .actions import TOOL_ACTIONS, ActionType, StopReason
from .budget import BudgetExceeded
from .feedback import AgentGateFeedback, build_gate_feedback, evidence_from_tool_result
from .graph_adapter import AgentGraphPathAdapter, AgentGraphPathResult
from .llm_client import LLMClient, LLMRequest, ModelCallError, ModelFailureClass
from .observation import AgentObservation, bounded_tool_catalog, build_repository_first_observation
from .parser import StrictActionParser
from .prompt import build_system_prompt, prompt_sha256
from .state import AgentState
from .tool_adapter import AgentToolResult, RepositoryCodeQLToolAdapter
from .trace import AgentTrace, TraceEventType


CONTROLLER_VERSION = "M7_CONTROLLER_V3"


class ControllerPhase(str, Enum):
    DISCOVERY = "DISCOVERY"
    INSPECTION = "INSPECTION"
    HYPOTHESIS = "HYPOTHESIS"
    PATH_SEARCH = "PATH_SEARCH"


_ROUND_ONE_ACTIONS = {ActionType.SEARCH_CODE, ActionType.SEARCH_SYMBOLS}
_ANCHOR_PROPOSALS = {ProposalType.EXTERNAL_INPUT, ProposalType.SECURITY_EFFECT}
_MIDDLE_PROPOSALS = {
    ProposalType.WRAPPER_FLOW,
    ProposalType.LIBRARY_FLOW,
    ProposalType.FIELD_STATE,
    ProposalType.FRAMEWORK_RELATION,
    ProposalType.CALLBACK_RELATION,
}


@dataclass(frozen=True, slots=True)
class AgentControllerFailure:
    failure_class: str
    message: str
    round: int
    model_call_id: str | None = None
    retryable: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "failure_class": self.failure_class,
            "message": self.message,
            "round": self.round,
            "model_call_id": self.model_call_id,
            "retryable": self.retryable,
        }


@dataclass(frozen=True, slots=True)
class AgentControllerResult:
    state: AgentState
    trace: AgentTrace
    observations: tuple[AgentObservation, ...]
    tool_results: tuple[AgentToolResult, ...]
    proposals: tuple[SecurityProposal, ...]
    gate_results: tuple[EvidenceGateResult, ...]
    gate_feedback: tuple[AgentGateFeedback, ...]
    graph_results: tuple[AgentGraphPathResult, ...]
    failures: tuple[AgentControllerFailure, ...]
    proposal_handling_enabled: bool

    def summary(self) -> dict[str, Any]:
        return {
            "controller_version": CONTROLLER_VERSION,
            "project_id": self.state.project_id,
            "rounds": self.state.current_round,
            "model_calls": self.state.budget.model_calls,
            "tool_calls": self.state.budget.tool_calls_total,
            "proposals": self.state.budget.proposals_total,
            "admissible_proposals": self.state.budget.admissible_proposals,
            "observations": len(self.observations),
            "failures": [item.to_dict() for item in self.failures],
            "stop_reason": self.state.stop_reason.value if self.state.stop_reason else None,
            "proposal_handling_enabled": self.proposal_handling_enabled,
        }


class AgentController:
    """Run one structured decision per round with optional deterministic Gate."""

    def __init__(
        self,
        *,
        state: AgentState,
        repository_index: RepositoryIndex,
        codeql_status: Mapping[str, Any],
        llm_client: LLMClient,
        parser: StrictActionParser,
        tool_adapter: RepositoryCodeQLToolAdapter,
        evidence_gate: EvidenceGate | None = None,
        graph_path_adapter: AgentGraphPathAdapter | None = None,
        native_baseline_summary: Mapping[str, Any] | None = None,
        max_stagnant_rounds: int = 3,
        max_model_output_retries: int = 1,
    ) -> None:
        if state.project_id != tool_adapter.project_id:
            raise ValueError("controller components are cross-project")
        if tool_adapter.index is not repository_index:
            raise ValueError("controller and tool adapter must share one RepositoryIndex")
        status_project = str(codeql_status.get("project_id", state.project_id))
        state.require_project(status_project)
        self.state = state
        self.repository_index = repository_index
        self.codeql_status = dict(codeql_status)
        self.llm_client = llm_client
        self.parser = parser
        self.tool_adapter = tool_adapter
        self.evidence_gate = evidence_gate
        if evidence_gate is not None and evidence_gate.repository_root != repository_index.repository_root.resolve():
            raise ValueError("controller and Evidence Gate repository roots differ")
        if graph_path_adapter is not None:
            if evidence_gate is None or graph_path_adapter.evidence_gate is not evidence_gate:
                raise ValueError("graph adapter must share the controller Evidence Gate")
            if graph_path_adapter.project_id != state.project_id:
                raise ValueError("graph adapter is cross-project")
        if not 1 <= int(max_stagnant_rounds) <= 10:
            raise ValueError("max_stagnant_rounds must be between 1 and 10")
        if not 0 <= int(max_model_output_retries) <= 2:
            raise ValueError("max_model_output_retries must be between 0 and 2")
        self.graph_path_adapter = graph_path_adapter
        self.max_stagnant_rounds = int(max_stagnant_rounds)
        self.max_model_output_retries = int(max_model_output_retries)
        self.stagnant_rounds = 0
        self.native_baseline_summary = dict(native_baseline_summary or {})
        self.trace = AgentTrace(state.project_id)
        self.observations: list[AgentObservation] = []
        self.tool_results: list[AgentToolResult] = []
        self.proposals: list[SecurityProposal] = []
        self.gate_results: list[EvidenceGateResult] = []
        self.gate_feedback: list[AgentGateFeedback] = []
        self.graph_results: list[AgentGraphPathResult] = []
        self.admissible_proposals: dict[str, SecurityProposal] = {}
        self.failures: list[AgentControllerFailure] = []
        self.recent_feedback: list[Mapping[str, Any]] = []
        self.evidence_entities: dict[str, set[str]] = {
            evidence_id: set(evidence.entity_ids)
            for evidence_id, evidence in (evidence_gate.evidence_catalog.items() if evidence_gate is not None else ())
            if evidence_id in state.evidence_refs
        }
        self.phase = ControllerPhase.DISCOVERY
        self.system_prompt = build_system_prompt(bounded_tool_catalog())
        self._provenance = {
            "producer": "M7_AGENT_CONTROLLER",
            "controller_version": CONTROLLER_VERSION,
            "benchmark_informed": False,
        }

    def _append(self, event_type: TraceEventType, payload: Mapping[str, Any]) -> None:
        self.trace.append(
            round=self.state.current_round,
            event_type=event_type,
            payload={**dict(payload), "phase": self.phase.value},
            provenance=self._provenance,
        )

    def _derive_phase(self) -> ControllerPhase:
        if self.proposals or self.state.active_candidate_path_ids:
            return ControllerPhase.PATH_SEARCH
        inspected_callables = {
            entity.entity_id
            for entity in self.repository_index.entities
            if entity.kind in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}
            and entity.entity_id in self.state.inspected_entity_ids
        }
        if inspected_callables:
            return ControllerPhase.HYPOTHESIS
        if self.tool_results:
            return ControllerPhase.INSPECTION
        return ControllerPhase.DISCOVERY

    def _structured_feedback(
        self,
        *,
        failure_class: str,
        message: str,
        action_id: str,
        required_actions: tuple[str, ...],
        details: Mapping[str, Any] | None = None,
    ) -> bool:
        feedback = {
            "feedback_type": "CONTROLLER_CONSTRAINT",
            "failure_class": failure_class,
            "message": message,
            "action_id": action_id,
            "required_actions": list(required_actions),
            "details": dict(details or {}),
        }
        self.recent_feedback.append(feedback)
        self._append(TraceEventType.CONTROLLER_FEEDBACK, feedback)
        self._append(TraceEventType.BUDGET, self.state.budget.to_dict())
        return self._record_progress(False)

    def _has_inspected_callable(self, entity_id: str) -> bool:
        by_id = {item.entity_id: item for item in self.repository_index.entities}
        target = by_id.get(entity_id)
        if target is None:
            return False
        for inspected_id in self.state.inspected_entity_ids:
            inspected = by_id.get(inspected_id)
            if inspected is None or inspected.kind not in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}:
                continue
            if (
                inspected.repository_relative_path == target.repository_relative_path
                and inspected.start_line <= target.start_line
                and target.end_line <= inspected.end_line
            ):
                return True
        return False

    def _eligible_inspected_callable_roles(self) -> dict[str, list[dict[str, Any]]]:
        by_id = {item.entity_id: item for item in self.repository_index.entities}
        callables = [
            by_id[entity_id]
            for entity_id in sorted(self.state.inspected_entity_ids)
            if entity_id in by_id
            and by_id[entity_id].kind in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}
        ][:10]
        callable_rows: list[dict[str, Any]] = []
        parameter_refs: list[dict[str, Any]] = []
        return_refs: list[dict[str, Any]] = []
        for entity in callables:
            identity = f"{entity.qualified_name}{(entity.signature or '')[len(entity.simple_name):]}"
            indexes = sorted(
                {
                    int(item.provenance["parameter_index"])
                    for item in self.repository_index.entities
                    if item.kind is ProgramEntityKind.PARAMETER
                    and item.enclosing_callable == identity
                    and "parameter_index" in item.provenance
                }
            )
            callable_rows.append(
                {
                    "entity_id": entity.entity_id,
                    "kind": entity.kind.value,
                    "qualified_name": entity.qualified_name,
                    "parameter_count": len(indexes),
                }
            )
            parameter_refs.extend(
                {"entity_id": entity.entity_id, "role": "PARAMETER", "index": index}
                for index in indexes
            )
            return_refs.append({"entity_id": entity.entity_id, "role": "RETURN"})
        return {
            "eligible_inspected_callables": callable_rows,
            "eligible_parameter_role_refs": parameter_refs[:20],
            "eligible_return_role_refs": return_refs,
        }

    def _proposal_constraint(self, proposal: SecurityProposal) -> tuple[str, str, tuple[str, ...], dict[str, Any]] | None:
        if not proposal.evidence_refs or not self.state.evidence_refs:
            return (
                "PROPOSAL_BEFORE_EVIDENCE",
                "PROPOSE requires at least one tool-grounded EvidenceRef",
                (ActionType.SEARCH_CODE.value, ActionType.SEARCH_SYMBOLS.value, ActionType.INSPECT_METHOD.value),
                {"known_evidence_count": len(self.state.evidence_refs)},
            )
        if proposal.proposal_type in _ANCHOR_PROPOSALS and not self._has_inspected_callable(proposal.subject.entity_id):
            eligible = self._eligible_inspected_callable_roles()
            if eligible["eligible_inspected_callables"]:
                return (
                    "ANCHOR_SUBJECT_NOT_INSPECTED_CALLABLE",
                    "the anchor subject is not inside an inspected callable; copy one supplied eligible role ref exactly",
                    (ActionType.PROPOSE.value,),
                    {"subject_entity_id": proposal.subject.entity_id, **eligible},
                )
            return (
                "ANCHOR_BEFORE_CALLABLE_INSPECTION",
                "input/effect anchors require an inspected containing method or constructor",
                (ActionType.INSPECT_METHOD.value,),
                {"subject_entity_id": proposal.subject.entity_id},
            )
        if proposal.proposal_type in _MIDDLE_PROPOSALS and proposal.source is not None and proposal.target is not None:
            covered: set[str] = set()
            for evidence_id in proposal.evidence_refs:
                covered.update(self.evidence_entities.get(evidence_id, set()))
            required = {proposal.source.entity_id, proposal.target.entity_id}
            missing = sorted(required - covered)
            if missing:
                return (
                    "PROPOSAL_EVIDENCE_COVERAGE_INCOMPLETE",
                    "propagation proposal evidence must ground both source and target entities",
                    (ActionType.INSPECT_METHOD.value, ActionType.READ_FILE_RANGE.value),
                    {"required_entity_ids": sorted(required), "covered_entity_ids": sorted(covered), "missing_entity_ids": missing},
                )
        return None

    def _stop(self, reason: StopReason, *, details: Mapping[str, Any] | None = None) -> None:
        self.state.stop(reason)
        self._append(
            TraceEventType.STOP,
            {"stop_reason": reason.value, "details": dict(details or {})},
        )

    def _failure(self, failure: AgentControllerFailure, *, stop_reason: StopReason = StopReason.OTHER) -> None:
        self.failures.append(failure)
        self._append(TraceEventType.FAILURE, failure.to_dict())
        self._stop(stop_reason, details={"failure_class": failure.failure_class})

    def _result(self) -> AgentControllerResult:
        return AgentControllerResult(
            self.state,
            self.trace,
            tuple(self.observations),
            tuple(self.tool_results),
            tuple(self.proposals),
            tuple(self.gate_results),
            tuple(self.gate_feedback),
            tuple(self.graph_results),
            tuple(self.failures),
            self.evidence_gate is not None,
        )

    def _record_progress(self, progress: bool) -> bool:
        self.stagnant_rounds = 0 if progress else self.stagnant_rounds + 1
        if self.stagnant_rounds < self.max_stagnant_rounds:
            return False
        self._stop(
            StopReason.NO_FURTHER_ACTION,
            details={"stagnant_rounds": self.stagnant_rounds, "threshold": self.max_stagnant_rounds},
        )
        return True

    def run(self) -> AgentControllerResult:
        known_entities = {item.entity_id for item in self.repository_index.entities}
        while not self.state.stopped:
            try:
                self.state.budget.begin_round()
            except BudgetExceeded as exc:
                self._append(TraceEventType.BUDGET, {"exhausted": exc.budget_name, "budget": self.state.budget.to_dict()})
                self._stop(StopReason.BUDGET_EXHAUSTED, details={"budget": exc.budget_name})
                break

            self.phase = self._derive_phase()

            observation = build_repository_first_observation(
                state=self.state,
                repository_index=self.repository_index,
                codeql_status=self.codeql_status,
                native_baseline_summary=self.native_baseline_summary,
                recent_feedback=self.recent_feedback,
                controller_phase=self.phase.value,
            )
            self.observations.append(observation)
            if len(self.observations) == 1:
                self._append(TraceEventType.INITIAL_OBSERVATION, observation.to_dict())

            action = None
            response = None
            repair_failure: AgentControllerFailure | None = None
            repairable = {
                ModelFailureClass.INVALID_JSON,
                ModelFailureClass.STRUCTURED_OUTPUT_AMBIGUOUS,
                ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED,
                ModelFailureClass.INVALID_ACTION,
                ModelFailureClass.SCHEMA_VIOLATION,
                ModelFailureClass.TOOL_ARGUMENT_INVALID,
            }
            for attempt in range(1, self.max_model_output_retries + 2):
                request_observation = observation.to_dict()
                if repair_failure is not None:
                    request_observation = {
                        **request_observation,
                        "model_output_repair": {
                            "attempt": attempt,
                            "previous_failure_class": repair_failure.failure_class,
                            "previous_failure_message": repair_failure.message,
                            "instruction": "Return a fresh bare JSON decision that exactly satisfies the frozen action/proposal contract; do not repeat or quote the invalid response.",
                        },
                    }
                request = LLMRequest.create(
                    project_id=self.state.project_id,
                    round=self.state.current_round,
                    system_prompt=self.system_prompt,
                    observation=request_observation,
                    attempt=attempt,
                )
                try:
                    response = self.llm_client.complete(request)
                    self.state.budget.record_model_call(
                        input_tokens=response.input_tokens,
                        output_tokens=response.output_tokens,
                    )
                    self._append(
                        TraceEventType.MODEL_CALL,
                        {
                            "request_id": request.request_id,
                            "observation_id": observation.observation_id,
                            "attempt": attempt,
                            "prompt_sha256": prompt_sha256(self.system_prompt),
                            "response": response.to_dict(),
                        },
                    )
                    action = self.parser.parse(
                        response,
                        project_id=self.state.project_id,
                        round=self.state.current_round,
                        budget=self.state.budget,
                        known_entity_ids=known_entities,
                        known_evidence_refs=set(self.state.evidence_refs),
                    )
                    break
                except ModelCallError as exc:
                    failure = AgentControllerFailure(
                        exc.failure_class.value,
                        str(exc).partition(": ")[2],
                        self.state.current_round,
                        exc.model_call_id,
                        exc.retryable,
                    )
                    output_repair = exc.failure_class in repairable
                    transient_transport_retry = (
                        exc.retryable
                        and exc.failure_class
                        in {ModelFailureClass.MODEL_TIMEOUT, ModelFailureClass.MODEL_UNAVAILABLE}
                    )
                    if (output_repair or transient_transport_retry) and attempt <= self.max_model_output_retries:
                        repair_failure = failure if output_repair else None
                        self._append(
                            TraceEventType.MODEL_RETRY,
                            {
                                **failure.to_dict(),
                                "attempt": attempt,
                                "next_attempt": attempt + 1,
                                "retry_kind": (
                                    "OUTPUT_REPAIR" if output_repair else "TRANSIENT_TRANSPORT"
                                ),
                            },
                        )
                        continue
                    self._failure(failure)
                    break
            if self.state.stopped:
                break
            assert action is not None and response is not None

            self._append(TraceEventType.ACTION, action.to_dict())
            proposal_without_evidence = (
                action.action_type is ActionType.PROPOSE
                and action.proposal is not None
                and (not action.proposal.get("evidence_refs") or not self.state.evidence_refs)
            )
            if (
                self.state.current_round == 1
                and action.action_type not in _ROUND_ONE_ACTIONS
                and not proposal_without_evidence
            ):
                if not self.repository_index.entities and action.action_type is ActionType.STOP:
                    self._stop(action.stop_reason or StopReason.INSUFFICIENT_EVIDENCE, details={"action_id": action.action_id})
                    break
                if self._structured_feedback(
                    failure_class="ROUND1_DISCOVERY_ACTION_REQUIRED",
                    message="round 1 requires SEARCH_CODE or SEARCH_SYMBOLS",
                    action_id=action.action_id,
                    required_actions=tuple(sorted(item.value for item in _ROUND_ONE_ACTIONS)),
                ):
                    break
                continue
            if action.action_type is ActionType.PROPOSE:
                if self.evidence_gate is None:
                    self._failure(
                        AgentControllerFailure(
                            "PROPOSAL_DISABLED_M7_5",
                            "controller was configured without an Evidence Gate",
                            self.state.current_round,
                            response.model_call_id,
                        )
                    )
                    break
                assert action.proposal is not None
                proposal = SecurityProposal.from_dict(action.proposal)
                constraint = self._proposal_constraint(proposal)
                if constraint is not None:
                    failure_class, message, required_actions, details = constraint
                    if self._structured_feedback(
                        failure_class=failure_class,
                        message=message,
                        action_id=action.action_id,
                        required_actions=required_actions,
                        details=details,
                    ):
                        break
                    continue
                try:
                    self.state.budget.record_proposal()
                    paths_before = tuple(self.state.active_candidate_path_ids)
                    gate_result = self.evidence_gate.evaluate(proposal)
                    new_admissible = gate_result.status is GateStatus.ADMISSIBLE and proposal.proposal_id not in self.admissible_proposals
                    if new_admissible:
                        self.state.budget.record_admissible_proposal()
                        self.admissible_proposals[proposal.proposal_id] = proposal
                except (BudgetExceeded, OSError, UnicodeError, ValueError) as exc:
                    self._failure(
                        AgentControllerFailure(
                            "BUDGET_EXCEEDED" if isinstance(exc, BudgetExceeded) else "GATE_EXECUTION_ERROR",
                            str(exc),
                            self.state.current_round,
                            response.model_call_id,
                        ),
                        stop_reason=StopReason.BUDGET_EXHAUSTED if isinstance(exc, BudgetExceeded) else StopReason.OTHER,
                    )
                    break
                self.proposals.append(proposal)
                self.gate_results.append(gate_result)
                self.state.record_proposal(
                    proposal.proposal_id,
                    project_id=self.state.project_id,
                    gate_status=gate_result.status.value,
                )
                self._append(TraceEventType.PROPOSAL, proposal.to_dict())
                connected_anchors: list[Mapping[str, Any]] = []
                path_truncated = False
                if new_admissible and self.graph_path_adapter is not None:
                    graph_result = self.graph_path_adapter.rebuild(
                        proposals=tuple(self.admissible_proposals.values()),
                        gate_results=tuple(self.gate_results),
                    )
                    self.graph_results.append(graph_result)
                    self.state.active_candidate_path_ids.update(graph_result.candidate_path_ids)
                    new_ids = set(graph_result.candidate_path_ids) - set(paths_before)
                    for path in graph_result.path_search.hybrid_paths:
                        if path.candidate_path_id in new_ids:
                            connected_anchors.append(
                                {
                                    "candidate_path_id": path.candidate_path_id,
                                    "input_anchor": dict(path.input_anchor),
                                    "effect_anchor": dict(path.effect_anchor),
                                }
                            )
                    path_truncated = graph_result.path_search.search_truncation_count > 0
                    self._append(
                        TraceEventType.PATH_FEEDBACK,
                        {
                            **graph_result.summary(),
                            "new_path_ids": sorted(new_ids),
                            "new_connected_anchors": connected_anchors,
                        },
                    )
                feedback = build_gate_feedback(
                    project_id=self.state.project_id,
                    round=self.state.current_round,
                    result=gate_result,
                    active_proposal_count=len(self.admissible_proposals),
                    candidate_path_ids_before=paths_before,
                    candidate_path_ids_after=tuple(self.state.active_candidate_path_ids),
                    tool_results=self.tool_results,
                    budget=self.state.budget,
                    new_connected_anchors=connected_anchors,
                    path_truncated=path_truncated,
                    graph_update_enabled=self.graph_path_adapter is not None and new_admissible,
                )
                self.gate_feedback.append(feedback)
                self.recent_feedback.append(feedback.to_dict())
                self._append(TraceEventType.GATE_RESULT, feedback.to_dict())
                self._append(TraceEventType.BUDGET, self.state.budget.to_dict())
                if self._record_progress(new_admissible or bool(set(self.state.active_candidate_path_ids) - set(paths_before))):
                    break
                continue
            if action.action_type is ActionType.STOP:
                self._stop(action.stop_reason or StopReason.OTHER, details={"action_id": action.action_id})
                break
            if action.action_type not in TOOL_ACTIONS:
                self._failure(
                    AgentControllerFailure(
                        "INVALID_CONTROLLER_ACTION",
                        "controller received an action outside the M7-5 allow-list",
                        self.state.current_round,
                        response.model_call_id,
                    )
                )
                break

            try:
                self.state.budget.record_tool_call()
                tool_result = self.tool_adapter.execute(action)
            except (BudgetExceeded, OSError, UnicodeError, ValueError) as exc:
                failure_class = "BUDGET_EXCEEDED" if isinstance(exc, BudgetExceeded) else "TOOL_DISPATCH_ERROR"
                self._failure(
                    AgentControllerFailure(
                        failure_class,
                        str(exc),
                        self.state.current_round,
                        response.model_call_id,
                    ),
                    stop_reason=StopReason.BUDGET_EXHAUSTED if isinstance(exc, BudgetExceeded) else StopReason.OTHER,
                )
                break

            entity_ids = tuple(
                str(value)
                for name, value in action.arguments.items()
                if name.endswith("entity_id")
            )
            self.state.record_tool_call(
                tool_result.tool_call_id,
                project_id=tool_result.project_id,
                entity_ids=entity_ids,
            )
            self.tool_results.append(tool_result)
            prior_evidence_count = len(self.state.evidence_refs)
            tool_evidence = evidence_from_tool_result(tool_result, self.repository_index)
            for evidence in tool_evidence:
                self.state.record_evidence(evidence.evidence_id, project_id=self.state.project_id)
                self.evidence_entities[evidence.evidence_id] = set(evidence.entity_ids)
                if self.evidence_gate is not None:
                    self.evidence_gate.register_evidence(evidence, tool_artifact=tool_result.to_dict())
                self._append(TraceEventType.EVIDENCE, evidence.to_dict())
            feedback = {
                **tool_result.to_dict(),
                "evidence_refs": [item.to_dict() for item in tool_evidence],
                "evidence_summary": {
                    "evidence_count": len(tool_evidence),
                    "evidence_ids": [item.evidence_id for item in tool_evidence[:5]],
                    "covered_entity_ids": sorted(
                        {entity_id for item in tool_evidence for entity_id in item.entity_ids}
                    )[:5],
                    "source_kind_counts": dict(
                        sorted(Counter(item.source_kind.value for item in tool_evidence).items())
                    ),
                    "truncated": len(tool_evidence) > 5,
                },
            }
            self.recent_feedback.append(feedback)
            self._append(TraceEventType.TOOL_RESULT, feedback)
            self._append(TraceEventType.BUDGET, self.state.budget.to_dict())
            if self._record_progress(len(self.state.evidence_refs) > prior_evidence_count):
                break

        return self._result()
