"""M7 project-local controller.

M7-5 intentionally supports only the model -> bounded tool -> next observation
loop.  Proposal, Gate, and path handling are added by later milestones.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from java_vuln_research.work1_agent.proposal import EvidenceGate, EvidenceGateResult, GateStatus, SecurityProposal
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex

from .actions import TOOL_ACTIONS, ActionType, StopReason
from .budget import BudgetExceeded
from .feedback import AgentGateFeedback, build_gate_feedback, evidence_from_tool_result
from .llm_client import LLMClient, LLMRequest, ModelCallError
from .observation import AgentObservation, bounded_tool_catalog, build_repository_first_observation
from .parser import StrictActionParser
from .prompt import build_system_prompt, prompt_sha256
from .state import AgentState
from .tool_adapter import AgentToolResult, RepositoryCodeQLToolAdapter
from .trace import AgentTrace, TraceEventType


CONTROLLER_VERSION = "M7_CONTROLLER_V1"


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
        native_baseline_summary: Mapping[str, Any] | None = None,
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
        self.native_baseline_summary = dict(native_baseline_summary or {})
        self.trace = AgentTrace(state.project_id)
        self.observations: list[AgentObservation] = []
        self.tool_results: list[AgentToolResult] = []
        self.proposals: list[SecurityProposal] = []
        self.gate_results: list[EvidenceGateResult] = []
        self.gate_feedback: list[AgentGateFeedback] = []
        self.admissible_proposals: dict[str, SecurityProposal] = {}
        self.failures: list[AgentControllerFailure] = []
        self.recent_feedback: list[Mapping[str, Any]] = []
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
            payload=payload,
            provenance=self._provenance,
        )

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
            tuple(self.failures),
            self.evidence_gate is not None,
        )

    def run(self) -> AgentControllerResult:
        known_entities = {item.entity_id for item in self.repository_index.entities}
        while not self.state.stopped:
            try:
                self.state.budget.begin_round()
            except BudgetExceeded as exc:
                self._append(TraceEventType.BUDGET, {"exhausted": exc.budget_name, "budget": self.state.budget.to_dict()})
                self._stop(StopReason.BUDGET_EXHAUSTED, details={"budget": exc.budget_name})
                break

            observation = build_repository_first_observation(
                state=self.state,
                repository_index=self.repository_index,
                codeql_status=self.codeql_status,
                native_baseline_summary=self.native_baseline_summary,
                recent_feedback=self.recent_feedback,
            )
            self.observations.append(observation)
            if len(self.observations) == 1:
                self._append(TraceEventType.INITIAL_OBSERVATION, observation.to_dict())

            request = LLMRequest.create(
                project_id=self.state.project_id,
                round=self.state.current_round,
                system_prompt=self.system_prompt,
                observation=observation.to_dict(),
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
            except ModelCallError as exc:
                self._failure(
                    AgentControllerFailure(
                        exc.failure_class.value,
                        str(exc).partition(": ")[2],
                        self.state.current_round,
                        exc.model_call_id,
                        exc.retryable,
                    )
                )
                break

            self._append(TraceEventType.ACTION, action.to_dict())
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
                try:
                    self.state.budget.record_proposal()
                    paths_before = tuple(self.state.active_candidate_path_ids)
                    gate_result = self.evidence_gate.evaluate(proposal)
                    if gate_result.status is GateStatus.ADMISSIBLE and proposal.proposal_id not in self.admissible_proposals:
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
                feedback = build_gate_feedback(
                    project_id=self.state.project_id,
                    round=self.state.current_round,
                    result=gate_result,
                    active_proposal_count=len(self.admissible_proposals),
                    candidate_path_ids_before=paths_before,
                    candidate_path_ids_after=tuple(self.state.active_candidate_path_ids),
                    tool_results=self.tool_results,
                    budget=self.state.budget,
                )
                self.gate_feedback.append(feedback)
                self.recent_feedback.append(feedback.to_dict())
                self._append(TraceEventType.GATE_RESULT, feedback.to_dict())
                self._append(TraceEventType.BUDGET, self.state.budget.to_dict())
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
            tool_evidence = evidence_from_tool_result(tool_result, self.repository_index)
            for evidence in tool_evidence:
                self.state.record_evidence(evidence.evidence_id, project_id=self.state.project_id)
                if self.evidence_gate is not None:
                    self.evidence_gate.register_evidence(evidence, tool_artifact=tool_result.to_dict())
                self._append(TraceEventType.EVIDENCE, evidence.to_dict())
            feedback = {
                **tool_result.to_dict(),
                "evidence_refs": [item.to_dict() for item in tool_evidence],
            }
            self.recent_feedback.append(feedback)
            self._append(TraceEventType.TOOL_RESULT, feedback)
            self._append(TraceEventType.BUDGET, self.state.budget.to_dict())

        return self._result()
