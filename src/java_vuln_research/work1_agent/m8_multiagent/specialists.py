"""Bounded runtimes for the three M8 security-exploration specialists."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from java_vuln_research.work1_agent.agent.actions import (
    TOOL_ACTIONS,
    ActionType,
    AgentAction,
)
from java_vuln_research.work1_agent.agent.feedback import evidence_from_tool_result
from java_vuln_research.work1_agent.agent.llm_client import (
    LLMClient,
    LLMRequest,
    LLMResponse,
    MockLLMClient,
    ModelCallError,
)
from java_vuln_research.work1_agent.agent.parser import validate_tool_arguments
from java_vuln_research.work1_agent.agent.structured_output import (
    StructuredOutputNormalizer,
)
from java_vuln_research.work1_agent.agent.tool_adapter import (
    AgentToolResult,
    AgentToolStatus,
    RepositoryCodeQLToolAdapter,
)
from java_vuln_research.work1_agent.proposal.evidence import EvidenceRef
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex

from .agent_registry import SPECIALIST_AGENT_REGISTRY, AgentModelSpec
from .contracts import (
    ROLE_FINDING_TYPES,
    FindingType,
    SpecialistFinding,
    SpecialistResult,
    SpecialistResultStatus,
    SpecialistRole,
    SpecialistStopReason,
    SpecialistTaskSpec,
)
from .observation import SpecialistObservation, build_specialist_observation
from .prompts.bridge_agent import SYSTEM_PROMPT as BRIDGE_SYSTEM_PROMPT
from .prompts.effect_agent import SYSTEM_PROMPT as EFFECT_SYSTEM_PROMPT
from .prompts.input_agent import SYSTEM_PROMPT as INPUT_SYSTEM_PROMPT

if TYPE_CHECKING:
    from java_vuln_research.work1_agent.m8_experiment.runtime_usage import (
        RuntimeUsageRecorder,
    )


SPECIALIST_RUNTIME_VERSION = "M8_SPECIALIST_RUNTIME_V2"
MAX_INTERNAL_ROUNDS = 4
MAX_TOOL_CALLS = 6
MAX_FINDING_BATCHES = 1

_REPOSITORY_TOOLS = frozenset(
    item.value
    for item in TOOL_ACTIONS
    if not item.value.startswith("CODEQL_")
)
_CODEQL_TOOLS = frozenset(
    item.value
    for item in TOOL_ACTIONS
    if item.value.startswith("CODEQL_")
)
INPUT_ALLOWED_TOOLS = _REPOSITORY_TOOLS | _CODEQL_TOOLS
EFFECT_ALLOWED_TOOLS = _REPOSITORY_TOOLS | _CODEQL_TOOLS
BRIDGE_ALLOWED_TOOLS = frozenset(
    {
        ActionType.READ_FILE_RANGE.value,
        ActionType.INSPECT_METHOD.value,
        ActionType.INSPECT_TYPE.value,
        ActionType.GET_CALLERS.value,
        ActionType.GET_CALLEES.value,
        ActionType.GET_IMPLEMENTATIONS.value,
        ActionType.GET_OVERRIDES.value,
        ActionType.GET_FIELDS.value,
        ActionType.GET_ANNOTATIONS.value,
        *(_CODEQL_TOOLS),
    }
)

ROLE_ALLOWED_TOOLS = {
    SpecialistRole.INPUT: INPUT_ALLOWED_TOOLS,
    SpecialistRole.EFFECT: EFFECT_ALLOWED_TOOLS,
    SpecialistRole.BRIDGE: BRIDGE_ALLOWED_TOOLS,
}
ROLE_PROMPTS = {
    SpecialistRole.INPUT: INPUT_SYSTEM_PROMPT,
    SpecialistRole.EFFECT: EFFECT_SYSTEM_PROMPT,
    SpecialistRole.BRIDGE: BRIDGE_SYSTEM_PROMPT,
}

_DECISION_KEYS = {
    "action_type",
    "tool_name",
    "arguments",
    "findings",
    "status",
    "next_suggested_evidence",
    "uncertainty",
    "reason",
}
_FINDING_KEYS = {
    "entity_ids",
    "tool_call_ids",
    "evidence_refs",
    "summary",
    "details",
    "uncertainties",
}
_ROLE_DETAIL_KEYS = {
    SpecialistRole.INPUT: {
        "role",
        "role_index",
        "inspected_context",
        "why_externally_influenced",
        "recommended_scope",
        "codeql_corroboration",
    },
    SpecialistRole.EFFECT: {
        "role",
        "effect_category",
        "semantic_reason",
        "local_code_excerpt_refs",
        "unresolved_assumptions",
        "proposed_scope",
        "codeql_corroboration",
    },
    SpecialistRole.BRIDGE: {
        "source",
        "target",
        "relation_type",
        "exact_local_scope",
        "structural_facts",
        "optional_codeql_evidence",
        "unresolved_semantics",
        "minimality_explanation",
    },
}
_BRIDGE_RELATIONS = frozenset(
    {
        "WRAPPER_FLOW",
        "LIBRARY_FLOW",
        "FIELD_STATE",
        "FRAMEWORK_RELATION",
        "CALLBACK_RELATION",
    }
)


@dataclass(frozen=True, slots=True)
class SpecialistRuntimeFailure:
    failure_class: str
    message: str
    internal_round: int
    model_call_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "failure_class": self.failure_class,
            "message": self.message,
            "internal_round": self.internal_round,
            "model_call_id": self.model_call_id,
        }


@dataclass(frozen=True, slots=True)
class SpecialistRuntimeRun:
    result: SpecialistResult
    observations: tuple[SpecialistObservation, ...]
    model_responses: tuple[Mapping[str, Any], ...]
    failures: tuple[SpecialistRuntimeFailure, ...]


@dataclass(frozen=True, slots=True)
class _SpecialistDecision:
    action_type: str
    tool_name: str | None
    arguments: Mapping[str, Any]
    findings: tuple[Mapping[str, Any], ...]
    status: SpecialistResultStatus | None
    next_suggested_evidence: tuple[str, ...]
    uncertainty: tuple[str, ...]
    reason: str


def _strings(value: Any, name: str, *, required: bool = False) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise ValueError(f"{name} must be an array of strings")
    if any(not isinstance(item, str) for item in value):
        raise ValueError(f"{name} must contain only strings")
    result = tuple(item.strip() for item in value)
    if any(not item for item in result):
        raise ValueError(f"{name} contains an empty string")
    if required and not result:
        raise ValueError(f"{name} requires at least one value")
    if len(result) != len(set(result)):
        raise ValueError(f"{name} must not contain duplicates")
    return result


def _empty_tool_name(value: Any) -> bool:
    return value is None or value == ""


def _parse_decision(
    response: LLMResponse,
    *,
    task: SpecialistTaskSpec,
    normalizer: StructuredOutputNormalizer,
) -> _SpecialistDecision:
    value = dict(normalizer.normalize(response).normalized_object)
    if set(value) != _DECISION_KEYS:
        raise ValueError("specialist decision has an invalid key set")
    action_type = str(value["action_type"])
    if action_type not in {"TOOL", "SUBMIT_FINDINGS", "STOP"}:
        raise ValueError("specialist action_type must be TOOL, SUBMIT_FINDINGS, or STOP")
    if not isinstance(value["arguments"], Mapping):
        raise ValueError("specialist arguments must be an object")
    arguments = dict(value["arguments"])
    if not isinstance(value["findings"], Sequence) or isinstance(
        value["findings"], (str, bytes, bytearray)
    ):
        raise ValueError("specialist findings must be an array")
    if not isinstance(value["reason"], str) or not value["reason"].strip():
        raise ValueError("specialist reason is required")
    next_evidence = _strings(value["next_suggested_evidence"], "next_suggested_evidence")
    uncertainty = _strings(value["uncertainty"], "uncertainty")

    tool_name: str | None = None
    findings: tuple[Mapping[str, Any], ...] = ()
    status: SpecialistResultStatus | None = None
    if action_type == "TOOL":
        if not isinstance(value["tool_name"], str) or not value["tool_name"].strip():
            raise ValueError("TOOL requires tool_name")
        tool_name = value["tool_name"].strip()
        if tool_name not in task.allowed_tools:
            raise ValueError("specialist attempted a tool outside the TaskSpec allow-list")
        if tool_name not in ROLE_ALLOWED_TOOLS[task.specialist_agent]:
            raise ValueError("specialist attempted a tool outside its role allow-list")
        try:
            action = ActionType(tool_name)
        except ValueError as exc:
            raise ValueError("specialist requested an unknown tool") from exc
        if action not in TOOL_ACTIONS:
            raise ValueError("specialist requested a non-tool action")
        validate_tool_arguments(action, arguments)
        if (
            value["findings"]
            or value["status"] not in {None, ""}
            or next_evidence
            or uncertainty
        ):
            raise ValueError(
                "TOOL must not include findings, status, next_suggested_evidence, "
                "or uncertainty"
            )
    elif action_type == "SUBMIT_FINDINGS":
        if not _empty_tool_name(value["tool_name"]) or arguments:
            raise ValueError("SUBMIT_FINDINGS must not include a tool")
        if value["status"] != SpecialistResultStatus.FINDINGS.value:
            raise ValueError("SUBMIT_FINDINGS requires FINDINGS status")
        raw_findings = tuple(value["findings"])
        if not raw_findings or any(not isinstance(item, Mapping) for item in raw_findings):
            raise ValueError("SUBMIT_FINDINGS requires one non-empty finding batch")
        findings = tuple(dict(item) for item in raw_findings)
        status = SpecialistResultStatus.FINDINGS
    else:
        if not _empty_tool_name(value["tool_name"]) or arguments or value["findings"]:
            raise ValueError("STOP must not include a tool or findings")
        try:
            status = SpecialistResultStatus(value["status"])
        except (TypeError, ValueError) as exc:
            raise ValueError("STOP requires a supported non-FINDINGS status") from exc
        if status is SpecialistResultStatus.FINDINGS:
            raise ValueError("STOP cannot use FINDINGS status")
    return _SpecialistDecision(
        action_type=action_type,
        tool_name=tool_name,
        arguments=arguments,
        findings=findings,
        status=status,
        next_suggested_evidence=next_evidence,
        uncertainty=uncertainty,
        reason=value["reason"].strip(),
    )


def _stop_reason(status: SpecialistResultStatus) -> SpecialistStopReason:
    return {
        SpecialistResultStatus.FINDINGS: SpecialistStopReason.FINDING_BATCH_READY,
        SpecialistResultStatus.NEED_MORE_EVIDENCE: SpecialistStopReason.NEED_MORE_EVIDENCE,
        SpecialistResultStatus.NO_SUPPORTED_FINDING: SpecialistStopReason.NO_SUPPORTED_FINDING,
        SpecialistResultStatus.BUDGET_EXHAUSTED: SpecialistStopReason.BUDGET_EXHAUSTED,
        SpecialistResultStatus.TOOL_UNAVAILABLE: SpecialistStopReason.TOOL_UNAVAILABLE,
        SpecialistResultStatus.FAILED: SpecialistStopReason.ERROR,
    }[status]


def _pair(left: int, right: int) -> int:
    total = left + right
    return total * (total + 1) // 2 + right


def _action_round(task: SpecialistTaskSpec, internal_round: int) -> int:
    """Map dispatch coordinates to the positive M7 action-round namespace."""

    return _pair(_pair(task.coordinator_round, task.dispatch_index), internal_round) + 1


class SpecialistAgentRuntime:
    role: SpecialistRole

    def __init__(
        self,
        *,
        project_id: str,
        repository_index: RepositoryIndex,
        llm_client: LLMClient,
        tool_adapter: RepositoryCodeQLToolAdapter,
        normalizer: StructuredOutputNormalizer | None = None,
        usage_recorder: RuntimeUsageRecorder | None = None,
    ) -> None:
        if not project_id:
            raise ValueError("specialist runtime project_id is required")
        if tool_adapter.project_id != project_id:
            raise ValueError("specialist runtime and tool adapter are cross-project")
        if tool_adapter.index is not repository_index:
            raise ValueError("specialist runtime must share the adapter RepositoryIndex")
        self.project_id = project_id
        self.repository_index = repository_index
        self.llm_client = llm_client
        self.tool_adapter = tool_adapter
        self.normalizer = normalizer or StructuredOutputNormalizer()
        self.usage_recorder = usage_recorder
        config = getattr(llm_client, "config", None)
        configured_model = getattr(config, "model_id", None)
        if configured_model is None and not isinstance(llm_client, MockLLMClient):
            raise ValueError("non-Mock specialist LLM client must expose its exact model configuration")
        if configured_model is not None and configured_model != self.model_spec.model_id:
            raise ValueError("specialist LLM client model does not match the frozen role assignment")

    @property
    def model_spec(self) -> AgentModelSpec:
        return SPECIALIST_AGENT_REGISTRY[self.role]

    @property
    def system_prompt(self) -> str:
        return ROLE_PROMPTS[self.role]

    @property
    def allowed_tools(self) -> frozenset[str]:
        return ROLE_ALLOWED_TOOLS[self.role]

    def _validate_task(self, task: SpecialistTaskSpec) -> None:
        if task.project_id != self.project_id:
            raise ValueError("specialist TaskSpec is cross-project")
        if task.specialist_agent is not self.role:
            raise ValueError("specialist TaskSpec targets a different role")
        if not set(task.allowed_tools).issubset(self.allowed_tools):
            raise ValueError("TaskSpec grants a tool outside the specialist role allow-list")
        limits = task.remaining_specialist_budget
        if int(limits["max_internal_rounds"]) > MAX_INTERNAL_ROUNDS:
            raise ValueError("TaskSpec exceeds the specialist round ceiling")
        if int(limits["max_tool_calls"]) > MAX_TOOL_CALLS:
            raise ValueError("TaskSpec exceeds the specialist tool ceiling")
        if int(limits["max_finding_batches"]) > MAX_FINDING_BATCHES:
            raise ValueError("TaskSpec exceeds the specialist finding-batch ceiling")
        if self.role is SpecialistRole.BRIDGE:
            known_types = {str(item.get("finding_type")) for item in task.known_findings}
            if not {FindingType.INPUT.value, FindingType.EFFECT.value}.issubset(known_types):
                raise ValueError("Bridge Agent requires existing input and effect findings")

    def _complete_and_parse(
        self,
        *,
        task: SpecialistTaskSpec,
        request: LLMRequest,
        model_responses: list[Mapping[str, Any]],
    ) -> tuple[LLMResponse, _SpecialistDecision]:
        from java_vuln_research.work1_agent.m8_experiment.usage import (
            TerminalStatus,
            UsageActorKind,
        )

        attempt = (
            self.usage_recorder.reserve_model_attempt(
                client=self.llm_client,
                request=request,
                actor_kind=UsageActorKind.SPECIALIST,
                agent_id=self.model_spec.id,
                role=self.role.value,
                configured_model_id=self.model_spec.model_id,
            )
            if self.usage_recorder is not None
            else None
        )
        try:
            response = self.llm_client.complete(request)
        except ModelCallError as exc:
            if attempt is not None:
                self.usage_recorder.reconcile_model_attempt(
                    attempt,
                    status=self.usage_recorder.status_for_model_error(exc),
                    error=exc,
                )
            raise
        except Exception as exc:
            if attempt is not None:
                self.usage_recorder.reconcile_model_attempt(
                    attempt,
                    status=TerminalStatus.PROVIDER_ERROR,
                    error=exc,
                )
            raise

        model_responses.append(response.to_dict())
        try:
            decision = _parse_decision(response, task=task, normalizer=self.normalizer)
        except ModelCallError as exc:
            if attempt is not None:
                self.usage_recorder.reconcile_model_attempt(
                    attempt,
                    status=self.usage_recorder.status_for_model_error(exc),
                    response=response,
                )
            if exc.model_call_id is None:
                exc.model_call_id = response.model_call_id
            raise
        except (KeyError, TypeError, ValueError) as exc:
            if attempt is not None:
                self.usage_recorder.reconcile_model_attempt(
                    attempt,
                    status=TerminalStatus.INVALID_OUTPUT,
                    response=response,
                )
            exc.model_call_id = response.model_call_id
            raise
        except Exception:
            if attempt is not None:
                self.usage_recorder.reconcile_model_attempt(
                    attempt,
                    status=TerminalStatus.INVALID_OUTPUT,
                    response=response,
                )
            raise

        if attempt is not None:
            self.usage_recorder.reconcile_model_attempt(
                attempt,
                status=TerminalStatus.SUCCESS,
                response=response,
            )
        return response, decision

    def _execute_tool(self, action: AgentAction) -> AgentToolResult:
        from java_vuln_research.work1_agent.m8_experiment.usage import (
            TerminalStatus,
            UsageActionKind,
            UsageActorKind,
        )

        action_kind = (
            UsageActionKind.CODEQL_CALL
            if action.action_type.value.startswith("CODEQL_")
            else UsageActionKind.REPOSITORY_TOOL_CALL
        )
        attempt = (
            self.usage_recorder.reserve_action(
                action_kind=action_kind,
                actor_kind=UsageActorKind.SPECIALIST,
                agent_id=self.model_spec.id,
                role=self.role.value,
                action_name=action.action_type.value,
                identity=action.action_id,
                max_wall_clock_ms=120_000,
            )
            if self.usage_recorder is not None
            else None
        )
        try:
            result = self.tool_adapter.execute(action)
        except Exception:
            if attempt is not None:
                self.usage_recorder.reconcile_action(
                    attempt,
                    status=TerminalStatus.TOOL_ERROR,
                )
            raise
        if attempt is not None:
            self.usage_recorder.reconcile_action(
                attempt,
                status=(
                    TerminalStatus.TOOL_ERROR
                    if result.status is AgentToolStatus.ERROR
                    else TerminalStatus.SUCCESS
                ),
            )
        return result

    def _result(
        self,
        *,
        task: SpecialistTaskSpec,
        status: SpecialistResultStatus,
        rounds_used: int,
        tool_results: Sequence[AgentToolResult],
        evidence_refs: Sequence[EvidenceRef],
        findings: Sequence[SpecialistFinding] = (),
        next_suggested_evidence: Sequence[str] = (),
        uncertainty: Sequence[str] = (),
        extra_provenance: Mapping[str, Any] | None = None,
    ) -> SpecialistResult:
        return SpecialistResult.create(
            task_id=task.task_id,
            project_id=task.project_id,
            specialist_agent=self.role,
            status=status,
            findings=findings,
            evidence_refs=[item.to_dict() for item in evidence_refs],
            tool_calls=[item.to_dict() for item in tool_results],
            next_suggested_evidence=next_suggested_evidence,
            uncertainty=uncertainty,
            stop_reason=_stop_reason(status),
            rounds_used=rounds_used,
            provenance={
                "producer": SPECIALIST_RUNTIME_VERSION,
                "specialist_agent": self.model_spec.id,
                "task_id": task.task_id,
                "exact_model_id": self.model_spec.model_id,
                "benchmark_informed": False,
                **dict(extra_provenance or {}),
            },
        )

    def _finding(
        self,
        *,
        task: SpecialistTaskSpec,
        raw: Mapping[str, Any],
        internal_round: int,
        response: LLMResponse,
        tool_results: Sequence[AgentToolResult],
        evidence_refs: Sequence[EvidenceRef],
    ) -> SpecialistFinding:
        if set(raw) != _FINDING_KEYS:
            raise ValueError("specialist finding draft has an invalid key set")
        entity_ids = _strings(raw["entity_ids"], "entity_ids", required=True)
        tool_call_ids = _strings(raw["tool_call_ids"], "tool_call_ids", required=True)
        evidence_ids = _strings(raw["evidence_refs"], "evidence_refs", required=True)
        if not isinstance(raw["summary"], str) or not raw["summary"].strip():
            raise ValueError("specialist finding summary is required")
        if not isinstance(raw["details"], Mapping):
            raise ValueError("specialist finding details must be an object")
        details = dict(raw["details"])
        missing_details = _ROLE_DETAIL_KEYS[self.role] - set(details)
        if missing_details:
            raise ValueError(
                "specialist finding is missing role details: " + ",".join(sorted(missing_details))
            )
        if self.role is SpecialistRole.BRIDGE and details["relation_type"] not in _BRIDGE_RELATIONS:
            raise ValueError("Bridge Agent emitted an unsupported relation type")
        uncertainties = _strings(raw["uncertainties"], "uncertainties")

        known_entities = {item.entity_id for item in self.repository_index.entities}
        if not set(entity_ids).issubset(known_entities):
            raise ValueError("specialist finding references an unknown project entity")
        if self.role is SpecialistRole.BRIDGE:
            for name in ("source", "target"):
                role_ref = details[name]
                if not isinstance(role_ref, Mapping):
                    raise ValueError(f"Bridge Agent {name} must be an entity role object")
                if set(role_ref) - {"entity_id", "role", "index"}:
                    raise ValueError(f"Bridge Agent {name} role object has unsupported fields")
                if role_ref.get("entity_id") not in entity_ids:
                    raise ValueError(f"Bridge Agent {name} references an ungrounded entity")
                if not isinstance(role_ref.get("role"), str) or not role_ref["role"].strip():
                    raise ValueError(f"Bridge Agent {name} requires a role")
                index = role_ref.get("index")
                if index is not None and (isinstance(index, bool) or not isinstance(index, int) or index < 0):
                    raise ValueError(f"Bridge Agent {name} index must be a non-negative integer")
        tools = {item.tool_call_id: item for item in tool_results}
        evidence = {item.evidence_id: item for item in evidence_refs}
        if not set(tool_call_ids).issubset(tools):
            raise ValueError("specialist finding references an unknown dispatch tool call")
        if not set(evidence_ids).issubset(evidence):
            raise ValueError("specialist finding references unknown dispatch evidence")
        cited_evidence = [evidence[item] for item in evidence_ids]
        if not set(entity_ids).issubset(
            {entity_id for item in cited_evidence for entity_id in item.entity_ids}
        ):
            raise ValueError("specialist finding entities are not grounded by cited evidence")
        if not {item.tool_call_id for item in cited_evidence}.issubset(tool_call_ids):
            raise ValueError("specialist finding evidence is not grounded by cited tool calls")
        return SpecialistFinding.create(
            project_id=task.project_id,
            specialist_agent=self.role,
            finding_type=ROLE_FINDING_TYPES[self.role],
            round=internal_round,
            entity_ids=entity_ids,
            tool_call_ids=tool_call_ids,
            evidence_refs=evidence_ids,
            summary=raw["summary"].strip(),
            details=details,
            uncertainties=uncertainties,
            provenance={
                "producer": SPECIALIST_RUNTIME_VERSION,
                "specialist_agent": self.model_spec.id,
                "task_id": task.task_id,
                "model_call_id": response.model_call_id,
                "provider": response.provider,
                "response_model_id": response.model_id,
                "configured_model_id": self.model_spec.model_id,
                "benchmark_informed": False,
            },
        )

    def run(self, task: SpecialistTaskSpec) -> SpecialistRuntimeRun:
        from java_vuln_research.work1_agent.m8_experiment.usage import UsageLedgerError

        self._validate_task(task)
        observations: list[SpecialistObservation] = []
        model_responses: list[Mapping[str, Any]] = []
        failures: list[SpecialistRuntimeFailure] = []
        tool_results: list[AgentToolResult] = []
        evidence_refs: list[EvidenceRef] = []
        previous: SpecialistObservation | None = None
        max_rounds = int(task.remaining_specialist_budget["max_internal_rounds"])
        max_tools = int(task.remaining_specialist_budget["max_tool_calls"])
        finding_batches = int(task.remaining_specialist_budget["max_finding_batches"])
        if max_rounds == 0:
            result = self._result(
                task=task,
                status=SpecialistResultStatus.BUDGET_EXHAUSTED,
                rounds_used=0,
                tool_results=(),
                evidence_refs=(),
            )
            return SpecialistRuntimeRun(result, (), (), ())

        for internal_round in range(1, max_rounds + 1):
            observation = build_specialist_observation(
                task=task,
                repository_index=self.repository_index,
                internal_round=internal_round,
                tool_results=tool_results,
                evidence_refs=evidence_refs,
                previous_observation=previous,
            )
            observations.append(observation)
            previous = observation
            request = LLMRequest.create(
                project_id=task.project_id,
                round=internal_round,
                system_prompt=self.system_prompt,
                observation=observation.to_dict(),
            )
            try:
                response, decision = self._complete_and_parse(
                    task=task,
                    request=request,
                    model_responses=model_responses,
                )
            except UsageLedgerError as exc:
                failure = SpecialistRuntimeFailure(
                    failure_class="BUDGET_EXHAUSTED",
                    message=str(exc),
                    internal_round=internal_round,
                )
                failures.append(failure)
                result = self._result(
                    task=task,
                    status=SpecialistResultStatus.BUDGET_EXHAUSTED,
                    rounds_used=internal_round,
                    tool_results=tool_results,
                    evidence_refs=evidence_refs,
                    uncertainty=(str(exc),),
                    extra_provenance={"failure": failure.to_dict()},
                )
                return SpecialistRuntimeRun(
                    result, tuple(observations), tuple(model_responses), tuple(failures)
                )
            except ModelCallError as exc:
                failure = SpecialistRuntimeFailure(
                    failure_class=exc.failure_class.value,
                    message=str(exc),
                    internal_round=internal_round,
                    model_call_id=exc.model_call_id,
                )
                failures.append(failure)
                result = self._result(
                    task=task,
                    status=SpecialistResultStatus.FAILED,
                    rounds_used=internal_round,
                    tool_results=tool_results,
                    evidence_refs=evidence_refs,
                    uncertainty=(str(exc),),
                    extra_provenance={"failure": failure.to_dict()},
                )
                return SpecialistRuntimeRun(
                    result, tuple(observations), tuple(model_responses), tuple(failures)
                )
            except (KeyError, TypeError, ValueError) as exc:
                failure = SpecialistRuntimeFailure(
                    failure_class="MODEL_OUTPUT_INVALID",
                    message=str(exc),
                    internal_round=internal_round,
                    model_call_id=getattr(exc, "model_call_id", None),
                )
                failures.append(failure)
                result = self._result(
                    task=task,
                    status=SpecialistResultStatus.FAILED,
                    rounds_used=internal_round,
                    tool_results=tool_results,
                    evidence_refs=evidence_refs,
                    uncertainty=(str(exc),),
                    extra_provenance={"failure": failure.to_dict()},
                )
                return SpecialistRuntimeRun(
                    result, tuple(observations), tuple(model_responses), tuple(failures)
                )

            if decision.action_type == "TOOL":
                if len(tool_results) >= max_tools:
                    result = self._result(
                        task=task,
                        status=SpecialistResultStatus.BUDGET_EXHAUSTED,
                        rounds_used=internal_round,
                        tool_results=tool_results,
                        evidence_refs=evidence_refs,
                        next_suggested_evidence=decision.next_suggested_evidence,
                        uncertainty=decision.uncertainty,
                    )
                    return SpecialistRuntimeRun(
                        result, tuple(observations), tuple(model_responses), tuple(failures)
                    )
                action = AgentAction.create(
                    project_id=task.project_id,
                    round=_action_round(task, internal_round),
                    action_type=decision.tool_name,
                    arguments=decision.arguments,
                    reason=decision.reason,
                    provenance={
                        "producer": SPECIALIST_RUNTIME_VERSION,
                        "specialist_agent": self.model_spec.id,
                        "task_id": task.task_id,
                        "model_call_id": response.model_call_id,
                        "benchmark_informed": False,
                    },
                )
                try:
                    tool_result = self._execute_tool(action)
                except UsageLedgerError as exc:
                    failure = SpecialistRuntimeFailure(
                        failure_class="BUDGET_EXHAUSTED",
                        message=str(exc),
                        internal_round=internal_round,
                        model_call_id=response.model_call_id,
                    )
                    failures.append(failure)
                    result = self._result(
                        task=task,
                        status=SpecialistResultStatus.BUDGET_EXHAUSTED,
                        rounds_used=internal_round,
                        tool_results=tool_results,
                        evidence_refs=evidence_refs,
                        uncertainty=(str(exc),),
                        extra_provenance={"failure": failure.to_dict()},
                    )
                    return SpecialistRuntimeRun(
                        result,
                        tuple(observations),
                        tuple(model_responses),
                        tuple(failures),
                    )
                tool_results.append(tool_result)
                evidence_refs.extend(evidence_from_tool_result(tool_result, self.repository_index))
                continue

            if decision.action_type == "SUBMIT_FINDINGS":
                if finding_batches < 1:
                    result = self._result(
                        task=task,
                        status=SpecialistResultStatus.BUDGET_EXHAUSTED,
                        rounds_used=internal_round,
                        tool_results=tool_results,
                        evidence_refs=evidence_refs,
                    )
                    return SpecialistRuntimeRun(
                        result, tuple(observations), tuple(model_responses), tuple(failures)
                    )
                try:
                    findings = tuple(
                        self._finding(
                            task=task,
                            raw=item,
                            internal_round=internal_round,
                            response=response,
                            tool_results=tool_results,
                            evidence_refs=evidence_refs,
                        )
                        for item in decision.findings
                    )
                except (KeyError, TypeError, ValueError) as exc:
                    failure = SpecialistRuntimeFailure(
                        failure_class="MODEL_OUTPUT_INVALID",
                        message=str(exc),
                        internal_round=internal_round,
                        model_call_id=response.model_call_id,
                    )
                    failures.append(failure)
                    result = self._result(
                        task=task,
                        status=SpecialistResultStatus.FAILED,
                        rounds_used=internal_round,
                        tool_results=tool_results,
                        evidence_refs=evidence_refs,
                        uncertainty=(str(exc),),
                        extra_provenance={"failure": failure.to_dict()},
                    )
                else:
                    result = self._result(
                        task=task,
                        status=SpecialistResultStatus.FINDINGS,
                        rounds_used=internal_round,
                        tool_results=tool_results,
                        evidence_refs=evidence_refs,
                        findings=findings,
                        next_suggested_evidence=decision.next_suggested_evidence,
                        uncertainty=decision.uncertainty,
                    )
                return SpecialistRuntimeRun(
                    result, tuple(observations), tuple(model_responses), tuple(failures)
                )

            assert decision.status is not None
            result = self._result(
                task=task,
                status=decision.status,
                rounds_used=internal_round,
                tool_results=tool_results,
                evidence_refs=evidence_refs,
                next_suggested_evidence=decision.next_suggested_evidence,
                uncertainty=decision.uncertainty,
            )
            return SpecialistRuntimeRun(
                result, tuple(observations), tuple(model_responses), tuple(failures)
            )

        result = self._result(
            task=task,
            status=SpecialistResultStatus.BUDGET_EXHAUSTED,
            rounds_used=max_rounds,
            tool_results=tool_results,
            evidence_refs=evidence_refs,
        )
        return SpecialistRuntimeRun(
            result, tuple(observations), tuple(model_responses), tuple(failures)
        )


class InputAgentRuntime(SpecialistAgentRuntime):
    role = SpecialistRole.INPUT


class EffectAgentRuntime(SpecialistAgentRuntime):
    role = SpecialistRole.EFFECT


class BridgeAgentRuntime(SpecialistAgentRuntime):
    role = SpecialistRole.BRIDGE
