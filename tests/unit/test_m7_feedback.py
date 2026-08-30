from __future__ import annotations

from pathlib import Path

from java_vuln_research.work1_agent.agent import (
    ActionType,
    AgentController,
    AgentToolResult,
    AgentToolStatus,
    AgentState,
    LLMRequest,
    LLMResponse,
    RepositoryCodeQLToolAdapter,
    RuntimeSecurityBoundary,
    StopReason,
    StrictActionParser,
    TraceEventType,
    evidence_from_tool_result,
    runtime_roots,
)
from java_vuln_research.work1_agent.proposal import (
    EntityRole,
    EntityRoleRef,
    EvidenceGate,
    GateStatus,
    ProposalScope,
    ProposalType,
    ScopeKind,
    SecurityProposal,
)
from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest
from java_vuln_research.work1_agent.repository.entity import ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import build_repository_index


FIXTURE = Path(__file__).parents[1] / "fixtures" / "work1_agent_m4"


def _decision(action_type: ActionType, *, arguments: dict[str, object] | None = None, proposal: SecurityProposal | None = None, stop_reason: StopReason | None = None) -> dict[str, object]:
    return {
        "action_type": action_type.value,
        "arguments": arguments or {},
        "proposal": proposal.to_dict() if proposal else None,
        "stop_reason": stop_reason.value if stop_reason else None,
        "reason": "Use only current project evidence.",
    }


def _external_input(entity_id: str, evidence_refs: tuple[str, ...]) -> SecurityProposal:
    return SecurityProposal.create(
        proposal_type=ProposalType.EXTERNAL_INPUT,
        subject=EntityRoleRef(entity_id, EntityRole.RETURN),
        scope=ProposalScope(ScopeKind.ENTITY, (entity_id,), "P"),
        semantic_category="UNKNOWN",
        evidence_refs=evidence_refs,
        reason="Bounded candidate input anchor; not a vulnerability conclusion.",
        provenance={"producer": "adaptive-test", "benchmark_informed": False},
    )


class _AdaptiveGateClient:
    def __init__(self, entity_id: str) -> None:
        self.entity_id = entity_id
        self.requests: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        step = len(self.requests)
        if step == 1:
            decision = _decision(ActionType.PROPOSE, proposal=_external_input(self.entity_id, ()))
        elif step == 2:
            decision = _decision(ActionType.INSPECT_METHOD, arguments={"entity_id": self.entity_id})
        elif step == 3:
            feedback = request.observation["recent_feedback"]
            evidence_id = next(
                item["evidence_refs"][0]["evidence_id"]
                for item in reversed(feedback)
                if item.get("evidence_refs")
            )
            decision = _decision(ActionType.PROPOSE, proposal=_external_input(self.entity_id, (evidence_id,)))
        else:
            decision = _decision(ActionType.STOP, stop_reason=StopReason.INSUFFICIENT_EVIDENCE)
        return LLMResponse(
            model_call_id=stable_digest("modelcall", {"request": request.request_id, "step": step}),
            request_id=request.request_id,
            provider="adaptive-test",
            model_id="adaptive-gate-v1",
            raw_text=canonical_json(decision),
            wall_clock_seconds=0.0,
            provenance={"deterministic": True},
        )


def _controller(tmp_path: Path) -> tuple[AgentController, str]:
    index = build_repository_index(FIXTURE)
    method = next(
        item
        for item in index.entities
        if item.kind is ProgramEntityKind.METHOD and item.simple_name == "customExternalInput"
    )
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    schema_root = Path(__file__).resolve().parents[2] / "schemas"
    boundary = RuntimeSecurityBoundary(
        project_id="P",
        repository_identity="controlled@abc",
        allowed_roots=runtime_roots(
            source_roots=[FIXTURE],
            artifact_roots=[artifacts],
            schema_roots=[schema_root],
        ),
    )
    adapter = RepositoryCodeQLToolAdapter(
        project_id="P",
        repository_index=index,
        security_boundary=boundary,
        codeql_ready=False,
    )
    gate = EvidenceGate(repository_root=FIXTURE, entities=index.entities, evidence_catalog={})
    controller = AgentController(
        state=AgentState.create(
            project_id="P",
            repository_identity="controlled@abc",
            provenance={"producer": "test", "benchmark_informed": False},
        ),
        repository_index=index,
        codeql_status={"project_id": "P", "ready": False, "status": "UNAVAILABLE"},
        llm_client=_AdaptiveGateClient(method.entity_id),
        parser=StrictActionParser(schema_root),
        tool_adapter=adapter,
        evidence_gate=gate,
    )
    return controller, method.entity_id


def test_needs_more_feedback_drives_tool_then_same_proposal_can_be_admitted(tmp_path: Path) -> None:
    controller, method_id = _controller(tmp_path)

    result = controller.run()

    assert [item.status for item in result.gate_results] == [GateStatus.NEEDS_MORE_EVIDENCE, GateStatus.ADMISSIBLE]
    assert result.gate_results[0].proposal_id == result.gate_results[1].proposal_id
    assert result.state.budget.proposals_total == 2
    assert result.state.budget.admissible_proposals == 1
    assert len(result.state.evidence_refs) >= 1
    assert method_id in result.state.inspected_entity_ids
    assert result.gate_feedback[0].payload["unresolved_semantics"] == ["NO_PROGRAM_EVIDENCE"]
    assert result.gate_feedback[1].payload["active_proposal_count"] == 1
    assert result.gate_feedback[1].payload["graph_update_enabled"] is False
    assert result.gate_feedback[1].payload["candidate_path_count_after"] == 0
    assert any(item.event_type is TraceEventType.EVIDENCE for item in result.trace.events)
    assert sum(item.event_type is TraceEventType.GATE_RESULT for item in result.trace.events) == 2


def test_rejected_feedback_never_activates_proposal_or_graph(tmp_path: Path) -> None:
    controller, _ = _controller(tmp_path)
    field = next(item for item in controller.repository_index.entities if item.kind is ProgramEntityKind.FIELD)
    rejected = SecurityProposal.create(
        proposal_type=ProposalType.EXTERNAL_INPUT,
        subject=EntityRoleRef(field.entity_id, EntityRole.RETURN),
        scope=ProposalScope(ScopeKind.ENTITY, (field.entity_id,), "P"),
        semantic_category="UNKNOWN",
        evidence_refs=(),
        reason="Deliberately incompatible role for Gate test.",
        provenance={"producer": "test", "benchmark_informed": False},
    )

    class RejectedThenStop:
        def __init__(self) -> None:
            self.calls = 0

        def complete(self, request: LLMRequest) -> LLMResponse:
            self.calls += 1
            decision = _decision(ActionType.PROPOSE, proposal=rejected) if self.calls == 1 else _decision(ActionType.STOP, stop_reason=StopReason.INSUFFICIENT_EVIDENCE)
            return LLMResponse(
                model_call_id=stable_digest("modelcall", {"request": request.request_id}),
                request_id=request.request_id,
                provider="test",
                model_id="reject-v1",
                raw_text=canonical_json(decision),
                wall_clock_seconds=0.0,
            )

    controller.llm_client = RejectedThenStop()
    result = controller.run()

    assert result.gate_results[0].status is GateStatus.REJECTED
    assert result.gate_feedback[0].payload["active_proposal_count"] == 0
    assert result.gate_feedback[0].payload["new_path_ids"] == []
    assert result.state.budget.admissible_proposals == 0
    assert result.state.active_candidate_path_ids == set()


def test_only_successful_fixed_codeql_results_become_direct_codeql_evidence(tmp_path: Path) -> None:
    controller, method_id = _controller(tmp_path)
    result = AgentToolResult(
        tool_call_id="agenttool-000000000000000000000000",
        project_id="P",
        action_id="action-000000000000000000000000",
        tool_name=ActionType.CODEQL_LOCAL_FLOW.value,
        status=AgentToolStatus.OK,
        items=({"nodes": [{"entity_id": method_id}], "provenance": {"fixed_query": True}},),
        truncated=False,
        warnings=(),
        failure=None,
        provenance={"bounded": True},
    )
    evidence = evidence_from_tool_result(result, controller.repository_index)
    assert len(evidence) == 1
    assert evidence[0].source_kind.value == "CODEQL_LOCAL_FLOW"
    assert evidence[0].confidence.value == "DIRECT"
    assert evidence[0].tool_call_id == result.tool_call_id

    unavailable = AgentToolResult(
        tool_call_id="agenttool-111111111111111111111111",
        project_id="P",
        action_id="action-111111111111111111111111",
        tool_name=ActionType.CODEQL_LOCAL_FLOW.value,
        status=AgentToolStatus.UNAVAILABLE,
        items=(),
        truncated=False,
        warnings=("UNAVAILABLE_IS_NOT_NEGATIVE_EVIDENCE",),
        failure={"reason": "CODEQL_UNAVAILABLE"},
        provenance={"bounded": True},
    )
    assert evidence_from_tool_result(unavailable, controller.repository_index) == ()
