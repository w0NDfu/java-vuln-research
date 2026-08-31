from __future__ import annotations

from pathlib import Path

from java_vuln_research.work1_agent.agent import (
    ActionType,
    AgentBudgetLimits,
    AgentController,
    AgentState,
    ModelCallError,
    ModelFailureClass,
    MockLLMClient,
    PROJECT_ARTIFACT_FILES,
    RepositoryCodeQLToolAdapter,
    RuntimeSecurityBoundary,
    StopReason,
    StrictActionParser,
    TraceEventType,
    runtime_roots,
    write_controller_artifacts,
)
from java_vuln_research.work1_agent.repository.entity import ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import build_repository_index


SOURCE = """package demo;
class Sample {
  void run() { helper(); }
  void helper() {}
}
"""


def _decision(action_type: ActionType, *, arguments: dict[str, object] | None = None, stop_reason: StopReason | None = None) -> dict[str, object]:
    return {
        "action_type": action_type.value,
        "arguments": arguments or {},
        "proposal": None,
        "stop_reason": stop_reason.value if stop_reason else None,
        "reason": "Collect one bounded repository fact.",
    }


def _controller(tmp_path: Path, responses: list[object], *, limits: AgentBudgetLimits | None = None) -> tuple[AgentController, MockLLMClient]:
    source_root = tmp_path / "repo"
    source = source_root / "src" / "Sample.java"
    source.parent.mkdir(parents=True)
    source.write_text(SOURCE, encoding="utf-8")
    index = build_repository_index(source_root)
    artifact_root = tmp_path / "artifacts"
    artifact_root.mkdir()
    schema_root = Path(__file__).resolve().parents[2] / "schemas"
    boundary = RuntimeSecurityBoundary(
        project_id="P",
        repository_identity="repo@abc",
        allowed_roots=runtime_roots(
            source_roots=[source_root],
            artifact_roots=[artifact_root],
            schema_roots=[schema_root],
        ),
    )
    adapter = RepositoryCodeQLToolAdapter(
        project_id="P",
        repository_index=index,
        security_boundary=boundary,
        codeql_ready=False,
    )
    client = MockLLMClient(responses)
    controller = AgentController(
        state=AgentState.create(
            project_id="P",
            repository_identity="repo@abc",
            provenance={"producer": "test", "benchmark_informed": False},
            limits=limits,
        ),
        repository_index=index,
        codeql_status={"project_id": "P", "ready": False, "status": "UNAVAILABLE"},
        llm_client=client,
        parser=StrictActionParser(schema_root),
        tool_adapter=adapter,
    )
    return controller, client


def test_controller_runs_tool_observation_loop_then_stops(tmp_path: Path) -> None:
    controller, client = _controller(tmp_path, [])
    method = next(
        item
        for item in controller.repository_index.entities
        if item.kind is ProgramEntityKind.METHOD and item.simple_name == "run"
    )
    client._responses.extend(
        [
            _decision(ActionType.SEARCH_CODE, arguments={"query": "helper", "max_hits": 10}),
            _decision(ActionType.INSPECT_METHOD, arguments={"entity_id": method.entity_id}),
            _decision(ActionType.STOP, stop_reason=StopReason.INSUFFICIENT_EVIDENCE),
        ]
    )

    result = controller.run()

    assert result.state.stop_reason is StopReason.INSUFFICIENT_EVIDENCE
    assert len(result.observations) == 3
    assert len(result.tool_results) == 2
    assert len(client.requests) == 3
    assert result.observations[1].payload["recent_feedback"][0]["tool_name"] == "SEARCH_CODE"
    assert result.observations[2].payload["recent_feedback"][-1]["tool_name"] == "INSPECT_METHOD"
    assert result.state.budget.tool_calls_total == 2
    assert result.state.budget.model_calls == 3
    assert method.entity_id in result.state.inspected_entity_ids
    assert [event.sequence for event in result.trace.events] == list(range(1, len(result.trace.events) + 1))
    assert result.trace.events[0].event_type is TraceEventType.INITIAL_OBSERVATION
    assert result.trace.events[-1].event_type is TraceEventType.STOP
    assert result.summary()["proposal_handling_enabled"] is False


def test_controller_records_model_failure_and_stops_fail_closed(tmp_path: Path) -> None:
    controller, client = _controller(tmp_path, ["not-json", "still-not-json"])

    result = controller.run()

    assert result.state.stop_reason is StopReason.OTHER
    assert result.failures[0].failure_class == "STRUCTURED_OUTPUT_UNSUPPORTED"
    assert [item.event_type for item in result.trace.events][-2:] == [TraceEventType.FAILURE, TraceEventType.STOP]
    assert result.state.budget.model_calls == 2
    assert [request.attempt for request in client.requests] == [1, 2]
    assert any(item.event_type is TraceEventType.MODEL_RETRY for item in result.trace.events)


def test_controller_repairs_one_invalid_model_output_without_relaxing_parser(tmp_path: Path) -> None:
    controller, client = _controller(
        tmp_path,
        [
            "```json\n{}\n```",
            _decision(ActionType.SEARCH_CODE, arguments={"query": "helper"}),
            _decision(ActionType.STOP, stop_reason=StopReason.INSUFFICIENT_EVIDENCE),
        ],
    )

    result = controller.run()

    assert result.state.stop_reason is StopReason.INSUFFICIENT_EVIDENCE
    assert result.failures == ()
    assert result.state.budget.model_calls == 3
    assert [request.attempt for request in client.requests] == [1, 2, 1]
    repair = next(item for item in result.trace.events if item.event_type is TraceEventType.MODEL_RETRY)
    assert repair.payload["failure_class"] == "SCHEMA_VIOLATION"
    assert repair.payload["retry_kind"] == "OUTPUT_REPAIR"
    assert "model_output_repair" in client.requests[1].observation


def test_controller_retries_one_retryable_transport_failure_without_output_repair(tmp_path: Path) -> None:
    controller, client = _controller(
        tmp_path,
        [
            ModelCallError(ModelFailureClass.MODEL_TIMEOUT, "transient", retryable=True),
            _decision(ActionType.SEARCH_CODE, arguments={"query": "helper"}),
            _decision(ActionType.STOP, stop_reason=StopReason.INSUFFICIENT_EVIDENCE),
        ],
    )

    result = controller.run()

    assert result.state.stop_reason is StopReason.INSUFFICIENT_EVIDENCE
    assert result.failures == ()
    assert [request.attempt for request in client.requests] == [1, 2, 1]
    assert client.requests[0].observation == client.requests[1].observation
    assert "model_output_repair" not in client.requests[1].observation
    retry = next(item for item in result.trace.events if item.event_type is TraceEventType.MODEL_RETRY)
    assert retry.payload["failure_class"] == "MODEL_TIMEOUT"
    assert retry.payload["retry_kind"] == "TRANSIENT_TRANSPORT"
    assert retry.payload["retryable"] is True


def test_round_one_non_discovery_action_returns_structured_controller_feedback(tmp_path: Path) -> None:
    controller, client = _controller(
        tmp_path,
        [
            _decision(ActionType.READ_FILE_RANGE, arguments={"path": "src/main/java/p/A.java", "start_line": 1, "end_line": 2}),
            _decision(ActionType.SEARCH_SYMBOLS, arguments={"query": "helper"}),
            _decision(ActionType.STOP, stop_reason=StopReason.INSUFFICIENT_EVIDENCE),
        ],
    )

    result = controller.run()

    feedback = next(item for item in result.trace.events if item.event_type is TraceEventType.CONTROLLER_FEEDBACK)
    assert feedback.payload["failure_class"] == "ROUND1_DISCOVERY_ACTION_REQUIRED"
    assert feedback.payload["phase"] == "DISCOVERY"
    assert result.state.budget.tool_calls_total == 1
    assert client.requests[1].observation["recent_feedback"][0]["failure_class"] == "ROUND1_DISCOVERY_ACTION_REQUIRED"
    assert {event.payload["phase"] for event in result.trace.events} >= {"DISCOVERY", "INSPECTION"}


def test_controller_enforces_round_budget_without_needing_an_extra_model_response(tmp_path: Path) -> None:
    controller, client = _controller(
        tmp_path,
        [_decision(ActionType.SEARCH_CODE, arguments={"query": "helper"})],
        limits=AgentBudgetLimits(max_rounds_per_project=1),
    )

    result = controller.run()

    assert result.state.stop_reason is StopReason.BUDGET_EXHAUSTED
    assert result.state.budget.tool_calls_total == 1
    assert len(client.requests) == 1
    assert any(item.event_type is TraceEventType.BUDGET and "exhausted" in item.payload for item in result.trace.events)


class _ProposalParser:
    def parse(self, response: object, **kwargs: object):
        from java_vuln_research.work1_agent.agent import AgentAction
        from java_vuln_research.work1_agent.proposal import (
            EntityRole,
            EntityRoleRef,
            ProposalScope,
            ScopeKind,
            SecurityProposal,
        )

        entity_id = next(iter(kwargs["known_entity_ids"]))
        proposal = SecurityProposal.create(
            proposal_type="EXTERNAL_INPUT",
            subject=EntityRoleRef(entity_id=entity_id, role=EntityRole.RETURN),
            scope=ProposalScope(kind=ScopeKind.CALLABLE, project_id="P", entity_ids=(entity_id,)),
            evidence_refs=(),
            reason="Controller boundary test.",
            provenance={"producer": "test", "benchmark_informed": False},
        )
        return AgentAction.create(
            project_id="P",
            round=kwargs["round"],
            action_type=ActionType.PROPOSE,
            proposal=proposal,
            reason="Boundary test.",
            provenance={"producer": "test"},
        )


def test_m7_5_controller_rejects_even_a_valid_proposal_action(tmp_path: Path) -> None:
    controller, _ = _controller(tmp_path, [_decision(ActionType.STOP, stop_reason=StopReason.OTHER)])
    controller.parser = _ProposalParser()

    result = controller.run()

    assert result.state.proposal_ids == []
    assert result.state.budget.proposals_total == 0
    assert result.failures[0].failure_class == "PROPOSAL_DISABLED_M7_5"


def test_controller_rejects_cross_project_components(tmp_path: Path) -> None:
    controller, _ = _controller(tmp_path, [_decision(ActionType.STOP, stop_reason=StopReason.OTHER)])
    controller.tool_adapter.project_id = "OTHER"
    try:
        AgentController(
            state=controller.state,
            repository_index=controller.repository_index,
            codeql_status={"project_id": "P"},
            llm_client=controller.llm_client,
            parser=controller.parser,
            tool_adapter=controller.tool_adapter,
        )
    except ValueError as error:
        assert "cross-project" in str(error)
    else:
        raise AssertionError("cross-project controller components must be rejected")


def test_controller_stops_after_frozen_stagnation_threshold(tmp_path: Path) -> None:
    controller, client = _controller(
        tmp_path,
        [
            _decision(ActionType.SEARCH_CODE, arguments={"query": "definitely-absent-1"}),
            _decision(ActionType.SEARCH_CODE, arguments={"query": "definitely-absent-2"}),
            _decision(ActionType.SEARCH_CODE, arguments={"query": "definitely-absent-3"}),
        ],
    )

    result = controller.run()

    assert result.state.stop_reason is StopReason.NO_FURTHER_ACTION
    assert len(client.requests) == 3
    assert result.state.budget.tool_calls_total == 3
    assert result.trace.events[-1].payload["details"] == {"stagnant_rounds": 3, "threshold": 3}


def test_runtime_writes_complete_artifacts_even_for_model_failure(tmp_path: Path) -> None:
    controller, _ = _controller(tmp_path, ["not-json", "still-not-json"])
    result = controller.run()
    output = tmp_path / "run"

    audit = write_controller_artifacts(
        result,
        output,
        run_manifest={"git_sha": "TEST", "system_prompt_sha256": "0" * 64},
        input_manifest={"no_leakage_pass": True, "entries": []},
    )

    assert audit["required_files_present"] is True
    assert all((output / name).is_file() for name in PROJECT_ARTIFACT_FILES)
    assert (output / "artifact_audit.json").is_file()
    assert "STRUCTURED_OUTPUT_UNSUPPORTED" in (output / "manifest.json").read_text(encoding="utf-8")
