from __future__ import annotations

import pytest

from java_vuln_research.work1_agent.agent.llm_client import (
    LLMRequest,
    MockLLMClient,
    ModelCallError,
    ModelFailureClass,
)
from java_vuln_research.work1_agent.m8_experiment import (
    ProjectBudgetCeilings,
    ProjectUsageLedger,
    RunKey,
    RuntimeUsageRecorder,
    TerminalStatus,
    UsageActionKind,
    UsageActorKind,
)


def _ledger() -> ProjectUsageLedger:
    return ProjectUsageLedger(
        RunKey(
            study_id="runtime-usage-test",
            split="dev-tune",
            subject_id="subject-1",
            arm_id="m8_m2",
            replicate_index=1,
            run_id="runtime-usage-test-run",
        ),
        ProjectBudgetCeilings(
            max_model_attempts=8,
            max_canonical_input_tokens=10_000,
            max_reserved_output_tokens=20_000,
            max_repository_tool_calls=8,
            max_codeql_calls=8,
            max_proposal_families=8,
            max_admissible_proposals=8,
            max_candidate_paths=8,
            max_wall_clock_ms=1_000_000,
        ),
    )


def _request(round_number: int = 1) -> LLMRequest:
    return LLMRequest.create(
        project_id="subject-1",
        round=round_number,
        system_prompt="Return one strict JSON decision.",
        observation={"round": round_number, "facts": ["bounded"]},
    )


def _recorder(ledger: ProjectUsageLedger) -> RuntimeUsageRecorder:
    return RuntimeUsageRecorder(ledger, tool_catalog_sha256="a" * 64)


def test_runtime_recorder_reconciles_success_and_invalid_output_with_response_usage() -> (
    None
):
    ledger = _ledger()
    recorder = _recorder(ledger)
    client = MockLLMClient([{"decision": "ok"}, {"decision": "invalid"}])

    success = recorder.reserve_model_attempt(
        client=client,
        request=_request(1),
        actor_kind=UsageActorKind.COORDINATOR,
        agent_id="coordinator_agent",
        role="coordinator",
        configured_model_id="claude-opus-5",
    )
    success_response = client.complete(_request(1))
    recorder.reconcile_model_attempt(
        success,
        status=TerminalStatus.SUCCESS,
        response=success_response,
    )

    invalid = recorder.reserve_model_attempt(
        client=client,
        request=_request(2),
        actor_kind=UsageActorKind.SPECIALIST,
        agent_id="input_agent",
        role="input",
        configured_model_id="claude-sonnet-5",
    )
    invalid_response = client.complete(_request(2))
    recorder.reconcile_model_attempt(
        invalid,
        status=TerminalStatus.INVALID_OUTPUT,
        response=invalid_response,
    )

    summary = ledger.summary()
    assert summary["terminal_status_counts"] == {
        "invalid-output": 1,
        "success": 1,
    }
    assert summary["model_attempts_by_actor"] == {
        "coordinator": 1,
        "specialist": 1,
    }
    assert summary["charged_usage"]["output_tokens"] == 2 * 2_048
    assert summary["token_measurements"]["output_tokens"]["not_reported_attempts"] == 2


@pytest.mark.parametrize(
    ("failure_class", "expected_status"),
    [
        (ModelFailureClass.MODEL_TIMEOUT, TerminalStatus.TIMEOUT),
        (ModelFailureClass.MODEL_UNAVAILABLE, TerminalStatus.PROVIDER_ERROR),
        (ModelFailureClass.INVALID_JSON, TerminalStatus.INVALID_OUTPUT),
    ],
)
def test_runtime_recorder_classifies_and_charges_failed_model_attempts(
    failure_class: ModelFailureClass,
    expected_status: TerminalStatus,
) -> None:
    ledger = _ledger()
    recorder = _recorder(ledger)
    error = ModelCallError(failure_class, "controlled failure")
    client = MockLLMClient([error])
    request = _request()
    attempt = recorder.reserve_model_attempt(
        client=client,
        request=request,
        actor_kind=UsageActorKind.SPECIALIST,
        agent_id="effect_agent",
        role="effect",
        configured_model_id="claude-sonnet-5",
    )

    with pytest.raises(ModelCallError) as raised:
        client.complete(request)
    status = recorder.status_for_model_error(raised.value)
    recorder.reconcile_model_attempt(attempt, status=status, error=raised.value)

    summary = ledger.summary()
    assert status is expected_status
    assert summary["terminal_status_counts"] == {expected_status.value: 1}
    assert summary["charged_usage"]["model_attempts"] == 1
    assert summary["charged_usage"]["output_tokens"] == 2_048
    assert summary["pending_attempt_ids"] == []


def test_runtime_recorder_accounts_tool_error_in_same_project_ledger() -> None:
    ledger = _ledger()
    recorder = _recorder(ledger)
    attempt = recorder.reserve_action(
        action_kind=UsageActionKind.REPOSITORY_TOOL_CALL,
        actor_kind=UsageActorKind.SPECIALIST,
        agent_id="semantic_bridge_agent",
        role="semantic-bridge",
        action_name="INSPECT_METHOD",
        identity="action-1",
        max_wall_clock_ms=1_000,
    )
    recorder.reconcile_action(attempt, status=TerminalStatus.TOOL_ERROR)

    summary = ledger.summary()
    assert summary["terminal_status_counts"] == {"tool-error": 1}
    assert summary["charged_usage"]["repository_tool_calls"] == 1
    assert summary["pending_attempt_ids"] == []
