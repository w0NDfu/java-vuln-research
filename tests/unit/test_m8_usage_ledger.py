from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import threading

import pytest

from java_vuln_research.work1_agent.m8_experiment.usage import (
    BudgetCeilingExceeded,
    CostMeasurement,
    CostSource,
    DuplicateAttemptError,
    LedgerBreachError,
    ModelAttemptRequest,
    ModelAttemptResult,
    ModelTokenUsage,
    ProjectBudgetCeilings,
    ProjectUsageLedger,
    ReconciliationError,
    ReservationExceeded,
    RunKey,
    TerminalStatus,
    TokenMeasurement,
    UsageActionKind,
    UsageActorKind,
)


def _budget(**overrides: int) -> ProjectBudgetCeilings:
    values = {
        "max_model_attempts": 10,
        "max_canonical_input_tokens": 10_000,
        "max_reserved_output_tokens": 2_000,
        "max_repository_tool_calls": 20,
        "max_codeql_calls": 10,
        "max_proposal_families": 10,
        "max_admissible_proposals": 8,
        "max_candidate_paths": 6,
        "max_wall_clock_ms": 100_000,
    }
    values.update(overrides)
    return ProjectBudgetCeilings(**values)


def _run(*, arm_id: str = "m8_m2") -> RunKey:
    return RunKey(
        study_id="study-1",
        split="dev-tune",
        subject_id="subject-1",
        arm_id=arm_id,
        replicate_index=1,
        run_id=f"run-{arm_id.lower()}-1",
    )


def _request(index: int, *, retry_index: int = 0, model: str = "claude-sonnet-5") -> ModelAttemptRequest:
    return ModelAttemptRequest(
        attempt_index=index,
        retry_index=retry_index,
        configured_model_id=model,
        request_timestamp=f"2026-09-02T00:00:{index:02d}Z",
        canonical_prompt_sha256="a" * 64,
        observation_sha256="b" * 64,
        tool_catalog_sha256="c" * 64,
        serialized_request_bytes=1_000 + index,
    )


def _reported_result(
    *,
    input_tokens: int = 100,
    output_tokens: int = 20,
    cost: str = "0.01",
) -> ModelAttemptResult:
    return ModelAttemptResult(
        tokens=ModelTokenUsage(
            input_tokens=TokenMeasurement.provider_reported(input_tokens),
            output_tokens=TokenMeasurement.provider_reported(output_tokens),
            cache_read_tokens=TokenMeasurement.provider_reported(3),
            cache_write_tokens=TokenMeasurement.provider_reported(2),
        ),
        billed_cost=CostMeasurement(
            amount_usd=cost,
            source=CostSource.LOCALLY_COMPUTED,
            price_table_id="price-table-v1",
        ),
        provider_request_id="provider-request-1",
        provider_status="200",
        response_reported_model="claude-sonnet-5-20260901",
        provider_deployment_revision="deployment-17",
        repeated_observation_bytes=12,
        cache_hit=True,
    )


def _unknown_result() -> ModelAttemptResult:
    return ModelAttemptResult(
        tokens=ModelTokenUsage.all_not_reported(),
        billed_cost=CostMeasurement.not_reported(price_table_id="price-table-v1"),
        provider_status="NO_RESPONSE",
    )


def test_model_ledger_covers_all_actor_kinds_failures_and_retries() -> None:
    ledger = ProjectUsageLedger(_run(), _budget())
    attempts = (
        ("coordinator-1", UsageActorKind.COORDINATOR, "coordinator_agent", "coordinator", 0),
        ("specialist-timeout", UsageActorKind.SPECIALIST, "input_agent", "input", 1),
        ("single-invalid", UsageActorKind.SINGLE_AGENT, "single_agent", "single-agent", 0),
        ("specialist-provider-error", UsageActorKind.SPECIALIST, "effect_agent", "effect", 0),
    )
    statuses = (
        TerminalStatus.SUCCESS,
        TerminalStatus.TIMEOUT,
        TerminalStatus.INVALID_OUTPUT,
        TerminalStatus.PROVIDER_ERROR,
    )

    for index, ((attempt_id, actor, agent_id, role, retry), status) in enumerate(
        zip(attempts, statuses), start=1
    ):
        ledger.reserve_model_attempt(
            attempt_id=attempt_id,
            actor_kind=actor,
            agent_id=agent_id,
            role=role,
            request=_request(index, retry_index=retry),
            canonical_input_tokens=100,
            max_output_tokens=100,
            max_wall_clock_ms=1_000,
        )
        if status is TerminalStatus.SUCCESS:
            result = _reported_result(output_tokens=20)
        elif status is TerminalStatus.INVALID_OUTPUT:
            result = ModelAttemptResult(
                tokens=ModelTokenUsage(
                    input_tokens=TokenMeasurement.not_reported(),
                    output_tokens=TokenMeasurement.locally_estimated(5),
                    cache_read_tokens=TokenMeasurement.not_reported(),
                    cache_write_tokens=TokenMeasurement.not_reported(),
                ),
                billed_cost=CostMeasurement.not_reported(),
                provider_status="INVALID_JSON",
            )
        else:
            result = _unknown_result()
        ledger.reconcile_model_attempt(
            attempt_id=attempt_id,
            status=status,
            ended_at=f"2026-09-02T00:01:{index:02d}Z",
            wall_clock_ms=100 + index,
            result=result,
        )

    summary = ledger.summary()
    assert summary["charged_usage"]["model_attempts"] == 4
    assert summary["charged_usage"]["canonical_input_tokens"] == 400
    # Unknown failed output retains its maximum reservation; it is never charged as zero.
    assert summary["charged_usage"]["output_tokens"] == 20 + 100 + 5 + 100
    assert summary["terminal_status_counts"] == {
        "invalid-output": 1,
        "provider-error": 1,
        "success": 1,
        "timeout": 1,
    }
    assert summary["model_attempts_by_actor"] == {
        "coordinator": 1,
        "single-agent": 1,
        "specialist": 2,
    }
    assert summary["transport_retry_attempts"] == 1
    assert summary["token_measurements"]["output_tokens"]["not_reported_attempts"] == 2
    assert summary["billed_cost"]["not_reported_attempts"] == 3
    assert summary["billed_cost"]["known_total_usd"] == "0.01"


def test_entries_are_frozen_append_only_and_attempt_ids_are_unique() -> None:
    ledger = ProjectUsageLedger(_run(), _budget())
    reservation = ledger.reserve_model_attempt(
        attempt_id="attempt-1",
        actor_kind=UsageActorKind.COORDINATOR,
        agent_id="coordinator_agent",
        role="coordinator",
        request=_request(1),
        canonical_input_tokens=10,
        max_output_tokens=20,
        max_wall_clock_ms=1_000,
    )
    with pytest.raises(FrozenInstanceError):
        reservation.attempt_id = "tampered"  # type: ignore[misc]
    with pytest.raises(DuplicateAttemptError, match="duplicate attempt ID"):
        ledger.reserve_model_attempt(
            attempt_id="attempt-1",
            actor_kind=UsageActorKind.SPECIALIST,
            agent_id="input_agent",
            role="input",
            request=_request(2),
            canonical_input_tokens=10,
            max_output_tokens=20,
            max_wall_clock_ms=1_000,
        )
    assert ledger.entries == (reservation,)

    reconciliation = ledger.reconcile_model_attempt(
        attempt_id="attempt-1",
        status=TerminalStatus.SUCCESS,
        ended_at="2026-09-02T00:02:00Z",
        wall_clock_ms=100,
        result=_reported_result(output_tokens=8),
    )
    assert ledger.entries == (reservation, reconciliation)
    assert reconciliation.previous_entry_sha256 == reservation.entry_sha256
    with pytest.raises(ReconciliationError, match="already reconciled"):
        ledger.reconcile_model_attempt(
            attempt_id="attempt-1",
            status=TerminalStatus.SUCCESS,
            ended_at="2026-09-02T00:03:00Z",
            wall_clock_ms=100,
            result=_reported_result(),
        )


def test_failed_unknown_tokens_are_explicit_and_hold_the_reservation() -> None:
    ledger = ProjectUsageLedger(
        _run(),
        _budget(max_model_attempts=1, max_reserved_output_tokens=50),
    )
    ledger.reserve_model_attempt(
        attempt_id="timeout-1",
        actor_kind=UsageActorKind.SPECIALIST,
        agent_id="semantic_bridge_agent",
        role="semantic-bridge",
        request=_request(1),
        canonical_input_tokens=30,
        max_output_tokens=50,
        max_wall_clock_ms=1_000,
    )
    ledger.reconcile_model_attempt(
        attempt_id="timeout-1",
        status=TerminalStatus.TIMEOUT,
        ended_at="2026-09-02T00:02:00Z",
        wall_clock_ms=1_000,
        result=_unknown_result(),
    )
    summary = ledger.summary()
    assert summary["charged_usage"]["output_tokens"] == 50
    assert summary["token_measurements"]["input_tokens"] == {
        "known_total": 0,
        "known_by_source": {},
        "attempts_by_source": {"NOT_REPORTED": 1},
        "not_reported_attempts": 1,
    }
    assert summary["billed_cost"]["not_reported_attempts"] == 1

    with pytest.raises(ValueError, match="NOT_REPORTED.*count=None"):
        TokenMeasurement(count=0, source=TokenMeasurement.not_reported().source)


def test_all_budgeted_actions_share_one_project_ceiling_and_fail_before_append() -> None:
    ledger = ProjectUsageLedger(
        _run(),
        _budget(max_repository_tool_calls=1, max_codeql_calls=1, max_proposal_families=1),
    )
    ledger.reserve_action(
        attempt_id="repo-1",
        action_kind=UsageActionKind.REPOSITORY_TOOL_CALL,
        actor_kind=UsageActorKind.SPECIALIST,
        agent_id="input_agent",
        role="input",
        action_name="INSPECT_METHOD",
        started_at="2026-09-02T00:00:00Z",
        max_wall_clock_ms=100,
    )
    before = ledger.entries
    with pytest.raises(BudgetCeilingExceeded) as error:
        ledger.reserve_action(
            attempt_id="repo-2",
            action_kind=UsageActionKind.REPOSITORY_TOOL_CALL,
            actor_kind=UsageActorKind.COORDINATOR,
            agent_id="coordinator_agent",
            role="coordinator",
            action_name="SEARCH_CODE",
            started_at="2026-09-02T00:00:01Z",
            max_wall_clock_ms=100,
        )
    assert error.value.resource == "repository_tool_calls"
    assert ledger.entries == before

    ledger.reconcile_action(
        attempt_id="repo-1",
        status=TerminalStatus.TOOL_ERROR,
        ended_at="2026-09-02T00:00:02Z",
        wall_clock_ms=30,
    )
    for attempt_id, kind in (
        ("ql-1", UsageActionKind.CODEQL_CALL),
        ("proposal-1", UsageActionKind.PROPOSAL_FAMILY),
        ("admissible-1", UsageActionKind.ADMISSIBLE_PROPOSAL),
        ("path-1", UsageActionKind.CANDIDATE_PATH),
    ):
        ledger.reserve_action(
            attempt_id=attempt_id,
            action_kind=kind,
            actor_kind=UsageActorKind.VERIFIER,
            agent_id="m8_verifier",
            role="verifier",
            action_name=kind.value.upper(),
            started_at="2026-09-02T00:00:03Z",
        )
        ledger.reconcile_action(
            attempt_id=attempt_id,
            status=TerminalStatus.SUCCESS,
            ended_at="2026-09-02T00:00:04Z",
            wall_clock_ms=0,
        )
    charged = ledger.summary()["charged_usage"]
    assert charged["repository_tool_calls"] == 1
    assert charged["codeql_calls"] == 1
    assert charged["proposal_families"] == 1
    assert charged["admissible_proposals"] == 1
    assert charged["candidate_paths"] == 1


def test_reconciliation_overrun_is_audited_then_ledger_fails_closed() -> None:
    ledger = ProjectUsageLedger(_run(), _budget(max_wall_clock_ms=100))
    ledger.reserve_action(
        attempt_id="repo-overrun",
        action_kind=UsageActionKind.REPOSITORY_TOOL_CALL,
        actor_kind=UsageActorKind.SPECIALIST,
        agent_id="effect_agent",
        role="effect",
        action_name="INSPECT_METHOD",
        started_at="2026-09-02T00:00:00Z",
        max_wall_clock_ms=50,
    )
    with pytest.raises(ReservationExceeded) as error:
        ledger.reconcile_action(
            attempt_id="repo-overrun",
            status=TerminalStatus.TIMEOUT,
            ended_at="2026-09-02T00:00:01Z",
            wall_clock_ms=60,
        )
    assert error.value.resource == "wall_clock_ms"
    assert ledger.summary()["is_breached"] is True
    # The per-attempt reservation was violated even though project capacity remains.
    # The exact overrun remains in the audit and cannot be reconciled a second time.
    assert ledger.summary()["charged_usage"]["wall_clock_ms"] == 60
    with pytest.raises(LedgerBreachError, match="unrecoverable reservation breach"):
        ledger.reserve_action(
            attempt_id="blocked-after-breach",
            action_kind=UsageActionKind.CODEQL_CALL,
            actor_kind=UsageActorKind.COORDINATOR,
            agent_id="coordinator_agent",
            role="coordinator",
            action_name="RUN_CODEQL",
            started_at="2026-09-02T00:00:02Z",
        )
    with pytest.raises(ReconciliationError, match="already reconciled"):
        ledger.reconcile_action(
            attempt_id="repo-overrun",
            status=TerminalStatus.TIMEOUT,
            ended_at="2026-09-02T00:00:02Z",
            wall_clock_ms=60,
        )


def test_canonical_serialization_roundtrip_and_tamper_detection() -> None:
    ledger = ProjectUsageLedger(_run(), _budget())
    ledger.reserve_model_attempt(
        attempt_id="attempt-1",
        actor_kind=UsageActorKind.SINGLE_AGENT,
        agent_id="single_agent",
        role="single-agent",
        request=_request(1),
        canonical_input_tokens=100,
        max_output_tokens=100,
        max_wall_clock_ms=1_000,
    )
    ledger.reconcile_model_attempt(
        attempt_id="attempt-1",
        status=TerminalStatus.INVALID_OUTPUT,
        ended_at="2026-09-02T00:01:00Z",
        wall_clock_ms=400,
        result=_unknown_result(),
    )

    encoded = ledger.to_canonical_json()
    restored = ProjectUsageLedger.from_canonical_json(encoded)
    assert restored.to_canonical_json() == encoded
    assert restored.sha256 == ledger.sha256
    assert ledger.to_dict()["ledger_sha256"] == ledger.sha256

    noncanonical = json.dumps(json.loads(encoded), indent=2)
    with pytest.raises(ValueError, match="not canonical"):
        ProjectUsageLedger.from_canonical_json(noncanonical)

    tampered = json.loads(encoded)
    tampered["entries"][0]["agent_id"] = "different_agent"
    with pytest.raises(ValueError, match="entry_sha256 is not canonical"):
        ProjectUsageLedger.from_dict(tampered)


def test_negative_usage_and_concurrent_reservations_fail_closed() -> None:
    with pytest.raises(ValueError, match="positive integer"):
        _budget(max_model_attempts=-1)

    ledger = ProjectUsageLedger(_run(), _budget(max_model_attempts=1))
    barrier = threading.Barrier(3)
    successes: list[str] = []
    failures: list[Exception] = []

    def reserve(attempt_id: str, index: int) -> None:
        barrier.wait()
        try:
            ledger.reserve_model_attempt(
                attempt_id=attempt_id,
                actor_kind=UsageActorKind.SPECIALIST,
                agent_id="input_agent",
                role="input",
                request=_request(index),
                canonical_input_tokens=10,
                max_output_tokens=10,
                max_wall_clock_ms=100,
            )
            successes.append(attempt_id)
        except Exception as error:  # assertions below verify the exact fail-closed type
            failures.append(error)

    threads = [
        threading.Thread(target=reserve, args=("attempt-a", 1)),
        threading.Thread(target=reserve, args=("attempt-b", 2)),
    ]
    for thread in threads:
        thread.start()
    barrier.wait()
    for thread in threads:
        thread.join()

    assert len(successes) == 1
    assert len(failures) == 1
    assert isinstance(failures[0], BudgetCeilingExceeded)
    assert ledger.summary()["charged_usage"]["model_attempts"] == 1
