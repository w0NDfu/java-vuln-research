from __future__ import annotations

import pytest

from java_vuln_research.work1_agent.m8_experiment.arms import FormalProfile
from java_vuln_research.work1_agent.m8_experiment.usage import (
    CORE_CONFIRMATORY_ARM_IDS,
    ROLE_CONFIRMATORY_ARM_IDS,
    BudgetComparabilityError,
    CostMeasurement,
    CostSource,
    ModelAttemptRequest,
    ModelAttemptResult,
    ModelTokenUsage,
    ProjectBudgetCeilings,
    ProjectUsageLedger,
    RunKey,
    TerminalStatus,
    TokenMeasurement,
    UsageActorKind,
    assert_confirmatory_budget_comparability,
    confirmatory_arms_for_profile,
)


def _budget(**overrides: int) -> ProjectBudgetCeilings:
    values = {
        "max_model_attempts": 2,
        "max_canonical_input_tokens": 1_000,
        "max_reserved_output_tokens": 500,
        "max_repository_tool_calls": 10,
        "max_codeql_calls": 4,
        "max_proposal_families": 4,
        "max_admissible_proposals": 3,
        "max_candidate_paths": 2,
        "max_wall_clock_ms": 10_000,
    }
    values.update(overrides)
    return ProjectBudgetCeilings(**values)


def _request(model: str, index: int) -> ModelAttemptRequest:
    return ModelAttemptRequest(
        attempt_index=index,
        retry_index=0,
        configured_model_id=model,
        request_timestamp=f"2026-09-02T00:00:0{index}Z",
        canonical_prompt_sha256="a" * 64,
        observation_sha256="b" * 64,
        tool_catalog_sha256="c" * 64,
        serialized_request_bytes=100,
    )


def test_core_and_role_profiles_require_one_identical_budget_hash() -> None:
    budget = _budget()
    assert CORE_CONFIRMATORY_ARM_IDS == FormalProfile.CORE.confirmatory_arm_ids
    assert ROLE_CONFIRMATORY_ARM_IDS == FormalProfile.ROLE.confirmatory_arm_ids
    core = {arm: ProjectBudgetCeilings.from_dict(budget.to_dict()) for arm in CORE_CONFIRMATORY_ARM_IDS}
    role = {arm: ProjectBudgetCeilings.from_dict(budget.to_dict()) for arm in ROLE_CONFIRMATORY_ARM_IDS}

    assert confirmatory_arms_for_profile("CORE") == CORE_CONFIRMATORY_ARM_IDS
    assert confirmatory_arms_for_profile("role") == ROLE_CONFIRMATORY_ARM_IDS
    assert assert_confirmatory_budget_comparability(core) == budget.sha256
    assert (
        assert_confirmatory_budget_comparability(
            role,
            confirmatory_arm_ids=confirmatory_arms_for_profile("ROLE"),
        )
        == budget.sha256
    )


def test_comparability_fails_on_missing_extra_or_arm_specific_ceiling() -> None:
    registrations = {arm: _budget() for arm in CORE_CONFIRMATORY_ARM_IDS}

    missing = dict(registrations)
    missing.pop("m8_s0")
    with pytest.raises(BudgetComparabilityError, match="missing=.*m8_s0"):
        assert_confirmatory_budget_comparability(missing)

    extra = {**registrations, "m8_h0": _budget()}
    with pytest.raises(BudgetComparabilityError, match="extra=.*m8_h0"):
        assert_confirmatory_budget_comparability(extra)

    unequal = dict(registrations)
    unequal["m8_m2"] = _budget(max_model_attempts=3)
    with pytest.raises(BudgetComparabilityError, match="budgets differ"):
        assert_confirmatory_budget_comparability(unequal)


def test_dollar_cost_is_an_outcome_not_a_budget_field_or_early_stop() -> None:
    budget = _budget()
    with pytest.raises(ValueError, match="extra=.*max_cost_usd"):
        ProjectBudgetCeilings.from_dict({**budget.to_dict(), "max_cost_usd": "1.00"})

    ledger = ProjectUsageLedger(
        RunKey(
            study_id="study-1",
            split="dev-tune",
            subject_id="subject-1",
            arm_id="m8_m2",
            replicate_index=1,
            run_id="run-m2-1",
        ),
        budget,
    )
    ledger.reserve_model_attempt(
        attempt_id="opus-1",
        actor_kind=UsageActorKind.COORDINATOR,
        agent_id="coordinator_agent",
        role="coordinator",
        request=_request("claude-opus-5", 1),
        canonical_input_tokens=100,
        max_output_tokens=100,
        max_wall_clock_ms=1_000,
    )
    ledger.reconcile_model_attempt(
        attempt_id="opus-1",
        status=TerminalStatus.SUCCESS,
        ended_at="2026-09-02T00:00:02Z",
        wall_clock_ms=100,
        result=ModelAttemptResult(
            tokens=ModelTokenUsage(
                input_tokens=TokenMeasurement.provider_reported(100),
                output_tokens=TokenMeasurement.provider_reported(10),
                cache_read_tokens=TokenMeasurement.not_reported(),
                cache_write_tokens=TokenMeasurement.not_reported(),
            ),
            billed_cost=CostMeasurement(
                amount_usd="999999.99",
                source=CostSource.LOCALLY_COMPUTED,
                price_table_id="price-table-v1",
            ),
        ),
    )

    # Even a deliberately huge observed cost cannot consume the second shared model slot.
    ledger.reserve_model_attempt(
        attempt_id="specialist-2",
        actor_kind=UsageActorKind.SPECIALIST,
        agent_id="input_agent",
        role="input",
        request=_request("claude-sonnet-5", 2),
        canonical_input_tokens=100,
        max_output_tokens=100,
        max_wall_clock_ms=1_000,
    )
    summary = ledger.summary()
    assert summary["charged_usage"]["model_attempts"] == 2
    assert summary["billed_cost"]["known_total_usd"] == "999999.99"
    assert summary["billed_cost"]["is_budget_ceiling"] is False


def test_m2_model_routing_does_not_change_shared_budget_identity() -> None:
    budget = _budget()
    ledgers = {
        arm: ProjectUsageLedger(
            RunKey(
                study_id="study-1",
                split="formal-holdout",
                subject_id="subject-1",
                arm_id=arm,
                replicate_index=1,
                run_id=f"run-{arm.lower()}-1",
            ),
            ProjectBudgetCeilings.from_dict(budget.to_dict()),
        )
        for arm in CORE_CONFIRMATORY_ARM_IDS
    }
    assert {ledger.budget_sha256 for ledger in ledgers.values()} == {budget.sha256}
    assert ledgers["m8_m2"].budget_sha256 == ledgers["m8_m1"].budget_sha256
