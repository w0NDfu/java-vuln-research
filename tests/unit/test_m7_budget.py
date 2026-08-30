from __future__ import annotations

import pytest

from java_vuln_research.work1_agent.agent.budget import AgentBudgetLimits, BudgetExceeded, BudgetTracker


def test_default_budget_is_frozen_contract() -> None:
    limits = AgentBudgetLimits()
    assert limits.to_dict() == {
        "max_rounds_per_project": 15,
        "max_tool_calls_per_round": 4,
        "max_total_tool_calls_per_project": 40,
        "max_proposals_per_project": 10,
        "max_admissible_proposals_per_project": 8,
        "max_proposals_per_round": 1,
    }


def test_round_tool_and_proposal_limits_are_enforced_before_increment() -> None:
    tracker = BudgetTracker(AgentBudgetLimits(max_rounds_per_project=1, max_tool_calls_per_round=1, max_total_tool_calls_per_project=2, max_proposals_per_project=2, max_admissible_proposals_per_project=1))
    assert tracker.begin_round() == 1
    tracker.record_tool_call()
    with pytest.raises(BudgetExceeded) as tool_error:
        tracker.record_tool_call()
    assert tool_error.value.budget_name == "max_tool_calls_per_round"
    tracker.record_proposal()
    with pytest.raises(BudgetExceeded) as proposal_error:
        tracker.record_proposal()
    assert proposal_error.value.budget_name == "max_proposals_per_round"
    tracker.record_admissible_proposal()
    with pytest.raises(BudgetExceeded) as gate_error:
        tracker.record_admissible_proposal()
    assert gate_error.value.budget_name == "max_admissible_proposals_per_project"
    with pytest.raises(BudgetExceeded) as round_error:
        tracker.begin_round()
    assert round_error.value.budget_name == "max_rounds_per_project"


def test_budget_roundtrip_and_remaining_counts() -> None:
    tracker = BudgetTracker(AgentBudgetLimits())
    tracker.begin_round()
    tracker.record_model_call(input_tokens=12, output_tokens=4)
    tracker.record_tool_call()
    snapshot = tracker.to_dict()
    restored = BudgetTracker.from_dict(snapshot)
    assert restored.to_dict() == snapshot
    assert snapshot["remaining"]["rounds"] == 14
    assert snapshot["remaining"]["tool_calls_total"] == 39
