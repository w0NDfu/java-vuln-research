from __future__ import annotations

import json
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.agent import (
    ActionType,
    AgentBudgetLimits,
    BudgetTracker,
    LLMResponse,
    ModelCallError,
    ModelFailureClass,
    StrictActionParser,
)


ROOT = Path(__file__).parents[2]
ENTITY = "entity-" + "1" * 24
EVIDENCE = "evidence-" + "2" * 24


def _response(value: object) -> LLMResponse:
    text = value if isinstance(value, str) else json.dumps(value)
    return LLMResponse("modelcall-" + "a" * 24, "request-1", "mock", "mock-v1", text, 0.0)


def _parser() -> StrictActionParser:
    return StrictActionParser(ROOT / "schemas")


def _tool(**arguments: object) -> dict[str, object]:
    return {"action_type": "SEARCH_CODE", "arguments": {"query": "request", **arguments}, "proposal": None, "stop_reason": None, "reason": "Collect bounded evidence."}


def _proposal() -> dict[str, object]:
    return {
        "action_type": "PROPOSE",
        "arguments": {},
        "proposal": {
            "proposal_type": "EXTERNAL_INPUT",
            "subject": {"entity_id": ENTITY, "role": "RETURN"},
            "source": None,
            "target": None,
            "scope": {"kind": "ENTITY", "entity_ids": [ENTITY]},
            "semantic_category": "UNKNOWN",
            "evidence_refs": [EVIDENCE],
            "reason": "Source evidence supports a candidate external-input anchor.",
            "model_confidence": 0.5,
            "provenance": {"originating_tool_call_ids": ["tool-call-1"]},
        },
        "stop_reason": None,
        "reason": "Submit one minimal proposal.",
    }


def test_parser_builds_canonical_tool_action_and_injects_identity() -> None:
    action = _parser().parse(_response(_tool(max_hits=10)), project_id="P", round=1)
    assert action.action_type is ActionType.SEARCH_CODE
    assert action.project_id == "P" and action.round == 1
    assert action.action_id.startswith("action-")
    assert action.provenance["benchmark_informed"] is False


@pytest.mark.parametrize(
    ("value", "failure"),
    [
        ("{not json}", ModelFailureClass.INVALID_JSON),
        ({"action_type": "WRITE_CODE", "arguments": {}, "proposal": None, "stop_reason": None, "reason": "x"}, ModelFailureClass.INVALID_ACTION),
        ({**_tool(), "extra": True}, ModelFailureClass.SCHEMA_VIOLATION),
        (_tool(max_hits=101), ModelFailureClass.TOOL_ARGUMENT_INVALID),
        (_tool(file_glob=7), ModelFailureClass.TOOL_ARGUMENT_INVALID),
    ],
)
def test_parser_classifies_invalid_model_output(value: object, failure: ModelFailureClass) -> None:
    with pytest.raises(ModelCallError) as caught:
        _parser().parse(_response(value), project_id="P", round=1)
    assert caught.value.failure_class is failure


def test_parser_canonicalizes_m4_proposal_and_rejects_fabricated_evidence() -> None:
    parser = _parser()
    action = parser.parse(
        _response(_proposal()),
        project_id="P",
        round=2,
        known_entity_ids={ENTITY},
        known_evidence_refs={EVIDENCE},
    )
    assert action.proposal is not None
    assert action.proposal["proposal_id"].startswith("proposal-")
    assert action.proposal["scope"]["project_id"] == "P"
    assert action.proposal["provenance"]["allowed_for_agent_runtime"] is True
    assert action.proposal["provenance"]["model_call_id"] == action.provenance["model_call_id"]

    with pytest.raises(ModelCallError) as caught:
        parser.parse(_response(_proposal()), project_id="P", round=2, known_entity_ids={ENTITY}, known_evidence_refs=set())
    assert caught.value.failure_class is ModelFailureClass.SCHEMA_VIOLATION


def test_parser_rejects_unknown_entity_and_cross_project_scope() -> None:
    parser = _parser()
    with pytest.raises(ModelCallError, match="entity absent"):
        parser.parse(_response(_proposal()), project_id="P", round=2, known_entity_ids=set(), known_evidence_refs={EVIDENCE})
    value = _proposal()
    value["proposal"]["scope"]["project_id"] = "OTHER"
    with pytest.raises(ModelCallError, match="cross-project"):
        parser.parse(_response(value), project_id="P", round=2)


def test_parser_budget_check_is_fail_closed_and_non_mutating() -> None:
    budget = BudgetTracker(AgentBudgetLimits(max_tool_calls_per_round=1))
    budget.begin_round()
    budget.record_tool_call()
    with pytest.raises(ModelCallError) as caught:
        _parser().parse(_response(_tool()), project_id="P", round=1, budget=budget)
    assert caught.value.failure_class is ModelFailureClass.BUDGET_EXCEEDED
    assert budget.tool_calls_total == 1


def test_parser_accepts_explicit_conservative_stop() -> None:
    value = {"action_type": "STOP", "arguments": {}, "proposal": None, "stop_reason": "INSUFFICIENT_EVIDENCE", "reason": "No grounded next action."}
    action = _parser().parse(_response(value), project_id="P", round=3)
    assert action.stop_reason.value == "INSUFFICIENT_EVIDENCE"


def test_model_decision_schema_accepts_proposal_draft_with_standard_validator() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    decision_schema = json.loads((ROOT / "schemas" / "work1_agent_model_decision.schema.json").read_text(encoding="utf-8"))
    proposal_schema = json.loads((ROOT / "schemas" / "security_proposal.schema.json").read_text(encoding="utf-8"))
    resolver = jsonschema.RefResolver.from_schema(
        decision_schema,
        store={
            "security_proposal.schema.json": proposal_schema,
            "work1_agent_model_decision.schema.json": decision_schema,
        },
    )
    jsonschema.Draft202012Validator(decision_schema, resolver=resolver).validate(_proposal())
