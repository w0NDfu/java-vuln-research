from __future__ import annotations

import json
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.agent.actions import ActionType, AgentAction, StopReason
from java_vuln_research.work1_agent.proposal import EntityRole, EntityRoleRef, ProposalScope, ProposalType, ScopeKind, SecurityProposal


ROOT = Path(__file__).parents[2]
ENTITY_ID = "entity-" + "1" * 24


def _proposal() -> SecurityProposal:
    ref = EntityRoleRef(ENTITY_ID, EntityRole.RETURN)
    return SecurityProposal.create(
        proposal_type=ProposalType.EXTERNAL_INPUT,
        subject=ref,
        scope=ProposalScope(ScopeKind.ENTITY, (ENTITY_ID,), "P"),
        evidence_refs=("evidence-" + "2" * 24,),
        reason="Grounded candidate input semantics.",
        provenance={"producer": "m7-mock", "benchmark_informed": False},
        semantic_category="UNKNOWN",
    )


def test_tool_action_has_stable_id_and_serialization() -> None:
    first = AgentAction.create(
        project_id="P",
        round=1,
        action_type=ActionType.SEARCH_CODE,
        arguments={"query": "request", "max_hits": 10},
        reason="Collect bounded source evidence.",
        provenance={"model_call_id": "mock-1"},
    )
    second = AgentAction.create(
        project_id="P",
        round=1,
        action_type="SEARCH_CODE",
        arguments={"max_hits": 10, "query": "request"},
        reason="Different explanation does not alter action identity.",
        provenance={"model_call_id": "mock-2"},
    )
    assert first.action_id == second.action_id
    assert AgentAction.from_dict(json.loads(first.to_json())).to_json() == first.to_json()


def test_propose_payload_is_exact_m4_proposal() -> None:
    proposal = _proposal()
    action = AgentAction.create(
        project_id="P",
        round=2,
        action_type=ActionType.PROPOSE,
        proposal=proposal,
        reason="Submit one minimal relation.",
        provenance={"model_call_id": "mock-3"},
    )
    assert SecurityProposal.from_dict(action.proposal or {}).to_json() == proposal.to_json()
    with pytest.raises(ValueError, match="compatible M4 proposal"):
        AgentAction.create(
            project_id="P",
            round=2,
            action_type=ActionType.PROPOSE,
            proposal=proposal,
            arguments={"extra": True},
            reason="invalid",
            provenance={"model_call_id": "mock-4"},
        )


def test_stop_requires_explicit_reason() -> None:
    action = AgentAction.create(
        project_id="P",
        round=3,
        action_type=ActionType.STOP,
        stop_reason=StopReason.INSUFFICIENT_EVIDENCE,
        reason="No grounded next action remains.",
        provenance={"model_call_id": "mock-5"},
    )
    assert action.stop_reason == StopReason.INSUFFICIENT_EVIDENCE
    with pytest.raises(ValueError, match="STOP requires"):
        AgentAction.create(
            project_id="P",
            round=3,
            action_type=ActionType.STOP,
            reason="missing stop reason",
            provenance={"model_call_id": "mock-6"},
        )


def test_action_schema_accepts_contracts() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    action_schema = json.loads((ROOT / "schemas" / "work1_agent_action.schema.json").read_text(encoding="utf-8"))
    proposal_schema = json.loads((ROOT / "schemas" / "security_proposal.schema.json").read_text(encoding="utf-8"))
    resolver = jsonschema.RefResolver.from_schema(action_schema, store={"security_proposal.schema.json": proposal_schema})
    validator = jsonschema.Draft202012Validator(action_schema, resolver=resolver)
    tool = AgentAction.create(project_id="P", round=1, action_type="SEARCH_SYMBOLS", arguments={"query": "Foo"}, reason="inspect", provenance={"source": "mock"})
    proposal = AgentAction.create(project_id="P", round=2, action_type="PROPOSE", proposal=_proposal(), reason="propose", provenance={"source": "mock"})
    stop = AgentAction.create(project_id="P", round=3, action_type="STOP", stop_reason="NO_FURTHER_ACTION", reason="stop", provenance={"source": "mock"})
    for value in (tool, proposal, stop):
        validator.validate(value.to_dict())
