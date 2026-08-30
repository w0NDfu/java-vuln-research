from __future__ import annotations

import json
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.agent import AgentState, StopReason


ROOT = Path(__file__).parents[2]


def test_state_stable_roundtrip_and_project_locality() -> None:
    state = AgentState.create(project_id="P1", repository_identity="repo@abc", provenance={"producer": "test"})
    state.budget.begin_round()
    state.record_tool_call("tool-1", project_id="P1", entity_ids=("entity-1",))
    state.record_evidence("evidence-1", project_id="P1")
    state.record_proposal("proposal-1", project_id="P1", gate_status="ADMISSIBLE")
    state.active_candidate_path_ids.add("path-1")
    state.current_exploration_focus = "inspect one callable"
    encoded = state.to_json()
    assert AgentState.from_dict(json.loads(encoded)).to_json() == encoded
    with pytest.raises(ValueError, match="cross-project"):
        state.record_tool_call("tool-2", project_id="P2")


def test_state_stop_and_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    state = AgentState.create(project_id="P1", repository_identity="repo@abc", provenance={"producer": "test"})
    state.stop(StopReason.NO_FURTHER_ACTION)
    schema = json.loads((ROOT / "schemas" / "work1_agent_state.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(state.to_dict())
    assert state.stopped
