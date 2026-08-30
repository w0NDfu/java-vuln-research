from __future__ import annotations

import json
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.agent import AgentTrace, AgentTraceEvent, TraceEventType


ROOT = Path(__file__).parents[2]


def test_trace_stable_replay_and_contiguous_sequence(tmp_path: Path) -> None:
    trace = AgentTrace("P1")
    first = trace.append(round=0, event_type=TraceEventType.INITIAL_OBSERVATION, payload={"java_files": 2}, provenance={"producer": "test"})
    trace.append(round=1, event_type=TraceEventType.ACTION, payload={"action_id": "a"}, provenance={"producer": "test"})
    assert first.event_id == AgentTraceEvent.from_dict(first.to_dict()).event_id
    restored = AgentTrace.from_jsonl_text("P1", trace.to_jsonl_text())
    assert restored.to_jsonl_text() == trace.to_jsonl_text()
    output = tmp_path / "trace.jsonl"
    trace.write_jsonl(output)
    assert output.read_text(encoding="utf-8") == trace.to_jsonl_text()


def test_trace_rejects_cross_project_and_noncontiguous_event() -> None:
    trace = AgentTrace("P1")
    wrong = AgentTraceEvent.create(sequence=1, project_id="P2", round=1, event_type="FAILURE", payload={}, provenance={"producer": "test"})
    with pytest.raises(ValueError, match="cross-project"):
        trace.append_event(wrong)
    skipped = AgentTraceEvent.create(sequence=2, project_id="P1", round=1, event_type="FAILURE", payload={}, provenance={"producer": "test"})
    with pytest.raises(ValueError, match="contiguous"):
        trace.append_event(skipped)


def test_trace_schema_accepts_event() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    event = AgentTraceEvent.create(sequence=1, project_id="P1", round=0, event_type="INITIAL_OBSERVATION", payload={}, provenance={"producer": "test"})
    schema = json.loads((ROOT / "schemas" / "work1_agent_trace.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(event.to_dict())
