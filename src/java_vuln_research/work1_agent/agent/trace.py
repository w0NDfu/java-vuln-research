from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest


TRACE_SCHEMA_VERSION = 1


class TraceEventType(str, Enum):
    INITIAL_OBSERVATION = "INITIAL_OBSERVATION"
    MODEL_CALL = "MODEL_CALL"
    MODEL_RETRY = "MODEL_RETRY"
    ACTION = "ACTION"
    TOOL_RESULT = "TOOL_RESULT"
    EVIDENCE = "EVIDENCE"
    PROPOSAL = "PROPOSAL"
    GATE_RESULT = "GATE_RESULT"
    PATH_FEEDBACK = "PATH_FEEDBACK"
    CONTROLLER_FEEDBACK = "CONTROLLER_FEEDBACK"
    BUDGET = "BUDGET"
    SECURITY_BOUNDARY = "SECURITY_BOUNDARY"
    FAILURE = "FAILURE"
    STOP = "STOP"


@dataclass(frozen=True, slots=True)
class AgentTraceEvent:
    event_id: str
    sequence: int
    project_id: str
    round: int
    event_type: TraceEventType
    payload: Mapping[str, Any]
    provenance: Mapping[str, Any]
    schema_version: int = TRACE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TRACE_SCHEMA_VERSION:
            raise ValueError("unsupported trace schema version")
        if self.sequence < 1 or self.round < 0 or not self.project_id or not self.provenance:
            raise ValueError("trace event identity is invalid")
        expected = self.compute_id(
            sequence=self.sequence,
            project_id=self.project_id,
            round=self.round,
            event_type=self.event_type,
            payload=self.payload,
        )
        if self.event_id != expected:
            raise ValueError(f"event_id is not canonical; expected {expected}")

    @staticmethod
    def compute_id(*, sequence: int, project_id: str, round: int, event_type: TraceEventType | str, payload: Mapping[str, Any]) -> str:
        return stable_digest(
            "trace",
            {
                "schema_version": TRACE_SCHEMA_VERSION,
                "sequence": int(sequence),
                "project_id": project_id,
                "round": int(round),
                "event_type": TraceEventType(event_type).value,
                "payload": dict(payload),
            },
        )

    @classmethod
    def create(cls, *, sequence: int, project_id: str, round: int, event_type: TraceEventType | str, payload: Mapping[str, Any], provenance: Mapping[str, Any]) -> "AgentTraceEvent":
        resolved_type = TraceEventType(event_type)
        return cls(
            event_id=cls.compute_id(sequence=sequence, project_id=project_id, round=round, event_type=resolved_type, payload=payload),
            sequence=sequence,
            project_id=project_id,
            round=round,
            event_type=resolved_type,
            payload=dict(payload),
            provenance=dict(provenance),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AgentTraceEvent":
        return cls(
            event_id=str(value["event_id"]),
            sequence=int(value["sequence"]),
            project_id=str(value["project_id"]),
            round=int(value["round"]),
            event_type=TraceEventType(value["event_type"]),
            payload=dict(value["payload"]),
            provenance=dict(value["provenance"]),
            schema_version=int(value.get("schema_version", TRACE_SCHEMA_VERSION)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "sequence": self.sequence,
            "project_id": self.project_id,
            "round": self.round,
            "event_type": self.event_type.value,
            "payload": dict(self.payload),
            "provenance": dict(self.provenance),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


@dataclass(slots=True)
class AgentTrace:
    project_id: str
    events: list[AgentTraceEvent] = field(default_factory=list)

    def append(self, *, round: int, event_type: TraceEventType | str, payload: Mapping[str, Any], provenance: Mapping[str, Any]) -> AgentTraceEvent:
        event = AgentTraceEvent.create(
            sequence=len(self.events) + 1,
            project_id=self.project_id,
            round=round,
            event_type=event_type,
            payload=payload,
            provenance=provenance,
        )
        self.events.append(event)
        return event

    def append_event(self, event: AgentTraceEvent) -> None:
        if event.project_id != self.project_id:
            raise ValueError("M7 trace is project-local; cross-project event rejected")
        if event.sequence != len(self.events) + 1:
            raise ValueError("trace sequence must be contiguous")
        self.events.append(event)

    def to_jsonl_text(self) -> str:
        return "\n".join(event.to_json() for event in self.events) + ("\n" if self.events else "")

    def write_jsonl(self, path: str | Path) -> None:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_jsonl_text(), encoding="utf-8", newline="\n")

    @classmethod
    def from_jsonl_text(cls, project_id: str, text: str) -> "AgentTrace":
        import json

        trace = cls(project_id)
        for line in text.splitlines():
            if line.strip():
                trace.append_event(AgentTraceEvent.from_dict(json.loads(line)))
        return trace
