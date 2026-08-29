from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


class ToolStatus(str, Enum):
    OK = "OK"
    EMPTY = "EMPTY"
    ERROR = "ERROR"
    UNSUPPORTED = "UNSUPPORTED"
    ENTITY_NOT_MAPPED = "ENTITY_NOT_MAPPED"


class FailureReason(str, Enum):
    CODEQL_UNAVAILABLE = "CODEQL_UNAVAILABLE"
    DB_NOT_FOUND = "DB_NOT_FOUND"
    DB_NOT_READY = "DB_NOT_READY"
    QUERY_NOT_FOUND = "QUERY_NOT_FOUND"
    QUERY_COMPILE_ERROR = "QUERY_COMPILE_ERROR"
    QUERY_EXECUTION_ERROR = "QUERY_EXECUTION_ERROR"
    TIMEOUT = "TIMEOUT"
    OOM = "OOM"
    BQRS_DECODE_ERROR = "BQRS_DECODE_ERROR"
    OUTPUT_PARSE_ERROR = "OUTPUT_PARSE_ERROR"


class EvidenceKind(str, Enum):
    # M2 lexical evidence. Kept here so serialized consumers cannot collapse it
    # into CodeQL-backed evidence by accident.
    LEXICAL_CALL = "LEXICAL_CALL"
    CALL_CANDIDATE = "CALL_CANDIDATE"
    EXTENDS_TEXT = "EXTENDS_TEXT"
    IMPLEMENTS_TEXT = "IMPLEMENTS_TEXT"
    OVERRIDE_CANDIDATE = "OVERRIDE_CANDIDATE"
    # M3 deterministic evidence.
    CODEQL_ENTITY_FACT = "CODEQL_ENTITY_FACT"
    CODEQL_CALL = "CODEQL_CALL"
    CODEQL_LOCAL_FLOW = "CODEQL_LOCAL_FLOW"
    CODEQL_DATAFLOW = "CODEQL_DATAFLOW"
    CODEQL_CFG = "CODEQL_CFG"
    CODEQL_RETURN = "CODEQL_RETURN"
    CODEQL_PARAMETER = "CODEQL_PARAMETER"


@dataclass(frozen=True, slots=True)
class ToolFailure:
    reason: FailureReason
    message: str
    exit_code: int | None = None


@dataclass(slots=True)
class CodeQLToolResult:
    tool_call_id: str
    tool_name: str
    status: ToolStatus
    queried_entity_ids: list[str] = field(default_factory=list)
    mapped_codeql_entities: list[dict[str, Any]] = field(default_factory=list)
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    truncated: bool = False
    warnings: list[str] = field(default_factory=list)
    failure: ToolFailure | None = None
    provenance: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.status == ToolStatus.ERROR and self.failure is None:
            raise ValueError("ERROR results require failure")
        if self.status != ToolStatus.ERROR and self.failure is not None:
            raise ValueError("failure is only valid for ERROR results")
        if self.status == ToolStatus.EMPTY and (self.nodes or self.edges):
            raise ValueError("EMPTY results cannot contain nodes or edges")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["status"] = self.status.value
        if self.failure is not None:
            value["failure"]["reason"] = self.failure.reason.value
        return value

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def bounded_text(value: str | None, limit: int) -> str:
    text = value or ""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"
