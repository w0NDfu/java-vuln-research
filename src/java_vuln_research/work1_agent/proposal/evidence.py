from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from .model import canonical_json, stable_digest


class EvidenceSourceKind(str, Enum):
    SOURCE_SNIPPET = "SOURCE_SNIPPET"
    PROGRAM_ENTITY = "PROGRAM_ENTITY"
    REPOSITORY_RELATION = "REPOSITORY_RELATION"
    REPOSITORY_TOOL_RESULT = "REPOSITORY_TOOL_RESULT"
    CODEQL_ENTITY_FACT = "CODEQL_ENTITY_FACT"
    CODEQL_CALL = "CODEQL_CALL"
    CODEQL_LOCAL_FLOW = "CODEQL_LOCAL_FLOW"
    CODEQL_DATAFLOW = "CODEQL_DATAFLOW"
    CODEQL_CFG = "CODEQL_CFG"
    TYPE_DECLARATION = "TYPE_DECLARATION"
    ANNOTATION_TEXT = "ANNOTATION_TEXT"


class EvidenceStrength(str, Enum):
    DIRECT = "DIRECT"
    STRONG_STRUCTURAL = "STRONG_STRUCTURAL"
    SUPPORTING = "SUPPORTING"
    WEAK = "WEAK"


DIRECT_SOURCE_KINDS = frozenset(
    {
        EvidenceSourceKind.SOURCE_SNIPPET,
        EvidenceSourceKind.PROGRAM_ENTITY,
        EvidenceSourceKind.CODEQL_ENTITY_FACT,
        EvidenceSourceKind.CODEQL_CALL,
        EvidenceSourceKind.CODEQL_LOCAL_FLOW,
        EvidenceSourceKind.CODEQL_DATAFLOW,
        EvidenceSourceKind.CODEQL_CFG,
        EvidenceSourceKind.TYPE_DECLARATION,
        EvidenceSourceKind.ANNOTATION_TEXT,
    }
)


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    evidence_id: str
    source_kind: EvidenceSourceKind
    entity_ids: tuple[str, ...]
    confidence: EvidenceStrength
    provenance: Mapping[str, Any]
    repository_relative_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    tool_call_id: str | None = None
    artifact_ref: str | None = None
    content_hash: str | None = None
    result_hash: str | None = None

    def __post_init__(self) -> None:
        if not self.entity_ids:
            raise ValueError("evidence requires at least one entity_id")
        if not isinstance(self.provenance, Mapping) or not self.provenance:
            raise ValueError("evidence provenance is required")
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("evidence line range must provide both start and end")
        if self.start_line is not None and (self.start_line < 1 or self.end_line < self.start_line):
            raise ValueError("evidence line range must be positive and ordered")
        if self.confidence == EvidenceStrength.DIRECT and self.source_kind not in DIRECT_SOURCE_KINDS:
            raise ValueError("DIRECT strength requires CodeQL, source, or explicit structural fact")
        expected = self.compute_id(
            source_kind=self.source_kind,
            entity_ids=self.entity_ids,
            repository_relative_path=self.repository_relative_path,
            start_line=self.start_line,
            end_line=self.end_line,
            tool_call_id=self.tool_call_id,
            artifact_ref=self.artifact_ref,
            content_hash=self.content_hash,
            result_hash=self.result_hash,
        )
        if self.evidence_id != expected:
            raise ValueError(f"evidence_id is not canonical; expected {expected}")

    @staticmethod
    def compute_id(**values: Any) -> str:
        material = {
            "source_kind": EvidenceSourceKind(values["source_kind"]).value,
            "entity_ids": sorted(str(item) for item in values["entity_ids"]),
            "repository_relative_path": values.get("repository_relative_path"),
            "start_line": values.get("start_line"),
            "end_line": values.get("end_line"),
            "tool_call_id": values.get("tool_call_id"),
            "artifact_ref": values.get("artifact_ref"),
            "content_hash": values.get("content_hash"),
            "result_hash": values.get("result_hash"),
        }
        return stable_digest("evidence", material)

    @classmethod
    def create(
        cls,
        *,
        source_kind: EvidenceSourceKind | str,
        entity_ids: Sequence[str],
        confidence: EvidenceStrength | str,
        provenance: Mapping[str, Any],
        repository_relative_path: str | None = None,
        start_line: int | None = None,
        end_line: int | None = None,
        tool_call_id: str | None = None,
        artifact_ref: str | None = None,
        content_hash: str | None = None,
        result_hash: str | None = None,
    ) -> "EvidenceRef":
        values = {
            "source_kind": EvidenceSourceKind(source_kind),
            "entity_ids": tuple(str(item) for item in entity_ids),
            "repository_relative_path": repository_relative_path,
            "start_line": start_line,
            "end_line": end_line,
            "tool_call_id": tool_call_id,
            "artifact_ref": artifact_ref,
            "content_hash": content_hash,
            "result_hash": result_hash,
        }
        return cls(
            evidence_id=cls.compute_id(**values),
            confidence=EvidenceStrength(confidence),
            provenance=dict(provenance),
            **values,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvidenceRef":
        return cls(
            evidence_id=str(value["evidence_id"]),
            source_kind=EvidenceSourceKind(value["source_kind"]),
            entity_ids=tuple(str(item) for item in value["entity_ids"]),
            repository_relative_path=str(value["repository_relative_path"]) if value.get("repository_relative_path") is not None else None,
            start_line=int(value["start_line"]) if value.get("start_line") is not None else None,
            end_line=int(value["end_line"]) if value.get("end_line") is not None else None,
            tool_call_id=str(value["tool_call_id"]) if value.get("tool_call_id") is not None else None,
            artifact_ref=str(value["artifact_ref"]) if value.get("artifact_ref") is not None else None,
            content_hash=str(value["content_hash"]) if value.get("content_hash") is not None else None,
            result_hash=str(value["result_hash"]) if value.get("result_hash") is not None else None,
            confidence=EvidenceStrength(value["confidence"]),
            provenance=dict(value["provenance"]),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_kind": self.source_kind.value,
            "entity_ids": list(self.entity_ids),
            "repository_relative_path": self.repository_relative_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "tool_call_id": self.tool_call_id,
            "artifact_ref": self.artifact_ref,
            "content_hash": self.content_hash,
            "result_hash": self.result_hash,
            "confidence": self.confidence.value,
            "provenance": dict(self.provenance),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())
