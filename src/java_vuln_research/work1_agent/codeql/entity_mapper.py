from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping

from ..repository.entity import ProgramEntity, ProgramEntityKind, normalise_repository_path


class MappingStatus(str, Enum):
    MAPPED_UNIQUE = "MAPPED_UNIQUE"
    MAPPED_AMBIGUOUS = "MAPPED_AMBIGUOUS"
    NOT_MAPPED = "NOT_MAPPED"
    UNSUPPORTED_KIND = "UNSUPPORTED_KIND"


SUPPORTED_KINDS = frozenset(
    {
        ProgramEntityKind.TYPE,
        ProgramEntityKind.METHOD,
        ProgramEntityKind.CONSTRUCTOR,
        ProgramEntityKind.PARAMETER,
        ProgramEntityKind.FIELD,
        ProgramEntityKind.CALL,
        ProgramEntityKind.ANNOTATION,
        ProgramEntityKind.RETURN,
        ProgramEntityKind.LOCAL,
        ProgramEntityKind.CALL_ARGUMENT,
        ProgramEntityKind.FIELD_READ,
        ProgramEntityKind.FIELD_WRITE,
    }
)


@dataclass(frozen=True, slots=True)
class MappingCandidate:
    codeql_identity: str
    kind: str
    repository_relative_path: str
    start_line: int
    end_line: int
    qualified_name: str
    signature: str | None = None
    declaring_type: str | None = None
    enclosing_callable: str | None = None

    @classmethod
    def from_row(cls, row: Mapping[str, Any]) -> "MappingCandidate":
        return cls(
            codeql_identity=str(row["codeql_identity"]),
            kind=str(row["kind"]).upper(),
            repository_relative_path=normalise_repository_path(str(row["repository_relative_path"])),
            start_line=int(row["start_line"]),
            end_line=int(row["end_line"]),
            qualified_name=str(row.get("qualified_name") or ""),
            signature=str(row["signature"]) if row.get("signature") not in {None, ""} else None,
            declaring_type=str(row["declaring_type"]) if row.get("declaring_type") not in {None, ""} else None,
            enclosing_callable=str(row["enclosing_callable"])
            if row.get("enclosing_callable") not in {None, ""}
            else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "codeql_identity": self.codeql_identity,
            "kind": self.kind,
            "repository_relative_path": self.repository_relative_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "qualified_name": self.qualified_name,
            "signature": self.signature,
            "declaring_type": self.declaring_type,
            "enclosing_callable": self.enclosing_callable,
        }


@dataclass(slots=True)
class EntityMappingResult:
    entity_id: str
    status: MappingStatus
    candidate_count: int
    candidates: list[MappingCandidate] = field(default_factory=list)
    codeql_identity: str | None = None
    confidence: str = "NONE"
    mapping_evidence: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "status": self.status.value,
            "candidate_count": self.candidate_count,
            "candidates": [item.to_dict() for item in self.candidates],
            "codeql_identity": self.codeql_identity,
            "confidence": self.confidence,
            "mapping_evidence": list(self.mapping_evidence),
            "provenance": dict(self.provenance),
        }


def _kind_compatible(entity: ProgramEntity, candidate: MappingCandidate) -> bool:
    expected = entity.kind.value
    if expected in {"FIELD_READ", "FIELD_WRITE"}:
        return candidate.kind in {expected, "FIELD_ACCESS"}
    if expected == "CALL_ARGUMENT":
        return candidate.kind in {"CALL_ARGUMENT", "EXPR"}
    return candidate.kind == expected


def _range_overlaps(entity: ProgramEntity, candidate: MappingCandidate) -> bool:
    return candidate.start_line <= entity.end_line and entity.start_line <= candidate.end_line


def map_program_entity(
    entity: ProgramEntity,
    rows: Iterable[MappingCandidate | Mapping[str, Any]],
    *,
    database_id: str | None = None,
    query_hash: str | None = None,
) -> EntityMappingResult:
    """Map using path, range, kind, and identity context; never simple-name only."""

    provenance = {"database_id": database_id, "query_hash": query_hash, "mapper": "WORK1_V11_STRICT_LOCATION_V1"}
    if entity.kind not in SUPPORTED_KINDS:
        return EntityMappingResult(
            entity_id=entity.entity_id,
            status=MappingStatus.UNSUPPORTED_KIND,
            candidate_count=0,
            confidence="NONE",
            mapping_evidence=[f"unsupported ProgramEntity kind: {entity.kind.value}"],
            provenance=provenance,
        )
    candidates = [item if isinstance(item, MappingCandidate) else MappingCandidate.from_row(item) for item in rows]
    filtered = [
        item
        for item in candidates
        if item.repository_relative_path == entity.repository_relative_path
        and _range_overlaps(entity, item)
        and _kind_compatible(entity, item)
    ]
    evidence = ["repository_relative_path exact", "source range overlap", "entity kind compatible"]
    if entity.qualified_name:
        exact_qualified = [item for item in filtered if item.qualified_name == entity.qualified_name]
        if exact_qualified:
            filtered = exact_qualified
            evidence.append("qualified_name exact")
    if entity.signature:
        exact_signature = [item for item in filtered if item.signature == entity.signature]
        if exact_signature:
            filtered = exact_signature
            evidence.append("signature exact")
    if entity.enclosing_type:
        exact_type = [item for item in filtered if item.declaring_type == entity.enclosing_type]
        if exact_type:
            filtered = exact_type
            evidence.append("declaring_type exact")
    if entity.enclosing_callable:
        exact_callable = [item for item in filtered if item.enclosing_callable == entity.enclosing_callable]
        if exact_callable:
            filtered = exact_callable
            evidence.append("enclosing_callable exact")

    if not filtered:
        return EntityMappingResult(
            entity_id=entity.entity_id,
            status=MappingStatus.NOT_MAPPED,
            candidate_count=0,
            confidence="NONE",
            mapping_evidence=evidence,
            provenance=provenance,
        )
    if len(filtered) > 1:
        return EntityMappingResult(
            entity_id=entity.entity_id,
            status=MappingStatus.MAPPED_AMBIGUOUS,
            candidate_count=len(filtered),
            candidates=filtered,
            confidence="AMBIGUOUS",
            mapping_evidence=evidence,
            provenance=provenance,
        )
    return EntityMappingResult(
        entity_id=entity.entity_id,
        status=MappingStatus.MAPPED_UNIQUE,
        candidate_count=1,
        candidates=filtered,
        codeql_identity=filtered[0].codeql_identity,
        confidence="HIGH" if len(evidence) >= 4 else "MEDIUM",
        mapping_evidence=evidence,
        provenance=provenance,
    )
