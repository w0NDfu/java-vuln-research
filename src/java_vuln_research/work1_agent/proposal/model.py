from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


PROPOSAL_SCHEMA_VERSION = 1


class ProposalType(str, Enum):
    EXTERNAL_INPUT = "EXTERNAL_INPUT"
    SECURITY_EFFECT = "SECURITY_EFFECT"
    WRAPPER_FLOW = "WRAPPER_FLOW"
    LIBRARY_FLOW = "LIBRARY_FLOW"
    FIELD_STATE = "FIELD_STATE"
    FRAMEWORK_RELATION = "FRAMEWORK_RELATION"
    CALLBACK_RELATION = "CALLBACK_RELATION"


class EntityRole(str, Enum):
    ENTITY = "ENTITY"
    PARAMETER = "PARAMETER"
    ARGUMENT = "ARGUMENT"
    RETURN = "RETURN"
    CALL_RESULT = "CALL_RESULT"
    RECEIVER = "RECEIVER"
    FIELD = "FIELD"
    FIELD_READ = "FIELD_READ"
    FIELD_WRITE = "FIELD_WRITE"
    CALL = "CALL"
    METHOD = "METHOD"
    CONSTRUCTOR = "CONSTRUCTOR"


class ScopeKind(str, Enum):
    ENTITY = "ENTITY"
    CALLABLE = "CALLABLE"
    FIELD = "FIELD"
    FRAMEWORK_RELATION = "FRAMEWORK_RELATION"
    CALLBACK_RELATION = "CALLBACK_RELATION"


EXTERNAL_INPUT_CATEGORIES = frozenset(
    {
        "HTTP", "RPC", "MESSAGE", "FILE", "ENVIRONMENT", "COMMAND_LINE",
        "DESERIALIZED_INPUT", "FRAMEWORK_INPUT", "OTHER", "UNKNOWN",
    }
)
SECURITY_EFFECT_CATEGORIES = frozenset(
    {
        "FILESYSTEM", "PROCESS_EXECUTION", "NETWORK", "DATABASE",
        "DESERIALIZATION", "DYNAMIC_CODE", "TEMPLATE_OR_EXPRESSION",
        "REDIRECT_OR_RESPONSE", "AUTHORIZATION_RELEVANT", "OTHER", "UNKNOWN",
    }
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_digest(prefix: str, value: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{digest}"


@dataclass(frozen=True, slots=True)
class EntityRoleRef:
    entity_id: str
    role: EntityRole
    index: int | None = None

    def __post_init__(self) -> None:
        if not self.entity_id:
            raise ValueError("entity_id is required")
        if self.index is not None and self.index < 0:
            raise ValueError("role index must be non-negative")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EntityRoleRef":
        return cls(
            entity_id=str(value["entity_id"]),
            role=EntityRole(value["role"]),
            index=int(value["index"]) if value.get("index") is not None else None,
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"entity_id": self.entity_id, "role": self.role.value}
        if self.index is not None:
            result["index"] = self.index
        return result


@dataclass(frozen=True, slots=True)
class ProposalScope:
    kind: ScopeKind
    entity_ids: tuple[str, ...]
    project_id: str | None = None

    def __post_init__(self) -> None:
        if not self.entity_ids or any(not item for item in self.entity_ids):
            raise ValueError("scope requires explicit entity_ids")
        if len(set(self.entity_ids)) != len(self.entity_ids):
            raise ValueError("scope entity_ids must be unique")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProposalScope":
        return cls(
            kind=ScopeKind(value["kind"]),
            entity_ids=tuple(str(item) for item in value["entity_ids"]),
            project_id=str(value["project_id"]) if value.get("project_id") is not None else None,
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"kind": self.kind.value, "entity_ids": list(self.entity_ids)}
        if self.project_id is not None:
            result["project_id"] = self.project_id
        return result


@dataclass(frozen=True, slots=True)
class SecurityProposal:
    proposal_id: str
    proposal_type: ProposalType
    subject: EntityRoleRef
    scope: ProposalScope
    evidence_refs: tuple[str, ...]
    reason: str
    provenance: Mapping[str, Any]
    source: EntityRoleRef | None = None
    target: EntityRoleRef | None = None
    semantic_category: str | None = None
    model_confidence: float | None = None

    def __post_init__(self) -> None:
        if not self.reason.strip():
            raise ValueError("reason is required")
        if not isinstance(self.provenance, Mapping) or not self.provenance:
            raise ValueError("provenance is required")
        if self.model_confidence is not None and not 0 <= self.model_confidence <= 1:
            raise ValueError("model_confidence must be between 0 and 1")
        expected = self.compute_id(
            proposal_type=self.proposal_type,
            subject=self.subject,
            source=self.source,
            target=self.target,
            scope=self.scope,
            semantic_category=self.semantic_category,
        )
        if self.proposal_id != expected:
            raise ValueError(f"proposal_id is not canonical; expected {expected}")

    @staticmethod
    def compute_id(
        *,
        proposal_type: ProposalType,
        subject: EntityRoleRef,
        scope: ProposalScope,
        source: EntityRoleRef | None = None,
        target: EntityRoleRef | None = None,
        semantic_category: str | None = None,
    ) -> str:
        material = {
            "schema_version": PROPOSAL_SCHEMA_VERSION,
            "proposal_type": proposal_type.value,
            "subject": subject.to_dict(),
            "source": source.to_dict() if source else None,
            "target": target.to_dict() if target else None,
            "scope": scope.to_dict(),
            "semantic_category": semantic_category,
        }
        return stable_digest("proposal", material)

    @classmethod
    def create(
        cls,
        *,
        proposal_type: ProposalType | str,
        subject: EntityRoleRef,
        scope: ProposalScope,
        evidence_refs: Sequence[str],
        reason: str,
        provenance: Mapping[str, Any],
        source: EntityRoleRef | None = None,
        target: EntityRoleRef | None = None,
        semantic_category: str | None = None,
        model_confidence: float | None = None,
    ) -> "SecurityProposal":
        resolved_type = ProposalType(proposal_type)
        proposal_id = cls.compute_id(
            proposal_type=resolved_type,
            subject=subject,
            source=source,
            target=target,
            scope=scope,
            semantic_category=semantic_category,
        )
        return cls(
            proposal_id=proposal_id,
            proposal_type=resolved_type,
            subject=subject,
            source=source,
            target=target,
            scope=scope,
            semantic_category=semantic_category,
            evidence_refs=tuple(str(item) for item in evidence_refs),
            reason=reason,
            model_confidence=model_confidence,
            provenance=dict(provenance),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SecurityProposal":
        return cls(
            proposal_id=str(value["proposal_id"]),
            proposal_type=ProposalType(value["proposal_type"]),
            subject=EntityRoleRef.from_dict(value["subject"]),
            source=EntityRoleRef.from_dict(value["source"]) if value.get("source") else None,
            target=EntityRoleRef.from_dict(value["target"]) if value.get("target") else None,
            scope=ProposalScope.from_dict(value["scope"]),
            semantic_category=str(value["semantic_category"]) if value.get("semantic_category") is not None else None,
            evidence_refs=tuple(str(item) for item in value.get("evidence_refs", ())),
            reason=str(value["reason"]),
            model_confidence=float(value["model_confidence"]) if value.get("model_confidence") is not None else None,
            provenance=dict(value["provenance"]),
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "proposal_id": self.proposal_id,
            "proposal_type": self.proposal_type.value,
            "subject": self.subject.to_dict(),
            "source": self.source.to_dict() if self.source else None,
            "target": self.target.to_dict() if self.target else None,
            "scope": self.scope.to_dict(),
            "semantic_category": self.semantic_category,
            "evidence_refs": list(self.evidence_refs),
            "reason": self.reason,
            "model_confidence": self.model_confidence,
            "provenance": dict(self.provenance),
        }
        return result

    def to_json(self) -> str:
        return canonical_json(self.to_dict())
