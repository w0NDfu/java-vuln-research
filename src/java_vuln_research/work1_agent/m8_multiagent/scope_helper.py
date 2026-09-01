"""Deterministic bounded-scope construction for M8 proposals."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from java_vuln_research.work1_agent.proposal.model import (
    EntityRoleRef,
    ProposalScope,
    ProposalType,
    ScopeKind,
)
from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex


class ScopeBasis(str, Enum):
    ENTITY_LOCAL = "ENTITY_LOCAL"
    CALLABLE_LOCAL = "CALLABLE_LOCAL"
    TYPE_LOCAL = "TYPE_LOCAL"
    FILE_LOCAL = "FILE_LOCAL"
    BOUNDED_EXPLICIT = "BOUNDED_EXPLICIT"


Anchor = ProgramEntity | EntityRoleRef | str


@dataclass(frozen=True, slots=True)
class ScopePreview:
    scope: ProposalScope
    basis: ScopeBasis
    anchor_entity_ids: tuple[str, ...]
    covered_anchor_ids: tuple[str, ...]
    owner_entity_id: str | None
    repository_relative_path: str | None
    enclosing_callable: str | None
    enclosing_type: str | None
    why_smaller_scope_invalid: tuple[str, ...]
    preferred_scope: str | None = None
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope": self.scope.to_dict(),
            "basis": self.basis.value,
            "anchor_entity_ids": list(self.anchor_entity_ids),
            "covered_anchor_ids": list(self.covered_anchor_ids),
            "owner_entity_id": self.owner_entity_id,
            "repository_relative_path": self.repository_relative_path,
            "enclosing_callable": self.enclosing_callable,
            "enclosing_type": self.enclosing_type,
            "why_smaller_scope_invalid": list(self.why_smaller_scope_invalid),
            "preferred_scope": self.preferred_scope,
            "warnings": list(self.warnings),
        }


def _callable_identity(entity: ProgramEntity) -> str | None:
    if entity.kind in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}:
        signature = entity.signature or entity.simple_name
        suffix = signature[len(entity.simple_name) :] if signature.startswith(entity.simple_name) else signature
        return f"{entity.qualified_name}{suffix}"
    return entity.enclosing_callable


def _type_identity(entity: ProgramEntity) -> str | None:
    if entity.kind == ProgramEntityKind.TYPE:
        return entity.qualified_name
    return entity.enclosing_type


def _resolve_anchor(anchor: Anchor, entities: dict[str, ProgramEntity]) -> ProgramEntity:
    entity_id = (
        anchor.entity_id
        if isinstance(anchor, (ProgramEntity, EntityRoleRef))
        else str(anchor).strip()
    )
    entity = entities.get(entity_id)
    if entity is None:
        raise ValueError(f"scope anchor is not present in RepositoryIndex: {entity_id}")
    if isinstance(anchor, ProgramEntity) and anchor.to_dict() != entity.to_dict():
        raise ValueError(f"scope anchor content differs from RepositoryIndex: {entity_id}")
    return entity


def _common(values: list[str | None]) -> str | None:
    if values and values[0] is not None and all(item == values[0] for item in values):
        return values[0]
    return None


def _owner_entity_id(
    entities: list[ProgramEntity],
    *,
    basis: ScopeBasis,
    callable_identity: str | None,
    type_identity: str | None,
    path: str | None,
) -> str | None:
    if basis == ScopeBasis.ENTITY_LOCAL:
        return entities[0].entity_id
    if basis == ScopeBasis.CALLABLE_LOCAL:
        return next(
            (
                item.entity_id
                for item in entities
                if item.kind in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}
                and _callable_identity(item) == callable_identity
            ),
            None,
        )
    if basis == ScopeBasis.TYPE_LOCAL:
        return next(
            (
                item.entity_id
                for item in entities
                if item.kind == ProgramEntityKind.TYPE and item.qualified_name == type_identity
            ),
            None,
        )
    if basis == ScopeBasis.FILE_LOCAL:
        return next(
            (
                item.entity_id
                for item in entities
                if item.kind == ProgramEntityKind.FILE and item.repository_relative_path == path
            ),
            None,
        )
    return None


def _scope_kind(proposal_type: ProposalType | None, basis: ScopeBasis) -> ScopeKind:
    if proposal_type == ProposalType.FIELD_STATE:
        return ScopeKind.FIELD
    if proposal_type == ProposalType.FRAMEWORK_RELATION:
        return ScopeKind.FRAMEWORK_RELATION
    if proposal_type == ProposalType.CALLBACK_RELATION:
        return ScopeKind.CALLBACK_RELATION
    if basis == ScopeBasis.CALLABLE_LOCAL:
        return ScopeKind.CALLABLE
    return ScopeKind.ENTITY


def build_valid_scope(
    repository_index: RepositoryIndex,
    *,
    project_id: str,
    subject: Anchor,
    source: Anchor | None = None,
    target: Anchor | None = None,
    proposal_type: ProposalType | str | None = None,
    preferred_scope: ScopeBasis | ScopeKind | str | None = None,
) -> ScopePreview:
    """Return the smallest structural scope that covers every proposal anchor."""

    resolved_project = str(project_id).strip()
    if not resolved_project:
        raise ValueError("project_id is required")
    if any(token in resolved_project for token in ("*", "?", "..")):
        raise ValueError("project_id must be bounded and must not contain wildcards or traversal")
    entity_catalog = {item.entity_id: item for item in repository_index.entities}
    raw_anchors = [item for item in (subject, source, target) if item is not None]
    resolved: list[ProgramEntity] = []
    seen: set[str] = set()
    for anchor in raw_anchors:
        entity = _resolve_anchor(anchor, entity_catalog)
        if entity.entity_id not in seen:
            resolved.append(entity)
            seen.add(entity.entity_id)
    if not resolved:
        raise ValueError("at least one scope anchor is required")
    if len(resolved) > 12:
        raise ValueError("scope anchor count exceeds the M4 bounded scope limit")

    common_callable = _common([_callable_identity(item) for item in resolved])
    common_type = _common([_type_identity(item) for item in resolved])
    common_path = _common([item.repository_relative_path for item in resolved])
    if len(resolved) == 1:
        basis = ScopeBasis.ENTITY_LOCAL
    elif common_callable is not None:
        basis = ScopeBasis.CALLABLE_LOCAL
    elif common_type is not None:
        basis = ScopeBasis.TYPE_LOCAL
    elif common_path is not None:
        basis = ScopeBasis.FILE_LOCAL
    else:
        basis = ScopeBasis.BOUNDED_EXPLICIT

    reasons: list[str] = []
    if basis != ScopeBasis.ENTITY_LOCAL:
        reasons.append("ANCHORS_REQUIRE_MULTIPLE_ENTITIES")
    if basis in {ScopeBasis.TYPE_LOCAL, ScopeBasis.FILE_LOCAL, ScopeBasis.BOUNDED_EXPLICIT}:
        reasons.append("ANCHORS_DO_NOT_SHARE_ONE_CALLABLE")
    if basis in {ScopeBasis.FILE_LOCAL, ScopeBasis.BOUNDED_EXPLICIT}:
        reasons.append("ANCHORS_DO_NOT_SHARE_ONE_TYPE")
    if basis == ScopeBasis.BOUNDED_EXPLICIT:
        reasons.append("ANCHORS_DO_NOT_SHARE_ONE_FILE")

    resolved_type = ProposalType(proposal_type) if proposal_type is not None else None
    preferred = preferred_scope.value if isinstance(preferred_scope, (ScopeBasis, ScopeKind)) else (
        str(preferred_scope).strip() if preferred_scope is not None else None
    )
    warnings: list[str] = []
    if preferred and preferred not in {basis.value, _scope_kind(resolved_type, basis).value}:
        warnings.append("PREFERRED_SCOPE_NOT_MINIMAL; MINIMAL_BOUNDED_SCOPE_SELECTED")

    anchor_ids = tuple(item.entity_id for item in resolved)
    scope = ProposalScope(
        kind=_scope_kind(resolved_type, basis),
        entity_ids=anchor_ids,
        project_id=resolved_project,
    )
    return ScopePreview(
        scope=scope,
        basis=basis,
        anchor_entity_ids=anchor_ids,
        covered_anchor_ids=anchor_ids,
        owner_entity_id=_owner_entity_id(
            repository_index.entities,
            basis=basis,
            callable_identity=common_callable,
            type_identity=common_type,
            path=common_path,
        ),
        repository_relative_path=common_path,
        enclosing_callable=common_callable,
        enclosing_type=common_type,
        why_smaller_scope_invalid=tuple(reasons),
        preferred_scope=preferred,
        warnings=tuple(warnings),
    )
