"""Proposal-specific structural role guidance for M8 specialists."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from java_vuln_research.work1_agent.proposal.model import EntityRole, EntityRoleRef, ProposalType, canonical_json
from java_vuln_research.work1_agent.proposal.roles import validate_role
from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex


ROLE_HELPER_VERSION = "M8_ROLE_HELPER_V1"


class ProposalAnchor(str, Enum):
    SUBJECT = "subject"
    SOURCE = "source"
    TARGET = "target"


@dataclass(frozen=True, slots=True)
class RoleOption:
    role: EntityRole
    index: int | None = None

    def to_ref(self, entity_id: str) -> EntityRoleRef:
        return EntityRoleRef(entity_id, self.role, self.index)

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"role": self.role.value}
        if self.index is not None:
            result["index"] = self.index
        return result


@dataclass(frozen=True, slots=True)
class RolePreview:
    proposal_type: ProposalType
    entity_id: str
    entity_kind: ProgramEntityKind
    valid_roles: tuple[RoleOption, ...]
    legal_anchor_roles: Mapping[str, tuple[RoleOption, ...]]
    required_anchors: tuple[str, ...]
    optional_anchors: tuple[str, ...]
    forbidden_anchors: tuple[str, ...]
    schema_example: Mapping[str, Any]
    observed_source_structure: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_type": self.proposal_type.value,
            "entity_id": self.entity_id,
            "entity_kind": self.entity_kind.value,
            "valid_roles": [item.to_dict() for item in self.valid_roles],
            "legal_anchor_roles": {
                key: [item.to_dict() for item in value]
                for key, value in self.legal_anchor_roles.items()
            },
            "required_anchors": list(self.required_anchors),
            "optional_anchors": list(self.optional_anchors),
            "forbidden_anchors": list(self.forbidden_anchors),
            "schema_example": dict(self.schema_example),
            "observed_source_structure": dict(self.observed_source_structure),
        }


_ALL_ROLES = frozenset(EntityRole)
_ANCHOR_CONTRACTS: dict[ProposalType, dict[ProposalAnchor, frozenset[EntityRole]]] = {
    ProposalType.EXTERNAL_INPUT: {
        ProposalAnchor.SUBJECT: _ALL_ROLES,
        ProposalAnchor.SOURCE: frozenset(),
        ProposalAnchor.TARGET: frozenset(),
    },
    ProposalType.SECURITY_EFFECT: {
        ProposalAnchor.SUBJECT: _ALL_ROLES,
        ProposalAnchor.SOURCE: frozenset(),
        ProposalAnchor.TARGET: frozenset(),
    },
    ProposalType.WRAPPER_FLOW: {anchor: _ALL_ROLES for anchor in ProposalAnchor},
    ProposalType.LIBRARY_FLOW: {anchor: _ALL_ROLES for anchor in ProposalAnchor},
    ProposalType.FIELD_STATE: {
        ProposalAnchor.SUBJECT: frozenset({EntityRole.FIELD}),
        ProposalAnchor.SOURCE: frozenset({EntityRole.FIELD_WRITE, EntityRole.ARGUMENT, EntityRole.PARAMETER}),
        ProposalAnchor.TARGET: frozenset({EntityRole.FIELD_READ, EntityRole.RETURN}),
    },
    ProposalType.FRAMEWORK_RELATION: {anchor: _ALL_ROLES for anchor in ProposalAnchor},
    ProposalType.CALLBACK_RELATION: {
        ProposalAnchor.SUBJECT: _ALL_ROLES,
        ProposalAnchor.SOURCE: _ALL_ROLES,
        ProposalAnchor.TARGET: frozenset({EntityRole.METHOD, EntityRole.PARAMETER, EntityRole.ARGUMENT}),
    },
}

_REQUIRED = {
    ProposalType.EXTERNAL_INPUT: (ProposalAnchor.SUBJECT,),
    ProposalType.SECURITY_EFFECT: (ProposalAnchor.SUBJECT,),
    ProposalType.WRAPPER_FLOW: tuple(ProposalAnchor),
    ProposalType.LIBRARY_FLOW: tuple(ProposalAnchor),
    ProposalType.FIELD_STATE: tuple(ProposalAnchor),
    ProposalType.FRAMEWORK_RELATION: (ProposalAnchor.SUBJECT, ProposalAnchor.TARGET),
    ProposalType.CALLBACK_RELATION: (ProposalAnchor.SUBJECT, ProposalAnchor.TARGET),
}

_OPTIONAL = {
    ProposalType.FRAMEWORK_RELATION: (ProposalAnchor.SOURCE,),
    ProposalType.CALLBACK_RELATION: (ProposalAnchor.SOURCE,),
}

_ROLE_PRIORITY = {
    ProposalAnchor.SUBJECT: (
        EntityRole.FIELD,
        EntityRole.METHOD,
        EntityRole.CONSTRUCTOR,
        EntityRole.CALL,
        EntityRole.PARAMETER,
        EntityRole.ARGUMENT,
        EntityRole.RETURN,
        EntityRole.CALL_RESULT,
        EntityRole.RECEIVER,
        EntityRole.FIELD_READ,
        EntityRole.FIELD_WRITE,
        EntityRole.ENTITY,
    ),
    ProposalAnchor.SOURCE: (
        EntityRole.FIELD_WRITE,
        EntityRole.PARAMETER,
        EntityRole.ARGUMENT,
        EntityRole.RECEIVER,
        EntityRole.FIELD_READ,
        EntityRole.CALL_RESULT,
        EntityRole.CALL,
        EntityRole.METHOD,
        EntityRole.CONSTRUCTOR,
        EntityRole.FIELD,
        EntityRole.RETURN,
        EntityRole.ENTITY,
    ),
    ProposalAnchor.TARGET: (
        EntityRole.FIELD_READ,
        EntityRole.RETURN,
        EntityRole.METHOD,
        EntityRole.PARAMETER,
        EntityRole.ARGUMENT,
        EntityRole.CALL_RESULT,
        EntityRole.RECEIVER,
        EntityRole.FIELD_WRITE,
        EntityRole.CALL,
        EntityRole.CONSTRUCTOR,
        EntityRole.FIELD,
        EntityRole.ENTITY,
    ),
}

_PROPOSAL_ROLE_PRIORITY = {
    (ProposalType.EXTERNAL_INPUT, ProposalAnchor.SUBJECT): (
        EntityRole.PARAMETER,
        EntityRole.RETURN,
        EntityRole.ARGUMENT,
        EntityRole.CALL_RESULT,
        EntityRole.FIELD_READ,
        EntityRole.FIELD,
    ),
    (ProposalType.SECURITY_EFFECT, ProposalAnchor.SUBJECT): (
        EntityRole.ARGUMENT,
        EntityRole.RECEIVER,
        EntityRole.CALL,
        EntityRole.CALL_RESULT,
        EntityRole.PARAMETER,
        EntityRole.FIELD_WRITE,
    ),
    (ProposalType.WRAPPER_FLOW, ProposalAnchor.SOURCE): (
        EntityRole.PARAMETER,
        EntityRole.ARGUMENT,
        EntityRole.RECEIVER,
        EntityRole.FIELD_READ,
    ),
    (ProposalType.WRAPPER_FLOW, ProposalAnchor.TARGET): (
        EntityRole.RETURN,
        EntityRole.CALL_RESULT,
        EntityRole.FIELD_WRITE,
    ),
    (ProposalType.LIBRARY_FLOW, ProposalAnchor.SOURCE): (
        EntityRole.ARGUMENT,
        EntityRole.RECEIVER,
        EntityRole.PARAMETER,
    ),
    (ProposalType.LIBRARY_FLOW, ProposalAnchor.TARGET): (
        EntityRole.CALL_RESULT,
        EntityRole.RETURN,
        EntityRole.FIELD_WRITE,
    ),
}


def _candidate_refs(entity: ProgramEntity, entities: Mapping[str, ProgramEntity]) -> tuple[EntityRoleRef, ...]:
    result: list[EntityRoleRef] = []
    for role in EntityRole:
        if role == EntityRole.ARGUMENT:
            indexes = range(max(0, int(entity.provenance.get("argument_count", 0))))
        elif role == EntityRole.PARAMETER:
            if entity.kind == ProgramEntityKind.PARAMETER:
                index = int(entity.provenance.get("parameter_index", -1))
                indexes = (index,) if index >= 0 else ()
            elif entity.kind in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}:
                identity = f"{entity.qualified_name}{(entity.signature or '')[len(entity.simple_name):]}"
                indexes = sorted(
                    {
                        int(item.provenance["parameter_index"])
                        for item in entities.values()
                        if item.kind == ProgramEntityKind.PARAMETER
                        and item.enclosing_callable == identity
                        and "parameter_index" in item.provenance
                    }
                )
            else:
                indexes = ()
        else:
            indexes = (None,)
        for index in indexes:
            ref = EntityRoleRef(entity.entity_id, role, index)
            valid, _ = validate_role(ref, entities)
            if valid:
                result.append(ref)
    return tuple(result)


def _ordered_options(
    refs: tuple[EntityRoleRef, ...],
    anchor: ProposalAnchor,
    proposal_type: ProposalType,
) -> tuple[RoleOption, ...]:
    allowed = _ANCHOR_CONTRACTS[proposal_type][anchor]
    preferred = _PROPOSAL_ROLE_PRIORITY.get((proposal_type, anchor), ())
    order = tuple(dict.fromkeys((*preferred, *_ROLE_PRIORITY[anchor])))
    priority = {role: position for position, role in enumerate(order)}
    options = [RoleOption(item.role, item.index) for item in refs if item.role in allowed]
    return tuple(sorted(options, key=lambda item: (priority[item.role], item.index if item.index is not None else -1)))


def _schema_example(
    proposal_type: ProposalType,
    entity_id: str,
    legal: Mapping[str, tuple[RoleOption, ...]],
) -> dict[str, Any]:
    example: dict[str, Any] = {"proposal_type": proposal_type.value}
    for anchor in ProposalAnchor:
        choices = legal[anchor.value]
        if anchor in _REQUIRED[proposal_type]:
            if choices:
                example[anchor.value] = choices[0].to_ref(entity_id).to_dict()
            else:
                example[anchor.value] = {"entity_id": f"<{anchor.value}-entity-id>", "role": "<legal-role>"}
        elif anchor in _OPTIONAL.get(proposal_type, ()):
            example[anchor.value] = None
    return example


def build_role_guidance(
    repository_index: RepositoryIndex,
    *,
    entity: ProgramEntity | str,
    proposal_type: ProposalType | str,
    observed_source_structure: Mapping[str, Any] | None = None,
) -> RolePreview:
    """Describe M4-legal roles without deciding whether any role is security-relevant."""

    entities = {item.entity_id: item for item in repository_index.entities}
    entity_id = entity.entity_id if isinstance(entity, ProgramEntity) else str(entity).strip()
    indexed = entities.get(entity_id)
    if indexed is None:
        raise ValueError(f"role entity is not present in RepositoryIndex: {entity_id}")
    if isinstance(entity, ProgramEntity) and entity.to_dict() != indexed.to_dict():
        raise ValueError(f"role entity content differs from RepositoryIndex: {entity_id}")
    resolved_type = ProposalType(proposal_type)
    observed = dict(observed_source_structure or {})
    canonical_json(observed)
    refs = _candidate_refs(indexed, entities)
    valid_roles = tuple(RoleOption(item.role, item.index) for item in refs)

    legal: dict[str, tuple[RoleOption, ...]] = {}
    for anchor in ProposalAnchor:
        legal[anchor.value] = _ordered_options(refs, anchor, resolved_type)
    required = _REQUIRED[resolved_type]
    optional = _OPTIONAL.get(resolved_type, ())
    forbidden = tuple(
        anchor
        for anchor in ProposalAnchor
        if not _ANCHOR_CONTRACTS[resolved_type][anchor]
    )
    return RolePreview(
        proposal_type=resolved_type,
        entity_id=indexed.entity_id,
        entity_kind=indexed.kind,
        valid_roles=valid_roles,
        legal_anchor_roles=legal,
        required_anchors=tuple(item.value for item in required),
        optional_anchors=tuple(item.value for item in optional),
        forbidden_anchors=tuple(item.value for item in forbidden),
        schema_example=_schema_example(resolved_type, indexed.entity_id, legal),
        observed_source_structure=observed,
    )
