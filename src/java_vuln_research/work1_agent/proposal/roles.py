from __future__ import annotations

from collections.abc import Mapping, Sequence

from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind

from .model import EntityRole, EntityRoleRef


CALLABLE_KINDS = frozenset({ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR})


def _callable_parameter_count(entity: ProgramEntity, entities: Mapping[str, ProgramEntity]) -> int | None:
    if entity.kind not in CALLABLE_KINDS:
        return None
    identity = f"{entity.qualified_name}{(entity.signature or '')[len(entity.simple_name):]}"
    indexes = [
        int(item.provenance["parameter_index"])
        for item in entities.values()
        if item.kind == ProgramEntityKind.PARAMETER
        and item.enclosing_callable == identity
        and "parameter_index" in item.provenance
    ]
    if indexes:
        return max(indexes) + 1
    signature = entity.signature or ""
    if "(" in signature and ")" in signature:
        body = signature.split("(", 1)[1].rsplit(")", 1)[0].strip()
        return 0 if not body else len([part for part in body.split(",") if part.strip()])
    return None


def validate_role(ref: EntityRoleRef, entities: Mapping[str, ProgramEntity]) -> tuple[bool, str | None]:
    entity = entities.get(ref.entity_id)
    if entity is None:
        return False, "ENTITY_NOT_FOUND"
    indexed = ref.role in {EntityRole.ARGUMENT, EntityRole.PARAMETER}
    if indexed != (ref.index is not None):
        return False, "ROLE_INDEX_REQUIRED" if indexed else "ROLE_INDEX_NOT_ALLOWED"
    compatible: dict[EntityRole, frozenset[ProgramEntityKind]] = {
        EntityRole.ENTITY: frozenset(ProgramEntityKind),
        EntityRole.ARGUMENT: frozenset({ProgramEntityKind.CALL}),
        EntityRole.PARAMETER: CALLABLE_KINDS | frozenset({ProgramEntityKind.PARAMETER}),
        EntityRole.RETURN: CALLABLE_KINDS,
        EntityRole.CALL_RESULT: frozenset({ProgramEntityKind.CALL}),
        EntityRole.RECEIVER: frozenset({ProgramEntityKind.CALL, ProgramEntityKind.METHOD}),
        EntityRole.FIELD: frozenset({ProgramEntityKind.FIELD}),
        EntityRole.FIELD_READ: frozenset({ProgramEntityKind.FIELD, ProgramEntityKind.FIELD_READ}),
        EntityRole.FIELD_WRITE: frozenset({ProgramEntityKind.FIELD, ProgramEntityKind.FIELD_WRITE}),
        EntityRole.CALL: frozenset({ProgramEntityKind.CALL}),
        EntityRole.METHOD: frozenset({ProgramEntityKind.METHOD}),
        EntityRole.CONSTRUCTOR: frozenset({ProgramEntityKind.CONSTRUCTOR}),
    }
    if entity.kind not in compatible[ref.role]:
        return False, "ROLE_ENTITY_KIND_MISMATCH"
    if ref.role == EntityRole.ARGUMENT:
        count = entity.provenance.get("argument_count")
        if count is None or ref.index >= int(count):
            return False, "ARGUMENT_INDEX_OUT_OF_RANGE"
    if ref.role == EntityRole.PARAMETER:
        if entity.kind == ProgramEntityKind.PARAMETER:
            if int(entity.provenance.get("parameter_index", -1)) != ref.index:
                return False, "PARAMETER_INDEX_MISMATCH"
        else:
            count = _callable_parameter_count(entity, entities)
            if count is None or ref.index >= count:
                return False, "PARAMETER_INDEX_OUT_OF_RANGE"
    return True, None


def proposal_role_refs(subject: EntityRoleRef, source: EntityRoleRef | None, target: EntityRoleRef | None) -> Sequence[EntityRoleRef]:
    return tuple(item for item in (subject, source, target) if item is not None)


def role_options(entity_id: str, entities: Mapping[str, ProgramEntity]) -> list[dict]:
    """Describe bounded legal endpoints using the same validator as the gate."""
    entity = entities.get(entity_id)
    if entity is None:
        return []
    parameter_count = _callable_parameter_count(entity, entities)
    options = []
    for role in EntityRole:
        if role == EntityRole.PARAMETER:
            indices = ([entity.provenance.get("parameter_index", -1)]
                       if entity.kind == ProgramEntityKind.PARAMETER else range(parameter_count or 0))
        elif role == EntityRole.ARGUMENT:
            indices = range(int(entity.provenance.get("argument_count", 0)))
        else:
            indices = [None]
        for index in list(indices)[:8]:
            ref = EntityRoleRef(entity_id, role, index)
            if validate_role(ref, entities)[0]:
                options.append(ref.to_dict())
    return options


def canonical_role_ref(ref: EntityRoleRef, entities: Mapping[str, ProgramEntity]) -> EntityRoleRef:
    """Unify the two supported representations of the same formal parameter."""
    entity = entities.get(ref.entity_id)
    if entity is None or ref.role != EntityRole.PARAMETER or entity.kind != ProgramEntityKind.PARAMETER:
        return ref
    owners = [
        owner for owner in entities.values()
        if owner.kind in CALLABLE_KINDS and owner.repository_relative_path == entity.repository_relative_path
        and f"{owner.qualified_name}{(owner.signature or '')[len(owner.simple_name):]}" == entity.enclosing_callable
    ]
    if len(owners) == 1:
        return EntityRoleRef(owners[0].entity_id, ref.role, ref.index)
    return ref
