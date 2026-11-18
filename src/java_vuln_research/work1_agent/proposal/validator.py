from __future__ import annotations

from collections.abc import Mapping

from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind

from .model import (
    EXTERNAL_INPUT_CATEGORIES,
    SECURITY_EFFECT_CATEGORIES,
    EntityRole,
    ProposalType,
    SecurityProposal,
)


def validate_proposal_shape(proposal: SecurityProposal, entities: Mapping[str, ProgramEntity]) -> list[str]:
    errors: list[str] = []
    if proposal.proposal_type == ProposalType.EXTERNAL_INPUT:
        if proposal.source is not None or proposal.target is not None:
            errors.append("EXTERNAL_INPUT_HAS_FLOW_ENDPOINTS")
        if proposal.semantic_category not in EXTERNAL_INPUT_CATEGORIES:
            errors.append("INVALID_EXTERNAL_INPUT_CATEGORY")
    elif proposal.proposal_type == ProposalType.SECURITY_EFFECT:
        if proposal.source is not None or proposal.target is not None:
            errors.append("SECURITY_EFFECT_HAS_FLOW_ENDPOINTS")
        if proposal.semantic_category not in SECURITY_EFFECT_CATEGORIES:
            errors.append("INVALID_SECURITY_EFFECT_CATEGORY")
    elif proposal.proposal_type in {ProposalType.WRAPPER_FLOW, ProposalType.LIBRARY_FLOW}:
        if proposal.source is None or proposal.target is None:
            errors.append("FLOW_ENDPOINT_REQUIRED")
        if proposal.scope.kind.value not in {"ENTITY", "CALLABLE"}:
            errors.append("FLOW_SCOPE_MUST_BE_CALLABLE")
    elif proposal.proposal_type == ProposalType.FIELD_STATE:
        if proposal.source is None or proposal.target is None:
            errors.append("FIELD_STATE_ANCHORS_REQUIRED")
        else:
            if proposal.source.role not in {EntityRole.FIELD_WRITE, EntityRole.ARGUMENT, EntityRole.PARAMETER}:
                errors.append("FIELD_STATE_WRITE_ROLE_REQUIRED")
            if proposal.subject.role != EntityRole.FIELD:
                errors.append("FIELD_STATE_FIELD_ROLE_REQUIRED")
            if proposal.target.role not in {EntityRole.FIELD_READ, EntityRole.RETURN}:
                errors.append("FIELD_STATE_READ_ROLE_REQUIRED")
            field_entity = entities.get(proposal.subject.entity_id)
            if field_entity is not None and field_entity.kind != ProgramEntityKind.FIELD:
                errors.append("FIELD_STATE_SUBJECT_NOT_FIELD")
    elif proposal.proposal_type == ProposalType.FRAMEWORK_RELATION:
        if proposal.target is None:
            errors.append("FRAMEWORK_TARGET_REQUIRED")
    elif proposal.proposal_type == ProposalType.CALLBACK_RELATION:
        if proposal.target is None:
            errors.append("CALLBACK_TARGET_REQUIRED")
        if proposal.target is not None and proposal.target.role not in {
            EntityRole.METHOD, EntityRole.PARAMETER, EntityRole.ARGUMENT,
        }:
            errors.append("CALLBACK_TARGET_ROLE_INVALID")
    return errors


def validate_scope(proposal: SecurityProposal) -> list[str]:
    errors: list[str] = []
    serialized = " ".join((*proposal.scope.entity_ids, proposal.scope.project_id or ""))
    if any(token in serialized for token in ("*", "?", "..")):
        errors.append("WILDCARD_OR_UNBOUNDED_SCOPE")
    if len(proposal.scope.entity_ids) > 12:
        errors.append("SCOPE_ENTITY_LIMIT_EXCEEDED")
    anchors = {
        item.entity_id
        for item in (proposal.subject, proposal.source, proposal.target)
        if item is not None
    }
    if not anchors.issubset(set(proposal.scope.entity_ids)):
        errors.append("SCOPE_DOES_NOT_BOUND_ALL_ANCHORS")
    return errors
