from __future__ import annotations

from pathlib import Path

import pytest

from java_vuln_research.work1_agent.m8_multiagent import build_role_guidance, build_valid_scope
from java_vuln_research.work1_agent.proposal import (
    EntityRole,
    EntityRoleRef,
    EvidenceGate,
    EvidenceRef,
    EvidenceSourceKind,
    EvidenceStrength,
    GateStatus,
    ProposalType,
    SecurityProposal,
)
from java_vuln_research.work1_agent.proposal.roles import validate_role
from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import build_repository_index


FIXTURE = Path(__file__).parents[1] / "fixtures" / "work1_agent_m4"


@pytest.fixture(scope="module")
def indexed():
    return build_repository_index(FIXTURE)


def _one(indexed, kind: ProgramEntityKind, name: str, *, enclosing: str | None = None) -> ProgramEntity:
    matches = [
        item
        for item in indexed.entities
        if item.kind == kind
        and item.simple_name == name
        and (enclosing is None or item.enclosing_type == enclosing)
    ]
    assert len(matches) == 1
    return matches[0]


def _roles(preview, anchor: str) -> set[tuple[EntityRole, int | None]]:
    return {(item.role, item.index) for item in preview.legal_anchor_roles[anchor]}


def test_external_input_guidance_exposes_legal_parameter_and_return_roles(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "customExternalInput")
    preview = build_role_guidance(
        indexed,
        entity=method,
        proposal_type=ProposalType.EXTERNAL_INPUT,
        observed_source_structure={"inspection": "METHOD_BODY_PRESENT"},
    )
    subject_roles = _roles(preview, "subject")
    assert (EntityRole.PARAMETER, 0) in subject_roles
    assert (EntityRole.RETURN, None) in subject_roles
    assert preview.required_anchors == ("subject",)
    assert preview.forbidden_anchors == ("source", "target")
    assert preview.legal_anchor_roles["source"] == ()
    assert preview.observed_source_structure == {"inspection": "METHOD_BODY_PRESENT"}
    assert preview.schema_example["subject"] == {
        "entity_id": method.entity_id,
        "role": "PARAMETER",
        "index": 0,
    }


def test_call_argument_indexes_are_bounded_by_indexed_structure(indexed) -> None:
    call = _one(indexed, ProgramEntityKind.CALL, "writeString")
    preview = build_role_guidance(indexed, entity=call, proposal_type=ProposalType.SECURITY_EFFECT)
    argument_roles = sorted(index for role, index in _roles(preview, "subject") if role == EntityRole.ARGUMENT)
    indexed_count = int(call.provenance["argument_count"])
    assert argument_roles == list(range(indexed_count))
    assert preview.schema_example["subject"]["role"] == "ARGUMENT"
    entities = {item.entity_id: item for item in indexed.entities}
    assert validate_role(EntityRoleRef(call.entity_id, EntityRole.ARGUMENT, indexed_count), entities) == (
        False,
        "ARGUMENT_INDEX_OUT_OF_RANGE",
    )


def test_field_state_guidance_repairs_old_shape_failure_and_passes_original_gate(indexed) -> None:
    field = _one(
        indexed,
        ProgramEntityKind.FIELD,
        "state",
        enclosing="com.example.ControlledSecurityCases",
    )
    preview = build_role_guidance(indexed, entity=field, proposal_type=ProposalType.FIELD_STATE)
    assert _roles(preview, "subject") == {(EntityRole.FIELD, None)}
    assert _roles(preview, "source") == {(EntityRole.FIELD_WRITE, None)}
    assert _roles(preview, "target") == {(EntityRole.FIELD_READ, None)}
    assert preview.required_anchors == ("subject", "source", "target")

    subject = EntityRoleRef.from_dict(preview.schema_example["subject"])
    source = EntityRoleRef.from_dict(preview.schema_example["source"])
    target = EntityRoleRef.from_dict(preview.schema_example["target"])
    scope = build_valid_scope(
        indexed,
        project_id="CONTROLLED",
        subject=subject,
        source=source,
        target=target,
        proposal_type=ProposalType.FIELD_STATE,
    ).scope
    evidence = EvidenceRef.create(
        source_kind=EvidenceSourceKind.PROGRAM_ENTITY,
        entity_ids=(field.entity_id,),
        confidence=EvidenceStrength.DIRECT,
        provenance={"producer": "M8_ROLE_HELPER_TEST"},
    )
    proposal = SecurityProposal.create(
        proposal_type=ProposalType.FIELD_STATE,
        subject=subject,
        source=source,
        target=target,
        scope=scope,
        evidence_refs=(evidence.evidence_id,),
        reason="Structural field-state hypothesis; admission is not confirmation.",
        provenance={"producer": "M8_ROLE_HELPER_TEST"},
    )
    result = EvidenceGate(
        repository_root=FIXTURE,
        entities=indexed.entities,
        evidence_catalog={evidence.evidence_id: evidence},
    ).evaluate(proposal)
    assert result.status == GateStatus.ADMISSIBLE
    assert next(item for item in result.checks if item.check == "ROLE_COMPATIBILITY").status.value == "PASS"


def test_callback_target_roles_are_contract_limited(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "trigger")
    preview = build_role_guidance(indexed, entity=method, proposal_type=ProposalType.CALLBACK_RELATION)
    target_roles = {role for role, _ in _roles(preview, "target")}
    assert target_roles == {EntityRole.METHOD, EntityRole.PARAMETER}
    assert EntityRole.RETURN not in target_roles


def test_role_helper_does_not_make_security_claims_or_accept_unknown_entities(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    preview = build_role_guidance(indexed, entity=method, proposal_type=ProposalType.SECURITY_EFFECT)
    serialized = str(preview.to_dict())
    assert "vulnerability" not in serialized.lower()
    assert "semantic_category" not in preview.schema_example
    with pytest.raises(ValueError, match="not present"):
        build_role_guidance(indexed, entity="entity-missing", proposal_type=ProposalType.EXTERNAL_INPUT)
