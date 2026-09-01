from __future__ import annotations

from pathlib import Path

import pytest

from java_vuln_research.work1_agent.m8_multiagent import ScopeBasis, build_valid_scope
from java_vuln_research.work1_agent.proposal import (
    EntityRole,
    EntityRoleRef,
    ProposalType,
    ScopeKind,
    SecurityProposal,
)
from java_vuln_research.work1_agent.proposal.validator import validate_scope
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


def test_external_input_scope_repairs_missing_anchor_without_widening(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "customExternalInput")
    preview = build_valid_scope(
        indexed,
        project_id="CONTROLLED",
        subject=EntityRoleRef(method.entity_id, EntityRole.RETURN),
        proposal_type=ProposalType.EXTERNAL_INPUT,
        preferred_scope=ScopeBasis.CALLABLE_LOCAL,
    )
    assert preview.basis == ScopeBasis.ENTITY_LOCAL
    assert preview.scope.kind == ScopeKind.ENTITY
    assert preview.scope.entity_ids == (method.entity_id,)
    assert preview.covered_anchor_ids == (method.entity_id,)
    assert preview.warnings == ("PREFERRED_SCOPE_NOT_MINIMAL; MINIMAL_BOUNDED_SCOPE_SELECTED",)

    proposal = SecurityProposal.create(
        proposal_type=ProposalType.EXTERNAL_INPUT,
        subject=EntityRoleRef(method.entity_id, EntityRole.RETURN),
        scope=preview.scope,
        evidence_refs=(),
        reason="Scope construction regression only; no security conclusion.",
        provenance={"producer": "M8_SCOPE_HELPER_TEST"},
        semantic_category="UNKNOWN",
    )
    assert validate_scope(proposal) == []


def test_minimal_scope_uses_callable_then_type_then_file(indexed) -> None:
    wrap = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    parameter = _one(indexed, ProgramEntityKind.PARAMETER, "input")
    same_callable = build_valid_scope(
        indexed,
        project_id="CONTROLLED",
        subject=wrap,
        source=parameter,
        target=wrap,
        proposal_type=ProposalType.WRAPPER_FLOW,
    )
    assert same_callable.basis == ScopeBasis.CALLABLE_LOCAL
    assert same_callable.scope.kind == ScopeKind.CALLABLE
    assert same_callable.owner_entity_id == wrap.entity_id
    assert set(same_callable.covered_anchor_ids) == {wrap.entity_id, parameter.entity_id}

    setter = _one(indexed, ProgramEntityKind.METHOD, "setState")
    getter = _one(indexed, ProgramEntityKind.METHOD, "getState")
    same_type = build_valid_scope(
        indexed,
        project_id="CONTROLLED",
        subject=setter,
        target=getter,
        proposal_type=ProposalType.FRAMEWORK_RELATION,
    )
    assert same_type.basis == ScopeBasis.TYPE_LOCAL
    assert same_type.scope.kind == ScopeKind.FRAMEWORK_RELATION
    assert same_type.enclosing_type == "com.example.ControlledSecurityCases"
    assert "ANCHORS_DO_NOT_SHARE_ONE_CALLABLE" in same_type.why_smaller_scope_invalid

    first_field = _one(
        indexed,
        ProgramEntityKind.FIELD,
        "state",
        enclosing="com.example.ControlledSecurityCases",
    )
    second_field = _one(
        indexed,
        ProgramEntityKind.FIELD,
        "state",
        enclosing="com.example.ControlledSecurityCases.AlternateState",
    )
    same_file = build_valid_scope(
        indexed,
        project_id="CONTROLLED",
        subject=first_field,
        target=second_field,
    )
    assert same_file.basis == ScopeBasis.FILE_LOCAL
    assert same_file.repository_relative_path == first_field.repository_relative_path
    assert same_file.scope.kind == ScopeKind.ENTITY


def test_cross_file_scope_remains_explicit_and_bounded(tmp_path: Path) -> None:
    source_root = tmp_path / "repo"
    source_root.mkdir()
    (source_root / "A.java").write_text("class A { void first() {} }\n", encoding="utf-8")
    (source_root / "B.java").write_text("class B { void second() {} }\n", encoding="utf-8")
    index = build_repository_index(source_root)
    first = next(item for item in index.entities if item.kind == ProgramEntityKind.METHOD and item.simple_name == "first")
    second = next(item for item in index.entities if item.kind == ProgramEntityKind.METHOD and item.simple_name == "second")
    preview = build_valid_scope(index, project_id="P1", subject=first, target=second)
    assert preview.basis == ScopeBasis.BOUNDED_EXPLICIT
    assert preview.owner_entity_id is None
    assert preview.scope.entity_ids == (first.entity_id, second.entity_id)
    assert "ANCHORS_DO_NOT_SHARE_ONE_FILE" in preview.why_smaller_scope_invalid


def test_scope_helper_fails_closed_for_unknown_or_unbounded_identity(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    with pytest.raises(ValueError, match="not present"):
        build_valid_scope(indexed, project_id="P1", subject="entity-missing")
    with pytest.raises(ValueError, match="bounded"):
        build_valid_scope(indexed, project_id="P*", subject=method)


def test_field_state_scope_uses_existing_m4_kind(indexed) -> None:
    field = _one(
        indexed,
        ProgramEntityKind.FIELD,
        "state",
        enclosing="com.example.ControlledSecurityCases",
    )
    preview = build_valid_scope(
        indexed,
        project_id="CONTROLLED",
        subject=field,
        source=field,
        target=field,
        proposal_type=ProposalType.FIELD_STATE,
    )
    assert preview.scope.kind == ScopeKind.FIELD
    assert preview.scope.entity_ids == (field.entity_id,)
