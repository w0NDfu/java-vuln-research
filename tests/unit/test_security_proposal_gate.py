from __future__ import annotations

import json
import csv
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.proposal import (
    EntityRole,
    EntityRoleRef,
    EvidenceGate,
    EvidenceRef,
    EvidenceSourceKind,
    EvidenceStrength,
    GateStatus,
    ProposalScope,
    ProposalType,
    ScopeKind,
    SecurityProposal,
)
from java_vuln_research.work1_agent.proposal.serialization import read_evidence, read_proposals, write_jsonl
from java_vuln_research.work1_agent.proposal.smoke import controlled_manual_set, run_controlled
from java_vuln_research.work1_agent.proposal.real_smoke import REAL_PROJECT_COHORT, combine_artifacts, run_real
from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import build_repository_index


FIXTURE = Path(__file__).parents[1] / "fixtures" / "work1_agent_m4"


@pytest.fixture(scope="module")
def indexed():
    return build_repository_index(FIXTURE)


def _one(indexed, kind: ProgramEntityKind, name: str, *, enclosing: str | None = None, callable_name: str | None = None) -> ProgramEntity:
    matches = [
        item for item in indexed.entities
        if item.kind == kind and item.simple_name == name
        and (enclosing is None or item.enclosing_type == enclosing)
        and (callable_name is None or callable_name in (item.enclosing_callable or ""))
    ]
    assert len(matches) == 1, [(item.kind.value, item.qualified_name) for item in matches]
    return matches[0]


def _evidence(entity: ProgramEntity, *, kind=EvidenceSourceKind.PROGRAM_ENTITY, strength=EvidenceStrength.DIRECT, **kwargs) -> EvidenceRef:
    return EvidenceRef.create(
        source_kind=kind,
        entity_ids=kwargs.pop("entity_ids", [entity.entity_id]),
        confidence=strength,
        provenance={"producer": "controlled-test"},
        **kwargs,
    )


def _proposal(
    proposal_type: ProposalType,
    subject: EntityRoleRef,
    evidence: tuple[str, ...],
    *,
    source: EntityRoleRef | None = None,
    target: EntityRoleRef | None = None,
    category: str | None = None,
    kind: ScopeKind = ScopeKind.ENTITY,
    project_id: str = "CONTROLLED",
    model_confidence: float | None = None,
) -> SecurityProposal:
    anchors = tuple(dict.fromkeys(item.entity_id for item in (subject, source, target) if item))
    return SecurityProposal.create(
        proposal_type=proposal_type,
        subject=subject,
        source=source,
        target=target,
        scope=ProposalScope(kind, anchors, project_id),
        evidence_refs=evidence,
        reason="Controlled semantic hypothesis; admission is not confirmation.",
        model_confidence=model_confidence,
        provenance={"producer": "manual-controlled-v1"},
        semantic_category=category,
    )


def _gate(indexed, evidence=(), **kwargs) -> EvidenceGate:
    return EvidenceGate(
        repository_root=FIXTURE,
        entities=indexed.entities,
        evidence_catalog={item.evidence_id: item for item in evidence},
        **kwargs,
    )


def test_stable_proposal_id_and_serialization(indexed, tmp_path: Path) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "customExternalInput")
    ev = _evidence(method)
    first = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(method.entity_id, EntityRole.RETURN), (ev.evidence_id,), category="UNKNOWN")
    second = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(method.entity_id, EntityRole.RETURN), (ev.evidence_id,), category="UNKNOWN", model_confidence=0.99)
    assert first.proposal_id == second.proposal_id
    assert first.to_json() == SecurityProposal.from_dict(json.loads(first.to_json())).to_json()
    proposals_path, evidence_path = tmp_path / "proposals.jsonl", tmp_path / "evidence.jsonl"
    write_jsonl(proposals_path, [first])
    write_jsonl(evidence_path, [ev])
    assert read_proposals(proposals_path)[0].to_json() == first.to_json()
    assert read_evidence(evidence_path)[0].to_json() == ev.to_json()


def test_valid_external_input_and_repository_only_admission(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "customExternalInput")
    ev = _evidence(method)
    proposal = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(method.entity_id, EntityRole.RETURN), (ev.evidence_id,), category="UNKNOWN")
    result = _gate(indexed, [ev]).evaluate(proposal)
    assert result.status == GateStatus.ADMISSIBLE
    assert result.provenance["admission_basis"] == "REPOSITORY_ONLY"


def test_valid_security_effect(indexed) -> None:
    call = _one(indexed, ProgramEntityKind.CALL, "writeString")
    ev = _evidence(call)
    proposal = _proposal(ProposalType.SECURITY_EFFECT, EntityRoleRef(call.entity_id, EntityRole.ARGUMENT, 0), (ev.evidence_id,), category="FILESYSTEM")
    assert _gate(indexed, [ev]).evaluate(proposal).status == GateStatus.ADMISSIBLE


def test_valid_wrapper_and_library_flow(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    ev = _evidence(method)
    source = EntityRoleRef(method.entity_id, EntityRole.PARAMETER, 0)
    target = EntityRoleRef(method.entity_id, EntityRole.RETURN)
    subject = EntityRoleRef(method.entity_id, EntityRole.METHOD)
    for proposal_type in (ProposalType.WRAPPER_FLOW, ProposalType.LIBRARY_FLOW):
        proposal = _proposal(proposal_type, subject, (ev.evidence_id,), source=source, target=target, kind=ScopeKind.CALLABLE)
        assert _gate(indexed, [ev]).evaluate(proposal).status == GateStatus.ADMISSIBLE


def test_valid_field_state(indexed) -> None:
    field = _one(indexed, ProgramEntityKind.FIELD, "state", enclosing="com.example.ControlledSecurityCases")
    ev = _evidence(field)
    proposal = _proposal(
        ProposalType.FIELD_STATE,
        EntityRoleRef(field.entity_id, EntityRole.FIELD),
        (ev.evidence_id,),
        source=EntityRoleRef(field.entity_id, EntityRole.FIELD_WRITE),
        target=EntityRoleRef(field.entity_id, EntityRole.FIELD_READ),
        kind=ScopeKind.FIELD,
    )
    assert _gate(indexed, [ev]).evaluate(proposal).status == GateStatus.ADMISSIBLE


def test_valid_framework_and_callback_relations(indexed) -> None:
    annotations = [item for item in indexed.entities if item.kind == ProgramEntityKind.ANNOTATION and item.simple_name == "BoundValue" and item.enclosing_type == "com.example.ControlledSecurityCases"]
    annotation = min(annotations, key=lambda item: item.start_line)
    bound = _one(indexed, ProgramEntityKind.METHOD, "frameworkBound")
    ev = _evidence(annotation, kind=EvidenceSourceKind.ANNOTATION_TEXT)
    framework = _proposal(
        ProposalType.FRAMEWORK_RELATION,
        EntityRoleRef(annotation.entity_id, EntityRole.ENTITY),
        (ev.evidence_id,),
        target=EntityRoleRef(bound.entity_id, EntityRole.METHOD),
        kind=ScopeKind.FRAMEWORK_RELATION,
    )
    assert _gate(indexed, [ev]).evaluate(framework).status == GateStatus.ADMISSIBLE

    register = _one(indexed, ProgramEntityKind.METHOD, "register")
    callback = _one(indexed, ProgramEntityKind.CALL, "onValue", enclosing="com.example.ControlledSecurityCases", callable_name="register")
    cb_ev = _evidence(callback)
    relation = _proposal(
        ProposalType.CALLBACK_RELATION,
        EntityRoleRef(register.entity_id, EntityRole.METHOD),
        (cb_ev.evidence_id,),
        source=EntityRoleRef(register.entity_id, EntityRole.PARAMETER, 0),
        target=EntityRoleRef(callback.entity_id, EntityRole.ARGUMENT, 0),
        kind=ScopeKind.CALLBACK_RELATION,
    )
    assert _gate(indexed, [cb_ev]).evaluate(relation).status == GateStatus.ADMISSIBLE


def test_invalid_and_fabricated_entity_rejected(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    proposal = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef("entity-000000000000000000000000", EntityRole.RETURN), (), category="UNKNOWN")
    result = _gate(indexed).evaluate(proposal)
    assert result.status == GateStatus.REJECTED
    assert any("ENTITY_NOT_FOUND" in item for item in result.rejection_reasons)


def test_invalid_argument_parameter_return_and_field_roles(indexed) -> None:
    call = _one(indexed, ProgramEntityKind.CALL, "writeString")
    field = _one(indexed, ProgramEntityKind.FIELD, "state", enclosing="com.example.ControlledSecurityCases")
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    evs = [_evidence(call), _evidence(field), _evidence(method)]
    proposals = [
        _proposal(ProposalType.SECURITY_EFFECT, EntityRoleRef(call.entity_id, EntityRole.ARGUMENT, 9), (evs[0].evidence_id,), category="UNKNOWN"),
        _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(field.entity_id, EntityRole.RETURN), (evs[1].evidence_id,), category="UNKNOWN"),
        _proposal(ProposalType.WRAPPER_FLOW, EntityRoleRef(method.entity_id, EntityRole.METHOD), (evs[2].evidence_id,), source=EntityRoleRef(method.entity_id, EntityRole.PARAMETER, 9), target=EntityRoleRef(method.entity_id, EntityRole.RETURN), kind=ScopeKind.CALLABLE),
    ]
    assert all(_gate(indexed, evs).evaluate(item).status == GateStatus.REJECTED for item in proposals)


def test_unrelated_missing_and_fabricated_evidence_rejected(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    other_field = _one(indexed, ProgramEntityKind.FIELD, "state", enclosing="com.example.ControlledSecurityCases.AlternateState")
    unrelated = _evidence(other_field)
    proposal = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(method.entity_id, EntityRole.RETURN), (unrelated.evidence_id,), category="UNKNOWN")
    assert _gate(indexed, [unrelated]).evaluate(proposal).status == GateStatus.REJECTED
    missing = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(method.entity_id, EntityRole.RETURN), ("evidence-000000000000000000000000",), category="UNKNOWN")
    assert _gate(indexed).evaluate(missing).status == GateStatus.REJECTED
    fake_tool = _evidence(method, kind=EvidenceSourceKind.CODEQL_CALL, tool_call_id="missing-call", result_hash="0" * 64)
    with_tool = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(method.entity_id, EntityRole.RETURN), (fake_tool.evidence_id,), category="UNKNOWN")
    assert _gate(indexed, [fake_tool]).evaluate(with_tool).status == GateStatus.REJECTED


def test_wildcard_scope_rejected(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    ev = _evidence(method)
    proposal = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(method.entity_id, EntityRole.RETURN), (ev.evidence_id,), category="UNKNOWN", project_id="com.example.*")
    result = _gate(indexed, [ev]).evaluate(proposal)
    assert result.status == GateStatus.REJECTED
    assert "WILDCARD_OR_UNBOUNDED_SCOPE" in result.rejection_reasons


def test_duplicate_and_already_supported(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    ev = _evidence(method)
    proposal = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(method.entity_id, EntityRole.RETURN), (ev.evidence_id,), category="UNKNOWN")
    gate = _gate(indexed, [ev])
    assert gate.evaluate(proposal).status == GateStatus.ADMISSIBLE
    assert gate.evaluate(proposal).status == GateStatus.DUPLICATE
    assert _gate(indexed, [ev], native_relation_ids=[proposal.proposal_id]).evaluate(proposal).status == GateStatus.ALREADY_SUPPORTED


def test_codeql_assisted_admission(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    ev = _evidence(method, kind=EvidenceSourceKind.CODEQL_LOCAL_FLOW, tool_call_id="call-1", result_hash="1" * 64)
    proposal = _proposal(ProposalType.WRAPPER_FLOW, EntityRoleRef(method.entity_id, EntityRole.METHOD), (ev.evidence_id,), source=EntityRoleRef(method.entity_id, EntityRole.PARAMETER, 0), target=EntityRoleRef(method.entity_id, EntityRole.RETURN), kind=ScopeKind.CALLABLE)
    result = _gate(indexed, [ev], artifact_index={"call-1": {"status": "OK"}}).evaluate(proposal)
    assert result.status == GateStatus.ADMISSIBLE
    assert result.provenance["admission_basis"] == "CODEQL_ASSISTED"


def test_model_confidence_does_not_bypass_missing_evidence(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    proposal = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(method.entity_id, EntityRole.RETURN), (), category="UNKNOWN", model_confidence=1.0)
    result = _gate(indexed).evaluate(proposal)
    assert result.status == GateStatus.NEEDS_MORE_EVIDENCE
    assert "NO_PROGRAM_EVIDENCE" in result.missing_evidence


def test_weak_evidence_and_ambiguous_field_need_more_evidence(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    weak = _evidence(method, strength=EvidenceStrength.WEAK)
    proposal = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(method.entity_id, EntityRole.RETURN), (weak.evidence_id,), category="UNKNOWN")
    assert _gate(indexed, [weak]).evaluate(proposal).status == GateStatus.NEEDS_MORE_EVIDENCE

    field = _one(indexed, ProgramEntityKind.FIELD, "state", enclosing="com.example.ControlledSecurityCases")
    other = _one(indexed, ProgramEntityKind.FIELD, "state", enclosing="com.example.ControlledSecurityCases.AlternateState")
    ambiguous = _evidence(field, kind=EvidenceSourceKind.REPOSITORY_RELATION, strength=EvidenceStrength.STRONG_STRUCTURAL, entity_ids=[field.entity_id, other.entity_id])
    state = _proposal(ProposalType.FIELD_STATE, EntityRoleRef(field.entity_id, EntityRole.FIELD), (ambiguous.evidence_id,), source=EntityRoleRef(field.entity_id, EntityRole.FIELD_WRITE), target=EntityRoleRef(field.entity_id, EntityRole.FIELD_READ), kind=ScopeKind.FIELD)
    result = _gate(indexed, [ambiguous]).evaluate(state)
    assert result.status == GateStatus.NEEDS_MORE_EVIDENCE
    assert "AMBIGUOUS_FIELD_ANCHOR" in result.missing_evidence


def test_needs_more_evidence_can_be_retried_with_stronger_evidence(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    proposal_without_evidence = _proposal(
        ProposalType.EXTERNAL_INPUT,
        EntityRoleRef(method.entity_id, EntityRole.RETURN),
        (),
        category="UNKNOWN",
    )
    gate = _gate(indexed)
    assert gate.evaluate(proposal_without_evidence).status == GateStatus.NEEDS_MORE_EVIDENCE
    evidence = _evidence(method)
    gate.register_evidence(evidence)
    proposal_with_evidence = _proposal(
        ProposalType.EXTERNAL_INPUT,
        EntityRoleRef(method.entity_id, EntityRole.RETURN),
        (evidence.evidence_id,),
        category="UNKNOWN",
    )
    assert proposal_with_evidence.proposal_id == proposal_without_evidence.proposal_id
    assert gate.evaluate(proposal_with_evidence).status == GateStatus.ADMISSIBLE


def test_provenance_preserved(indexed) -> None:
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    ev = _evidence(method)
    proposal = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(method.entity_id, EntityRole.RETURN), (ev.evidence_id,), category="UNKNOWN")
    result = _gate(indexed, [ev]).evaluate(proposal)
    assert result.provenance["proposal_provenance"] == {"producer": "manual-controlled-v1"}
    assert result.resolved_evidence[0]["provenance"] == {"producer": "controlled-test"}


def test_schemas_accept_serialized_objects(indexed) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    method = _one(indexed, ProgramEntityKind.METHOD, "wrap")
    ev = _evidence(method)
    proposal = _proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(method.entity_id, EntityRole.RETURN), (ev.evidence_id,), category="UNKNOWN")
    result = _gate(indexed, [ev]).evaluate(proposal)
    root = Path(__file__).parents[2]
    for name, value in (
        ("security_proposal.schema.json", proposal.to_dict()),
        ("evidence_ref.schema.json", ev.to_dict()),
        ("evidence_gate_result.schema.json", result.to_dict()),
    ):
        schema = json.loads((root / "schemas" / name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator(schema).validate(value)


def test_gate_contains_no_route_b_rule_lists() -> None:
    package = Path(__file__).parents[2] / "src" / "java_vuln_research" / "work1_agent" / "proposal"
    text = "\n".join(path.read_text(encoding="utf-8") for path in package.glob("*.py"))
    forbidden = ("KNOWN_SOURCE_APIS", "KNOWN_SINK_APIS", "HTTP_REQUEST_TYPES", "DANGEROUS_METHOD_NAMES", "SPRING_SOURCE_RULES", "CWE22_RULES")
    assert not any(item in text for item in forbidden)


def test_controlled_fixture_expected_outcomes(tmp_path: Path) -> None:
    _, _, proposals, _ = controlled_manual_set(FIXTURE)
    assert len(proposals) == 45
    assert {item.proposal_type.value for item in proposals} == {item.value for item in ProposalType}
    summary = run_controlled(FIXTURE, tmp_path / "artifacts")
    assert summary["valid_manual_proposal_count"] == 29
    assert summary["status_counts"] == {
        "ADMISSIBLE": 29,
        "ALREADY_SUPPORTED": 1,
        "DUPLICATE": 1,
        "NEEDS_MORE_EVIDENCE": 4,
        "REJECTED": 10,
    }
    assert summary["invalid_or_fabricated_non_admission_rate"] == 1.0
    assert summary["repository_only_admission_count"] == 29


def test_eight_project_real_smoke_and_combined_artifacts(indexed, tmp_path: Path) -> None:
    index_root = tmp_path / "indices"
    rows = []
    tool_calls = []
    callables = [item for item in indexed.sorted_entities() if item.kind in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}]
    assert len(callables) >= 2
    for position, project_id in enumerate(REAL_PROJECT_COHORT):
        target = index_root / project_id / "entities.jsonl"
        indexed.write_jsonl(target)
        ready = project_id not in {"V002", "V003"}
        rows.append({"project_id": project_id, "source_root": str(FIXTURE), "codeql_db_ready": str(ready).lower()})
        if ready:
            entity = callables[1]
            tool_calls.append({
                "project_id": project_id,
                "entity_id": entity.entity_id,
                "entity_path": entity.repository_relative_path,
                "entity_start_line": entity.start_line,
                "tool_call_id": f"call-{project_id}",
                "tool_name": "codeql_entity_facts",
                "status": "OK",
                "provenance": {"result_hash": str(position) * 64, "query_hash": "a" * 64, "v11_git_sha": "b" * 40},
            })
    inventory = tmp_path / "inventory.csv"
    with inventory.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["project_id", "source_root", "codeql_db_ready"])
        writer.writeheader()
        writer.writerows(rows)
    calls_path = tmp_path / "tool_calls.jsonl"
    write_jsonl(calls_path, tool_calls)
    controlled_root = tmp_path / "controlled"
    run_controlled(FIXTURE, controlled_root)
    real_root = tmp_path / "real"
    real = run_real(inventory_csv=inventory, index_roots=[index_root], tool_calls_jsonl=calls_path, artifact_root=real_root)
    assert real["project_count"] == 8
    assert real["max_proposals_per_project"] == 2
    assert real["repository_only_admission_count"] == 8
    assert real["codeql_assisted_admission_count"] == 6
    assert real["status_counts"] == {"ADMISSIBLE": 14}
    combined = combine_artifacts(controlled_root, real_root, tmp_path / "combined")
    assert combined["proposal_count"] == 59
    assert combined["status_counts"]["ADMISSIBLE"] == 43
