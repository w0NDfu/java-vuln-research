from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.proposal.evidence import EvidenceRef, EvidenceSourceKind, EvidenceStrength
from java_vuln_research.work1_agent.proposal.model import (
    EntityRole,
    EntityRoleRef,
    ProposalScope,
    ProposalType,
    ScopeKind,
    SecurityProposal,
)
from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind

from .contracts import DiagnosticCause, PROPOSAL_ORIGIN
from .io import read_jsonl, sha256_file, write_json, write_jsonl


CALLABLE_KINDS = {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}


def load_entities(path: str | Path) -> list[ProgramEntity]:
    return [ProgramEntity.from_dict(row) for row in read_jsonl(path)]


def _callable_identity(entity: ProgramEntity) -> str:
    suffix = (entity.signature or entity.simple_name)[len(entity.simple_name) :]
    return f"{entity.qualified_name}{suffix}"


def _parameter_count(entity: ProgramEntity) -> int:
    signature = entity.signature or ""
    if "(" not in signature or ")" not in signature:
        return 0
    body = signature.split("(", 1)[1].rsplit(")", 1)[0].strip()
    return 0 if not body else len([part for part in body.split(",") if part.strip()])


def _target_score(entity: ProgramEntity, hint: Mapping[str, Any]) -> tuple[int, int, int, str]:
    method_name = str(hint.get("method_name") or "")
    path_hint = str(hint.get("file_path") or hint.get("file_name") or "").replace("\\", "/")
    start = int(hint.get("start_line") or 0)
    score = 0
    if method_name and entity.simple_name == method_name:
        score += 100
    if path_hint and (entity.repository_relative_path.endswith(path_hint) or Path(entity.repository_relative_path).name == Path(path_hint).name):
        score += 50
    if start and entity.start_line <= start <= entity.end_line:
        score += 30
    score += min(_parameter_count(entity), 9)
    return (score, -abs(entity.start_line - start) if start else 0, -entity.start_line, entity.entity_id)


def choose_target(entities: Sequence[ProgramEntity], hint: Mapping[str, Any]) -> tuple[ProgramEntity, ProgramEntity]:
    callables = [item for item in entities if item.kind in CALLABLE_KINDS and _parameter_count(item) > 0]
    callables.sort(key=lambda item: _target_score(item, hint), reverse=True)
    for method in callables:
        identity = _callable_identity(method)
        calls = [
            item
            for item in entities
            if item.kind == ProgramEntityKind.CALL
            and item.enclosing_callable == identity
            and int(item.provenance.get("argument_count") or 0) > 0
        ]
        if calls:
            calls.sort(key=lambda item: (item.start_line, item.entity_id))
            return method, calls[0]
    raise ValueError("ENTITY_MAPPING_LIMITATION: no parameterized callable with an argument-bearing call matches the diagnostic hint")


def locate_entity_index(root: str | Path, project_id: str, hint: Mapping[str, Any]) -> Path:
    paths = sorted(Path(root).rglob("entities.jsonl"))
    ranked: list[tuple[int, Path]] = []
    for path in paths:
        path_score = 20 if project_id.lower() in str(path).lower() else 0
        try:
            entities = load_entities(path)
            method, _ = choose_target(entities, hint)
        except (OSError, ValueError, KeyError):
            continue
        ranked.append((_target_score(method, hint)[0] + path_score, path))
    if not ranked:
        raise ValueError(f"ENTITY_MAPPING_LIMITATION: no entity index resolves {project_id}")
    ranked.sort(key=lambda item: (item[0], str(item[1])), reverse=True)
    return ranked[0][1]


def _source_hash(root: Path, entity: ProgramEntity, start: int, end: int) -> str:
    lines = (root / Path(*entity.repository_relative_path.split("/"))).read_text(encoding="utf-8").splitlines()
    return hashlib.sha256("\n".join(lines[start - 1 : end]).encode("utf-8")).hexdigest()


def _evidence(root: Path, entities: Sequence[ProgramEntity], *, start: int, end: int, purpose: str) -> EvidenceRef:
    first = entities[0]
    return EvidenceRef.create(
        source_kind=EvidenceSourceKind.SOURCE_SNIPPET,
        entity_ids=[item.entity_id for item in entities],
        repository_relative_path=first.repository_relative_path,
        start_line=start,
        end_line=end,
        content_hash=_source_hash(root, first, start, end),
        confidence=EvidenceStrength.DIRECT,
        provenance={
            "producer": "WORK1_V11_M6_DIAGNOSTIC",
            "purpose": purpose,
            "proposal_origin": PROPOSAL_ORIGIN,
            "benchmark_informed": True,
            "allowed_for_agent_runtime": False,
        },
    )


def _flow_type(method: ProgramEntity) -> ProposalType:
    if method.kind == ProgramEntityKind.CONSTRUCTOR:
        return ProposalType.LIBRARY_FLOW
    text = f"{method.simple_name} {method.enclosing_type or ''}".lower()
    if any(token in text for token in ("handle", "startelement", "authenticate", "callback", "listener")):
        return ProposalType.CALLBACK_RELATION
    if any(token in text for token in ("filter", "validator", "parser", "controller", "framework")):
        return ProposalType.FRAMEWORK_RELATION
    return ProposalType.LIBRARY_FLOW


def _flow_scope(proposal_type: ProposalType) -> ScopeKind:
    if proposal_type == ProposalType.CALLBACK_RELATION:
        return ScopeKind.CALLBACK_RELATION
    if proposal_type == ProposalType.FRAMEWORK_RELATION:
        return ScopeKind.FRAMEWORK_RELATION
    return ScopeKind.CALLABLE


def analyse_case(
    *,
    project_id: str,
    case_id: str,
    source_root: str | Path,
    entity_index: str | Path,
    hint: Mapping[str, Any],
    output_root: str | Path,
) -> dict[str, Any]:
    if hint.get("diagnostic_status"):
        raise ValueError(str(hint["diagnostic_status"]))
    root = Path(source_root).resolve()
    entities = load_entities(entity_index)
    method, call = choose_target(entities, hint)
    callable_role = EntityRole.METHOD if method.kind == ProgramEntityKind.METHOD else EntityRole.CONSTRUCTOR
    parameter = EntityRoleRef(method.entity_id, EntityRole.PARAMETER, 0)
    callable_ref = EntityRoleRef(method.entity_id, callable_role)
    call_ref = EntityRoleRef(call.entity_id, EntityRole.CALL)
    method_ev = _evidence(root, [method], start=method.start_line, end=method.end_line, purpose="callable_semantic_hypothesis")
    call_ev = _evidence(root, [call], start=call.start_line, end=call.end_line, purpose="effect_anchor_hypothesis")
    relation_ev = _evidence(root, [method, call], start=method.start_line, end=method.end_line, purpose="lexical_containment_relation")
    evidence = [method_ev, call_ev, relation_ev]
    common = {
        "producer": "WORK1_V11_M6_DIAGNOSTIC",
        "proposal_origin": PROPOSAL_ORIGIN,
        "benchmark_informed": True,
        "allowed_for_agent_runtime": False,
        "eligible_for_detection_metric": False,
        "project_id": project_id,
        "case_id": case_id,
    }
    input_proposal = SecurityProposal.create(
        proposal_type=ProposalType.EXTERNAL_INPUT,
        subject=parameter,
        scope=ProposalScope(ScopeKind.CALLABLE, (method.entity_id,), project_id),
        evidence_refs=[method_ev.evidence_id],
        reason="Diagnostic hypothesis: the selected callable parameter is an externally influenced value.",
        provenance={**common, "diagnostic_role": "input_anchor"},
        semantic_category="OTHER",
    )
    flow_type = _flow_type(method)
    flow_proposal = SecurityProposal.create(
        proposal_type=flow_type,
        subject=callable_ref,
        source=parameter,
        target=callable_ref,
        scope=ProposalScope(_flow_scope(flow_type), (method.entity_id,), project_id),
        evidence_refs=[method_ev.evidence_id],
        reason="Diagnostic hypothesis: the parameter participates in the selected callable's missing semantic relation.",
        provenance={**common, "diagnostic_role": "non_anchor_semantic_relation"},
    )
    effect_proposal = SecurityProposal.create(
        proposal_type=ProposalType.SECURITY_EFFECT,
        subject=call_ref,
        scope=ProposalScope(ScopeKind.CALLABLE, (call.entity_id,), project_id),
        evidence_refs=[call_ev.evidence_id],
        reason="Diagnostic hypothesis: the selected invocation is the security-relevant effect boundary.",
        provenance={**common, "diagnostic_role": "effect_anchor"},
        semantic_category="OTHER",
    )
    proposals = [input_proposal, flow_proposal, effect_proposal]
    cause = (
        DiagnosticCause.FRAMEWORK_OR_CALLBACK_RELATION_MISSING
        if flow_type in {ProposalType.FRAMEWORK_RELATION, ProposalType.CALLBACK_RELATION}
        else DiagnosticCause.WRAPPER_OR_LIBRARY_FLOW_MISSING
    )
    output = Path(output_root)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "evidence_refs.jsonl", evidence)
    write_jsonl(output / "proposals.jsonl", proposals)
    detector_input = {
        "schema_version": 1,
        "project_id": project_id,
        "source_root": str(root),
        "entity_index": str(Path(entity_index).resolve()),
        "entity_index_hash": sha256_file(entity_index),
        "evidence_refs": str((output / "evidence_refs.jsonl").resolve()),
        "repository_relations": [
            {
                "relation_id": f"m6-lexical-{method.entity_id}-{call.entity_id}",
                "relation_kind": "LEXICAL_CALL",
                "source": callable_ref.to_dict(),
                "target": call_ref.to_dict(),
                "evidence_refs": [relation_ev.evidence_id],
                "provenance": {"producer": "WORK1_V11_M6_REPOSITORY_BINDING", "basis": "enclosing_callable_identity"},
            }
        ],
    }
    write_json(output / "detector_input.json", detector_input)
    analysis = {
        "schema_version": 1,
        "project_id": project_id,
        "case_id": case_id,
        "proposal_origin": PROPOSAL_ORIGIN,
        "benchmark_informed": True,
        "allowed_for_agent_runtime": False,
        "eligible_for_detection_metric": False,
        "diagnostic_cause": cause.value,
        "proposal_budget": 5,
        "proposal_count": len(proposals),
        "target_annotation": dict(hint),
        "mapped_callable": method.to_dict(),
        "mapped_call": call.to_dict(),
        "flow_proposal_type": flow_type.value,
        "proposal_ids_in_replay_order": [item.proposal_id for item in proposals],
        "separation_note": "This artifact is diagnostic-only and is not imported by the detector or Agent runtime.",
    }
    write_json(output / "diagnostic_analysis.json", analysis)
    return analysis
