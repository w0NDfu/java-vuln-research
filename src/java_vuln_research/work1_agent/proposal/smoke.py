from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence

from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import build_repository_index

from .evidence import EvidenceRef, EvidenceSourceKind, EvidenceStrength
from .gate import EvidenceGate, EvidenceGateResult, GateStatus
from .model import EntityRole, EntityRoleRef, ProposalScope, ProposalType, ScopeKind, SecurityProposal
from .serialization import write_jsonl


def _one(entities: Sequence[ProgramEntity], kind: ProgramEntityKind, name: str, *, occurrence: int = 0) -> ProgramEntity:
    matches = sorted(
        (item for item in entities if item.kind == kind and item.simple_name == name),
        key=lambda item: (item.repository_relative_path, item.start_line, item.entity_id),
    )
    if occurrence >= len(matches):
        raise ValueError(f"fixture entity unavailable: {kind.value} {name} occurrence {occurrence}")
    return matches[occurrence]


class _ManualSet:
    def __init__(self, entities: Sequence[ProgramEntity]) -> None:
        self.entities = list(entities)
        self.evidence: dict[str, EvidenceRef] = {}
        self.proposals: list[SecurityProposal] = []
        self.native_relation_ids: set[str] = set()

    def evidence_for(
        self,
        entity: ProgramEntity,
        *,
        source_kind: EvidenceSourceKind = EvidenceSourceKind.SOURCE_SNIPPET,
        strength: EvidenceStrength = EvidenceStrength.DIRECT,
        entity_ids: Sequence[str] | None = None,
        tool_call_id: str | None = None,
        result_hash: str | None = None,
    ) -> EvidenceRef:
        extra: dict[str, Any] = {}
        if source_kind in {EvidenceSourceKind.SOURCE_SNIPPET, EvidenceSourceKind.ANNOTATION_TEXT, EvidenceSourceKind.TYPE_DECLARATION}:
            path = Path(entity.repository_relative_path)
            source = Path(self.entities_root) / path if hasattr(self, "entities_root") else None
            if source is not None and source.is_file():
                lines = source.read_text(encoding="utf-8").splitlines()
                selected = "\n".join(lines[entity.start_line - 1 : entity.end_line])
                extra = {
                    "repository_relative_path": entity.repository_relative_path,
                    "start_line": entity.start_line,
                    "end_line": entity.end_line,
                    "content_hash": hashlib.sha256(selected.encode("utf-8")).hexdigest(),
                }
        item = EvidenceRef.create(
            source_kind=source_kind,
            entity_ids=entity_ids or [entity.entity_id],
            confidence=strength,
            tool_call_id=tool_call_id,
            result_hash=result_hash,
            provenance={"producer": "WORK1_V11_M4_MANUAL_CONTROLLED_SET"},
            **extra,
        )
        self.evidence[item.evidence_id] = item
        return item

    def proposal(
        self,
        proposal_type: ProposalType,
        subject: EntityRoleRef,
        evidence_refs: Sequence[str],
        *,
        source: EntityRoleRef | None = None,
        target: EntityRoleRef | None = None,
        category: str | None = None,
        scope_kind: ScopeKind = ScopeKind.ENTITY,
        project_id: str = "CONTROLLED_M4",
        model_confidence: float | None = None,
        scope_ids: Sequence[str] | None = None,
        reason: str = "Manual grounded hypothesis for the M4 admission mechanism.",
    ) -> SecurityProposal:
        anchors = tuple(dict.fromkeys(item.entity_id for item in (subject, source, target) if item))
        item = SecurityProposal.create(
            proposal_type=proposal_type,
            subject=subject,
            source=source,
            target=target,
            scope=ProposalScope(scope_kind, tuple(scope_ids) if scope_ids is not None else anchors, project_id),
            evidence_refs=evidence_refs,
            reason=reason,
            model_confidence=model_confidence,
            provenance={"producer": "WORK1_V11_M4_MANUAL_CONTROLLED_SET", "llm_used": False},
            semantic_category=category,
        )
        self.proposals.append(item)
        return item


def controlled_manual_set(repository_root: str | Path) -> tuple[list[ProgramEntity], list[EvidenceRef], list[SecurityProposal], set[str]]:
    index = build_repository_index(repository_root)
    entities = index.entities
    data = _ManualSet(entities)
    data.entities_root = str(Path(repository_root).resolve())
    methods = {name: _one(entities, ProgramEntityKind.METHOD, name) for name in (
        "customExternalInput", "wrap", "getState", "frameworkBound", "trigger",
        "setState", "setSecondaryState", "setTokenState", "setPathState", "setMessageState",
        "getSecondaryState", "getTokenState", "getPathState", "getMessageState",
    )}
    calls = sorted((item for item in entities if item.kind == ProgramEntityKind.CALL), key=lambda item: (item.start_line, item.entity_id))
    fields = [
        _one(entities, ProgramEntityKind.FIELD, name)
        for name in ("state", "secondaryState", "tokenState", "pathState", "messageState")
    ]
    annotations = sorted((item for item in entities if item.kind == ProgramEntityKind.ANNOTATION), key=lambda item: (item.start_line, item.entity_id))

    # 5 EXTERNAL_INPUT proposals.
    external_specs = [
        (methods["customExternalInput"], EntityRole.RETURN, None, "HTTP"),
        (methods["wrap"], EntityRole.RETURN, None, "UNKNOWN"),
        (methods["getState"], EntityRole.RETURN, None, "FILE"),
        (methods["frameworkBound"], EntityRole.PARAMETER, 0, "FRAMEWORK_INPUT"),
        (methods["trigger"], EntityRole.PARAMETER, 1, "MESSAGE"),
    ]
    for entity, role, index_value, category in external_specs:
        evidence = data.evidence_for(entity)
        data.proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(entity.entity_id, role, index_value), [evidence.evidence_id], category=category)

    # 5 SECURITY_EFFECT proposals; categories are proposal metadata, not recognizer rules.
    effect_categories = ("FILESYSTEM", "NETWORK", "DATABASE", "PROCESS_EXECUTION", "UNKNOWN")
    for entity, category in zip(calls[:5], effect_categories, strict=True):
        evidence = data.evidence_for(entity)
        data.proposal(ProposalType.SECURITY_EFFECT, EntityRoleRef(entity.entity_id, EntityRole.ARGUMENT, 0), [evidence.evidence_id], category=category)

    # 5 WRAPPER_FLOW proposals.
    wrapper_specs = (
        (methods["customExternalInput"], EntityRole.PARAMETER, 0),
        (methods["wrap"], EntityRole.PARAMETER, 0),
        (methods["getState"], EntityRole.RECEIVER, None),
        (methods["getSecondaryState"], EntityRole.RECEIVER, None),
        (methods["getTokenState"], EntityRole.RECEIVER, None),
    )
    for entity, source_role, source_index in wrapper_specs:
        evidence = data.evidence_for(entity)
        data.proposal(
            ProposalType.WRAPPER_FLOW,
            EntityRoleRef(entity.entity_id, EntityRole.METHOD),
            [evidence.evidence_id],
            source=EntityRoleRef(entity.entity_id, source_role, source_index),
            target=EntityRoleRef(entity.entity_id, EntityRole.RETURN),
            scope_kind=ScopeKind.CALLABLE,
        )

    # 3 LIBRARY_FLOW proposals.
    for entity in calls[:3]:
        evidence = data.evidence_for(entity)
        data.proposal(
            ProposalType.LIBRARY_FLOW,
            EntityRoleRef(entity.entity_id, EntityRole.CALL),
            [evidence.evidence_id],
            source=EntityRoleRef(entity.entity_id, EntityRole.ARGUMENT, 0),
            target=EntityRoleRef(entity.entity_id, EntityRole.CALL_RESULT),
            scope_kind=ScopeKind.CALLABLE,
        )

    # 5 FIELD_STATE proposals.
    state_methods = (
        (methods["setState"], methods["getState"]),
        (methods["setSecondaryState"], methods["getSecondaryState"]),
        (methods["setTokenState"], methods["getTokenState"]),
        (methods["setPathState"], methods["getPathState"]),
        (methods["setMessageState"], methods["getMessageState"]),
    )
    for entity, (setter, getter) in zip(fields, state_methods, strict=True):
        evidence = data.evidence_for(
            entity,
            source_kind=EvidenceSourceKind.REPOSITORY_RELATION,
            strength=EvidenceStrength.STRONG_STRUCTURAL,
            entity_ids=[setter.entity_id, entity.entity_id, getter.entity_id],
        )
        data.proposal(
            ProposalType.FIELD_STATE,
            EntityRoleRef(entity.entity_id, EntityRole.FIELD),
            [evidence.evidence_id],
            source=EntityRoleRef(setter.entity_id, EntityRole.PARAMETER, 0),
            target=EntityRoleRef(getter.entity_id, EntityRole.RETURN),
            scope_kind=ScopeKind.FIELD,
        )

    # 3 FRAMEWORK_RELATION proposals.
    for annotation, target in zip(annotations[:3], (methods["frameworkBound"], methods["frameworkBound"], methods["customExternalInput"]), strict=True):
        evidence = data.evidence_for(annotation, source_kind=EvidenceSourceKind.ANNOTATION_TEXT)
        data.proposal(
            ProposalType.FRAMEWORK_RELATION,
            EntityRoleRef(annotation.entity_id, EntityRole.ENTITY),
            [evidence.evidence_id],
            target=EntityRoleRef(target.entity_id, EntityRole.METHOD),
            scope_kind=ScopeKind.FRAMEWORK_RELATION,
        )

    # 3 CALLBACK_RELATION proposals.
    callback_calls = [item for item in calls if item.simple_name == "onValue"]
    for entity, owner in zip(callback_calls[:2], (methods["trigger"], _one(entities, ProgramEntityKind.METHOD, "register")), strict=True):
        evidence = data.evidence_for(entity)
        data.proposal(
            ProposalType.CALLBACK_RELATION,
            EntityRoleRef(owner.entity_id, EntityRole.METHOD),
            [evidence.evidence_id],
            source=EntityRoleRef(owner.entity_id, EntityRole.PARAMETER, 0),
            target=EntityRoleRef(entity.entity_id, EntityRole.ARGUMENT, 0),
            scope_kind=ScopeKind.CALLBACK_RELATION,
        )
    callback_type = _one(entities, ProgramEntityKind.TYPE, "ValueCallback")
    callback_method = _one(entities, ProgramEntityKind.METHOD, "onValue")
    callback_ev = data.evidence_for(callback_type, source_kind=EvidenceSourceKind.TYPE_DECLARATION)
    data.proposal(
        ProposalType.CALLBACK_RELATION,
        EntityRoleRef(callback_type.entity_id, EntityRole.ENTITY),
        [callback_ev.evidence_id],
        target=EntityRoleRef(callback_method.entity_id, EntityRole.METHOD),
        scope_kind=ScopeKind.CALLBACK_RELATION,
    )

    valid_counts = Counter(item.proposal_type.value for item in data.proposals)
    assert valid_counts == {
        "EXTERNAL_INPUT": 5, "SECURITY_EFFECT": 5, "WRAPPER_FLOW": 5,
        "LIBRARY_FLOW": 3, "FIELD_STATE": 5, "FRAMEWORK_RELATION": 3,
        "CALLBACK_RELATION": 3,
    }, valid_counts
    valid = list(data.proposals)

    # At least 15 intentionally invalid/insufficient/duplicate/native-supported cases.
    wrap = methods["wrap"]
    write_call = calls[0]
    alternate = _one(entities, ProgramEntityKind.FIELD, "state", occurrence=1)
    wrap_ev = data.evidence_for(wrap)
    alternate_ev = data.evidence_for(alternate)
    data.proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef("entity-000000000000000000000000", EntityRole.RETURN), [], category="UNKNOWN")
    data.proposal(ProposalType.SECURITY_EFFECT, EntityRoleRef(write_call.entity_id, EntityRole.ARGUMENT, 99), [data.evidence_for(write_call).evidence_id], category="UNKNOWN")
    data.proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(fields[0].entity_id, EntityRole.RETURN), [data.evidence_for(fields[0]).evidence_id], category="UNKNOWN")
    data.proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(wrap.entity_id, EntityRole.RETURN), [alternate_ev.evidence_id], category="OTHER")
    data.proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(methods["setPathState"].entity_id, EntityRole.RETURN), ["evidence-000000000000000000000000"], category="ENVIRONMENT")
    fake_tool = data.evidence_for(wrap, source_kind=EvidenceSourceKind.CODEQL_CALL, tool_call_id="fabricated-tool-call", result_hash="0" * 64)
    data.proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(methods["setMessageState"].entity_id, EntityRole.RETURN), [fake_tool.evidence_id], category="COMMAND_LINE")
    data.proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(methods["setTokenState"].entity_id, EntityRole.RETURN), [wrap_ev.evidence_id], category="DESERIALIZED_INPUT", project_id="com.example.*")
    data.proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(methods["setState"].entity_id, EntityRole.RETURN), [], category="DESERIALIZED_INPUT", reason="Natural language only.")
    data.proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(methods["setSecondaryState"].entity_id, EntityRole.RETURN), [], category="RPC", model_confidence=1.0)
    weak = data.evidence_for(methods["setState"], source_kind=EvidenceSourceKind.REPOSITORY_TOOL_RESULT, strength=EvidenceStrength.WEAK)
    data.proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(methods["setState"].entity_id, EntityRole.RETURN), [weak.evidence_id], category="OTHER")
    ambiguous = data.evidence_for(fields[0], source_kind=EvidenceSourceKind.REPOSITORY_RELATION, strength=EvidenceStrength.STRONG_STRUCTURAL, entity_ids=[fields[0].entity_id, alternate.entity_id])
    data.proposal(ProposalType.FIELD_STATE, EntityRoleRef(alternate.entity_id, EntityRole.FIELD), [ambiguous.evidence_id], source=EntityRoleRef(alternate.entity_id, EntityRole.FIELD_WRITE), target=EntityRoleRef(alternate.entity_id, EntityRole.FIELD_READ), scope_kind=ScopeKind.FIELD)
    data.proposals.append(valid[0])
    native = data.proposal(ProposalType.EXTERNAL_INPUT, EntityRoleRef(methods["setPathState"].entity_id, EntityRole.PARAMETER, 0), [data.evidence_for(methods["setPathState"]).evidence_id], category="OTHER")
    data.native_relation_ids.add(native.proposal_id)
    data.proposal(ProposalType.WRAPPER_FLOW, EntityRoleRef(wrap.entity_id, EntityRole.METHOD), [wrap_ev.evidence_id], source=EntityRoleRef(wrap.entity_id, EntityRole.PARAMETER, 9), target=EntityRoleRef(wrap.entity_id, EntityRole.RETURN), scope_kind=ScopeKind.CALLABLE)
    data.proposal(ProposalType.WRAPPER_FLOW, EntityRoleRef(wrap.entity_id, EntityRole.METHOD), [wrap_ev.evidence_id], source=EntityRoleRef(wrap.entity_id, EntityRole.PARAMETER, 0), target=EntityRoleRef(methods["customExternalInput"].entity_id, EntityRole.RETURN), scope_kind=ScopeKind.CALLABLE, scope_ids=[wrap.entity_id])
    data.proposal(ProposalType.FIELD_STATE, EntityRoleRef(fields[1].entity_id, EntityRole.FIELD), [data.evidence_for(fields[1]).evidence_id], source=EntityRoleRef(fields[1].entity_id, EntityRole.FIELD_READ), target=EntityRoleRef(fields[1].entity_id, EntityRole.FIELD_WRITE), scope_kind=ScopeKind.FIELD)
    assert len(data.proposals) - len(valid) >= 15
    return entities, list(data.evidence.values()), data.proposals, data.native_relation_ids


def summarize(proposals: Sequence[SecurityProposal], results: Sequence[EvidenceGateResult], *, expected_invalid_count: int) -> dict[str, Any]:
    status_counts = Counter(item.status.value for item in results)
    type_status: dict[str, Counter[str]] = defaultdict(Counter)
    by_id = {item.proposal_id: item for item in proposals}
    for result in results:
        type_status[by_id[result.proposal_id].proposal_type.value][result.status.value] += 1
    resolution_checks = [check for result in results for check in result.checks if check.check == "EVIDENCE_RESOLUTION"]
    invalid_results = results[-expected_invalid_count:] if expected_invalid_count else []
    invalid_terminal = sum(item.status != GateStatus.ADMISSIBLE for item in invalid_results)
    admitted = [item for item in results if item.status == GateStatus.ADMISSIBLE]
    return {
        "proposal_count": len(proposals),
        "status_counts": dict(sorted(status_counts.items())),
        "status_rates": {key: round(value / len(results), 6) for key, value in sorted(status_counts.items())},
        "proposal_type_counts": dict(sorted(Counter(item.proposal_type.value for item in proposals).items())),
        "per_proposal_type": {key: dict(sorted(value.items())) for key, value in sorted(type_status.items())},
        "evidence_resolution_success_rate": round(sum(item.status.value == "PASS" for item in resolution_checks) / len(resolution_checks), 6) if resolution_checks else None,
        "invalid_or_fabricated_count": expected_invalid_count,
        "invalid_or_fabricated_non_admission_rate": round(invalid_terminal / expected_invalid_count, 6) if expected_invalid_count else None,
        "repository_only_admission_count": sum(item.provenance.get("admission_basis") == "REPOSITORY_ONLY" for item in admitted),
        "codeql_assisted_admission_count": sum(item.provenance.get("admission_basis") == "CODEQL_ASSISTED" for item in admitted),
        "detection_rate": None,
        "interpretation": "Mechanism metrics only; ADMISSIBLE is not vulnerability confirmation.",
    }


def run_controlled(repository_root: str | Path, artifact_root: str | Path) -> dict[str, Any]:
    entities, evidence, proposals, native_ids = controlled_manual_set(repository_root)
    gate = EvidenceGate(
        repository_root=repository_root,
        entities=entities,
        evidence_catalog={item.evidence_id: item for item in evidence},
        native_relation_ids=native_ids,
    )
    results = gate.evaluate_many(proposals)
    invalid_count = len(proposals) - 29
    summary = summarize(proposals, results, expected_invalid_count=invalid_count)
    summary.update({"fixture": str(Path(repository_root).resolve()), "valid_manual_proposal_count": 29})
    output = Path(artifact_root)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "proposals.jsonl", proposals)
    write_jsonl(output / "gate_results.jsonl", results)
    write_jsonl(output / "evidence_index.jsonl", evidence)
    write_jsonl(output / "failures.jsonl", (item for item in results if item.status != GateStatus.ADMISSIBLE))
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Work1 V11 M4 controlled proposal gate validation")
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--artifact-root", required=True)
    args = parser.parse_args(argv)
    print(json.dumps(run_controlled(args.repository_root, args.artifact_root), ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
