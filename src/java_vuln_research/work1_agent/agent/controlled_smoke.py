"""Non-benchmark controlled M7 smoke used before the real kill test."""

from __future__ import annotations

import argparse
from pathlib import Path

from java_vuln_research.work1_agent.hybrid_graph import RelationKind, SupportClass
from java_vuln_research.work1_agent.proposal import (
    EntityRole,
    EntityRoleRef,
    EvidenceGate,
    EvidenceRef,
    EvidenceSourceKind,
    EvidenceStrength,
    ProposalScope,
    ProposalType,
    ScopeKind,
    SecurityProposal,
)
from java_vuln_research.work1_agent.proposal.model import canonical_json
from java_vuln_research.work1_agent.repository.entity import ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import build_repository_index

from .actions import StopReason
from .controller import AgentController
from .graph_adapter import AgentGraphPathAdapter, AgentGraphRelation
from .llm_client import MockLLMClient
from .parser import StrictActionParser
from .prompt import build_system_prompt, prompt_sha256
from .observation import bounded_tool_catalog
from .runtime import write_controller_artifacts
from .security_boundary import RuntimeInputKind, RuntimeSecurityBoundary, runtime_roots
from .state import AgentState
from .tool_adapter import RepositoryCodeQLToolAdapter


def _decision(proposal: SecurityProposal | None = None, *, stop: StopReason | None = None) -> dict[str, object]:
    return {
        "action_type": "PROPOSE" if proposal else "STOP",
        "arguments": {},
        "proposal": proposal.to_dict() if proposal else None,
        "stop_reason": stop.value if stop else None,
        "reason": "Controlled evidence-only exploration.",
    }


def run_controlled_smoke(*, repository_root: Path, schema_root: Path, artifact_root: Path, git_sha: str) -> dict[str, object]:
    index = build_repository_index(repository_root)
    method = next(item for item in index.entities if item.kind is ProgramEntityKind.METHOD and item.simple_name == "customExternalInput")
    call = next(item for item in index.entities if item.kind is ProgramEntityKind.CALL and item.simple_name == "writeString")
    evidence = [
        EvidenceRef.create(source_kind=EvidenceSourceKind.PROGRAM_ENTITY, entity_ids=[method.entity_id], confidence=EvidenceStrength.DIRECT, provenance={"producer": "M7_CONTROLLED"}),
        EvidenceRef.create(source_kind=EvidenceSourceKind.PROGRAM_ENTITY, entity_ids=[call.entity_id], confidence=EvidenceStrength.DIRECT, provenance={"producer": "M7_CONTROLLED"}),
        EvidenceRef.create(source_kind=EvidenceSourceKind.REPOSITORY_RELATION, entity_ids=[method.entity_id, call.entity_id], confidence=EvidenceStrength.STRONG_STRUCTURAL, provenance={"producer": "M7_CONTROLLED", "deterministic_relation": False}),
    ]
    input_proposal = SecurityProposal.create(proposal_type=ProposalType.EXTERNAL_INPUT, subject=EntityRoleRef(method.entity_id, EntityRole.RETURN), scope=ProposalScope(ScopeKind.ENTITY, (method.entity_id,), "CONTROLLED"), semantic_category="UNKNOWN", evidence_refs=[evidence[0].evidence_id], reason="Controlled input candidate.", provenance={"producer": "M7_CONTROLLED"})
    effect_proposal = SecurityProposal.create(proposal_type=ProposalType.SECURITY_EFFECT, subject=EntityRoleRef(call.entity_id, EntityRole.ARGUMENT, 0), scope=ProposalScope(ScopeKind.ENTITY, (call.entity_id,), "CONTROLLED"), semantic_category="UNKNOWN", evidence_refs=[evidence[1].evidence_id], reason="Controlled effect candidate.", provenance={"producer": "M7_CONTROLLED"})
    output = artifact_root / "CONTROLLED"
    output.mkdir(parents=True, exist_ok=True)
    boundary = RuntimeSecurityBoundary(project_id="CONTROLLED", repository_identity="controlled@" + git_sha, allowed_roots=runtime_roots(source_roots=[repository_root], artifact_roots=[artifact_root], schema_roots=[schema_root]))
    for source in sorted(repository_root.rglob("*.java")):
        boundary.read_bytes(source, kind=RuntimeInputKind.JAVA_SOURCE, logical_name="java:" + source.relative_to(repository_root).as_posix())
    gate = EvidenceGate(repository_root=repository_root, entities=index.entities, evidence_catalog={item.evidence_id: item for item in evidence})
    relation = AgentGraphRelation(source_ref=EntityRoleRef(method.entity_id, EntityRole.RETURN), target_ref=EntityRoleRef(call.entity_id, EntityRole.ARGUMENT, 0), relation_kind=RelationKind.LEXICAL_CALL, support_class=SupportClass.STRUCTURAL_EVIDENCE, evidence_refs=(evidence[2].evidence_id,), repository_relation_ids=("controlled-relation",), provenance={"producer": "M7_CONTROLLED", "deterministic_relation": False})
    graph_adapter = AgentGraphPathAdapter(project_id="CONTROLLED", entities=index.entities, evidence_gate=gate, base_relations=[relation], git_sha=git_sha)
    state = AgentState.create(project_id="CONTROLLED", repository_identity="controlled@" + git_sha, provenance={"producer": "M7_CONTROLLED", "benchmark_informed": False})
    for item in evidence:
        state.record_evidence(item.evidence_id, project_id="CONTROLLED")
    controller = AgentController(
        state=state,
        repository_index=index,
        codeql_status={"project_id": "CONTROLLED", "ready": False, "status": "UNAVAILABLE"},
        llm_client=MockLLMClient([_decision(input_proposal), _decision(effect_proposal), _decision(stop=StopReason.PATH_FORMED)]),
        parser=StrictActionParser(schema_root),
        tool_adapter=RepositoryCodeQLToolAdapter(project_id="CONTROLLED", repository_index=index, security_boundary=boundary),
        evidence_gate=gate,
        graph_path_adapter=graph_adapter,
    )
    result = controller.run()
    input_manifest = boundary.seal()
    boundary.audit()
    prompt = build_system_prompt(bounded_tool_catalog())
    audit = write_controller_artifacts(result, output, run_manifest={"run_kind": "CONTROLLED_DETERMINISTIC_MOCK", "git_sha": git_sha, "repository_revision": git_sha, "model_provider": "deterministic-mock", "exact_model_id": "m7-mock-v1", "system_prompt_sha256": prompt_sha256(prompt), "benchmark_informed": False}, input_manifest=input_manifest)
    summary = {**result.summary(), "artifact_root": str(output), "artifact_audit_pass": audit["required_files_present"], "no_leakage_pass": audit["no_leakage_pass"]}
    (artifact_root / "aggregate_summary.json").write_text(canonical_json(summary) + "\n", encoding="utf-8")
    (artifact_root / "no_leakage_audit.json").write_text(canonical_json(input_manifest) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--git-sha", required=True)
    args = parser.parse_args()
    print(canonical_json(run_controlled_smoke(repository_root=args.repository_root, schema_root=args.schema_root, artifact_root=args.artifact_root, git_sha=args.git_sha)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
