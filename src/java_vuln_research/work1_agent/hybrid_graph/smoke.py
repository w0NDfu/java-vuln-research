from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Sequence

from java_vuln_research.work1_agent.proposal.evidence import EvidenceRef, EvidenceSourceKind, EvidenceStrength
from java_vuln_research.work1_agent.proposal.gate import EvidenceGate, GateStatus
from java_vuln_research.work1_agent.proposal.model import EntityRole, EntityRoleRef, ProposalScope, ProposalType, ScopeKind, SecurityProposal
from java_vuln_research.work1_agent.proposal.smoke import controlled_manual_set
from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind

from .builder import HybridEvidenceGraphBuilder
from .model import RelationKind
from .path import BoundedPathBuilder, SearchLimits
from .serialization import file_sha256, write_artifacts


CONTROLLED_PROJECT_ID = "M5-CONTROLLED"


def _entity(entities: Sequence[ProgramEntity], name: str, kind: ProgramEntityKind) -> ProgramEntity:
    matches = [item for item in entities if item.simple_name == name and item.kind == kind]
    if len(matches) != 1:
        raise ValueError(f"expected one {kind.value} named {name}, found {len(matches)}")
    return matches[0]


def _source_evidence(root: Path, entity: ProgramEntity, label: str) -> EvidenceRef:
    source = root / Path(*entity.repository_relative_path.split("/"))
    selected = "\n".join(source.read_text(encoding="utf-8").splitlines()[entity.start_line - 1 : entity.end_line])
    return EvidenceRef.create(
        source_kind=EvidenceSourceKind.SOURCE_SNIPPET,
        entity_ids=[entity.entity_id],
        repository_relative_path=entity.repository_relative_path,
        start_line=entity.start_line,
        end_line=entity.end_line,
        content_hash=hashlib.sha256(selected.encode("utf-8")).hexdigest(),
        confidence=EvidenceStrength.DIRECT,
        provenance={"producer": "WORK1_V11_M5_CONTROLLED", "label": label, "llm_used": False},
    )


def _anchor_proposal(
    *,
    proposal_type: ProposalType,
    ref: EntityRoleRef,
    evidence: EvidenceRef,
    project_id: str = CONTROLLED_PROJECT_ID,
) -> SecurityProposal:
    return SecurityProposal.create(
        proposal_type=proposal_type,
        subject=ref,
        scope=ProposalScope(ScopeKind.ENTITY, (ref.entity_id,), project_id),
        evidence_refs=[evidence.evidence_id],
        reason="Manual controlled M5 anchor; grounded mechanism input, not a confirmed security fact.",
        semantic_category="OTHER",
        provenance={"producer": "WORK1_V11_M5_CONTROLLED", "llm_used": False, "benchmark_input_used": False},
    )


def _legacy_native_path() -> dict[str, Any]:
    return {
        "candidate_path_id": "native-controlled-path",
        "project_id": CONTROLLED_PROJECT_ID,
        "input_candidate_id": "native-input",
        "effect_candidate_id": "native-effect",
        "input_entity": "native.input",
        "effect_entity": "native.effect",
        "input_discovery_route": "ROUTE_A",
        "effect_discovery_route": "ROUTE_A",
        "input_analysis_anchor": {},
        "effect_analysis_anchor": {},
        "path_nodes": [],
        "path_edges": [],
        "semantic_mechanisms": ["DATA"],
        "unresolved_relations": [],
        "path_status": "COMPLETE_STATIC",
        "frontier_nodes": [],
        "frontier_reason": None,
        "candidate_type_hypothesis": "UNKNOWN",
        "evidence_refs": [],
        "source_locations": [{"file": "ControlledSecurityCases.java", "line": 1}],
        "provenance": {"path_origin": "CODEQL_NATIVE", "native_path_id": "native-controlled-path"},
        "schema_version": 2,
        "detector_commit": "CONTROLLED",
    }


def run_controlled(
    *,
    repository_root: str | Path,
    artifact_root: str | Path,
    git_sha: str,
    search_limits: SearchLimits | None = None,
    assert_scenarios: bool = True,
) -> dict[str, Any]:
    root = Path(repository_root).resolve()
    entities, base_evidence, base_proposals, native_relation_ids = controlled_manual_set(root)
    evidence = {item.evidence_id: item for item in base_evidence}
    artifact_index: dict[str, Any] = {}
    gate = EvidenceGate(
        repository_root=root,
        entities=entities,
        evidence_catalog=evidence,
        artifact_index=artifact_index,
        native_relation_ids=native_relation_ids,
    )
    base_results = gate.evaluate_many(base_proposals)

    set_state = _entity(entities, "setState", ProgramEntityKind.METHOD)
    get_state = _entity(entities, "getState", ProgramEntityKind.METHOD)
    trigger = _entity(entities, "trigger", ProgramEntityKind.METHOD)
    bound_annotation = next(item for item in entities if item.entity_id == base_proposals[25].subject.entity_id)
    custom_input = _entity(entities, "customExternalInput", ProgramEntityKind.METHOD)
    get_secondary = _entity(entities, "getSecondaryState", ProgramEntityKind.METHOD)
    framework_bound = _entity(entities, "frameworkBound", ProgramEntityKind.METHOD)
    extra_evidence = [
        _source_evidence(root, set_state, "field-input"),
        _source_evidence(root, get_state, "field-effect"),
        _source_evidence(root, trigger, "callback-input"),
        _source_evidence(root, bound_annotation, "framework-input"),
        _source_evidence(root, custom_input, "framework-effect"),
        _source_evidence(root, get_secondary, "disconnected-input"),
        _source_evidence(root, framework_bound, "disconnected-effect"),
    ]
    for item in extra_evidence:
        evidence[item.evidence_id] = item
    extra_proposals = [
        _anchor_proposal(proposal_type=ProposalType.EXTERNAL_INPUT, ref=EntityRoleRef(set_state.entity_id, EntityRole.PARAMETER, 0), evidence=extra_evidence[0]),
        _anchor_proposal(proposal_type=ProposalType.SECURITY_EFFECT, ref=EntityRoleRef(get_state.entity_id, EntityRole.RETURN), evidence=extra_evidence[1]),
        _anchor_proposal(proposal_type=ProposalType.EXTERNAL_INPUT, ref=EntityRoleRef(trigger.entity_id, EntityRole.PARAMETER, 0), evidence=extra_evidence[2]),
        _anchor_proposal(proposal_type=ProposalType.EXTERNAL_INPUT, ref=EntityRoleRef(bound_annotation.entity_id, EntityRole.ENTITY), evidence=extra_evidence[3]),
        _anchor_proposal(proposal_type=ProposalType.SECURITY_EFFECT, ref=EntityRoleRef(custom_input.entity_id, EntityRole.METHOD), evidence=extra_evidence[4]),
        _anchor_proposal(proposal_type=ProposalType.EXTERNAL_INPUT, ref=EntityRoleRef(get_secondary.entity_id, EntityRole.RETURN), evidence=extra_evidence[5]),
        _anchor_proposal(proposal_type=ProposalType.SECURITY_EFFECT, ref=EntityRoleRef(framework_bound.entity_id, EntityRole.METHOD), evidence=extra_evidence[6]),
    ]
    extra_gate = EvidenceGate(repository_root=root, entities=entities, evidence_catalog=evidence)
    extra_results = extra_gate.evaluate_many(extra_proposals)
    if any(item.status != GateStatus.ADMISSIBLE for item in extra_results):
        raise AssertionError("controlled M5 anchor proposal failed M4 gate")

    proposals = [*base_proposals, *extra_proposals]
    gate_results = [*base_results, *extra_results]
    wrap = _entity(entities, "wrap", ProgramEntityKind.METHOD)
    hybrid_input = next(item for item in base_proposals if item.proposal_type == ProposalType.EXTERNAL_INPUT and item.subject.entity_id == custom_input.entity_id)
    hybrid_semantic = next(item for item in base_proposals if item.proposal_type == ProposalType.WRAPPER_FLOW and item.subject.entity_id == wrap.entity_id)
    hybrid_effect = next(item for item in base_proposals if item.proposal_type == ProposalType.SECURITY_EFFECT)
    if hybrid_semantic.source is None or hybrid_semantic.target is None:
        raise AssertionError("controlled wrapper proposal lacks source/target roles")
    codeql_specs = (
        (hybrid_input.subject, hybrid_semantic.source, "controlled-codeql-before-semantic"),
        (hybrid_semantic.target, hybrid_effect.subject, "controlled-codeql-after-semantic"),
    )
    codeql_evidence: list[EvidenceRef] = []
    for codeql_source, codeql_target, call_id in codeql_specs:
        item = EvidenceRef.create(
            source_kind=EvidenceSourceKind.CODEQL_DATAFLOW,
            entity_ids=[codeql_source.entity_id, codeql_target.entity_id],
            tool_call_id=call_id,
            result_hash=hashlib.sha256(call_id.encode("utf-8")).hexdigest(),
            confidence=EvidenceStrength.DIRECT,
            provenance={
                "producer": "WORK1_V11_M5_CONTROLLED",
                "query_hash": hashlib.sha256(f"{call_id}-query".encode("utf-8")).hexdigest(),
            },
        )
        evidence[item.evidence_id] = item
        codeql_evidence.append(item)
    tool_index = {**artifact_index}
    for item in codeql_evidence:
        assert item.tool_call_id is not None
        tool_index[item.tool_call_id] = {
            "status": "OK",
            "tool_name": "codeql_dataflow_neighbors",
            "query_hash": item.provenance["query_hash"],
        }
    builder = HybridEvidenceGraphBuilder(
        project_id=CONTROLLED_PROJECT_ID,
        entities=entities,
        evidence_catalog=evidence,
        proposals=proposals,
        gate_results=gate_results,
        tool_artifact_index=tool_index,
        manifest={"git_sha": git_sha, "fixture": str(root), "llm_used": False, "benchmark_input_used": False},
    )
    builder.add_proposal_edges()

    repository_source = base_proposals[0].subject
    repository_target = base_proposals[5].subject
    repository_evidence = EvidenceRef.create(
        source_kind=EvidenceSourceKind.REPOSITORY_RELATION,
        entity_ids=[repository_source.entity_id, repository_target.entity_id],
        confidence=EvidenceStrength.STRONG_STRUCTURAL,
        provenance={"producer": "WORK1_V11_M5_CONTROLLED", "relation": "LEXICAL_CALL", "llm_used": False},
    )
    evidence[repository_evidence.evidence_id] = repository_evidence
    builder.evidence_catalog[repository_evidence.evidence_id] = repository_evidence
    for relation_id in ("controlled-lexical-call-a", "controlled-lexical-call-b"):
        builder.add_repository_relation(
            source_ref=repository_source,
            target_ref=repository_target,
            relation_kind=RelationKind.LEXICAL_CALL,
            evidence_refs=[repository_evidence.evidence_id],
            repository_relation_ids=[relation_id],
            provenance={"source": "CONTROLLED_REPOSITORY_RELATION", "relation_id": relation_id},
        )
    cycle_evidence = EvidenceRef.create(
        source_kind=EvidenceSourceKind.REPOSITORY_RELATION,
        entity_ids=[get_state.entity_id, set_state.entity_id],
        confidence=EvidenceStrength.STRONG_STRUCTURAL,
        provenance={"producer": "WORK1_V11_M5_CONTROLLED", "relation": "OVERRIDE_CANDIDATE", "llm_used": False},
    )
    evidence[cycle_evidence.evidence_id] = cycle_evidence
    builder.evidence_catalog[cycle_evidence.evidence_id] = cycle_evidence
    for (codeql_source, codeql_target, call_id), evidence_item in zip(codeql_specs, codeql_evidence, strict=True):
        builder.add_codeql_relation(
            source_ref=codeql_source,
            target_ref=codeql_target,
            relation_kind=RelationKind.CODEQL_DATAFLOW,
            evidence_refs=[evidence_item.evidence_id],
            tool_call_ids=[call_id],
            provenance={"source": "CONTROLLED_CODEQL_RESULT", "query_hash": evidence_item.provenance["query_hash"]},
        )
    builder.add_repository_relation(
        source_ref=EntityRoleRef(get_state.entity_id, EntityRole.RETURN),
        target_ref=EntityRoleRef(set_state.entity_id, EntityRole.PARAMETER, 0),
        relation_kind=RelationKind.OVERRIDE_CANDIDATE,
        evidence_refs=[cycle_evidence.evidence_id],
        repository_relation_ids=["controlled-cycle"],
        provenance={"source": "CONTROLLED_CYCLE"},
    )
    # Explicitly attempt an invalid role and a non-admissible proposal edge.
    builder.node_for_ref(EntityRoleRef(get_state.entity_id, EntityRole.ARGUMENT, 99))
    rejected = next(item for item in base_results if item.status == GateStatus.REJECTED)
    rejected_proposal = next(item for item in base_proposals if item.proposal_id == rejected.proposal_id)
    subject = builder.node_for_ref(base_proposals[0].subject)
    target = builder.node_for_ref(base_proposals[5].subject)
    assert subject is not None and target is not None
    builder.add_edge(
        source=subject,
        target=target,
        relation_kind=RelationKind(rejected_proposal.proposal_type.value),
        support_class="ADMISSIBLE_SEMANTIC_PROPOSAL",
        evidence_refs=rejected_proposal.evidence_refs or base_proposals[0].evidence_refs,
        proposal_id=rejected_proposal.proposal_id,
        provenance={"source": "CONTROLLED_INVALID_ATTEMPT"},
    )

    graph = builder.build()
    native_path = _legacy_native_path()
    result = BoundedPathBuilder(search_limits or SearchLimits(max_depth=12, max_paths=20, max_nodes_expanded=10000)).search(
        graph, native_paths=[native_path], git_sha=git_sha
    )
    relation_sets = [{edge["relation_kind"] for edge in path.ordered_edges} for path in result.hybrid_paths]
    relation_sequences = [[edge["relation_kind"] for edge in path.ordered_edges] for path in result.hybrid_paths]
    codeql_semantic_codeql = ("CODEQL_DATAFLOW", "WRAPPER_FLOW", "CODEQL_DATAFLOW")
    disconnected_input = extra_proposals[-2]
    disconnected_effect = extra_proposals[-1]
    disconnected_pair_blocked = not any(
        path.input_anchor.get("anchor_proposal_id") == disconnected_input.proposal_id
        and path.effect_anchor.get("anchor_proposal_id") == disconnected_effect.proposal_id
        for path in result.hybrid_paths
    )
    scenarios = {
        "native_path_preserved": len(result.native_paths) == 1 and result.native_paths[0] is native_path,
        "repository_only_hybrid_path": any(path.support_summary["repository_only_hybrid"] for path in result.hybrid_paths),
        "codeql_assisted_hybrid_path": any(
            any(tuple(relations[index:index + 3]) == codeql_semantic_codeql for index in range(len(relations) - 2))
            for relations in relation_sequences
        ),
        "field_state_path": any("FIELD_STATE" in kinds for kinds in relation_sets),
        "framework_path": any("FRAMEWORK_RELATION" in kinds for kinds in relation_sets),
        "callback_path": any("CALLBACK_RELATION" in kinds for kinds in relation_sets),
        "cycle_prevented": result.cycle_prevention_count > 0,
        "duplicate_path_suppressed": result.deduplicated_path_count > 0,
        "invalid_proposal_edge_rejected": any(item.code == "PROPOSAL_NOT_ADMISSIBLE" for item in graph.diagnostics),
        "needs_more_evidence_inactive": not any(
            edge.proposal_id == item.proposal_id
            for item in base_results if item.status == GateStatus.NEEDS_MORE_EVIDENCE
            for edge in graph.edges
        ),
        "disconnected_anchor_pair_no_path": result.no_candidate_path_pairs > 0 and disconnected_pair_blocked,
    }
    if assert_scenarios and not all(scenarios.values()):
        raise AssertionError(f"controlled M5 scenarios incomplete: {scenarios}")
    summary = write_artifacts(
        output_root=artifact_root,
        graph=graph,
        result=result,
        manifest={
            "git_sha": git_sha,
            "source_project_identity": CONTROLLED_PROJECT_ID,
            "program_entity_index_hash": hashlib.sha256("\n".join(item.to_json() for item in entities).encode("utf-8")).hexdigest(),
            "m2_artifact_hashes": {
                "controlled-lexical-relation": hashlib.sha256(repository_evidence.to_json().encode("utf-8")).hexdigest(),
                "controlled-cycle-relation": hashlib.sha256(cycle_evidence.to_json().encode("utf-8")).hexdigest(),
            },
            "m3_artifact_hashes": {item.tool_call_id: item.result_hash for item in codeql_evidence},
            "m4_artifact_hashes": {
                "proposal_set": hashlib.sha256("\n".join(item.to_json() for item in proposals).encode("utf-8")).hexdigest(),
                "gate_results": hashlib.sha256("\n".join(item.to_json() for item in gate_results).encode("utf-8")).hexdigest(),
            },
            "scenario_results": scenarios,
        },
    )
    summary["scenario_results"] = scenarios
    (Path(artifact_root) / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Work1 V11 M5 controlled graph/path validation")
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--git-sha", required=True)
    args = parser.parse_args(argv)
    summary = run_controlled(repository_root=args.repository_root, artifact_root=args.artifact_root, git_sha=args.git_sha)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
