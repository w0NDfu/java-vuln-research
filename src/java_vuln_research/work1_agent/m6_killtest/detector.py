from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.hybrid_graph import BoundedPathBuilder, HybridEvidenceGraphBuilder, RelationKind, SearchLimits
from java_vuln_research.work1_agent.proposal.evidence import EvidenceRef
from java_vuln_research.work1_agent.proposal.gate import EvidenceGate, GateStatus
from java_vuln_research.work1_agent.proposal.model import EntityRoleRef, SecurityProposal
from java_vuln_research.work1_agent.repository.entity import ProgramEntity

from .contracts import M6_PROPOSAL_BUDGET
from .io import artifact_hashes, read_json, read_jsonl, write_json, write_jsonl


DETECTOR_VERSION = "WORK1_V11_M6_EXPLICIT_PROPOSAL_DETECTOR_V1"


def _load_entities(path: str | Path) -> list[ProgramEntity]:
    return [ProgramEntity.from_dict(row) for row in read_jsonl(path)]


def _load_evidence(path: str | Path) -> list[EvidenceRef]:
    return [EvidenceRef.from_dict(row) for row in read_jsonl(path)]


def _load_proposals(path: str | Path) -> list[SecurityProposal]:
    return [SecurityProposal.from_dict(row) for row in read_jsonl(path)]


def run_detector(
    *,
    detector_input_json: str | Path,
    proposals_jsonl: str | Path,
    output_root: str | Path,
    proposal_ids: Sequence[str] | None = None,
    git_sha: str = "UNKNOWN",
) -> dict[str, Any]:
    config = read_json(detector_input_json)
    output = Path(output_root)
    output.mkdir(parents=True, exist_ok=True)
    entities = _load_entities(config["entity_index"])
    evidence = _load_evidence(config["evidence_refs"])
    evidence_index = {item.evidence_id: item for item in evidence}
    proposals = _load_proposals(proposals_jsonl)
    if proposal_ids is not None:
        selected = set(proposal_ids)
        proposals = [item for item in proposals if item.proposal_id in selected]
    if len(proposals) > M6_PROPOSAL_BUDGET:
        raise ValueError(f"proposal budget exceeded: {len(proposals)} > {M6_PROPOSAL_BUDGET}")
    gate = EvidenceGate(
        repository_root=config["source_root"],
        entities=entities,
        evidence_catalog=evidence_index,
    )
    gate_results = gate.evaluate_many(proposals)
    builder = HybridEvidenceGraphBuilder(
        project_id=str(config["project_id"]),
        entities=entities,
        evidence_catalog=evidence_index,
        proposals=proposals,
        gate_results=gate_results,
        manifest={"producer": DETECTOR_VERSION},
    )
    for relation in config.get("repository_relations", ()):
        builder.add_repository_relation(
            source_ref=EntityRoleRef.from_dict(relation["source"]),
            target_ref=EntityRoleRef.from_dict(relation["target"]),
            relation_kind=RelationKind(relation["relation_kind"]),
            evidence_refs=relation["evidence_refs"],
            repository_relation_ids=[str(relation["relation_id"])],
            provenance=dict(relation["provenance"]),
        )
    builder.add_proposal_edges()
    graph = builder.build()
    search = BoundedPathBuilder(SearchLimits(max_depth=12, max_paths=20, max_nodes_expanded=2000)).search(graph, git_sha=git_sha)
    write_jsonl(output / "gate_results.jsonl", gate_results)
    write_jsonl(output / "graph_nodes.jsonl", graph.nodes)
    write_jsonl(output / "graph_edges.jsonl", graph.edges)
    write_jsonl(output / "candidate_paths.jsonl", search.all_candidate_paths)
    write_jsonl(output / "graph_diagnostics.jsonl", graph.diagnostics)
    write_jsonl(output / "path_diagnostics.jsonl", search.diagnostics)
    active = [item for item in gate_results if item.status == GateStatus.ADMISSIBLE]
    summary = {
        "detector_version": DETECTOR_VERSION,
        "project_id": config["project_id"],
        "proposal_count": len(proposals),
        "admissible_proposal_count": len(active),
        "gate_status_counts": {
            status.value: sum(item.status == status for item in gate_results)
            for status in GateStatus
        },
        "graph_node_count": len(graph.nodes),
        "graph_edge_count": len(graph.edges),
        "candidate_path_count": len(search.all_candidate_paths),
        "hybrid_path_count": len(search.hybrid_paths),
        "search_truncation_count": search.search_truncation_count,
        "nodes_expanded": search.nodes_expanded,
        "proposal_budget": M6_PROPOSAL_BUDGET,
        "benchmark_input_read": False,
        "detector_annotation_access": False,
        "eligible_for_detection_metric": False,
    }
    write_json(output / "summary.json", summary)
    names = (
        "gate_results.jsonl",
        "graph_nodes.jsonl",
        "graph_edges.jsonl",
        "candidate_paths.jsonl",
        "graph_diagnostics.jsonl",
        "path_diagnostics.jsonl",
        "summary.json",
    )
    manifest = {
        "schema_version": 1,
        "detector_version": DETECTOR_VERSION,
        "detector_frozen": True,
        "project_id": config["project_id"],
        "git_sha": git_sha,
        "input_entity_index_hash": config["entity_index_hash"],
        "proposal_ids": [item.proposal_id for item in proposals],
        "artifact_hashes": artifact_hashes(output, names),
        "benchmark_input_read": False,
        "detector_annotation_access": False,
    }
    write_json(output / "detector_manifest.json", manifest)
    return {**summary, "manifest": manifest}
