from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.proposal.evidence import EvidenceRef, EvidenceSourceKind, EvidenceStrength
from java_vuln_research.work1_agent.proposal.gate import EvidenceGate, EvidenceGateResult, GateStatus
from java_vuln_research.work1_agent.proposal.model import EntityRole, ProposalScope, ProposalType, ScopeKind, SecurityProposal
from java_vuln_research.work1_agent.proposal.real_smoke import REAL_PROJECT_COHORT, _entities_path, _load_entities
from java_vuln_research.work1_agent.proposal.serialization import read_evidence, read_proposals
from java_vuln_research.work1_agent.repository.entity import ProgramEntity

from .builder import HybridEvidenceGraphBuilder
from .model import NodeKind
from .path import BoundedPathBuilder, SearchLimits
from .serialization import combine_artifact_sets, file_sha256, write_artifacts


def _read_gate_results(path: Path) -> list[Mapping[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _source_evidence(root: Path, entity: ProgramEntity, project_id: str, label: str) -> EvidenceRef:
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
        provenance={
            "producer": "WORK1_V11_M5_REAL_PROJECT_SMOKE",
            "project_id": project_id,
            "label": label,
            "llm_used": False,
            "benchmark_vulnerability_location_patch_cve_cwe_used": False,
        },
    )


def _effect_proposal(project_id: str, source_proposal: SecurityProposal, evidence: EvidenceRef, *, label: str) -> SecurityProposal:
    return SecurityProposal.create(
        proposal_type=ProposalType.SECURITY_EFFECT,
        subject=source_proposal.subject,
        scope=ProposalScope(ScopeKind.ENTITY, (source_proposal.subject.entity_id,), project_id),
        evidence_refs=[evidence.evidence_id],
        reason="Manual source-grounded M5 mechanism anchor; not a confirmed security effect or vulnerability.",
        semantic_category="UNKNOWN",
        provenance={
            "producer": "WORK1_V11_M5_REAL_PROJECT_SMOKE",
            "project_id": project_id,
            "label": label,
            "llm_used": False,
            "benchmark_vulnerability_location_patch_cve_cwe_used": False,
        },
    )


def _tool_index(path: Path) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get("tool_call_id"):
            result[str(item["tool_call_id"])] = item
    return result


def _update_summary_and_hash(root: Path, updates: Mapping[str, Any]) -> dict[str, Any]:
    summary_path = root / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary.update(updates)
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.setdefault("artifact_hashes", {})["summary.json"] = file_sha256(summary_path)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def run_real(
    *,
    inventory_csv: str | Path,
    index_roots: Sequence[str | Path],
    m3_tool_calls: str | Path,
    m4_root: str | Path,
    artifact_root: str | Path,
    git_sha: str,
) -> dict[str, Any]:
    inventory_path = Path(inventory_csv)
    with inventory_path.open(encoding="utf-8-sig", newline="") as handle:
        inventory = {str(row["project_id"]): row for row in csv.DictReader(handle)}
    index_paths = [Path(item) for item in index_roots]
    m3_path = Path(m3_tool_calls)
    m4 = Path(m4_root)
    proposal_path = m4 / "proposals.jsonl"
    gate_path = m4 / "gate_results.jsonl"
    evidence_path = m4 / "evidence_index.jsonl"
    m4_proposals = read_proposals(proposal_path)
    m4_results = _read_gate_results(gate_path)
    m4_evidence = read_evidence(evidence_path)
    tool_index = _tool_index(m3_path)
    project_roots: list[Path] = []
    project_summaries: list[dict[str, Any]] = []
    program_hashes: dict[str, str] = {}
    output = Path(artifact_root)

    for project_id in REAL_PROJECT_COHORT:
        row = inventory[project_id]
        source_root = Path(str(row["source_root"]))
        entities_path = _entities_path(index_paths, project_id)
        entities = _load_entities(entities_path)
        entity_by_id = {item.entity_id: item for item in entities}
        project_proposals = [item for item in m4_proposals if str(item.provenance.get("project_id")) == project_id]
        project_results = [item for item in m4_results if str((item.get("provenance") or {}).get("proposal_provenance", {}).get("project_id")) == project_id]
        proposal_ids = {item.proposal_id for item in project_proposals}
        project_evidence = {item.evidence_id: item for item in m4_evidence if proposal_ids.intersection({p.proposal_id for p in project_proposals if item.evidence_id in p.evidence_refs})}
        admitted_inputs = [item for item in project_proposals if item.proposal_type == ProposalType.EXTERNAL_INPUT]
        if not admitted_inputs:
            raise ValueError(f"M4 external input proposal missing for {project_id}")
        selected = sorted(admitted_inputs, key=lambda item: item.proposal_id)[0]
        selected_entity = entity_by_id[selected.subject.entity_id]
        same_evidence = _source_evidence(source_root, selected_entity, project_id, "same-node-effect")
        same_effect = _effect_proposal(project_id, selected, same_evidence, label="same-node-effect")
        other_entity = next(item for item in entities if item.entity_id != selected_entity.entity_id and item.kind.value in {"METHOD", "CONSTRUCTOR", "CALL", "FIELD", "PARAMETER"})
        # Select a role already proven compatible by another M4 proposal when possible.
        alternate = next((item for item in admitted_inputs if item.subject.entity_id != selected.subject.entity_id), None)
        if alternate is not None:
            disconnected_ref = alternate.subject
            other_entity = entity_by_id[disconnected_ref.entity_id]
        else:
            disconnected_ref = selected.subject.__class__(other_entity.entity_id, EntityRole.ENTITY)
        disconnected_evidence = _source_evidence(source_root, other_entity, project_id, "disconnected-effect")
        disconnected_effect = SecurityProposal.create(
            proposal_type=ProposalType.SECURITY_EFFECT,
            subject=disconnected_ref,
            scope=ProposalScope(ScopeKind.ENTITY, (disconnected_ref.entity_id,), project_id),
            evidence_refs=[disconnected_evidence.evidence_id],
            reason="Manual disconnected negative anchor; no relation is asserted.",
            semantic_category="UNKNOWN",
            provenance={
                "producer": "WORK1_V11_M5_REAL_PROJECT_SMOKE",
                "project_id": project_id,
                "label": "disconnected-effect",
                "llm_used": False,
                "benchmark_vulnerability_location_patch_cve_cwe_used": False,
            },
        )
        project_evidence[same_evidence.evidence_id] = same_evidence
        project_evidence[disconnected_evidence.evidence_id] = disconnected_evidence
        extra_gate = EvidenceGate(repository_root=source_root, entities=entities, evidence_catalog=project_evidence)
        extra_results = extra_gate.evaluate_many([same_effect, disconnected_effect])
        if any(item.status != GateStatus.ADMISSIBLE for item in extra_results):
            raise AssertionError(f"real M5 manual anchors failed gate for {project_id}")
        all_project_proposals = [*project_proposals, same_effect, disconnected_effect]
        all_project_results: list[EvidenceGateResult | Mapping[str, Any]] = [*project_results, *extra_results]
        builder = HybridEvidenceGraphBuilder(
            project_id=project_id,
            entities=entities,
            evidence_catalog=project_evidence,
            proposals=all_project_proposals,
            gate_results=all_project_results,
            tool_artifact_index=tool_index,
            manifest={"git_sha": git_sha, "source_root": str(source_root), "bounded": True},
        )
        builder.add_proposal_edges()
        full_graph = builder.build()
        seed_ids = [
            item.node_id
            for item in full_graph.nodes
            if item.node_kind in {NodeKind.SECURITY_INPUT_ROOT, NodeKind.SECURITY_EFFECT_ROOT}
        ]
        graph = builder.build_subgraph(seed_node_ids=seed_ids, max_nodes=64, max_edges=64, max_depth=4)
        result = BoundedPathBuilder(SearchLimits(max_depth=4, max_paths=10, max_nodes_expanded=256)).search(graph, git_sha=git_sha)
        exact_same_path = any(
            path.input_anchor.get("anchor_proposal_id") == selected.proposal_id
            and path.effect_anchor.get("anchor_proposal_id") == same_effect.proposal_id
            for path in result.hybrid_paths
        )
        disconnected_negative_blocked = not any(
            path.input_anchor.get("anchor_proposal_id") == selected.proposal_id
            and path.effect_anchor.get("anchor_proposal_id") == disconnected_effect.proposal_id
            for path in result.hybrid_paths
        )
        if not exact_same_path:
            raise AssertionError(f"same-node grounded M5 mechanism path missing for {project_id}")
        if result.no_candidate_path_pairs < 1 or not disconnected_negative_blocked:
            raise AssertionError(f"disconnected negative pair was unexpectedly connected for {project_id}")
        project_root = output / "projects" / project_id
        project_roots.append(project_root)
        program_hashes[project_id] = file_sha256(entities_path)
        project_summary = write_artifacts(
            output_root=project_root,
            graph=graph,
            result=result,
            manifest={
                "git_sha": git_sha,
                "source_project_identity": project_id,
                "source_revision": row.get("source_revision") or row.get("revision"),
                "program_entity_index_hash": program_hashes[project_id],
                "m2_artifact_hashes": {"entities.jsonl": program_hashes[project_id]},
                "m3_artifact_hashes": {"tool_calls.jsonl": file_sha256(m3_path)},
                "m4_artifact_hashes": {
                    "proposals.jsonl": file_sha256(proposal_path),
                    "gate_results.jsonl": file_sha256(gate_path),
                    "evidence_index.jsonl": file_sha256(evidence_path),
                },
                "benchmark_vulnerability_location_patch_cve_cwe_used": False,
                "llm_used": False,
            },
        )
        project_summaries.append({
            "project_id": project_id,
            "codeql_ready": str(row.get("codeql_db_ready", "")).casefold() == "true",
            "candidate_path_count": project_summary["candidate_path_count"],
            "repository_only_hybrid_path_count": project_summary["repository_only_hybrid_path_count"],
            "no_candidate_path_cases": project_summary["no_candidate_path_cases"],
            "expected_same_anchor_path_constructed": exact_same_path,
            "disconnected_negative_blocked": disconnected_negative_blocked,
            "graph_node_count": project_summary["graph_node_count"],
            "graph_edge_count": project_summary["graph_edge_count"],
        })

    summary = combine_artifact_sets(
        roots=project_roots,
        output_root=output,
        manifest={
            "git_sha": git_sha,
            "source_project_identity": list(REAL_PROJECT_COHORT),
            "program_entity_index_hashes": program_hashes,
            "m2_artifact_hashes": {item: program_hashes[item] for item in REAL_PROJECT_COHORT},
            "m3_artifact_hashes": {"tool_calls.jsonl": file_sha256(m3_path)},
            "m4_artifact_hashes": {
                "proposals.jsonl": file_sha256(proposal_path),
                "gate_results.jsonl": file_sha256(gate_path),
                "evidence_index.jsonl": file_sha256(evidence_path),
            },
            "inventory_hash": file_sha256(inventory_path),
            "benchmark_vulnerability_location_patch_cve_cwe_used": False,
            "llm_used": False,
        },
    )
    return _update_summary_and_hash(output, {
        "cohort": list(REAL_PROJECT_COHORT),
        "selection_rule": "same deterministic M4 family: first two P, first two D, first four V",
        "projects": project_summaries,
        "project_count": len(project_summaries),
        "benchmark_vulnerability_location_patch_cve_cwe_used": False,
        "all_disconnected_negative_pairs_blocked": all(item["disconnected_negative_blocked"] for item in project_summaries),
    })


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Work1 V11 M5 real-project graph/path grounding smoke")
    parser.add_argument("--inventory-csv", required=True)
    parser.add_argument("--index-root", action="append", required=True)
    parser.add_argument("--m3-tool-calls", required=True)
    parser.add_argument("--m4-root", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--controlled-root")
    parser.add_argument("--combined-root")
    args = parser.parse_args(argv)
    summary = run_real(
        inventory_csv=args.inventory_csv,
        index_roots=args.index_root,
        m3_tool_calls=args.m3_tool_calls,
        m4_root=args.m4_root,
        artifact_root=args.artifact_root,
        git_sha=args.git_sha,
    )
    if args.controlled_root and args.combined_root:
        summary = combine_artifact_sets(
            roots=[args.controlled_root, args.artifact_root],
            output_root=args.combined_root,
            manifest={
                "git_sha": args.git_sha,
                "components": ["controlled_fixture", "real_project_smoke"],
                "benchmark_vulnerability_location_patch_cve_cwe_used": False,
                "llm_used": False,
            },
        )
        summary = _update_summary_and_hash(Path(args.combined_root), {
            "controlled_fixture": json.loads((Path(args.controlled_root) / "summary.json").read_text(encoding="utf-8")),
            "real_project_smoke": json.loads((Path(args.artifact_root) / "summary.json").read_text(encoding="utf-8")),
        })
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
