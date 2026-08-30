from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from java_vuln_research.work1_agent.proposal.model import canonical_json

from .model import HybridEvidenceGraph
from .path import PathSearchResult


def _write_jsonl(path: Path, values: Iterable[Any]) -> None:
    rows: list[str] = []
    for value in values:
        encoded = value.to_dict() if hasattr(value, "to_dict") else value
        rows.append(canonical_json(encoded))
    path.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8", newline="\n")


def file_sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def graph_summary(graph: HybridEvidenceGraph, result: PathSearchResult) -> dict[str, Any]:
    relation_counts = Counter(item.relation_kind.value for item in graph.edges)
    support_counts = Counter(item.support_class.value for item in graph.edges)
    proposal_edges = sum(item.proposal_id is not None for item in graph.edges)
    codeql_edges = sum(item.relation_kind.value.startswith("CODEQL_") for item in graph.edges)
    repository_edges = sum(item.support_class.value == "STRUCTURAL_EVIDENCE" for item in graph.edges)
    hybrid_paths = list(result.hybrid_paths)
    lengths = [int(item.support_summary["path_length"]) for item in hybrid_paths]
    proposal_per_path = [int(item.support_summary["proposal_edge_count"]) for item in hybrid_paths]
    proposal_types_in_paths = Counter(
        edge["relation_kind"]
        for path in hybrid_paths
        for edge in path.ordered_edges
        if edge["support_class"] == "ADMISSIBLE_SEMANTIC_PROPOSAL"
    )
    invalid_codes = {
        "EDGE_NODE_NOT_FOUND", "CROSS_REPOSITORY_EDGE", "SUPPORT_CLASS_MISMATCH", "UNKNOWN_RELATION_OR_SUPPORT",
        "ANONYMOUS_EDGE", "EDGE_PROVENANCE_REQUIRED",
        "EVIDENCE_REF_NOT_FOUND", "FABRICATED_CODEQL_EDGE", "CODEQL_TOOL_CALL_NOT_FOUND",
        "EVIDENCE_ENTITY_NOT_FOUND", "CODEQL_TOOL_CALL_NOT_OK", "CODEQL_TOOL_EVIDENCE_MISMATCH",
        "REPOSITORY_EVIDENCE_REQUIRED", "REPOSITORY_EVIDENCE_ENDPOINT_MISMATCH",
        "PROPOSAL_NOT_ADMISSIBLE", "PROPOSAL_EVIDENCE_MISMATCH",
        "PROPOSAL_GATE_EVIDENCE_UNRESOLVED", "INVALID_ROLE_NODE", "ENTITY_NOT_FOUND",
    }
    return {
        "graph_node_count": len(graph.nodes),
        "graph_edge_count": len(graph.edges),
        "edge_count_by_relation_kind": dict(sorted(relation_counts.items())),
        "edge_count_by_support_class": dict(sorted(support_counts.items())),
        "proposal_derived_edge_count": proposal_edges,
        "codeql_derived_edge_count": codeql_edges,
        "repository_derived_edge_count": repository_edges,
        "candidate_path_count": len(result.native_paths) + len(hybrid_paths),
        "native_path_count": len(result.native_paths),
        "hybrid_path_count": len(hybrid_paths),
        "repository_only_hybrid_path_count": sum(bool(item.support_summary["repository_only_hybrid"]) for item in hybrid_paths),
        "average_path_length": round(sum(lengths) / len(lengths), 6) if lengths else None,
        "average_proposal_edges_per_path": round(sum(proposal_per_path) / len(proposal_per_path), 6) if proposal_per_path else None,
        "proposal_types_participating_in_paths": dict(sorted(proposal_types_in_paths.items())),
        "deduplicated_path_count": result.deduplicated_path_count,
        "search_truncation_count": result.search_truncation_count,
        "cycle_prevention_count": result.cycle_prevention_count,
        "nodes_expanded": result.nodes_expanded,
        "invalid_edge_rejection_count": sum(item.code in invalid_codes for item in graph.diagnostics),
        "no_candidate_path_cases": result.no_candidate_path_pairs,
        "detection_rate": None,
        "interpretation": "M5 mechanism statistics only; candidate paths are not confirmed vulnerabilities.",
    }


def write_artifacts(
    *,
    output_root: str | Path,
    graph: HybridEvidenceGraph,
    result: PathSearchResult,
    manifest: Mapping[str, Any],
    summary_extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    output = Path(output_root)
    output.mkdir(parents=True, exist_ok=True)
    _write_jsonl(output / "graph_nodes.jsonl", graph.nodes)
    _write_jsonl(output / "graph_edges.jsonl", graph.edges)
    _write_jsonl(output / "candidate_paths.jsonl", result.all_candidate_paths)
    _write_jsonl(output / "graph_diagnostics.jsonl", graph.diagnostics)
    _write_jsonl(output / "path_diagnostics.jsonl", result.diagnostics)
    summary = graph_summary(graph, result)
    if summary_extra:
        summary.update(dict(summary_extra))
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    artifact_names = (
        "graph_nodes.jsonl", "graph_edges.jsonl", "candidate_paths.jsonl",
        "graph_diagnostics.jsonl", "path_diagnostics.jsonl", "summary.json",
    )
    resolved_manifest = {
        "graph_schema_version": 1,
        "hybrid_candidate_path_schema_version": 1,
        "legacy_candidate_path_schema_version": 2,
        "source_project_identity": graph.project_id,
        "artifact_hashes": {name: file_sha256(output / name) for name in artifact_names},
        **dict(manifest),
    }
    (output / "manifest.json").write_text(json.dumps(resolved_manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def combine_artifact_sets(*, roots: Sequence[str | Path], output_root: str | Path, manifest: Mapping[str, Any]) -> dict[str, Any]:
    output = Path(output_root)
    output.mkdir(parents=True, exist_ok=True)
    line_files = (
        "graph_nodes.jsonl", "graph_edges.jsonl", "candidate_paths.jsonl",
        "graph_diagnostics.jsonl", "path_diagnostics.jsonl",
    )
    rows_by_file: dict[str, list[dict[str, Any]]] = {name: [] for name in line_files}
    summaries: list[dict[str, Any]] = []
    component_manifests: list[dict[str, Any]] = []
    for root_value in roots:
        root = Path(root_value)
        summaries.append(json.loads((root / "summary.json").read_text(encoding="utf-8")))
        component_manifests.append(json.loads((root / "manifest.json").read_text(encoding="utf-8")))
        for name in line_files:
            rows_by_file[name].extend(json.loads(line) for line in (root / name).read_text(encoding="utf-8").splitlines() if line.strip())
    for name, rows in rows_by_file.items():
        key = "node_id" if name == "graph_nodes.jsonl" else "edge_id" if name == "graph_edges.jsonl" else "candidate_path_id" if name == "candidate_paths.jsonl" else None
        if key:
            unique: dict[str, dict[str, Any]] = {}
            for row in rows:
                unique.setdefault(str(row.get(key)), row)
            rows = [unique[item] for item in sorted(unique)]
        _write_jsonl(output / name, rows)
    additive = {
        key: sum(int(item.get(key) or 0) for item in summaries)
        for key in (
            "graph_node_count", "graph_edge_count", "proposal_derived_edge_count", "codeql_derived_edge_count",
            "repository_derived_edge_count", "candidate_path_count", "native_path_count", "hybrid_path_count",
            "repository_only_hybrid_path_count", "deduplicated_path_count", "search_truncation_count",
            "cycle_prevention_count", "nodes_expanded", "invalid_edge_rejection_count", "no_candidate_path_cases",
        )
    }
    relation = Counter()
    support = Counter()
    participating = Counter()
    for item in summaries:
        relation.update(item.get("edge_count_by_relation_kind", {}))
        support.update(item.get("edge_count_by_support_class", {}))
        participating.update(item.get("proposal_types_participating_in_paths", {}))
    path_rows = rows_by_file["candidate_paths.jsonl"]
    hybrid_rows = [item for item in path_rows if item.get("path_origin") == "HYBRID"]
    lengths = [int(item["support_summary"]["path_length"]) for item in hybrid_rows]
    proposals = [int(item["support_summary"]["proposal_edge_count"]) for item in hybrid_rows]
    summary = {
        **additive,
        "edge_count_by_relation_kind": dict(sorted(relation.items())),
        "edge_count_by_support_class": dict(sorted(support.items())),
        "proposal_types_participating_in_paths": dict(sorted(participating.items())),
        "average_path_length": round(sum(lengths) / len(lengths), 6) if lengths else None,
        "average_proposal_edges_per_path": round(sum(proposals) / len(proposals), 6) if proposals else None,
        "component_summaries": summaries,
        "detection_rate": None,
        "interpretation": "Combined M5 mechanism statistics only; no benchmark evaluation was performed.",
    }
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    artifact_names = (*line_files, "summary.json")
    resolved_manifest = {
        "graph_schema_version": 1,
        "hybrid_candidate_path_schema_version": 1,
        "legacy_candidate_path_schema_version": 2,
        "component_roots": [str(Path(item)) for item in roots],
        "component_input_lineage": component_manifests,
        "artifact_hashes": {name: file_sha256(output / name) for name in artifact_names},
        **dict(manifest),
    }
    (output / "manifest.json").write_text(json.dumps(resolved_manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary
