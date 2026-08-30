from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .model import (
    HybridCandidatePath,
    HybridEdge,
    HybridEvidenceGraph,
    NodeKind,
    SupportClass,
)


SUPPORT_PRIORITY = {
    SupportClass.DETERMINISTIC_FACT: 0,
    SupportClass.STRUCTURAL_EVIDENCE: 1,
    SupportClass.ADMISSIBLE_SEMANTIC_PROPOSAL: 2,
}


@dataclass(frozen=True, slots=True)
class SearchLimits:
    max_depth: int = 12
    max_paths: int = 20
    max_nodes_expanded: int = 2000

    def __post_init__(self) -> None:
        if not 1 <= self.max_depth <= 20:
            raise ValueError("max_depth hard ceiling is 20")
        if not 1 <= self.max_paths <= 20:
            raise ValueError("max_paths hard ceiling is 20")
        if not 1 <= self.max_nodes_expanded <= 10000:
            raise ValueError("max_nodes_expanded hard ceiling is 10000")


@dataclass(frozen=True, slots=True)
class PathSearchResult:
    hybrid_paths: tuple[HybridCandidatePath, ...]
    native_paths: tuple[Mapping[str, Any], ...]
    diagnostics: tuple[Mapping[str, Any], ...]
    nodes_expanded: int
    cycle_prevention_count: int
    deduplicated_path_count: int
    search_truncation_count: int
    no_candidate_path_pairs: int

    @property
    def all_candidate_paths(self) -> tuple[Mapping[str, Any], ...]:
        return (*self.native_paths, *(item.to_dict() for item in self.hybrid_paths))


class NativePathAdapter:
    """Preserve CandidatePath schema-v2 native paths byte-semantically unchanged."""

    @staticmethod
    def preserve(paths: Sequence[Mapping[str, Any]]) -> tuple[Mapping[str, Any], ...]:
        result: list[Mapping[str, Any]] = []
        for path in paths:
            if not path.get("candidate_path_id") or not path.get("project_id"):
                raise ValueError("native candidate path is missing stable identity")
            if int(path.get("schema_version", 0)) != 2:
                raise ValueError("NativePathAdapter accepts frozen CandidatePath schema version 2")
            result.append(path)
        return tuple(result)


class BoundedPathBuilder:
    def __init__(self, limits: SearchLimits | None = None) -> None:
        self.limits = limits or SearchLimits()

    def search(
        self,
        graph: HybridEvidenceGraph,
        *,
        native_paths: Sequence[Mapping[str, Any]] = (),
        git_sha: str = "UNKNOWN",
    ) -> PathSearchResult:
        native = NativePathAdapter.preserve(native_paths)
        nodes = graph.node_index()
        adjacency: dict[str, list[HybridEdge]] = {}
        for edge in graph.edges:
            adjacency.setdefault(edge.source_node_id, []).append(edge)
        for values in adjacency.values():
            values.sort(key=lambda item: (SUPPORT_PRIORITY[item.support_class], item.relation_kind.value, item.edge_id))
        inputs = sorted((item for item in graph.nodes if item.node_kind == NodeKind.SECURITY_INPUT_ROOT), key=lambda item: item.node_id)
        effects = sorted((item for item in graph.nodes if item.node_kind == NodeKind.SECURITY_EFFECT_ROOT), key=lambda item: item.node_id)
        effect_ids = {item.node_id for item in effects}
        found: dict[str, HybridCandidatePath] = {}
        pair_counts: dict[tuple[str, str], int] = {}
        nodes_expanded = cycles = deduplicated = truncations = 0
        reached_pairs: set[tuple[str, str]] = set()
        diagnostics: list[dict[str, Any]] = []

        for input_node in inputs:
            stack: list[tuple[str, tuple[str, ...], tuple[HybridEdge, ...]]] = [(input_node.node_id, (input_node.node_id,), ())]
            while stack:
                if nodes_expanded >= self.limits.max_nodes_expanded:
                    truncations += 1
                    diagnostics.append({"code": "MAX_NODES_EXPANDED", "project_id": graph.project_id, "input_anchor": input_node.node_id, "limit": self.limits.max_nodes_expanded})
                    stack.clear()
                    break
                current, node_path, edge_path = stack.pop()
                nodes_expanded += 1
                if current in effect_ids and edge_path:
                    pair = (input_node.node_id, current)
                    reached_pairs.add(pair)
                    if pair_counts.get(pair, 0) >= self.limits.max_paths:
                        truncations += 1
                        continue
                    candidate = HybridCandidatePath.create(
                        project_id=graph.project_id,
                        nodes=[nodes[item] for item in node_path],
                        edges=edge_path,
                        provenance={
                            "builder": "WORK1_V11_M5_BOUNDED_PATH_SEARCH_V1",
                            "git_sha": git_sha,
                            "graph_schema_version": graph.manifest.get("graph_schema_version"),
                            "warning": "candidate path is not a confirmed vulnerability",
                        },
                    )
                    if candidate.path_fingerprint in found:
                        deduplicated += 1
                    else:
                        found[candidate.path_fingerprint] = candidate
                        pair_counts[pair] = pair_counts.get(pair, 0) + 1
                    continue
                if len(edge_path) >= self.limits.max_depth:
                    if adjacency.get(current):
                        truncations += 1
                    continue
                outgoing = adjacency.get(current, ())
                for edge in reversed(outgoing):
                    if edge.target_node_id in node_path:
                        cycles += 1
                        continue
                    stack.append((edge.target_node_id, (*node_path, edge.target_node_id), (*edge_path, edge)))

        no_path_pairs = len(inputs) * len(effects) - len(reached_pairs)
        if no_path_pairs:
            diagnostics.append({"code": "NO_CANDIDATE_PATH", "project_id": graph.project_id, "anchor_pair_count": no_path_pairs})
        hybrid = tuple(sorted(found.values(), key=lambda item: (item.path_fingerprint, item.candidate_path_id)))
        return PathSearchResult(
            hybrid_paths=hybrid,
            native_paths=native,
            diagnostics=tuple(diagnostics),
            nodes_expanded=nodes_expanded,
            cycle_prevention_count=cycles,
            deduplicated_path_count=deduplicated,
            search_truncation_count=truncations,
            no_candidate_path_pairs=no_path_pairs,
        )
