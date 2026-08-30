"""Deterministic M5 graph/path rebuild adapter for admitted M7 proposals."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.hybrid_graph import (
    BoundedPathBuilder,
    HybridEvidenceGraph,
    HybridEvidenceGraphBuilder,
    PathSearchResult,
    RelationKind,
    SearchLimits,
    SupportClass,
)
from java_vuln_research.work1_agent.proposal import EntityRoleRef, EvidenceGate, EvidenceGateResult, SecurityProposal
from java_vuln_research.work1_agent.repository.entity import ProgramEntity


@dataclass(frozen=True, slots=True)
class AgentGraphPathResult:
    graph: HybridEvidenceGraph
    path_search: PathSearchResult

    @property
    def candidate_path_ids(self) -> tuple[str, ...]:
        native = (str(item["candidate_path_id"]) for item in self.path_search.native_paths)
        hybrid = (item.candidate_path_id for item in self.path_search.hybrid_paths)
        return tuple(sorted((*native, *hybrid)))

    def summary(self) -> dict[str, Any]:
        return {
            "node_count": len(self.graph.nodes),
            "edge_count": len(self.graph.edges),
            "hybrid_path_count": len(self.path_search.hybrid_paths),
            "native_path_count": len(self.path_search.native_paths),
            "candidate_path_ids": list(self.candidate_path_ids),
            "nodes_expanded": self.path_search.nodes_expanded,
            "cycle_prevention_count": self.path_search.cycle_prevention_count,
            "deduplicated_path_count": self.path_search.deduplicated_path_count,
            "search_truncation_count": self.path_search.search_truncation_count,
            "no_candidate_path_pairs": self.path_search.no_candidate_path_pairs,
            "diagnostics": [dict(item) for item in self.path_search.diagnostics],
        }


@dataclass(frozen=True, slots=True)
class AgentGraphRelation:
    source_ref: EntityRoleRef
    target_ref: EntityRoleRef
    relation_kind: RelationKind
    support_class: SupportClass
    evidence_refs: tuple[str, ...]
    provenance: Mapping[str, Any]
    tool_call_ids: tuple[str, ...] = ()
    repository_relation_ids: tuple[str, ...] = ()

    def add_to(self, builder: HybridEvidenceGraphBuilder) -> None:
        if self.support_class is SupportClass.DETERMINISTIC_FACT:
            builder.add_codeql_relation(
                source_ref=self.source_ref,
                target_ref=self.target_ref,
                relation_kind=self.relation_kind,
                evidence_refs=self.evidence_refs,
                tool_call_ids=self.tool_call_ids,
                provenance=self.provenance,
            )
        elif self.support_class is SupportClass.STRUCTURAL_EVIDENCE:
            builder.add_repository_relation(
                source_ref=self.source_ref,
                target_ref=self.target_ref,
                relation_kind=self.relation_kind,
                evidence_refs=self.evidence_refs,
                repository_relation_ids=self.repository_relation_ids,
                provenance=self.provenance,
            )
        else:
            raise ValueError("base graph relation cannot be a semantic proposal edge")


class AgentGraphPathAdapter:
    def __init__(
        self,
        *,
        project_id: str,
        entities: Sequence[ProgramEntity],
        evidence_gate: EvidenceGate,
        native_paths: Sequence[Mapping[str, Any]] = (),
        base_relations: Sequence[AgentGraphRelation] = (),
        search_limits: SearchLimits | None = None,
        git_sha: str = "UNKNOWN",
    ) -> None:
        self.project_id = project_id
        self.entities = tuple(entities)
        self.evidence_gate = evidence_gate
        self.native_paths = tuple(native_paths)
        self.base_relations = tuple(base_relations)
        self.path_builder = BoundedPathBuilder(search_limits or SearchLimits())
        self.git_sha = git_sha

    def rebuild(
        self,
        *,
        proposals: Sequence[SecurityProposal],
        gate_results: Sequence[EvidenceGateResult],
    ) -> AgentGraphPathResult:
        builder = HybridEvidenceGraphBuilder(
            project_id=self.project_id,
            entities=self.entities,
            evidence_catalog=self.evidence_gate.evidence_catalog,
            proposals=proposals,
            gate_results=gate_results,
            tool_artifact_index=self.evidence_gate.artifact_index,
            manifest={
                "producer": "M7_AGENT_GRAPH_ADAPTER",
                "incremental_rebuild": True,
                "native_paths_preserved": True,
            },
        )
        for relation in self.base_relations:
            relation.add_to(builder)
        builder.add_proposal_edges()
        graph = builder.build()
        search = self.path_builder.search(graph, native_paths=self.native_paths, git_sha=self.git_sha)
        return AgentGraphPathResult(graph, search)
