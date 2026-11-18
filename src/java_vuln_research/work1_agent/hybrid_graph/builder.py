from __future__ import annotations

from collections import deque
from dataclasses import replace
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.proposal.evidence import EvidenceRef, EvidenceSourceKind
from java_vuln_research.work1_agent.proposal.gate import EvidenceGateResult, GateStatus
from java_vuln_research.work1_agent.proposal.model import EntityRoleRef, ProposalType, SecurityProposal
from java_vuln_research.work1_agent.repository.entity import ProgramEntity

from .model import (
    CODEQL_RELATIONS,
    PROPOSAL_RELATIONS,
    REPOSITORY_RELATIONS,
    EvidenceNode,
    GraphDiagnostic,
    HybridEdge,
    HybridEvidenceGraph,
    NodeKind,
    RelationKind,
    SupportClass,
)


CODEQL_EVIDENCE_KINDS = frozenset(
    {
        EvidenceSourceKind.CODEQL_CALL,
        EvidenceSourceKind.CODEQL_LOCAL_FLOW,
        EvidenceSourceKind.CODEQL_DATAFLOW,
        EvidenceSourceKind.CODEQL_CFG,
    }
)
REPOSITORY_EVIDENCE_KINDS = frozenset(
    {
        EvidenceSourceKind.SOURCE_SNIPPET,
        EvidenceSourceKind.PROGRAM_ENTITY,
        EvidenceSourceKind.REPOSITORY_RELATION,
        EvidenceSourceKind.REPOSITORY_TOOL_RESULT,
        EvidenceSourceKind.TYPE_DECLARATION,
        EvidenceSourceKind.ANNOTATION_TEXT,
    }
)
CODEQL_EVIDENCE_BY_RELATION = {
    RelationKind.CODEQL_CALL: EvidenceSourceKind.CODEQL_CALL,
    RelationKind.CODEQL_LOCAL_FLOW: EvidenceSourceKind.CODEQL_LOCAL_FLOW,
    RelationKind.CODEQL_DATAFLOW: EvidenceSourceKind.CODEQL_DATAFLOW,
    RelationKind.CODEQL_CFG: EvidenceSourceKind.CODEQL_CFG,
}


def _gate_status(value: EvidenceGateResult | Mapping[str, Any]) -> GateStatus:
    return value.status if isinstance(value, EvidenceGateResult) else GateStatus(value["status"])


def _gate_resolved_evidence_ids(value: EvidenceGateResult | Mapping[str, Any]) -> set[str]:
    resolved = value.resolved_evidence if isinstance(value, EvidenceGateResult) else value.get("resolved_evidence", ())
    return {
        str(item.get("evidence_id"))
        for item in resolved
        if isinstance(item, Mapping) and item.get("evidence_id")
    }


class HybridEvidenceGraphBuilder:
    """Build a bounded, evidence-preserving graph without semantic truth claims."""

    def __init__(
        self,
        *,
        project_id: str,
        entities: Sequence[ProgramEntity],
        evidence_catalog: Mapping[str, EvidenceRef],
        proposals: Sequence[SecurityProposal] = (),
        gate_results: Sequence[EvidenceGateResult | Mapping[str, Any]] = (),
        tool_artifact_index: Mapping[str, Mapping[str, Any]] | None = None,
        manifest: Mapping[str, Any] | None = None,
    ) -> None:
        if not project_id:
            raise ValueError("project_id is required")
        self.project_id = project_id
        self.entities = {item.entity_id: item for item in entities}
        self.evidence_catalog = dict(evidence_catalog)
        self.proposals: dict[str, SecurityProposal] = {}
        for item in proposals:
            self.proposals.setdefault(item.proposal_id, item)
        self.gate_results: dict[str, EvidenceGateResult | Mapping[str, Any]] = {}
        for item in gate_results:
            proposal_id = item.proposal_id if isinstance(item, EvidenceGateResult) else str(item["proposal_id"])
            existing = self.gate_results.get(proposal_id)
            if existing is None or (_gate_status(item) == GateStatus.ADMISSIBLE and _gate_status(existing) != GateStatus.ADMISSIBLE):
                self.gate_results[proposal_id] = item
        self.tool_artifact_index = dict(tool_artifact_index or {})
        self.nodes: dict[str, EvidenceNode] = {}
        self.edges: dict[str, HybridEdge] = {}
        self.diagnostics: list[GraphDiagnostic] = []
        self.manifest = {
            "graph_schema_version": 1,
            "project_id": project_id,
            "construction": "BOUNDED_TASK_SCOPED",
            **dict(manifest or {}),
        }

    def _diagnose(self, code: str, message: str, *, subject_id: str | None = None, severity: str = "ERROR") -> None:
        self.diagnostics.append(
            GraphDiagnostic(
                severity=severity,
                code=code,
                message=message,
                subject_id=subject_id,
                provenance={"builder": "WORK1_V11_M5_HYBRID_GRAPH_V1", "project_id": self.project_id},
            )
        )

    def node_for_ref(self, ref: EntityRoleRef, *, provenance: Mapping[str, Any] | None = None) -> EvidenceNode | None:
        entity = self.entities.get(ref.entity_id)
        if entity is None:
            self._diagnose("ENTITY_NOT_FOUND", f"graph node entity does not resolve: {ref.entity_id}", subject_id=ref.entity_id)
            return None
        try:
            node = EvidenceNode.for_entity(
                project_id=self.project_id,
                entity=entity,
                ref=ref,
                entities=self.entities,
                provenance=provenance or {"source": "PROGRAM_ENTITY", "entity_id": entity.entity_id},
            )
        except ValueError as error:
            self._diagnose("INVALID_ROLE_NODE", str(error), subject_id=ref.entity_id)
            return None
        self.nodes.setdefault(node.node_id, node)
        return self.nodes[node.node_id]

    def _anchor_node(self, *, kind: NodeKind, proposal: SecurityProposal) -> EvidenceNode:
        node = EvidenceNode.security_anchor(
            project_id=self.project_id,
            node_kind=kind,
            proposal_id=proposal.proposal_id,
            provenance={"source": "M4_PROPOSAL", "proposal_id": proposal.proposal_id},
        )
        self.nodes.setdefault(node.node_id, node)
        return self.nodes[node.node_id]

    @staticmethod
    def _support_matches(relation: RelationKind, support: SupportClass) -> bool:
        if relation in CODEQL_RELATIONS:
            return support == SupportClass.DETERMINISTIC_FACT
        if relation in REPOSITORY_RELATIONS:
            return support == SupportClass.STRUCTURAL_EVIDENCE
        if relation in PROPOSAL_RELATIONS:
            return support == SupportClass.ADMISSIBLE_SEMANTIC_PROPOSAL
        return False

    def add_edge(
        self,
        *,
        source: EvidenceNode,
        target: EvidenceNode,
        relation_kind: RelationKind | str,
        support_class: SupportClass | str,
        evidence_refs: Sequence[str],
        provenance: Mapping[str, Any],
        proposal_id: str | None = None,
        tool_call_ids: Sequence[str] = (),
        repository_relation_ids: Sequence[str] = (),
        confidence: str | None = None,
    ) -> HybridEdge | None:
        try:
            relation, support = RelationKind(relation_kind), SupportClass(support_class)
        except ValueError as error:
            self._diagnose("UNKNOWN_RELATION_OR_SUPPORT", str(error))
            return None
        if source.node_id not in self.nodes or target.node_id not in self.nodes:
            self._diagnose("EDGE_NODE_NOT_FOUND", "edge endpoint is not active in this graph")
            return None
        if source.project_id != self.project_id or target.project_id != self.project_id:
            self._diagnose("CROSS_REPOSITORY_EDGE", "V1 graph edge cannot cross project identity")
            return None
        if not self._support_matches(relation, support):
            self._diagnose("SUPPORT_CLASS_MISMATCH", f"{relation.value} cannot use {support.value}")
            return None
        if not evidence_refs:
            self._diagnose("ANONYMOUS_EDGE", "every graph edge requires EvidenceRef IDs")
            return None
        if not provenance:
            self._diagnose("EDGE_PROVENANCE_REQUIRED", "every graph edge requires non-empty provenance")
            return None
        missing = [item for item in evidence_refs if item not in self.evidence_catalog]
        if missing:
            self._diagnose("EVIDENCE_REF_NOT_FOUND", ",".join(sorted(missing)))
            return None
        evidence = [self.evidence_catalog[item] for item in evidence_refs]
        endpoint_entity_ids = {item for item in (source.entity_id, target.entity_id) if item is not None}
        unresolved_entities = sorted(
            {
                entity_id
                for item in evidence
                for entity_id in item.entity_ids
                if entity_id not in self.entities
            }
        )
        if unresolved_entities:
            self._diagnose("EVIDENCE_ENTITY_NOT_FOUND", ",".join(unresolved_entities))
            return None
        if relation in CODEQL_RELATIONS:
            expected_kind = CODEQL_EVIDENCE_BY_RELATION[relation]
            if not any(item.source_kind == expected_kind for item in evidence):
                self._diagnose("FABRICATED_CODEQL_EDGE", f"{relation.value} requires {expected_kind.value} EvidenceRef")
                return None
            if not tool_call_ids or any(item not in self.tool_artifact_index for item in tool_call_ids):
                self._diagnose("CODEQL_TOOL_CALL_NOT_FOUND", "CodeQL edge tool_call_id does not resolve")
                return None
            if any(str(self.tool_artifact_index[item].get("status")) != "OK" for item in tool_call_ids):
                self._diagnose("CODEQL_TOOL_CALL_NOT_OK", "deterministic CodeQL edge requires successful tool result")
                return None
            matching_codeql_evidence = [item for item in evidence if item.source_kind == expected_kind]
            if any(
                not any(
                    item.tool_call_id == tool_call_id
                    and endpoint_entity_ids.issubset(set(item.entity_ids))
                    for item in matching_codeql_evidence
                )
                for tool_call_id in tool_call_ids
            ):
                self._diagnose(
                    "CODEQL_TOOL_EVIDENCE_MISMATCH",
                    "each edge tool_call_id must be bound by matching EvidenceRef covering both endpoint entities",
                )
                return None
        if relation in REPOSITORY_RELATIONS:
            matching_repository_evidence = [item for item in evidence if item.source_kind in REPOSITORY_EVIDENCE_KINDS]
            if not matching_repository_evidence:
                self._diagnose("REPOSITORY_EVIDENCE_REQUIRED", "repository relation lacks structural/source evidence")
                return None
            if not any(endpoint_entity_ids.issubset(set(item.entity_ids)) for item in matching_repository_evidence):
                self._diagnose(
                    "REPOSITORY_EVIDENCE_ENDPOINT_MISMATCH",
                    "repository relation requires EvidenceRef covering both endpoint entities",
                )
                return None
        if relation in PROPOSAL_RELATIONS:
            proposal = self.proposals.get(proposal_id or "")
            result = self.gate_results.get(proposal_id or "")
            if proposal is None or result is None or _gate_status(result) != GateStatus.ADMISSIBLE:
                self._diagnose("PROPOSAL_NOT_ADMISSIBLE", "proposal edge requires an ADMISSIBLE M4 result", subject_id=proposal_id)
                return None
            if set(evidence_refs) != set(proposal.evidence_refs):
                self._diagnose("PROPOSAL_EVIDENCE_MISMATCH", "proposal edge must preserve its exact EvidenceRef set", subject_id=proposal_id)
                return None
            if not set(proposal.evidence_refs).issubset(_gate_resolved_evidence_ids(result)):
                self._diagnose(
                    "PROPOSAL_GATE_EVIDENCE_UNRESOLVED",
                    "ADMISSIBLE result does not prove resolution of every proposal EvidenceRef",
                    subject_id=proposal_id,
                )
                return None
        edge = HybridEdge.create(
            project_id=self.project_id,
            source_node_id=source.node_id,
            target_node_id=target.node_id,
            relation_kind=relation,
            support_class=support,
            evidence_refs=evidence_refs,
            proposal_id=proposal_id,
            tool_call_ids=tool_call_ids,
            repository_relation_ids=repository_relation_ids,
            confidence=confidence,
            provenance=provenance,
        )
        self.edges.setdefault(edge.edge_id, edge)
        return self.edges[edge.edge_id]

    def add_codeql_relation(
        self,
        *,
        source_ref: EntityRoleRef,
        target_ref: EntityRoleRef,
        relation_kind: RelationKind | str,
        evidence_refs: Sequence[str],
        tool_call_ids: Sequence[str],
        provenance: Mapping[str, Any],
    ) -> HybridEdge | None:
        source = self.node_for_ref(source_ref)
        target = self.node_for_ref(target_ref)
        if source is None or target is None:
            return None
        return self.add_edge(
            source=source,
            target=target,
            relation_kind=relation_kind,
            support_class=SupportClass.DETERMINISTIC_FACT,
            evidence_refs=evidence_refs,
            tool_call_ids=tool_call_ids,
            provenance=provenance,
        )

    def add_repository_relation(
        self,
        *,
        source_ref: EntityRoleRef,
        target_ref: EntityRoleRef,
        relation_kind: RelationKind | str,
        evidence_refs: Sequence[str],
        repository_relation_ids: Sequence[str],
        provenance: Mapping[str, Any],
    ) -> HybridEdge | None:
        source = self.node_for_ref(source_ref)
        target = self.node_for_ref(target_ref)
        if source is None or target is None:
            return None
        return self.add_edge(
            source=source,
            target=target,
            relation_kind=relation_kind,
            support_class=SupportClass.STRUCTURAL_EVIDENCE,
            evidence_refs=evidence_refs,
            repository_relation_ids=repository_relation_ids,
            provenance=provenance,
        )

    def _proposal_pairs(self, proposal: SecurityProposal) -> list[tuple[EvidenceNode, EvidenceNode]]:
        subject = self.node_for_ref(proposal.subject, provenance={"source": "M4_PROPOSAL_SUBJECT", "proposal_id": proposal.proposal_id})
        if subject is None:
            return []
        if proposal.proposal_type == ProposalType.EXTERNAL_INPUT:
            return [(self._anchor_node(kind=NodeKind.SECURITY_INPUT_ROOT, proposal=proposal), subject)]
        if proposal.proposal_type == ProposalType.SECURITY_EFFECT:
            return [(subject, self._anchor_node(kind=NodeKind.SECURITY_EFFECT_ROOT, proposal=proposal))]
        source = self.node_for_ref(proposal.source, provenance={"source": "M4_PROPOSAL_SOURCE", "proposal_id": proposal.proposal_id}) if proposal.source else subject
        target = self.node_for_ref(proposal.target, provenance={"source": "M4_PROPOSAL_TARGET", "proposal_id": proposal.proposal_id}) if proposal.target else subject
        if source is None or target is None:
            return []
        if proposal.proposal_type == ProposalType.FIELD_STATE:
            return [(source, subject), (subject, target)]
        return [(source, target)]

    def add_proposal_edges(self) -> None:
        for proposal in sorted(self.proposals.values(), key=lambda item: item.proposal_id):
            result = self.gate_results.get(proposal.proposal_id)
            if result is None:
                self._diagnose("PROPOSAL_GATE_RESULT_MISSING", "proposal has no gate result", subject_id=proposal.proposal_id)
                continue
            status = _gate_status(result)
            if status == GateStatus.ALREADY_SUPPORTED:
                pairs = self._proposal_pairs(proposal)
                for source, target in pairs:
                    for edge_id, edge in list(self.edges.items()):
                        if edge.source_node_id == source.node_id and edge.target_node_id == target.node_id:
                            attached = sorted(set(edge.provenance.get("already_supported_proposal_ids", ())) | {proposal.proposal_id})
                            self.edges[edge_id] = replace(edge, provenance={**dict(edge.provenance), "already_supported_proposal_ids": attached})
                self._diagnose("ALREADY_SUPPORTED_NOT_DUPLICATED", "proposal provenance attached where a native edge matched", subject_id=proposal.proposal_id, severity="INFO")
                continue
            if status != GateStatus.ADMISSIBLE:
                self._diagnose("INACTIVE_PROPOSAL_SKIPPED", f"gate status {status.value} cannot enter active graph", subject_id=proposal.proposal_id, severity="INFO")
                continue
            relation = RelationKind(proposal.proposal_type.value)
            for ordinal, (source, target) in enumerate(self._proposal_pairs(proposal)):
                self.add_edge(
                    source=source,
                    target=target,
                    relation_kind=relation,
                    support_class=SupportClass.ADMISSIBLE_SEMANTIC_PROPOSAL,
                    evidence_refs=proposal.evidence_refs,
                    proposal_id=proposal.proposal_id,
                    provenance={
                        "source": "M4_EVIDENCE_GATE",
                        "proposal_id": proposal.proposal_id,
                        "gate_status": GateStatus.ADMISSIBLE.value,
                        "segment_ordinal": ordinal,
                        "warning": "ADMISSIBLE is grounded, not a confirmed semantic fact or vulnerability",
                    },
                )

    def _suppress_dominated_structural_edges(self) -> None:
        deterministic_calls = {
            (item.source_node_id, item.target_node_id)
            for item in self.edges.values()
            if item.relation_kind == RelationKind.CODEQL_CALL and item.support_class == SupportClass.DETERMINISTIC_FACT
        }
        for edge_id, edge in list(self.edges.items()):
            if edge.relation_kind == RelationKind.LEXICAL_CALL and (edge.source_node_id, edge.target_node_id) in deterministic_calls:
                self.edges.pop(edge_id)
                self._diagnose("DOMINATED_STRUCTURAL_EDGE_SUPPRESSED", "LEXICAL_CALL suppressed because identical CODEQL_CALL exists", subject_id=edge_id, severity="INFO")

    def build(self) -> HybridEvidenceGraph:
        self._suppress_dominated_structural_edges()
        nodes = tuple(sorted(self.nodes.values(), key=lambda item: item.node_id))
        edges = tuple(sorted(self.edges.values(), key=lambda item: item.edge_id))
        return HybridEvidenceGraph(
            project_id=self.project_id,
            nodes=nodes,
            edges=edges,
            diagnostics=tuple(self.diagnostics),
            manifest={**self.manifest, "node_count": len(nodes), "edge_count": len(edges)},
        )

    def build_subgraph(
        self,
        *,
        seed_node_ids: Sequence[str],
        max_nodes: int,
        max_edges: int,
        max_depth: int,
    ) -> HybridEvidenceGraph:
        graph = self.build()
        if not (1 <= max_nodes <= 10000 and 1 <= max_edges <= 20000 and 0 <= max_depth <= 20):
            raise ValueError("subgraph bounds exceed hard ceilings")
        node_index = graph.node_index()
        adjacency: dict[str, list[HybridEdge]] = {}
        for edge in graph.edges:
            adjacency.setdefault(edge.source_node_id, []).append(edge)
        for values in adjacency.values():
            values.sort(key=lambda item: item.edge_id)
        selected_nodes: dict[str, EvidenceNode] = {}
        selected_edges: dict[str, HybridEdge] = {}
        queue = deque((item, 0) for item in sorted(set(seed_node_ids)) if item in node_index)
        truncated = False
        while queue:
            node_id, depth = queue.popleft()
            if node_id not in selected_nodes:
                if len(selected_nodes) >= max_nodes:
                    truncated = True
                    break
                selected_nodes[node_id] = node_index[node_id]
            if depth >= max_depth:
                continue
            for edge in adjacency.get(node_id, ()):
                if len(selected_edges) >= max_edges:
                    truncated = True
                    break
                if edge.target_node_id not in selected_nodes and len(selected_nodes) >= max_nodes:
                    truncated = True
                    break
                selected_edges.setdefault(edge.edge_id, edge)
                queue.append((edge.target_node_id, depth + 1))
            if truncated:
                break
        diagnostics = list(graph.diagnostics)
        if truncated:
            diagnostics.append(GraphDiagnostic("WARNING", "SUBGRAPH_TRUNCATED", "max_nodes or max_edges bound reached"))
        return HybridEvidenceGraph(
            project_id=self.project_id,
            nodes=tuple(sorted(selected_nodes.values(), key=lambda item: item.node_id)),
            edges=tuple(sorted(selected_edges.values(), key=lambda item: item.edge_id)),
            diagnostics=tuple(diagnostics),
            manifest={**graph.manifest, "subgraph": True, "max_nodes": max_nodes, "max_edges": max_edges, "max_depth": max_depth, "truncated": truncated},
        )
