from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.proposal.model import EntityRole, EntityRoleRef, canonical_json, stable_digest
from java_vuln_research.work1_agent.proposal.roles import validate_role
from java_vuln_research.work1_agent.repository.entity import ProgramEntity


GRAPH_SCHEMA_VERSION = 1
HYBRID_PATH_SCHEMA_VERSION = 1


class NodeKind(str, Enum):
    PROGRAM_VALUE = "PROGRAM_VALUE"
    SECURITY_INPUT_ROOT = "SECURITY_INPUT_ROOT"
    SECURITY_EFFECT_ROOT = "SECURITY_EFFECT_ROOT"


class SupportClass(str, Enum):
    DETERMINISTIC_FACT = "DETERMINISTIC_FACT"
    STRUCTURAL_EVIDENCE = "STRUCTURAL_EVIDENCE"
    ADMISSIBLE_SEMANTIC_PROPOSAL = "ADMISSIBLE_SEMANTIC_PROPOSAL"


class RelationKind(str, Enum):
    CODEQL_CALL = "CODEQL_CALL"
    CODEQL_LOCAL_FLOW = "CODEQL_LOCAL_FLOW"
    CODEQL_DATAFLOW = "CODEQL_DATAFLOW"
    CODEQL_CFG = "CODEQL_CFG"
    LEXICAL_CALL = "LEXICAL_CALL"
    DECLARES = "DECLARES"
    EXTENDS_TEXT = "EXTENDS_TEXT"
    IMPLEMENTS_TEXT = "IMPLEMENTS_TEXT"
    OVERRIDE_CANDIDATE = "OVERRIDE_CANDIDATE"
    EXTERNAL_INPUT = "EXTERNAL_INPUT"
    SECURITY_EFFECT = "SECURITY_EFFECT"
    WRAPPER_FLOW = "WRAPPER_FLOW"
    LIBRARY_FLOW = "LIBRARY_FLOW"
    FIELD_STATE = "FIELD_STATE"
    FRAMEWORK_RELATION = "FRAMEWORK_RELATION"
    CALLBACK_RELATION = "CALLBACK_RELATION"


CODEQL_RELATIONS = frozenset(
    {
        RelationKind.CODEQL_CALL,
        RelationKind.CODEQL_LOCAL_FLOW,
        RelationKind.CODEQL_DATAFLOW,
        RelationKind.CODEQL_CFG,
    }
)
REPOSITORY_RELATIONS = frozenset(
    {
        RelationKind.LEXICAL_CALL,
        RelationKind.DECLARES,
        RelationKind.EXTENDS_TEXT,
        RelationKind.IMPLEMENTS_TEXT,
        RelationKind.OVERRIDE_CANDIDATE,
    }
)
PROPOSAL_RELATIONS = frozenset(
    {
        RelationKind.EXTERNAL_INPUT,
        RelationKind.SECURITY_EFFECT,
        RelationKind.WRAPPER_FLOW,
        RelationKind.LIBRARY_FLOW,
        RelationKind.FIELD_STATE,
        RelationKind.FRAMEWORK_RELATION,
        RelationKind.CALLBACK_RELATION,
    }
)


@dataclass(frozen=True, slots=True)
class EvidenceNode:
    node_id: str
    project_id: str
    node_kind: NodeKind
    role: EntityRole
    provenance: Mapping[str, Any]
    entity_id: str | None = None
    role_index: int | None = None
    repository_relative_path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    program_kind: str | None = None
    anchor_proposal_id: str | None = None

    @classmethod
    def for_entity(
        cls,
        *,
        project_id: str,
        entity: ProgramEntity,
        ref: EntityRoleRef,
        entities: Mapping[str, ProgramEntity],
        provenance: Mapping[str, Any],
    ) -> "EvidenceNode":
        valid, reason = validate_role(ref, entities)
        if not valid:
            raise ValueError(reason or "INVALID_ROLE")
        material = {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "project_id": project_id,
            "node_kind": NodeKind.PROGRAM_VALUE.value,
            "entity_id": entity.entity_id,
            "role": ref.role.value,
            "role_index": ref.index,
        }
        return cls(
            node_id=stable_digest("hnode", material),
            project_id=project_id,
            node_kind=NodeKind.PROGRAM_VALUE,
            entity_id=entity.entity_id,
            role=ref.role,
            role_index=ref.index,
            repository_relative_path=entity.repository_relative_path,
            start_line=entity.start_line,
            end_line=entity.end_line,
            program_kind=entity.kind.value,
            anchor_proposal_id=None,
            provenance=dict(provenance),
        )

    @classmethod
    def security_anchor(
        cls,
        *,
        project_id: str,
        node_kind: NodeKind,
        proposal_id: str,
        provenance: Mapping[str, Any],
    ) -> "EvidenceNode":
        if node_kind not in {NodeKind.SECURITY_INPUT_ROOT, NodeKind.SECURITY_EFFECT_ROOT}:
            raise ValueError("security anchor must be an input or effect root")
        material = {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "project_id": project_id,
            "node_kind": node_kind.value,
            "proposal_id": proposal_id,
        }
        return cls(
            node_id=stable_digest("hnode", material),
            project_id=project_id,
            node_kind=node_kind,
            role=EntityRole.ENTITY,
            anchor_proposal_id=proposal_id,
            provenance=dict(provenance),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "project_id": self.project_id,
            "node_kind": self.node_kind.value,
            "entity_id": self.entity_id,
            "role": self.role.value,
            "role_index": self.role_index,
            "repository_relative_path": self.repository_relative_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "program_kind": self.program_kind,
            "anchor_proposal_id": self.anchor_proposal_id,
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True, slots=True)
class HybridEdge:
    edge_id: str
    project_id: str
    source_node_id: str
    target_node_id: str
    relation_kind: RelationKind
    support_class: SupportClass
    evidence_refs: tuple[str, ...]
    provenance: Mapping[str, Any]
    proposal_id: str | None = None
    tool_call_ids: tuple[str, ...] = ()
    repository_relation_ids: tuple[str, ...] = ()
    confidence: str | None = None

    @classmethod
    def create(
        cls,
        *,
        project_id: str,
        source_node_id: str,
        target_node_id: str,
        relation_kind: RelationKind | str,
        support_class: SupportClass | str,
        evidence_refs: Sequence[str],
        provenance: Mapping[str, Any],
        proposal_id: str | None = None,
        tool_call_ids: Sequence[str] = (),
        repository_relation_ids: Sequence[str] = (),
        confidence: str | None = None,
    ) -> "HybridEdge":
        relation = RelationKind(relation_kind)
        support = SupportClass(support_class)
        evidence = tuple(sorted(set(str(item) for item in evidence_refs)))
        tools = tuple(sorted(set(str(item) for item in tool_call_ids)))
        repository_ids = tuple(sorted(set(str(item) for item in repository_relation_ids)))
        material = {
            "schema_version": GRAPH_SCHEMA_VERSION,
            "project_id": project_id,
            "source_node_id": source_node_id,
            "target_node_id": target_node_id,
            "relation_kind": relation.value,
            "support_class": support.value,
            "evidence_refs": evidence,
            "proposal_id": proposal_id,
            "tool_call_ids": tools,
            "repository_relation_ids": repository_ids,
        }
        return cls(
            edge_id=stable_digest("hedge", material),
            project_id=project_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            relation_kind=relation,
            support_class=support,
            evidence_refs=evidence,
            proposal_id=proposal_id,
            tool_call_ids=tools,
            repository_relation_ids=repository_ids,
            confidence=confidence,
            provenance=dict(provenance),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "project_id": self.project_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "relation_kind": self.relation_kind.value,
            "support_class": self.support_class.value,
            "evidence_refs": list(self.evidence_refs),
            "proposal_id": self.proposal_id,
            "tool_call_ids": list(self.tool_call_ids),
            "repository_relation_ids": list(self.repository_relation_ids),
            "confidence": self.confidence,
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True, slots=True)
class GraphDiagnostic:
    severity: str
    code: str
    message: str
    subject_id: str | None = None
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
            "subject_id": self.subject_id,
            "provenance": dict(self.provenance),
        }


@dataclass(frozen=True, slots=True)
class HybridEvidenceGraph:
    project_id: str
    nodes: tuple[EvidenceNode, ...]
    edges: tuple[HybridEdge, ...]
    diagnostics: tuple[GraphDiagnostic, ...]
    manifest: Mapping[str, Any]

    def node_index(self) -> dict[str, EvidenceNode]:
        return {item.node_id: item for item in self.nodes}

    def to_manifest_dict(self) -> dict[str, Any]:
        return dict(self.manifest)


@dataclass(frozen=True, slots=True)
class HybridCandidatePath:
    candidate_path_id: str
    project_id: str
    path_origin: str
    input_anchor: Mapping[str, Any]
    effect_anchor: Mapping[str, Any]
    ordered_nodes: tuple[Mapping[str, Any], ...]
    ordered_edges: tuple[Mapping[str, Any], ...]
    support_summary: Mapping[str, Any]
    proposal_ids: tuple[str, ...]
    unresolved_semantics: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    provenance: Mapping[str, Any]
    path_fingerprint: str
    schema_version: int = HYBRID_PATH_SCHEMA_VERSION

    @classmethod
    def create(
        cls,
        *,
        project_id: str,
        nodes: Sequence[EvidenceNode],
        edges: Sequence[HybridEdge],
        provenance: Mapping[str, Any],
    ) -> "HybridCandidatePath":
        if len(nodes) != len(edges) + 1:
            raise ValueError("candidate path nodes and edges are not contiguous")
        if not nodes or nodes[0].node_kind != NodeKind.SECURITY_INPUT_ROOT or nodes[-1].node_kind != NodeKind.SECURITY_EFFECT_ROOT:
            raise ValueError("candidate path must run from input anchor to effect anchor")
        for index, edge in enumerate(edges):
            if edge.source_node_id != nodes[index].node_id or edge.target_node_id != nodes[index + 1].node_id:
                raise ValueError("candidate path edge order is not contiguous")
        proposal_ids = tuple(sorted({item.proposal_id for item in edges if item.proposal_id}))
        unresolved = tuple(
            sorted(
                f"{item.relation_kind.value}:{item.proposal_id}"
                for item in edges
                if item.support_class == SupportClass.ADMISSIBLE_SEMANTIC_PROPOSAL and item.proposal_id
            )
        )
        evidence_refs = tuple(sorted({ref for item in edges for ref in item.evidence_refs}))
        deterministic = sum(item.support_class == SupportClass.DETERMINISTIC_FACT for item in edges)
        structural = sum(item.support_class == SupportClass.STRUCTURAL_EVIDENCE for item in edges)
        proposal = sum(item.support_class == SupportClass.ADMISSIBLE_SEMANTIC_PROPOSAL for item in edges)
        codeql = sum(item.relation_kind in CODEQL_RELATIONS for item in edges)
        fingerprint_material = {
            "node_ids": [item.node_id for item in nodes],
            "relations": [item.relation_kind.value for item in edges],
            "proposal_ids": [item.proposal_id for item in edges],
        }
        fingerprint = stable_digest("pathfp", fingerprint_material)
        identity = {"schema_version": HYBRID_PATH_SCHEMA_VERSION, "project_id": project_id, "fingerprint": fingerprint}
        return cls(
            candidate_path_id=stable_digest("hpath", identity),
            project_id=project_id,
            path_origin="HYBRID",
            input_anchor=nodes[0].to_dict(),
            effect_anchor=nodes[-1].to_dict(),
            ordered_nodes=tuple(item.to_dict() for item in nodes),
            ordered_edges=tuple(item.to_dict() for item in edges),
            support_summary={
                "deterministic_edge_count": deterministic,
                "structural_edge_count": structural,
                "proposal_edge_count": proposal,
                "codeql_edge_count": codeql,
                "repository_only_hybrid": codeql == 0,
                "path_length": len(edges),
                "proposal_edges_per_path": proposal,
            },
            proposal_ids=proposal_ids,
            unresolved_semantics=unresolved,
            evidence_refs=evidence_refs,
            provenance=dict(provenance),
            path_fingerprint=fingerprint,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_path_id": self.candidate_path_id,
            "project_id": self.project_id,
            "path_origin": self.path_origin,
            "input_anchor": dict(self.input_anchor),
            "effect_anchor": dict(self.effect_anchor),
            "ordered_nodes": [dict(item) for item in self.ordered_nodes],
            "ordered_edges": [dict(item) for item in self.ordered_edges],
            "support_summary": dict(self.support_summary),
            "proposal_ids": list(self.proposal_ids),
            "unresolved_semantics": list(self.unresolved_semantics),
            "evidence_refs": list(self.evidence_refs),
            "provenance": dict(self.provenance),
            "path_fingerprint": self.path_fingerprint,
            "schema_version": self.schema_version,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())
