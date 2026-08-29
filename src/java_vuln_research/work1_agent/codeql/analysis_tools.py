from __future__ import annotations

import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..repository.entity import ProgramEntity
from .entity_mapper import EntityMappingResult, MappingStatus, map_program_entity
from .executor import CodeQLExecutor, QuerySpec
from .result import CodeQLToolResult, EvidenceKind, ToolStatus


ENTITY_COLUMNS = (
    "codeql_identity",
    "kind",
    "repository_relative_path",
    "start_line",
    "end_line",
    "qualified_name",
    "signature",
    "declaring_type",
    "enclosing_callable",
)
EDGE_COLUMNS = (
    "source_identity",
    "target_identity",
    "edge_kind",
    "repository_relative_path",
    "start_line",
    "end_line",
    "callable_identity",
)


class CodeQLAnalysisTools:
    """Allow-listed M3 tool facade. It never accepts model-authored QL."""

    def __init__(self, executor: CodeQLExecutor, query_root: str | Path) -> None:
        self.executor = executor
        root = Path(query_root)
        self.queries = {
            "entity_facts": QuerySpec("EntityFacts", root / "EntityFacts.ql", ENTITY_COLUMNS, 100),
            "call_graph": QuerySpec("CallGraph", root / "CallGraph.ql", EDGE_COLUMNS, 100),
            "local_flow": QuerySpec("LocalFlow", root / "LocalFlow.ql", EDGE_COLUMNS, 100),
            "dataflow_neighbors": QuerySpec("DataFlowNeighbors", root / "DataFlowNeighbors.ql", EDGE_COLUMNS, 100),
            "cfg_neighbors": QuerySpec("CfgNeighbors", root / "CfgNeighbors.ql", EDGE_COLUMNS, 100),
        }

    @staticmethod
    def _unmapped(tool_name: str, entity: ProgramEntity, mapping: EntityMappingResult) -> CodeQLToolResult:
        status = ToolStatus.UNSUPPORTED if mapping.status == MappingStatus.UNSUPPORTED_KIND else ToolStatus.ENTITY_NOT_MAPPED
        return CodeQLToolResult(
            tool_call_id="codeql-call-" + uuid.uuid4().hex,
            tool_name=tool_name,
            status=status,
            queried_entity_ids=[entity.entity_id],
            warnings=[mapping.status.value],
            provenance={"mapping": mapping.to_dict()},
        )

    def map_entity(
        self,
        *,
        database: str | Path,
        entity: ProgramEntity,
    ) -> tuple[EntityMappingResult, CodeQLToolResult]:
        executed = self.executor.execute(
            database=database,
            query=self.queries["entity_facts"],
            tool_name="map_program_entity",
            queried_entity_ids=[entity.entity_id],
            template_values={
                "PATH": entity.repository_relative_path,
                "START_LINE": entity.start_line,
                "END_LINE": entity.end_line,
            },
        )
        mapping = map_program_entity(
            entity,
            executed.nodes,
            database_id=Path(database).name,
            query_hash=str(executed.provenance.get("query_hash") or ""),
        )
        executed.mapped_codeql_entities = [item.to_dict() for item in mapping.candidates]
        executed.provenance["mapping"] = mapping.to_dict()
        if executed.status not in {ToolStatus.ERROR, ToolStatus.EMPTY}:
            if mapping.status == MappingStatus.MAPPED_UNIQUE:
                executed.status = ToolStatus.OK
            elif mapping.status == MappingStatus.UNSUPPORTED_KIND:
                executed.status = ToolStatus.UNSUPPORTED
            else:
                executed.status = ToolStatus.ENTITY_NOT_MAPPED
        return mapping, executed

    def codeql_entity_facts(self, *, database: str | Path, entity: ProgramEntity) -> CodeQLToolResult:
        _, result = self.map_entity(database=database, entity=entity)
        result.tool_name = "codeql_entity_facts"
        for node in result.nodes:
            node["evidence_kind"] = EvidenceKind.CODEQL_ENTITY_FACT.value
        return result

    def _edge_tool(
        self,
        *,
        database: str | Path,
        entity: ProgramEntity,
        query_key: str,
        tool_name: str,
        evidence_kind: EvidenceKind,
        max_nodes: int,
        max_edges: int,
        max_depth: int,
        allowed_edge_kinds: set[str] | None = None,
    ) -> CodeQLToolResult:
        for name, value, ceiling in (
            ("max_nodes", max_nodes, 200),
            ("max_edges", max_edges, 500),
            ("max_depth", max_depth, 5),
        ):
            if int(value) < 1 or int(value) > ceiling:
                raise ValueError(f"{name} must be between 1 and {ceiling}")
        mapping, mapped_result = self.map_entity(database=database, entity=entity)
        if mapped_result.status == ToolStatus.ERROR:
            mapped_result.tool_name = tool_name
            return mapped_result
        if mapping.status != MappingStatus.MAPPED_UNIQUE:
            return self._unmapped(tool_name, entity, mapping)
        spec = replace(self.queries[query_key], max_rows=max_edges + 1)
        result = self.executor.execute(
            database=database,
            query=spec,
            tool_name=tool_name,
            queried_entity_ids=[entity.entity_id],
            template_values={
                "PATH": entity.repository_relative_path,
                "START_LINE": entity.start_line,
                "END_LINE": entity.end_line,
            },
        )
        result.mapped_codeql_entities = [mapping.candidates[0].to_dict()]
        result.provenance.update(
            mapping=mapping.to_dict(),
            limits={"max_nodes": max_nodes, "max_edges": max_edges, "max_depth": max_depth},
        )
        raw_rows = list(result.nodes)
        filtered = [
            row
            for row in raw_rows
            if allowed_edge_kinds is None
            or str(row.get("edge_kind") or "").upper() in allowed_edge_kinds
        ]
        edge_limited = filtered[:max_edges]

        node_ids: list[str] = []
        seen_nodes: set[str] = set()
        for row in edge_limited:
            for key in ("source_identity", "target_identity"):
                identity = str(row.get(key) or "")
                if identity and identity not in seen_nodes:
                    seen_nodes.add(identity)
                    node_ids.append(identity)
        selected_node_ids = set(node_ids[:max_nodes])
        selected = [
            row
            for row in edge_limited
            if str(row.get("source_identity") or "") in selected_node_ids
            and str(row.get("target_identity") or "") in selected_node_ids
        ]
        result.edges = [{**row, "evidence_kind": evidence_kind.value} for row in selected]
        result.nodes = [
            {"codeql_identity": identity, "evidence_kind": evidence_kind.value}
            for identity in node_ids[:max_nodes]
        ]
        result.truncated = (
            result.truncated
            or len(filtered) > max_edges
            or len(node_ids) > max_nodes
            or len(selected) < len(edge_limited)
        )
        if result.status == ToolStatus.OK and not result.edges:
            result.status = ToolStatus.EMPTY
        result.metrics.update(returned_nodes=len(result.nodes), returned_edges=len(result.edges))
        return result

    def codeql_callers(self, *, database: str | Path, entity: ProgramEntity, max_edges: int = 30) -> CodeQLToolResult:
        return self._edge_tool(database=database, entity=entity, query_key="call_graph", tool_name="codeql_callers", evidence_kind=EvidenceKind.CODEQL_CALL, max_nodes=30, max_edges=max_edges, max_depth=1, allowed_edge_kinds={"CALLER"})

    def codeql_callees(self, *, database: str | Path, entity: ProgramEntity, max_edges: int = 30) -> CodeQLToolResult:
        return self._edge_tool(database=database, entity=entity, query_key="call_graph", tool_name="codeql_callees", evidence_kind=EvidenceKind.CODEQL_CALL, max_nodes=30, max_edges=max_edges, max_depth=1, allowed_edge_kinds={"CALLEE"})

    def codeql_local_flow(self, *, database: str | Path, entity: ProgramEntity, max_edges: int = 30) -> CodeQLToolResult:
        return self._edge_tool(database=database, entity=entity, query_key="local_flow", tool_name="codeql_local_flow", evidence_kind=EvidenceKind.CODEQL_LOCAL_FLOW, max_nodes=30, max_edges=max_edges, max_depth=1)

    def codeql_dataflow_neighbors(
        self,
        *,
        database: str | Path,
        entity: ProgramEntity,
        direction: str = "BOTH",
        max_nodes: int = 30,
        max_edges: int = 50,
        max_depth: int = 1,
    ) -> CodeQLToolResult:
        resolved = str(direction).upper()
        if resolved not in {"FORWARD", "BACKWARD", "BOTH"}:
            raise ValueError("direction must be FORWARD, BACKWARD, or BOTH")
        allowed = None if resolved == "BOTH" else {resolved}
        result = self._edge_tool(database=database, entity=entity, query_key="dataflow_neighbors", tool_name="codeql_dataflow_neighbors", evidence_kind=EvidenceKind.CODEQL_DATAFLOW, max_nodes=max_nodes, max_edges=max_edges, max_depth=max_depth, allowed_edge_kinds=allowed)
        result.provenance["direction"] = resolved
        return result

    def codeql_cfg_neighbors(
        self,
        *,
        database: str | Path,
        entity: ProgramEntity,
        direction: str = "BOTH",
        max_nodes: int = 30,
        max_edges: int = 50,
        max_depth: int = 1,
    ) -> CodeQLToolResult:
        resolved = str(direction).upper()
        if resolved not in {"FORWARD", "BACKWARD", "BOTH"}:
            raise ValueError("direction must be FORWARD, BACKWARD, or BOTH")
        allowed = None if resolved == "BOTH" else {"SUCCESSOR" if resolved == "FORWARD" else "PREDECESSOR"}
        result = self._edge_tool(database=database, entity=entity, query_key="cfg_neighbors", tool_name="codeql_cfg_neighbors", evidence_kind=EvidenceKind.CODEQL_CFG, max_nodes=max_nodes, max_edges=max_edges, max_depth=max_depth, allowed_edge_kinds=allowed)
        result.provenance["direction"] = resolved
        return result
