from __future__ import annotations

import copy
import uuid
from dataclasses import replace
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

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
    "parameter_positions",
    "return_information",
    "type_information",
    "annotation_facts",
    "override_interface_facts",
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
        self._mapping_cache: dict[tuple[str, str], tuple[EntityMappingResult, CodeQLToolResult]] = {}
        root = Path(query_root)
        self.queries = {
            "entity_facts": QuerySpec("EntityFacts", root / "EntityFacts.ql", ENTITY_COLUMNS, 100),
            "call_graph": QuerySpec("CallGraph", root / "CallGraph.ql", EDGE_COLUMNS, 100),
            "local_flow": QuerySpec("LocalFlow", root / "LocalFlow.ql", EDGE_COLUMNS, 100),
            "dataflow_neighbors": QuerySpec("DataFlowNeighbors", root / "DataFlowNeighbors.ql", EDGE_COLUMNS, 100),
            "cfg_neighbors": QuerySpec("CfgNeighbors", root / "CfgNeighbors.ql", EDGE_COLUMNS, 100),
        }

    @staticmethod
    def _entity_target_values(entities: Iterable[ProgramEntity]) -> dict[str, str | int]:
        selected = list(entities)
        if len(selected) > 11:
            raise ValueError("EntityFacts supports at most eleven bounded targets")
        values: dict[str, str | int] = {}
        for index in range(11):
            if index < len(selected):
                entity = selected[index]
                values.update(
                    {
                        f"PATH_{index}": entity.repository_relative_path,
                        f"START_LINE_{index}": entity.start_line,
                        f"END_LINE_{index}": entity.end_line,
                        f"KIND_{index}": entity.kind.value,
                    }
                )
            else:
                values.update(
                    {
                        f"PATH_{index}": "__WORK1_V11_UNUSED_TARGET__",
                        f"START_LINE_{index}": 1,
                        f"END_LINE_{index}": 1,
                        f"KIND_{index}": "TYPE",
                    }
                )
        return values

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
        cache_key = (str(Path(database).resolve()), entity.entity_id)
        cached = self._mapping_cache.get(cache_key)
        if cached is not None:
            mapping, result = cached
            cloned = copy.deepcopy(result)
            cloned.provenance["mapping_cache_hit"] = True
            return copy.deepcopy(mapping), cloned
        executed = self.executor.execute(
            database=database,
            query=self.queries["entity_facts"],
            tool_name="map_program_entity",
            queried_entity_ids=[entity.entity_id],
            template_values=self._entity_target_values([entity]),
        )
        mapping = map_program_entity(
            entity,
            executed.nodes,
            database_id=Path(database).name,
            query_hash=str(executed.provenance.get("query_hash") or ""),
        )
        executed.mapped_codeql_entities = [item.to_dict() for item in mapping.candidates]
        executed.provenance["mapping"] = mapping.to_dict()
        if executed.status != ToolStatus.ERROR:
            if mapping.status == MappingStatus.MAPPED_UNIQUE:
                executed.status = ToolStatus.OK
            elif mapping.status == MappingStatus.UNSUPPORTED_KIND:
                executed.status = ToolStatus.UNSUPPORTED
            else:
                executed.status = ToolStatus.ENTITY_NOT_MAPPED
        self._mapping_cache[cache_key] = (copy.deepcopy(mapping), copy.deepcopy(executed))
        return mapping, executed

    def prefetch_entity_facts(
        self,
        *,
        database: str | Path,
        entities: Iterable[ProgramEntity],
    ) -> CodeQLToolResult:
        """Populate the strict mapping cache with one bounded multi-entity query."""

        selected = list(entities)
        executed = self.executor.execute(
            database=database,
            query=replace(self.queries["entity_facts"], max_rows=max(100, len(selected) * 100)),
            tool_name="prefetch_entity_facts",
            queried_entity_ids=[entity.entity_id for entity in selected],
            template_values=self._entity_target_values(selected),
        )
        database_key = str(Path(database).resolve())
        for index, entity in enumerate(selected):
            mapping = map_program_entity(
                entity,
                executed.nodes,
                database_id=Path(database).name,
                query_hash=str(executed.provenance.get("query_hash") or ""),
            )
            per_entity = copy.deepcopy(executed)
            per_entity.tool_call_id = "codeql-call-" + uuid.uuid4().hex
            per_entity.tool_name = "codeql_entity_facts"
            per_entity.queried_entity_ids = [entity.entity_id]
            per_entity.nodes = [candidate.to_dict() for candidate in mapping.candidates]
            per_entity.mapped_codeql_entities = [candidate.to_dict() for candidate in mapping.candidates]
            per_entity.provenance.update(
                {
                    "mapping": mapping.to_dict(),
                    "batch_parent_tool_call_id": executed.tool_call_id,
                    "batch_size": len(selected),
                    "batch_entity_index": index,
                }
            )
            elapsed = float(executed.metrics.get("wall_clock_seconds") or 0.0)
            per_entity.metrics["batch_wall_clock_seconds"] = elapsed
            per_entity.metrics["wall_clock_seconds"] = round(elapsed / max(1, len(selected)), 6)
            if executed.status != ToolStatus.ERROR:
                if mapping.status == MappingStatus.MAPPED_UNIQUE:
                    per_entity.status = ToolStatus.OK
                elif mapping.status == MappingStatus.UNSUPPORTED_KIND:
                    per_entity.status = ToolStatus.UNSUPPORTED
                else:
                    per_entity.status = ToolStatus.ENTITY_NOT_MAPPED
            self._mapping_cache[(database_key, entity.entity_id)] = (
                copy.deepcopy(mapping),
                copy.deepcopy(per_entity),
            )
        return executed

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
        row_filter: Callable[[Mapping[str, Any]], bool] | None = None,
    ) -> CodeQLToolResult:
        for name, value, ceiling in (
            ("max_nodes", max_nodes, 200),
            ("max_edges", max_edges, 500),
            ("max_depth", max_depth, 1),
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
                "CODEQL_IDENTITY": mapping.candidates[0].codeql_identity,
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
            if row_filter is None or row_filter(row)
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

    def codeql_local_flow(
        self,
        *,
        database: str | Path,
        entity: ProgramEntity,
        target_entity: ProgramEntity | None = None,
        scope_entity: ProgramEntity | None = None,
        max_edges: int = 30,
    ) -> CodeQLToolResult:
        target_mapping = None
        scope_mapping = None
        if target_entity is not None:
            target_mapping, target_result = self.map_entity(database=database, entity=target_entity)
            if target_result.status == ToolStatus.ERROR:
                target_result.tool_name = "codeql_local_flow"
                return target_result
            if target_mapping.status != MappingStatus.MAPPED_UNIQUE:
                return self._unmapped("codeql_local_flow", target_entity, target_mapping)
        if scope_entity is not None:
            scope_mapping, scope_result = self.map_entity(database=database, entity=scope_entity)
            if scope_result.status == ToolStatus.ERROR:
                scope_result.tool_name = "codeql_local_flow"
                return scope_result
            if scope_mapping.status != MappingStatus.MAPPED_UNIQUE:
                return self._unmapped("codeql_local_flow", scope_entity, scope_mapping)

        expected_scope = None
        if scope_mapping is not None:
            scope_candidate = scope_mapping.candidates[0]
            if (
                scope_candidate.kind not in {"METHOD", "CONSTRUCTOR"}
                or not scope_candidate.declaring_type
                or not scope_candidate.signature
            ):
                raise ValueError("scope_entity must map to a callable")
            expected_scope = f"{scope_candidate.declaring_type}.{scope_candidate.signature}"

        def local_filter(row: Mapping[str, Any]) -> bool:
            if target_entity is not None:
                if str(row.get("repository_relative_path") or "") != target_entity.repository_relative_path:
                    return False
                start_line = int(row.get("start_line") or 0)
                end_line = int(row.get("end_line") or start_line)
                if start_line > target_entity.end_line or target_entity.start_line > end_line:
                    return False
            return expected_scope is None or str(row.get("callable_identity") or "") == expected_scope

        result = self._edge_tool(
            database=database,
            entity=entity,
            query_key="local_flow",
            tool_name="codeql_local_flow",
            evidence_kind=EvidenceKind.CODEQL_LOCAL_FLOW,
            max_nodes=30,
            max_edges=max_edges,
            max_depth=1,
            row_filter=local_filter,
        )
        result.provenance.update(
            target_entity_id=target_entity.entity_id if target_entity is not None else None,
            scope_entity_id=scope_entity.entity_id if scope_entity is not None else None,
        )
        return result

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
