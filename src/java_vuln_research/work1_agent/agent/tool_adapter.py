"""Deterministic, bounded dispatcher over the existing M2 and M3 APIs."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping

from java_vuln_research.work1_agent.codeql.analysis_tools import CodeQLAnalysisTools
from java_vuln_research.work1_agent.proposal.model import stable_digest
from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex
from java_vuln_research.work1_agent.repository.reader import inspect_entity, read_file_range
from java_vuln_research.work1_agent.repository.search import search_code, search_symbols

from .actions import TOOL_ACTIONS, ActionType, AgentAction
from .parser import validate_tool_arguments
from .security_boundary import RuntimeInputKind, RuntimeSecurityBoundary


class AgentToolStatus(str, Enum):
    OK = "OK"
    EMPTY = "EMPTY"
    ERROR = "ERROR"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    ENTITY_NOT_MAPPED = "ENTITY_NOT_MAPPED"


@dataclass(frozen=True, slots=True)
class AgentToolResult:
    tool_call_id: str
    project_id: str
    action_id: str
    tool_name: str
    status: AgentToolStatus
    items: tuple[Mapping[str, Any], ...]
    truncated: bool
    warnings: tuple[str, ...]
    failure: Mapping[str, Any] | None
    provenance: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_call_id": self.tool_call_id,
            "project_id": self.project_id,
            "action_id": self.action_id,
            "tool_name": self.tool_name,
            "status": self.status.value,
            "items": [dict(item) for item in self.items],
            "truncated": self.truncated,
            "warnings": list(self.warnings),
            "failure": dict(self.failure) if self.failure else None,
            "provenance": dict(self.provenance),
        }


def _callable_identity(entity: ProgramEntity) -> str:
    if entity.signature and entity.signature.startswith(entity.simple_name):
        return entity.qualified_name + entity.signature[len(entity.simple_name) :]
    return entity.qualified_name


def _entity_row(entity: ProgramEntity, *, relation: str, evidence_kind: str) -> dict[str, Any]:
    return {
        "entity": entity.to_dict(),
        "relation": relation,
        "evidence_kind": evidence_kind,
        "provenance": {"kind": "M1_NEUTRAL_STRUCTURAL_RELATION", "deterministic_relation": False},
    }


class RepositoryCodeQLToolAdapter:
    def __init__(
        self,
        *,
        project_id: str,
        repository_index: RepositoryIndex,
        security_boundary: RuntimeSecurityBoundary,
        codeql_tools: CodeQLAnalysisTools | None = None,
        codeql_database: str | Path | None = None,
        codeql_ready: bool = False,
    ) -> None:
        self.project_id = project_id
        self.index = repository_index
        self.boundary = security_boundary
        self.codeql_tools = codeql_tools
        self.codeql_database = Path(codeql_database) if codeql_database is not None else None
        self.codeql_ready = bool(codeql_ready)
        self.entities = {item.entity_id: item for item in repository_index.entities}

    def _register_source(self, entity_or_path: ProgramEntity | str) -> None:
        relative = entity_or_path.repository_relative_path if isinstance(entity_or_path, ProgramEntity) else entity_or_path
        source = self.index.repository_root / Path(*relative.split("/"))
        self.boundary.read_bytes(source, kind=RuntimeInputKind.JAVA_SOURCE, logical_name="java:" + relative)

    def _register_all_sources(self) -> None:
        paths = sorted({item.repository_relative_path for item in self.index.entities if item.kind is ProgramEntityKind.FILE})
        for path in paths:
            self._register_source(path)

    def _entity(self, entity_id: str) -> ProgramEntity:
        try:
            return self.entities[entity_id]
        except KeyError as exc:
            raise ValueError("entity_id is absent from the project-local RepositoryIndex") from exc

    @staticmethod
    def _bounded(rows: list[dict[str, Any]], limit: int) -> tuple[tuple[Mapping[str, Any], ...], bool]:
        return tuple(rows[:limit]), len(rows) > limit

    def _repository(self, action_type: ActionType, arguments: Mapping[str, Any]) -> tuple[tuple[Mapping[str, Any], ...], bool, tuple[str, ...]]:
        if action_type is ActionType.SEARCH_CODE:
            self._register_all_sources()
            rows = search_code(self.index, **arguments)
            return tuple(rows), len(rows) >= int(arguments.get("max_hits", 30)), ()
        if action_type is ActionType.SEARCH_SYMBOLS:
            self._register_all_sources()
            rows = search_symbols(self.index, **arguments)
            return tuple(rows), len(rows) >= int(arguments.get("max_hits", 30)), ()
        if action_type is ActionType.READ_FILE_RANGE:
            self._register_source(str(arguments["path"]))
            value = read_file_range(
                self.index.repository_root,
                str(arguments["path"]),
                int(arguments["start_line"]),
                int(arguments["end_line"]),
                max_lines=int(arguments.get("max_lines", 250)),
                max_bytes=int(arguments.get("max_bytes", 64 * 1024)),
            )
            return (value,), bool(value["truncated"]), ()
        entity = self._entity(str(arguments["entity_id"]))
        limit = int(arguments.get("max_results", 30))
        if action_type in {ActionType.INSPECT_METHOD, ActionType.INSPECT_TYPE}:
            expected = {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR} if action_type is ActionType.INSPECT_METHOD else {ProgramEntityKind.TYPE}
            if entity.kind not in expected:
                raise ValueError(f"{action_type.value} requires {sorted(item.value for item in expected)} entity")
            self._register_source(entity)
            value = inspect_entity(
                self.index.repository_root,
                entity,
                context_lines=int(arguments.get("context_lines", 0)),
                max_lines=int(arguments.get("max_lines", 250)),
                max_bytes=int(arguments.get("max_bytes", 64 * 1024)),
            )
            return (value,), bool(value["truncated"]), ()
        rows: list[dict[str, Any]] = []
        if action_type is ActionType.GET_CALLERS:
            for call in self.index.sorted_entities():
                if call.kind is ProgramEntityKind.CALL and call.simple_name == entity.simple_name:
                    rows.append(_entity_row(call, relation="CALLS_CANDIDATE", evidence_kind="CALL_CANDIDATE"))
        elif action_type is ActionType.GET_CALLEES:
            identity = _callable_identity(entity)
            for call in self.index.sorted_entities():
                if call.kind is ProgramEntityKind.CALL and call.enclosing_callable == identity:
                    rows.append(_entity_row(call, relation="CALLEE_CANDIDATE", evidence_kind="LEXICAL_CALL"))
        elif action_type is ActionType.GET_IMPLEMENTATIONS:
            self._register_all_sources()
            for hit in search_code(self.index, entity.simple_name, max_hits=100):
                snippet = str(hit.get("snippet") or "")
                if "implements" in snippet or "extends" in snippet:
                    rows.append({**hit, "relation": "IMPLEMENTS_OR_EXTENDS_TEXT", "evidence_kind": "IMPLEMENTS_TEXT"})
        elif action_type is ActionType.GET_OVERRIDES:
            for candidate in self.index.sorted_entities():
                if candidate.entity_id != entity.entity_id and candidate.kind in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR} and candidate.simple_name == entity.simple_name and candidate.signature == entity.signature:
                    rows.append(_entity_row(candidate, relation="OVERRIDE_CANDIDATE", evidence_kind="OVERRIDE_CANDIDATE"))
        elif action_type is ActionType.GET_FIELDS:
            owner = entity.qualified_name if entity.kind is ProgramEntityKind.TYPE else entity.enclosing_type
            for candidate in self.index.sorted_entities():
                if candidate.kind is ProgramEntityKind.FIELD and candidate.enclosing_type == owner:
                    rows.append(_entity_row(candidate, relation="DECLARED_FIELD", evidence_kind="STRUCTURAL_FIELD"))
        elif action_type is ActionType.GET_ANNOTATIONS:
            for candidate in self.index.sorted_entities():
                if candidate.kind is not ProgramEntityKind.ANNOTATION or candidate.repository_relative_path != entity.repository_relative_path:
                    continue
                attached = entity.start_line <= candidate.start_line <= entity.end_line or 0 <= entity.start_line - candidate.end_line <= 3
                if attached:
                    rows.append(_entity_row(candidate, relation="ANNOTATION_CANDIDATE", evidence_kind="STRUCTURAL_ANNOTATION"))
        else:
            raise ValueError(f"unsupported repository action: {action_type.value}")
        selected, truncated = self._bounded(rows, limit)
        warning = ("M1_RELATION_IS_STRUCTURAL_CANDIDATE_NOT_SEMANTIC_FACT",) if action_type in {
            ActionType.GET_CALLERS,
            ActionType.GET_CALLEES,
            ActionType.GET_IMPLEMENTATIONS,
            ActionType.GET_OVERRIDES,
            ActionType.GET_ANNOTATIONS,
        } else ()
        return selected, truncated, warning

    def _codeql(self, action_type: ActionType, arguments: Mapping[str, Any]) -> tuple[tuple[Mapping[str, Any], ...], bool, tuple[str, ...], Mapping[str, Any] | None, AgentToolStatus]:
        if not self.codeql_ready or self.codeql_tools is None or self.codeql_database is None:
            failure = {"reason": "CODEQL_UNAVAILABLE", "message": "CodeQL tool or ready database is unavailable; relation absence is not inferred"}
            return (), False, ("UNAVAILABLE_IS_NOT_NEGATIVE_EVIDENCE",), failure, AgentToolStatus.UNAVAILABLE
        entity = self._entity(str(arguments["entity_id"]))
        kwargs: dict[str, Any] = {"database": self.codeql_database, "entity": entity}
        for name in ("max_edges", "max_nodes", "max_depth", "direction"):
            if name in arguments:
                kwargs[name] = arguments[name]
        if action_type is ActionType.CODEQL_LOCAL_FLOW:
            if "target_entity_id" in arguments:
                kwargs["target_entity"] = self._entity(str(arguments["target_entity_id"]))
            if "scope_entity_id" in arguments:
                kwargs["scope_entity"] = self._entity(str(arguments["scope_entity_id"]))
        method_name = {
            ActionType.CODEQL_ENTITY_FACTS: "codeql_entity_facts",
            ActionType.CODEQL_CALLERS: "codeql_callers",
            ActionType.CODEQL_CALLEES: "codeql_callees",
            ActionType.CODEQL_LOCAL_FLOW: "codeql_local_flow",
            ActionType.CODEQL_DATAFLOW_NEIGHBORS: "codeql_dataflow_neighbors",
            ActionType.CODEQL_CFG_NEIGHBORS: "codeql_cfg_neighbors",
        }[action_type]
        method = getattr(self.codeql_tools, method_name)
        raw = method(**kwargs).to_dict()
        status = AgentToolStatus(raw["status"])
        failure = raw.get("failure")
        return (raw,), bool(raw.get("truncated")), tuple(raw.get("warnings") or ()), failure, status

    def execute(self, action: AgentAction) -> AgentToolResult:
        if action.project_id != self.project_id:
            raise ValueError("tool action is cross-project")
        if action.action_type not in TOOL_ACTIONS:
            raise ValueError("only tool actions can be dispatched")
        arguments = validate_tool_arguments(action.action_type, action.arguments)
        failure: Mapping[str, Any] | None = None
        status = AgentToolStatus.OK
        try:
            if action.action_type in {
                ActionType.CODEQL_ENTITY_FACTS,
                ActionType.CODEQL_CALLERS,
                ActionType.CODEQL_CALLEES,
                ActionType.CODEQL_LOCAL_FLOW,
                ActionType.CODEQL_DATAFLOW_NEIGHBORS,
                ActionType.CODEQL_CFG_NEIGHBORS,
            }:
                items, truncated, warnings, failure, status = self._codeql(action.action_type, arguments)
            else:
                items, truncated, warnings = self._repository(action.action_type, arguments)
                status = AgentToolStatus.OK if items else AgentToolStatus.EMPTY
        except (OSError, UnicodeError, ValueError) as exc:
            items, truncated, warnings = (), False, ()
            failure = {"reason": "TOOL_EXECUTION_ERROR", "message": str(exc)}
            status = AgentToolStatus.ERROR
        identity = {
            "project_id": self.project_id,
            "action_id": action.action_id,
            "tool_name": action.action_type.value,
            "status": status.value,
            "items": [dict(item) for item in items],
            "failure": dict(failure) if failure else None,
        }
        return AgentToolResult(
            stable_digest("agenttool", identity),
            self.project_id,
            action.action_id,
            action.action_type.value,
            status,
            items,
            truncated,
            warnings,
            failure,
            {
                "bounded": True,
                "repository_first": True,
                "codeql_unavailable_is_not_absence": True,
                "arguments": dict(arguments),
            },
        )
