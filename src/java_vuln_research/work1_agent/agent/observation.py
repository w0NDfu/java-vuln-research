"""Bounded repository-first observations for the M7 reasoner."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest
from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex

from .actions import ActionType
from .state import AgentState


OBSERVATION_VERSION = 1
MAX_OVERVIEW_PACKAGES = 20
MAX_OVERVIEW_TYPES = 30
MAX_OVERVIEW_METHODS = 30
MAX_NAME_CHARS = 300
MAX_OBSERVATION_CHARS = 64 * 1024


def _text(value: str | None) -> str | None:
    if value is None:
        return None
    return value if len(value) <= MAX_NAME_CHARS else value[: MAX_NAME_CHARS - 1] + "…"


def _entity_overview(entity: ProgramEntity) -> dict[str, Any]:
    return {
        "entity_id": entity.entity_id,
        "kind": entity.kind.value,
        "qualified_name": _text(entity.qualified_name),
        "signature": _text(entity.signature),
        "repository_relative_path": _text(entity.repository_relative_path),
        "start_line": entity.start_line,
        "end_line": entity.end_line,
        "extraction_confidence": entity.extraction_confidence.value,
    }


def bounded_tool_catalog() -> list[dict[str, Any]]:
    entries = {
        ActionType.SEARCH_CODE: {"required": ["query"], "bounds": {"query_chars": 512, "max_hits": 100}},
        ActionType.SEARCH_SYMBOLS: {"required": ["query"], "bounds": {"query_chars": 512, "max_hits": 100}},
        ActionType.INSPECT_METHOD: {"required": ["entity_id"], "bounds": {"context_lines": 100, "max_lines": 1000, "max_bytes": 1048576}},
        ActionType.INSPECT_TYPE: {"required": ["entity_id"], "bounds": {"context_lines": 100, "max_lines": 1000, "max_bytes": 1048576}},
        ActionType.READ_FILE_RANGE: {"required": ["path", "start_line", "end_line"], "bounds": {"max_lines": 1000, "max_bytes": 1048576}},
        ActionType.GET_CALLERS: {"required": ["entity_id"], "bounds": {"max_results": 100}},
        ActionType.GET_CALLEES: {"required": ["entity_id"], "bounds": {"max_results": 100}},
        ActionType.GET_IMPLEMENTATIONS: {"required": ["entity_id"], "bounds": {"max_results": 100}},
        ActionType.GET_OVERRIDES: {"required": ["entity_id"], "bounds": {"max_results": 100}},
        ActionType.GET_FIELDS: {"required": ["entity_id"], "bounds": {"max_results": 100}},
        ActionType.GET_ANNOTATIONS: {"required": ["entity_id"], "bounds": {"max_results": 100}},
        ActionType.CODEQL_ENTITY_FACTS: {"required": ["entity_id"], "bounds": {"fixed_query": True}},
        ActionType.CODEQL_CALLERS: {"required": ["entity_id"], "bounds": {"max_edges": 500, "max_depth": 1}},
        ActionType.CODEQL_CALLEES: {"required": ["entity_id"], "bounds": {"max_edges": 500, "max_depth": 1}},
        ActionType.CODEQL_LOCAL_FLOW: {"required": ["entity_id"], "bounds": {"max_edges": 500, "max_depth": 1}},
        ActionType.CODEQL_DATAFLOW_NEIGHBORS: {"required": ["entity_id"], "bounds": {"max_nodes": 200, "max_edges": 500, "max_depth": 1}},
        ActionType.CODEQL_CFG_NEIGHBORS: {"required": ["entity_id"], "bounds": {"max_nodes": 200, "max_edges": 500, "max_depth": 1}},
    }
    return [{"name": action.value, **entries[action]} for action in sorted(entries, key=lambda item: item.value)]


@dataclass(frozen=True, slots=True)
class AgentObservation:
    observation_id: str
    project_id: str
    round: int
    payload: Mapping[str, Any]
    schema_version: int = OBSERVATION_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "project_id": self.project_id,
            "round": self.round,
            **dict(self.payload),
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


def build_repository_first_observation(
    *,
    state: AgentState,
    repository_index: RepositoryIndex,
    codeql_status: Mapping[str, Any],
    native_baseline_summary: Mapping[str, Any] | None = None,
    recent_feedback: Sequence[Mapping[str, Any]] = (),
) -> AgentObservation:
    if state.project_id != str(codeql_status.get("project_id", state.project_id)):
        raise ValueError("CodeQL status is cross-project")
    entities = repository_index.sorted_entities()
    counts = Counter(entity.kind.value for entity in entities)
    packages = [_entity_overview(item) for item in entities if item.kind is ProgramEntityKind.PACKAGE][:MAX_OVERVIEW_PACKAGES]
    types = [_entity_overview(item) for item in entities if item.kind is ProgramEntityKind.TYPE][:MAX_OVERVIEW_TYPES]
    methods = [
        _entity_overview(item)
        for item in entities
        if item.kind in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}
    ][:MAX_OVERVIEW_METHODS]
    payload: dict[str, Any] = {
        "repository_identity": state.repository_identity,
        "repository_summary": {
            "java_file_count": repository_index.java_file_count,
            "program_entity_count": len(entities),
            "entity_kind_counts": dict(sorted(counts.items())),
            "diagnostic_count": len(repository_index.diagnostics),
        },
        "bounded_overview": {
            "packages": packages,
            "types": types,
            "methods": methods,
            "truncated": {
                "packages": counts[ProgramEntityKind.PACKAGE.value] > len(packages),
                "types": counts[ProgramEntityKind.TYPE.value] > len(types),
                "methods": counts[ProgramEntityKind.METHOD.value] + counts[ProgramEntityKind.CONSTRUCTOR.value] > len(methods),
            },
        },
        "codeql_status": dict(codeql_status),
        "native_baseline_summary": dict(native_baseline_summary or {"candidate_path_count": 0, "available": False}),
        "budget": state.budget.to_dict(),
        "tool_catalog": bounded_tool_catalog(),
        "current_exploration_focus": state.current_exploration_focus,
        "unresolved_questions": list(state.unresolved_questions[-20:]),
        "recent_feedback": [dict(item) for item in recent_feedback[-10:]],
        "runtime_rules": {
            "repository_first": True,
            "frontier_required": False,
            "native_path_required": False,
            "codeql_unavailable_means_no_relation": False,
            "candidate_path_is_vulnerability": False,
        },
    }
    identity = {"schema_version": OBSERVATION_VERSION, "project_id": state.project_id, "round": state.current_round, "payload": payload}
    observation = AgentObservation(stable_digest("observation", identity), state.project_id, state.current_round, payload)
    if len(observation.to_json()) > MAX_OBSERVATION_CHARS:
        raise ValueError("bounded observation unexpectedly exceeds hard character ceiling")
    return observation
