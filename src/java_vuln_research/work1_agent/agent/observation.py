"""Bounded repository-first observations for the M7 reasoner."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest
from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex

from .actions import ActionType
from .state import AgentState


OBSERVATION_VERSION = 2
MAX_OVERVIEW_PACKAGES = 10
MAX_RECENT_ENTITIES = 5
MAX_RECENT_EVIDENCE = 5
MAX_RECENT_FEEDBACK = 3
MAX_NAME_CHARS = 300
MAX_TOOL_SUMMARY_TEXT_CHARS = 3000
MAX_BOOTSTRAP_OBSERVATION_CHARS = 16 * 1024
MAX_TOOL_GROUNDED_OBSERVATION_CHARS = 24 * 1024
MAX_OBSERVATION_CHARS = MAX_TOOL_GROUNDED_OBSERVATION_CHARS


_TOOL_PURPOSES = {
    ActionType.SEARCH_CODE: "Search bounded source text and return grounded file and line hits.",
    ActionType.SEARCH_SYMBOLS: "Search bounded indexed symbols and return stable entity IDs.",
    ActionType.INSPECT_METHOD: "Read one indexed method or constructor with bounded source context.",
    ActionType.INSPECT_TYPE: "Read one indexed type with bounded source context.",
    ActionType.READ_FILE_RANGE: "Read one explicit repository-relative source range.",
    ActionType.GET_CALLERS: "List bounded structural caller candidates for one entity.",
    ActionType.GET_CALLEES: "List bounded structural callee candidates within one callable.",
    ActionType.GET_IMPLEMENTATIONS: "List bounded implementation or extension candidates.",
    ActionType.GET_OVERRIDES: "List bounded override candidates for one callable.",
    ActionType.GET_FIELDS: "List bounded fields declared by the containing type.",
    ActionType.GET_ANNOTATIONS: "List bounded annotations structurally attached to one entity.",
    ActionType.CODEQL_ENTITY_FACTS: "Request fixed CodeQL facts for one mapped entity.",
    ActionType.CODEQL_CALLERS: "Request fixed depth-one CodeQL caller edges.",
    ActionType.CODEQL_CALLEES: "Request fixed depth-one CodeQL callee edges.",
    ActionType.CODEQL_LOCAL_FLOW: "Request fixed bounded CodeQL local-flow evidence.",
    ActionType.CODEQL_DATAFLOW_NEIGHBORS: "Request fixed bounded CodeQL data-flow neighbors.",
    ActionType.CODEQL_CFG_NEIGHBORS: "Request fixed bounded CodeQL control-flow neighbors.",
}


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
    return [
        {"name": action.value, "purpose": _TOOL_PURPOSES[action], **entries[action]}
        for action in sorted(entries, key=lambda item: item.value)
    ]


def _bounded_value(value: Any, *, depth: int = 0, text_chars: int = 500) -> Any:
    if isinstance(value, str):
        return value if len(value) <= text_chars else value[: text_chars - 1] + "…"
    if isinstance(value, Mapping):
        if depth >= 3:
            return {"summary": f"mapping[{len(value)}]"}
        return {
            str(key): _bounded_value(value[key], depth=depth + 1, text_chars=text_chars)
            for key in sorted(value, key=str)[:12]
        }
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        if depth >= 3:
            return {"summary": f"sequence[{len(value)}]"}
        return [_bounded_value(item, depth=depth + 1, text_chars=text_chars) for item in value[:5]]
    return value


def _compact_entity(entity: ProgramEntity) -> dict[str, Any]:
    return {
        "entity_id": entity.entity_id,
        "kind": entity.kind.value,
        "qualified_name": _text(entity.qualified_name),
        "repository_relative_path": _text(entity.repository_relative_path),
        "start_line": entity.start_line,
        "end_line": entity.end_line,
    }


def _compact_tool_item(item: Mapping[str, Any]) -> dict[str, Any]:
    selected: dict[str, Any] = {}
    entity = item.get("entity")
    if isinstance(entity, Mapping):
        selected["entity"] = {
            key: _bounded_value(entity[key])
            for key in (
                "entity_id",
                "kind",
                "qualified_name",
                "signature",
                "repository_relative_path",
                "start_line",
                "end_line",
            )
            if key in entity
        }
    for key in (
        "entity_id",
        "kind",
        "qualified_name",
        "signature",
        "repository_relative_path",
        "start_line",
        "end_line",
        "relation",
        "evidence_kind",
        "location",
        "range",
        "status",
        "truncated",
        "warnings",
        "failure",
        "summary",
        "snippet",
        "content",
        "nodes",
        "edges",
    ):
        if key in item:
            limit = MAX_TOOL_SUMMARY_TEXT_CHARS if key in {"snippet", "content", "summary"} else 500
            selected[key] = _bounded_value(item[key], text_chars=limit)
    if not selected:
        selected = _bounded_value(item)
    return selected


def _compact_evidence(value: Mapping[str, Any] | str) -> dict[str, Any]:
    if isinstance(value, str):
        return {"evidence_id": value}
    compact = {
        key: _bounded_value(value[key])
        for key in (
            "evidence_id",
            "source_kind",
            "repository_relative_path",
            "start_line",
            "end_line",
            "tool_call_id",
            "confidence",
        )
        if key in value
    }
    entity_ids = value.get("entity_ids")
    if isinstance(entity_ids, Sequence) and not isinstance(entity_ids, (str, bytes, bytearray)):
        compact["entity_ids"] = [str(item) for item in entity_ids[:25]]
        compact["entity_ids_truncated"] = len(entity_ids) > 25
    return compact


def _compact_feedback(value: Mapping[str, Any]) -> dict[str, Any]:
    compact = {
        key: _bounded_value(value[key])
        for key in (
            "feedback_id",
            "round",
            "tool_call_id",
            "tool_name",
            "status",
            "truncated",
            "warnings",
            "failure",
            "proposal_id",
            "gate_status",
            "gate_reason",
            "active_proposal_count",
            "candidate_path_count_before",
            "candidate_path_count_after",
            "new_path_ids",
            "new_connected_anchors",
            "unresolved_semantics",
            "search_truncated",
            "path_truncated",
            "graph_update_enabled",
        )
        if key in value
    }
    items = value.get("items")
    if isinstance(items, Sequence) and not isinstance(items, (str, bytes, bytearray)):
        compact["item_count"] = len(items)
        compact["items"] = [_compact_tool_item(item) for item in items[:3] if isinstance(item, Mapping)]
    evidence = value.get("evidence_refs")
    if isinstance(evidence, Sequence) and not isinstance(evidence, (str, bytes, bytearray)):
        compact["evidence_refs"] = [
            _compact_evidence(item)
            for item in evidence[:MAX_RECENT_EVIDENCE]
            if isinstance(item, (Mapping, str))
        ]
    resolved = value.get("resolved_evidence_refs")
    if isinstance(resolved, Sequence) and not isinstance(resolved, (str, bytes, bytearray)):
        compact["resolved_evidence_refs"] = [str(item) for item in resolved[:MAX_RECENT_EVIDENCE]]
    return compact


def _compact_last_tool_summary(value: Mapping[str, Any]) -> dict[str, Any]:
    compact = _compact_feedback(value)
    compact.pop("items", None)
    compact.pop("evidence_refs", None)
    return compact


def _collect_entity_ids(value: Any, found: list[str]) -> None:
    if len(found) >= MAX_RECENT_ENTITIES:
        return
    if isinstance(value, Mapping):
        raw = value.get("entity_id")
        if isinstance(raw, str) and raw not in found:
            found.append(raw)
        for item in value.values():
            _collect_entity_ids(item, found)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _collect_entity_ids(item, found)


def _recent_evidence(feedback: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    order: list[str] = []
    selected: dict[str, dict[str, Any]] = {}
    for item in reversed(feedback):
        values: list[Mapping[str, Any] | str] = []
        raw = item.get("evidence_refs")
        if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
            values.extend(value for value in raw if isinstance(value, (Mapping, str)))
        resolved = item.get("resolved_evidence_refs")
        if isinstance(resolved, Sequence) and not isinstance(resolved, (str, bytes, bytearray)):
            values.extend(str(value) for value in resolved)
        for value in values:
            compact = _compact_evidence(value)
            identity = str(compact.get("evidence_id") or canonical_json(compact))
            if identity not in selected:
                order.append(identity)
                selected[identity] = compact
            elif compact.get("entity_ids") and not selected[identity].get("entity_ids"):
                selected[identity] = compact
    return [selected[identity] for identity in order[:MAX_RECENT_EVIDENCE]]


def _finalize_observation(
    *,
    state: AgentState,
    level: str,
    payload: dict[str, Any],
    hard_ceiling_chars: int,
) -> AgentObservation:
    metrics = {
        "serialized_chars": 0,
        "estimated_input_tokens": 0,
        "token_estimate_method": "ceil(serialized_chars/4)",
        "hard_ceiling_chars": hard_ceiling_chars,
    }
    payload["observation_metrics"] = metrics
    observation: AgentObservation | None = None
    for _ in range(8):
        identity = {
            "schema_version": OBSERVATION_VERSION,
            "project_id": state.project_id,
            "round": state.current_round,
            "payload": payload,
        }
        observation = AgentObservation(
            stable_digest("observation", identity),
            state.project_id,
            state.current_round,
            payload,
        )
        size = len(observation.to_json())
        estimate = math.ceil(size / 4)
        if metrics["serialized_chars"] == size and metrics["estimated_input_tokens"] == estimate:
            break
        metrics["serialized_chars"] = size
        metrics["estimated_input_tokens"] = estimate
    assert observation is not None
    actual_size = len(observation.to_json())
    if actual_size != metrics["serialized_chars"]:
        raise ValueError("observation size accounting did not converge")
    if actual_size > hard_ceiling_chars:
        raise ValueError(f"{level} observation exceeds hard character ceiling")
    return observation


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
    packages = [
        _text(item.qualified_name) or _text(item.simple_name)
        for item in entities
        if item.kind is ProgramEntityKind.PACKAGE
    ][:MAX_OVERVIEW_PACKAGES]
    compact_tools = [
        {"name": item["name"], "purpose": item["purpose"]}
        for item in bounded_tool_catalog()
    ]
    compact_codeql = {
        key: _bounded_value(codeql_status[key])
        for key in ("available", "ready", "status", "reason", "database_identity")
        if key in codeql_status
    }
    baseline = native_baseline_summary or {}
    compact_native = {
        key: _bounded_value(baseline[key])
        for key in ("available", "candidate_path_count", "native_candidate_path_count", "status")
        if key in baseline
    } or {"available": False, "candidate_path_count": 0}
    all_feedback = [dict(item) for item in recent_feedback]
    selected_feedback = all_feedback[-MAX_RECENT_FEEDBACK:]
    level = "TOOL_GROUNDED" if all_feedback else "BOOTSTRAP"
    payload: dict[str, Any] = {
        "observation_level": level,
        "repository_identity": state.repository_identity,
        "bootstrap": {
            "java_file_count": repository_index.java_file_count,
            "program_entity_count": len(entities),
            "entity_kind_counts": dict(sorted(counts.items())),
            "diagnostic_count": len(repository_index.diagnostics),
            "top_packages": packages,
            "top_packages_truncated": counts[ProgramEntityKind.PACKAGE.value] > len(packages),
            "codeql_status": compact_codeql,
            "native_baseline_summary": compact_native,
            "budget": state.budget.to_dict(),
            "tools": compact_tools,
        },
        "current_exploration_focus": state.current_exploration_focus,
        "unresolved_questions": [_text(item) for item in state.unresolved_questions[-3:]],
        "recent_feedback": [_compact_feedback(item) for item in selected_feedback],
        "runtime_rules": {
            "repository_first": True,
            "frontier_required": False,
            "native_path_required": False,
            "codeql_unavailable_means_no_relation": False,
            "candidate_path_is_vulnerability": False,
        },
    }
    if selected_feedback:
        entity_ids: list[str] = []
        for item in reversed(all_feedback):
            _collect_entity_ids(item, entity_ids)
        if len(entity_ids) < MAX_RECENT_ENTITIES:
            entity_ids.extend(
                entity_id
                for entity_id in sorted(state.inspected_entity_ids)
                if entity_id not in entity_ids
            )
        by_id = {item.entity_id: item for item in entities}
        recent_entities = [
            _compact_entity(by_id[entity_id])
            for entity_id in entity_ids[:MAX_RECENT_ENTITIES]
            if entity_id in by_id
        ]
        last_tool = next(
            (
                _compact_last_tool_summary(item)
                for item in reversed(selected_feedback)
                if item.get("tool_name") is not None
            ),
            None,
        )
        payload["tool_grounded_context"] = {
            "last_tool_summary": last_tool,
            "recent_entities": recent_entities,
            "recent_evidence_refs": _recent_evidence(all_feedback),
            "recent_feedback_count": len(selected_feedback),
        }
    ceiling = (
        MAX_BOOTSTRAP_OBSERVATION_CHARS
        if level == "BOOTSTRAP"
        else MAX_TOOL_GROUNDED_OBSERVATION_CHARS
    )
    return _finalize_observation(
        state=state,
        level=level,
        payload=payload,
        hard_ceiling_chars=ceiling,
    )
