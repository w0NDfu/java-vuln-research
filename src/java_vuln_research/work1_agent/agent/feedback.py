"""M7 adapters for tool evidence and deterministic Evidence Gate feedback."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.proposal import (
    EvidenceGateResult,
    EvidenceRef,
    EvidenceSourceKind,
    EvidenceStrength,
)
from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex

from .actions import ActionType
from .budget import BudgetTracker
from .tool_adapter import AgentToolResult, AgentToolStatus


_ENTITY_ID = re.compile(r"^entity-[0-9a-f]{24}$")
_CODEQL_KIND = {
    ActionType.CODEQL_ENTITY_FACTS.value: EvidenceSourceKind.CODEQL_ENTITY_FACT,
    ActionType.CODEQL_CALLERS.value: EvidenceSourceKind.CODEQL_CALL,
    ActionType.CODEQL_CALLEES.value: EvidenceSourceKind.CODEQL_CALL,
    ActionType.CODEQL_LOCAL_FLOW.value: EvidenceSourceKind.CODEQL_LOCAL_FLOW,
    ActionType.CODEQL_DATAFLOW_NEIGHBORS.value: EvidenceSourceKind.CODEQL_DATAFLOW,
    ActionType.CODEQL_CFG_NEIGHBORS.value: EvidenceSourceKind.CODEQL_CFG,
}
_RELATION_TOOLS = {
    ActionType.GET_CALLERS.value,
    ActionType.GET_CALLEES.value,
    ActionType.GET_IMPLEMENTATIONS.value,
    ActionType.GET_OVERRIDES.value,
    ActionType.GET_FIELDS.value,
    ActionType.GET_ANNOTATIONS.value,
}


def _entity_ids(value: Any, known: set[str], found: set[str]) -> None:
    if isinstance(value, Mapping):
        for item in value.values():
            _entity_ids(item, known, found)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for item in value:
            _entity_ids(item, known, found)
    elif isinstance(value, str) and _ENTITY_ID.fullmatch(value) and value in known:
        found.add(value)


def _location(item: Mapping[str, Any]) -> tuple[str | None, int | None, int | None]:
    entity = item.get("entity")
    if isinstance(entity, Mapping) and entity.get("repository_relative_path"):
        return (
            str(entity["repository_relative_path"]),
            int(entity["start_line"]),
            int(entity["end_line"]),
        )
    if item.get("repository_relative_path") and item.get("start_line") is not None:
        return (
            str(item["repository_relative_path"]),
            int(item["start_line"]),
            int(item.get("end_line", item["start_line"])),
        )
    location = item.get("location")
    if isinstance(location, Mapping) and location.get("repository_relative_path") and location.get("line") is not None:
        line = int(location["line"])
        return str(location["repository_relative_path"]), line, line
    return None, None, None


def evidence_from_tool_result(
    result: AgentToolResult,
    repository_index: RepositoryIndex,
) -> tuple[EvidenceRef, ...]:
    """Convert only successful, entity-grounded bounded results to M4 EvidenceRef."""

    if result.status is not AgentToolStatus.OK:
        return ()
    known = {item.entity_id for item in repository_index.entities}
    evidence: list[EvidenceRef] = []
    for position, item in enumerate(result.items):
        ids: set[str] = set()
        _entity_ids({"item": item, "arguments": result.provenance.get("arguments", {})}, known, ids)
        path, start, end = _location(item)
        if not ids and path is not None and start is not None and end is not None:
            ids.update(
                entity.entity_id
                for entity in repository_index.entities
                if entity.repository_relative_path == path
                and entity.start_line <= end
                and start <= entity.end_line
            )
        if not ids:
            continue
        if result.tool_name in _CODEQL_KIND:
            source_kind = _CODEQL_KIND[result.tool_name]
            strength = EvidenceStrength.DIRECT
            path, start, end = None, None, None
        elif result.tool_name in _RELATION_TOOLS:
            source_kind = EvidenceSourceKind.REPOSITORY_RELATION
            strength = EvidenceStrength.STRONG_STRUCTURAL
        else:
            source_kind = EvidenceSourceKind.REPOSITORY_TOOL_RESULT
            strength = EvidenceStrength.SUPPORTING
        item_hash = hashlib.sha256(
            canonical_json({"tool_call_id": result.tool_call_id, "position": position, "item": dict(item)}).encode("utf-8")
        ).hexdigest()
        evidence.append(
            EvidenceRef.create(
                source_kind=source_kind,
                entity_ids=sorted(ids),
                confidence=strength,
                repository_relative_path=path,
                start_line=start,
                end_line=end,
                tool_call_id=result.tool_call_id,
                result_hash=item_hash,
                provenance={
                    "producer": "M7_AGENT_TOOL_ADAPTER",
                    "tool_name": result.tool_name,
                    "tool_call_id": result.tool_call_id,
                    "item_position": position,
                    "deterministic_relation": source_kind in _CODEQL_KIND.values(),
                    "benchmark_informed": False,
                },
            )
        )
    return tuple(evidence)


@dataclass(frozen=True, slots=True)
class AgentGateFeedback:
    feedback_id: str
    project_id: str
    round: int
    payload: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "feedback_id": self.feedback_id,
            "project_id": self.project_id,
            "round": self.round,
            **dict(self.payload),
        }


def build_gate_feedback(
    *,
    project_id: str,
    round: int,
    result: EvidenceGateResult,
    active_proposal_count: int,
    candidate_path_ids_before: Sequence[str],
    candidate_path_ids_after: Sequence[str],
    tool_results: Sequence[AgentToolResult],
    budget: BudgetTracker,
    new_connected_anchors: Sequence[Mapping[str, Any]] = (),
    path_truncated: bool = False,
    graph_update_enabled: bool = False,
) -> AgentGateFeedback:
    before = set(candidate_path_ids_before)
    after = set(candidate_path_ids_after)
    reasons = result.rejection_reasons or result.missing_evidence or result.warnings or [result.status.value]
    tool_errors = [
        {
            "tool_call_id": item.tool_call_id,
            "tool_name": item.tool_name,
            "status": item.status.value,
            "failure": dict(item.failure) if item.failure else None,
        }
        for item in tool_results[-10:]
        if item.status not in {AgentToolStatus.OK, AgentToolStatus.EMPTY}
    ]
    payload = {
        "proposal_id": result.proposal_id,
        "gate_status": result.status.value,
        "gate_reason": "; ".join(reasons),
        "resolved_evidence_refs": [str(item["evidence_id"]) for item in result.resolved_evidence],
        "active_proposal_count": active_proposal_count,
        "candidate_path_count_before": len(before),
        "candidate_path_count_after": len(after),
        "new_path_ids": sorted(after - before),
        "new_connected_anchors": [dict(item) for item in new_connected_anchors],
        "unresolved_semantics": sorted(set(result.missing_evidence + result.rejection_reasons)),
        "search_truncated": any(item.truncated for item in tool_results[-10:]),
        "path_truncated": bool(path_truncated),
        "tool_availability_or_error": tool_errors,
        "remaining_budget": dict(budget.to_dict()["remaining"]),
        "gate_result": result.to_dict(),
        "graph_update_enabled": bool(graph_update_enabled),
    }
    identity = {"project_id": project_id, "round": round, "payload": payload}
    return AgentGateFeedback(stable_digest("gatefeedback", identity), project_id, round, payload)
