"""Strict model-output parser.  Natural language never becomes graph input."""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.proposal import EntityRoleRef, ProposalScope, SecurityProposal

from .actions import CODEQL_ACTIONS, REPOSITORY_ACTIONS, TOOL_ACTIONS, ActionType, AgentAction, StopReason
from .budget import BudgetTracker
from .llm_client import LLMResponse, ModelCallError, ModelFailureClass
from .schema_validation import SchemaValidationError, validate_json_schema


ENTITY_ID_PATTERN = re.compile(r"^entity-[0-9a-f]{24}$")
_DECISION_KEYS = {"action_type", "arguments", "proposal", "stop_reason", "reason"}


def _failure(kind: ModelFailureClass, message: str, response: LLMResponse) -> ModelCallError:
    return ModelCallError(kind, message, model_call_id=response.model_call_id)


def _integer(value: Any, name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    return value


def _entity_id(value: Any, name: str = "entity_id") -> str:
    if not isinstance(value, str) or not ENTITY_ID_PATTERN.fullmatch(value):
        raise ValueError(f"{name} must be a canonical ProgramEntity ID")
    return value


def _only(arguments: Mapping[str, Any], *, required: Sequence[str], optional: Sequence[str] = ()) -> None:
    missing = set(required) - set(arguments)
    extra = set(arguments) - set(required) - set(optional)
    if missing or extra:
        details = []
        if missing:
            details.append("missing=" + ",".join(sorted(missing)))
        if extra:
            details.append("extra=" + ",".join(sorted(extra)))
        raise ValueError("tool arguments violate allow-list (" + "; ".join(details) + ")")


def validate_tool_arguments(action_type: ActionType, raw: Mapping[str, Any]) -> dict[str, Any]:
    arguments = dict(raw)
    if action_type == ActionType.SEARCH_CODE:
        _only(arguments, required=("query",), optional=("file_glob", "max_hits", "case_sensitive"))
        query = arguments["query"]
        if not isinstance(query, str) or not query.strip() or len(query) > 512:
            raise ValueError("query must be a non-empty string of at most 512 characters")
        if "file_glob" in arguments and (not isinstance(arguments["file_glob"], str) or len(arguments["file_glob"]) > 512):
            raise ValueError("file_glob must be a string of at most 512 characters")
    elif action_type == ActionType.SEARCH_SYMBOLS:
        _only(arguments, required=("query",), optional=("kind", "max_hits", "case_sensitive"))
        query = arguments["query"]
        if not isinstance(query, str) or not query.strip() or len(query) > 512:
            raise ValueError("query must be a non-empty string of at most 512 characters")
        if "kind" in arguments and (not isinstance(arguments["kind"], str) or not arguments["kind"]):
            raise ValueError("kind must be a non-empty ProgramEntity kind")
    elif action_type in {ActionType.INSPECT_METHOD, ActionType.INSPECT_TYPE}:
        _only(arguments, required=("entity_id",), optional=("context_lines", "max_lines", "max_bytes"))
        _entity_id(arguments["entity_id"])
        if "context_lines" in arguments:
            _integer(arguments["context_lines"], "context_lines", 0, 100)
        if "max_lines" in arguments:
            _integer(arguments["max_lines"], "max_lines", 1, 1000)
        if "max_bytes" in arguments:
            _integer(arguments["max_bytes"], "max_bytes", 1, 1024 * 1024)
    elif action_type == ActionType.READ_FILE_RANGE:
        _only(arguments, required=("path", "start_line", "end_line"), optional=("max_lines", "max_bytes"))
        path = arguments["path"]
        if not isinstance(path, str) or not path or "\\" in path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
            raise ValueError("path must be a confined repository-relative POSIX path")
        first = _integer(arguments["start_line"], "start_line", 1, 2**31 - 1)
        last = _integer(arguments["end_line"], "end_line", 1, 2**31 - 1)
        if last < first:
            raise ValueError("end_line must not precede start_line")
        max_lines = _integer(arguments.get("max_lines", 250), "max_lines", 1, 1000)
        if last - first + 1 > max_lines:
            raise ValueError("requested line range exceeds max_lines")
        if "max_bytes" in arguments:
            _integer(arguments["max_bytes"], "max_bytes", 1, 1024 * 1024)
    elif action_type in {
        ActionType.GET_CALLERS,
        ActionType.GET_CALLEES,
        ActionType.GET_IMPLEMENTATIONS,
        ActionType.GET_OVERRIDES,
        ActionType.GET_FIELDS,
        ActionType.GET_ANNOTATIONS,
    }:
        _only(arguments, required=("entity_id",), optional=("max_results",))
        _entity_id(arguments["entity_id"])
        if "max_results" in arguments:
            _integer(arguments["max_results"], "max_results", 1, 100)
    elif action_type == ActionType.CODEQL_ENTITY_FACTS:
        _only(arguments, required=("entity_id",))
        _entity_id(arguments["entity_id"])
    elif action_type in {ActionType.CODEQL_CALLERS, ActionType.CODEQL_CALLEES}:
        _only(arguments, required=("entity_id",), optional=("max_edges",))
        _entity_id(arguments["entity_id"])
        if "max_edges" in arguments:
            _integer(arguments["max_edges"], "max_edges", 1, 500)
    elif action_type == ActionType.CODEQL_LOCAL_FLOW:
        _only(arguments, required=("entity_id",), optional=("target_entity_id", "scope_entity_id", "max_edges"))
        _entity_id(arguments["entity_id"])
        for name in ("target_entity_id", "scope_entity_id"):
            if name in arguments:
                _entity_id(arguments[name], name)
        if "max_edges" in arguments:
            _integer(arguments["max_edges"], "max_edges", 1, 500)
    elif action_type in {ActionType.CODEQL_DATAFLOW_NEIGHBORS, ActionType.CODEQL_CFG_NEIGHBORS}:
        _only(arguments, required=("entity_id",), optional=("direction", "max_nodes", "max_edges", "max_depth"))
        _entity_id(arguments["entity_id"])
        if str(arguments.get("direction", "BOTH")).upper() not in {"FORWARD", "BACKWARD", "BOTH"}:
            raise ValueError("direction must be FORWARD, BACKWARD, or BOTH")
        if "max_nodes" in arguments:
            _integer(arguments["max_nodes"], "max_nodes", 1, 200)
        if "max_edges" in arguments:
            _integer(arguments["max_edges"], "max_edges", 1, 500)
        if "max_depth" in arguments and _integer(arguments["max_depth"], "max_depth", 1, 1) != 1:
            raise ValueError("max_depth must remain 1")
    else:
        raise ValueError(f"{action_type.value} is not an executable tool action")
    for name in ("max_hits",):
        if name in arguments:
            _integer(arguments[name], name, 1, 100)
    if "case_sensitive" in arguments and not isinstance(arguments["case_sensitive"], bool):
        raise ValueError("case_sensitive must be boolean")
    return arguments


def _check_budget(action_type: ActionType, budget: BudgetTracker | None, response: LLMResponse) -> None:
    if budget is None:
        return
    if action_type in TOOL_ACTIONS and (
        budget.tool_calls_current_round >= budget.limits.max_tool_calls_per_round
        or budget.tool_calls_total >= budget.limits.max_total_tool_calls_per_project
    ):
        raise _failure(ModelFailureClass.BUDGET_EXCEEDED, "tool-call budget exhausted", response)
    if action_type is ActionType.PROPOSE and (
        budget.proposals_current_round >= budget.limits.max_proposals_per_round
        or budget.proposals_total >= budget.limits.max_proposals_per_project
    ):
        raise _failure(ModelFailureClass.BUDGET_EXCEEDED, "proposal budget exhausted", response)


class StrictActionParser:
    def __init__(self, schema_root: str | Path) -> None:
        self.schema_root = Path(schema_root)
        self.decision_schema = json.loads((self.schema_root / "work1_agent_model_decision.schema.json").read_text(encoding="utf-8"))
        self.action_schema = json.loads((self.schema_root / "work1_agent_action.schema.json").read_text(encoding="utf-8"))
        self.proposal_schema = json.loads((self.schema_root / "security_proposal.schema.json").read_text(encoding="utf-8"))

    def _validate(self, value: Mapping[str, Any], schema: Mapping[str, Any], response: LLMResponse) -> None:
        try:
            validate_json_schema(
                value,
                schema,
                store={
                    "security_proposal.schema.json": self.proposal_schema,
                    "work1_agent_action.schema.json": self.action_schema,
                    "work1_agent_model_decision.schema.json": self.decision_schema,
                },
            )
        except SchemaValidationError as exc:
            raise _failure(ModelFailureClass.SCHEMA_VIOLATION, f"schema rejected model output at {exc}", response) from exc

    def parse(
        self,
        response: LLMResponse,
        *,
        project_id: str,
        round: int,
        budget: BudgetTracker | None = None,
        known_entity_ids: set[str] | None = None,
        known_evidence_refs: set[str] | None = None,
    ) -> AgentAction:
        raw_text = response.raw_text.strip()
        if not raw_text.startswith("{") or not raw_text.endswith("}"):
            raise _failure(ModelFailureClass.INVALID_JSON, "model output must be one bare JSON object", response)
        try:
            value = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise _failure(ModelFailureClass.INVALID_JSON, f"invalid JSON at line {exc.lineno} column {exc.colno}", response) from exc
        if not isinstance(value, dict):
            raise _failure(ModelFailureClass.INVALID_JSON, "model output must decode to an object", response)
        if set(value) != _DECISION_KEYS:
            raise _failure(ModelFailureClass.SCHEMA_VIOLATION, "model decision must contain exactly the five allowed fields", response)
        try:
            action_type = ActionType(value.get("action_type"))
        except (TypeError, ValueError) as exc:
            raise _failure(ModelFailureClass.INVALID_ACTION, "unknown or missing action_type", response) from exc
        self._validate(value, self.decision_schema, response)
        _check_budget(action_type, budget, response)

        arguments: dict[str, Any] = {}
        proposal: SecurityProposal | None = None
        stop_reason: StopReason | None = None
        if action_type in TOOL_ACTIONS:
            try:
                arguments = validate_tool_arguments(action_type, value["arguments"])
                entity_ids = {str(item) for name, item in arguments.items() if name.endswith("entity_id")}
                if known_entity_ids is not None and not entity_ids.issubset(known_entity_ids):
                    raise ValueError("tool action references an entity absent from the current ProgramEntity catalog")
            except (TypeError, ValueError) as exc:
                raise _failure(ModelFailureClass.TOOL_ARGUMENT_INVALID, str(exc), response) from exc
        elif action_type is ActionType.PROPOSE:
            raw_proposal = dict(value["proposal"])
            raw_provenance = dict(raw_proposal.get("provenance") or {})
            if raw_provenance.get("benchmark_informed") not in {None, False}:
                raise _failure(ModelFailureClass.SCHEMA_VIOLATION, "proposal claims benchmark-informed provenance", response)
            if raw_provenance.get("allowed_for_agent_runtime") is False:
                raise _failure(ModelFailureClass.SCHEMA_VIOLATION, "proposal is marked ineligible for Agent runtime", response)
            scope_value = dict(raw_proposal["scope"])
            if scope_value.get("project_id") not in {None, project_id}:
                raise _failure(ModelFailureClass.SCHEMA_VIOLATION, "proposal scope is cross-project", response)
            scope_value["project_id"] = project_id
            raw_proposal["scope"] = scope_value
            try:
                if "proposal_id" in raw_proposal:
                    proposal = SecurityProposal.from_dict(raw_proposal)
                else:
                    proposal = SecurityProposal.create(
                        proposal_type=raw_proposal["proposal_type"],
                        subject=EntityRoleRef.from_dict(raw_proposal["subject"]),
                        source=EntityRoleRef.from_dict(raw_proposal["source"]) if raw_proposal.get("source") else None,
                        target=EntityRoleRef.from_dict(raw_proposal["target"]) if raw_proposal.get("target") else None,
                        scope=ProposalScope.from_dict(scope_value),
                        semantic_category=raw_proposal.get("semantic_category"),
                        evidence_refs=raw_proposal["evidence_refs"],
                        reason=str(raw_proposal["reason"]),
                        model_confidence=raw_proposal.get("model_confidence"),
                        provenance=raw_provenance,
                    )
            except (KeyError, TypeError, ValueError) as exc:
                raise _failure(ModelFailureClass.SCHEMA_VIOLATION, f"proposal is not a valid M4 proposal: {exc}", response) from exc
            referenced_entities = {
                proposal.subject.entity_id,
                *(item.entity_id for item in (proposal.source, proposal.target) if item is not None),
                *proposal.scope.entity_ids,
            }
            if known_entity_ids is not None and not referenced_entities.issubset(known_entity_ids):
                raise _failure(ModelFailureClass.SCHEMA_VIOLATION, "proposal references an entity absent from the current ProgramEntity catalog", response)
            if known_evidence_refs is not None and not set(proposal.evidence_refs).issubset(known_evidence_refs):
                raise _failure(ModelFailureClass.SCHEMA_VIOLATION, "proposal references fabricated or unavailable evidence", response)
            provenance = {
                **dict(proposal.provenance),
                "producer": "M7_AGENT_LLM",
                "model_call_id": response.model_call_id,
                "provider": response.provider,
                "model_id": response.model_id,
                "round": round,
                "benchmark_informed": False,
                "allowed_for_agent_runtime": True,
            }
            proposal = replace(proposal, provenance=provenance)
        else:
            stop_reason = StopReason(value["stop_reason"])

        action = AgentAction.create(
            project_id=project_id,
            round=round,
            action_type=action_type,
            arguments=arguments,
            proposal=proposal,
            stop_reason=stop_reason,
            reason=str(value["reason"]),
            provenance={
                "producer": "M7_AGENT_LLM",
                "model_call_id": response.model_call_id,
                "provider": response.provider,
                "model_id": response.model_id,
                "benchmark_informed": False,
            },
        )
        self._validate(action.to_dict(), self.action_schema, response)
        return action
