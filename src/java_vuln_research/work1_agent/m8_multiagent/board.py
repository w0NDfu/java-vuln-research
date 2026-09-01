"""Project-local SharedEvidenceBoard with deterministic replay events."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest

from .contracts import (
    FindingType,
    SpecialistFinding,
    SpecialistResult,
    SpecialistResultStatus,
    SpecialistRole,
    SpecialistTaskSpec,
)


BOARD_SCHEMA_VERSION = 1
BOARD_PRODUCER = "M8_SHARED_EVIDENCE_BOARD_V1"


def _mapping(value: Mapping[str, Any], name: str, *, required: bool = False) -> dict[str, Any]:
    result = dict(value)
    if required and not result:
        raise ValueError(f"{name} is required")
    canonical_json(result)
    return result


def _project(value: Mapping[str, Any], expected: str, name: str) -> None:
    project_id = value.get("project_id")
    if project_id is not None and str(project_id) != expected:
        raise ValueError(f"{name} is cross-project")


@dataclass(slots=True)
class SpecialistAgentState:
    specialist_agent: SpecialistRole
    dispatches: int = 0
    internal_rounds: int = 0
    tool_calls: int = 0
    finding_batches: int = 0
    findings: int = 0
    last_task_id: str | None = None
    last_result_id: str | None = None
    last_result_status: SpecialistResultStatus | None = None

    def record(self, task: SpecialistTaskSpec, result: SpecialistResult) -> None:
        if task.specialist_agent is not self.specialist_agent or result.specialist_agent is not self.specialist_agent:
            raise ValueError("specialist state update is cross-role")
        self.dispatches += 1
        self.internal_rounds += result.rounds_used
        self.tool_calls += result.tool_calls_used
        self.finding_batches += int(bool(result.findings))
        self.findings += len(result.findings)
        self.last_task_id = task.task_id
        self.last_result_id = result.result_id
        self.last_result_status = result.status

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SpecialistAgentState":
        return cls(
            specialist_agent=SpecialistRole(value["specialist_agent"]),
            dispatches=int(value.get("dispatches", 0)),
            internal_rounds=int(value.get("internal_rounds", 0)),
            tool_calls=int(value.get("tool_calls", 0)),
            finding_batches=int(value.get("finding_batches", 0)),
            findings=int(value.get("findings", 0)),
            last_task_id=str(value["last_task_id"]) if value.get("last_task_id") else None,
            last_result_id=str(value["last_result_id"]) if value.get("last_result_id") else None,
            last_result_status=SpecialistResultStatus(value["last_result_status"]) if value.get("last_result_status") else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "specialist_agent": self.specialist_agent.value,
            "dispatches": self.dispatches,
            "internal_rounds": self.internal_rounds,
            "tool_calls": self.tool_calls,
            "finding_batches": self.finding_batches,
            "findings": self.findings,
            "last_task_id": self.last_task_id,
            "last_result_id": self.last_result_id,
            "last_result_status": self.last_result_status.value if self.last_result_status else None,
        }


@dataclass(frozen=True, slots=True)
class BoardEvent:
    event_id: str
    sequence: int
    project_id: str
    event_type: str
    coordinator_round: int
    specialist_agent: SpecialistRole | None
    payload: Mapping[str, Any]
    provenance: Mapping[str, Any]
    schema_version: int = BOARD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != BOARD_SCHEMA_VERSION:
            raise ValueError("unsupported BoardEvent schema version")
        if self.sequence < 1 or self.coordinator_round < 0 or not self.project_id or not self.event_type:
            raise ValueError("invalid BoardEvent identity")
        _mapping(self.payload, "event payload", required=True)
        _mapping(self.provenance, "event provenance", required=True)
        if self.event_id != self.compute_id(self.identity_material()):
            raise ValueError("event_id is not canonical")

    def identity_material(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "project_id": self.project_id,
            "event_type": self.event_type,
            "coordinator_round": self.coordinator_round,
            "specialist_agent": self.specialist_agent.value if self.specialist_agent else None,
            "payload": dict(self.payload),
            "provenance": dict(self.provenance),
        }

    @staticmethod
    def compute_id(material: Mapping[str, Any]) -> str:
        return stable_digest("m8boardevent", dict(material))

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        project_id: str,
        event_type: str,
        coordinator_round: int,
        specialist_agent: SpecialistRole | None,
        payload: Mapping[str, Any],
    ) -> "BoardEvent":
        provenance = {"producer": BOARD_PRODUCER, "benchmark_informed": False}
        material = {
            "sequence": int(sequence),
            "project_id": str(project_id),
            "event_type": str(event_type),
            "coordinator_round": int(coordinator_round),
            "specialist_agent": specialist_agent.value if specialist_agent else None,
            "payload": dict(payload),
            "provenance": provenance,
        }
        return cls(event_id=cls.compute_id(material), provenance=provenance, **{key: value for key, value in material.items() if key != "provenance" and key != "specialist_agent"}, specialist_agent=specialist_agent)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BoardEvent":
        role = value.get("specialist_agent")
        return cls(
            event_id=str(value["event_id"]),
            sequence=int(value["sequence"]),
            project_id=str(value["project_id"]),
            event_type=str(value["event_type"]),
            coordinator_round=int(value["coordinator_round"]),
            specialist_agent=SpecialistRole(role) if role else None,
            payload=dict(value["payload"]),
            provenance=dict(value["provenance"]),
            schema_version=int(value.get("schema_version", BOARD_SCHEMA_VERSION)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "sequence": self.sequence,
            "project_id": self.project_id,
            "event_type": self.event_type,
            "coordinator_round": self.coordinator_round,
            "specialist_agent": self.specialist_agent.value if self.specialist_agent else None,
            "payload": dict(self.payload),
            "provenance": dict(self.provenance),
        }


@dataclass(slots=True)
class SharedEvidenceBoard:
    board_id: str
    project_id: str
    repository_summary: Mapping[str, Any]
    codeql_status: Mapping[str, Any]
    input_findings: list[SpecialistFinding] = field(default_factory=list)
    effect_findings: list[SpecialistFinding] = field(default_factory=list)
    bridge_findings: list[SpecialistFinding] = field(default_factory=list)
    inspected_entities: list[str] = field(default_factory=list)
    tool_calls: list[Mapping[str, Any]] = field(default_factory=list)
    evidence_refs: list[Mapping[str, Any]] = field(default_factory=list)
    pending_proposals: list[Mapping[str, Any]] = field(default_factory=list)
    gate_results: list[Mapping[str, Any]] = field(default_factory=list)
    active_admissible_proposals: list[Mapping[str, Any]] = field(default_factory=list)
    candidate_paths: list[Mapping[str, Any]] = field(default_factory=list)
    unresolved_questions: list[str] = field(default_factory=list)
    failed_hypotheses: list[Mapping[str, Any]] = field(default_factory=list)
    budget_state: Mapping[str, Any] = field(default_factory=dict)
    round_state: Mapping[str, Any] = field(default_factory=dict)
    agent_states: dict[SpecialistRole, SpecialistAgentState] = field(default_factory=dict)
    event_log: list[BoardEvent] = field(default_factory=list)
    schema_version: int = BOARD_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != BOARD_SCHEMA_VERSION or not self.project_id:
            raise ValueError("invalid SharedEvidenceBoard identity")
        _mapping(self.repository_summary, "repository_summary", required=True)
        _mapping(self.codeql_status, "codeql_status", required=True)
        _project(self.repository_summary, self.project_id, "repository_summary")
        _project(self.codeql_status, self.project_id, "codeql_status")
        expected = self.compute_id(self.project_id, self.repository_summary, self.codeql_status)
        if self.board_id != expected:
            raise ValueError("board_id is not canonical")
        if not self.agent_states:
            self.agent_states = {role: SpecialistAgentState(role) for role in SpecialistRole}
        if set(self.agent_states) != set(SpecialistRole):
            raise ValueError("agent_states must contain exactly the three specialists")

    @staticmethod
    def compute_id(project_id: str, repository_summary: Mapping[str, Any], codeql_status: Mapping[str, Any]) -> str:
        return stable_digest(
            "m8board",
            {
                "project_id": project_id,
                "repository_summary": dict(repository_summary),
                "codeql_status": dict(codeql_status),
            },
        )

    @classmethod
    def create(
        cls,
        *,
        project_id: str,
        repository_summary: Mapping[str, Any],
        codeql_status: Mapping[str, Any],
        budget_state: Mapping[str, Any],
        round_state: Mapping[str, Any],
        unresolved_questions: Sequence[str] = (),
    ) -> "SharedEvidenceBoard":
        repository = _mapping(repository_summary, "repository_summary", required=True)
        codeql = _mapping(codeql_status, "codeql_status", required=True)
        board = cls(
            board_id=cls.compute_id(project_id, repository, codeql),
            project_id=project_id,
            repository_summary=repository,
            codeql_status=codeql,
            budget_state=_mapping(budget_state, "budget_state", required=True),
            round_state=_mapping(round_state, "round_state", required=True),
            unresolved_questions=[str(item) for item in unresolved_questions],
        )
        board._append_event(
            event_type="BOARD_INITIALIZED",
            coordinator_round=int(board.round_state.get("coordinator_round", 0)),
            specialist_agent=None,
            payload={
                "project_id": board.project_id,
                "repository_summary": dict(board.repository_summary),
                "codeql_status": dict(board.codeql_status),
                "budget_state": dict(board.budget_state),
                "round_state": dict(board.round_state),
                "unresolved_questions": list(board.unresolved_questions),
            },
        )
        return board

    def require_project(self, project_id: str) -> None:
        if str(project_id) != self.project_id:
            raise ValueError("SharedEvidenceBoard is cross-project")

    def all_findings(self) -> tuple[SpecialistFinding, ...]:
        return tuple((*self.input_findings, *self.effect_findings, *self.bridge_findings))

    def _append_event(
        self,
        *,
        event_type: str,
        coordinator_round: int,
        specialist_agent: SpecialistRole | None,
        payload: Mapping[str, Any],
    ) -> BoardEvent:
        event = BoardEvent.create(
            sequence=len(self.event_log) + 1,
            project_id=self.project_id,
            event_type=event_type,
            coordinator_round=coordinator_round,
            specialist_agent=specialist_agent,
            payload=payload,
        )
        self.event_log.append(event)
        return event

    @staticmethod
    def _merge_artifacts(
        existing: list[Mapping[str, Any]],
        incoming: Sequence[Mapping[str, Any]],
        identity_key: str,
    ) -> None:
        index = {str(item[identity_key]): dict(item) for item in existing}
        for artifact in incoming:
            value = dict(artifact)
            identity = str(value[identity_key])
            prior = index.get(identity)
            if prior is not None and canonical_json(prior) != canonical_json(value):
                raise ValueError(f"{identity_key} collision with different content")
            if prior is None:
                existing.append(value)
                index[identity] = value

    def _apply_specialist_result(self, task: SpecialistTaskSpec, result: SpecialistResult) -> None:
        self.require_project(task.project_id)
        self.require_project(result.project_id)
        if task.task_id != result.task_id or task.specialist_agent is not result.specialist_agent:
            raise ValueError("specialist result does not match its TaskSpec")
        limits = task.remaining_specialist_budget
        if result.rounds_used > int(limits["max_internal_rounds"]):
            raise ValueError("specialist exceeded internal round budget")
        if result.tool_calls_used > int(limits["max_tool_calls"]):
            raise ValueError("specialist exceeded tool-call budget")
        if int(bool(result.findings)) > int(limits["max_finding_batches"]):
            raise ValueError("specialist exceeded finding-batch budget")

        for artifact in (*result.tool_calls, *result.evidence_refs):
            _project(artifact, self.project_id, "specialist artifact")
        self._merge_artifacts(self.tool_calls, result.tool_calls, "tool_call_id")
        self._merge_artifacts(self.evidence_refs, result.evidence_refs, "evidence_id")
        known_tool_ids = {str(item["tool_call_id"]) for item in self.tool_calls}
        known_evidence_ids = {str(item["evidence_id"]) for item in self.evidence_refs}
        finding_ids = {item.finding_id for item in self.all_findings()}
        for finding in result.findings:
            self.require_project(finding.project_id)
            if finding.finding_id in finding_ids:
                prior = next(item for item in self.all_findings() if item.finding_id == finding.finding_id)
                if canonical_json(prior.to_dict()) != canonical_json(finding.to_dict()):
                    raise ValueError("finding_id collision with different content")
                continue
            missing_tools = sorted(set(finding.tool_call_ids) - known_tool_ids)
            missing_evidence = sorted(set(finding.evidence_refs) - known_evidence_ids)
            if missing_tools or missing_evidence:
                raise ValueError(
                    f"finding references unknown artifacts: tools={missing_tools}, evidence={missing_evidence}"
                )
            target = {
                FindingType.INPUT: self.input_findings,
                FindingType.EFFECT: self.effect_findings,
                FindingType.BRIDGE: self.bridge_findings,
            }[finding.finding_type]
            target.append(finding)
            finding_ids.add(finding.finding_id)

        inspected = set(self.inspected_entities)
        for finding in result.findings:
            inspected.update(finding.entity_ids)
        for tool_call in result.tool_calls:
            inspected.update(str(item) for item in tool_call.get("entity_ids", ()) if str(item))
        self.inspected_entities = sorted(inspected)

        for suggestion in result.next_suggested_evidence:
            if suggestion not in self.unresolved_questions:
                self.unresolved_questions.append(suggestion)
        if result.status in {
            SpecialistResultStatus.NO_SUPPORTED_FINDING,
            SpecialistResultStatus.FAILED,
            SpecialistResultStatus.BUDGET_EXHAUSTED,
        }:
            self.failed_hypotheses.append(
                {
                    "task_id": task.task_id,
                    "result_id": result.result_id,
                    "specialist_agent": result.specialist_agent.value,
                    "status": result.status.value,
                    "stop_reason": result.stop_reason.value,
                    "uncertainty": list(result.uncertainty),
                }
            )
        self.agent_states[result.specialist_agent].record(task, result)
        self.round_state = {
            **dict(self.round_state),
            "coordinator_round": task.coordinator_round,
            "last_task_id": task.task_id,
            "last_result_id": result.result_id,
        }

    def merge_specialist_result(self, task: SpecialistTaskSpec, result: SpecialistResult) -> BoardEvent:
        prior_task_ids = {
            str(event.payload["task"]["task_id"])
            for event in self.event_log
            if event.event_type == "SPECIALIST_RESULT_MERGED"
        }
        if task.task_id in prior_task_ids:
            raise ValueError("task_id has already been merged")
        self._apply_specialist_result(task, result)
        return self._append_event(
            event_type="SPECIALIST_RESULT_MERGED",
            coordinator_round=task.coordinator_round,
            specialist_agent=task.specialist_agent,
            payload={"task": task.to_dict(), "result": result.to_dict()},
        )

    def _apply_coordinator_event(self, event_type: str, payload: Mapping[str, Any]) -> None:
        coordinator_round = int(payload["coordinator_round"])
        if coordinator_round < 1:
            raise ValueError("coordinator event round must be positive")
        if event_type == "COORDINATOR_ACTION_RECORDED":
            action = _mapping(payload["action"], "coordinator action", required=True)
            self.require_project(str(action["project_id"]))
            self.round_state = {
                **dict(self.round_state),
                "coordinator_round": coordinator_round,
                "last_coordinator_action_id": str(action["action_id"]),
            }
            return
        if event_type == "COORDINATOR_FEEDBACK_RECORDED":
            feedback = _mapping(payload["feedback"], "coordinator feedback", required=True)
            self.failed_hypotheses.append(
                {"coordinator_round": coordinator_round, **feedback}
            )
            question = feedback.get("next_required_action")
            if question and str(question) not in self.unresolved_questions:
                self.unresolved_questions.append(str(question))
            return
        if event_type == "CODEQL_CORROBORATION_RECORDED":
            tool_call = _mapping(payload["tool_call"], "CodeQL tool call", required=True)
            self.require_project(str(tool_call["project_id"]))
            evidence = tuple(
                _mapping(item, "CodeQL evidence", required=True)
                for item in payload.get("evidence_refs", ())
            )
            self._merge_artifacts(self.tool_calls, (tool_call,), "tool_call_id")
            self._merge_artifacts(self.evidence_refs, evidence, "evidence_id")
            arguments = dict(tool_call.get("provenance", {})).get("arguments", {})
            inspected = set(self.inspected_entities)
            if isinstance(arguments, Mapping):
                inspected.update(
                    str(value)
                    for key, value in arguments.items()
                    if key.endswith("entity_id") and value
                )
            self.inspected_entities = sorted(inspected)
            self.round_state = {
                **dict(self.round_state),
                "coordinator_round": coordinator_round,
                "last_codeql_tool_call_id": str(tool_call["tool_call_id"]),
            }
            return
        if event_type in {"PROPOSAL_PENDING", "PROPOSAL_REPAIR_PREPARED"}:
            entry = _mapping(payload["pending_proposal"], "pending proposal", required=True)
            proposal = _mapping(entry["proposal"], "pending proposal payload", required=True)
            proposal_id = str(proposal["proposal_id"])
            existing = {
                str(dict(item["proposal"])["proposal_id"]): dict(item)
                for item in self.pending_proposals
            }
            prior = existing.get(proposal_id)
            if prior is not None and canonical_json(prior) != canonical_json(entry):
                raise ValueError("pending proposal collision with different content")
            if prior is None:
                self.pending_proposals.append(entry)
            return
        if event_type == "GATE_RESULT_RECORDED":
            proposal = _mapping(payload["proposal"], "gated proposal", required=True)
            result = _mapping(payload["gate_result"], "gate result", required=True)
            proposal_id = str(proposal["proposal_id"])
            if str(result["proposal_id"]) != proposal_id:
                raise ValueError("gate result does not match proposal")
            self.pending_proposals = [
                item
                for item in self.pending_proposals
                if str(dict(item["proposal"])["proposal_id"]) != proposal_id
            ]
            gate_record = {
                **result,
                "coordinator_round": coordinator_round,
                "supporting_finding_ids": list(payload["supporting_finding_ids"]),
            }
            self.gate_results.append(gate_record)
            if str(result["status"]) == "ADMISSIBLE" and not any(
                str(item["proposal_id"]) == proposal_id
                for item in self.active_admissible_proposals
            ):
                self.active_admissible_proposals.append(proposal)
            question = payload.get("unresolved_question")
            if question and str(question) not in self.unresolved_questions:
                self.unresolved_questions.append(str(question))
            return
        if event_type == "PATH_REBUILT":
            paths = [
                _mapping(item, "candidate path", required=True)
                for item in payload.get("candidate_paths", ())
            ]
            identities = [str(item["candidate_path_id"]) for item in paths]
            if len(identities) != len(set(identities)):
                raise ValueError("candidate path IDs must be unique")
            self.candidate_paths = paths
            self.round_state = {
                **dict(self.round_state),
                "coordinator_round": coordinator_round,
                "last_path_summary": dict(payload["path_summary"]),
            }
            return
        if event_type == "BUDGET_UPDATED":
            self.budget_state = _mapping(payload["budget_state"], "budget state", required=True)
            self.round_state = {**dict(self.round_state), "coordinator_round": coordinator_round}
            return
        if event_type == "COORDINATOR_STOPPED":
            self.round_state = {
                **dict(self.round_state),
                "coordinator_round": coordinator_round,
                "stopped": True,
                "stop_reason": str(payload["stop_reason"]),
            }
            return
        raise ValueError(f"unsupported coordinator board event type: {event_type}")

    def record_coordinator_event(
        self,
        *,
        event_type: str,
        coordinator_round: int,
        payload: Mapping[str, Any],
    ) -> BoardEvent:
        value = {"coordinator_round": int(coordinator_round), **dict(payload)}
        self._apply_coordinator_event(event_type, value)
        return self._append_event(
            event_type=event_type,
            coordinator_round=coordinator_round,
            specialist_agent=None,
            payload=value,
        )

    @classmethod
    def replay(cls, events: Sequence[BoardEvent | Mapping[str, Any]]) -> "SharedEvidenceBoard":
        parsed = [item if isinstance(item, BoardEvent) else BoardEvent.from_dict(item) for item in events]
        if not parsed or parsed[0].event_type != "BOARD_INITIALIZED":
            raise ValueError("replay requires BOARD_INITIALIZED as the first event")
        for expected_sequence, event in enumerate(parsed, 1):
            if event.sequence != expected_sequence:
                raise ValueError("board event sequence is not contiguous")
        initial = parsed[0]
        payload = initial.payload
        board = cls.create(
            project_id=str(payload["project_id"]),
            repository_summary=dict(payload["repository_summary"]),
            codeql_status=dict(payload["codeql_status"]),
            budget_state=dict(payload["budget_state"]),
            round_state=dict(payload["round_state"]),
            unresolved_questions=tuple(str(item) for item in payload["unresolved_questions"]),
        )
        if board.event_log[0].to_dict() != initial.to_dict():
            raise ValueError("initial board event failed deterministic replay")
        for expected in parsed[1:]:
            if expected.event_type == "SPECIALIST_RESULT_MERGED":
                task = SpecialistTaskSpec.from_dict(expected.payload["task"])
                result = SpecialistResult.from_dict(expected.payload["result"])
                actual = board.merge_specialist_result(task, result)
            else:
                actual = board.record_coordinator_event(
                    event_type=expected.event_type,
                    coordinator_round=expected.coordinator_round,
                    payload={
                        key: value
                        for key, value in expected.payload.items()
                        if key != "coordinator_round"
                    },
                )
            if actual.to_dict() != expected.to_dict():
                raise ValueError("board event failed deterministic replay")
        return board

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SharedEvidenceBoard":
        events = [BoardEvent.from_dict(item) for item in value.get("event_log", ())]
        if events:
            replayed = cls.replay(events)
            expected = dict(value)
            if replayed.to_dict() != expected:
                raise ValueError("board snapshot differs from replayed event log")
            return replayed
        raise ValueError("SharedEvidenceBoard snapshot requires a replayable event_log")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "board_id": self.board_id,
            "project_id": self.project_id,
            "repository_summary": dict(self.repository_summary),
            "codeql_status": dict(self.codeql_status),
            "input_findings": [item.to_dict() for item in self.input_findings],
            "effect_findings": [item.to_dict() for item in self.effect_findings],
            "bridge_findings": [item.to_dict() for item in self.bridge_findings],
            "inspected_entities": list(self.inspected_entities),
            "tool_calls": [dict(item) for item in self.tool_calls],
            "evidence_refs": [dict(item) for item in self.evidence_refs],
            "pending_proposals": [dict(item) for item in self.pending_proposals],
            "gate_results": [dict(item) for item in self.gate_results],
            "active_admissible_proposals": [dict(item) for item in self.active_admissible_proposals],
            "candidate_paths": [dict(item) for item in self.candidate_paths],
            "unresolved_questions": list(self.unresolved_questions),
            "failed_hypotheses": [dict(item) for item in self.failed_hypotheses],
            "budget_state": dict(self.budget_state),
            "round_state": dict(self.round_state),
            "agent_states": {
                role.value: self.agent_states[role].to_dict() for role in SpecialistRole
            },
            "event_log": [item.to_dict() for item in self.event_log],
        }
