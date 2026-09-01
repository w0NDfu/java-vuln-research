from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from java_vuln_research.work1_agent.agent import (
    ActionType,
    AgentGraphPathAdapter,
    AgentGraphRelation,
    AgentToolResult,
    AgentToolStatus,
    MockLLMClient,
    RepositoryCodeQLToolAdapter,
    RuntimeSecurityBoundary,
    StopReason,
    runtime_roots,
)
from java_vuln_research.work1_agent.hybrid_graph import RelationKind, SupportClass
from java_vuln_research.work1_agent.m8_multiagent import (
    BridgeAgentRuntime,
    CoordinatorRuntime,
    EffectAgentRuntime,
    InputAgentRuntime,
    SharedEvidenceBoard,
    SpecialistRole,
    build_valid_scope,
)
from java_vuln_research.work1_agent.m8_multiagent.prompts import (
    COORDINATOR_PROMPT_VERSION,
    COORDINATOR_SYSTEM_PROMPT,
    prompt_sha256,
)
from java_vuln_research.work1_agent.proposal import (
    EntityRole,
    EntityRoleRef,
    EvidenceGate,
    EvidenceRef,
    EvidenceSourceKind,
    EvidenceStrength,
    GateStatus,
    ProposalScope,
    ProposalType,
    ScopeKind,
    SecurityProposal,
)
from java_vuln_research.work1_agent.proposal.model import stable_digest
from java_vuln_research.work1_agent.repository.entity import ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import build_repository_index


SOURCE = """package demo;
import java.nio.file.Files;
import java.nio.file.Path;
class ControlledPath {
  private String state;
  void entry(String raw) throws Exception { effect(wrap(raw)); }
  String wrap(String value) { return value; }
  void effect(String path) throws Exception { Files.writeString(Path.of(path), "x"); }
  void setState(String value) { this.state = value; }
  String getState() { return this.state; }
}
"""


def _specialist_decision(
    action_type: str,
    *,
    tool_name: str | None = None,
    arguments: dict[str, object] | None = None,
    findings: list[dict[str, object]] | None = None,
    status: str | None = None,
) -> dict[str, object]:
    return {
        "action_type": action_type,
        "tool_name": tool_name,
        "arguments": arguments or {},
        "findings": findings or [],
        "status": status,
        "next_suggested_evidence": [],
        "uncertainty": [],
        "reason": "Collect one bounded role-specific program fact.",
    }


def _coordinator_decision(
    action_type: str,
    *,
    arguments: dict[str, object] | None = None,
    proposal: dict[str, object] | None = None,
    supporting_finding_ids: list[str] | None = None,
    stop_reason: str | None = None,
) -> dict[str, object]:
    return {
        "action_type": action_type,
        "arguments": arguments or {},
        "proposal": proposal,
        "supporting_finding_ids": supporting_finding_ids or [],
        "stop_reason": stop_reason,
        "reason": "Choose one bounded next step from the SharedEvidenceBoard.",
    }


def _dispatch(role: SpecialistRole, entity_id: str, tool: str) -> dict[str, object]:
    return _coordinator_decision(
        {
            SpecialistRole.INPUT: "DISPATCH_INPUT_AGENT",
            SpecialistRole.EFFECT: "DISPATCH_EFFECT_AGENT",
            SpecialistRole.BRIDGE: "DISPATCH_BRIDGE_AGENT",
        }[role],
        arguments={
            "objective": "Find one project-local role-specific candidate.",
            "seed_entity_ids": [entity_id],
            "unresolved_question": "Is there sufficient local program evidence?",
            "allowed_tools": [tool],
        },
    )


def _recent_finding(request, finding_type: str) -> dict[str, object]:
    return next(
        item
        for item in request.observation["evidence_board"]["recent_findings"]
        if item["finding_type"] == finding_type
    )


def _input_responses(method_id: str):
    def submit(request):
        evidence = next(
            item
            for item in request.observation["external_input_context"]["recent_evidence_refs"]
            if method_id in item["entity_ids"]
        )
        return _specialist_decision(
            "SUBMIT_FINDINGS",
            status="FINDINGS",
            findings=[
                {
                    "entity_ids": [method_id],
                    "tool_call_ids": [evidence["tool_call_id"]],
                    "evidence_refs": [evidence["evidence_id"]],
                    "summary": "The controlled entry parameter is externally supplied.",
                    "details": {
                        "role": "PARAMETER",
                        "role_index": 0,
                        "inspected_context": "entry(String raw)",
                        "why_externally_influenced": "The controlled fixture defines the entry boundary.",
                        "recommended_scope": "CALLABLE_LOCAL",
                        "codeql_corroboration": "NOT_ATTEMPTED",
                    },
                    "uncertainties": ["This is a controlled boundary, not a vulnerability claim."],
                }
            ],
        )

    return [
        _specialist_decision(
            "TOOL", tool_name="INSPECT_METHOD", arguments={"entity_id": method_id}
        ),
        submit,
    ]


def _effect_responses(method_id: str):
    def submit(request):
        evidence = next(
            item
            for item in request.observation["security_effect_context"]["recent_evidence_refs"]
            if method_id in item["entity_ids"]
        )
        return _specialist_decision(
            "SUBMIT_FINDINGS",
            status="FINDINGS",
            findings=[
                {
                    "entity_ids": [method_id],
                    "tool_call_ids": [evidence["tool_call_id"]],
                    "evidence_refs": [evidence["evidence_id"]],
                    "summary": "The inspected method performs a filesystem write.",
                    "details": {
                        "role": "PARAMETER",
                        "effect_category": "FILESYSTEM",
                        "semantic_reason": "The method passes its path value to Files.writeString.",
                        "local_code_excerpt_refs": [evidence["evidence_id"]],
                        "unresolved_assumptions": ["Candidate path is not vulnerability confirmation."],
                        "proposed_scope": "CALLABLE_LOCAL",
                        "codeql_corroboration": "NOT_ATTEMPTED",
                    },
                    "uncertainties": ["Protection effectiveness is outside Work1."],
                }
            ],
        )

    return [
        _specialist_decision(
            "TOOL", tool_name="INSPECT_METHOD", arguments={"entity_id": method_id}
        ),
        submit,
    ]


def _wrapper_bridge_responses(method_id: str):
    def submit(request):
        evidence = next(
            item
            for item in request.observation["semantic_bridge_context"]["recent_evidence_refs"]
            if method_id in item["entity_ids"]
        )
        return _specialist_decision(
            "SUBMIT_FINDINGS",
            status="FINDINGS",
            findings=[
                {
                    "entity_ids": [method_id],
                    "tool_call_ids": [evidence["tool_call_id"]],
                    "evidence_refs": [evidence["evidence_id"]],
                    "summary": "One callable-local wrapper handoff is supported.",
                    "details": {
                        "source": {"entity_id": method_id, "role": "PARAMETER", "index": 0},
                        "target": {"entity_id": method_id, "role": "RETURN"},
                        "relation_type": "WRAPPER_FLOW",
                        "exact_local_scope": "CALLABLE_LOCAL",
                        "structural_facts": ["The return expression is the inspected parameter."],
                        "optional_codeql_evidence": [],
                        "unresolved_semantics": [],
                        "minimality_explanation": "One parameter-to-return relation in one method.",
                    },
                    "uncertainties": ["The relation is a Gate candidate, not confirmed truth."],
                }
            ],
        )

    return [
        _specialist_decision(
            "TOOL", tool_name="INSPECT_METHOD", arguments={"entity_id": method_id}
        ),
        submit,
    ]


def _field_bridge_responses(type_id: str, field_id: str):
    def submit(request):
        evidence = next(
            item
            for item in request.observation["semantic_bridge_context"]["recent_evidence_refs"]
            if field_id in item["entity_ids"]
        )
        return _specialist_decision(
            "SUBMIT_FINDINGS",
            status="FINDINGS",
            findings=[
                {
                    "entity_ids": [field_id],
                    "tool_call_ids": [evidence["tool_call_id"]],
                    "evidence_refs": [evidence["evidence_id"]],
                    "summary": "A bounded field-state handoff is structurally present.",
                    "details": {
                        "source": {"entity_id": field_id, "role": "FIELD_WRITE"},
                        "target": {"entity_id": field_id, "role": "FIELD_READ"},
                        "relation_type": "FIELD_STATE",
                        "exact_local_scope": "TYPE_LOCAL",
                        "structural_facts": ["The indexed type owns the field."],
                        "optional_codeql_evidence": [],
                        "unresolved_semantics": ["Object instance identity remains a Work2 concern."],
                        "minimality_explanation": "One field write-to-read relation.",
                    },
                    "uncertainties": ["The relation is not a vulnerability verdict."],
                }
            ],
        )

    return [
        _specialist_decision(
            "TOOL", tool_name="GET_FIELDS", arguments={"entity_id": type_id}
        ),
        submit,
    ]


class ControlledCodeQLAdapter(RepositoryCodeQLToolAdapter):
    def __init__(self, *args, codeql_outcome: AgentToolStatus, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.codeql_outcome = codeql_outcome

    def execute(self, action):
        if action.action_type not in {
            ActionType.CODEQL_ENTITY_FACTS,
            ActionType.CODEQL_CALLERS,
            ActionType.CODEQL_CALLEES,
            ActionType.CODEQL_LOCAL_FLOW,
            ActionType.CODEQL_DATAFLOW_NEIGHBORS,
            ActionType.CODEQL_CFG_NEIGHBORS,
        }:
            return super().execute(action)
        arguments = dict(action.arguments)
        items = (
            ({"entity_id": arguments["entity_id"], "fact": "CONTROLLED_CODEQL_MAPPING"},)
            if self.codeql_outcome is AgentToolStatus.OK
            else ()
        )
        failure = (
            None
            if self.codeql_outcome is AgentToolStatus.OK
            else {
                "reason": "CODEQL_UNAVAILABLE",
                "message": "Controlled CodeQL runtime unavailable; absence is not inferred.",
            }
        )
        identity = {
            "project_id": self.project_id,
            "action_id": action.action_id,
            "status": self.codeql_outcome.value,
        }
        return AgentToolResult(
            tool_call_id=stable_digest("agenttool", identity),
            project_id=self.project_id,
            action_id=action.action_id,
            tool_name=action.action_type.value,
            status=self.codeql_outcome,
            items=items,
            truncated=False,
            warnings=(
                ()
                if self.codeql_outcome is AgentToolStatus.OK
                else ("UNAVAILABLE_IS_NOT_NEGATIVE_EVIDENCE",)
            ),
            failure=failure,
            provenance={
                "bounded": True,
                "arguments": arguments,
                "codeql_unavailable_is_not_absence": True,
            },
            summary={"outcome": self.codeql_outcome.value},
        )


def _environment(
    tmp_path: Path,
    coordinator_responses: list[object],
    *,
    bridge_kind: str = "WRAPPER",
    codeql_ready: bool = False,
    codeql_outcome: AgentToolStatus = AgentToolStatus.UNAVAILABLE,
    mapped_entry: bool = False,
):
    root = tmp_path / "repo"
    source = root / "src" / "ControlledPath.java"
    source.parent.mkdir(parents=True)
    source.write_text(SOURCE, encoding="utf-8")
    index = build_repository_index(root)
    by_name = {
        name: next(
            item
            for item in index.entities
            if item.kind is ProgramEntityKind.METHOD and item.simple_name == name
        )
        for name in ("entry", "wrap", "effect")
    }
    field = next(
        item
        for item in index.entities
        if item.kind is ProgramEntityKind.FIELD and item.simple_name == "state"
    )
    owner_type = next(
        item
        for item in index.entities
        if item.kind is ProgramEntityKind.TYPE and item.simple_name == "ControlledPath"
    )
    if mapped_entry:
        mapped = replace(by_name["entry"], codeql_identity="demo.ControlledPath.entry(String)")
        index.entities[index.entities.index(by_name["entry"])] = mapped
        by_name["entry"] = mapped

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    boundary = RuntimeSecurityBoundary(
        project_id="P",
        repository_identity="controlled@abc",
        allowed_roots=runtime_roots(source_roots=[root], artifact_roots=[artifacts]),
    )
    adapter = ControlledCodeQLAdapter(
        project_id="P",
        repository_index=index,
        security_boundary=boundary,
        codeql_ready=codeql_ready,
        codeql_outcome=codeql_outcome,
    )

    input_ref = EntityRoleRef(by_name["entry"].entity_id, EntityRole.PARAMETER, 0)
    bridge_source = EntityRoleRef(by_name["wrap"].entity_id, EntityRole.PARAMETER, 0)
    bridge_target = EntityRoleRef(by_name["wrap"].entity_id, EntityRole.RETURN)
    effect_ref = EntityRoleRef(by_name["effect"].entity_id, EntityRole.PARAMETER, 0)
    left_evidence = EvidenceRef.create(
        source_kind=EvidenceSourceKind.SOURCE_SNIPPET,
        entity_ids=(input_ref.entity_id, bridge_source.entity_id),
        confidence=EvidenceStrength.DIRECT,
        repository_relative_path=by_name["entry"].repository_relative_path,
        start_line=by_name["entry"].start_line,
        end_line=by_name["entry"].end_line,
        provenance={"producer": "M8_CONTROLLED_FIXTURE", "benchmark_informed": False},
    )
    right_evidence = EvidenceRef.create(
        source_kind=EvidenceSourceKind.SOURCE_SNIPPET,
        entity_ids=(bridge_target.entity_id, effect_ref.entity_id),
        confidence=EvidenceStrength.DIRECT,
        repository_relative_path=by_name["entry"].repository_relative_path,
        start_line=by_name["entry"].start_line,
        end_line=by_name["entry"].end_line,
        provenance={"producer": "M8_CONTROLLED_FIXTURE", "benchmark_informed": False},
    )
    gate = EvidenceGate(
        repository_root=root,
        entities=index.entities,
        evidence_catalog={
            left_evidence.evidence_id: left_evidence,
            right_evidence.evidence_id: right_evidence,
        },
    )
    graph = AgentGraphPathAdapter(
        project_id="P",
        entities=index.entities,
        evidence_gate=gate,
        base_relations=(
            AgentGraphRelation(
                source_ref=input_ref,
                target_ref=bridge_source,
                relation_kind=RelationKind.LEXICAL_CALL,
                support_class=SupportClass.STRUCTURAL_EVIDENCE,
                evidence_refs=(left_evidence.evidence_id,),
                repository_relation_ids=("controlled-entry-wrap",),
                provenance={"producer": "M8_CONTROLLED_FIXTURE", "benchmark_informed": False},
            ),
            AgentGraphRelation(
                source_ref=bridge_target,
                target_ref=effect_ref,
                relation_kind=RelationKind.LEXICAL_CALL,
                support_class=SupportClass.STRUCTURAL_EVIDENCE,
                evidence_refs=(right_evidence.evidence_id,),
                repository_relation_ids=("controlled-wrap-effect",),
                provenance={"producer": "M8_CONTROLLED_FIXTURE", "benchmark_informed": False},
            ),
        ),
        git_sha="CONTROLLED",
    )
    board = SharedEvidenceBoard.create(
        project_id="P",
        repository_summary={
            "project_id": "P",
            "repository_identity": "controlled@abc",
            "java_file_count": 1,
            "program_entity_count": len(index.entities),
        },
        codeql_status={
            "project_id": "P",
            "ready": codeql_ready,
            "status": "READY" if codeql_ready else "UNAVAILABLE",
        },
        budget_state={"coordinator_rounds_remaining": 12},
        round_state={"coordinator_round": 0},
    )
    bridge_responses = (
        _wrapper_bridge_responses(by_name["wrap"].entity_id)
        if bridge_kind == "WRAPPER"
        else _field_bridge_responses(owner_type.entity_id, field.entity_id)
    )
    runtimes = {
        SpecialistRole.INPUT: InputAgentRuntime(
            project_id="P",
            repository_index=index,
            llm_client=MockLLMClient(_input_responses(by_name["entry"].entity_id)),
            tool_adapter=adapter,
        ),
        SpecialistRole.EFFECT: EffectAgentRuntime(
            project_id="P",
            repository_index=index,
            llm_client=MockLLMClient(_effect_responses(by_name["effect"].entity_id)),
            tool_adapter=adapter,
        ),
        SpecialistRole.BRIDGE: BridgeAgentRuntime(
            project_id="P",
            repository_index=index,
            llm_client=MockLLMClient(bridge_responses),
            tool_adapter=adapter,
        ),
    }
    runtime = CoordinatorRuntime(
        project_id="P",
        repository_index=index,
        board=board,
        llm_client=MockLLMClient(coordinator_responses),
        specialist_runtimes=runtimes,
        tool_adapter=adapter,
        evidence_gate=gate,
        graph_path_adapter=graph,
    )
    return SimpleNamespace(
        runtime=runtime,
        board=board,
        index=index,
        methods=by_name,
        field=field,
        owner_type=owner_type,
        input_ref=input_ref,
        effect_ref=effect_ref,
        bridge_source=bridge_source,
        bridge_target=bridge_target,
    )


def _input_proposal_decision(env, *, bad_scope: bool = False, include_codeql: bool = False):
    def decide(request):
        finding = _recent_finding(request, "INPUT_FINDING")
        evidence = list(finding["evidence_refs"])
        if include_codeql:
            evidence.extend(
                item["evidence_id"]
                for item in request.observation["evidence_board"]["recent_evidence_refs"]
                if str(item["source_kind"]).startswith("CODEQL_")
            )
        scope = (
            ProposalScope(ScopeKind.ENTITY, (env.methods["wrap"].entity_id,), "P")
            if bad_scope
            else build_valid_scope(
                env.index,
                project_id="P",
                subject=env.input_ref,
                proposal_type=ProposalType.EXTERNAL_INPUT,
            ).scope
        )
        proposal = SecurityProposal.create(
            proposal_type=ProposalType.EXTERNAL_INPUT,
            subject=env.input_ref,
            scope=scope,
            semantic_category="FRAMEWORK_INPUT",
            evidence_refs=evidence,
            reason="Controlled external-influence hypothesis.",
            provenance={"producer": "CONTROLLED_COORDINATOR"},
        )
        env.last_proposal_id = proposal.proposal_id
        draft = proposal.to_dict()
        draft.pop("proposal_id")
        return _coordinator_decision(
            "SUBMIT_PROPOSAL",
            proposal=draft,
            supporting_finding_ids=[finding["finding_id"]],
        )

    return decide


def _effect_proposal_decision(env):
    def decide(request):
        finding = _recent_finding(request, "EFFECT_FINDING")
        proposal = SecurityProposal.create(
            proposal_type=ProposalType.SECURITY_EFFECT,
            subject=env.effect_ref,
            scope=build_valid_scope(
                env.index,
                project_id="P",
                subject=env.effect_ref,
                proposal_type=ProposalType.SECURITY_EFFECT,
            ).scope,
            semantic_category="FILESYSTEM",
            evidence_refs=finding["evidence_refs"],
            reason="Controlled filesystem-effect hypothesis.",
            provenance={"producer": "CONTROLLED_COORDINATOR"},
        )
        return _coordinator_decision(
            "SUBMIT_PROPOSAL",
            proposal=proposal.to_dict(),
            supporting_finding_ids=[finding["finding_id"]],
        )

    return decide


def _wrapper_proposal_decision(env):
    def decide(request):
        finding = _recent_finding(request, "BRIDGE_FINDING")
        proposal = SecurityProposal.create(
            proposal_type=ProposalType.WRAPPER_FLOW,
            subject=EntityRoleRef(env.methods["wrap"].entity_id, EntityRole.METHOD),
            source=env.bridge_source,
            target=env.bridge_target,
            scope=build_valid_scope(
                env.index,
                project_id="P",
                subject=env.methods["wrap"],
                source=env.bridge_source,
                target=env.bridge_target,
                proposal_type=ProposalType.WRAPPER_FLOW,
            ).scope,
            evidence_refs=finding["evidence_refs"],
            reason="Controlled callable-local wrapper hypothesis.",
            provenance={"producer": "CONTROLLED_COORDINATOR"},
        )
        return _coordinator_decision(
            "SUBMIT_PROPOSAL",
            proposal=proposal.to_dict(),
            supporting_finding_ids=[finding["finding_id"]],
        )

    return decide


def test_a_dispatch_merge_gate_and_candidate_path(tmp_path: Path) -> None:
    responses: list[object] = []
    env = _environment(tmp_path, responses)
    responses.extend(
        [
            _dispatch(SpecialistRole.INPUT, env.methods["entry"].entity_id, "INSPECT_METHOD"),
            _dispatch(SpecialistRole.EFFECT, env.methods["effect"].entity_id, "INSPECT_METHOD"),
            _input_proposal_decision(env),
            _effect_proposal_decision(env),
            _dispatch(SpecialistRole.BRIDGE, env.methods["wrap"].entity_id, "INSPECT_METHOD"),
            _wrapper_proposal_decision(env),
            _coordinator_decision("STOP", stop_reason="PATH_FORMED"),
        ]
    )
    env.runtime.llm_client._responses.extend(responses)

    result = env.runtime.run()

    assert result.stop_reason is StopReason.PATH_FORMED
    assert [run.result.specialist_agent for run in result.specialist_runs] == [
        SpecialistRole.INPUT,
        SpecialistRole.EFFECT,
        SpecialistRole.BRIDGE,
    ]
    assert [item.status for item in result.gate_results] == [
        GateStatus.ADMISSIBLE,
        GateStatus.ADMISSIBLE,
        GateStatus.ADMISSIBLE,
    ]
    assert result.board.candidate_paths
    assert all(
        item["provenance"]["warning"] == "candidate path is not a confirmed vulnerability"
        for item in result.board.candidate_paths
        if item.get("schema_version") == 1
    )
    assert SharedEvidenceBoard.replay(result.board.event_log).to_dict() == result.board.to_dict()
    assert all("benchmark" not in observation.to_dict() for observation in result.observations)


def test_b_scope_reject_helper_repair_and_admission(tmp_path: Path) -> None:
    env = _environment(tmp_path, [])

    def request_scope_repair(_request):
        return _coordinator_decision(
            "REQUEST_SCOPE_REPAIR", arguments={"proposal_id": env.last_proposal_id}
        )

    def submit_repair(request):
        repaired = next(
            item
            for item in request.observation["evidence_board"]["pending_proposals"]
            if item["repair_kind"] == "SCOPE"
        )
        return _coordinator_decision(
            "SUBMIT_PROPOSAL",
            arguments={"proposal_id": repaired["proposal"]["proposal_id"]},
        )

    env.runtime.llm_client._responses.extend(
        [
            _dispatch(SpecialistRole.INPUT, env.methods["entry"].entity_id, "INSPECT_METHOD"),
            _input_proposal_decision(env, bad_scope=True),
            request_scope_repair,
            submit_repair,
            _coordinator_decision("STOP", stop_reason="NO_FURTHER_ACTION"),
        ]
    )

    result = env.runtime.run()

    assert [item.status for item in result.gate_results] == [
        GateStatus.REJECTED,
        GateStatus.ADMISSIBLE,
    ]
    assert "SCOPE_DOES_NOT_BOUND_ALL_ANCHORS" in result.gate_results[0].rejection_reasons
    assert result.scope_repairs_prepared == result.scope_repairs_admitted == 1
    original, repaired = result.proposals
    assert original.subject == repaired.subject
    assert original.evidence_refs == repaired.evidence_refs
    assert original.semantic_category == repaired.semantic_category
    assert repaired.provenance["security_semantics_changed"] is False


def test_c_role_reject_helper_repair_and_admission(tmp_path: Path) -> None:
    env = _environment(tmp_path, [], bridge_kind="FIELD")

    def bad_field_state(request):
        finding = _recent_finding(request, "BRIDGE_FINDING")
        bad_source = EntityRoleRef(env.field.entity_id, EntityRole.ARGUMENT, 0)
        target = EntityRoleRef(env.field.entity_id, EntityRole.FIELD_READ)
        subject = EntityRoleRef(env.field.entity_id, EntityRole.FIELD)
        proposal = SecurityProposal.create(
            proposal_type=ProposalType.FIELD_STATE,
            subject=subject,
            source=bad_source,
            target=target,
            scope=build_valid_scope(
                env.index,
                project_id="P",
                subject=subject,
                source=bad_source,
                target=target,
                proposal_type=ProposalType.FIELD_STATE,
            ).scope,
            evidence_refs=finding["evidence_refs"],
            reason="Controlled field-state hypothesis with an intentionally invalid role.",
            provenance={"producer": "CONTROLLED_COORDINATOR"},
        )
        env.last_proposal_id = proposal.proposal_id
        return _coordinator_decision(
            "SUBMIT_PROPOSAL",
            proposal=proposal.to_dict(),
            supporting_finding_ids=[finding["finding_id"]],
        )

    def submit_repair(request):
        repaired = next(
            item
            for item in request.observation["evidence_board"]["pending_proposals"]
            if item["repair_kind"] == "ROLE"
        )
        return _coordinator_decision(
            "SUBMIT_PROPOSAL",
            arguments={"proposal_id": repaired["proposal"]["proposal_id"]},
        )

    env.runtime.llm_client._responses.extend(
        [
            _dispatch(SpecialistRole.INPUT, env.methods["entry"].entity_id, "INSPECT_METHOD"),
            _dispatch(SpecialistRole.EFFECT, env.methods["effect"].entity_id, "INSPECT_METHOD"),
            _dispatch(SpecialistRole.BRIDGE, env.field.entity_id, "GET_FIELDS"),
            bad_field_state,
            lambda _request: _coordinator_decision(
                "REQUEST_ROLE_REPAIR", arguments={"proposal_id": env.last_proposal_id}
            ),
            submit_repair,
            _coordinator_decision("STOP", stop_reason="NO_FURTHER_ACTION"),
        ]
    )

    result = env.runtime.run()

    assert [item.status for item in result.gate_results] == [
        GateStatus.REJECTED,
        GateStatus.ADMISSIBLE,
    ]
    assert result.role_repairs_prepared == result.role_repairs_admitted == 1
    assert result.proposals[0].source.role is EntityRole.ARGUMENT
    assert result.proposals[1].source.role is EntityRole.FIELD_WRITE
    assert result.proposals[1].subject.role is EntityRole.FIELD
    assert result.proposals[1].target.role is EntityRole.FIELD_READ


def test_d_fixed_codeql_corroboration_enters_proposal_and_path_evidence(tmp_path: Path) -> None:
    env = _environment(
        tmp_path,
        [],
        codeql_ready=True,
        codeql_outcome=AgentToolStatus.OK,
        mapped_entry=True,
    )
    env.runtime.llm_client._responses.extend(
        [
            _dispatch(SpecialistRole.INPUT, env.methods["entry"].entity_id, "INSPECT_METHOD"),
            _coordinator_decision(
                "REQUEST_CODEQL_CORROBORATION",
                arguments={
                    "tool_name": "CODEQL_ENTITY_FACTS",
                    "entity_id": env.methods["entry"].entity_id,
                },
            ),
            _input_proposal_decision(env, include_codeql=True),
            _dispatch(SpecialistRole.EFFECT, env.methods["effect"].entity_id, "INSPECT_METHOD"),
            _effect_proposal_decision(env),
            _dispatch(SpecialistRole.BRIDGE, env.methods["wrap"].entity_id, "INSPECT_METHOD"),
            _wrapper_proposal_decision(env),
            _coordinator_decision("STOP", stop_reason="PATH_FORMED"),
        ]
    )

    result = env.runtime.run()

    assert [item.tool_name for item in result.codeql_results] == ["CODEQL_ENTITY_FACTS"]
    assert result.gate_results[0].status is GateStatus.ADMISSIBLE
    assert result.gate_results[0].provenance["admission_basis"] == "CODEQL_ASSISTED"
    codeql_ids = {
        item["evidence_id"]
        for item in result.board.evidence_refs
        if str(item["source_kind"]).startswith("CODEQL_")
    }
    assert codeql_ids and codeql_ids.issubset(set(result.proposals[0].evidence_refs))
    assert codeql_ids.issubset(
        {item["evidence_id"] for item in result.gate_results[0].resolved_evidence}
    )
    assert result.board.candidate_paths
    assert codeql_ids.issubset(set(result.board.candidate_paths[0]["evidence_refs"]))


def test_e_codeql_unavailable_is_not_negative_and_repository_exploration_continues(
    tmp_path: Path,
) -> None:
    env = _environment(
        tmp_path,
        [],
        codeql_ready=False,
        codeql_outcome=AgentToolStatus.UNAVAILABLE,
        mapped_entry=True,
    )
    env.runtime.llm_client._responses.extend(
        [
            _dispatch(SpecialistRole.INPUT, env.methods["entry"].entity_id, "INSPECT_METHOD"),
            _coordinator_decision(
                "REQUEST_CODEQL_CORROBORATION",
                arguments={
                    "tool_name": "CODEQL_ENTITY_FACTS",
                    "entity_id": env.methods["entry"].entity_id,
                },
            ),
            _input_proposal_decision(env),
            _coordinator_decision("STOP", stop_reason="NO_FURTHER_ACTION"),
        ]
    )

    result = env.runtime.run()

    assert result.codeql_results[0].status is AgentToolStatus.UNAVAILABLE
    assert result.codeql_results[0].warnings == ("UNAVAILABLE_IS_NOT_NEGATIVE_EVIDENCE",)
    assert result.gate_results[0].status is GateStatus.ADMISSIBLE
    assert result.gate_results[0].provenance["admission_basis"] == "REPOSITORY_ONLY"
    assert result.stop_reason is StopReason.NO_FURTHER_ACTION


def test_coordinator_observation_advertises_exact_dispatch_tool_policy(
    tmp_path: Path,
) -> None:
    env = _environment(
        tmp_path,
        [_coordinator_decision("STOP", stop_reason="NO_FURTHER_ACTION")],
    )

    result = env.runtime.run()

    policy = result.observations[0].to_dict()["dispatch_tool_policy"]
    actions = {
        SpecialistRole.INPUT: "DISPATCH_INPUT_AGENT",
        SpecialistRole.EFFECT: "DISPATCH_EFFECT_AGENT",
        SpecialistRole.BRIDGE: "DISPATCH_BRIDGE_AGENT",
    }
    for role, action_type in actions.items():
        entry = policy[action_type]
        assert entry == {
            "specialist_agent": role.value,
            "allowed_tools": sorted(env.runtime.specialist_runtimes[role].allowed_tools),
            "non_empty_subset_required": True,
            "canonical_names_case_sensitive": True,
        }
        assert all(name == ActionType(name).value for name in entry["allowed_tools"])
    assert "SEARCH_CODE" not in policy["DISPATCH_BRIDGE_AGENT"]["allowed_tools"]
    assert "SEARCH_SYMBOLS" not in policy["DISPATCH_BRIDGE_AGENT"]["allowed_tools"]


def test_invalid_dispatch_is_repairable_without_consuming_specialist_budget(
    tmp_path: Path,
) -> None:
    env = _environment(tmp_path, [])
    invalid = _coordinator_decision(
        "DISPATCH_INPUT_AGENT",
        arguments={
            "objective": "Find one project-local external input candidate.",
            "seed_entity_ids": [env.methods["entry"].entity_id],
            "unresolved_question": "Is external influence supported?",
            "allowed_tools": ["NOT_A_CANONICAL_TOOL"],
        },
    )
    valid_tools = ["SEARCH_CODE", "READ_FILE_RANGE", "INSPECT_METHOD"]
    valid = _coordinator_decision(
        "DISPATCH_INPUT_AGENT",
        arguments={
            "objective": "Find one project-local external input candidate.",
            "seed_entity_ids": [env.methods["entry"].entity_id],
            "unresolved_question": "Is external influence supported?",
            "allowed_tools": valid_tools,
        },
    )
    env.runtime.llm_client._responses.extend(
        [invalid, valid, _coordinator_decision("STOP", stop_reason="NO_FURTHER_ACTION")]
    )

    result = env.runtime.run()

    assert len(result.specialist_runs) == 1
    assert result.budget_state["usage"]["dispatches"]["INPUT_AGENT"] == 1
    assert result.specialist_runs[0].observations[0].to_dict()["task"][
        "allowed_tools"
    ] == valid_tools
    assert [item.failure_class for item in result.failures] == [
        "SPECIALIST_TOOL_RESTRICTION"
    ]
    message = result.failures[0].message
    assert "NOT_A_CANONICAL_TOOL" in message
    assert 'invalid=["NOT_A_CANONICAL_TOOL"]' in message
    assert 'allowed=[' in message and '"INSPECT_METHOD"' in message
    assert result.failures[0].details["requested_tools"] == ["NOT_A_CANONICAL_TOOL"]
    assert result.failures[0].details["invalid_tools"] == ["NOT_A_CANONICAL_TOOL"]
    assert result.failures[0].details["specialist_agent"] == "INPUT_AGENT"
    feedback = result.observations[1].to_dict()["evidence_board"][
        "failed_hypotheses"
    ][-1]
    assert feedback["message"] == message
    assert feedback["details"]["requested_tools"] == ["NOT_A_CANONICAL_TOOL"]
    assert feedback["details"]["invalid_tools"] == ["NOT_A_CANONICAL_TOOL"]
    assert feedback["details"]["specialist_agent"] == "INPUT_AGENT"
    assert feedback["next_required_action"] == "DISPATCH_INPUT_AGENT"


def test_coordinator_prompt_is_frozen_and_role_assignment_is_enforced(tmp_path: Path) -> None:
    assert COORDINATOR_PROMPT_VERSION == "M8_COORDINATOR_V3"
    assert "Specialists never chat directly" in COORDINATOR_SYSTEM_PROMPT
    assert "omit proposal_id" in COORDINATOR_SYSTEM_PROMPT
    assert "dispatch_tool_policy[action_type].allowed_tools" in COORDINATOR_SYSTEM_PROMPT
    assert prompt_sha256(COORDINATOR_SYSTEM_PROMPT) == (
        "ca5c7792dbce8ac544912d9a5a04d6053985a3f60ea2e0f9786ef22eeae9916c"
    )

    env = _environment(tmp_path, [])

    class WrongCoordinatorClient:
        config = SimpleNamespace(model_id="claude-sonnet-5")

        def complete(self, request):  # pragma: no cover - constructor rejects first
            raise AssertionError(request)

    with pytest.raises(ValueError, match="frozen role assignment"):
        CoordinatorRuntime(
            project_id="P",
            repository_index=env.index,
            board=env.board,
            llm_client=WrongCoordinatorClient(),
            specialist_runtimes=env.runtime.specialist_runtimes,
            tool_adapter=env.runtime.tool_adapter,
            evidence_gate=env.runtime.evidence_gate,
            graph_path_adapter=env.runtime.graph_path_adapter,
        )
