from __future__ import annotations

from pathlib import Path

from java_vuln_research.work1_agent.agent import (
    ActionType,
    AgentController,
    AgentGraphPathAdapter,
    AgentGraphRelation,
    AgentState,
    MockLLMClient,
    RepositoryCodeQLToolAdapter,
    RuntimeSecurityBoundary,
    StopReason,
    StrictActionParser,
    TraceEventType,
    runtime_roots,
)
from java_vuln_research.work1_agent.hybrid_graph import RelationKind, SearchLimits, SupportClass
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
from java_vuln_research.work1_agent.proposal.smoke import controlled_manual_set
from java_vuln_research.work1_agent.repository.entity import ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import build_repository_index


FIXTURE = Path(__file__).parents[1] / "fixtures" / "work1_agent_m4"


def test_graph_adapter_reuses_m5_builder_and_preserves_native_paths() -> None:
    entities, _, _, _ = controlled_manual_set(FIXTURE)
    method = next(item for item in entities if item.kind is ProgramEntityKind.METHOD and item.simple_name == "customExternalInput")
    call = next(item for item in entities if item.kind is ProgramEntityKind.CALL and item.simple_name == "writeString")
    input_evidence = EvidenceRef.create(
        source_kind=EvidenceSourceKind.PROGRAM_ENTITY,
        entity_ids=[method.entity_id],
        confidence=EvidenceStrength.DIRECT,
        provenance={"producer": "controlled-test"},
    )
    effect_evidence = EvidenceRef.create(
        source_kind=EvidenceSourceKind.PROGRAM_ENTITY,
        entity_ids=[call.entity_id],
        confidence=EvidenceStrength.DIRECT,
        provenance={"producer": "controlled-test"},
    )
    relation_evidence = EvidenceRef.create(
        source_kind=EvidenceSourceKind.REPOSITORY_RELATION,
        entity_ids=[method.entity_id, call.entity_id],
        confidence=EvidenceStrength.STRONG_STRUCTURAL,
        provenance={"producer": "controlled-test", "deterministic_relation": False},
    )
    input_proposal = SecurityProposal.create(
        proposal_type=ProposalType.EXTERNAL_INPUT,
        subject=EntityRoleRef(method.entity_id, EntityRole.RETURN),
        scope=ProposalScope(ScopeKind.ENTITY, (method.entity_id,), "P"),
        semantic_category="UNKNOWN",
        evidence_refs=[input_evidence.evidence_id],
        reason="Controlled input anchor.",
        provenance={"producer": "controlled-test"},
    )
    effect_proposal = SecurityProposal.create(
        proposal_type=ProposalType.SECURITY_EFFECT,
        subject=EntityRoleRef(call.entity_id, EntityRole.ARGUMENT, 0),
        scope=ProposalScope(ScopeKind.ENTITY, (call.entity_id,), "P"),
        semantic_category="UNKNOWN",
        evidence_refs=[effect_evidence.evidence_id],
        reason="Controlled effect anchor.",
        provenance={"producer": "controlled-test"},
    )
    evidence = [input_evidence, effect_evidence, relation_evidence]
    proposals = [input_proposal, effect_proposal]
    gate = EvidenceGate(
        repository_root=FIXTURE,
        entities=entities,
        evidence_catalog={item.evidence_id: item for item in evidence},
    )
    results = gate.evaluate_many(proposals)
    assert all(result.status is GateStatus.ADMISSIBLE for result in results)
    native = {
        "candidate_path_id": "native-controlled-1",
        "project_id": "P",
        "schema_version": 2,
        "provenance": {"path_origin": "CODEQL_NATIVE"},
    }
    adapter = AgentGraphPathAdapter(
        project_id="P",
        entities=entities,
        evidence_gate=gate,
        native_paths=[native],
        base_relations=[
            AgentGraphRelation(
                source_ref=EntityRoleRef(method.entity_id, EntityRole.RETURN),
                target_ref=EntityRoleRef(call.entity_id, EntityRole.ARGUMENT, 0),
                relation_kind=RelationKind.LEXICAL_CALL,
                support_class=SupportClass.STRUCTURAL_EVIDENCE,
                evidence_refs=(relation_evidence.evidence_id,),
                repository_relation_ids=("controlled-lexical-1",),
                provenance={"producer": "controlled-test", "deterministic_relation": False},
            )
        ],
        search_limits=SearchLimits(max_depth=12, max_paths=20, max_nodes_expanded=2000),
        git_sha="TEST-SHA",
    )

    rebuilt = adapter.rebuild(proposals=proposals, gate_results=results)

    assert rebuilt.path_search.native_paths[0] is native
    assert len(rebuilt.path_search.hybrid_paths) >= 1
    assert rebuilt.summary()["search_truncation_count"] == 0
    assert all(path.project_id == "P" for path in rebuilt.path_search.hybrid_paths)
    assert all(path.provenance["warning"] == "candidate path is not a confirmed vulnerability" for path in rebuilt.path_search.hybrid_paths)


def test_graph_adapter_keeps_m5_hard_ceilings() -> None:
    try:
        SearchLimits(max_depth=21)
    except ValueError as error:
        assert "hard ceiling" in str(error)
    else:
        raise AssertionError("M7 must not relax the M5 path ceiling")


def test_controller_returns_new_path_feedback_and_waits_for_explicit_stop(tmp_path: Path) -> None:
    index = build_repository_index(FIXTURE)
    method = next(item for item in index.entities if item.kind is ProgramEntityKind.METHOD and item.simple_name == "customExternalInput")
    call = next(item for item in index.entities if item.kind is ProgramEntityKind.CALL and item.simple_name == "writeString")
    input_evidence = EvidenceRef.create(source_kind=EvidenceSourceKind.PROGRAM_ENTITY, entity_ids=[method.entity_id], confidence=EvidenceStrength.DIRECT, provenance={"producer": "test"})
    effect_evidence = EvidenceRef.create(source_kind=EvidenceSourceKind.PROGRAM_ENTITY, entity_ids=[call.entity_id], confidence=EvidenceStrength.DIRECT, provenance={"producer": "test"})
    relation_evidence = EvidenceRef.create(source_kind=EvidenceSourceKind.REPOSITORY_RELATION, entity_ids=[method.entity_id, call.entity_id], confidence=EvidenceStrength.STRONG_STRUCTURAL, provenance={"producer": "test", "deterministic_relation": False})
    input_proposal = SecurityProposal.create(proposal_type=ProposalType.EXTERNAL_INPUT, subject=EntityRoleRef(method.entity_id, EntityRole.RETURN), scope=ProposalScope(ScopeKind.ENTITY, (method.entity_id,), "P"), semantic_category="UNKNOWN", evidence_refs=[input_evidence.evidence_id], reason="Controlled input.", provenance={"producer": "test"})
    effect_proposal = SecurityProposal.create(proposal_type=ProposalType.SECURITY_EFFECT, subject=EntityRoleRef(call.entity_id, EntityRole.ARGUMENT, 0), scope=ProposalScope(ScopeKind.ENTITY, (call.entity_id,), "P"), semantic_category="UNKNOWN", evidence_refs=[effect_evidence.evidence_id], reason="Controlled effect.", provenance={"producer": "test"})
    gate = EvidenceGate(repository_root=FIXTURE, entities=index.entities, evidence_catalog={item.evidence_id: item for item in (input_evidence, effect_evidence, relation_evidence)})
    relation = AgentGraphRelation(source_ref=EntityRoleRef(method.entity_id, EntityRole.RETURN), target_ref=EntityRoleRef(call.entity_id, EntityRole.ARGUMENT, 0), relation_kind=RelationKind.LEXICAL_CALL, support_class=SupportClass.STRUCTURAL_EVIDENCE, evidence_refs=(relation_evidence.evidence_id,), repository_relation_ids=("controlled-1",), provenance={"producer": "test"})
    graph_adapter = AgentGraphPathAdapter(project_id="P", entities=index.entities, evidence_gate=gate, base_relations=[relation], git_sha="TEST")
    schema_root = Path(__file__).resolve().parents[2] / "schemas"
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    boundary = RuntimeSecurityBoundary(project_id="P", repository_identity="controlled@abc", allowed_roots=runtime_roots(source_roots=[FIXTURE], artifact_roots=[artifacts], schema_roots=[schema_root]))
    tool_adapter = RepositoryCodeQLToolAdapter(project_id="P", repository_index=index, security_boundary=boundary)
    state = AgentState.create(project_id="P", repository_identity="controlled@abc", provenance={"producer": "test"})
    for evidence in (input_evidence, effect_evidence, relation_evidence):
        state.record_evidence(evidence.evidence_id, project_id="P")
    responses = [
        {"action_type": "PROPOSE", "arguments": {}, "proposal": input_proposal.to_dict(), "stop_reason": None, "reason": "Input anchor."},
        {"action_type": "PROPOSE", "arguments": {}, "proposal": effect_proposal.to_dict(), "stop_reason": None, "reason": "Effect anchor."},
        {"action_type": ActionType.STOP.value, "arguments": {}, "proposal": None, "stop_reason": StopReason.PATH_FORMED.value, "reason": "A bounded candidate path formed."},
    ]
    controller = AgentController(state=state, repository_index=index, codeql_status={"project_id": "P", "ready": False}, llm_client=MockLLMClient(responses), parser=StrictActionParser(schema_root), tool_adapter=tool_adapter, evidence_gate=gate, graph_path_adapter=graph_adapter)

    result = controller.run()

    assert result.state.stop_reason is StopReason.PATH_FORMED
    assert len(result.state.active_candidate_path_ids) == 1
    assert result.gate_feedback[1].payload["new_path_ids"]
    assert result.gate_feedback[1].payload["new_connected_anchors"]
    assert result.gate_feedback[1].payload["graph_update_enabled"] is True
    assert any(event.event_type is TraceEventType.PATH_FEEDBACK for event in result.trace.events)
