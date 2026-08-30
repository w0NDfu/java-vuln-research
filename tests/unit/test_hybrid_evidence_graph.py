from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.hybrid_graph import (
    BoundedPathBuilder,
    EvidenceNode,
    HybridEdge,
    HybridEvidenceGraphBuilder,
    NativePathAdapter,
    NodeKind,
    RelationKind,
    SearchLimits,
    SupportClass,
)
from java_vuln_research.work1_agent.hybrid_graph.serialization import file_sha256
from java_vuln_research.work1_agent.hybrid_graph.smoke import run_controlled
from java_vuln_research.work1_agent.hybrid_graph.real_smoke import run_real as run_m5_real
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
from java_vuln_research.work1_agent.proposal.real_smoke import REAL_PROJECT_COHORT, run_real as run_m4_real
from java_vuln_research.work1_agent.proposal.serialization import write_jsonl
from java_vuln_research.work1_agent.repository.entity import ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import build_repository_index


FIXTURE = Path(__file__).parents[1] / "fixtures" / "work1_agent_m4"


@pytest.fixture(scope="module")
def controlled_data():
    entities, evidence, proposals, native = controlled_manual_set(FIXTURE)
    gate = EvidenceGate(repository_root=FIXTURE, entities=entities, evidence_catalog={item.evidence_id: item for item in evidence}, native_relation_ids=native)
    results = gate.evaluate_many(proposals)
    return entities, evidence, proposals, results


@pytest.fixture(scope="module")
def controlled_artifacts(tmp_path_factory):
    root = tmp_path_factory.mktemp("m5-controlled")
    summary = run_controlled(repository_root=FIXTURE, artifact_root=root, git_sha="TEST-SHA")
    return root, summary


def _one(entities, name, kind):
    values = [item for item in entities if item.simple_name == name and item.kind == kind]
    assert len(values) == 1
    return values[0]


def _program_evidence(entity):
    return EvidenceRef.create(
        source_kind=EvidenceSourceKind.PROGRAM_ENTITY,
        entity_ids=[entity.entity_id],
        confidence=EvidenceStrength.DIRECT,
        provenance={"producer": "m5-unit"},
    )


def _proposal(proposal_type, ref, evidence, *, source=None, target=None):
    ids = tuple(dict.fromkeys(item.entity_id for item in (ref, source, target) if item))
    return SecurityProposal.create(
        proposal_type=proposal_type,
        subject=ref,
        source=source,
        target=target,
        scope=ProposalScope(ScopeKind.ENTITY, ids, "TEST"),
        evidence_refs=[evidence.evidence_id],
        reason="M5 unit hypothesis, not a fact.",
        semantic_category="UNKNOWN" if proposal_type in {ProposalType.EXTERNAL_INPUT, ProposalType.SECURITY_EFFECT} else None,
        provenance={"producer": "m5-unit"},
    )


def test_deterministic_node_and_edge_ids(controlled_data):
    entities, _, _, _ = controlled_data
    method = _one(entities, "getState", ProgramEntityKind.METHOD)
    ref = EntityRoleRef(method.entity_id, EntityRole.RETURN)
    by_id = {item.entity_id: item for item in entities}
    first = EvidenceNode.for_entity(project_id="TEST", entity=method, ref=ref, entities=by_id, provenance={"run": 1})
    second = EvidenceNode.for_entity(project_id="TEST", entity=method, ref=ref, entities=by_id, provenance={"run": 2})
    assert first.node_id == second.node_id
    anchor = EvidenceNode.security_anchor(project_id="TEST", node_kind=NodeKind.SECURITY_EFFECT_ROOT, proposal_id="p", provenance={"run": 1})
    edge_a = HybridEdge.create(project_id="TEST", source_node_id=first.node_id, target_node_id=anchor.node_id, relation_kind=RelationKind.SECURITY_EFFECT, support_class=SupportClass.ADMISSIBLE_SEMANTIC_PROPOSAL, evidence_refs=["e"], proposal_id="p", provenance={"run": 1})
    edge_b = HybridEdge.create(project_id="TEST", source_node_id=first.node_id, target_node_id=anchor.node_id, relation_kind=RelationKind.SECURITY_EFFECT, support_class=SupportClass.ADMISSIBLE_SEMANTIC_PROPOSAL, evidence_refs=["e"], proposal_id="p", provenance={"run": 2})
    assert edge_a.edge_id == edge_b.edge_id


def test_graph_serialization_and_schemas(controlled_artifacts):
    root, _ = controlled_artifacts
    jsonschema = pytest.importorskip("jsonschema")
    schema_root = Path(__file__).parents[2] / "schemas"
    node_schema = json.loads((schema_root / "hybrid_evidence_node.schema.json").read_text(encoding="utf-8"))
    edge_schema = json.loads((schema_root / "hybrid_evidence_edge.schema.json").read_text(encoding="utf-8"))
    path_schema = json.loads((schema_root / "hybrid_candidate_path.schema.json").read_text(encoding="utf-8"))
    nodes = [json.loads(line) for line in (root / "graph_nodes.jsonl").read_text(encoding="utf-8").splitlines()]
    edges = [json.loads(line) for line in (root / "graph_edges.jsonl").read_text(encoding="utf-8").splitlines()]
    for value in nodes:
        jsonschema.Draft202012Validator(node_schema).validate(value)
    for value in edges:
        jsonschema.Draft202012Validator(edge_schema).validate(value)
    resolver = jsonschema.RefResolver.from_schema(
        path_schema,
        store={
            "hybrid_evidence_node.schema.json": node_schema,
            "hybrid_evidence_edge.schema.json": edge_schema,
        },
    )
    paths = [json.loads(line) for line in (root / "candidate_paths.jsonl").read_text(encoding="utf-8").splitlines() if '"path_origin":"HYBRID"' in line]
    for value in paths:
        jsonschema.Draft202012Validator(path_schema, resolver=resolver).validate(value)
    assert all("provenance" in item for item in nodes + edges)


def test_proposal_to_edge_and_inactive_proposals(controlled_artifacts, controlled_data):
    root, summary = controlled_artifacts
    edges = [json.loads(line) for line in (root / "graph_edges.jsonl").read_text(encoding="utf-8").splitlines()]
    _, _, proposals, results = controlled_data
    active = {item.proposal_id for item in results if item.status == GateStatus.ADMISSIBLE}
    inactive = {item.proposal_id for item in results if item.status in {GateStatus.REJECTED, GateStatus.NEEDS_MORE_EVIDENCE}} - active
    proposal_edges = [item for item in edges if item["support_class"] == "ADMISSIBLE_SEMANTIC_PROPOSAL"]
    assert proposal_edges and all(item["provenance"]["gate_status"] == "ADMISSIBLE" for item in proposal_edges)
    assert not inactive.intersection({item["proposal_id"] for item in proposal_edges})
    assert summary["scenario_results"]["invalid_proposal_edge_rejected"]
    assert summary["scenario_results"]["needs_more_evidence_inactive"]


def test_already_supported_does_not_duplicate_edge(controlled_data):
    entities, evidence, proposals, results = controlled_data
    already = next(item for item in results if item.status == GateStatus.ALREADY_SUPPORTED)
    proposal = next(item for item in proposals if item.proposal_id == already.proposal_id)
    builder = HybridEvidenceGraphBuilder(project_id="TEST", entities=entities, evidence_catalog={item.evidence_id: item for item in evidence}, proposals=[proposal], gate_results=[already])
    builder.add_proposal_edges()
    assert not builder.build().edges
    assert any(item.code == "ALREADY_SUPPORTED_NOT_DUPLICATED" for item in builder.build().diagnostics)


def test_codeql_and_repository_edge_provenance(controlled_artifacts):
    root, summary = controlled_artifacts
    edges = [json.loads(line) for line in (root / "graph_edges.jsonl").read_text(encoding="utf-8").splitlines()]
    codeql = [item for item in edges if item["relation_kind"] == "CODEQL_DATAFLOW"]
    repository = next(item for item in edges if item["relation_kind"] == "LEXICAL_CALL")
    assert len(codeql) == 2
    assert all(item["support_class"] == "DETERMINISTIC_FACT" for item in codeql)
    assert {item["tool_call_ids"][0] for item in codeql} == {"controlled-codeql-before-semantic", "controlled-codeql-after-semantic"}
    assert repository["support_class"] == "STRUCTURAL_EVIDENCE" and repository["repository_relation_ids"]
    assert summary["codeql_derived_edge_count"] == 2


def test_repository_only_and_codeql_assisted_paths(controlled_artifacts):
    root, summary = controlled_artifacts
    paths = [json.loads(line) for line in (root / "candidate_paths.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    hybrid = [item for item in paths if item.get("path_origin") == "HYBRID"]
    assert any(item["support_summary"]["repository_only_hybrid"] for item in hybrid)
    assert any(
        item["support_summary"]["codeql_edge_count"] >= 2
        and "WRAPPER_FLOW" in {edge["relation_kind"] for edge in item["ordered_edges"]}
        for item in hybrid
    )
    assert summary["repository_only_hybrid_path_count"] >= 1
    assert all(item["unresolved_semantics"] for item in hybrid)


def test_field_framework_callback_paths(controlled_artifacts):
    root, summary = controlled_artifacts
    paths = [json.loads(line) for line in (root / "candidate_paths.jsonl").read_text(encoding="utf-8").splitlines() if "ordered_edges" in line]
    kinds = [{edge["relation_kind"] for edge in item["ordered_edges"]} for item in paths]
    assert any("FIELD_STATE" in item for item in kinds)
    assert any("FRAMEWORK_RELATION" in item for item in kinds)
    assert any("CALLBACK_RELATION" in item for item in kinds)
    assert summary["scenario_results"]["field_state_path"]


def test_cycle_prevention_and_exact_path_dedupe(controlled_artifacts):
    _, summary = controlled_artifacts
    assert summary["cycle_prevention_count"] > 0
    assert summary["deduplicated_path_count"] > 0
    assert summary["search_truncation_count"] == 0


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_depth": 21},
        {"max_paths": 21},
        {"max_nodes_expanded": 10001},
    ],
)
def test_search_hard_ceilings(kwargs):
    with pytest.raises(ValueError):
        SearchLimits(**kwargs)


def test_max_depth_and_nodes_expanded_are_enforced(controlled_data):
    entities, evidence, proposals, results = controlled_data
    builder = HybridEvidenceGraphBuilder(project_id="TEST", entities=entities, evidence_catalog={item.evidence_id: item for item in evidence}, proposals=proposals[:10], gate_results=results[:10])
    builder.add_proposal_edges()
    graph = builder.build()
    result = BoundedPathBuilder(SearchLimits(max_depth=1, max_paths=1, max_nodes_expanded=1)).search(graph)
    assert result.nodes_expanded == 1
    assert result.search_truncation_count >= 1


def test_max_paths_is_enforced_per_anchor_pair(tmp_path):
    run_controlled(
        repository_root=FIXTURE,
        artifact_root=tmp_path,
        git_sha="TEST-SHA",
        search_limits=SearchLimits(max_depth=12, max_paths=1, max_nodes_expanded=10000),
        assert_scenarios=False,
    )
    pair_counts: dict[tuple[str, str], int] = {}
    paths = [json.loads(line) for line in (tmp_path / "candidate_paths.jsonl").read_text(encoding="utf-8").splitlines()]
    for path in (item for item in paths if item.get("path_origin") == "HYBRID"):
        pair = (str(path["input_anchor"]["node_id"]), str(path["effect_anchor"]["node_id"]))
        pair_counts[pair] = pair_counts.get(pair, 0) + 1
    assert pair_counts and max(pair_counts.values()) == 1


def test_subgraph_bounds(controlled_data):
    entities, evidence, proposals, results = controlled_data
    builder = HybridEvidenceGraphBuilder(project_id="TEST", entities=entities, evidence_catalog={item.evidence_id: item for item in evidence}, proposals=proposals[:10], gate_results=results[:10])
    builder.add_proposal_edges()
    graph = builder.build()
    seed = graph.nodes[0].node_id
    subgraph = builder.build_subgraph(seed_node_ids=[seed], max_nodes=1, max_edges=1, max_depth=1)
    assert len(subgraph.nodes) <= 1 and len(subgraph.edges) <= 1


def test_native_path_preservation_is_identity_preserving():
    native = {"candidate_path_id": "native-1", "project_id": "P", "schema_version": 2, "provenance": {"path_origin": "CODEQL_NATIVE"}}
    result = NativePathAdapter.preserve([native])
    assert result[0] is native
    assert result[0] == native


def test_disconnected_anchors_do_not_form_path(controlled_artifacts):
    _, summary = controlled_artifacts
    assert summary["no_candidate_path_cases"] > 0
    assert summary["scenario_results"]["disconnected_anchor_pair_no_path"]


def test_invalid_role_and_cross_repository_edge_rejected(controlled_data):
    entities, evidence, _, _ = controlled_data
    method = _one(entities, "getState", ProgramEntityKind.METHOD)
    ev = _program_evidence(method)
    builder = HybridEvidenceGraphBuilder(project_id="TEST", entities=entities, evidence_catalog={ev.evidence_id: ev})
    assert builder.node_for_ref(EntityRoleRef(method.entity_id, EntityRole.ARGUMENT, 0)) is None
    valid = builder.node_for_ref(EntityRoleRef(method.entity_id, EntityRole.RETURN))
    assert valid is not None
    foreign = EvidenceNode.security_anchor(project_id="OTHER", node_kind=NodeKind.SECURITY_EFFECT_ROOT, proposal_id="p", provenance={"source": "test"})
    builder.nodes[foreign.node_id] = foreign
    assert builder.add_edge(source=valid, target=foreign, relation_kind=RelationKind.LEXICAL_CALL, support_class=SupportClass.STRUCTURAL_EVIDENCE, evidence_refs=[ev.evidence_id], repository_relation_ids=["r"], provenance={"source": "test"}) is None
    assert {item.code for item in builder.diagnostics}.issuperset({"INVALID_ROLE_NODE", "CROSS_REPOSITORY_EDGE"})


def test_unknown_relation_and_empty_provenance_are_diagnosed_not_raised(controlled_data):
    entities, _, _, _ = controlled_data
    method = _one(entities, "getState", ProgramEntityKind.METHOD)
    evidence = _program_evidence(method)
    builder = HybridEvidenceGraphBuilder(project_id="TEST", entities=entities, evidence_catalog={evidence.evidence_id: evidence})
    node = builder.node_for_ref(EntityRoleRef(method.entity_id, EntityRole.RETURN))
    assert node is not None
    assert builder.add_edge(
        source=node,
        target=node,
        relation_kind="UNKNOWN_RELATION",
        support_class=SupportClass.STRUCTURAL_EVIDENCE,
        evidence_refs=[evidence.evidence_id],
        provenance={"source": "test"},
    ) is None
    assert builder.add_edge(
        source=node,
        target=node,
        relation_kind=RelationKind.LEXICAL_CALL,
        support_class=SupportClass.STRUCTURAL_EVIDENCE,
        evidence_refs=[evidence.evidence_id],
        repository_relation_ids=["relation"],
        provenance={},
    ) is None
    assert {item.code for item in builder.diagnostics}.issuperset({"UNKNOWN_RELATION_OR_SUPPORT", "EDGE_PROVENANCE_REQUIRED"})


def test_fabricated_codeql_edge_rejected(controlled_data):
    entities, _, _, _ = controlled_data
    first = _one(entities, "getState", ProgramEntityKind.METHOD)
    second = _one(entities, "getSecondaryState", ProgramEntityKind.METHOD)
    ev = _program_evidence(first)
    builder = HybridEvidenceGraphBuilder(project_id="TEST", entities=entities, evidence_catalog={ev.evidence_id: ev}, tool_artifact_index={"call": {"status": "OK"}})
    edge = builder.add_codeql_relation(source_ref=EntityRoleRef(first.entity_id, EntityRole.RETURN), target_ref=EntityRoleRef(second.entity_id, EntityRole.RETURN), relation_kind=RelationKind.CODEQL_DATAFLOW, evidence_refs=[ev.evidence_id], tool_call_ids=["call"], provenance={"source": "test"})
    assert edge is None
    assert any(item.code == "FABRICATED_CODEQL_EDGE" for item in builder.diagnostics)


def test_codeql_evidence_must_cover_both_edge_endpoints(controlled_data):
    entities, _, _, _ = controlled_data
    first = _one(entities, "getState", ProgramEntityKind.METHOD)
    second = _one(entities, "getSecondaryState", ProgramEntityKind.METHOD)
    evidence = EvidenceRef.create(
        source_kind=EvidenceSourceKind.CODEQL_DATAFLOW,
        entity_ids=[first.entity_id],
        tool_call_id="call",
        result_hash="a" * 64,
        confidence=EvidenceStrength.DIRECT,
        provenance={"producer": "m5-unit", "query_hash": "b" * 64},
    )
    builder = HybridEvidenceGraphBuilder(
        project_id="TEST",
        entities=entities,
        evidence_catalog={evidence.evidence_id: evidence},
        tool_artifact_index={"call": {"status": "OK"}},
    )
    edge = builder.add_codeql_relation(
        source_ref=EntityRoleRef(first.entity_id, EntityRole.RETURN),
        target_ref=EntityRoleRef(second.entity_id, EntityRole.RETURN),
        relation_kind=RelationKind.CODEQL_DATAFLOW,
        evidence_refs=[evidence.evidence_id],
        tool_call_ids=["call"],
        provenance={"source": "test"},
    )
    assert edge is None
    assert any(item.code == "CODEQL_TOOL_EVIDENCE_MISMATCH" for item in builder.diagnostics)


def test_repository_evidence_must_cover_both_edge_endpoints(controlled_data):
    entities, _, _, _ = controlled_data
    first = _one(entities, "getState", ProgramEntityKind.METHOD)
    second = _one(entities, "getSecondaryState", ProgramEntityKind.METHOD)
    evidence = _program_evidence(first)
    builder = HybridEvidenceGraphBuilder(project_id="TEST", entities=entities, evidence_catalog={evidence.evidence_id: evidence})
    edge = builder.add_repository_relation(
        source_ref=EntityRoleRef(first.entity_id, EntityRole.RETURN),
        target_ref=EntityRoleRef(second.entity_id, EntityRole.RETURN),
        relation_kind=RelationKind.LEXICAL_CALL,
        evidence_refs=[evidence.evidence_id],
        repository_relation_ids=["relation"],
        provenance={"source": "test"},
    )
    assert edge is None
    assert any(item.code == "REPOSITORY_EVIDENCE_ENDPOINT_MISMATCH" for item in builder.diagnostics)


def test_admissible_proposal_requires_gate_resolved_evidence(controlled_data):
    entities, evidence, proposals, results = controlled_data
    admitted = next(item for item in results if item.status == GateStatus.ADMISSIBLE)
    proposal = next(item for item in proposals if item.proposal_id == admitted.proposal_id)
    unresolved_result = {**admitted.to_dict(), "resolved_evidence": []}
    builder = HybridEvidenceGraphBuilder(
        project_id="TEST",
        entities=entities,
        evidence_catalog={item.evidence_id: item for item in evidence},
        proposals=[proposal],
        gate_results=[unresolved_result],
    )
    builder.add_proposal_edges()
    assert not builder.build().edges
    assert any(item.code == "PROPOSAL_GATE_EVIDENCE_UNRESOLVED" for item in builder.diagnostics)


@pytest.mark.parametrize(
    ("tool_index", "tool_call_ids", "expected_code"),
    [
        ({"evidence-call": {"status": "FAILED"}}, ["evidence-call"], "CODEQL_TOOL_CALL_NOT_OK"),
        ({"edge-call": {"status": "OK"}}, ["edge-call"], "CODEQL_TOOL_EVIDENCE_MISMATCH"),
    ],
)
def test_codeql_edge_requires_successful_exact_tool_evidence_binding(controlled_data, tool_index, tool_call_ids, expected_code):
    entities, _, _, _ = controlled_data
    first = _one(entities, "getState", ProgramEntityKind.METHOD)
    second = _one(entities, "getSecondaryState", ProgramEntityKind.METHOD)
    evidence = EvidenceRef.create(
        source_kind=EvidenceSourceKind.CODEQL_DATAFLOW,
        entity_ids=[first.entity_id, second.entity_id],
        tool_call_id="evidence-call",
        result_hash="a" * 64,
        confidence=EvidenceStrength.DIRECT,
        provenance={"producer": "m5-unit", "query_hash": "b" * 64},
    )
    builder = HybridEvidenceGraphBuilder(
        project_id="TEST",
        entities=entities,
        evidence_catalog={evidence.evidence_id: evidence},
        tool_artifact_index=tool_index,
    )
    edge = builder.add_codeql_relation(
        source_ref=EntityRoleRef(first.entity_id, EntityRole.RETURN),
        target_ref=EntityRoleRef(second.entity_id, EntityRole.RETURN),
        relation_kind=RelationKind.CODEQL_DATAFLOW,
        evidence_refs=[evidence.evidence_id],
        tool_call_ids=tool_call_ids,
        provenance={"source": "test"},
    )
    assert edge is None
    assert any(item.code == expected_code for item in builder.diagnostics)


def test_artifact_hashes_are_stable(controlled_artifacts, tmp_path):
    root, _ = controlled_artifacts
    first = {name: file_sha256(root / name) for name in ("graph_nodes.jsonl", "graph_edges.jsonl", "candidate_paths.jsonl")}
    other = tmp_path / "rerun"
    run_controlled(repository_root=FIXTURE, artifact_root=other, git_sha="TEST-SHA")
    second = {name: file_sha256(other / name) for name in first}
    assert first == second


def test_no_vulnerability_score_or_route_b_rules():
    root = Path(__file__).parents[2] / "src" / "java_vuln_research" / "work1_agent" / "hybrid_graph"
    text = "\n".join(path.read_text(encoding="utf-8") for path in root.glob("*.py"))
    for forbidden in ("vulnerability_score", "risk_score", "KNOWN_SOURCE_APIS", "KNOWN_SINK_APIS", "DANGEROUS_METHOD_NAMES"):
        assert forbidden not in text


def test_eight_project_real_smoke_driver(tmp_path):
    indexed = build_repository_index(FIXTURE)
    index_root = tmp_path / "indices"
    rows = []
    tool_calls = []
    callables = [item for item in indexed.sorted_entities() if item.kind in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}]
    for position, project_id in enumerate(REAL_PROJECT_COHORT):
        indexed.write_jsonl(index_root / project_id / "entities.jsonl")
        ready = project_id not in {"V002", "V003"}
        rows.append({"project_id": project_id, "source_root": str(FIXTURE), "codeql_db_ready": str(ready).lower(), "source_revision": f"rev-{project_id}"})
        if ready:
            entity = callables[1]
            tool_calls.append({
                "project_id": project_id,
                "entity_id": entity.entity_id,
                "entity_path": entity.repository_relative_path,
                "entity_start_line": entity.start_line,
                "tool_call_id": f"call-{project_id}",
                "tool_name": "codeql_entity_facts",
                "status": "OK",
                "provenance": {"result_hash": f"{position:064x}", "query_hash": "a" * 64, "v11_git_sha": "b" * 40},
            })
    inventory = tmp_path / "inventory.csv"
    with inventory.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["project_id", "source_root", "codeql_db_ready", "source_revision"])
        writer.writeheader()
        writer.writerows(rows)
    calls = tmp_path / "tool_calls.jsonl"
    write_jsonl(calls, tool_calls)
    m4 = tmp_path / "m4"
    run_m4_real(inventory_csv=inventory, index_roots=[index_root], tool_calls_jsonl=calls, artifact_root=m4)
    output = tmp_path / "m5"
    summary = run_m5_real(
        inventory_csv=inventory,
        index_roots=[index_root],
        m3_tool_calls=calls,
        m4_root=m4,
        artifact_root=output,
        git_sha="TEST-SHA",
    )
    assert summary["project_count"] == 8
    assert summary["cohort"] == list(REAL_PROJECT_COHORT)
    assert summary["hybrid_path_count"] >= 8
    assert summary["repository_only_hybrid_path_count"] == summary["hybrid_path_count"]
    assert summary["all_disconnected_negative_pairs_blocked"]
    assert all(item["no_candidate_path_cases"] >= 1 for item in summary["projects"])
    assert all(item["expected_same_anchor_path_constructed"] for item in summary["projects"])
    assert all(item["disconnected_negative_blocked"] for item in summary["projects"])
    assert {item["project_id"] for item in summary["projects"] if not item["codeql_ready"]} == {"V002", "V003"}
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["benchmark_vulnerability_location_patch_cve_cwe_used"] is False
    assert set(manifest["program_entity_index_hashes"]) == set(REAL_PROJECT_COHORT)
