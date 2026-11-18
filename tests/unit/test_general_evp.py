"""General Java fixtures; these policies are not measured benchmark detections."""
import io
import json
import os
import subprocess
import sys

import pytest

from java_vuln_research.work1_agent.dag_harness import AgentTeam, Node, _Run, run_dag, normalize_source_citations, response_contract_error
from java_vuln_research.work1_agent.dag_retrieval import StructuralRetrieval
from java_vuln_research.work1_agent.evidence_chain import EvidenceChain
from java_vuln_research.work1_agent.evp_memory import DataflowFactLedger
from java_vuln_research.work1_agent.graph_rag import CodeQLGraphIndex
from java_vuln_research.work1_agent.harness import HarnessLimits, ModelTurn, SUPPORTED_CWES
from java_vuln_research.work1_agent.repository.tools import RepositoryTools
from java_vuln_research.work1_agent.value_paths import ValuePaths


def make_run(tmp_path, text, rounds=6):
    pytest.importorskip("tree_sitter_java")
    source = tmp_path / "source"
    source.mkdir()
    (source / "Fixture.java").write_text(text, encoding="utf-8")
    tools = RepositoryTools.open(source)
    graph = CodeQLGraphIndex(source, tools.index.entities, None)
    retrieval = StructuralRetrieval(tools.index.entities, None, graph)
    values = ValuePaths(graph)
    def unused(_):
        pytest.fail("This operation must not call a model.")
    stream = io.StringIO()
    runner = _Run(tools, retrieval, AgentTeam(unused, unused, unused), HarnessLimits(40, 100), stream,
                  "adaptive", rounds, repair_protocol=True, path_sensitive=True, agentic_rag=True,
                  value_paths=values, focus_scheduling=True, general_evp=True,
                  request_headroom=lambda: 16)
    return runner, stream


def read_all(runner, cwe="CWE-79"):
    case = runner.cases[cwe]
    node = Node("retrieve:1:" + cwe, "retrieval", (), cwe, 1)
    for method in list(case.entities.values()):
        if method.kind.value in {"METHOD", "CONSTRUCTOR"}:
            runner.action(node, {"action": "inspect_entity", "entity_id": method.entity_id,
                                "start_line": method.start_line, "end_line": min(method.end_line, method.start_line + 39)},
                          prefetch=False)
    return node


def draft(line, expression, role="PROPAGATION", method="handle"):
    return {"file_path": "Fixture.java", "line_start": line, "line_end": line,
            "method_symbol": method, "tracked_variable_or_expr": expression, "step_role": role}


def test_fact_splicing_survives_rotated_windows_and_rejects_forgery_and_cycles(tmp_path):
    runner, stream = make_run(tmp_path, "class Fixture {\n"
        " public void handle(Request request, Response response) {\n"
        '  String value = request.getParameter("x");\n'
        "  String copy = value;\n"
        "  response.write(copy);\n }\n}\n")
    read_all(runner)
    case = runner.cases["CWE-79"]
    checker = EvidenceChain(case, runner.retrieval, runner.value_paths)
    ledger = runner.fact_ledgers["CWE-79"]
    a, b, c = [checker.step(step)[0] for step in [draft(3, "value", "SOURCE"), draft(4, "copy"), draft(5, "copy", "SINK")]]
    ledger.add_checked(a, b, "DIRECT_CALL", "intra_method_hop")
    ledger.add_checked(b, c, "DIRECT_CALL", "intra_method_hop")
    assert len(ledger.context()["connected_partial_chains"]) == 1
    chain = ledger.context()["connected_partial_chains"][0]
    assert len(chain["edge_ids"]) == 2 and chain["source_prefix"] and chain["sink_suffix"]
    with pytest.raises(ValueError, match="hash mismatch"):
        ledger.add_checked(a, c, "DIRECT_CALL", "intra_method_hop", expected_hash="0" * 64)
    with pytest.raises(ValueError, match="cycle"):
        ledger.add_checked(c, a, "DIRECT_CALL", "intra_method_hop")
    context = {"retrieved": [], "value_paths": [], "navigation": {}}
    result = runner.compact_reasoning_context(Node("reason:5:CWE-79", "reasoning", (), "CWE-79", 5), context, [])
    assert len(result["verified_subpaths"]) == 2 and result["connected_partial_chains"]
    assert all(row["status"] == "SOURCE_GROUNDED_PENDING_REVIEW" for row in result["verified_subpaths"])


def test_ast_field_prefetch_ignores_shadowed_local_and_finds_nested_reader(tmp_path):
    runner, stream = make_run(tmp_path, "class Fixture {\n"
        " String stored;\n"
        " public Fixture(String input) { this.stored = input; }\n"
        " class Worker { void run() { write(stored); } }\n"
        " void unrelated() { String stored = \"fixed\"; write(stored); }\n"
        " String read() { String copy = stored; return copy; }\n"
        " void write(String s) {}\n}\n")
    constructor = next(e for e in runner.cases["CWE-79"].entities.values() if e.kind.value == "CONSTRUCTOR")
    node = Node("retrieve:1:CWE-79", "retrieval", (), "CWE-79", 1)
    runner.action(node, {"action": "inspect_entity", "entity_id": constructor.entity_id,
                        "start_line": 3, "end_line": 3}, prefetch=False)
    field = next(iter(runner.state_index.fields.values()))
    hits = runner.state_index.query("stored", field.enclosing_type, "forward")["matches"]
    names = {runner.cases["CWE-79"].entities[h["method_id"]].simple_name for h in hits}
    assert {"run", "read"} <= names and "unrelated" not in names
    assert any(e["event"] == "state_bridge_prefetch" for e in map(json.loads, stream.getvalue().splitlines()))
    assert runner.model_calls == 0
    assert any(proof.start_line <= 4 <= proof.end_line for proof in runner.cases["CWE-79"].evidence.values())


def test_dispatch_is_scoped_to_referenced_class_not_global_run_names(tmp_path):
    runner, _ = make_run(tmp_path, "class Fixture {\n"
        " void execute() { new Worker().run(); }\n"
        " class Worker { void run() {} }\n}\n"
        "class Unrelated { void run() {} }\n")
    hits = runner.state_index.query("run", "Fixture", "forward")["matches"]
    assert hits
    assert all(runner.cases["CWE-79"].entities[h["method_id"]].enclosing_type == "Fixture.Worker" for h in hits)


def test_anonymous_callback_field_read_retains_its_enclosing_source_location(tmp_path):
    runner, _ = make_run(tmp_path, "class Fixture {\n String stored;\n"
        " void schedule(String value) { this.stored = value;\n"
        " Runnable r = new Runnable() { public void run() { write(stored); } };\n"
        " }\n void write(String x) {}\n}\n")
    hits = runner.state_index.query("stored", "Fixture", "forward")["matches"]
    assert any(hit["line"] == 4 and hit.get("callback") == "run" for hit in hits)


def test_unreferenced_interface_implementor_is_not_a_callback_candidate(tmp_path):
    runner, _ = make_run(tmp_path, "interface Work { void run(); }\n"
        "class Fixture { void execute(Work work) { work.run(); } }\n"
        "class Unrelated implements Work { public void run() {} }\n")
    hits = runner.state_index.query("run", "Fixture", "forward")["matches"]
    assert all(hit.get("enclosing_type") == "Work" for hit in hits)


def test_annotation_priors_and_inferred_anchors_refresh_navigation(tmp_path):
    runner, _ = make_run(tmp_path, "class Fixture {\n"
        " @PostMapping public void accept(Request request) { save(request); }\n"
        " void save(Object x) {}\n"
        " void helper(Request request) { startTimer(request); }\n"
        " void startTimer(Object x) {}\n}\n")
    nav = runner.retrieval.branch_navigation("CWE-78")
    assert not nav.sinks
    accept = next(e for e in runner.cases["CWE-78"].entities.values() if e.kind.value == "METHOD" and e.simple_name == "accept")
    assert runner.state_index.source_scores[accept.entity_id] >= 8
    assert accept.entity_id in nav.source_owners
    runner.retrieval.add_inferred_anchors("CWE-22", [accept.entity_id], [])
    assert accept.entity_id in runner.retrieval.branch_navigation("CWE-22").source_ids
    with pytest.raises(ValueError, match="production AST"):
        runner.retrieval.add_inferred_anchors("CWE-22", ["invented"], [])


@pytest.mark.parametrize("confirm", [False, True])
def test_semantic_candidate_triggers_probe_and_requires_condition_confirmation(tmp_path, confirm):
    runner, stream = make_run(tmp_path, "class Fixture {\n"
        " public void entry(Request request) { String x = request.getParameter(\"x\"); }\n"
        "}\n"
        "class Worker {\n"
        " void run(String input) { write(input); }\n"
        " void write(String input) {}\n}\n")
    node = read_all(runner)
    action = {"action": "submit_witness_path", "steps": [draft(2, "request.getParameter", "SOURCE", "entry"),
              draft(5, "write(input)", "SINK", "run")], "input_category": "HTTP", "effect_category": "REDIRECT_OR_RESPONSE",
              "conditions": ["A framework binding passes the request value into the worker."],
              "semantic_bridges": [{"from_callable": "entry", "to_callable": "run", "bridge_type": "FRAMEWORK_CALLBACK",
                 "rationale": "A framework may dispatch this input to the worker.",
                 "testable_condition": "Find binding code passing the same request value to Worker.run."}]}
    status, result = runner.action(node, action)
    assert status == "PATH_SUBMITTED", result
    assert not runner.fact_ledgers["CWE-79"].facts
    def verify(context):
        assert context["targeted_bridge_probe"]["probes"]
        refs = list(context["source_evidence"])
        return ModelTurn(json.dumps({"verdict": "SUPPORTED", "evidence_refs": refs,
            "reason": "Fixture-only independent adjudication.", "support": ["Scripted fixture evidence."],
            "counterevidence": [], "unproven_conditions": [],
            "checks": {"input_control": "supported", "value_flow": "supported", "security_effect": "supported", "effective_protection": "absent"},
            "bridge_checks": {key: {"verdict": "BRIDGE_CONFIRMED", "evidence_refs": refs,
                                      **({"condition_assessment": "CONFIRMED"} if confirm else {})}
                              for key in context["assumed_bridges"]}}))
    runner.team = AgentTeam(runner.team.discovery, runner.team.reasoning, verify)
    runner.verify(Node("verify:1:CWE-79", "verification", (), "CWE-79", 1))
    review = next(iter(runner.reviews.values()))
    assert review["verdict"] == ("SUPPORTED" if confirm else "UNRESOLVED")
    assert review["semantic_bridge_probe_completed"]
    assert sum(e["event"] == "semantic_bridge_probe" for e in map(json.loads, stream.getvalue().splitlines())) == 1
    assert bool(runner.fact_ledgers["CWE-79"].facts) == confirm


def test_dynamic_rounds_prune_dead_branch_and_reallocate_to_growing_slice(tmp_path):
    runner, stream = make_run(tmp_path, "class Fixture {\n"
        " public void handle(Request r, Response out) {\n"
        " String x = r.getParameter(\"x\");\n"
        " String y = x;\n"
        " out.write(y);\n }\n}\n")
    node = read_all(runner)
    runner.seed_dataflow_facts(node)
    assert runner.fact_ledgers["CWE-79"].facts
    runner.active = {"CWE-79", "CWE-78"}
    result = runner.route(Node("route:2", "router", (), round=2))
    assert result["active"] == ["CWE-79"]
    assert result["reasons"]["CWE-78"] == "FROZEN_NO_VIABLE_SINK"
    assert runner.rounds == 6
    assert result["vitality"]["CWE-79"]["confirmed_subpaths_count"] > 0


def test_semantic_bridge_cap_and_missing_source_witness_are_not_relaxed(tmp_path):
    runner, _ = make_run(tmp_path, "class Fixture { public void handle(String value) { write(value); } void write(String value) {} }\n")
    checker = EvidenceChain(runner.cases["CWE-79"], runner.retrieval, runner.value_paths)
    with pytest.raises(ValueError, match="At most two"):
        checker.validate([{}], complete=True, semantic_bridges=[{}] * 3, general_evp=True)
    with pytest.raises(ValueError):
        checker.validate([draft(1, "value", "SOURCE"), draft(1, "write", "SINK")], complete=True,
                         semantic_bridges=[], general_evp=True)


def test_growing_branch_reaches_sixth_round_and_must_submit(tmp_path):
    runner, _ = make_run(tmp_path, "class Fixture {\n public void handle(Request r, Response out) {\n"
        ' String value = r.getParameter("x");\n String a = value;\n String b = a;\n'
        " String c = b;\n String d = c;\n String e = d;\n out.write(e);\n }\n}\n")
    read_all(runner)
    runner.active = {"CWE-79"}
    runner.focus_order = ["CWE-79"]
    checker = EvidenceChain(runner.cases["CWE-79"], runner.retrieval, runner.value_paths)
    source = checker.step(draft(3, "value", "SOURCE"))[0]
    for number in range(2, 6):
        target = checker.step(draft(number + 2, ("a", "b", "c", "d")[number - 2]))[0]
        runner.fact_ledgers["CWE-79"].add_checked(source, target, "DIRECT_CALL", "intra_method_hop")
        result = runner.route(Node(f"route:{number}", "router", (), round=number))
        assert result["active"] == ["CWE-79"]
    def reason(context):
        assert context["round"] == 6 and context["synthesis_required"]
        assert context["allowed_actions"] == ["submit_witness_path"]
        return ModelTurn(json.dumps({"action": "submit_witness_path", "steps": [draft(3, "value", "SOURCE"),
            draft(4, "a"), draft(9, "out.write(e)", "SINK")], "input_category": "HTTP",
            "effect_category": "REDIRECT_OR_RESPONSE", "conditions": ["The handler is externally reachable."]}))
    runner.team = AgentTeam(runner.team.discovery, reason, runner.team.verification)
    result = runner.reason_paths(Node("reason:6:CWE-79", "reasoning", (), "CWE-79", 6))
    assert result["outcome"] == "PATH_SUBMITTED"


def test_candidate_view_is_bounded_without_evicting_facts_or_source(tmp_path):
    runner, _ = make_run(tmp_path, "class Fixture {\n public void handle(Request r, Response out) {\n"
        ' String value = r.getParameter("x");\n String a = value;\n out.write(a);\n }\n}\n')
    node = read_all(runner)
    runner.seed_dataflow_facts(node)
    windows, history, _ = runner.reasoning_sources(node)
    paths = [{"id": f"path-{i}", "ports": [{"entity_id": f"source-{i}"}, {"entity_id": f"sink-{i}"}],
              "source_complete": True} for i in range(158)]
    context = runner.compact_reasoning_context(Node("reason:2:CWE-79", "reasoning", (), "CWE-79", 2),
                                               {"value_paths": paths, "retrieved": windows, "navigation": {}}, history)
    assert len(context["value_paths"]) == 8 and context["value_paths_available"] == 158
    assert context["retrieved"] == windows and context["verified_subpaths"]


def test_evp_does_not_underreserve_a_large_final_request(tmp_path, monkeypatch):
    import java_vuln_research.work1_agent.experiment_policy as policy
    monkeypatch.setattr(policy, "request_reserve", lambda *_: (9000, "fixture"))
    class Chat:
        system_prompt = "JSON"
        max_output_tokens = 4096
        model = "gpt-6.1-sol"
        endpoint = "https://example.test"
        def __call__(self, _):
            pytest.fail("A 9k request cannot consume a 3k admission slot.")
    journal = policy.RequestJournal(tmp_path / "journal.jsonl", max_requests=16, max_tokens=150000,
                                    max_seconds=60, binding="evp", verification_reserve=True)
    journal.tokens = 135000
    with pytest.raises(policy.VerificationReserve):
        journal.wrap(Chat())({"role": "reasoning", "general_evp": True, "final_synthesis": True,
                               "verification_budget": {"pending_verification_count": 0}})
    assert journal.requests == 0 and journal.tokens == 135000


def test_typed_receiver_field_access_does_not_bind_to_same_named_local_field(tmp_path):
    runner, _ = make_run(tmp_path, "class Carrier {\n String data;\n"
        " public Carrier(String input) { this.data = input; }\n}\n"
        "class Reader { String data;\n void execute(Carrier carrier) { write(carrier.data); }\n"
        " void write(String x) {}\n}\n")
    hits = runner.state_index.query("data", "Carrier", "forward")["matches"]
    assert any(hit["line"] == 6 and hit["declaring_type"] == "Carrier" for hit in hits)
    reader_field = next(field for field in runner.state_index.fields.values() if field.enclosing_type == "Reader")
    assert not runner.state_index.accesses[reader_field.entity_id]


def test_line_qualified_citations_require_exact_scope_and_read_bounds():
    context = {"source_evidence": {"evidence-a": {"location": {"start_line": 3}, "source": "line3\nline4"}}}
    action = {"evidence_refs": ["evidence-a:3", "evidence-a:3-4", "evidence-a:5", "invented:3"],
              "bridge_checks": {"hop": {"evidence_refs": ["evidence-a:4"]}}}
    mapping = normalize_source_citations(action, context)
    assert action["evidence_refs"] == ["evidence-a", "evidence-a", "evidence-a:5", "invented:3"]
    assert action["bridge_checks"]["hop"]["evidence_refs"] == ["evidence-a"]
    assert len(mapping) == 3


def test_evp_detailed_static_path_reason_and_conditions_are_admitted():
    context = {"general_evp": True, "allowed_actions": ["submit_bridge"],
               "value_paths": [{"id": "path", "source_complete": True}]}
    action = {"action": "submit_bridge", "path_id": "path", "input_category": "HTTP",
              "effect_category": "REDIRECT_OR_RESPONSE", "conditions": ["x" * 300], "reason": "x" * 800}
    assert response_contract_error("reasoning", context, action) is None
    assert response_contract_error("reasoning", {**context, "general_evp": False}, action)


def test_project_discovery_propagates_evp_text_limits_into_each_branch():
    branches = {cwe: {"queries": [], "hypotheses": []} for cwe in SUPPORTED_CWES}
    branches["CWE-79"]["hypotheses"] = [{"anchor_entity_id": "anchor", "hypothesis": "A concrete source-to-output hypothesis.",
                                          "evidence_question": "x" * 800}]
    context = {"task": "project_discovery", "general_evp": True,
               "inventories": {cwe: [{"entity_id": "anchor"}] for cwe in SUPPORTED_CWES}}
    assert response_contract_error("discovery", context, {"branches": branches}) is None
    assert response_contract_error("discovery", {**context, "general_evp": False}, {"branches": branches})


def test_reasoning_consumes_state_query_matches_as_indexed_entities(tmp_path):
    runner, _ = make_run(tmp_path, "class Fixture {\n String stored;\n"
        " public void handle(Request r, Response out) { stored = r.getParameter(\"x\"); }\n"
        " void run(Response out) { out.write(stored); }\n}\n")
    read_all(runner)
    runner.active = {"CWE-79"}
    calls = []
    def reason(context):
        calls.append(context)
        if len(calls) == 1:
            return ModelTurn(json.dumps({"action": "query_state_and_dispatch_bridge", "symbol": "stored",
                                         "enclosing_type": "Fixture", "direction": "forward"}))
        assert context["recent_actions"][-1]["matches"][0]["simple_name"] == "run"
        return ModelTurn(json.dumps({"action": "finish", "outcome": "EVIDENCE_GAP", "reason": "End of interface regression fixture."}))
    runner.team = AgentTeam(runner.team.discovery, reason, runner.team.verification)
    result = runner.reason_paths(Node("reason:1:CWE-79", "reasoning", (), "CWE-79", 1))
    assert result["outcome"] == "EVIDENCE_GAP" and len(calls) == 2


def test_field_prefetch_is_identical_across_python_hash_seeds(tmp_path):
    runner, _ = make_run(tmp_path, "class Fixture {\n String alpha; String beta; String gamma;\n"
        " public Fixture(String value) {\n this.alpha = value;\n this.beta = value;\n this.gamma = value;\n }\n"
        " String first() { return alpha; }\n String second() { return beta; }\n String third() { return gamma; }\n}\n")
    source = str(runner.cases["CWE-79"].tools.index.repository_root)
    script = r'''
import io,json,sys
from java_vuln_research.work1_agent.dag_harness import AgentTeam,Node,_Run
from java_vuln_research.work1_agent.dag_retrieval import StructuralRetrieval
from java_vuln_research.work1_agent.repository.tools import RepositoryTools
from java_vuln_research.work1_agent.graph_rag import CodeQLGraphIndex
from java_vuln_research.work1_agent.value_paths import ValuePaths
from java_vuln_research.work1_agent.harness import HarnessLimits
tools=RepositoryTools.open(sys.argv[1]);graph=CodeQLGraphIndex(tools.index.repository_root,tools.index.entities,None)
def unused(_):raise AssertionError('No provider calls')
stream=io.StringIO();runner=_Run(tools,StructuralRetrieval(tools.index.entities,None,graph),
 AgentTeam(unused,unused,unused),HarnessLimits(24,64),stream,'adaptive',6,value_paths=ValuePaths(graph),general_evp=True)
method=next(e for e in tools.index.entities if e.kind.value=='CONSTRUCTOR')
runner.action(Node('retrieve:1:CWE-79','retrieval',(),'CWE-79',1),
 {'action':'inspect_entity','entity_id':method.entity_id,'start_line':method.start_line,'end_line':method.end_line},prefetch=False)
print(json.dumps([(e['result']['entity']['simple_name'],e['result']['evidence']['evidence_id'])
 for e in map(json.loads,stream.getvalue().splitlines()) if e['event']=='action_result' and e.get('status')=='SOURCE_READ']))
'''
    outputs = [subprocess.check_output([sys.executable, "-B", "-c", script, source], text=True,
                                      env={**os.environ, "PYTHONHASHSEED": seed}) for seed in ("1", "97")]
    assert outputs[0] == outputs[1]


def test_audit_and_journal_wrappers_preserve_request_estimation_metadata(tmp_path):
    from java_vuln_research.work1_agent.experiment_policy import RequestJournal, audited_policy
    class Chat:
        system_prompt = "JSON only"
        max_output_tokens = 4096
        model = "gpt-6.1-sol"
        endpoint = "https://example.test"
        def __call__(self, _):
            pytest.fail("This test only inspects admission metadata.")
    journal = RequestJournal(tmp_path / "journal.jsonl", max_requests=16, max_tokens=150000,
                             max_seconds=60, binding="wrappers")
    wrapped = audited_policy(journal.wrap(Chat()), lambda **row: None, input_rate=1, output_rate=2)
    for name in ("system_prompt", "max_output_tokens", "model", "endpoint"):
        assert getattr(wrapped, name) == getattr(Chat, name)


def test_first_probe_keeps_raw_source_and_later_round_pins_full_ledger(tmp_path):
    runner, _ = make_run(tmp_path, "class Fixture {\n public void handle(Request r, Response out) {\n"
        ' String value = r.getParameter("x");\n String copy = value;\n out.write(copy);\n }\n}\n')
    node = read_all(runner)
    runner.seed_dataflow_facts(node)
    windows, history, _ = runner.reasoning_sources(node)
    first = runner.compact_reasoning_context(node, {"value_paths": [], "retrieved": windows, "navigation": {}}, history)
    assert first["persistent_fact_count"] > 0 and first["verified_subpaths"] == []
    assert first["retrieved"] == windows
    later = runner.compact_reasoning_context(Node("reason:2:CWE-79", "reasoning", (), "CWE-79", 2),
                                             {"value_paths": [], "retrieved": [], "navigation": {}}, [])
    assert len(later["verified_subpaths"]) == first["persistent_fact_count"]
    assert later["connected_partial_chains"]
