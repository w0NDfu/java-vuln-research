"""Engineering fixtures. These deterministic policies are not benchmark detections."""
import io
import hashlib
import csv
import json

import pytest

from java_vuln_research.work1_agent.dag_harness import (
    AgentTeam, Node, _Run, _read_batch, response_contract_error, run_dag, _execution_order, plan,
)
from java_vuln_research.work1_agent.experiment_policy import RequestJournal
from java_vuln_research.work1_agent.dag_retrieval import StructuralRetrieval
from java_vuln_research.work1_agent.harness import HarnessLimits, ModelTurn
from java_vuln_research.work1_agent.repository.tools import RepositoryTools
from java_vuln_research.work1_agent.proposal.model import canonical_json
from java_vuln_research.work1_agent.graph_rag import CodeQLGraphIndex


def make_run(tmp_path, responses, source_text=None):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Example.java").write_text(
        source_text or "class Example {\n String first(String value) { return value; }\n"
        " String second(String value) { return first(value); }\n}\n",
        encoding="utf-8",
    )
    tools = RepositoryTools.open(source)
    replies = iter(responses)
    policy = lambda context: ModelTurn(next(replies))
    trace = io.StringIO()
    run = _Run(tools, StructuralRetrieval(tools.index.entities, None),
               AgentTeam(policy, policy, policy), HarnessLimits(12, 20), trace,
               "adaptive", 2, repair_protocol=True, agentic_rag=True)
    return run, trace


def test_concatenated_reads_execute_without_another_model_call(tmp_path):
    run, trace = make_run(tmp_path, [])
    case = run.cases["CWE-78"]
    methods = [entity.entity_id for entity in case.entities.values()
               if entity.kind.value == "METHOD"]
    content = "".join(json.dumps({"action": "inspect_entity", "entity_id": entity})
                      for entity in methods)
    run.team = AgentTeam(*(lambda context: ModelTurn(content) for _ in range(3)))
    node = Node("reason:1:CWE-78", "reasoning", (), "CWE-78", 1)
    response = run.ask(node, {"allowed_actions": ["inspect_entity"]})
    assert run.model_calls == 1
    for action in response["read_batch"]:
        assert run.action(node, action)[0] == "SOURCE_READ"
    assert "read_batch_recovered" in trace.getvalue()


def test_one_complete_json_after_preamble_needs_no_model_repair(tmp_path):
    action = {"action": "finish", "outcome": "EVIDENCE_GAP", "reason": "The receiver is not established."}
    run, trace = make_run(tmp_path, ["I will inspect the `receiver`.\n" + json.dumps(action)])
    result = run.ask(Node("reason:1:CWE-78", "reasoning", (), "CWE-78", 1),
                     {"task": "evidence_reasoning", "allowed_actions": ["finish"]})
    assert result == action and run.model_calls == 1
    assert "response_preamble_unwrapped" in trace.getvalue()


def test_preamble_does_not_hide_multiple_json_actions(tmp_path):
    action = {"action": "finish", "outcome": "EVIDENCE_GAP", "reason": "No supported receiver."}
    run, trace = make_run(tmp_path, ["I will inspect. " + json.dumps(action) * 2, json.dumps(action)])
    result = run.ask(Node("reason:1:CWE-78", "reasoning", (), "CWE-78", 1),
                     {"task": "evidence_reasoning", "allowed_actions": ["finish"]})
    assert result == action and run.model_calls == 2
    assert "response_preamble_unwrapped" not in trace.getvalue()


def test_witness_conditions_are_checked_before_final_dispatch():
    action = {"action": "submit_witness_path", "steps": [], "input_category": "HTTP",
              "effect_category": "FILESYSTEM", "conditions": ["x" * 151]}
    context = {"allowed_actions": ["submit_witness_path"], "final_synthesis": True}
    assert "150 characters" in response_contract_error("reasoning", context, action)
    action["conditions"] = ["The handler accepts untrusted requests."]
    assert response_contract_error("reasoning", context, action) is None


@pytest.mark.parametrize("suffix", [
    '{"action":"submit_path","proposals":[]}',
    '{"action":"inspect_entity"',
    ' trailing text',
])
def test_batch_rejects_unsafe_or_incomplete_tail(suffix):
    first = '{"action":"inspect_entity","entity_id":"entity-1"}'
    with pytest.raises(ValueError):
        _read_batch(first + suffix, {"allowed_actions": ["inspect_entity", "submit_path"]})


def test_batch_deduplicates_and_enforces_limit():
    item = '{"action":"inspect_entity","entity_id":"entity-1"}'
    assert len(_read_batch(item * 4, {"allowed_actions": ["inspect_entity"]})) == 1
    assert len(_read_batch(item * 16, {"allowed_actions": ["inspect_entity"]})) == 1
    with pytest.raises(ValueError):
        _read_batch(item * 17, {"allowed_actions": ["inspect_entity"]})
    with pytest.raises(ValueError):
        _read_batch("".join(json.dumps({"action": "inspect_entity", "entity_id": str(i)}) for i in range(5)),
                    {"allowed_actions": ["inspect_entity"]})


def test_case_reference_limit_is_checked_before_dispatch():
    action = {"action": "record_case", "anchor_entity_id": "a",
              "hypothesis": "a concrete hypothesis", "next_question": "missing return",
              "evidence_refs": ["a", "b", "c", "d", "e"]}
    assert "one to four" in response_contract_error(
        "reasoning", {"allowed_actions": ["record_case"]}, action)


def test_transient_search_failure_does_not_poison_query_cache(tmp_path, monkeypatch):
    run, trace = make_run(tmp_path, [])
    case = run.cases["CWE-78"]
    original = case.tools.search_symbols
    calls = 0

    def transient(*args, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("temporary read error")
        return original(*args, **kwargs)

    monkeypatch.setattr(type(case.tools), "search_symbols",
                        lambda self, *a, **kw: transient(*a, **kw))
    node = Node("reason:1:CWE-78", "reasoning", (), "CWE-78", 1)
    action = {"action": "search_symbols", "query": "first"}
    assert run.action(node, action)[0] == "TOOL_ERROR"
    assert run.action(node, action)[0] == "SYMBOLS_FOUND"
    assert calls == 2


def test_verifier_requests_are_validated_and_executed_next_round(tmp_path):
    run, trace = make_run(tmp_path, ['{"queries":[]}'])
    case = run.cases["CWE-78"]
    method = next(e for e in case.entities.values() if e.simple_name == "second" and e.kind.value == "METHOD")
    node = Node("verify:1:CWE-78", "verification", (), "CWE-78", 1)
    request = {"action": "inspect_entity", "entity_id": method.entity_id,
               "start_line": method.start_line, "end_line": method.end_line}
    assert run.queue_retrieval(node, {"retrieval_requests": [request]}) == [request]
    assert not run.queue_retrieval(node, {"retrieval_requests": [{"action": "submit_path"}]})
    run.retrieve(Node("retrieve:2:CWE-78", "retrieval", (), "CWE-78", 2))
    assert "retrieval_task_finished" in trace.getvalue()
    assert any(proof.start_line == method.start_line for proof in case.evidence.values())


def test_adaptive_reasoner_can_finish_without_inventing_an_audit_case(tmp_path):
    run, trace = make_run(tmp_path, ['{"action":"finish"}'])
    run.adaptive_gaps = True
    run.context["CWE-22"] = {"entity_ids": []}
    case = run.cases["CWE-22"]
    method = next(e for e in case.entities.values() if e.kind.value == "METHOD")
    node = Node("reason:1:CWE-22", "reasoning", (), "CWE-22", 1)
    assert run.action(node, {"action": "inspect_entity", "entity_id": method.entity_id})[0] == "SOURCE_READ"
    run.reason(node)
    assert run.model_calls == 1
    assert not run.audit_cases
    assert "reasoner_finished" in trace.getvalue()
    assert "CWE-22" not in run.route(Node("route:1", "router", (), round=1))["active"]


def test_full_dag_rebuilds_state_from_journal_without_duplicate_provider_calls(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Example.java").write_text(
        "class Example { public String value(String input) { return input; } }\n")

    class Chat:
        endpoint = "https://example.test"
        model = "gpt-6.1-sol"
        max_output_tokens = 100
        calls = 0

        def __init__(self, role):
            self.system_prompt = role

        def __call__(self, context):
            Chat.calls += 1
            action = {"queries": []} if context["role"] == "discovery" else {"action": "finish"}
            return ModelTurn(json.dumps(action), {"total_tokens": 100})

    path = tmp_path / "journal.jsonl"
    for attempt in range(2):
        journal = RequestJournal(path, max_requests=16, max_tokens=200000, max_seconds=60, binding="same-source")
        team = AgentTeam(**{role: journal.wrap(Chat(role)) for role in ("discovery", "reasoning", "verification")})
        result = run_dag(source, tmp_path / f"attempt-{attempt}", team, repair_protocol=True,
                         adaptive_gaps=True, agentic_rag=True)
        assert result["stop_reason"] == "GRAPH_COMPLETE"
        assert result["candidate_paths"] == 0
    assert Chat.calls == 8
    assert journal.requests == 8
    events = [json.loads(row) for row in (tmp_path / "attempt-1/trace.jsonl").read_text().splitlines()]
    finished = [row["node"] for row in events if row["event"] == "node_finished"]
    assert finished.index("verify:1:CWE-22") < finished.index("reason:1:CWE-78")
    for event in events:
        if event["event"] == "model_input":
            assert event["context"]["role"] == event["role"]
            assert hashlib.sha256(canonical_json(event["context"]).encode("utf-8")).hexdigest() == event["context_sha256"]


def test_discovery_hypotheses_select_real_source_before_generic_queries(tmp_path):
    run, trace = make_run(tmp_path, [])
    case = run.cases["CWE-79"]
    method = next(e for e in case.entities.values() if e.kind.value == "METHOD")
    hypothesis = {"anchor_entity_id": method.entity_id, "hypothesis": "Returned input may reach an HTML output.",
                  "evidence_question": "Which caller establishes the browser output context?"}
    run.team = AgentTeam(*(lambda context: ModelTurn(json.dumps({"queries": [], "hypotheses": [hypothesis]}))
                           for _ in range(3)))
    node = Node("discover:CWE-79", "discovery", (), "CWE-79")
    assert run.discover(node)["hypotheses"] == [hypothesis]
    run.retrieve(Node("retrieve:1:CWE-79", "retrieval", (), "CWE-79", 1))
    assert any(method.entity_id in proof.entity_ids for proof in case.evidence.values())
    assert not case.admitted
    forged = {**hypothesis, "anchor_entity_id": "invented"}
    assert response_contract_error("discovery", {"repository_inventory": run.catalogues["CWE-79"]},
                                   {"queries": [], "hypotheses": [forged]})


def test_repeated_reads_stop_with_explicit_stalled_status(tmp_path):
    run, trace = make_run(tmp_path, [])
    run.adaptive_gaps = True
    run.context["CWE-22"] = {"entity_ids": []}
    case = run.cases["CWE-22"]
    method = next(e for e in case.entities.values() if e.kind.value == "METHOD")
    action = {"action": "inspect_entity", "entity_id": method.entity_id}
    run.team = AgentTeam(*(lambda context: ModelTurn(json.dumps(action)) for _ in range(3)))
    node = Node("reason:1:CWE-22", "reasoning", (), "CWE-22", 1)
    run.action(node, action)
    assert run.reason(node)["outcome"] == "RETRIEVAL_STALLED"
    assert run.model_calls == 2
    assert "CWE-22" in run.stalled_branches


def test_scheduler_prioritizes_discovery_leads_and_preserves_dependencies(tmp_path):
    run, trace = make_run(tmp_path, [])
    run.discovery_hypotheses["CWE-79"] = [{"hypothesis": "Unverified source lead."}]
    nodes = plan(2)
    by_id = {node.id: node for node in nodes}
    order = list(_execution_order(nodes, run))
    assert order.index("reason:1:CWE-79") < order.index("reason:1:CWE-22")
    assert order.index("verify:1:CWE-79") < order.index("reason:1:CWE-22")
    visited = set()
    for identity in order:
        assert set(by_id[identity].needs) <= visited
        visited.add(identity)
    assert len(order) == len(visited) == len(nodes)


def test_gate_feedback_identifies_legal_roles_and_scope_without_coercion(tmp_path):
    run, trace = make_run(tmp_path, [])
    case = run.cases["CWE-79"]
    method = next(e for e in case.entities.values() if e.kind.value == "METHOD")
    node = Node("reason:1:CWE-79", "reasoning", (), "CWE-79", 1)
    _, source = run.action(node, {"action": "inspect_entity", "entity_id": method.entity_id})
    action = {"action": "propose", "proposal": {
        "proposal_type": "SECURITY_EFFECT", "subject": {"entity_id": method.entity_id, "role": "CALL_RESULT"},
        "scope": {"kind": "CALLABLE", "entity_ids": [method.entity_id]},
        "evidence_refs": [source["evidence"]["evidence_id"]], "reason": "A source-grounded but invalid endpoint.",
        "semantic_category": "REDIRECT_OR_RESPONSE",
    }}
    status, result = run.action(node, action)
    assert status == "REJECTED"
    options = result["repair_context"]["endpoint_options"][method.entity_id]
    assert any(option["role"] == "RETURN" for option in options)
    assert all(option["role"] != "CALL_RESULT" for option in options)
    assert result["repair_context"]["required_scope_entity_ids"] == [method.entity_id]
    assert not case.admitted
    status, partial = run.action(node, {"action": "submit_path", "proposals": [action["proposal"]]})
    assert status == "INCOMPLETE_PATH"
    assert partial["proposal_feedback"][0]["status"] == "REJECTED"
    assert partial["proposal_feedback"][0]["repair_context"]["endpoint_options"]


def test_stalled_reads_preserve_discovery_hypothesis_for_synthesis(tmp_path):
    run, trace = make_run(tmp_path, [])
    run.adaptive_gaps = True
    run.context["CWE-79"] = {"entity_ids": []}
    case = run.cases["CWE-79"]
    method = next(e for e in case.entities.values() if e.kind.value == "METHOD")
    node = Node("reason:1:CWE-79", "reasoning", (), "CWE-79", 1)
    _, read = run.action(node, {"action": "inspect_entity", "entity_id": method.entity_id})
    run.discovery_hypotheses["CWE-79"] = [{"anchor_entity_id": method.entity_id,
                                         "hypothesis": "An output context is missing."}]

    def policy(context):
        if not context["synthesis_required"]:
            return ModelTurn(json.dumps({"action": "inspect_entity", "entity_id": method.entity_id}))
        return ModelTurn(json.dumps({"action": "record_case", "anchor_entity_id": method.entity_id,
                                     "hypothesis": "An output context is missing.",
                                     "next_question": "Which caller supplies a browser output context?",
                                     "evidence_refs": [read["evidence"]["evidence_id"]]}))

    run.team = AgentTeam(policy, policy, policy)
    run.reason(node)
    assert run.model_calls == 3
    assert "CWE-79" in run.audit_cases


def test_candidate_schema_error_is_repaired_before_semantic_dispatch(tmp_path):
    run, trace = make_run(tmp_path, [])
    case = run.cases["CWE-79"]
    method = next(e for e in case.entities.values() if e.kind.value == "METHOD")
    node = Node("reason:1:CWE-79", "reasoning", (), "CWE-79", 1)
    _, read = run.action(node, {"action": "inspect_entity", "entity_id": method.entity_id})
    draft = {"proposal_type": "SECURITY_EFFECT", "subject": {"entity_id": method.entity_id, "role": "RETURN"},
             "scope": {"kind": "CALLABLE", "entity_ids": [method.entity_id]},
             "evidence_refs": [read["evidence"]["evidence_id"]], "reason": "Source-grounded endpoint hypothesis.",
             "semantic_category": "OTHER"}
    missing = {key: value for key, value in draft.items() if key != "subject"}
    responses = iter(({"action": "propose", "proposal": missing}, {"action": "propose", "proposal": draft}))
    policy = lambda context: ModelTurn(json.dumps(next(responses)))
    run.team = AgentTeam(policy, policy, policy)
    action = run.ask(node, {"allowed_actions": ["propose"]})
    assert run.model_calls == 2
    assert run.protocol_failures["RESPONSE_SCHEMA"] == 1
    assert not case.admitted
    assert run.action(node, action)[0] == "ADMISSIBLE"


def test_missing_program_evidence_does_not_trigger_schema_retry(tmp_path):
    run, trace = make_run(tmp_path, [])
    case = run.cases["CWE-79"]
    method = next(e for e in case.entities.values() if e.kind.value == "METHOD")
    action = {"action": "propose", "proposal": {
        "proposal_type": "SECURITY_EFFECT", "subject": {"entity_id": method.entity_id, "role": "RETURN"},
        "scope": {"kind": "CALLABLE", "entity_ids": [method.entity_id]},
        "evidence_refs": ["evidence-unread"], "reason": "Evidence is not yet available.",
        "semantic_category": "OTHER",
    }}
    run.team = AgentTeam(*(lambda context: ModelTurn(json.dumps(action)) for _ in range(3)))
    node = Node("reason:1:CWE-79", "reasoning", (), "CWE-79", 1)
    assert run.ask(node, {"allowed_actions": ["propose"]}) == action
    assert run.model_calls == 1
    assert not run.protocol_failures
    assert not case.admitted


def test_exhausted_protocol_recovery_is_recorded_as_node_failure(tmp_path):
    run, trace = make_run(tmp_path, ["invalid", "invalid"])
    node = Node("reason:1:CWE-79", "reasoning", (), "CWE-79", 1)
    assert run.ask(node, {"allowed_actions": ["finish"]}) == {}
    assert run.protocol_failed_nodes == {node.id}
    assert run.stopped is None
    assert "protocol_recovery_exhausted" in trace.getvalue()


def test_call_entity_can_access_its_enclosing_method_graph(tmp_path):
    run, trace = make_run(tmp_path, [])
    case = run.cases["CWE-78"]
    lines = (case.tools.index.repository_root / "Example.java").read_text().splitlines()
    path = tmp_path / "graph.csv"
    with path.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["kind", "from_file", "from_line", "from_column", "to_file", "to_line", "to_column"])
        writer.writerow(["CODEQL_CALL", "Example.java", 3, lines[2].index("first") + 1,
                         "Example.java", 2, lines[1].index("first") + 1])
    graph = CodeQLGraphIndex(case.tools.index.repository_root, case.tools.index.entities, path)
    run.retrieval.graph = graph
    call = next(e for e in case.entities.values() if e.kind.value == "CALL" and e.simple_name == "first")
    method = next(e for e in case.entities.values() if e.kind.value == "METHOD" and e.simple_name == "second")
    assert graph.context([call.entity_id]) == graph.context([method.entity_id])
    node = Node("reason:1:CWE-78", "reasoning", (), "CWE-78", 1)
    status, result = run.action(node, {"action": "follow_graph", "entity_id": call.entity_id})
    assert status == "GRAPH_RESULT"
    assert result["relations"]
    assert result["next_offset"] is None


def test_native_report_paths_reach_reasoning_without_report_descriptions(tmp_path):
    run, trace = make_run(tmp_path, [])
    source = run.cases["CWE-79"].tools.index.repository_root
    report = tmp_path / "native.json"
    report.write_text(json.dumps({"vulnerabilities": [{
        "source_scanner": "CodeQL", "description": "ORACLE_METADATA_DO_NOT_SEND", "affected_files": [],
        "tainted_data_flow": [[{"file_path": "Example.java", "line_number": 2},
                               {"file_path": "Example.java", "line_number": 3}]],
    }]}))
    contexts = []

    def policy(context):
        if context["role"] == "discovery":
            return ModelTurn('{"queries":[]}')
        contexts.append(context)
        return ModelTurn('{"action":"finish"}')

    output = tmp_path / "native-run"
    run_dag(source, output, AgentTeam(policy, policy, policy), rounds=1, static_report=report,
            repair_protocol=True, agentic_rag=True, adaptive_gaps=True)
    hints = next(context["native_flow_hints"] for context in contexts if context["cwe"] == "CWE-79")
    assert hints[0]["navigation_only"] is True
    assert [node["line"] for node in hints[0]["nodes"]] == [2, 3]
    assert hints[0]["omitted_nodes"] == 0
    assert "ORACLE_METADATA_DO_NOT_SEND" not in (output / "trace.jsonl").read_text()


def test_zero_native_alerts_preserve_independent_source_exploration(tmp_path):
    run, trace = make_run(tmp_path, [])
    source = run.cases["CWE-79"].tools.index.repository_root
    empty = tmp_path / "empty.json"
    empty.write_text('{"vulnerabilities":[]}')
    observed = []
    for index, report in enumerate((None, empty)):
        contexts = []
        def policy(context):
            contexts.append(context)
            value = {"queries": []} if context["role"] == "discovery" else {"action": "finish"}
            return ModelTurn(json.dumps(value))
        run_dag(source, tmp_path / f"zero-{index}", AgentTeam(policy, policy, policy), rounds=1,
                static_report=report, repair_protocol=True, agentic_rag=True, adaptive_gaps=True)
        observed.append(contexts)
    assert observed[0] == observed[1]
    assert any(context.get("retrieved") for context in observed[1] if context["role"] == "reasoning")


def test_equivalent_parameter_references_form_one_connected_candidate(tmp_path):
    run, trace = make_run(tmp_path, [], source_text=(
        "class Example {\n String first(String value) { return value; }\n"
        " String second(String value) { return first(value); }\n"
        " public static void main(String[] args) { new Example().second(args[0]); }\n}\n"
    ))
    case = run.cases["CWE-79"]
    method = next(e for e in case.entities.values() if e.kind.value == "METHOD" and e.simple_name == "first")
    parameter = next(e for e in case.entities.values()
                     if e.kind.value == "PARAMETER" and e.start_line == method.start_line)
    node = Node("reason:1:CWE-79", "reasoning", (), "CWE-79", 1)
    _, parameter_source = run.action(node, {"action": "inspect_entity", "entity_id": parameter.entity_id})
    _, method_source = run.action(node, {"action": "inspect_entity", "entity_id": method.entity_id})
    param_ref = {"entity_id": parameter.entity_id, "role": "PARAMETER", "index": 0}
    method_param = {"entity_id": method.entity_id, "role": "PARAMETER", "index": 0}
    returned = {"entity_id": method.entity_id, "role": "RETURN"}
    proofs = [method_source["evidence"]["evidence_id"]]
    proposals = [
        {"proposal_type": "EXTERNAL_INPUT", "subject": param_ref,
         "scope": {"kind": "ENTITY", "entity_ids": [parameter.entity_id]},
         "evidence_refs": [parameter_source["evidence"]["evidence_id"]],
         "reason": "A parameter-boundary hypothesis.", "semantic_category": "OTHER"},
        {"proposal_type": "WRAPPER_FLOW", "subject": {"entity_id": method.entity_id, "role": "METHOD"},
         "source": method_param, "target": returned,
         "scope": {"kind": "CALLABLE", "entity_ids": [method.entity_id]},
         "evidence_refs": proofs, "reason": "The same formal parameter reaches the return."},
        {"proposal_type": "SECURITY_EFFECT", "subject": returned,
         "scope": {"kind": "CALLABLE", "entity_ids": [method.entity_id]},
         "evidence_refs": proofs, "reason": "A return-boundary hypothesis.", "semantic_category": "OTHER"},
    ]
    run.path_sensitive = True
    context = {"allowed_actions": ["submit_path"], "require_conditions": True}
    action = {"action": "submit_path", "proposals": proposals}
    assert "conditions" in response_contract_error("reasoning", context, action)
    for invalid in (None, [], [""], "client uses output"):
        assert run.action(node, {**action, "conditions": invalid})[0] == "INVALID_ACTION"
        assert not case.admitted
        assert not run.path_claims
    conditions = ["A client uses the returned value in an HTML document."]
    assert response_contract_error("reasoning", context, {**action, "conditions": conditions}) is None
    status, result = run.action(node, {**action, "conditions": conditions})
    assert status == "PATH_SUBMITTED"
    assert len(result["candidate_path_ids"]) == 1
    assert len(case.paths().hybrid_paths) == 1
    identity = result["candidate_path_ids"][0]
    assert run.path_claims[("CWE-79", identity)] == {"conditions": conditions}
    entry = next(e for e in case.entities.values() if e.kind.value == "METHOD" and e.simple_name == "main")
    _, entry_source = run.action(node, {"action": "inspect_entity", "entity_id": entry.entity_id})
    entry_ref = entry_source["evidence"]["evidence_id"]
    contexts = []

    def independent_review(context):
        contexts.append(context)
        return ModelTurn(json.dumps({
            "verdict": "UNRESOLVED", "evidence_refs": [entry_ref],
            "reason": "This fixture has no browser output effect.",
            "support": [], "counterevidence": [], "unproven_conditions": ["HTML output effect"],
        }))

    run.team = AgentTeam(independent_review, independent_review, independent_review)
    result = run.verify(Node("verify:1:CWE-79", "verification", (), "CWE-79", 1))
    assert result["reviewed"] == 1
    assert contexts[0]["claim_to_falsify"] == {"conditions": conditions}
    assert entry_ref in contexts[0]["source_evidence"]
    assert "new Example().second" in contexts[0]["source_evidence"][entry_ref]["source"]
    assert run.reviews[("CWE-79", identity)]["verdict"] == "UNRESOLVED"


def test_graph_owner_uses_callable_identity_for_methods_on_one_line(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    text = "class A { void a() {} void b() { a(); } }\n"
    (source / "A.java").write_text(text)
    tools = RepositoryTools.open(source)
    path = tmp_path / "graph.csv"
    with path.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(["kind", "from_file", "from_line", "from_column", "to_file", "to_line", "to_column"])
        writer.writerow(["CODEQL_CALL", "A.java", 1, text.rindex("a()") + 1,
                         "A.java", 1, text.index("a()") + 1])
    graph = CodeQLGraphIndex(source, tools.index.entities, path)
    graph.methods["A.java"].sort(key=lambda entity: entity.simple_name)
    call = next(e for e in tools.index.entities if e.kind.value == "CALL" and e.simple_name == "a")
    method = next(e for e in tools.index.entities if e.kind.value == "METHOD" and e.simple_name == "b")
    assert graph.context([call.entity_id], direction="forward") == graph.context([method.entity_id], direction="forward")
    assert graph.context([call.entity_id], direction="forward")
