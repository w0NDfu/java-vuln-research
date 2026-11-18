import json
from graphlib import TopologicalSorter

import pytest

from java_vuln_research.work1_agent import dag_harness
from java_vuln_research.work1_agent.dag_harness import AgentTeam, plan, run_dag
from java_vuln_research.work1_agent.harness import ModelTurn, SUPPORTED_CWES
from java_vuln_research.work1_agent.repository.tools import RepositoryTools
from test_work1_harness import endpoint, role


def reply(**value):
    return ModelTurn(json.dumps(value))


@pytest.mark.parametrize("review_behavior", ["valid", "forged", "recover", "oversize"])
def test_independent_review_cannot_support_a_path_without_edge_citations(tmp_path, review_behavior, monkeypatch):
    if review_behavior == "oversize":
        monkeypatch.setattr(dag_harness, "_VERIFICATION_BYTES", 1)
    source = tmp_path / "source"
    source.mkdir()
    (source / "Endpoint.java").write_text(
        "class Endpoint {\n"
        "  void consume(String input) throws Exception {\n"
        "    Runtime.getRuntime().exec(input);\n"
        "  }\n"
        "  boolean guard(String value) { return value != null; }\n"
        "}\n"
    )
    entities = RepositoryTools.open(source).index.entities
    method = next(e.entity_id for e in entities if e.kind.value == "METHOD" and e.simple_name == "consume")
    call = next(e.entity_id for e in entities if e.kind.value == "CALL" and e.simple_name == "exec")
    guard = next(e.entity_id for e in entities if e.kind.value == "METHOD" and e.simple_name == "guard")
    reasoning_calls = []

    def reasoning(context):
        if context["cwe"] != "CWE-78" or context["round"] > 1:
            return reply(action="finish")
        refs = {entity_id: proof["evidence_id"] for proof in context["evidence_refs"]
                for entity_id in proof["entity_ids"]}
        for entity_id in (method, call):
            if entity_id not in refs:
                return reply(action="inspect_entity", entity_id=entity_id)
        reasoning_calls.append(context)
        if len(reasoning_calls) == 1:
            return reply(**endpoint("EXTERNAL_INPUT", role(method, "PARAMETER"), "HTTP", [refs[method]]))
        if len(reasoning_calls) == 2:
            return reply(**endpoint("SECURITY_EFFECT", role(call, "ARGUMENT"), "PROCESS_EXECUTION", [refs[call]]))
        return reply(action="propose", proposal={
            "proposal_type": "WRAPPER_FLOW", "subject": {"entity_id": method, "role": "METHOD"},
            "source": role(method, "PARAMETER"), "target": role(call, "ARGUMENT"),
            "scope": {"kind": "CALLABLE", "entity_ids": [method, call]},
            "evidence_refs": [refs[method], refs[call]], "reason": "input is passed to exec",
        })

    def verification(context):
        assert review_behavior != "oversize"
        assert context["cwe"] == "CWE-78"
        assert "admitted_proposals" not in context and "recent_actions" not in context
        refs = list(context["source_evidence"])
        if review_behavior == "recover":
            if context["round"] == 1:
                return reply(verdict="UNRESOLVED", focus_entity_ids=[guard], reason="Read the guard implementation.")
            assert any(guard in proof["location"]["entity_ids"] for proof in context["source_evidence"].values())
        return reply(verdict="SUPPORTED", evidence_refs=refs if review_behavior != "forged" else ["invented-ref"],
                     checks={"input_control": "supported", "value_flow": "supported",
                             "security_effect": "supported", "effective_protection": "absent"})

    report = tmp_path / "static.json"
    report.write_text(json.dumps({"vulnerabilities": [{
        "source_scanner": "CodeQL", "description": "Do not expose static analysis descriptions to the model",
        "affected_files": [{"file_path": "Endpoint.java", "line_numbers": [3]}],
    }]}))
    output = tmp_path / "out"
    result = run_dag(source, output, AgentTeam(lambda context: reply(queries=[]), reasoning, verification),
                     static_report=report, rounds=2 if review_behavior == "recover" else 1)
    assert result["candidate_paths"] == 1
    assert result["verifier_supported"] == int(review_behavior in {"valid", "recover"})
    if review_behavior == "oversize":
        review = json.loads((output / "reviews.jsonl").read_text())
        assert review["verdict"] == "UNRESOLVED" and "byte ceiling" in review["reason"]
    assert result["static_report_sha256"]
    assert result["eligible_for_detection_metric"] is False
    assert "Do not expose static" not in (output / "trace.jsonl").read_text()
    assert result["nodes"]["retrieve:1:CWE-78"]["static_locations"] == 1


@pytest.mark.parametrize("mode", ["adaptive", "fixed"])
def test_topological_dependencies_and_fixed_recovery_control(tmp_path, mode):
    nodes = plan(2)
    order = list(TopologicalSorter({node.id: node.needs for node in nodes}).static_order())
    assert all(order.index(parent) < order.index(node.id) for node in nodes for parent in node.needs)
    source = tmp_path / "source"
    source.mkdir()
    active_calls = []

    def discover(context):
        active_calls.append(context["cwe"])
        return reply(queries=["getParameter"] if context["cwe"] == "CWE-22" else [])

    def reason(context):
        return reply(action="finish")

    result = run_dag(source, tmp_path / "out", AgentTeam(discover, reason, reason), rounds=2, mode=mode)
    assert tuple(active_calls[:4]) == SUPPORTED_CWES
    assert active_calls[4:] == (["CWE-22"] if mode == "adaptive" else [])
    assert result["nodes"]["reason:2:CWE-22"]["status"] == "COMPLETE"
    assert result["nodes"]["reason:2:CWE-78"]["status"] == ("SKIPPED" if mode == "adaptive" else "COMPLETE")


def test_repository_inventory_recovers_empty_symbol_search_without_repeating_it(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "OutputCodec.java").write_text(
        "class OutputCodec {\n String encode(String value) { return value; }\n}\n",
        encoding="utf-8",
    )
    observed = []
    def discover(context):
        assert any(entry["name"] == "encode" for entry in context["repository_inventory"])
        return reply(queries=["MissingServlet"])
    def reason(context):
        if context["cwe"] == "CWE-79":
            observed.extend(context["retrieved"])
        return reply(action="finish")
    out = tmp_path / "out"
    result = run_dag(source, out, AgentTeam(discover, reason, reason), rounds=2)
    assert any(item["entity"]["simple_name"] == "encode" for item in observed)
    assert "REPEATED_QUERY" in (out / "trace.jsonl").read_text()
    assert all(count <= 10 for count in result["branch_tool_calls"].values())


def test_graph_evidence_supports_transfer_but_cannot_establish_boundaries(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Codec.java").write_text(
        "class Codec {\n"
        "  public String encode(String input) {\n"
        "    String value = input;\n"
        "    return value;\n"
        "  }\n"
        "  private String helper(String input) { return input; }\n"
        "}\n",
        encoding="utf-8",
    )
    entities = RepositoryTools.open(source).index.entities
    entry = next(e.entity_id for e in entities if e.kind.value == "METHOD" and e.simple_name == "encode")
    helper = next(e.entity_id for e in entities if e.kind.value == "METHOD" and e.simple_name == "helper")
    parameter = next(e.entity_id for e in entities
                     if e.kind.value == "PARAMETER" and "helper" in e.enclosing_callable)
    graph = tmp_path / "graph.csv"
    graph.write_text(
        "kind,col1,col2,col3,col4,col5,col6\n"
        "CODEQL_LOCAL_FLOW,Codec.java,3,20,Codec.java,4,12\n",
        encoding="utf-8",
    )
    steps = []

    def reason(context):
        if context["cwe"] != "CWE-79":
            return reply(action="finish")
        relation = context["codeql_relation_context"][0]["evidence_id"]
        refs = {entity: proof["evidence_id"] for proof in context["evidence_refs"]
                for entity in proof["entity_ids"]}
        if entry not in refs:
            return reply(action="inspect_entity", entity_id=entry)
        actions = [
            endpoint("EXTERNAL_INPUT", role(helper, "PARAMETER"), "OTHER", [refs[entry]]),
            endpoint("EXTERNAL_INPUT", role(parameter, "PARAMETER"), "OTHER", [refs[entry]]),
            endpoint("EXTERNAL_INPUT", role(entry, "PARAMETER"), "OTHER", [relation]),
            endpoint("EXTERNAL_INPUT", role(entry, "PARAMETER"), "OTHER", [refs[entry]]),
            endpoint("SECURITY_EFFECT", {"entity_id": entry, "role": "RETURN"}, "OTHER", [refs[entry]]),
            {"action": "propose", "proposal": {
                "proposal_type": "WRAPPER_FLOW", "subject": {"entity_id": entry, "role": "METHOD"},
                "source": role(entry, "PARAMETER"), "target": {"entity_id": entry, "role": "RETURN"},
                "scope": {"kind": "CALLABLE", "entity_ids": [entry]},
                "evidence_refs": [refs[entry], relation], "reason": "fixture transfer",
            }},
        ]
        steps.append(context)
        return reply(**actions[len(steps) - 1]) if len(steps) <= len(actions) else reply(action="finish")

    def verify(context):
        assert len(context["codeql_evidence"]) == 1
        assert context["source_evidence"]
        return reply(verdict="SUPPORTED", evidence_refs=list(context["codeql_evidence"]),
                     checks={"input_control": "supported", "value_flow": "supported",
                             "security_effect": "supported", "effective_protection": "absent"})

    output = tmp_path / "out"
    result = run_dag(source, output, AgentTeam(lambda context: reply(queries=["encode"]), reason, verify),
                     static_graph=graph, rounds=1)
    assert result["candidate_paths"] == 1
    assert result["verifier_supported"] == 0
    trace = (output / "trace.jsonl").read_text()
    results = [event for line in trace.splitlines()
               if (event := json.loads(line))["event"] == "action_result"]
    assert sum("PRIVATE_CALLABLE_INPUT" in json.dumps(event["result"]) for event in results) == 2
    assert "CODEQL_RELATION_IS_TRANSFER_SUPPORT_ONLY" in trace
    assert "CODEQL_ASSISTED" in trace
    assert json.loads((output / "reviews.jsonl").read_text())["verdict"] == "UNRESOLVED"


def test_context_ceiling_drops_complete_source_windows(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    java = source / "Codec.java"
    java.write_text("class Codec {\n  String encode(String x) {\n    return x;\n  }\n}\n")
    monkeypatch.setattr(dag_harness, "_CONTEXT_BYTES", 800)
    seen = []

    def reason(context):
        seen.append(context)
        assert len(json.dumps(context, ensure_ascii=False).encode("utf-8")) <= 800
        return reply(action="finish")

    run_dag(source, tmp_path / "out", AgentTeam(lambda ctx: reply(queries=["encode"]), reason, reason), rounds=1)
    assert seen and any(c.get("omitted_source_windows") for c in seen)
    assert all(not c["retrieved"] for c in seen if c.get("omitted_source_windows"))


def test_complete_run_limits_cover_two_full_rounds(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Codec.java").write_text(
        "class Codec {\n String encode(String value) { return value; }\n}\n",
        encoding="utf-8",
    )
    calls = {}

    def discover(context):
        return reply(queries=[f"discovery_{context['round']}_{i}" for i in range(3)])

    def reason(context):
        if context["synthesis_required"]:
            return reply(action="finish")
        key = (context["cwe"], context["round"])
        calls[key] = calls.get(key, 0) + 1
        return reply(action="search_symbols", query=f"reasoning_{context['round']}_{calls[key]}")

    limits = dag_harness.complete_run_limits(2)
    assert (limits.max_turns, limits.max_tool_calls) == (88, 124)
    assert dag_harness.complete_run_limits(3).max_tool_calls == 172
    result = run_dag(source, tmp_path / "out", AgentTeam(discover, reason, reason), rounds=2, limits=limits)
    assert result["stop_reason"] == "GRAPH_COMPLETE"
    assert len(calls) == 8 and all(count == 7 for count in calls.values())
    assert result["model_calls"] == 72 and result["tool_calls"] > 64


@pytest.mark.parametrize("complete_path", [True, False])
def test_case_handoff_and_path_bundle_keep_evidence_distinct(tmp_path, complete_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Codec.java").write_text(
        "class Codec {\n"
        "  public String encode(String input) { return helper(input); }\n"
        "  private String helper(String input) { return input; }\n"
        "}\n", encoding="utf-8",
    )
    entities = RepositoryTools.open(source).index.entities
    entry = next(e.entity_id for e in entities if e.kind.value == "METHOD" and e.simple_name == "encode")
    helper = next(e.entity_id for e in entities if e.kind.value == "METHOD" and e.simple_name == "helper")
    seen = []

    def reason(context):
        if context["cwe"] != "CWE-79":
            return reply(action="finish")
        refs = {entity_id: proof["evidence_id"] for proof in context["evidence_refs"] for entity_id in proof["entity_ids"]}
        if context["round"] == 1:
            if not seen:
                seen.append("repeat")
                assert entry in refs  # Exact declaration is prefetched.
                return reply(action="inspect_entity", entity_id=entry)
            if context["synthesis_required"]:
                return reply(action="record_case", anchor_entity_id=entry, evidence_refs=[refs[entry]],
                             hypothesis="The public result may preserve the value from the input.",
                             next_question="Check the called helper and its return value.")
            return reply(action="finish")
        assert context["audit_case"]["anchor_entity_id"] == entry
        assert "helper" in context["review_gaps"][-1]
        if not complete_path:
            return reply(action="finish")
        if "submitted" in seen:
            return reply(action="finish")
        if helper not in refs:
            return reply(action="inspect_entity", entity_id=helper)
        effect_role = {"entity_id": entry, "role": "RETURN"}
        wrong = {"entity_id": helper, "role": "RETURN"}
        destination = effect_role if "disconnected" in seen else wrong
        seen.append("submitted" if destination == effect_role else "disconnected")
        return reply(action="submit_path", proposals=[
            endpoint("EXTERNAL_INPUT", role(entry, "PARAMETER"), "OTHER", [refs[entry]])["proposal"],
            {"proposal_type": "WRAPPER_FLOW", "subject": {"entity_id": entry, "role": "METHOD"},
             "source": role(entry, "PARAMETER"), "target": destination,
             "scope": {"kind": "CALLABLE", "entity_ids": list(dict.fromkeys([entry, destination["entity_id"]]))},
             "evidence_refs": [refs[entry], refs[helper]], "reason": "Fixture value flow through the helper."},
            endpoint("SECURITY_EFFECT", effect_role, "OTHER", [refs[entry]])["proposal"],
        ])

    def verify(context):
        refs = list(context["source_evidence"])
        if context.get("review_kind") == "partial_case":
            return reply(verdict="SUPPORTED", evidence_refs=refs,
                         reason="Read the helper to close the value transfer.", focus_entity_ids=[helper])
        return reply(verdict="SUPPORTED", evidence_refs=refs,
                     checks={"input_control": "supported", "value_flow": "supported",
                             "security_effect": "supported", "effective_protection": "absent"})

    out = tmp_path / "out"
    result = run_dag(source, out, AgentTeam(lambda ctx: reply(queries=["encode"]), reason, verify),
                     limits=dag_harness.complete_run_limits(2))
    assert result["stop_reason"] == "GRAPH_COMPLETE"
    assert result["candidate_paths"] == result["verifier_supported"] == int(complete_path)
    reviews = [json.loads(line) for line in (out / "case_reviews.jsonl").read_text().splitlines()]
    assert reviews and all(row["verdict"] == "UNRESOLVED" for row in reviews)
    trace = (out / "trace.jsonl").read_text()
    assert "SOURCE_ALREADY_READ" in trace
    if complete_path:
        assert "DISCONNECTED_PATH" in trace and "PATH_SUBMITTED" in trace


@pytest.mark.parametrize("grounded", [True, False])
def test_source_bounds_and_incomplete_path_are_actionable(tmp_path, grounded):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Codec.java").write_text(
        "class Codec {\n  public String encode(String input) {\n"
        + "".join(f"    String temp{i} = input;\n" for i in range(20))
        + "    return input;\n  }\n}\n", encoding="utf-8",
    )
    method = next(e for e in RepositoryTools.open(source).index.entities
                  if e.kind.value == "METHOD" and e.simple_name == "encode")
    first = method.start_line + 14
    requested = method.end_line + 20
    steps = []
    actual = {}

    def reason(context):
        if context["cwe"] != "CWE-79":
            return reply(action="finish")
        steps.append(context)
        n = len(steps)
        if n == 1:
            assert any(w["entity"]["end_line"] == method.end_line for w in context["retrieved"])
        if n in (1, 2):
            return reply(action="inspect_entity", entity_id=method.entity_id, start_line=first, end_line=requested)
        if n == 3:
            cached = context["recent_actions"][0]
            assert cached["status"] == "SOURCE_ALREADY_READ"
            assert cached["window_adjustment"]["used"] == {"start_line": first, "end_line": method.end_line}
            actual["ref"] = cached["evidence_id"]
            return reply(action="inspect_entity", entity_id=method.entity_id, start_line=10, end_line=9)
        if n == 4:
            invalid = context["recent_actions"][0]
            assert invalid["status"] == "INVALID_SOURCE_RANGE"
            assert invalid["valid_range"]["end_line"] == method.end_line
            ref = actual["ref"] if grounded else "fabricated"
            return reply(action="submit_path", proposals=[
                endpoint("EXTERNAL_INPUT", role(method.entity_id, "PARAMETER"), "OTHER", [ref])["proposal"],
                endpoint("SECURITY_EFFECT", {"entity_id": method.entity_id, "role": "RETURN"}, "OTHER", [ref])["proposal"],
            ])
        if n == 5:
            assert context["recent_actions"][0]["status"] == "INCOMPLETE_PATH"
            if grounded:
                assert context["recent_actions"][0]["missing_components"] == ["TRANSFER"]
            else:
                assert context["audit_case"] is None
        return reply(action="finish")

    def verify(context):
        assert grounded and context["review_kind"] == "partial_case"
        return reply(verdict="SUPPORTED", evidence_refs=[actual["ref"]], reason="The fixture lacks a submitted transfer.")

    out = tmp_path / "out"
    result = run_dag(source, out, AgentTeam(lambda ctx: reply(queries=["encode"]), reason, verify), rounds=1)
    assert result["candidate_paths"] == result["verifier_supported"] == 0
    assert result["partial_case_reviews"] == int(grounded)
    assert result["nodes"]["reason:1:CWE-79"]["admitted"] == 0
    events = [json.loads(line) for line in (out / "trace.jsonl").read_text().splitlines()]
    reads = [r for r in events if r["node"] == "reason:1:CWE-79" and r.get("status") == "SOURCE_READ"]
    assert len(reads) == 1 and reads[0]["result"]["evidence"]["end_line"] == method.end_line
    if grounded:
        review = json.loads((out / "case_reviews.jsonl").read_text())
        assert review["verdict"] == "UNRESOLVED"


@pytest.mark.parametrize("include_return_proof", [True, False])
def test_library_contract_and_call_sites_require_return_evidence(tmp_path, include_return_proof):
    source = tmp_path / "source"
    source.mkdir()
    lines = [
        "/** The returned value is safe to embed in an HTML script element. */",
        "class Encoder {",
        "  /** @return embeddable text */",
        "  public String encode(String input) { /* 😀 */ return transform(input); }",
        "  private String transform(String input) { return input; }",
        "}",
    ]
    (source / "Encoder.java").write_text("\n".join(lines) + "\n", encoding="utf-8")
    call_offset = lines[3].index("transform(")
    call = len(lines[3][:call_offset].encode("utf-16-le")) // 2 + 1
    method = lines[3].index("encode(") + 1
    helper = lines[4].index("transform(") + 1
    graph = tmp_path / "graph.csv"
    graph.write_text(
        "kind,col1,col2,col3,col4,col5,col6\n"
        f"CODEQL_CALL,Encoder.java,4,{call},Encoder.java,5,{helper}\n"
        f"CODEQL_RETURN_SITE,Encoder.java,4,{method},Encoder.java,4,{call}\n",
        encoding="utf-8",
    )
    seen = []

    def reason(context):
        if context["cwe"] != "CWE-79":
            return reply(action="finish")
        boundary = context["library_boundary"]
        assert boundary["entry"]["simple_name"] == "encode"
        assert boundary["contract_scope"] == "enclosing_type"
        assert "HTML script element" in boundary["documented_output"]
        assert boundary["call_sites"][0]["from"]["column"] == call
        assert boundary["return_site"]["column"] == call
        entry = boundary["entry"]["entity_id"]
        doc_ref = boundary["contract_evidence_id"]
        assert any(ref["evidence_id"] == doc_ref for ref in context["evidence_refs"])
        if seen:
            return reply(action="finish")
        seen.append(boundary)
        impl_ref = next(ref["evidence_id"] for ref in context["evidence_refs"]
                        if entry in ref["entity_ids"] and ref["start_line"] <= 4 <= ref["end_line"])
        effect = {"entity_id": entry, "role": "RETURN"}
        return reply(action="submit_path", proposals=[
            endpoint("EXTERNAL_INPUT", role(entry, "PARAMETER"), "OTHER", [impl_ref])["proposal"],
            {"proposal_type": "WRAPPER_FLOW", "subject": {"entity_id": entry, "role": "METHOD"},
             "source": role(entry, "PARAMETER"), "target": effect,
             "scope": {"kind": "CALLABLE", "entity_ids": [entry]},
             "evidence_refs": [impl_ref], "reason": "Fixture passes the input to the returned expression."},
            endpoint("SECURITY_EFFECT", effect, "LIBRARY_OUTPUT_CONTRACT",
                     [doc_ref, impl_ref] if include_return_proof else [doc_ref])["proposal"],
        ])

    def verify(context):
        assert include_return_proof and context["review_kind"] == "library_contract_path"
        return reply(verdict="SUPPORTED", evidence_refs=list(context["source_evidence"]),
                     checks={"input_control": "supported", "value_flow": "supported",
                             "security_effect": "supported", "effective_protection": "absent"})

    out = tmp_path / "out"
    result = run_dag(source, out, AgentTeam(lambda ctx: reply(queries=["Encoder.transform"]), reason, verify),
                     static_graph=graph, rounds=1, limits=dag_harness.complete_run_limits(1))
    assert seen and result["candidate_paths"] == int(include_return_proof)
    assert result["verifier_supported"] == 0
    assert result["conditionally_supported"] == int(include_return_proof)
    if not include_return_proof:
        assert "LIBRARY_CONTRACT_REQUIRES_DOCUMENTATION_AND_RETURN_SOURCE" in (out / "trace.jsonl").read_text()
    event = next(json.loads(line) for line in (out / "trace.jsonl").read_text().splitlines()
                 if '"action":"inspect_output_contract"' in line)
    proof = event["result"]["evidence"]
    assert proof["start_line"] == proof["end_line"] == 1
    assert proof["provenance"]["kind"] == "documented_library_output"
