import csv
import json

import pytest

from java_vuln_research.work1_agent.dag_harness import AgentTeam, run_dag
from java_vuln_research.work1_agent.harness import ModelTurn, SUPPORTED_CWES


def reply(**value):
    return ModelTurn(json.dumps(value))


@pytest.mark.parametrize("method_symbol", ["handle", "handle(Request,Response)"])
def test_witness_chain_without_static_ports_keeps_memory_and_requires_hop_reviews(tmp_path, method_symbol):
    pytest.importorskip("tree_sitter_java")
    source = tmp_path / "source"
    source.mkdir()
    (source / "Fixture.java").write_text(
        "class Fixture {\n"
        "  public void handle(Request r, Response out) {\n"
        '    String value = r.getParameter("value");\n'
        "    String copy = value;\n"
        "    out.write(copy);\n"
        "  }\n"
        "  boolean registered() { return true; }\n"
        "  String contentType() { return \"text/html\"; }\n"
        "}\n")
    from java_vuln_research.work1_agent.repository.tools import RepositoryTools

    helpers = {entity.simple_name: entity.entity_id for entity in RepositoryTools.open(source).index.entities
               if entity.kind.value == "METHOD"}
    def step(line, expr, role):
        return {"file_path": "Fixture.java", "line_start": line, "line_end": line,
                "method_symbol": method_symbol, "tracked_variable_or_expr": expr, "step_role": role}

    steps = [step(3, "r.getParameter", "SOURCE"), step(4, "copy", "PROPAGATION"), step(5, "copy", "SINK")]
    count = 0
    reviews = []

    def discover(_):
        return reply(branches={cwe: {"queries": [], "hypotheses": []} for cwe in SUPPORTED_CWES})

    def reason(context):
        nonlocal count
        if context["cwe"] != "CWE-79":
            return reply(action="finish", outcome="NO_GROUNDED_LEAD", reason="No effect for this branch.")
        assert not context["value_paths"]
        assert context["navigation"]["sinks"][0]["name"] == "write"
        count += 1
        if count == 1:
            return reply(action="submit_witness_path", steps=[steps[0], step(4, "fabricated", "PROPAGATION"), steps[-1]],
                         input_category="HTTP", effect_category="REDIRECT_OR_RESPONSE",
                         conditions=["Handler is reachable."])
        if count == 2:
            assert context["recent_actions"][-1]["status"] == "INVALID_ACTION"
            assert "Fixture.java:4-4" in context["recent_actions"][-1]["error"]
            return reply(action="remember_witness_path", steps=steps[:2],
                         frontier_question=("Where does the copy reach the response? "
                                            "Check the receiver binding and response context. " * 5).strip())
        assert context["exploration_memory"]["Confirmed_Hops"]
        return reply(action="submit_witness_path", steps=steps, input_category="HTTP",
                     effect_category="REDIRECT_OR_RESPONSE", conditions=["Handler is reachable."])

    def verify(context):
        assert len(context["assumed_bridges"]) == 2
        assert context["path"]["steps"][-1]["line_start"] == 5
        refs = list(context["source_evidence"])
        reviews.append(context)
        if len(reviews) <= 2:
            helper = ("registered", "contentType")[len(reviews) - 1]
            return reply(verdict="UNRESOLVED", evidence_refs=refs, reason="Read one more precise context window.",
                         support=[], counterevidence=[], unproven_conditions=[helper],
                         retrieval_requests=[{"action": "inspect_entity", "entity_id": helpers[helper]}],
                         bridge_checks={key: {"verdict": "BRIDGE_UNRESOLVED", "evidence_refs": []}
                                        for key in context["assumed_bridges"]})
        return reply(verdict="SUPPORTED", evidence_refs=refs, reason="Scripted check of the witness chain.",
                     support=["The same value reaches the response."], counterevidence=[], unproven_conditions=[],
                     checks={"input_control": "supported", "value_flow": "supported", "security_effect": "supported",
                             "effective_protection": "absent"},
                     bridge_checks={key: {"verdict": "BRIDGE_CONFIRMED", "evidence_refs": refs}
                                    for key in context["assumed_bridges"]})

    output = tmp_path / "output"
    summary = run_dag(source, output, AgentTeam(discover, reason, verify), source_witness_navigation=True,
                      rounds=1, repair_protocol=True, path_sensitive=True)
    assert summary["candidate_paths"] == summary["verifier_supported"] == 1
    assert len(reviews) == 3
    assert all(any(helpers[helper] in proof["location"]["entity_ids"] for proof in reviews[-1]["source_evidence"].values())
               for helper in ("registered", "contentType"))
    result = json.loads((output / "candidates.jsonl").read_text())
    assert result["provenance"]["producer"] == "source_witness_steps"
    assert all(row["kind"] == "intra_method_hop" for row in result["assumed_bridges"].values())
    checkpoint = json.loads((output / "checkpoint.json").read_text())
    assert not checkpoint["exploration_memory"]["CWE-79"]["Frontier_Questions"]


@pytest.mark.parametrize("confirm", [False, True])
def test_assumed_bridge_needs_independent_confirmation(tmp_path, confirm):
    pytest.importorskip("tree_sitter_java")
    from java_vuln_research.work1_agent.repository.tools import RepositoryTools

    source = tmp_path / "source"
    source.mkdir()
    (source / "Fixture.java").write_text(
        "class Fixture {\n"
        "  public void start(String input) {}\n"
        "  public void accept(String value) {}\n"
        "}\n")
    graph = tmp_path / "graph.csv"
    graph.write_text("kind,left,l,c,right,l,c\n")
    values = tmp_path / "values.csv"
    values.write_text(",".join(map(str, range(17))) + "\n")
    entities = {e.simple_name: e for e in RepositoryTools.open(source).index.entities if e.kind.value == "METHOD"}
    start, accept = (entities[name].entity_id for name in ("start", "accept"))

    def discover(context):
        return reply(branches={cwe: {"queries": [], "hypotheses": [{
            "anchor_entity_id": start, "hypothesis": "Potential external input in the fixture.",
            "evidence_question": "Inspect the dispatch target for this fixture."
        }] if cwe == "CWE-79" else []} for cwe in SUPPORTED_CWES})

    def reason(context):
        reads = {row["entity"]["entity_id"]: row for row in context["retrieved"]}
        if accept not in reads:
            return reply(action="inspect_entity", entity_id=accept)
        assert "propose_assumed_bridge" in context["allowed_actions"]
        first = {"entity_id": start, "role": "PARAMETER", "index": 0}
        last = {"entity_id": accept, "role": "PARAMETER", "index": 0}
        code_witness = {side: {"line": reads[key]["start_line"], "evidence_id": reads[key]["evidence_id"]}
                        for side, key in (("from", start), ("to", accept))}
        proposals = [
            {"proposal_type": kind, "subject": anchor, "semantic_category": category,
             "scope": {"kind": "CALLABLE", "entity_ids": [anchor["entity_id"]]},
             "evidence_refs": [code_witness[side]["evidence_id"]], "reason": "Fixture endpoint."}
            for kind, anchor, category, side in (
                ("EXTERNAL_INPUT", first, "HTTP", "from"),
                ("SECURITY_EFFECT", last, "REDIRECT_OR_RESPONSE", "to"))
        ]
        return reply(action="propose_assumed_bridge", from_anchor=first, to_anchor=last, bridge_index=1,
                     code_witness=code_witness, proposals=proposals, conditions=["Fixture dispatches the value."],
                     reason="The two source-anchored endpoints are connected by the scripted fixture.")

    def verify(context):
        proposal_id, bridge = next(iter(context["assumed_bridges"].items()))
        assert bridge["kind"] == "llm_assumed_bridge"
        refs = list(context["source_evidence"])
        return reply(verdict="SUPPORTED", reason="Scripted verdict exercises the independent bridge gate.",
                     evidence_refs=refs, support=["Fixture"], counterevidence=[], unproven_conditions=[],
                     checks={"input_control": "supported", "value_flow": "supported", "security_effect": "supported",
                             "effective_protection": "absent"},
                     bridge_checks={proposal_id: {"verdict": "BRIDGE_CONFIRMED",
                                                 "evidence_refs": refs if confirm else refs[:1]}})

    output = tmp_path / "output"
    summary = run_dag(source, output, AgentTeam(discover, reason, verify), static_graph=graph,
                      static_value_bridges=values, rounds=1, repair_protocol=True, path_sensitive=True,
                      agentic_rag=True, adaptive_gaps=True)
    assert summary["candidate_paths"] == 1
    assert summary["verifier_supported"] == int(confirm)
    review = json.loads((output / "reviews.jsonl").read_text())
    assert list(review["bridge_verdicts"].values()) == ["BRIDGE_CONFIRMED" if confirm else "BRIDGE_UNRESOLVED"]


@pytest.mark.parametrize(("connected", "protected"), [(True, False), (False, False), (True, True), (False, True)])
def test_value_path_uses_only_exported_ports_and_rechecks_new_source(tmp_path, connected, protected):
    pytest.importorskip("tree_sitter_java")
    source = tmp_path / "src"
    source.mkdir()
    lines = [
        "class Handler {",
        "  void handle() {",
        "    String input = request();",
        "    String output = forward(input);",
        "    if (ready()) {",
        "      write(output);",
        "    }",
        "  }",
        "  private String forward(String s) {",
        "    return s;",
        "  }",
        '  private String request() { return ""; }',
        "  private boolean ready() { return true; }",
        "  private void write(String s) {}",
        "}",
    ]
    (source / "Handler.java").write_text("\n".join(lines) + "\n")
    graph = tmp_path / "graph.csv"
    graph.write_text("kind,left,l,c,right,l,c\n")
    values = tmp_path / "value.csv"

    def port(line, expression, role, index=-1):
        start = lines[line - 1].index(expression) + 1
        return ["Handler.java", line, start, line, start + len(expression) - 1, role, index]

    input_port = port(3, "request()", "CALL_RESULT")
    forward_argument = port(4, "forward(input)", "ARGUMENT", 0)
    forward_result = port(4, "forward(input)", "CALL_RESULT")
    output_port = port(6, "write(output)", "ARGUMENT", 0)
    with values.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(range(17))
        writer.writerow([*input_port, *forward_argument, "Handler.java", 3, 4])
        writer.writerow([*forward_result, *output_port, "Handler.java", 4, 6])
        if connected:
            writer.writerow([*forward_argument, *forward_result, "Handler.java", 9, 10])
            writer.writerow([*forward_argument, *forward_result, "Handler.java", 9, 10])

    from java_vuln_research.work1_agent.repository.tools import RepositoryTools
    ready = next(entity.entity_id for entity in RepositoryTools.open(source).index.entities
                 if entity.simple_name == "ready" and entity.kind.value == "METHOD")

    def discover(context):
        return reply(branches={cwe: {"queries": [], "hypotheses": []} for cwe in SUPPORTED_CWES})

    def reason(context):
        if context["cwe"] != "CWE-79":
            return reply(action="finish", outcome="NO_GROUNDED_LEAD", reason="No effect for this CWE.")
        alternatives = [row for row in context["value_paths"]
                        if row["ports"][0]["name"] == "request" and row["ports"][-1]["name"] == "write"]
        path = next((row for row in alternatives if all(kind == "static" for kind in row["bridge_kinds"])), None)
        if not connected and not protected:
            assert path is None
            assert all(any(kind != "static" for kind in row["bridge_kinds"]) for row in alternatives)
            return reply(action="finish", outcome="EVIDENCE_GAP", reason="No argument-to-return relation.")
        if connected:
            assert path["source_complete"] and len(path["ports"]) == 4
            assert path["guards"][0]["start"] == 5
        else:
            path = next(row for row in alternatives if row["source_complete"])
        if protected:
            return reply(action="finish", outcome="PROTECTION_ESTABLISHED", path_id=path["id"],
                         reason="Fixture asks the verifier to inspect the guard.")
        return reply(action="submit_bridge", path_id=path["id"], input_category="HTTP",
                     effect_category="REDIRECT_OR_RESPONSE", conditions=["Handler is invoked."],
                     reason="Fixture callback passes request output to write.")

    review_calls = []

    def review(context):
        review_calls.append(context)
        bridges = context.get("assumed_bridges", {})
        bridge_checks = {key: {"verdict": "BRIDGE_CONFIRMED", "evidence_refs": list(context["source_evidence"])}
                         for key in bridges}
        if len(review_calls) == 1:
            return reply(verdict="UNRESOLVED", evidence_refs=[], reason="Inspect ready guard.",
                         support=[], counterevidence=[], unproven_conditions=["Guard"],
                         bridge_checks=bridge_checks,
                         retrieval_requests=[{"action": "inspect_entity", "entity_id": ready}])
        if protected:
            assert any("private boolean ready()" in proof["source"] for proof in context["source_evidence"].values())
            return reply(verdict="REJECTED", evidence_refs=list(context["source_evidence"]),
                         bridge_checks=bridge_checks,
                         reason="Fixture confirms the supplied protection evidence was independently reviewed.")
        assert any(ready in proof["location"]["entity_ids"] for proof in context["source_evidence"].values())
        return reply(verdict="SUPPORTED", evidence_refs=list(context["source_evidence"]),
                     reason="Fixture confirms the guard.", support=["Witnessed transfers and guard"],
                     counterevidence=[], unproven_conditions=[],
                     checks={"input_control": "supported", "value_flow": "supported",
                             "security_effect": "supported", "effective_protection": "absent"})

    output = tmp_path / "out"
    summary = run_dag(source, output, AgentTeam(discover, reason, review), static_graph=graph,
                      static_value_bridges=values, rounds=2, repair_protocol=True, path_sensitive=True,
                      agentic_rag=True, adaptive_gaps=True)
    assert summary["stop_reason"] == "GRAPH_COMPLETE"
    assert summary["candidate_paths"] == int(connected and not protected)
    assert summary["verifier_supported"] == int(connected and not protected)
    assert summary["protection_rejected"] == int(protected)
    assert summary["value_graph"]["duplicates"] == int(connected)
    assert len(review_calls) == 2 * (connected or protected)
    if connected or protected:
        events = [json.loads(line)["event"] for line in (output / "trace.jsonl").read_text().splitlines()]
        assert "retrieval_task_finished" in events and "candidate_evidence_updated" in events


def test_value_reasoning_continues_an_explicit_source_range_past_a_cached_window(tmp_path):
    pytest.importorskip("tree_sitter_java")
    from java_vuln_research.work1_agent.repository.tools import RepositoryTools

    source = tmp_path / "src"
    source.mkdir()
    (source / "Handler.java").write_text(
        "class Handler {\n  void handle() {\n"
        + "    int ignored = 0;\n" + "    ignored++;\n" * 60
        + "    consume(ignored);\n  }\n  void consume(int value) {}\n}\n", encoding="utf-8",
    )
    method = next(entity for entity in RepositoryTools.open(source).index.entities
                  if entity.kind.value == "METHOD" and entity.simple_name == "handle")
    graph = tmp_path / "graph.csv"
    graph.write_text("kind,left,l,c,right,l,c\n", encoding="utf-8")
    values = tmp_path / "value.csv"
    values.write_text(",".join(map(str, range(17))) + "\n", encoding="utf-8")

    def discover(context):
        branches = {cwe: {"queries": [], "hypotheses": []} for cwe in SUPPORTED_CWES}
        branches["CWE-79"]["hypotheses"].append({"anchor_entity_id": method.entity_id,
                                                  "hypothesis": "Inspect the fixture handler implementation.",
                                                  "evidence_question": "Where is the final value used?"})
        return reply(branches=branches)

    def reason(context):
        if not context["recent_actions"]:
            return reply(action="inspect_entity", entity_id=method.entity_id,
                         line_start=method.start_line, line_end=method.end_line)
        assert [item["status"] for item in context["recent_actions"]] == ["SOURCE_ALREADY_READ", "SOURCE_READ"]
        assert any(window["start_line"] == method.start_line + 40 and "consume(ignored);" in window["source"]
                   for window in context["retrieved"])
        return reply(action="finish", outcome="EVIDENCE_GAP", reason="Read the complete requested range.")

    summary = run_dag(source, tmp_path / "out", AgentTeam(discover, reason, lambda _: pytest.fail("No review")),
                      static_graph=graph, static_value_bridges=values, repair_protocol=True, path_sensitive=True,
                      agentic_rag=True, adaptive_gaps=True)
    assert summary["branch_outcomes"]["CWE-79"] == "EVIDENCE_GAP"


@pytest.mark.parametrize("search", ["search_symbols", "search_code"])
def test_value_reasoning_retains_initial_paths_and_adds_new_search_hits(tmp_path, search):
    pytest.importorskip("tree_sitter_java")
    source = tmp_path / "src"
    source.mkdir()
    graph = tmp_path / "graph.csv"
    graph.write_text("kind,left,l,c,right,l,c\n", encoding="utf-8")
    values = tmp_path / "value.csv"
    with values.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(range(17))
        for name, methods in (("A", [f"route{i}" for i in range(12)]), ("Z", ["lateCallback"])):
            file = f"{name}.java"
            lines = [f"class {name} {{"]
            for method in methods:
                lines += [f"  void {method}() {{", "    String input = request();", "    write(input);", "  }"]
                start, end = len(lines) - 2, len(lines) - 1
                writer.writerow([file, start, 20, start, 28, "CALL_RESULT", -1,
                                 file, end, 5, end, 16, "ARGUMENT", 0, file, start, end])
            lines += ['  String request() { return ""; }', "  void write(String value) {}", "}"]
            (source / file).write_text("\n".join(lines) + "\n", encoding="utf-8")

    def discover(context):
        return reply(branches={cwe: {"queries": [], "hypotheses": []} for cwe in SUPPORTED_CWES})

    def reason(context):
        if context["cwe"] != "CWE-79":
            return reply(action="finish", outcome="NO_GROUNDED_LEAD", reason="Fixture models an HTTP response.")
        paths = context["value_paths"]
        if not context["recent_actions"]:
            assert sum(path["bridge_kinds"] == ["static"] for path in paths) > 8
            assert all(path["ports"][0]["file"] == "A.java" for path in paths)
            return reply(action=search, query="lateCallback")
        target = next(path for path in paths if path["ports"][0]["file"] == "Z.java"
                      and path["bridge_kinds"] == ["static"])
        assert target["source_complete"]
        assert any(path["ports"][0]["file"] == "A.java" for path in paths)
        return reply(action="submit_bridge", path_id=target["id"], input_category="HTTP",
                     effect_category="REDIRECT_OR_RESPONSE", conditions=["The late callback is invoked."],
                     reason="The fixture directs the callback input into the response writer.")

    def verify(context):
        return reply(verdict="SUPPORTED", evidence_refs=list(context["source_evidence"]),
                     reason="Fixture connects the callback input to the response.", support=["Source and value edges."],
                     counterevidence=[], unproven_conditions=[],
                     checks={"input_control": "supported", "value_flow": "supported",
                             "security_effect": "supported", "effective_protection": "absent"})

    output = tmp_path / "out"
    summary = run_dag(source, output, AgentTeam(discover, reason, verify), static_graph=graph,
                      static_value_bridges=values, repair_protocol=True, path_sensitive=True,
                      agentic_rag=True, adaptive_gaps=True)
    assert summary["candidate_paths"] == summary["verifier_supported"] == 1
    assert any(json.loads(line)["event"] == "value_paths_refreshed"
               for line in (output / "trace.jsonl").read_text().splitlines())
