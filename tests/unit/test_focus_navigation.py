import csv
import io
import json

import pytest

from java_vuln_research.work1_agent.dag_harness import AgentTeam, Node, _Run, run_dag
from java_vuln_research.work1_agent.dag_retrieval import StructuralRetrieval
from java_vuln_research.work1_agent.graph_rag import CodeQLGraphIndex
from java_vuln_research.work1_agent.harness import HarnessLimits, ModelTurn, SUPPORTED_CWES
from java_vuln_research.work1_agent.repository.tools import RepositoryTools
from java_vuln_research.work1_agent.value_paths import ValuePaths


def reply(**value):
    return ModelTurn(json.dumps(value))


def test_strict_prefetch_and_production_sink_isolation(tmp_path):
    pytest.importorskip("tree_sitter_java")
    source = tmp_path / "source"
    source.mkdir()
    (source / "Example.java").write_text(
        "class Example {\n"
        "    public void handle(String data) { relay(data); }\n"
        "    private void relay(String data) { emit(data); }\n"
        "    private void emit(String data) { write(data); }\n"
        '    void constants(int offset) { write("a" + "b", offset); write(Flavor.FIXED); }\n'
        '    void launch(String command) { new ProcessBuilder("fixed").start(); new ProcessBuilder(command).start(); }\n'
        '    void wrapped(String arg) { exec("fixed", arg); Runtime.getRuntime().exec("fixed", arg); }\n'
        "    static void exec(String... args) {}\n"
        "    void write(Object... args) {}\n"
        "}\n"
        "enum Flavor { FIXED }\n", encoding="utf-8")
    (source / "ExampleTest.java").write_text(
        "class ExampleTest { void handle(String data) { write(data); } void write(String data) {} }\n",
        encoding="utf-8")
    tools = RepositoryTools.open(source)
    methods = {e.simple_name: e for e in tools.index.entities
               if e.kind.value == "METHOD" and e.repository_relative_path == "Example.java"}
    graph_file = tmp_path / "graph.csv"
    with graph_file.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(range(8))
        writer.writerow(["CODEQL_DIRECT_CALL", "Example.java", 2, 39, "Example.java", 3, 5, ""])
        writer.writerow(["CODEQL_DIRECT_CALL", "Example.java", 3, 39, "Example.java", 4, 5, ""])
        # The second write has an enum argument, which needs CodeQL's symbol resolution.
        enum_column = (source / "Example.java").read_text().splitlines()[4].index("write(Flavor") + 1
        writer.writerow(["CODEQL_CONSTANT_ARGUMENT", "Example.java", 5, enum_column,
                         "Example.java", 5, enum_column + 6, "0"])
    graph = CodeQLGraphIndex(source, tools.index.entities, graph_file)
    values = ValuePaths(graph)
    retrieval = StructuralRetrieval(tools.index.entities, None, graph)
    navigation = retrieval.branch_navigation("CWE-79")
    assert [(sink.repository_relative_path, sink.start_line) for sink in navigation.sinks] == [("Example.java", 4)]
    assert all(item.repository_relative_path == "Example.java" for item in navigation.sources)
    command_sinks = retrieval.branch_navigation("CWE-78").sinks
    assert len([sink for sink in command_sinks if sink.simple_name == "start"]) == 1
    execs = [sink for sink in command_sinks if sink.simple_name == "exec"]
    assert len(execs) == 1
    assert execs[0].provenance["start_column"] == (source / "Example.java").read_text().splitlines()[6].index("exec") + 1
    handle, relay, emit = (methods[name].entity_id for name in ("handle", "relay", "emit"))
    assert [navigation.distance[item] for item in (handle, relay, emit)] == [2, 1, 0]

    def unused(_):
        pytest.fail("Deterministic prefetch must not call a model.")

    stream = io.StringIO()
    runner = _Run(tools, retrieval, AgentTeam(unused, unused, unused), HarnessLimits(24, 64), stream,
                  mode="adaptive", rounds=4, value_paths=values, focus_scheduling=True)
    node = Node("retrieve:1:CWE-79", "retrieval", (), "CWE-79", 1)
    assert runner.action(node, {"action": "inspect_entity", "entity_id": handle})[0] == "SOURCE_READ"
    assert runner.action(node, {"action": "inspect_entity", "entity_id": handle})[0] == "SOURCE_ALREADY_READ"
    reads = [e for e in map(json.loads, stream.getvalue().splitlines()) if e["event"] == "strict_neighbor_prefetch"]
    assert [row["neighbor"] for row in reads] == [relay]
    assert runner.tool_calls == 2 and runner.model_calls == 0


def test_unread_spine_and_edge_windows_cover_distant_call_and_signature(tmp_path):
    pytest.importorskip("tree_sitter_java")
    source = tmp_path / "source"
    source.mkdir()
    lines = ["class Example {", "    public void handle(String input) {"]
    lines += ["        // keep the call far from the declaration"] * 68
    call_line = len(lines) + 1
    lines += ["        relay(input);", "    }", "    private void relay(String value) {",
              "        write(value);", "    }", "    private void write(String value) {}", "}"]
    (source / "Example.java").write_text("\n".join(lines) + "\n", encoding="utf-8")
    relay_line = call_line + 2
    graph_path = tmp_path / "graph.csv"
    with graph_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(range(8))
        writer.writerow(["CODEQL_DIRECT_CALL", "Example.java", call_line, 9, "Example.java", relay_line, 5, ""])
    value_path = tmp_path / "values.csv"

    def port(line, expression, role, index):
        column = lines[line - 1].index(expression) + 1
        return ["Example.java", line, column, line, column + len(expression) - 1, role, index]

    handle = ["Example.java", 2, 5, call_line + 1, 5, "PARAMETER", 0]
    relay = ["Example.java", relay_line, 5, relay_line + 2, 5, "PARAMETER", 0]
    invocation = port(call_line, "relay(input)", "ARGUMENT", 0)
    sink = port(relay_line + 1, "write(value)", "ARGUMENT", 0)
    with value_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(range(17))
        writer.writerow([*handle, *invocation, "Example.java", 2, call_line])
        writer.writerow([*invocation, *relay, "Example.java", call_line, call_line])
        writer.writerow([*relay, *sink, "Example.java", relay_line, relay_line + 1])
    tools = RepositoryTools.open(source)
    graph = CodeQLGraphIndex(source, tools.index.entities, graph_path)
    paths = ValuePaths(graph, value_path)
    retrieval = StructuralRetrieval(tools.index.entities, None, graph)
    methods = {e.simple_name: e.entity_id for e in tools.index.entities if e.kind.value == "METHOD"}

    def unused(_):
        pytest.fail("Spine planning and read windows are deterministic.")

    stream = io.StringIO()
    runner = _Run(tools, retrieval, AgentTeam(unused, unused, unused), HarnessLimits(24, 64), stream,
                  mode="adaptive", rounds=4, value_paths=paths, focus_scheduling=True)
    node = Node("retrieve:1:CWE-79", "retrieval", (), "CWE-79", 1)
    hint = runner.static_spine_hints(node)[0]
    assert hint["typed_source_to_sink"]
    assert any(site["start"] == call_line and not site["read"] for site in hint["edge_sites"])
    assert not any(site["read"] for site in hint["edge_sites"])
    nav = retrieval.branch_navigation("CWE-79")
    nav.distance[methods["handle"]] = 0
    nav.distance[methods["relay"]] = 1
    # Explicit forward focus can prefetch across an increase in sink distance.
    runner.action(node, {"action": "inspect_entity", "entity_id": methods["handle"]}, prefetch=False)
    runner.prefetch_neighbors(node, methods["handle"], direction=0)
    case = runner.cases["CWE-79"]
    assert paths.proof(case, (methods["handle"], 2, 2))
    assert paths.proof(case, (methods["handle"], call_line, call_line))
    assert paths.proof(case, (methods["relay"], relay_line, relay_line))
    assert runner.read_static_spine(node, {"spine_id": hint["id"]})[1]["missing_sites"] == 0
    assert runner.reason_paths(Node("reason:1:CWE-94", "reasoning", (), "CWE-94", 1))["outcome"] == "NO_GROUNDED_LEAD"
    assert runner.model_calls == 0


def test_witness_frontier_reaches_round_four_and_prunes_empty_branches(tmp_path):
    pytest.importorskip("tree_sitter_java")
    source = tmp_path / "source"
    source.mkdir()
    (source / "Example.java").write_text(
        "class Example {\n"
        "    public void handle(Request r, Response out) {\n"
        '        String data = r.getParameter("input");\n'
        "        String copy = data;\n"
        "        out.write(copy);\n"
        "    }\n"
        "    void helper(String data) { open(data); execute(data); eval(data); }\n"
        "}\n", encoding="utf-8")

    def step(line, expression, role):
        return {"file_path": "Example.java", "line_start": line, "line_end": line,
                "method_symbol": "handle", "tracked_variable_or_expr": expression, "step_role": role}

    prefix = [step(3, "r.getParameter()", "SOURCE"), step(4, "copy + data", "PROPAGATION")]
    visited = []
    probed = []

    def discover(_):
        return reply(branches={cwe: {"queries": [], "hypotheses": []} for cwe in SUPPORTED_CWES})

    def reason(context):
        number = context["round"]
        if context["cwe"] != "CWE-79":
            assert number == 1
            probed.append(context["cwe"])
            return reply(action="inspect_entity", entity_id=context["navigation"]["sinks"][0]["method_id"])
        visited.append(number)
        if number == 4:
            assert context["final_synthesis"]["instruction"] == "[FINAL ROUND: EVIDENCE SYNTHESIS REQUIRED]"
            assert set(context["allowed_actions"]) == {"submit_witness_path", "finish"}
            return reply(action="submit_witness_path", steps=[*prefix, step(5, "out.write(copy)", "SINK")],
                         input_category="HTTP", effect_category="REDIRECT_OR_RESPONSE",
                         conditions=["The handler is registered for incoming requests."])
        if not context["recent_actions"]:
            return reply(action="remember_witness_path", steps=prefix,
                         frontier_question=f"Round {number}: inspect how copy becomes response content.")
        assert context["exploration_memory"]["Frontier_Questions"]
        return reply(action="finish", outcome="EVIDENCE_GAP", reason="Preserve the current frontier.")

    def verify(context):
        refs = list(context["source_evidence"])
        return reply(verdict="SUPPORTED", evidence_refs=refs, reason="Scripted verification of the complete chain.",
                     support=["Witnessed input and output."], counterevidence=[], unproven_conditions=[],
                     checks={"input_control": "supported", "value_flow": "supported", "security_effect": "supported",
                             "effective_protection": "absent"},
                     bridge_checks={key: {"verdict": "BRIDGE_CONFIRMED", "evidence_refs": refs}
                                    for key in context["assumed_bridges"]})

    output = tmp_path / "output"
    result = run_dag(source, output, AgentTeam(discover, reason, verify), rounds=4,
                     source_witness_navigation=True, repair_protocol=True, path_sensitive=True,
                     adaptive_gaps=True)
    assert result["verifier_supported"] == 1
    assert set(visited) == {1, 2, 3, 4}
    assert visited.count(1) == 1
    assert sorted(probed) == sorted(set(SUPPORTED_CWES) - {"CWE-79"})
    assert result["nodes"]["route:1"]["active"] == ["CWE-79"]
    assert all(result["branch_outcomes"][cwe] == "PRUNED_LOW_POTENTIAL" for cwe in SUPPORTED_CWES if cwe != "CWE-79")


@pytest.mark.parametrize("headroom", [2, 3])
def test_stalled_focus_uses_physical_headroom_and_changes_perspective(tmp_path, headroom):
    pytest.importorskip("tree_sitter_java")
    source = tmp_path / "source"
    source.mkdir()
    (source / "Example.java").write_text(
        "class Example {\n"
        "    String field;\n"
        "    public void handle(Request r, Response out) {\n"
        '        String data = r.getParameter("input");\n'
        "        out.write(data);\n"
        "    }\n"
        "}\n", encoding="utf-8")
    rounds = set()

    def discover(_):
        return reply(branches={cwe: {"queries": [], "hypotheses": []} for cwe in SUPPORTED_CWES})

    def reason(context):
        number = context["round"]
        rounds.add(number)
        if context.get("final_synthesis"):
            return reply(action="finish", outcome="EVIDENCE_GAP", reason="The intermediate receiver is unproven.")
        if number == 1 and not context["recent_actions"]:
            return reply(action="remember_witness_path", frontier_question="Find the downstream response effect.",
                         steps=[{"file_path": "Example.java", "line_start": 4, "line_end": 4,
                                 "method_symbol": "handle", "tracked_variable_or_expr": "r.getParameter",
                                 "step_role": "SOURCE"}])
        if number >= 3:
            assert context["pivot"]["instruction"].startswith("[PIVOT MODE: BRIDGE_GAP]")
            assert any(symbol["name"].endswith("field") for symbol in context["pivot"]["boundary_symbols"])
        return reply(action="finish", outcome="EVIDENCE_GAP", reason="No new intermediate transfer.")

    def unused(_):
        pytest.fail("The stalled fixture does not submit a candidate.")

    output = tmp_path / "output"
    result = run_dag(source, output, AgentTeam(discover, reason, unused), rounds=4,
                     source_witness_navigation=True, repair_protocol=True, path_sensitive=True,
                     adaptive_gaps=True, request_headroom=lambda: headroom if 2 in rounds else 16)
    assert rounds == (set(range(1, 5)) if headroom == 3 else {1, 2})
    if headroom == 3:
        assert result["nodes"]["route:2"]["reasons"]["CWE-79"] == "BRIDGE_GAP"


def test_diverse_spines_keep_five_distinct_deep_endpoint_pairs(tmp_path):
    pytest.importorskip("tree_sitter_java")
    source = tmp_path / "source"
    source.mkdir()
    lines = ["class Example {"]
    graph_rows = []
    for i in range(6):
        a = len(lines) + 1
        lines += [f"    public void handle{i}(String value) {{ middle{i}(value); }}",
                  f"    private void middle{i}(String value) {{ emit{i}(value); }}",
                  f"    private void emit{i}(String value) {{ write(value); }}"]
        graph_rows.extend([
            ["CODEQL_DIRECT_CALL", "Example.java", a, lines[a - 1].index(f"middle{i}") + 1,
             "Example.java", a + 1, 5, ""],
            ["CODEQL_DIRECT_CALL", "Example.java", a + 1, lines[a].index(f"emit{i}") + 1,
             "Example.java", a + 2, 5, ""],
        ])
    lines += ["    private void write(String value) {}", "}"]
    (source / "Example.java").write_text("\n".join(lines), encoding="utf-8")
    graph_file = tmp_path / "graph.csv"
    with graph_file.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(range(8))
        writer.writerows(graph_rows)
    tools = RepositoryTools.open(source)
    graph = CodeQLGraphIndex(source, tools.index.entities, graph_file)
    values = ValuePaths(graph)
    nav = StructuralRetrieval(tools.index.entities, None, graph).branch_navigation("CWE-79")
    selected = list(values.static_spines(nav, "CWE-79").values())
    assert len(selected) == 5
    assert len({(row["methods"][0], row["methods"][-1]) for row in selected}) == 5
    assert all(len(row["methods"]) == 3 for row in selected)


def test_unique_relay_and_shared_parent_have_two_read_windows_per_round(tmp_path):
    pytest.importorskip("tree_sitter_java")
    source = tmp_path / "source"
    source.mkdir()
    lines = ["class Example {", "    public void handle(String data) { relay(data); }",
             "    private void relay(String data) { emit(data); }",
             "    private void emit(String data) { write(data); }",
             "    void parent(String data) { handle(data); emit(data); }",
             "    void write(String data) {}", "}"]
    (source / "Example.java").write_text("\n".join(lines), encoding="utf-8")
    graph_file = tmp_path / "graph.csv"
    with graph_file.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(range(8))
        for origin, name, target in ((2, "relay", 3), (3, "emit", 4), (5, "handle", 2), (5, "emit", 4)):
            writer.writerow(["CODEQL_DIRECT_CALL", "Example.java", origin, lines[origin - 1].index(name) + 1,
                             "Example.java", target, 5, ""])
    tools = RepositoryTools.open(source)
    graph = CodeQLGraphIndex(source, tools.index.entities, graph_file)
    values = ValuePaths(graph)
    retrieval = StructuralRetrieval(tools.index.entities, None, graph)
    ids = {entity.simple_name: entity.entity_id for entity in tools.index.entities if entity.kind.value == "METHOD"}

    def unused(_):
        pytest.fail("Relay reads must not call a model.")

    stream = io.StringIO()
    runner = _Run(tools, retrieval, AgentTeam(unused, unused, unused), HarnessLimits(24, 64), stream,
                  mode="adaptive", rounds=4, value_paths=values, focus_scheduling=True)
    node = Node("retrieve:1:CWE-79", "retrieval", (), "CWE-79", 1)
    for name in ("handle", "emit"):
        runner.action(node, {"action": "inspect_entity", "entity_id": ids[name], "start_line": 2 if name == "handle" else 4,
                             "end_line": 2 if name == "handle" else 4}, prefetch=False)
    runner.prefetch_relays(node, ids["handle"])
    runner.prefetch_relays(node, ids["handle"])
    assert runner.relay_reads["CWE-79", 1] == 2
    events = [json.loads(line) for line in stream.getvalue().splitlines()]
    relays = [event for event in events if event["event"] == "strict_relay_prefetch"]
    assert {event["middle"] for event in relays} == {ids["relay"], ids["parent"]}
    assert runner.model_calls == 0


def test_archived_windows_can_be_restored_without_becoming_new_source_evidence(tmp_path):
    pytest.importorskip("tree_sitter_java")
    source = tmp_path / "source"
    source.mkdir()
    lines = ["class Example {", "    public void handle(String data) {"]
    lines += [f"        String value{i} = data; // " + "context filler " * 200 for i in range(20)]
    lines += ["        write(data);", "    }", "    void write(String data) {}", "}"]
    (source / "Example.java").write_text("\n".join(lines), encoding="utf-8")
    tools = RepositoryTools.open(source)
    graph = CodeQLGraphIndex(source, tools.index.entities, None)
    values = ValuePaths(graph)
    retrieval = StructuralRetrieval(tools.index.entities, None, graph)
    handle = next(entity.entity_id for entity in tools.index.entities if entity.kind.value == "METHOD"
                  and entity.simple_name == "handle")

    def unused(_):
        pytest.fail("Archive selection is deterministic.")

    runner = _Run(tools, retrieval, AgentTeam(unused, unused, unused), HarnessLimits(24, 160), io.StringIO(),
                  mode="adaptive", rounds=4, value_paths=values, focus_scheduling=True)
    node = Node("retrieve:1:CWE-79", "retrieval", (), "CWE-79", 1)
    first = None
    for line in range(3, 23):
        _, result = runner.action(node, {"action": "inspect_entity", "entity_id": handle,
                                         "start_line": line, "end_line": line}, prefetch=False)
        if first is None:
            first = result["evidence"]["evidence_id"]
    later = Node("reason:2:CWE-79", "reasoning", (), "CWE-79", 2)
    selected, history, count = runner.reasoning_sources(later)
    assert selected == [] and count == 20
    prior = len(runner.cases["CWE-79"].evidence)
    assert runner.action(later, {"action": "recall_source", "evidence_id": first})[0] == "SOURCE_RECALLED"
    selected, history, count = runner.reasoning_sources(later)
    assert len(selected) == 1 and selected[0]["evidence_id"] == first and count == 19
    assert len(runner.cases["CWE-79"].evidence) == prior
    context = {"retrieved": selected, "value_paths": [], "navigation": {"forward_prefixes": [], "backward_slices": []}}
    runner.compact_reasoning_context(later, context, history)
    assert context["archived_sources_total"] == 19
    assert all(item["summary"].startswith("[Read & Archived] Example.java:") for item in context["archived_sources"])

    # A final-round pivot can reuse a cached read, with no new SOURCE_READ event.
    # Both the current pivot and a preceding pivot must survive archive pruning.
    refs = list(runner.cases["CWE-79"].evidence)
    runner.pivots["CWE-79"] = {"evidence_ids": [refs[1]]}
    runner.pivot_evidence["CWE-79"] = [refs[2]]
    final = Node("reason:4:CWE-79", "reasoning", (), "CWE-79", 4)
    selected, history, _ = runner.reasoning_sources(final)
    assert {row["evidence_id"] for row in selected} == {refs[1], refs[2]}
    spines = [{"id": f"spine-{i}", "edge_kinds": ["VALUE_BRIDGE"] * 3,
               "methods": [{"id": handle, "signature": "handle(String)"}],
               "edge_sites": [{"read": True}] * 80} for i in range(5)]
    context = {"retrieved": selected, "value_paths": [], "Static_Spine_Hints": spines,
               "navigation": {"forward_prefixes": [], "backward_slices": []},
               "pivot": {"boundary_symbols": [{"id": str(i), "signature": "String field"} for i in range(40)]}}
    runner.compact_reasoning_context(final, context, history)
    assert {row["evidence_id"] for row in context["retrieved"]} == {refs[1], refs[2]}
    assert len(context["Static_Spine_Hints"]) == 5
    assert all(row["total_sites"] == 80 and "edge_sites" not in row for row in context["Static_Spine_Hints"])
    assert len(context["pivot"]["boundary_symbols"]) == 4

    # Ten legitimate active windows can still exceed ask()'s byte ceiling.
    # Keep high priority pivot proofs, archive the rest, and leave repair headroom.
    runner.path_sensitive = True
    runner.recalled["CWE-79", 4].update(refs)
    selected, history, _ = runner.reasoning_sources(final)
    assert len(selected) == 10
    context = {"retrieved": selected, "value_paths": [], "navigation": {}}
    runner.compact_reasoning_context(final, context, history)
    assert len(json.dumps(context, ensure_ascii=False).encode()) <= 24576 - 1024
    assert 1 < len(context["retrieved"]) < 10
    assert {refs[1], refs[2]} <= {row["evidence_id"] for row in context["retrieved"]}
