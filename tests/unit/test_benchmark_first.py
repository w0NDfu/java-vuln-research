"""R12 protocol, leakage boundary, bounded discovery and paper metric checks."""
import importlib
import json
import sys
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.benchmark import BenchmarkLimits, BenchmarkRun, run_benchmark
from java_vuln_research.work1_agent.dag_harness import AgentTeam
from java_vuln_research.work1_agent.dag_retrieval import StructuralRetrieval
from java_vuln_research.work1_agent.graph_rag import CodeQLGraphIndex
from java_vuln_research.work1_agent.harness import ModelTurn
from java_vuln_research.work1_agent.repository.tools import RepositoryTools


TEXT = '''class Fixture {
  public void handle(Request req, Response out) {
    String value = req.getParameter("x");
    out.write(value);
  }
  String command(String input) { return input; }
}
'''


@pytest.fixture
def runner(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    (root / "Fixture.java").write_text(TEXT)
    output = tmp_path / "output"
    output.mkdir()
    tools = RepositoryTools.open(root)
    graph = CodeQLGraphIndex(root, tools.index.entities, None)
    retrieval = StructuralRetrieval(tools.index.entities, None, graph)
    def unused(_):
        pytest.fail("Unexpected model call")
    value = BenchmarkRun(tools, retrieval, AgentTeam(unused, unused, unused), output)
    yield value
    value.trace.close()


def grounded(runner):
    method = next(m for m in runner.methods.values() if m.simple_name == "handle")
    proof = runner.read(method.entity_id)
    return {"cwe": "CWE-79", "title": "Unescaped reflected request output",
            "input_reason": "The request query parameter supplies the value.",
            "effect_reason": "The response writes that value without visible encoding.",
            "guard_analysis": "No encoding is visible; response content type still needs checking.",
            "conditions": ["The response is rendered as HTML by the caller."],
            "uncertainties": ["Response content type is not shown."],
            "steps": [{"evidence_id": proof["evidence_id"], "method_id": method.entity_id,
                       "line": line, "expression": expression, "role": role}
                      for line, expression, role in [(3, 'req.getParameter("x")', "SOURCE"), (4, "out.write(value)", "SINK")]]}


def test_grounded_candidate_is_retained_without_flow_proofs_or_verifier(runner):
    draft = grounded(runner)
    i = runner.candidate(draft)
    assert runner.candidates[i]["status"] == "UNCONFIRMED"
    assert runner.candidates[i]["uncertainties"]
    assert not runner.reviews
    assert runner.candidate({**draft, "title": "Another description of the same candidate"}) == i
    assert len(runner.candidates) == 1


@pytest.mark.parametrize("mutation", ["expression", "line", "method", "evidence", "role", "single", "guard"])
def test_fabricated_or_location_only_candidates_cannot_be_exported(runner, mutation):
    draft = grounded(runner)
    if mutation == "expression": draft["steps"][1]["expression"] = "Runtime.exec(value)"
    if mutation == "line": draft["steps"][1]["line"] = 99
    if mutation == "method": draft["steps"][1]["method_id"] = "invented"
    if mutation == "evidence": draft["steps"][1]["evidence_id"] = "invented"
    if mutation == "role": draft["steps"][0]["role"] = "SINK"
    if mutation == "single": draft["steps"] = draft["steps"][:1]
    if mutation == "guard": draft["guard_analysis"] = ""
    with pytest.raises(ValueError): runner.candidate(draft)
    assert not runner.candidates


def test_source_reads_are_bounded_deduplicated_and_search_uses_real_facade(runner):
    grounded(runner)
    before = runner.tool_calls
    method = next(m for m in runner.methods.values() if m.simple_name == "handle")
    runner.read(method.entity_id)
    assert runner.tool_calls == before
    with pytest.raises(ValueError): runner.read(method.entity_id, 1, 7)
    hits = runner.request({"action": "search_symbols", "query": "handle"})
    assert hits["hits"]


def test_light_review_cannot_upgrade_to_confirmed_or_reject_without_citations(runner):
    i = runner.candidate(grounded(runner))
    def review(_):
        return ModelTurn(json.dumps({"reviews": [{"candidate_path_id": i, "verdict": "SUPPORTED",
                                                  "reason": "Seems valid", "evidence_refs": []}]}))
    runner.team = AgentTeam(review, review, review)
    runner.review()
    assert not runner.reviews
    assert runner.candidates[i]["status"] == "UNCONFIRMED"


def test_negative_filter_requires_real_source_and_does_not_delete_raw_candidate(runner):
    draft = grounded(runner)
    i = runner.candidate(draft)
    def review(_):
        return ModelTurn(json.dumps({"reviews": [{"candidate_path_id": i, "verdict": "REJECTED",
            "reason": "Fixture refutation from supplied code", "evidence_refs": [draft["steps"][0]["evidence_id"]]}]}))
    runner.team = AgentTeam(review, review, review)
    runner.review()
    assert runner.reviews[i]["verdict"] == "REJECTED"
    assert i in runner.candidates
    assert runner.reviews[i]["strict_verification"] is False


def test_discovery_keeps_all_four_cwes_even_with_no_process_api(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "Fixture.java").write_text(TEXT)
    contexts = []
    def policy(context):
        contexts.append(context)
        if context["role"] == "discovery": return ModelTurn('{"leads":[]}')
        return ModelTurn('{"candidates":[],"requests":[],"leads":[],"disposition":"No grounded candidate"}')
    summary = run_benchmark(source, tmp_path / "run", AgentTeam(policy, policy, policy),
                            limits=BenchmarkLimits(max_focus=4, light_review=False))
    reasoning = [c for c in contexts if c["role"] == "reasoning"]
    assert all(set(c["supported_cwes"]) == {"CWE-22", "CWE-78", "CWE-79", "CWE-94"} for c in reasoning)
    assert len({c["focus"]["method_id"] for c in reasoning}) == len(reasoning) == 2
    assert summary["strict_verified"] == 0
    assert summary["stop_reason"] == "GRAPH_COMPLETE"
    assert not any(x in json.dumps(contexts) for x in ("fix_info", "true_cwe", "expected", "targets", "sample_0055"))


def test_last_targeted_read_gets_a_synthesis_turn_instead_of_being_discarded(runner):
    main = next(m for m in runner.methods.values() if m.simple_name == "handle")
    helper = next(m for m in runner.methods.values() if m.simple_name == "command")
    calls = []
    def reason(context):
        calls.append(context)
        if len(calls) == 1:
            value = {"requests": [{"action": "search_symbols", "query": "command"}]}
        elif len(calls) == 2:
            value = {"requests": [{"action": "inspect_entity", "entity_id": helper.entity_id}]}
        else:
            assert any(p["method_id"] == helper.entity_id for p in context["source_evidence"])
            value = {"candidates": [grounded(runner)]}
        return ModelTurn(json.dumps(value))
    runner.team = AgentTeam(reason, reason, reason)
    runner.explore({"method_id": main.entity_id, "cwe": "CWE-79", "reason": "Fixture focus"})
    assert len(calls) == 3
    assert len(runner.candidates) == 1


def test_budget_admission_stop_retains_frozen_output_without_claiming_execution_failure(tmp_path):
    from java_vuln_research.work1_agent.experiment_policy import BudgetExceeded
    source = tmp_path / "source"
    source.mkdir()
    (source / "Fixture.java").write_text(TEXT)
    def policy(context):
        if context["role"] == "discovery": return ModelTurn('{"leads":[]}')
        raise BudgetExceeded("No remaining admission capacity; no provider request started.")
    result = run_benchmark(source, tmp_path / "run", AgentTeam(policy, policy, policy))
    assert result["stop_reason"] == "BENCHMARK_BUDGET_COMPLETE"
    assert not result["protocol_failed_nodes"]
    assert (tmp_path / "run/benchmark-candidates.jsonl").exists()


def test_benchmark_budget_uses_request_estimate_without_strict_verification_reserve(tmp_path):
    from java_vuln_research.work1_agent.experiment_policy import RequestJournal
    class Provider:
        system_prompt, model, endpoint, max_output_tokens = "fixture", "fixture", "unused", 512
        def __call__(self, context):
            return ModelTurn('{}', {"total_tokens": 100})
    journal = RequestJournal(tmp_path / "journal.jsonl", max_requests=2, max_tokens=10000,
                             max_seconds=60, binding="fixture", verification_reserve=False)
    journal.wrap(Provider())({"role": "reasoning", "benchmark_first": True})
    row = json.loads((tmp_path / "journal.jsonl").read_text().splitlines()[0])
    assert row["reserve_method"] != "legacy_utf8_reserve"
    assert row["held_verification_requests"] == row["held_verification_tokens"] == 0


@pytest.fixture
def scoring(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "reproduction"))
    return importlib.import_module("agentic_detection.benchmark_track")


def test_paper_equations_match_compatible_scorer_on_nested_methods_and_empty_outputs(tmp_path, scoring):
    (tmp_path / "F.java").write_text('class F {\n void source() {}\n class Nested {\n void sink() {}\n }\n}\n')
    fixes = [{"file": "F.java", "class": "Nested", "method": "sink"}]
    records = [{"fingerprint": str(i), "tainted_data_flow": [[{"file_path": "F.java", "line_number": line}]]}
               for i, line in enumerate([4, 2, 2])]
    metric = scoring.evaluate(tmp_path, records, fixes)
    empty = scoring.evaluate(tmp_path, [], fixes)
    assert metric["recall"] == 1 and metric["precision"] == pytest.approx(1 / 3)
    assert metric["f1"] == pytest.approx(0.5)
    result = scoring.aggregate([metric, empty])
    assert result["#Detected"] == 1
    assert result["AvgFDR"] == pytest.approx(2 / 3)
    assert result["AvgF1"] == pytest.approx(0.25)
    assert result["fdr_denominator"] == 1
    assert result["expected"] == 2


def test_no_output_and_missing_labels_are_distinguished(tmp_path, scoring):
    (tmp_path / "F.java").write_text("class F { void method() {} }")
    missing = scoring.evaluate(tmp_path, [], [])
    result = scoring.aggregate([missing, {"status": "failed"}])
    assert result["#Detected"] == 0
    assert result["AvgF1"] is None and result["AvgFDR"] is None
    assert result["failed_or_unscorable"] == 2
