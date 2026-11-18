import json

import pytest

from java_vuln_research.work1_agent.harness import HarnessLimits, ModelTurn, run_harness


@pytest.mark.parametrize("feedback", ["fixed", "adaptive"])
def test_source_proposals_can_be_repaired_and_form_a_candidate(tmp_path, feedback):
    repository = tmp_path / "source"
    repository.mkdir()
    (repository / "Endpoint.java").write_text(
        "class Endpoint {\n"
        "  void consume(String input) throws Exception {\n"
        "    Runtime.getRuntime().exec(input);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    output = tmp_path / feedback
    method = call = method_proof = call_proof = None
    seen = []

    def policy(context):
        nonlocal method, call, method_proof, call_proof
        seen.append(context)
        step = len(seen)
        if step == 1:
            action = {"action": "search_symbols", "kind": "METHOD", "query": "consume"}
        elif step == 2:
            method = context["observations"][-1]["matches"][0]["entity"]["entity_id"]
            action = endpoint("EXTERNAL_INPUT", role(method, "PARAMETER"), "HTTP", [])
        elif step == 3:
            assert context["observations"][-1]["status"] == "NEEDS_MORE_EVIDENCE"
            assert ("recovery" in context) == (feedback == "adaptive")
            assert ("propose" not in context["allowed_actions"]) == (feedback == "adaptive")
            action = {"action": "inspect_entity", "entity_id": method}
        elif step == 4:
            method_proof = context["evidence_refs"][-1]["evidence_id"]
            action = endpoint("EXTERNAL_INPUT", role(method, "PARAMETER"), "HTTP", [method_proof])
        elif step == 5:
            action = {"action": "search_symbols", "kind": "CALL", "query": "exec"}
        elif step == 6:
            call = context["observations"][-1]["matches"][0]["entity"]["entity_id"]
            action = {"action": "inspect_entity", "entity_id": call}
        elif step == 7:
            call_proof = context["evidence_refs"][-1]["evidence_id"]
            action = endpoint("SECURITY_EFFECT", role(call, "ARGUMENT"), "PROCESS_EXECUTION", [call_proof])
        elif step == 8:
            action = {
                "action": "propose",
                "proposal": {
                    "proposal_type": "WRAPPER_FLOW",
                    "subject": {"entity_id": method, "role": "METHOD"},
                    "source": role(method, "PARAMETER"),
                    "target": role(call, "ARGUMENT"),
                    "scope": {"kind": "CALLABLE", "entity_ids": [method, call]},
                    "evidence_refs": [method_proof, call_proof],
                    "reason": "The parameter is passed as argument zero to exec.",
                },
            }
        else:
            action = {"action": "finish"}
        return ModelTurn(json.dumps(action), {"total_tokens": 20})

    result = run_harness(repository, output, policy, feedback=feedback, limits=HarnessLimits(9, 4))
    assert result["stop_reason"] == "FINISHED"
    assert result["admitted_proposals"] == 3
    assert result["candidate_paths"] == 1
    assert result["eligible_for_detection_metric"] is False
    assert result["tool_calls"] == 4
    assert result["reported_usage"] == {"total_tokens": 180}
    events = [json.loads(line) for line in (output / "trace.jsonl").read_text(encoding="utf-8").splitlines()]
    assert events[1]["result"]["proposal"]["proposal_id"] == events[3]["result"]["proposal"]["proposal_id"]
    assert events[3]["status"] == "ADMISSIBLE"
    assert len((output / "candidate_paths.jsonl").read_text(encoding="utf-8").splitlines()) == 1


def role(entity_id, name):
    return {"entity_id": entity_id, "role": name, "index": 0}


def endpoint(proposal_type, subject, category, evidence):
    return {
        "action": "propose",
        "proposal": {
            "proposal_type": proposal_type,
            "subject": subject,
            "scope": {"kind": "ENTITY", "entity_ids": [subject["entity_id"]]},
            "evidence_refs": evidence,
            "reason": "Hypothesis for the controlled fixture.",
            "semantic_category": category,
        },
    }


def test_budget_and_artifact_isolation(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    output = tmp_path / "results"
    calls = []

    def policy(context):
        calls.append(context)
        return ModelTurn('{"action":"search_symbols","query":"absent"}')

    with pytest.raises(ValueError, match="outside"):
        run_harness(repository, repository / "results", policy)
    result = run_harness(repository, output, policy, limits=HarnessLimits(2, 1))
    assert result["stop_reason"] == "TURN_BUDGET_EXHAUSTED"
    assert result["tool_calls"] == 1
    assert len(calls) == 2
    assert "TOOL_BUDGET_EXHAUSTED" in (output / "trace.jsonl").read_text(encoding="utf-8")
    with pytest.raises(FileExistsError):
        run_harness(repository, output, policy)
    assert len(calls) == 2
