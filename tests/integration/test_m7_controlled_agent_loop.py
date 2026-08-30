from __future__ import annotations

import json
from pathlib import Path

from java_vuln_research.work1_agent.agent import LLMClientConfig, MockLLMClient, ModelCallError, ModelFailureClass
from java_vuln_research.work1_agent.agent.controlled_smoke import run_controlled_real_llm_smoke, run_controlled_smoke


def test_controlled_agent_loop_writes_audited_path_artifacts(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    summary = run_controlled_smoke(
        repository_root=root / "tests" / "fixtures" / "work1_agent_m7",
        schema_root=root / "schemas",
        artifact_root=tmp_path / "m7_agent",
        git_sha="TEST-SHA",
    )
    project = tmp_path / "m7_agent" / "CONTROLLED"
    audit = json.loads((project / "artifact_audit.json").read_text(encoding="utf-8"))

    assert summary["stop_reason"] == "PATH_FORMED"
    assert summary["artifact_audit_pass"] is True
    assert summary["no_leakage_pass"] is True
    assert summary["tool_sequence"] == ["SEARCH_SYMBOLS", "INSPECT_METHOD"]
    assert summary["proposal_sequence"] == ["EXTERNAL_INPUT", "LIBRARY_FLOW", "SECURITY_EFFECT"]
    assert summary["gate_status_sequence"] == ["ADMISSIBLE", "ADMISSIBLE", "ADMISSIBLE"]
    assert summary["candidate_path_count"] == 1
    assert audit["required_files_present"] is True
    assert (project / "evidence_refs.jsonl").stat().st_size > 0
    assert (project / "candidate_paths.jsonl").stat().st_size > 0

    tool_calls = [json.loads(line) for line in (project / "tool_calls.jsonl").read_text(encoding="utf-8").splitlines()]
    proposals = [json.loads(line) for line in (project / "proposals.jsonl").read_text(encoding="utf-8").splitlines()]
    gate_results = [json.loads(line) for line in (project / "gate_results.jsonl").read_text(encoding="utf-8").splitlines()]

    assert [item["tool_name"] for item in tool_calls] == ["SEARCH_SYMBOLS", "INSPECT_METHOD"]
    assert [item["proposal_type"] for item in proposals] == ["EXTERNAL_INPUT", "LIBRARY_FLOW", "SECURITY_EFFECT"]
    assert all(item["evidence_refs"] for item in proposals)
    assert all(item["provenance"]["originating_tool_call_ids"] for item in proposals)
    assert [item["status"] for item in gate_results] == ["ADMISSIBLE", "ADMISSIBLE", "ADMISSIBLE"]


def test_real_llm_controlled_runner_writes_fail_closed_artifacts(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    config = LLMClientConfig(
        "test-provider",
        "test-model",
        "https://model.example/v1",
        "never-serialize-this-secret",
        endpoint_url="https://model.example/v1/chat/completions",
    )
    summary = run_controlled_real_llm_smoke(
        repository_root=root / "tests" / "fixtures" / "work1_agent_m7",
        schema_root=root / "schemas",
        artifact_root=tmp_path / "m7_agent",
        git_sha="TEST-SHA",
        config=config,
        llm_client=MockLLMClient([ModelCallError(ModelFailureClass.MODEL_UNAVAILABLE, "controlled outage")]),
    )
    project = tmp_path / "m7_agent" / "CONTROLLED_REAL_LLM"
    manifest_text = (project / "manifest.json").read_text(encoding="utf-8")

    assert summary["stop_reason"] == "OTHER"
    assert summary["failures"][0]["failure_class"] == "MODEL_UNAVAILABLE"
    assert summary["artifact_audit_pass"] is True
    assert summary["no_leakage_pass"] is True
    assert "never-serialize-this-secret" not in manifest_text
    assert json.loads(manifest_text)["endpoint_mode"] == "EXACT"
