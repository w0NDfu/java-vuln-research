from __future__ import annotations

import json
from pathlib import Path

from java_vuln_research.work1_agent.agent import AgentBudgetLimits, MockLLMClient
from java_vuln_research.work1_agent.agent.llm_client import LLMClientConfig
from java_vuln_research.work1_agent.hybrid_graph.path import SearchLimits
from java_vuln_research.work1_agent.m7_killtest.detector import run_detector_project


def test_formal_detector_project_freezes_without_benchmark_input(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "Sample.java").write_text("class Sample { void run() {} }\n", encoding="utf-8")
    frozen_path = tmp_path / "detector_manifest.json"
    frozen = {
        "manifest_id": "m7detector-test",
        "schemas": {},
        "controller": {"max_stagnant_rounds": 3, "max_model_output_retries": 1},
        "component_lineage": {},
        "baseline_lineage": {"codeql_version": "test"},
        "prompt": {"sha256": "test"},
        "tool_catalog_sha256": "test",
        "path_bounds": {"max_depth": 12, "max_paths": 20, "max_nodes_expanded": 2000},
        "benchmark_informed": False,
    }
    frozen_path.write_text(json.dumps(frozen), encoding="utf-8")
    config = LLMClientConfig(provider="test", model_id="test", base_url="https://example.invalid/v1", api_key="test")
    client = MockLLMClient(
        [
            {
                "action_type": "STOP",
                "arguments": {},
                "proposal": None,
                "stop_reason": "INSUFFICIENT_EVIDENCE",
                "reason": "No grounded evidence was collected.",
            }
        ]
    )
    output = tmp_path / "output"
    summary = run_detector_project(
        project={
            "project_id": "PTEST",
            "repository_root": str(source_root),
            "repository_revision": "abc",
            "codeql_db_path": "",
            "codeql_db_ready": False,
            "codeql_db_identity": {"status": "UNAVAILABLE"},
            "native_baseline": {"candidate_path_count": 0},
        },
        frozen_manifest_path=frozen_path,
        frozen_manifest=frozen,
        repository_root=repo_root,
        schema_root=repo_root / "schemas",
        output=output,
        git_sha="abc",
        config=config,
        limits=AgentBudgetLimits(),
        path_limits=SearchLimits(),
        llm_client=client,
    )
    assert summary["detector_frozen"] is True
    assert summary["runtime_input_audit_status"] == "PASS"
    detector_manifest = json.loads((output / "detector_manifest.json").read_text(encoding="utf-8"))
    assert detector_manifest["detector_frozen"] is True
    runtime_manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))["detector_input_manifest"]
    assert runtime_manifest["no_leakage_pass"] is True
    assert all("case" not in entry["logical_name"] for entry in runtime_manifest["entries"])
