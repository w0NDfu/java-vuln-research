from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from java_vuln_research.work1_agent.agent import AgentBudgetLimits, MockLLMClient
from java_vuln_research.work1_agent.agent.controller import CONTROLLER_VERSION
from java_vuln_research.work1_agent.agent.llm_client import LLMClientConfig
from java_vuln_research.work1_agent.agent.observation import (
    MAX_BOOTSTRAP_OBSERVATION_CHARS,
    MAX_TOOL_GROUNDED_OBSERVATION_CHARS,
    OBSERVATION_VERSION,
    bounded_tool_catalog,
)
from java_vuln_research.work1_agent.agent.prompt import build_system_prompt, prompt_sha256
from java_vuln_research.work1_agent.agent.structured_output import NORMALIZER_VERSION
from java_vuln_research.work1_agent.hybrid_graph.path import SearchLimits
from java_vuln_research.work1_agent.m7_killtest.detector import (
    _validate_frozen_contract,
    run_detector_project,
)
from java_vuln_research.work1_agent.proposal.model import canonical_json


def test_frozen_contract_rejects_runtime_protocol_drift(tmp_path: Path) -> None:
    config = LLMClientConfig(provider="test", model_id="test", base_url="https://example.invalid/v1", api_key="test")
    catalog = bounded_tool_catalog()
    manifest = {
        "detector_input_frozen": True,
        "benchmark_informed": False,
        "git_sha": "abc123",
        "model": config.to_manifest_dict(),
        "prompt": {"sha256": prompt_sha256(build_system_prompt(catalog))},
        "structured_output_normalizer": {"version": NORMALIZER_VERSION},
        "observation": {
            "schema_version": OBSERVATION_VERSION,
            "bootstrap_max_chars": MAX_BOOTSTRAP_OBSERVATION_CHARS,
            "tool_grounded_max_chars": MAX_TOOL_GROUNDED_OBSERVATION_CHARS,
        },
        "tool_catalog_sha256": hashlib.sha256(canonical_json(catalog).encode("utf-8")).hexdigest(),
        "controller": {
            "version": CONTROLLER_VERSION,
            "max_stagnant_rounds": 3,
            "max_model_output_retries": 2,
        },
        "schemas": {},
        "budget": AgentBudgetLimits().to_dict(),
        "path_bounds": {
            "max_depth": SearchLimits().max_depth,
            "max_paths": SearchLimits().max_paths,
            "max_nodes_expanded": SearchLimits().max_nodes_expanded,
        },
    }
    limits, path_limits = _validate_frozen_contract(
        manifest,
        config=config,
        schema_root=tmp_path,
        git_sha="abc123",
    )
    assert limits == AgentBudgetLimits()
    assert path_limits == SearchLimits()

    mutations = (
        ("git_sha", "different"),
        ("structured_output_normalizer", {"version": "different"}),
        ("observation", {**manifest["observation"], "bootstrap_max_chars": 1}),
        ("tool_catalog_sha256", "0" * 64),
        ("controller", {**manifest["controller"], "version": "different"}),
    )
    for field, value in mutations:
        drifted = copy.deepcopy(manifest)
        drifted[field] = value
        try:
            _validate_frozen_contract(
                drifted,
                config=config,
                schema_root=tmp_path,
                git_sha="abc123",
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"frozen contract drift was accepted: {field}")


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
