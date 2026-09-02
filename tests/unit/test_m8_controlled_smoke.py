from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.agent import (
    LLMAPIProtocol,
    LLMClientConfig,
    MockLLMClient,
    ModelCallError,
    ModelFailureClass,
    StructuredOutputMode,
)
from java_vuln_research.work1_agent.m8_experiment import ProjectUsageLedger
from java_vuln_research.work1_agent.m8_multiagent import (
    read_board_snapshot,
    replay_board,
)
from java_vuln_research.work1_agent.m8_multiagent.contracts import SpecialistRole
from java_vuln_research.work1_agent.m8_multiagent.controlled_smoke import (
    ARTIFACT_FILES,
    M8ModelConfigs,
    _deterministic_clients,
    run_controlled_smoke,
)
from java_vuln_research.work1_agent.repository.indexer import build_repository_index

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "work1_agent_m8"
SCHEMAS = ROOT / "schemas"
SECRET_MARKER = "controlled-secret-must-not-appear"


def _config(model_id: str) -> LLMClientConfig:
    return LLMClientConfig(
        provider="controlled-openai-compatible",
        model_id=model_id,
        base_url="https://llm.invalid/v1",
        endpoint_url="https://llm.invalid/v1/chat/completions",
        api_key=SECRET_MARKER,
        api_key_env="CONTROLLED_TEST_API_KEY",
        temperature=0,
        seed=None,
        structured_output_mode=StructuredOutputMode.JSON_OBJECT,
        api_protocol=LLMAPIProtocol.OPENAI,
    )


def _configs() -> M8ModelConfigs:
    return M8ModelConfigs(
        coordinator=_config("claude-opus-5"),
        specialist=_config("claude-sonnet-5"),
    )


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_controlled_smoke_forms_path_and_writes_replayable_audited_artifacts(
    tmp_path: Path,
) -> None:
    index = build_repository_index(FIXTURE)
    coordinator, specialists = _deterministic_clients(index)
    output = tmp_path / "controlled"

    summary = run_controlled_smoke(
        repository_root=FIXTURE,
        schema_root=SCHEMAS,
        artifact_root=output,
        git_sha="TEST-M8-CONTROLLED",
        branch="work1/test-m8-controlled",
        coordinator_client=coordinator,
        specialist_clients=specialists,
        model_configs=_configs(),
    )

    assert summary["candidate_paths"] == 1
    assert summary["input_findings"] == 1
    assert summary["effect_findings"] == 1
    assert summary["bridge_findings"] == 1
    assert summary["admissible_proposals"] == 3
    assert summary["stop_reason"] == "PATH_FORMED"
    assert summary["artifact_audit_pass"] is True
    assert summary["no_leakage_pass"] is True
    assert all((output / name).is_file() for name in ARTIFACT_FILES)

    paths = _read_jsonl(output / "candidate_paths.jsonl")
    assert len(paths) == 1
    assert paths[0]["provenance"]["warning"] == (
        "candidate path is not a confirmed vulnerability"
    )
    snapshot = read_board_snapshot(output / "evidence_board.json")
    assert replay_board(output / "board_events.jsonl").to_dict() == snapshot.to_dict()

    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["git_sha"] == "TEST-M8-CONTROLLED"
    assert manifest["branch"] == "work1/test-m8-controlled"
    assert manifest["created_at_utc"].endswith("+00:00")
    assert manifest["schema_hashes"]["security_proposal.schema.json"]
    assert manifest["tool_catalog_sha256"]
    assert manifest["components"]["m4_evidence_gate"]["source_sha256"]
    assert manifest["components"]["m5_hybrid_graph"]["source_sha256"]
    assert manifest["shared_project_budget_sha256"]
    assert manifest["usage_ledger_sha256"] == hashlib.sha256(
        (output / "usage_ledger.json").read_bytes()
    ).hexdigest()
    assert manifest["path_limits"] == {
        "max_depth": 12,
        "max_paths": 20,
        "max_nodes_expanded": 2000,
    }
    assert any(name.startswith("java:") for name in manifest["detector_input_hashes"])
    assert any(name.startswith("schema:") for name in manifest["detector_input_hashes"])
    assert set(manifest["agents"]) == {
        "coordinator_agent",
        "input_agent",
        "effect_agent",
        "semantic_bridge_agent",
    }
    assert all(value["id"] == value["name"] for value in manifest["agents"].values())
    assert manifest["agents"]["coordinator_agent"]["exact_model_id"] == "claude-opus-5"
    assert {
        manifest["agents"][name]["exact_model_id"]
        for name in ("input_agent", "effect_agent", "semantic_bridge_agent")
    } == {"claude-sonnet-5"}
    assert {role: manifest["prompts"][role] for role in ("input", "effect", "bridge")} == {
        "input": {
            "version": "M8_INPUT_AGENT_V3",
            "sha256": "65f79a095c8a12b040c6a46971dd89bbe6480a882d60425ad643d64fac24ce31",
        },
        "effect": {
            "version": "M8_EFFECT_AGENT_V3",
            "sha256": "4507245419c1ddceccc02249daa2ab2583c19d697bc220c8f012bb24765b8539",
        },
        "bridge": {
            "version": "M8_BRIDGE_AGENT_V3",
            "sha256": "96318fc66e1b79bd318784f338d34d825cf04b23971fd795323f7081d19d5517",
        },
    }
    for name, expected in manifest["output_hashes"].items():
        assert hashlib.sha256((output / name).read_bytes()).hexdigest() == expected

    ledger = ProjectUsageLedger.from_canonical_json(
        (output / "usage_ledger.json").read_text(encoding="utf-8").rstrip("\n")
    )
    usage = ledger.summary()
    charged = usage["charged_usage"]
    assert {
        key: charged[key]
        for key in (
            "model_attempts",
            "output_tokens",
            "repository_tool_calls",
            "codeql_calls",
            "proposal_families",
            "admissible_proposals",
            "candidate_paths",
        )
    } == {
        "model_attempts": 13,
        "output_tokens": 13 * 2_048,
        "repository_tool_calls": 3,
        "codeql_calls": 0,
        "proposal_families": 3,
        "admissible_proposals": 3,
        "candidate_paths": 1,
    }
    assert charged["canonical_input_tokens"] > 0
    assert charged["wall_clock_ms"] >= 0
    assert usage["model_attempts_by_actor"] == {
        "coordinator": 7,
        "specialist": 6,
    }
    assert usage["terminal_status_counts"] == {"success": 23}
    assert usage["pending_attempt_ids"] == []
    assert usage["is_breached"] is False

    audit = json.loads((output / "artifact_audit.json").read_text(encoding="utf-8"))
    leakage = json.loads((output / "no_leakage_audit.json").read_text(encoding="utf-8"))
    assert audit["required_files_present"] is True
    assert audit["no_leakage_pass"] is True
    assert leakage["status"] == "PASS"
    assert leakage["secret_hit_files"] == []
    assert SECRET_MARKER not in "".join(
        path.read_text(encoding="utf-8")
        for path in output.rglob("*")
        if path.is_file()
    )


def test_controlled_smoke_refuses_to_overwrite_non_empty_artifact_root(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    (output / "preserve.txt").write_text("user-owned", encoding="utf-8")

    with pytest.raises(FileExistsError, match="refusing to overwrite"):
        run_controlled_smoke(
            repository_root=FIXTURE,
            schema_root=SCHEMAS,
            artifact_root=output,
            git_sha="TEST-M8-CONTROLLED",
        )

    assert (output / "preserve.txt").read_text(encoding="utf-8") == "user-owned"


def test_controlled_smoke_rejects_partial_or_unmanifested_client_configuration(
    tmp_path: Path,
) -> None:
    coordinator, specialists = _deterministic_clients(build_repository_index(FIXTURE))
    partial_output = tmp_path / "partial"
    with pytest.raises(ValueError, match="supplied together"):
        run_controlled_smoke(
            repository_root=FIXTURE,
            schema_root=SCHEMAS,
            artifact_root=partial_output,
            git_sha="TEST-M8-CONTROLLED",
            coordinator_client=coordinator,
        )
    assert not partial_output.exists()

    unmanifested_output = tmp_path / "unmanifested"
    with pytest.raises(ValueError, match="explicit model configs"):
        run_controlled_smoke(
            repository_root=FIXTURE,
            schema_root=SCHEMAS,
            artifact_root=unmanifested_output,
            git_sha="TEST-M8-CONTROLLED",
            coordinator_client=coordinator,
            specialist_clients=specialists,
        )
    assert not unmanifested_output.exists()


@pytest.mark.parametrize(
    ("coordinator_response", "expected_status"),
    [
        ({"unexpected": "shape"}, "invalid-output"),
        (ModelCallError(ModelFailureClass.MODEL_TIMEOUT, "controlled"), "timeout"),
        (
            ModelCallError(ModelFailureClass.MODEL_UNAVAILABLE, "controlled"),
            "provider-error",
        ),
    ],
)
def test_controlled_smoke_ledgers_coordinator_failure_before_audited_stop(
    tmp_path: Path,
    coordinator_response: object,
    expected_status: str,
) -> None:
    output = tmp_path / expected_status
    summary = run_controlled_smoke(
        repository_root=FIXTURE,
        schema_root=SCHEMAS,
        artifact_root=output,
        git_sha="TEST-M8-FAILURE-LEDGER",
        coordinator_client=MockLLMClient([coordinator_response]),
        specialist_clients={role: MockLLMClient([]) for role in SpecialistRole},
        model_configs=_configs(),
    )

    ledger = ProjectUsageLedger.from_canonical_json(
        (output / "usage_ledger.json").read_text(encoding="utf-8").rstrip("\n")
    )
    assert ledger.summary()["terminal_status_counts"] == {expected_status: 1}
    assert ledger.summary()["pending_attempt_ids"] == []
    assert summary["artifact_audit_pass"] is True
    assert summary["no_leakage_pass"] is True


@pytest.mark.parametrize(
    ("coordinator", "specialist", "message"),
    [
        (replace(_config("claude-opus-5"), model_id="wrong"), _config("claude-sonnet-5"), "Coordinator exact model"),
        (_config("claude-opus-5"), replace(_config("claude-sonnet-5"), model_id="wrong"), "specialist exact model"),
        (replace(_config("claude-opus-5"), endpoint_url=None), _config("claude-sonnet-5"), "exact endpoint"),
        (replace(_config("claude-opus-5"), temperature=0.1), _config("claude-sonnet-5"), "temperature=0"),
        (replace(_config("claude-opus-5"), seed=0), _config("claude-sonnet-5"), "seed omitted"),
        (
            replace(
                _config("claude-opus-5"),
                structured_output_mode=StructuredOutputMode.TOOL_CALL,
            ),
            _config("claude-sonnet-5"),
            "JSON_OBJECT",
        ),
    ],
)
def test_model_configs_enforce_exact_frozen_runtime(
    coordinator: LLMClientConfig,
    specialist: LLMClientConfig,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        M8ModelConfigs(coordinator=coordinator, specialist=specialist)


def test_model_configs_read_role_specific_environment_without_secret_leakage() -> None:
    env: dict[str, str] = {}
    for prefix, model in (
        ("M8_COORDINATOR_LLM_", "claude-opus-5"),
        ("M8_SPECIALIST_LLM_", "claude-sonnet-5"),
    ):
        env.update(
            {
                prefix + "PROVIDER": "controlled",
                prefix + "MODEL": model,
                prefix + "BASE_URL": "https://llm.invalid/v1",
                prefix + "ENDPOINT": "https://llm.invalid/v1/chat/completions",
                prefix + "API_KEY": SECRET_MARKER,
                prefix + "TEMPERATURE": "0",
                prefix + "OUTPUT_MODE": "JSON_OBJECT",
                prefix + "API_PROTOCOL": "OPENAI",
            }
        )

    manifest = M8ModelConfigs.from_environment(env).to_manifest_dict()

    assert manifest["coordinator"]["exact_model_id"] == "claude-opus-5"
    assert manifest["specialists"]["exact_model_id"] == "claude-sonnet-5"
    assert manifest["coordinator"]["seed"] is None
    assert manifest["specialists"]["seed"] is None
    assert SECRET_MARKER not in json.dumps(manifest)
