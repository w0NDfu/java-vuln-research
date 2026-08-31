from __future__ import annotations

import json
import shutil
from pathlib import Path

from java_vuln_research.work1_agent.agent import (
    ActionType,
    LLMAPIProtocol,
    LLMClientConfig,
    MockLLMClient,
    StopReason,
    StructuredOutputMode,
)
from java_vuln_research.work1_agent.agent.controlled_smoke import (
    _decision,
    _proposal_factory,
    _tool_decision,
)
from java_vuln_research.work1_agent.agent.real_model_preflight import (
    PREFLIGHT_SELECTION_BASIS,
    PREFLIGHT_VERSION,
    PreflightProject,
    run_real_model_preflight,
)
from java_vuln_research.work1_agent.proposal import (
    EntityRole,
    EntityRoleRef,
    ProposalScope,
    ProposalType,
    ScopeKind,
)
from java_vuln_research.work1_agent.repository.entity import ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "work1_agent_m7"
SMALL_REVISION = "1" * 40
MEDIUM_REVISION = "2" * 40


def _configuration(small: Path, medium: Path) -> dict[str, object]:
    return {
        "schema_version": 1,
        "preflight_version": PREFLIGHT_VERSION,
        "selection_basis": PREFLIGHT_SELECTION_BASIS,
        "benchmark_informed": False,
        "allowed_for_agent_runtime": True,
        "required_model": {
            "provider": "openlux",
            "exact_model_id": "claude-opus-5",
            "base_url": "https://api.openlux.ai/v1",
            "endpoint_url": "https://api.openlux.ai/v1/chat/completions",
            "api_protocol": "OPENAI",
            "structured_output_mode": "TOOL_CALL",
            "temperature": 0.0,
            "max_output_tokens": 2048,
            "seed": None,
        },
        "projects": [
            {
                "project_id": "SMALL",
                "project_name": "public/small-project",
                "size_class": "SMALL",
                "source_root": str(small),
                "repository_revision": SMALL_REVISION,
                "expected_java_file_count": 1,
            },
            {
                "project_id": "MEDIUM",
                "project_name": "public/medium-project",
                "size_class": "MEDIUM",
                "source_root": str(medium),
                "repository_revision": MEDIUM_REVISION,
                "expected_java_file_count": 100,
            },
        ],
    }


def _client(project: PreflightProject, index: RepositoryIndex) -> MockLLMClient:
    pipeline = next(
        item
        for item in index.entities
        if item.kind is ProgramEntityKind.METHOD and item.simple_name == "controlledPipeline"
    )
    input_call = next(
        item
        for item in index.entities
        if item.kind is ProgramEntityKind.CALL
        and item.simple_name == "customExternalInput"
        and item.repository_relative_path == pipeline.repository_relative_path
    )
    return MockLLMClient(
        [
            _tool_decision(ActionType.SEARCH_SYMBOLS, {"query": "controlledPipeline", "max_hits": 30}),
            _tool_decision(ActionType.INSPECT_METHOD, {"entity_id": pipeline.entity_id, "context_lines": 0}),
            _proposal_factory(
                proposal_type=ProposalType.EXTERNAL_INPUT,
                subject=EntityRoleRef(input_call.entity_id, EntityRole.CALL_RESULT),
                scope=ProposalScope(ScopeKind.ENTITY, (input_call.entity_id,), project.project_id),
                evidence_entity_ids=(input_call.entity_id, pipeline.entity_id),
                semantic_category="UNKNOWN",
                reason="The inspected method exposes one bounded input hypothesis.",
            ),
            _decision(stop=StopReason.INSUFFICIENT_EVIDENCE),
        ]
    )


def test_two_real_project_preflight_contract_is_automatically_audited(tmp_path: Path) -> None:
    small = tmp_path / "small"
    medium = tmp_path / "medium"
    shutil.copytree(FIXTURE, small)
    source = next(FIXTURE.rglob("*.java"))
    for index in range(100):
        target = medium / "src" / "main" / "java" / "com" / "example" / f"Case{index:03}.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    config_path = tmp_path / "preflight.json"
    config_path.write_text(json.dumps(_configuration(small, medium)), encoding="utf-8")
    model = LLMClientConfig(
        "openlux",
        "claude-opus-5",
        "https://api.openlux.ai/v1",
        "unit-secret-key",
        endpoint_url="https://api.openlux.ai/v1/chat/completions",
        seed=None,
        structured_output_mode=StructuredOutputMode.TOOL_CALL,
        api_protocol=LLMAPIProtocol.OPENAI,
    )

    summary = run_real_model_preflight(
        config_path=config_path,
        schema_root=Path(__file__).resolve().parents[2] / "schemas",
        artifact_root=tmp_path / "artifacts",
        git_sha="TEST-SHA",
        model_config=model,
        client_factory=_client,
        revision_resolver=lambda root: SMALL_REVISION if root.name == "small" else MEDIUM_REVISION,
    )

    assert summary["pass"] is True
    assert summary["freeze_allowed"] is True
    assert summary["size_classes"] == ["SMALL", "MEDIUM"]
    assert summary["selection_input_manifest"]["no_leakage_pass"] is True
    for project in summary["projects"]:
        assert project["pass"] is True
        assert all(project["checks"].values())
        assert project["tool_sequence"] == ["SEARCH_SYMBOLS", "INSPECT_METHOD"]
        assert project["proposal_count"] == 1
        assert project["normalization_audit"]["pass"] is True
        assert project["normalization_audit"]["unaccounted_model_call_ids"] == []
    output_text = "".join(
        path.read_text(encoding="utf-8")
        for path in (tmp_path / "artifacts").rglob("*")
        if path.is_file()
    )
    assert "unit-secret-key" not in output_text


def test_preflight_model_endpoint_must_be_exact_and_unconcatenated(tmp_path: Path) -> None:
    small = tmp_path / "small"
    medium = tmp_path / "medium"
    small.mkdir()
    medium.mkdir()
    config_path = tmp_path / "preflight.json"
    config_path.write_text(json.dumps(_configuration(small, medium)), encoding="utf-8")
    concatenating_model = LLMClientConfig(
        "openlux",
        "claude-opus-5",
        "https://api.openlux.ai/v1",
        "unit-secret-key",
        endpoint_url=None,
        seed=None,
        structured_output_mode=StructuredOutputMode.TOOL_CALL,
        api_protocol=LLMAPIProtocol.OPENAI,
    )

    try:
        run_real_model_preflight(
            config_path=config_path,
            schema_root=Path(__file__).resolve().parents[2] / "schemas",
            artifact_root=tmp_path / "artifacts",
            git_sha="TEST-SHA",
            model_config=concatenating_model,
        )
    except ValueError as exc:
        assert "configuration mismatch" in str(exc)
    else:
        raise AssertionError("preflight accepted a model configuration that would append an endpoint path")
