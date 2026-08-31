"""Formal M7 detector phase.

This module deliberately has no dependency on the M6 evaluator, selection
manifest, or benchmark annotations.  Its only cohort input is the frozen,
project-only M7 detector manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from java_vuln_research.work1_agent.agent.budget import AgentBudgetLimits
from java_vuln_research.work1_agent.agent.controller import CONTROLLER_VERSION, AgentController
from java_vuln_research.work1_agent.agent.graph_adapter import AgentGraphPathAdapter
from java_vuln_research.work1_agent.agent.llm_client import (
    AnthropicMessagesLLMClient,
    LLMAPIProtocol,
    LLMClient,
    LLMClientConfig,
    OpenAICompatibleLLMClient,
)
from java_vuln_research.work1_agent.agent.killtest_manifest import resolved_source_root_identity
from java_vuln_research.work1_agent.agent.observation import (
    MAX_BOOTSTRAP_OBSERVATION_CHARS,
    MAX_TOOL_GROUNDED_OBSERVATION_CHARS,
    OBSERVATION_VERSION,
    bounded_tool_catalog,
)
from java_vuln_research.work1_agent.agent.parser import StrictActionParser
from java_vuln_research.work1_agent.agent.prompt import (
    build_system_prompt,
    prompt_sha256,
)
from java_vuln_research.work1_agent.agent.runtime import (
    PROJECT_ARTIFACT_FILES,
    write_controller_artifacts,
)
from java_vuln_research.work1_agent.agent.security_boundary import (
    RuntimeInputKind,
    RuntimeSecurityBoundary,
    runtime_roots,
)
from java_vuln_research.work1_agent.agent.state import AgentState
from java_vuln_research.work1_agent.agent.structured_output import NORMALIZER_VERSION
from java_vuln_research.work1_agent.agent.tool_adapter import (
    RepositoryCodeQLToolAdapter,
)
from java_vuln_research.work1_agent.codeql.analysis_tools import CodeQLAnalysisTools
from java_vuln_research.work1_agent.codeql.executor import CodeQLExecutor
from java_vuln_research.work1_agent.hybrid_graph.path import SearchLimits
from java_vuln_research.work1_agent.proposal import EvidenceGate
from java_vuln_research.work1_agent.proposal.model import canonical_json
from java_vuln_research.work1_agent.repository.indexer import build_repository_index

DETECTOR_RUN_VERSION = "WORK1_V11_M7_AUTONOMOUS_DETECTOR_V1"


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"JSON object required: {path}")
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(value) + "\n", encoding="utf-8", newline="\n")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_sha(repository_root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _model_client(config: LLMClientConfig) -> LLMClient:
    if config.api_protocol is LLMAPIProtocol.ANTHROPIC:
        return AnthropicMessagesLLMClient(config)
    return OpenAICompatibleLLMClient(config)


def _validate_frozen_contract(
    detector_manifest: Mapping[str, Any],
    *,
    config: LLMClientConfig,
    schema_root: Path,
    git_sha: str,
) -> tuple[AgentBudgetLimits, SearchLimits]:
    if not detector_manifest.get("detector_input_frozen") or detector_manifest.get("benchmark_informed") is not False:
        raise ValueError("M7 detector input is not a frozen annotation-blind manifest")
    if dict(detector_manifest.get("model") or {}) != config.to_manifest_dict():
        raise ValueError("runtime model configuration differs from the frozen M7-9 contract")
    if str(detector_manifest.get("git_sha") or "") != git_sha:
        raise ValueError("runtime Git SHA differs from the frozen M7-9 contract")
    prompt = build_system_prompt(bounded_tool_catalog())
    if prompt_sha256(prompt) != str(detector_manifest["prompt"]["sha256"]):
        raise ValueError("runtime system prompt differs from the frozen M7-9 contract")
    if dict(detector_manifest.get("structured_output_normalizer") or {}) != {"version": NORMALIZER_VERSION}:
        raise ValueError("runtime structured-output normalizer differs from the frozen M7-9 contract")
    expected_observation = {
        "schema_version": OBSERVATION_VERSION,
        "bootstrap_max_chars": MAX_BOOTSTRAP_OBSERVATION_CHARS,
        "tool_grounded_max_chars": MAX_TOOL_GROUNDED_OBSERVATION_CHARS,
    }
    if dict(detector_manifest.get("observation") or {}) != expected_observation:
        raise ValueError("runtime observation contract differs from the frozen M7-9 contract")
    tool_catalog_hash = hashlib.sha256(canonical_json(bounded_tool_catalog()).encode("utf-8")).hexdigest()
    if str(detector_manifest.get("tool_catalog_sha256") or "") != tool_catalog_hash:
        raise ValueError("runtime tool catalog differs from the frozen M7-9 contract")
    controller = dict(detector_manifest.get("controller") or {})
    if str(controller.get("version") or "") != CONTROLLER_VERSION:
        raise ValueError("runtime controller differs from the frozen M7-9 contract")
    for project in detector_manifest.get("projects") or ():
        project_id = str(project.get("project_id") or "UNKNOWN")
        lexical_root = Path(str(project.get("repository_root") or ""))
        if not lexical_root.is_absolute() or not lexical_root.is_dir():
            raise ValueError(f"frozen project source root is not ready: {project_id}")
        if dict(project.get("repository_resolved_root_identity") or {}) != resolved_source_root_identity(lexical_root):
            raise ValueError(f"runtime project source resolution differs from the frozen M7-9 contract: {project_id}")
    for name, expected in dict(detector_manifest.get("schemas") or {}).items():
        path = schema_root / name
        if not path.is_file() or _sha256(path) != expected:
            raise ValueError(f"runtime schema differs from frozen contract: {name}")
    limits = AgentBudgetLimits.from_dict(detector_manifest["budget"])
    path_limits = SearchLimits(**{name: int(value) for name, value in detector_manifest["path_bounds"].items()})
    return limits, path_limits


def _freeze_project(output: Path, *, project_id: str, input_manifest: Mapping[str, Any]) -> dict[str, Any]:
    names = [*PROJECT_ARTIFACT_FILES, "artifact_audit.json"]
    if (output / "runtime_input_audit.json").is_file():
        names.append("runtime_input_audit.json")
    hashes = {name: _sha256(output / name) for name in names}
    material = {
        "schema_version": 1,
        "detector_run_version": DETECTOR_RUN_VERSION,
        "project_id": project_id,
        "detector_frozen": True,
        "benchmark_informed": False,
        "detector_input_manifest_id": input_manifest.get("manifest_id"),
        "artifact_hashes": hashes,
    }
    _write_json(output / "detector_manifest.json", material)
    return material


def _write_setup_failure(
    output: Path,
    *,
    project: Mapping[str, Any],
    git_sha: str,
    failure_class: str,
    message: str,
) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    for name in PROJECT_ARTIFACT_FILES:
        if name.endswith(".jsonl"):
            (output / name).write_text("", encoding="utf-8")
    failure = {"failure_class": failure_class, "message": message, "round": 0, "retryable": False}
    summary = {
        "project_id": project["project_id"],
        "rounds": 0,
        "model_calls": 0,
        "tool_calls": 0,
        "proposals": 0,
        "admissible_proposals": 0,
        "candidate_path_count": 0,
        "stop_reason": "OTHER",
        "failures": [failure],
    }
    _write_json(output / "summary.json", summary)
    _write_json(
        output / "manifest.json",
        {
            "run_kind": "M7_AUTONOMOUS_KILLTEST_DETECTOR",
            "git_sha": git_sha,
            "project_id": project["project_id"],
            "benchmark_informed": False,
            "failure_manifest": [failure],
            "artifact_contract": list(PROJECT_ARTIFACT_FILES),
        },
    )
    audit = {
        "project_id": project["project_id"],
        "required_files_present": all((output / name).is_file() for name in PROJECT_ARTIFACT_FILES),
        "artifact_count": len(PROJECT_ARTIFACT_FILES),
        "artifacts": [],
        "no_leakage_pass": True,
    }
    _write_json(output / "artifact_audit.json", audit)
    _freeze_project(output, project_id=str(project["project_id"]), input_manifest={"manifest_id": "SETUP_FAILURE"})
    return summary


def run_detector_project(
    *,
    project: Mapping[str, Any],
    frozen_manifest_path: Path,
    frozen_manifest: Mapping[str, Any],
    repository_root: Path,
    schema_root: Path,
    output: Path,
    git_sha: str,
    config: LLMClientConfig,
    limits: AgentBudgetLimits,
    path_limits: SearchLimits,
    llm_client: LLMClient | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    project_id = str(project["project_id"])
    source_lexical_root = Path(str(project["repository_root"]))
    source_root = source_lexical_root.resolve()
    database = Path(str(project.get("codeql_db_path") or "")).resolve()
    db_ready = bool(project.get("codeql_db_ready"))
    output.mkdir(parents=True, exist_ok=True)
    query_root = repository_root / "codeql" / "work1_agent"
    boundary = RuntimeSecurityBoundary(
        project_id=project_id,
        repository_identity=f"{project_id}@{project.get('repository_revision', 'UNKNOWN')}",
        allowed_roots=runtime_roots(
            source_roots=[source_lexical_root, source_root],
            artifact_roots=[frozen_manifest_path.parent, output],
            schema_roots=[schema_root, query_root],
        ),
    )
    boundary.read_bytes(frozen_manifest_path, kind=RuntimeInputKind.RUNTIME_CONFIG, logical_name="frozen_detector_manifest")
    for name in sorted(dict(frozen_manifest.get("schemas") or {})):
        boundary.read_bytes(schema_root / name, kind=RuntimeInputKind.TRUSTED_SCHEMA, logical_name="schema:" + name)
    for query in sorted(query_root.glob("*.ql")):
        boundary.read_bytes(query, kind=RuntimeInputKind.TRUSTED_SCHEMA, logical_name="codeql-query:" + query.name)
    for source in sorted(source_root.rglob("*.java")):
        boundary.read_bytes(source, kind=RuntimeInputKind.JAVA_SOURCE, logical_name="java:" + source.relative_to(source_root).as_posix())

    index = build_repository_index(source_root)
    gate = EvidenceGate(repository_root=source_root, entities=index.entities, evidence_catalog={})
    graph = AgentGraphPathAdapter(
        project_id=project_id,
        entities=index.entities,
        evidence_gate=gate,
        native_paths=(),
        search_limits=path_limits,
        git_sha=git_sha,
    )
    codeql_tools: CodeQLAnalysisTools | None = None
    if db_ready:
        executor = CodeQLExecutor(artifact_root=output / "codeql_calls", timeout_seconds=90, threads=0)
        codeql_tools = CodeQLAnalysisTools(executor, query_root)
    state = AgentState.create(
        project_id=project_id,
        repository_identity=f"{project_id}@{project.get('repository_revision', 'UNKNOWN')}",
        provenance={"producer": DETECTOR_RUN_VERSION, "benchmark_informed": False},
        limits=limits,
    )
    controller = AgentController(
        state=state,
        repository_index=index,
        codeql_status={
            "project_id": project_id,
            "ready": db_ready,
            "status": "READY" if db_ready else "UNAVAILABLE",
            "database_identity": dict(project.get("codeql_db_identity") or {}),
        },
        llm_client=llm_client or _model_client(config),
        parser=StrictActionParser(schema_root),
        tool_adapter=RepositoryCodeQLToolAdapter(
            project_id=project_id,
            repository_index=index,
            security_boundary=boundary,
            codeql_tools=codeql_tools,
            codeql_database=database if db_ready else None,
            codeql_ready=db_ready,
        ),
        evidence_gate=gate,
        graph_path_adapter=graph,
        native_baseline_summary=dict(project.get("native_baseline") or {}),
        max_stagnant_rounds=int(frozen_manifest["controller"]["max_stagnant_rounds"]),
        max_model_output_retries=int(frozen_manifest["controller"]["max_model_output_retries"]),
    )
    result = controller.run()
    input_manifest = boundary.seal()
    input_audit = boundary.audit()
    wall_clock = round(time.monotonic() - started, 6)
    audit = write_controller_artifacts(
        result,
        output,
        run_manifest={
            "run_kind": "M7_AUTONOMOUS_KILLTEST_DETECTOR",
            "detector_run_version": DETECTOR_RUN_VERSION,
            "git_sha": git_sha,
            "repository_revision": project.get("repository_revision"),
            "codeql_version": frozen_manifest.get("baseline_lineage", {}).get("codeql_version"),
            "codeql_db_identity": dict(project.get("codeql_db_identity") or {}),
            "component_lineage": dict(frozen_manifest.get("component_lineage") or {}),
            "frozen_detector_manifest_id": frozen_manifest.get("manifest_id"),
            **config.to_manifest_dict(),
            "system_prompt_sha256": frozen_manifest["prompt"]["sha256"],
            "schema_hashes": dict(frozen_manifest.get("schemas") or {}),
            "tool_catalog_sha256": frozen_manifest.get("tool_catalog_sha256"),
            "path_bounds": dict(frozen_manifest.get("path_bounds") or {}),
            "wall_clock_seconds": wall_clock,
            "benchmark_informed": False,
        },
        input_manifest=input_manifest,
    )
    _write_json(output / "runtime_input_audit.json", input_audit)
    frozen = _freeze_project(output, project_id=project_id, input_manifest=input_manifest)
    return {
        **result.summary(),
        "candidate_path_count": len(result.state.active_candidate_path_ids),
        "input_manifest_id": input_manifest["manifest_id"],
        "runtime_input_audit_status": input_audit["status"],
        "artifact_audit_pass": audit["required_files_present"],
        "detector_frozen": frozen["detector_frozen"],
        "wall_clock_seconds": wall_clock,
    }


def run_detector(
    *,
    frozen_manifest_path: str | Path,
    repository_root: str | Path,
    schema_root: str | Path,
    output_root: str | Path,
    config: LLMClientConfig | None = None,
    client_factory: Callable[[Mapping[str, Any]], LLMClient] | None = None,
) -> dict[str, Any]:
    manifest_path = Path(frozen_manifest_path).resolve()
    repo = Path(repository_root).resolve()
    schemas = Path(schema_root).resolve()
    output = Path(output_root).resolve()
    output.mkdir(parents=True, exist_ok=True)
    freeze_path = output / "detector_output_manifest.json"
    if freeze_path.exists():
        raise ValueError("formal detector output is already frozen; refusing to overwrite it")
    frozen = _read_json(manifest_path)
    git_sha = _git_sha(repo)
    resolved_config = config or LLMClientConfig.from_environment()
    limits, path_limits = _validate_frozen_contract(
        frozen,
        config=resolved_config,
        schema_root=schemas,
        git_sha=git_sha,
    )
    rows: list[dict[str, Any]] = []
    project_manifests: dict[str, str] = {}
    for project in frozen["projects"]:
        project_id = str(project["project_id"])
        project_output = output / "projects" / project_id
        try:
            row = run_detector_project(
                project=project,
                frozen_manifest_path=manifest_path,
                frozen_manifest=frozen,
                repository_root=repo,
                schema_root=schemas,
                output=project_output,
                git_sha=git_sha,
                config=resolved_config,
                limits=limits,
                path_limits=path_limits,
                llm_client=client_factory(project) if client_factory else None,
            )
        except (OSError, RuntimeError, TypeError, ValueError) as exc:  # formal runs must preserve setup failures
            row = _write_setup_failure(
                project_output,
                project=project,
                git_sha=git_sha,
                failure_class="DETECTOR_SETUP_ERROR",
                message=f"{type(exc).__name__}: {exc}",
            )
        rows.append({"project_id": project_id, **row})
        project_manifests[project_id] = _sha256(project_output / "detector_manifest.json")
        _write_json(output / "detector_progress.json", {"completed_project_ids": [item["project_id"] for item in rows]})
    summary = {
        "schema_version": 1,
        "detector_run_version": DETECTOR_RUN_VERSION,
        "git_sha": git_sha,
        "frozen_detector_manifest_id": frozen["manifest_id"],
        "project_count": len(rows),
        "projects": rows,
        "total_model_calls": sum(int(row.get("model_calls") or 0) for row in rows),
        "total_tool_calls": sum(int(row.get("tool_calls") or 0) for row in rows),
        "total_proposals": sum(int(row.get("proposals") or 0) for row in rows),
        "total_candidate_paths": sum(int(row.get("candidate_path_count") or 0) for row in rows),
        "benchmark_informed": False,
    }
    _write_json(output / "detector_summary.json", summary)
    freeze = {
        "schema_version": 1,
        "detector_run_version": DETECTOR_RUN_VERSION,
        "detector_frozen": True,
        "evaluation_started": False,
        "git_sha": git_sha,
        "frozen_detector_manifest_sha256": _sha256(manifest_path),
        "detector_summary_sha256": _sha256(output / "detector_summary.json"),
        "project_detector_manifest_hashes": project_manifests,
        "benchmark_informed": False,
    }
    _write_json(freeze_path, freeze)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the annotation-blind M7 autonomous detector")
    parser.add_argument("--frozen-manifest", type=Path, required=True)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    args = parser.parse_args(argv)
    summary = run_detector(
        frozen_manifest_path=args.frozen_manifest,
        repository_root=args.repository_root,
        schema_root=args.schema_root,
        output_root=args.output_root,
    )
    print(canonical_json(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
