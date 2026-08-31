"""Audited two-project real-model preflight required before the M7 freeze.

The preflight is deliberately separate from the benchmark detector.  Its JSON
configuration contains only public project identity, frozen source revision,
source-size class, and model transport requirements.  It never consumes a
benchmark cohort, vulnerability annotation, patch, CWE, CVE, or M6 artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping

from java_vuln_research.work1_agent.proposal import EvidenceGate, GateStatus
from java_vuln_research.work1_agent.proposal.model import canonical_json
from java_vuln_research.work1_agent.repository.entity import ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex, build_repository_index

from .actions import ActionType
from .controller import CONTROLLER_VERSION, AgentController, AgentControllerResult
from .graph_adapter import AgentGraphPathAdapter
from .llm_client import (
    AnthropicMessagesLLMClient,
    LLMAPIProtocol,
    LLMClient,
    LLMClientConfig,
    OpenAICompatibleLLMClient,
)
from .observation import bounded_tool_catalog
from .parser import StrictActionParser
from .prompt import build_system_prompt, prompt_sha256
from .runtime import write_controller_artifacts
from .security_boundary import RuntimeInputKind, RuntimeSecurityBoundary, runtime_roots
from .state import AgentState
from .structured_output import NORMALIZER_VERSION, NormalizationMode
from .tool_adapter import RepositoryCodeQLToolAdapter
from .trace import TraceEventType


PREFLIGHT_VERSION = "M7_REAL_MODEL_PREFLIGHT_V1"
PREFLIGHT_CONFIG_SCHEMA_VERSION = 1
PREFLIGHT_SELECTION_BASIS = "FROZEN_PROJECT_INVENTORY_JAVA_FILE_COUNT"


class PreflightSizeClass(str, Enum):
    SMALL = "SMALL"
    MEDIUM = "MEDIUM"


_SIZE_BOUNDS = {
    PreflightSizeClass.SMALL: (1, 50),
    PreflightSizeClass.MEDIUM: (100, 1000),
}


@dataclass(frozen=True, slots=True)
class PreflightProject:
    project_id: str
    project_name: str
    size_class: PreflightSizeClass
    source_root: Path
    repository_revision: str
    expected_java_file_count: int

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PreflightProject":
        required = {
            "project_id",
            "project_name",
            "size_class",
            "source_root",
            "repository_revision",
            "expected_java_file_count",
        }
        if set(value) != required:
            raise ValueError("preflight project must contain exactly the frozen project fields")
        project = cls(
            project_id=str(value["project_id"]).strip(),
            project_name=str(value["project_name"]).strip(),
            size_class=PreflightSizeClass(str(value["size_class"])),
            source_root=Path(str(value["source_root"])),
            repository_revision=str(value["repository_revision"]).strip(),
            expected_java_file_count=int(value["expected_java_file_count"]),
        )
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", project.project_id):
            raise ValueError("preflight project_id is not a safe artifact identity")
        if not project.project_name or len(project.project_name) > 200:
            raise ValueError("preflight project_name must be non-empty and bounded")
        if not re.fullmatch(r"[0-9a-f]{40}", project.repository_revision):
            raise ValueError("preflight repository_revision must be one lowercase 40-hex Git SHA")
        lower, upper = _SIZE_BOUNDS[project.size_class]
        if not lower <= project.expected_java_file_count <= upper:
            raise ValueError(
                f"{project.project_id} expected Java count does not satisfy {project.size_class.value} bounds"
            )
        return project

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "project_name": self.project_name,
            "size_class": self.size_class.value,
            "source_root": str(self.source_root),
            "repository_revision": self.repository_revision,
            "expected_java_file_count": self.expected_java_file_count,
        }


@dataclass(frozen=True, slots=True)
class PreflightConfiguration:
    projects: tuple[PreflightProject, ...]
    required_model: Mapping[str, Any]
    selection_basis: str


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(dict(value)) + "\n", encoding="utf-8", newline="\n")


def _read_preflight_configuration(
    path: Path,
    *,
    git_sha: str,
) -> tuple[PreflightConfiguration, Mapping[str, Any], Mapping[str, Any]]:
    boundary = RuntimeSecurityBoundary(
        project_id="M7_PREFLIGHT_SELECTION",
        repository_identity="m7-preflight-config@" + git_sha,
        allowed_roots=runtime_roots(artifact_roots=[path.parent]),
    )
    raw = boundary.read_bytes(path, kind=RuntimeInputKind.RUNTIME_CONFIG, logical_name="m7-real-model-preflight-config")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("preflight configuration must be one UTF-8 JSON object") from exc
    if not isinstance(value, Mapping):
        raise ValueError("preflight configuration must be a JSON object")
    required_keys = {
        "schema_version",
        "preflight_version",
        "selection_basis",
        "benchmark_informed",
        "allowed_for_agent_runtime",
        "required_model",
        "projects",
    }
    if set(value) != required_keys:
        raise ValueError("preflight configuration contains an unknown or missing top-level field")
    if int(value["schema_version"]) != PREFLIGHT_CONFIG_SCHEMA_VERSION:
        raise ValueError("unsupported preflight configuration schema")
    if value["preflight_version"] != PREFLIGHT_VERSION:
        raise ValueError("preflight configuration version mismatch")
    if value["selection_basis"] != PREFLIGHT_SELECTION_BASIS:
        raise ValueError("preflight projects must be selected only from frozen source-size inventory")
    if value["benchmark_informed"] is not False or value["allowed_for_agent_runtime"] is not True:
        raise ValueError("preflight configuration is not eligible for detector-side use")
    raw_projects = value["projects"]
    if not isinstance(raw_projects, list):
        raise ValueError("preflight projects must be a JSON array")
    projects = tuple(PreflightProject.from_dict(item) for item in raw_projects if isinstance(item, Mapping))
    if len(projects) != len(raw_projects):
        raise ValueError("every preflight project must be a JSON object")
    if len(projects) != 2 or {item.size_class for item in projects} != {
        PreflightSizeClass.SMALL,
        PreflightSizeClass.MEDIUM,
    }:
        raise ValueError("preflight requires exactly one SMALL and one MEDIUM project")
    if len({item.project_id for item in projects}) != 2 or len({str(item.source_root) for item in projects}) != 2:
        raise ValueError("preflight project IDs and source roots must be distinct")
    required_model = value["required_model"]
    if not isinstance(required_model, Mapping):
        raise ValueError("required_model must be a JSON object")
    manifest = boundary.seal()
    audit = boundary.audit()
    if audit["status"] != "PASS":
        raise ValueError("preflight selection input boundary audit failed")
    return (
        PreflightConfiguration(projects, dict(required_model), str(value["selection_basis"])),
        manifest,
        audit,
    )


def _validate_model_configuration(config: LLMClientConfig, required: Mapping[str, Any]) -> None:
    expected_keys = {
        "provider",
        "exact_model_id",
        "base_url",
        "endpoint_url",
        "api_protocol",
        "structured_output_mode",
        "temperature",
        "max_output_tokens",
        "seed",
    }
    if set(required) != expected_keys:
        raise ValueError("required_model contains an unknown or missing field")
    actual = config.to_manifest_dict()
    mismatches = {
        key: {"expected": required[key], "actual": actual[key]}
        for key in sorted(expected_keys)
        if actual[key] != required[key]
    }
    if mismatches:
        raise ValueError("real-model preflight configuration mismatch: " + canonical_json(mismatches))
    if actual["endpoint_mode"] != "EXACT":
        raise ValueError("preflight requires a frozen exact endpoint; client-side default path concatenation is forbidden")


def _git_revision(source_root: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if completed.returncode != 0:
        raise ValueError("preflight source root is not a readable Git checkout")
    return completed.stdout.strip()


def _make_client(config: LLMClientConfig) -> LLMClient:
    if config.api_protocol is LLMAPIProtocol.ANTHROPIC:
        return AnthropicMessagesLLMClient(config)
    return OpenAICompatibleLLMClient(config)


def _normalization_audit(result: AgentControllerResult) -> dict[str, Any]:
    model_call_ids = {
        str(event.payload["response"]["model_call_id"])
        for event in result.trace.events
        if event.event_type is TraceEventType.MODEL_CALL
    }
    action_events = [event for event in result.trace.events if event.event_type is TraceEventType.ACTION]
    explicit_failure_ids = {
        str(event.payload["model_call_id"])
        for event in result.trace.events
        if event.event_type in {TraceEventType.MODEL_RETRY, TraceEventType.FAILURE}
        and event.payload.get("model_call_id")
    }
    action_call_ids: set[str] = set()
    modes: dict[str, int] = {}
    malformed_actions: list[str] = []
    allowed_modes = {item.value for item in NormalizationMode}
    for event in action_events:
        provenance = event.payload.get("provenance")
        normalization = provenance.get("structured_output_normalization") if isinstance(provenance, Mapping) else None
        call_id = provenance.get("model_call_id") if isinstance(provenance, Mapping) else None
        if not isinstance(normalization, Mapping) or not call_id:
            malformed_actions.append(event.event_id)
            continue
        mode = str(normalization.get("normalization_mode") or "")
        if (
            mode not in allowed_modes
            or normalization.get("ambiguity_detected") is not False
            or "raw_response_hash" not in normalization
            or "provider_payload_shape" not in normalization
            or "normalization_warnings" not in normalization
        ):
            malformed_actions.append(event.event_id)
            continue
        action_call_ids.add(str(call_id))
        modes[mode] = modes.get(mode, 0) + 1
    accounted = action_call_ids | explicit_failure_ids
    unaccounted = sorted(model_call_ids - accounted)
    return {
        "normalizer_version": NORMALIZER_VERSION,
        "model_call_count": len(model_call_ids),
        "action_normalization_count": len(action_call_ids),
        "normalization_modes": dict(sorted(modes.items())),
        "explicit_failure_or_retry_count": len(explicit_failure_ids),
        "malformed_action_event_ids": malformed_actions,
        "unaccounted_model_call_ids": unaccounted,
        "pass": not malformed_actions and not unaccounted,
    }


def evaluate_preflight_result(
    result: AgentControllerResult,
    *,
    input_manifest: Mapping[str, Any],
    artifact_audit: Mapping[str, Any],
    secret_absent_from_artifacts: bool,
) -> dict[str, Any]:
    actions = [event for event in result.trace.events if event.event_type is TraceEventType.ACTION]
    first = actions[0] if actions else None
    first_action_type = str(first.payload.get("action_type")) if first else None
    first_round_legal_tool = bool(
        first
        and first.round == 1
        and first_action_type in {ActionType.SEARCH_CODE.value, ActionType.SEARCH_SYMBOLS.value}
        and any(event.event_type is TraceEventType.TOOL_RESULT and event.round == 1 for event in result.trace.events)
    )
    gate_events = [event for event in result.trace.events if event.event_type is TraceEventType.GATE_RESULT]
    needs_more = [event for event in gate_events if event.payload.get("gate_status") == GateStatus.NEEDS_MORE_EVIDENCE.value]
    needs_more_followups = [
        {
            "gate_event_id": event.event_id,
            "followed_by_tool": any(
                later.sequence > event.sequence and later.event_type is TraceEventType.TOOL_RESULT
                for later in result.trace.events
            ),
        }
        for event in needs_more
    ]
    normalization = _normalization_audit(result)
    checks = {
        "round1_legal_tool_action": first_round_legal_tool,
        "at_least_two_tool_calls": len(result.tool_results) >= 2,
        "at_least_one_schema_valid_proposal": len(result.proposals) >= 1,
        "at_least_one_proposal_entered_gate": len(result.gate_results) >= 1,
        "needs_more_evidence_followed_by_tool": all(item["followed_by_tool"] for item in needs_more_followups),
        "no_leakage": bool(input_manifest.get("no_leakage_pass"))
        and bool(artifact_audit.get("no_leakage_pass"))
        and secret_absent_from_artifacts,
        "normalization_fully_accounted": bool(normalization["pass"]),
        "artifact_contract_complete": bool(artifact_audit.get("required_files_present")),
    }
    return {
        "checks": checks,
        "pass": all(checks.values()),
        "first_action_type": first_action_type,
        "tool_sequence": [item.tool_name for item in result.tool_results],
        "proposal_count": len(result.proposals),
        "gate_status_sequence": [item.status.value for item in result.gate_results],
        "needs_more_evidence_followups": needs_more_followups,
        "normalization_audit": normalization,
        "controller_summary": result.summary(),
    }


ClientFactory = Callable[[PreflightProject, RepositoryIndex], LLMClient]
RevisionResolver = Callable[[Path], str]


def _run_project(
    project: PreflightProject,
    *,
    schema_root: Path,
    artifact_root: Path,
    git_sha: str,
    config: LLMClientConfig,
    client_factory: ClientFactory,
    revision_resolver: RevisionResolver,
) -> dict[str, Any]:
    source_root = project.source_root.resolve(strict=True)
    actual_revision = revision_resolver(source_root)
    if actual_revision != project.repository_revision:
        raise ValueError(
            f"{project.project_id} source revision mismatch: expected {project.repository_revision}, got {actual_revision}"
        )
    index = build_repository_index(source_root)
    java_sources = [
        source_root / Path(*item.repository_relative_path.split("/"))
        for item in index.sorted_entities()
        if item.kind is ProgramEntityKind.FILE
    ]
    if index.java_file_count != project.expected_java_file_count:
        raise ValueError(
            f"{project.project_id} Java file count mismatch: expected {project.expected_java_file_count}, got {index.java_file_count}"
        )
    if not index.entities:
        raise ValueError(f"{project.project_id} has zero indexed Java entities")
    output = artifact_root / project.project_id
    output.mkdir(parents=True, exist_ok=True)
    boundary = RuntimeSecurityBoundary(
        project_id=project.project_id,
        repository_identity=project.project_id + "@" + actual_revision,
        allowed_roots=runtime_roots(
            source_roots=[project.source_root],
            artifact_roots=[artifact_root],
            schema_roots=[schema_root],
        ),
    )
    for source in java_sources:
        boundary.read_bytes(
            source,
            kind=RuntimeInputKind.JAVA_SOURCE,
            logical_name="java:" + source.relative_to(source_root).as_posix(),
        )
    gate = EvidenceGate(repository_root=source_root, entities=index.entities, evidence_catalog={})
    graph_adapter = AgentGraphPathAdapter(
        project_id=project.project_id,
        entities=index.entities,
        evidence_gate=gate,
        git_sha=git_sha,
    )
    state = AgentState.create(
        project_id=project.project_id,
        repository_identity=project.project_id + "@" + actual_revision,
        provenance={
            "producer": PREFLIGHT_VERSION,
            "benchmark_informed": False,
            "allowed_for_agent_runtime": True,
        },
    )
    controller = AgentController(
        state=state,
        repository_index=index,
        codeql_status={
            "project_id": project.project_id,
            "ready": False,
            "status": "UNAVAILABLE",
            "reason": "REAL_MODEL_PREFLIGHT_ISOLATES_REPOSITORY_TOOL_LOOP",
        },
        llm_client=client_factory(project, index),
        parser=StrictActionParser(schema_root),
        tool_adapter=RepositoryCodeQLToolAdapter(
            project_id=project.project_id,
            repository_index=index,
            security_boundary=boundary,
        ),
        evidence_gate=gate,
        graph_path_adapter=graph_adapter,
    )
    result = controller.run()
    input_manifest = boundary.seal()
    boundary_audit = boundary.audit()
    if boundary_audit["status"] != "PASS":
        raise ValueError(f"{project.project_id} runtime input boundary audit failed")
    prompt = build_system_prompt(bounded_tool_catalog())
    artifact_audit = write_controller_artifacts(
        result,
        output,
        run_manifest={
            "run_kind": "M7_CONTROLLED_REAL_MODEL_PREFLIGHT",
            "preflight_version": PREFLIGHT_VERSION,
            "git_sha": git_sha,
            "repository_revision": actual_revision,
            "project_name": project.project_name,
            "size_class": project.size_class.value,
            "java_file_count": index.java_file_count,
            **config.to_manifest_dict(),
            "system_prompt_sha256": prompt_sha256(prompt),
            "normalizer_version": NORMALIZER_VERSION,
            "controller_version": CONTROLLER_VERSION,
            "benchmark_informed": False,
            "preflight_only_not_benchmark_evaluation": True,
        },
        input_manifest=input_manifest,
    )
    secret_absent = all(
        config.api_key not in path.read_text(encoding="utf-8", errors="replace")
        for path in output.rglob("*")
        if path.is_file()
    )
    evaluation = evaluate_preflight_result(
        result,
        input_manifest=input_manifest,
        artifact_audit=artifact_audit,
        secret_absent_from_artifacts=secret_absent,
    )
    row = {
        **project.to_dict(),
        "resolved_source_root": str(source_root),
        "actual_repository_revision": actual_revision,
        "actual_java_file_count": index.java_file_count,
        "artifact_root": str(output),
        "boundary_audit": boundary_audit,
        **evaluation,
    }
    _write_json(output / "preflight_evaluation.json", row)
    return row


def run_real_model_preflight(
    *,
    config_path: str | Path,
    schema_root: str | Path,
    artifact_root: str | Path,
    git_sha: str,
    model_config: LLMClientConfig | None = None,
    client_factory: ClientFactory | None = None,
    revision_resolver: RevisionResolver = _git_revision,
) -> dict[str, Any]:
    config_file = Path(config_path).resolve(strict=True)
    schemas = Path(schema_root).resolve(strict=True)
    output = Path(artifact_root)
    if output.exists() and any(output.iterdir()):
        raise ValueError("preflight artifact root must be absent or empty; preserve prior attempts in separate roots")
    output.mkdir(parents=True, exist_ok=True)
    preflight, selection_manifest, selection_audit = _read_preflight_configuration(config_file, git_sha=git_sha)
    _write_json(output / "selection_input_manifest.json", selection_manifest)
    _write_json(output / "selection_input_audit.json", selection_audit)
    resolved_model = model_config or LLMClientConfig.from_environment()
    _validate_model_configuration(resolved_model, preflight.required_model)
    resolved_factory = client_factory or (lambda _project, _index: _make_client(resolved_model))
    project_rows: list[dict[str, Any]] = []
    for project in preflight.projects:
        try:
            project_rows.append(
                _run_project(
                    project,
                    schema_root=schemas,
                    artifact_root=output,
                    git_sha=git_sha,
                    config=resolved_model,
                    client_factory=resolved_factory,
                    revision_resolver=revision_resolver,
                )
            )
        except (OSError, subprocess.SubprocessError, UnicodeError, ValueError) as exc:
            failure = {
                **project.to_dict(),
                "pass": False,
                "failure": {
                    "failure_class": "PREFLIGHT_SETUP_ERROR",
                    "exception_type": type(exc).__name__,
                    "message": str(exc),
                },
            }
            project_rows.append(failure)
            _write_json(output / project.project_id / "preflight_setup_failure.json", failure)
    overall_pass = (
        selection_audit["status"] == "PASS"
        and len(project_rows) == 2
        and all(bool(item.get("pass")) for item in project_rows)
    )
    aggregate = {
        "schema_version": 1,
        "preflight_version": PREFLIGHT_VERSION,
        "git_sha": git_sha,
        "selection_basis": preflight.selection_basis,
        "configuration_path": str(config_file),
        "configuration_sha256": _sha256_bytes(config_file.read_bytes()),
        "selection_input_manifest": selection_manifest,
        "selection_input_audit": selection_audit,
        "model_configuration": resolved_model.to_manifest_dict(),
        "project_count": len(project_rows),
        "size_classes": [item.size_class.value for item in preflight.projects],
        "projects": project_rows,
        "pass": overall_pass,
        "freeze_allowed": overall_pass,
        "benchmark_informed": False,
        "benchmark_evaluator_used": False,
        "interpretation": "This preflight validates agent protocol/tool reachability only; it is not vulnerability evaluation.",
    }
    _write_json(output / "preflight_summary.json", aggregate)
    secret_absent_from_all_artifacts = all(
        resolved_model.api_key not in path.read_text(encoding="utf-8", errors="replace")
        for path in output.rglob("*")
        if path.is_file()
    )
    aggregate["secret_absent_from_all_artifacts"] = secret_absent_from_all_artifacts
    aggregate["pass"] = bool(aggregate["pass"]) and secret_absent_from_all_artifacts
    aggregate["freeze_allowed"] = bool(aggregate["pass"])
    _write_json(output / "preflight_summary.json", aggregate)
    artifact_rows = [
        {
            "file": path.relative_to(output).as_posix(),
            "sha256": _sha256_bytes(path.read_bytes()),
            "bytes": path.stat().st_size,
        }
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "preflight_artifact_audit.json"
    ]
    _write_json(
        output / "preflight_artifact_audit.json",
        {
            "required_project_count": 2,
            "actual_project_count": len(project_rows),
            "small_and_medium_present": set(aggregate["size_classes"]) == {"SMALL", "MEDIUM"},
            "all_projects_pass": all(bool(item.get("pass")) for item in project_rows),
            "selection_no_leakage_pass": selection_manifest.get("no_leakage_pass") is True,
            "secret_absent_from_all_artifacts": secret_absent_from_all_artifacts,
            "artifact_count_excluding_self": len(artifact_rows),
            "artifacts": artifact_rows,
            "freeze_allowed": aggregate["freeze_allowed"],
        },
    )
    return aggregate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--schema-root", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--git-sha", required=True)
    args = parser.parse_args()
    summary = run_real_model_preflight(
        config_path=args.config,
        schema_root=args.schema_root,
        artifact_root=args.artifact_root,
        git_sha=args.git_sha,
    )
    print(canonical_json(summary))
    return 0 if summary["pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
