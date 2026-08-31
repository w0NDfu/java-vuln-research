"""Freeze the M7 kill-test detector input before any benchmark evaluation."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.hybrid_graph.path import SearchLimits
from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest

from .budget import AgentBudgetLimits
from .controller import CONTROLLER_VERSION
from .llm_client import LLMClientConfig
from .observation import (
    MAX_BOOTSTRAP_OBSERVATION_CHARS,
    MAX_TOOL_GROUNDED_OBSERVATION_CHARS,
    OBSERVATION_VERSION,
    bounded_tool_catalog,
)
from .prompt import PROMPT_VERSION, build_system_prompt, prompt_sha256
from .structured_output import NORMALIZER_VERSION


DETECTOR_MANIFEST_VERSION = 1
FORBIDDEN_FIELD_NAMES = frozenset(
    {
        "case_id", "cve", "cwe", "patch", "fix", "fix_method", "vulnerable_location",
        "benchmark_location", "diagnostic", "diagnostic_hint", "root_cause", "annotation",
    }
)
FORBIDDEN_TEXT_TOKENS = ("cve-", "cwe-", "diagnostic_proposal", "root_cause", "benchmark_location", "fix_method")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.write_text(canonical_json(value) + "\n", encoding="utf-8", newline="\n")


def _tree_identity(root: Path) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        rows.append({"path": path.relative_to(root).as_posix(), "sha256": _sha256(path), "bytes": path.stat().st_size})
    return {
        "root": str(root),
        "file_count": len(rows),
        "tree_sha256": hashlib.sha256(canonical_json(rows).encode("utf-8")).hexdigest(),
    }


def _schema_hashes(schema_root: Path) -> dict[str, str]:
    names = (
        "work1_agent_action.schema.json",
        "work1_agent_model_decision.schema.json",
        "work1_agent_state.schema.json",
        "work1_agent_trace.schema.json",
        "work1_agent_killtest_detector_manifest.schema.json",
        "security_proposal.schema.json",
        "evidence_ref.schema.json",
        "hybrid_evidence_node.schema.json",
        "hybrid_evidence_edge.schema.json",
        "hybrid_candidate_path.schema.json",
        "candidate_path.schema.json",
    )
    return {name: _sha256(schema_root / name) for name in names}


def _inventory_index(rows: Sequence[Mapping[str, str]]) -> dict[str, Mapping[str, str]]:
    result: dict[str, Mapping[str, str]] = {}
    for row in rows:
        project_id = str(row.get("project_id") or row.get("project") or "")
        if project_id:
            result[project_id] = row
    return result


def freeze_killtest_manifest(
    *,
    selected_cases_csv: str | Path,
    project_inventory_csv: str | Path,
    component_roots: Mapping[str, str | Path],
    baseline_root: str | Path,
    schema_root: str | Path,
    output_root: str | Path,
    git_sha: str,
    model_config: LLMClientConfig,
) -> dict[str, Any]:
    selected_path = Path(selected_cases_csv).resolve()
    inventory_path = Path(project_inventory_csv).resolve()
    schemas = Path(schema_root).resolve()
    output = Path(output_root).resolve()
    output.mkdir(parents=True, exist_ok=True)
    selected = _read_csv(selected_path)
    inventory = _inventory_index(_read_csv(inventory_path))
    project_ids = [str(row["project_id"]) for row in selected]
    if len(project_ids) != 10 or len(set(project_ids)) != len(project_ids):
        raise ValueError("M7 kill test requires the frozen 10 distinct M6 baseline-miss projects")

    component_lineage = {
        name: _tree_identity(Path(root).resolve())
        for name, root in sorted(component_roots.items())
    }
    baseline_identity = _tree_identity(Path(baseline_root).resolve())
    baseline_manifest_path = Path(baseline_root).resolve() / "run_manifest.json"
    baseline_manifest = json.loads(baseline_manifest_path.read_text(encoding="utf-8")) if baseline_manifest_path.is_file() else {}
    baseline_identity["codeql_version"] = baseline_manifest.get("codeql_version") or baseline_manifest.get("CodeQL_version") or "UNKNOWN"
    projects: list[dict[str, Any]] = []
    for selected_row in selected:
        project_id = str(selected_row["project_id"])
        row = inventory.get(project_id)
        if row is None:
            raise ValueError(f"selected project missing from project inventory: {project_id}")
        source_root = str(row.get("source_root") or row.get("source_path") or "")
        db_path = str(row.get("codeql_db_path") or "")
        source_ready = str(row.get("source_exists") or row.get("source_ready") or "").casefold() == "true"
        db_ready = str(row.get("codeql_db_ready") or row.get("db_ready") or "").casefold() == "true"
        if not source_root or not source_ready:
            raise ValueError(f"selected project source is not ready: {project_id}")
        metadata = Path(db_path) / "codeql-database.yml"
        projects.append(
            {
                "project_id": project_id,
                "project_name": str(row.get("project_name") or row.get("name") or project_id),
                "repository_root": source_root,
                "repository_revision": str(selected_row.get("source_revision") or "UNKNOWN"),
                "source_ready": source_ready,
                "codeql_db_path": db_path,
                "codeql_db_ready": db_ready,
                "codeql_db_identity": {
                    "metadata_sha256": _sha256(metadata) if metadata.is_file() else None,
                    "status": "READY" if db_ready else "UNAVAILABLE",
                },
                "native_baseline": {
                    "available": True,
                    "candidate_path_count": 0,
                    "preservation_required": True,
                    "baseline_tree_sha256": baseline_identity["tree_sha256"],
                },
                "benchmark_informed": False,
            }
        )

    prompt = build_system_prompt(bounded_tool_catalog())
    limits = AgentBudgetLimits()
    path_limits = SearchLimits()
    detector_manifest: dict[str, Any] = {
        "schema_version": DETECTOR_MANIFEST_VERSION,
        "manifest_id": "pending",
        "run_kind": "M7_AUTONOMOUS_KILLTEST_DETECTOR_INPUT",
        "git_sha": git_sha,
        "selection_count": len(projects),
        "projects": projects,
        "model": model_config.to_manifest_dict(),
        "prompt": {"version": PROMPT_VERSION, "sha256": prompt_sha256(prompt)},
        "structured_output_normalizer": {"version": NORMALIZER_VERSION},
        "observation": {
            "schema_version": OBSERVATION_VERSION,
            "bootstrap_max_chars": MAX_BOOTSTRAP_OBSERVATION_CHARS,
            "tool_grounded_max_chars": MAX_TOOL_GROUNDED_OBSERVATION_CHARS,
        },
        "schemas": _schema_hashes(schemas),
        "tool_catalog_sha256": hashlib.sha256(canonical_json(bounded_tool_catalog()).encode("utf-8")).hexdigest(),
        "budget": limits.to_dict(),
        "controller": {
            "version": CONTROLLER_VERSION,
            "max_stagnant_rounds": 3,
            "max_model_output_retries": 2,
        },
        "path_bounds": {
            "max_depth": path_limits.max_depth,
            "max_paths": path_limits.max_paths,
            "max_nodes_expanded": path_limits.max_nodes_expanded,
        },
        "component_lineage": component_lineage,
        "baseline_lineage": baseline_identity,
        "detector_input_frozen": True,
        "benchmark_informed": False,
        "selection_manifest_allowed_for_agent_runtime": False,
        "m6_diagnostic_allowed_for_agent_runtime": False,
        "evaluator_allowed_during_detector_run": False,
    }
    detector_manifest["manifest_id"] = stable_digest(
        "m7detector",
        {key: value for key, value in detector_manifest.items() if key != "manifest_id"},
    )

    selection_manifest = {
        "schema_version": 1,
        "freeze_stage": "BEFORE_M7_DETECTOR_RUN",
        "selection_source_sha256": _sha256(selected_path),
        "selection_source_allowed_for_agent_runtime": False,
        "benchmark_informed": True,
        "selected": [
            {"selection_rank": index + 1, "project_id": str(row["project_id"]), "case_id": str(row["case_id"])}
            for index, row in enumerate(selected)
        ],
    }

    serialized = canonical_json(detector_manifest)
    selected_forbidden_values = {
        str(row.get(key) or "").casefold()
        for row in selected
        for key in ("case_id", "cwe", "diagnostic_cause", "fix_method", "benchmark_location")
        if str(row.get(key) or "").strip()
    }
    forbidden_value_hits = sorted(value for value in selected_forbidden_values if value in serialized.casefold())
    forbidden_token_hits = sorted(token for token in FORBIDDEN_TEXT_TOKENS if token in serialized.casefold())
    forbidden_field_hits = sorted(
        key
        for key in FORBIDDEN_FIELD_NAMES
        if f'"{key}"' in serialized.casefold()
    )
    audit = {
        "schema_version": 1,
        "detector_manifest_sha256": hashlib.sha256((serialized + "\n").encode("utf-8")).hexdigest(),
        "selected_project_ids": project_ids,
        "forbidden_field_hits": forbidden_field_hits,
        "forbidden_token_hits": forbidden_token_hits,
        "forbidden_selected_value_hits": forbidden_value_hits,
        "runtime_denylist_test_required": True,
        "all_projects_benchmark_informed_false": all(not row["benchmark_informed"] for row in projects),
        "selection_manifest_isolated": selection_manifest["selection_source_allowed_for_agent_runtime"] is False,
        "no_leakage_pass": not forbidden_field_hits and not forbidden_token_hits and not forbidden_value_hits,
    }
    if not audit["no_leakage_pass"]:
        raise ValueError("detector manifest contains forbidden benchmark-derived information")

    _write_json(output / "detector_manifest.json", detector_manifest)
    _write_json(output / "selection_manifest.json", selection_manifest)
    _write_json(output / "no_leakage_audit.json", audit)
    artifact_hashes = {
        name: _sha256(output / name)
        for name in ("detector_manifest.json", "selection_manifest.json", "no_leakage_audit.json")
    }
    aggregate = {
        "schema_version": 1,
        "detector_manifest_id": detector_manifest["manifest_id"],
        "selected_project_count": len(projects),
        "selected_project_ids": project_ids,
        "detector_input_frozen": True,
        "no_leakage_pass": audit["no_leakage_pass"],
        "killtest_started": False,
        "artifact_hashes": artifact_hashes,
    }
    _write_json(output / "manifest.json", aggregate)
    return aggregate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--selected-cases", type=Path, required=True)
    parser.add_argument("--project-inventory", type=Path, required=True)
    parser.add_argument("--baseline-root", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--git-sha", required=True)
    for name in ("m1", "m2", "m3", "m4", "m5"):
        parser.add_argument(f"--{name}-root", type=Path, required=True)
    args = parser.parse_args()
    summary = freeze_killtest_manifest(
        selected_cases_csv=args.selected_cases,
        project_inventory_csv=args.project_inventory,
        component_roots={name.upper(): getattr(args, f"{name}_root") for name in ("m1", "m2", "m3", "m4", "m5")},
        baseline_root=args.baseline_root,
        schema_root=args.schema_root,
        output_root=args.output_root,
        git_sha=args.git_sha,
        model_config=LLMClientConfig.from_environment(),
    )
    print(canonical_json(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
