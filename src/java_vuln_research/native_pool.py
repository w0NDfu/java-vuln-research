from __future__ import annotations

import hashlib
import json
import os
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .common.contracts import load_detector_manifest
from .common.io import read_jsonl, write_json, write_jsonl
from .common.provenance import git_metadata, tool_versions
from .evaluation.coverage import iter_sarif_native_paths
from .frontier.candidate_path import CandidatePathError, build_candidate_path


class NativePoolError(ValueError):
    """Raised when a native-path pool cannot be built safely."""


def _digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:24]


def _location(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        file_name, line = str(value["file"]), int(value["line"])
    except (KeyError, TypeError, ValueError) as error:
        raise NativePoolError("native path location needs file and positive line") from error
    if not file_name or line < 1:
        raise NativePoolError("native path location needs file and positive line")
    return {"file": file_name, "line": line}


def _endpoint(*, project_id: str, revision: str, path_id: str, side: str, location: Mapping[str, Any]) -> dict[str, Any]:
    loc = _location(location)
    candidate_id = f"native-{side.lower()}-{_digest({'project_id': project_id, 'native_path_id': path_id, 'side': side, 'location': loc})}"
    return {
        "candidate_id": candidate_id,
        "kind": "EXTERNAL_INPUT" if side == "INPUT" else "SECURITY_EFFECT",
        "entity": f"codeql.native.{project_id}.{side.lower()}.{candidate_id[-12:]}",
        "source": "STATIC",
        "evidence": [{"project": project_id, "revision": revision, **loc}],
    }


def _anchor(candidate: Mapping[str, Any], *, role: str) -> dict[str, Any]:
    location = dict(candidate["evidence"][0])
    return {
        "candidate_id": str(candidate["candidate_id"]),
        "mapping_status": "MAPPED",
        "anchor_kind": role,
        "value_role": role,
        "method_identity": "CODEQL_NATIVE_PATH",
        "call_identity": None,
        "argument_index": None,
        "location": {"file": location["file"], "line": location["line"]},
        "mapping_reason": "CODEQL_NATIVE_PATH_LOCATION",
    }


def adapt_native_path(
    native_path: Mapping[str, Any],
    *,
    revision: str,
    codeql_version: str,
    detector_commit: str,
) -> dict[str, Any]:
    """Adapt one parsed SARIF native path into the existing CandidatePath IR."""

    project_id, native_path_id = str(native_path.get("project_id", "")), str(native_path.get("native_path_id", ""))
    locations = native_path.get("locations")
    if not project_id or not native_path_id or not isinstance(locations, list) or not locations:
        raise NativePoolError("native path requires project_id, native_path_id, and locations")
    normalised = [_location(item) for item in locations]
    input_candidate = _endpoint(project_id=project_id, revision=revision, path_id=native_path_id, side="INPUT", location=normalised[0])
    effect_candidate = _endpoint(project_id=project_id, revision=revision, path_id=native_path_id, side="EFFECT", location=normalised[-1])
    input_anchor = _anchor(input_candidate, role="CALL_RESULT")
    effect_anchor = _anchor(effect_candidate, role="CALL_ARGUMENT")
    intermediate_nodes: list[dict[str, Any]] = []
    for index, location in enumerate(normalised[1:-1], start=1):
        intermediate_nodes.append(
            {
                "node_id": f"native-node-{_digest({'path': native_path_id, 'index': index, 'location': location})}",
                "entity": f"codeql.native.location.{index}",
                "kind": "NATIVE_PATH_LOCATION",
                "location": location,
            }
        )
    node_ids = ["input:" + str(input_candidate["candidate_id"])] + [node["node_id"] for node in intermediate_nodes] + ["effect:" + str(effect_candidate["candidate_id"])]
    edges = [
        {
            "from_node_id": node_ids[index],
            "to_node_id": node_ids[index + 1],
            "mechanism": "DATA",
            "evidence": {"kind": "CODEQL_NATIVE_PATH", "native_path_id": native_path_id, "step": index},
        }
        for index in range(len(node_ids) - 1)
    ]
    rule_id = str(native_path.get("rule_id") or "").strip()
    hypothesis = f"CODEQL_RULE:{rule_id}" if rule_id else "UNKNOWN"
    provenance = {
        "sarif_file": str(native_path.get("sarif_file", "")),
        "codeql_version": codeql_version,
        "query_or_rule": rule_id or "UNKNOWN",
        "project_revision": revision,
        "detector_commit": detector_commit,
        "source_indices": {
            "run": native_path.get("run_index"),
            "result": native_path.get("result_index"),
            "code_flow": native_path.get("code_flow_index"),
            "thread_flow": native_path.get("thread_flow_index"),
        },
    }
    return build_candidate_path(
        project_id=project_id,
        input_candidate=input_candidate,
        effect_candidate=effect_candidate,
        input_analysis_anchor=input_anchor,
        effect_analysis_anchor=effect_anchor,
        intermediate_nodes=intermediate_nodes,
        edges=edges,
        path_status="COMPLETE_STATIC",
        detector_commit=detector_commit,
        candidate_type_hypothesis=hypothesis,
        provenance=provenance,
        path_origin="CODEQL_NATIVE",
        discovery_route_override="CODEQL_NATIVE",
        native_rule_id=rule_id or None,
        native_path_id=native_path_id,
        confidence_tier="NATIVE_HIGH",
        static_evidence=[{"kind": "CODEQL_NATIVE_PATH", "native_path_id": native_path_id}],
        unresolved_semantics=(),
    )


def _codeql_version(codeql: str) -> str:
    try:
        result = subprocess.run([codeql, "version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return "UNKNOWN"
    return (result.stdout or "UNKNOWN").splitlines()[0].strip() or "UNKNOWN"


def run_p0_a1_native_pool(
    *,
    detector_manifest: str | Path,
    baseline_raw_dir: str | Path,
    output_root: str | Path,
    project_root: str | Path,
    codeql: str = "codeql",
    run_id: str,
) -> dict[str, Any]:
    projects = load_detector_manifest(detector_manifest)
    baseline_root = Path(baseline_raw_dir) / "baseline"
    output = Path(output_root)
    output.mkdir(parents=True, exist_ok=True)
    detector_commit, detector_branch = git_metadata(project_root)
    codeql_version = _codeql_version(codeql)
    started = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    all_candidates: list[dict[str, Any]] = []
    statuses: list[dict[str, Any]] = []
    expected_ids: list[str] = []
    failures = 0
    for project in projects:
        project_id, revision = project["project"], project["revision"]
        sarif = baseline_root / f"{project_id}.sarif"
        status: dict[str, Any] = {"project_id": project_id, "revision": revision, "sarif_file": str(sarif), "status": "SUCCESS"}
        try:
            parsed = iter_sarif_native_paths(sarif, project_id=project_id)
        except Exception as error:  # parser errors are persisted, never silently filtered
            parsed = []
            status.update(status="FAILED", error_class="SARIF_INVALID", error=str(error))
        unique: dict[str, Mapping[str, Any]] = {str(row["native_path_id"]): row for row in parsed}
        duplicate_count = len(parsed) - len(unique)
        adapted: list[dict[str, Any]] = []
        project_failures: list[dict[str, Any]] = []
        for native_path_id, row in unique.items():
            expected_ids.append(native_path_id)
            try:
                adapted.append(adapt_native_path(row, revision=revision, codeql_version=codeql_version, detector_commit=detector_commit))
            except (NativePoolError, CandidatePathError) as error:
                project_failures.append({"native_path_id": native_path_id, "error": str(error)})
        failures += len(project_failures)
        all_candidates.extend(adapted)
        status.update(native_paths_parsed=len(parsed), unique_native_path_ids=len(unique), native_paths_adapted=len(adapted), native_paths_failed=len(project_failures), duplicate_native_path_ids=duplicate_count, failures=project_failures)
        if not sarif.is_file() and status["status"] == "SUCCESS":
            status.update(status="FAILED", error_class="SARIF_MISSING")
        statuses.append(status)

    all_candidates.sort(key=lambda row: str(row["native_path_id"]))
    adapted_ids = [str(row["native_path_id"]) for row in all_candidates]
    expected_set, adapted_set = set(expected_ids), set(adapted_ids)
    loss_ids = sorted(expected_set - adapted_set)
    duplicate_candidate_ids = len(adapted_ids) - len(set(adapted_ids))
    baseline_preservation = {
        "native_paths_parsed": len(expected_set),
        "native_paths_adapted": len(adapted_set),
        "native_paths_failed": failures,
        "unique_native_path_ids": len(expected_set),
        "unique_candidate_ids": len(set(str(row["candidate_path_id"]) for row in all_candidates)),
        "baseline_preservation_loss_count": len(loss_ids),
        "baseline_preservation_loss_ids": loss_ids,
        "baseline_preservation_rate": (len(expected_set & adapted_set) / len(expected_set)) if expected_set else "NOT_EVALUABLE",
        "invariant_parsed_equals_adapted": len(expected_set) == len(adapted_set) and not failures,
        "duplicate_candidate_ids": duplicate_candidate_ids,
        "status": "PASS" if not loss_ids and not failures and duplicate_candidate_ids == 0 else "FAIL",
    }
    write_jsonl(output / "native_candidate_paths.jsonl", all_candidates)
    write_jsonl(output / "unified_candidate_pool.jsonl", all_candidates)
    write_jsonl(output / "adapter_status.jsonl", statuses)
    write_json(output / "baseline_preservation.json", baseline_preservation)
    versions = tool_versions()
    manifest = {
        "run_id": run_id,
        "experiment": "P0-A1-NATIVE-POOL",
        "timestamp_start": started,
        "timestamp_end": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "git_commit": detector_commit,
        "git_branch": detector_branch,
        "codeql_version": codeql_version,
        "java_version": versions.get("java_version"),
        "projects_requested": len(projects),
        "projects_runnable": sum(row["status"] == "SUCCESS" for row in statuses),
        "detector_ground_truth_access": False,
        "status": "SUCCESS" if baseline_preservation["status"] == "PASS" and all(row["status"] == "SUCCESS" for row in statuses) else "FAIL",
    }
    write_json(output / "run_manifest.json", manifest)
    summary = {
        **baseline_preservation,
        "status": manifest["status"],
        "projects_total": len(projects),
        "projects_success": manifest["projects_runnable"],
        "native_candidate_paths": len(all_candidates),
        "unified_candidate_pool_paths": len(all_candidates),
        "path_origin_counts": dict(Counter(str(row.get("path_origin")) for row in all_candidates)),
        "detector_ground_truth_access": False,
        "scientific_method_changed": "NO",
        "codeql_rerun_performed": False,
    }
    write_json(output / "summary.json", summary)
    (output / "summary.md").write_text(
        "\n".join(
            [
                f"# {run_id} — P0-A1 NativePathAdapter + Unified Candidate Pool",
                "",
                f"- Status: `{summary['status']}`",
                f"- E0 native paths parsed: `{summary['native_paths_parsed']}`",
                f"- Successfully adapted: `{summary['native_paths_adapted']}`",
                f"- Adapter failures: `{summary['native_paths_failed']}`",
                f"- Unified pool paths: `{summary['unified_candidate_pool_paths']}`",
                f"- Baseline preservation loss: `{summary['baseline_preservation_loss_count']}`",
                f"- Baseline preservation rate: `{summary['baseline_preservation_rate']}`",
                "- detector_ground_truth_access: `false`",
                "- scientific_method_changed: `NO`",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    return summary


def evaluate_native_pool(*, baseline_raw_dir: str | Path, manifest_path: str | Path, pool_path: str | Path, output_root: str | Path) -> dict[str, Any]:
    projects = load_detector_manifest(manifest_path)
    baseline_root = Path(baseline_raw_dir) / "baseline"
    expected = [row for project in projects for row in iter_sarif_native_paths(baseline_root / f"{project['project']}.sarif", project_id=project["project"])]
    candidates = read_jsonl(pool_path)
    by_native_id = {str(row.get("native_path_id")): row for row in candidates if row.get("native_path_id")}
    cases: list[dict[str, Any]] = []
    for row in expected:
        native_id = str(row["native_path_id"])
        candidate = by_native_id.get(native_id)
        cases.append({"native_path_id": native_id, "project_id": row["project_id"], "covered": candidate is not None, "candidate_path_id": candidate.get("candidate_path_id") if candidate else None})
    covered = sum(bool(row["covered"]) for row in cases)
    summary = {
        "status": "SUCCESS",
        "e0_evaluable_paths": len(expected),
        "e0_covered": covered,
        "e0_coverage_rate": covered / len(expected) if expected else "NOT_EVALUABLE",
        "native_pool_evaluable_paths": len(expected),
        "native_pool_covered": covered,
        "native_pool_coverage_rate": covered / len(expected) if expected else "NOT_EVALUABLE",
        "baseline_paths_parsed": len(expected),
        "native_candidates_adapted": len(candidates),
        "baseline_preservation_loss_count": len(expected) - covered,
        "baseline_preservation_rate": covered / len(expected) if expected else "NOT_EVALUABLE",
        "detector_ground_truth_access": False,
        "evaluation_basis": "E0_SARIF_NATIVE_PATH_ID_JOIN",
    }
    target = Path(output_root)
    write_json(target / "coverage_metrics.json", summary)
    write_jsonl(target / "coverage_cases.jsonl", cases)
    return summary
