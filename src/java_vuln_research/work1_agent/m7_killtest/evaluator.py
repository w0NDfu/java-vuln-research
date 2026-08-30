"""Post-freeze M7 evaluator and counterfactual analysis.

Benchmark-derived inputs are read only here, after the detector output hash
manifest has been validated.  This module is not imported by the detector.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from java_vuln_research.work1_agent.hybrid_graph.model import (
    EvidenceNode,
    HybridEdge,
    HybridEvidenceGraph,
    NodeKind,
)
from java_vuln_research.work1_agent.hybrid_graph.path import (
    BoundedPathBuilder,
    SearchLimits,
)
from java_vuln_research.work1_agent.proposal.model import EntityRole, canonical_json

EVALUATOR_VERSION = "WORK1_V11_M7_POST_FREEZE_EVALUATOR_V1"
FAILURE_TAXONOMY = (
    "AGENT_FAILED_TO_FIND_INPUT",
    "AGENT_FAILED_TO_FIND_EFFECT",
    "AGENT_FAILED_TO_FIND_SEMANTIC_RELATION",
    "INSUFFICIENT_PROGRAM_EVIDENCE",
    "REPOSITORY_TOOL_LIMITATION",
    "CODEQL_TOOL_UNAVAILABLE",
    "CODEQL_ENTITY_ALIGNMENT_FAILURE",
    "GATE_BLOCKED",
    "PATH_NOT_CONNECTED",
    "BUDGET_EXHAUSTED",
    "MODEL_OUTPUT_INVALID",
    "MODEL_REASONING_STALLED",
    "OTHER",
)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"JSON object required: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def _write_json(path: Path, value: Mapping[str, Any] | Sequence[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(canonical_json(value) + "\n", encoding="utf-8", newline="\n")


def _write_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = list(rows[0]) if rows else ["project_id", "case_id"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _path_matches(path: Mapping[str, Any], annotation: Mapping[str, Any]) -> tuple[bool, str]:
    mapped_entity_id = str(annotation.get("mapped_entity_id") or "")
    if mapped_entity_id and any(str(node.get("entity_id") or "") == mapped_entity_id for node in path.get("ordered_nodes", ())):
        return True, "METHOD"
    file_hint = str(annotation.get("file_path") or annotation.get("file_name") or "").replace("\\", "/")
    start = int(annotation.get("start_line") or 0)
    end = int(annotation.get("end_line") or start or 0)
    method_name = str(annotation.get("method_name") or "")
    for node in path.get("ordered_nodes", ()):
        relative = str(node.get("repository_relative_path") or "")
        if not relative:
            continue
        if file_hint and not (relative.endswith(file_hint) or Path(relative).name == Path(file_hint).name):
            continue
        node_start = int(node.get("start_line") or 0)
        node_end = int(node.get("end_line") or node_start or 0)
        if start and not (node_start <= end and start <= node_end):
            continue
        return True, "METHOD" if method_name or start else "FILE"
    return False, "NONE"


def _causal_shape(path: Mapping[str, Any]) -> bool:
    support = dict(path.get("support_summary") or {})
    proposal_edges = int(support.get("proposal_edge_count") or 0)
    real_program = int(support.get("structural_edge_count") or 0) + int(support.get("deterministic_edge_count") or 0) > 0
    middle = any(edge.get("relation_kind") not in {"EXTERNAL_INPUT", "SECURITY_EFFECT"} for edge in path.get("ordered_edges", ()))
    return proposal_edges > 0 and real_program and middle


def _load_graph(project_root: Path) -> HybridEvidenceGraph:
    nodes = tuple(
        EvidenceNode(
            node_id=str(row["node_id"]),
            project_id=str(row["project_id"]),
            node_kind=NodeKind(row["node_kind"]),
            role=EntityRole(row["role"]),
            provenance=dict(row.get("provenance") or {}),
            entity_id=row.get("entity_id"),
            role_index=row.get("role_index"),
            repository_relative_path=row.get("repository_relative_path"),
            start_line=row.get("start_line"),
            end_line=row.get("end_line"),
            program_kind=row.get("program_kind"),
            anchor_proposal_id=row.get("anchor_proposal_id"),
        )
        for row in _read_jsonl(project_root / "graph_nodes.jsonl")
    )
    edges = tuple(
        HybridEdge.create(
            project_id=str(row["project_id"]),
            source_node_id=str(row["source_node_id"]),
            target_node_id=str(row["target_node_id"]),
            relation_kind=str(row["relation_kind"]),
            support_class=str(row["support_class"]),
            evidence_refs=row.get("evidence_refs", ()),
            proposal_id=row.get("proposal_id"),
            tool_call_ids=row.get("tool_call_ids", ()),
            repository_relation_ids=row.get("repository_relation_ids", ()),
            confidence=row.get("confidence"),
            provenance=dict(row.get("provenance") or {}),
        )
        for row in _read_jsonl(project_root / "graph_edges.jsonl")
    )
    project_id = str(nodes[0].project_id if nodes else project_root.name)
    return HybridEvidenceGraph(project_id, nodes, edges, (), {"graph_schema_version": 1})


def _counterfactual(
    *,
    project_root: Path,
    matched_paths: Sequence[Mapping[str, Any]],
    annotation: Mapping[str, Any],
    limits: SearchLimits,
    git_sha: str,
) -> dict[str, Any]:
    if not matched_paths:
        return {"status": "NOT_APPLICABLE", "counterfactual_pass": None, "paths": []}
    graph = _load_graph(project_root)
    rows: list[dict[str, Any]] = []
    all_pass = True
    for matched in matched_paths:
        middle_ids = sorted(
            {
                str(edge["proposal_id"])
                for edge in matched.get("ordered_edges", ())
                if edge.get("proposal_id") and edge.get("relation_kind") not in {"EXTERNAL_INPUT", "SECURITY_EFFECT"}
            }
        )
        removals: list[dict[str, Any]] = []
        for proposal_id in middle_ids:
            filtered = HybridEvidenceGraph(
                graph.project_id,
                graph.nodes,
                tuple(edge for edge in graph.edges if edge.proposal_id != proposal_id),
                graph.diagnostics,
                graph.manifest,
            )
            rerun = BoundedPathBuilder(limits).search(filtered, git_sha=git_sha)
            remaining = [path.to_dict() for path in rerun.hybrid_paths if _path_matches(path.to_dict(), annotation)[0] and _causal_shape(path.to_dict())]
            removals.append(
                {
                    "removed_proposal_id": proposal_id,
                    "same_config_rerun": True,
                    "benchmark_consistent_path_count_after_removal": len(remaining),
                    "recovery_removed": not remaining,
                }
            )
        path_pass = bool(removals) and any(row["recovery_removed"] for row in removals)
        all_pass = all_pass and path_pass
        rows.append(
            {
                "candidate_path_id": matched["candidate_path_id"],
                "minimal_causal_proposal_ids": [row["removed_proposal_id"] for row in removals if row["recovery_removed"]],
                "counterfactual_pass": path_pass,
                "removals": removals,
            }
        )
    return {"status": "PASS" if all_pass else "FAIL", "counterfactual_pass": all_pass, "paths": rows}


def _diagnostic_index(m6_root: Path) -> dict[tuple[str, str], dict[str, Any]]:
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for path in sorted((m6_root / "cases").glob("*/diagnostic_analysis.json")):
        value = _read_json(path)
        annotation = dict(value.get("target_annotation") or {})
        mapped = dict(value.get("mapped_callable") or {})
        project_id = str(annotation.get("project_id") or value.get("project_id") or "")
        case_id = str(annotation.get("case_id") or value.get("case_id") or "")
        if project_id and case_id:
            result[(project_id, case_id)] = {**annotation, "mapped_entity_id": mapped.get("entity_id")}
    return result


def _classify_failure(
    *,
    summary: Mapping[str, Any],
    proposals: Sequence[Mapping[str, Any]],
    gates: Sequence[Mapping[str, Any]],
    tools: Sequence[Mapping[str, Any]],
    recovered: bool,
) -> list[str]:
    if recovered:
        return []
    failure_rows = [dict(row) for row in summary.get("failures", ())]
    if any(str(row.get("failure_class") or "") == "DETECTOR_SETUP_ERROR" for row in failure_rows):
        return ["OTHER"]
    labels: list[str] = []
    types = {str(row.get("proposal_type") or row.get("relation_type") or "") for row in proposals}
    failures = [str(row.get("failure_class") or "") for row in failure_rows]
    stop = str(summary.get("stop_reason") or "")
    if "EXTERNAL_INPUT" not in types:
        labels.append("AGENT_FAILED_TO_FIND_INPUT")
    if "SECURITY_EFFECT" not in types:
        labels.append("AGENT_FAILED_TO_FIND_EFFECT")
    if not types.intersection({"WRAPPER_FLOW", "LIBRARY_FLOW", "FIELD_STATE", "CALLBACK_RELATION", "FRAMEWORK_RELATION"}):
        labels.append("AGENT_FAILED_TO_FIND_SEMANTIC_RELATION")
    if any(str(row.get("status")) == "NEEDS_MORE_EVIDENCE" for row in gates):
        labels.append("INSUFFICIENT_PROGRAM_EVIDENCE")
    if any(str(row.get("status")) in {"ERROR", "UNSUPPORTED"} and not str(row.get("tool_name", "")).startswith("CODEQL_") for row in tools):
        labels.append("REPOSITORY_TOOL_LIMITATION")
    if any(str(row.get("status")) == "UNAVAILABLE" and str(row.get("tool_name", "")).startswith("CODEQL_") for row in tools):
        labels.append("CODEQL_TOOL_UNAVAILABLE")
    if any(str(row.get("status")) == "ENTITY_NOT_MAPPED" for row in tools):
        labels.append("CODEQL_ENTITY_ALIGNMENT_FAILURE")
    if proposals and not any(str(row.get("status")) == "ADMISSIBLE" for row in gates):
        labels.append("GATE_BLOCKED")
    if int(summary.get("candidate_path_count") or 0) == 0 and proposals:
        labels.append("PATH_NOT_CONNECTED")
    if stop == "BUDGET_EXHAUSTED" or "BUDGET_EXCEEDED" in failures:
        labels.append("BUDGET_EXHAUSTED")
    if any(item in {"INVALID_JSON", "INVALID_ACTION", "SCHEMA_VIOLATION", "TOOL_ARGUMENT_INVALID"} for item in failures):
        labels.append("MODEL_OUTPUT_INVALID")
    if stop == "NO_FURTHER_ACTION" and int(summary.get("candidate_path_count") or 0) == 0:
        labels.append("MODEL_REASONING_STALLED")
    return list(dict.fromkeys(labels or ["OTHER"]))


def _validate_detector_freeze(output: Path, freeze: Mapping[str, Any]) -> None:
    if not freeze.get("detector_frozen") or freeze.get("evaluation_started") is not False:
        raise ValueError("detector output must be frozen before M7 evaluation")
    if _sha256(output / "detector_summary.json") != freeze["detector_summary_sha256"]:
        raise ValueError("detector summary changed after freeze")
    for project_id, expected in dict(freeze["project_detector_manifest_hashes"]).items():
        project_root = output / "projects" / project_id
        if _sha256(project_root / "detector_manifest.json") != expected:
            raise ValueError(f"project detector manifest changed after freeze: {project_id}")
        manifest = _read_json(project_root / "detector_manifest.json")
        for name, artifact_hash in dict(manifest["artifact_hashes"]).items():
            if _sha256(project_root / name) != artifact_hash:
                raise ValueError(f"frozen detector artifact changed: {project_id}/{name}")


def _detector_leakage_audit(
    *,
    output: Path,
    freeze: Mapping[str, Any],
    selected: Sequence[Mapping[str, str]],
) -> dict[str, Any]:
    forbidden_values = sorted(
        {
            str(row.get(key) or "").casefold()
            for row in selected
            for key in ("case_id", "cwe", "diagnostic_cause", "fix_method", "benchmark_location")
            if len(str(row.get(key) or "").strip()) >= 6
        }
    )
    value_hits: list[dict[str, str]] = []
    secret_hits: list[str] = []
    boundary_violations: list[str] = []
    denied_input_projects: list[str] = []
    unverified_input_projects: list[str] = []
    for project_id in sorted(freeze["project_detector_manifest_hashes"]):
        project_root = output / "projects" / project_id
        manifest = _read_json(project_root / "detector_manifest.json")
        for name in manifest["artifact_hashes"]:
            path = project_root / name
            text = path.read_text(encoding="utf-8", errors="replace")
            lowered = text.casefold()
            for value in forbidden_values:
                if value in lowered:
                    value_hits.append({"project_id": project_id, "file": name, "value_sha256": hashlib.sha256(value.encode()).hexdigest()})
            if re.search(r"\bsk-[A-Za-z0-9_-]{16,}\b|authorization\s*[:=]\s*bearer\s+\S+", text, re.IGNORECASE):
                secret_hits.append(f"{project_id}/{name}")
        project_manifest = _read_json(project_root / "manifest.json")
        runtime_manifest = project_manifest.get("detector_input_manifest")
        if isinstance(runtime_manifest, Mapping):
            if runtime_manifest.get("violations") or runtime_manifest.get("no_leakage_pass") is not True:
                boundary_violations.append(project_id)
            continue
        setup_failures = [dict(row) for row in project_manifest.get("failure_manifest", ())]
        fail_closed_denial = any(
            str(row.get("failure_class") or "") == "DETECTOR_SETUP_ERROR"
            and "SECURITY_BOUNDARY_VIOLATION" in str(row.get("message") or "")
            for row in setup_failures
        )
        if fail_closed_denial:
            denied_input_projects.append(project_id)
        else:
            unverified_input_projects.append(project_id)
    return {
        "schema_version": 1,
        "detector_files_scanned": sum(len(_read_json(output / "projects" / pid / "detector_manifest.json")["artifact_hashes"]) for pid in freeze["project_detector_manifest_hashes"]),
        "forbidden_selected_value_hits": value_hits,
        "secret_hits": secret_hits,
        "runtime_boundary_violation_projects": boundary_violations,
        "fail_closed_denied_input_projects": denied_input_projects,
        "unverified_runtime_input_projects": unverified_input_projects,
        "no_leakage_pass": not value_hits and not secret_hits and not boundary_violations and not unverified_input_projects,
    }


def evaluate(
    *,
    output_root: str | Path,
    freeze_root: str | Path,
    m6_root: str | Path,
) -> dict[str, Any]:
    output = Path(output_root).resolve()
    frozen_inputs = Path(freeze_root).resolve()
    m6 = Path(m6_root).resolve()
    detector_freeze = _read_json(output / "detector_output_manifest.json")
    _validate_detector_freeze(output, detector_freeze)
    selection = _read_json(frozen_inputs / "selection_manifest.json")
    selected_rows = _read_csv(m6 / "selected_cases.csv")
    selected_by_pair = {(str(row["project_id"]), str(row["case_id"])): row for row in selected_rows}
    annotations = _diagnostic_index(m6)
    selection_rows = list(selection["selected"])
    no_leakage = _detector_leakage_audit(output=output, freeze=detector_freeze, selected=selected_rows)
    detector_input = _read_json(frozen_inputs / "detector_manifest.json")
    limits = SearchLimits(**{name: int(value) for name, value in detector_input["path_bounds"].items()})
    results: list[dict[str, Any]] = []
    recovered_paths: list[dict[str, Any]] = []
    taxonomy_counts: Counter[str] = Counter()
    for selected in selection_rows:
        project_id = str(selected["project_id"])
        case_id = str(selected["case_id"])
        project_root = output / "projects" / project_id
        selected_source = selected_by_pair.get((project_id, case_id))
        if selected_source is None:
            raise ValueError(f"frozen selected case missing from M6 inventory: {project_id}/{case_id}")
        baseline_miss = str(selected_source.get("baseline_detected") or "").casefold() != "true"
        summary = _read_json(project_root / "summary.json")
        project_manifest = _read_json(project_root / "manifest.json")
        paths = _read_jsonl(project_root / "candidate_paths.jsonl")
        proposals = _read_jsonl(project_root / "proposals.jsonl")
        gates = _read_jsonl(project_root / "gate_results.jsonl")
        tools = _read_jsonl(project_root / "tool_calls.jsonl")
        evidence = {str(row["evidence_id"]) for row in _read_jsonl(project_root / "evidence_refs.jsonl")}
        annotation = annotations.get((project_id, case_id))
        if annotation is None:
            raise ValueError(f"post-freeze evaluator annotation missing: {project_id}/{case_id}")
        matched = [path for path in paths if _path_matches(path, annotation)[0] and _causal_shape(path)]
        proposal_audit = all(
            proposal.get("provenance", {}).get("benchmark_informed") is False
            and set(proposal.get("evidence_refs", ())).issubset(evidence)
            for proposal in proposals
        )
        trace_clean = no_leakage["no_leakage_pass"]
        recovered = baseline_miss and bool(matched) and proposal_audit and trace_clean
        counterfactual = _counterfactual(
            project_root=project_root,
            matched_paths=matched,
            annotation=annotation,
            limits=limits,
            git_sha=str(detector_freeze["git_sha"]),
        )
        if recovered and counterfactual.get("counterfactual_pass") is not True:
            recovered = False
        failures = _classify_failure(summary=summary, proposals=proposals, gates=gates, tools=tools, recovered=recovered)
        taxonomy_counts.update(failures)
        gate_counts = Counter(str(row.get("status") or "UNKNOWN") for row in gates)
        relation_counts = Counter(str(row.get("proposal_type") or row.get("relation_type") or "UNKNOWN") for row in proposals)
        match_granularity = _path_matches(matched[0], annotation)[1] if matched else "NONE"
        row = {
            "selection_rank": selected["selection_rank"],
            "project_id": project_id,
            "case_id": case_id,
            "baseline_miss": baseline_miss,
            "autonomous_recovered": recovered,
            "candidate_path_count": len(paths),
            "matched_path_count": len(matched),
            "matching_granularity": match_granularity,
            "counterfactual_pass": counterfactual.get("counterfactual_pass"),
            "rounds": summary.get("rounds", 0),
            "tool_calls": summary.get("tool_calls", 0),
            "model_calls": summary.get("model_calls", 0),
            "proposals": summary.get("proposals", 0),
            "admissible_proposals": summary.get("admissible_proposals", 0),
            "input_tokens": project_manifest.get("budget", {}).get("usage", {}).get("input_tokens", 0),
            "output_tokens": project_manifest.get("budget", {}).get("usage", {}).get("output_tokens", 0),
            "wall_clock_seconds": project_manifest.get("wall_clock_seconds", 0),
            "stop_reason": summary.get("stop_reason"),
            "gate_status_counts": dict(gate_counts),
            "relation_type_counts": dict(relation_counts),
            "failure_classes": failures,
            "benchmark_informed": False,
        }
        results.append(row)
        _write_json(project_root / "evaluation.json", {**row, "matched_paths": [path["candidate_path_id"] for path in matched], "evaluator_version": EVALUATOR_VERSION})
        _write_json(project_root / "counterfactual.json", counterfactual)
        for path in matched:
            if recovered:
                recovered_paths.append({"project_id": project_id, "case_id": case_id, **path})

    recovered_rows = [row for row in results if row["autonomous_recovered"]]
    support = Counter()
    relations = Counter()
    for path in recovered_paths:
        for key, value in dict(path.get("support_summary") or {}).items():
            if key.endswith("_edge_count"):
                support[key] += int(value)
        relations.update(str(edge.get("relation_kind") or "UNKNOWN") for edge in path.get("ordered_edges", ()))
    aggregate = {
        "schema_version": 1,
        "evaluator_version": EVALUATOR_VERSION,
        "evaluation_started_after_detector_freeze": True,
        "detector_git_sha": detector_freeze["git_sha"],
        "selected_case_count": len(results),
        "autonomous_recovery_count": len(recovered_rows),
        "autonomous_recovery_rate": round(len(recovered_rows) / len(results), 6) if results else 0.0,
        "recovered_projects": sorted({row["project_id"] for row in recovered_rows}),
        "recovered_path_support_composition": dict(support),
        "relation_type_contribution": dict(relations),
        "totals": {
            "rounds": sum(int(row["rounds"]) for row in results),
            "tool_calls": sum(int(row["tool_calls"]) for row in results),
            "model_calls": sum(int(row["model_calls"]) for row in results),
            "proposals": sum(int(row["proposals"]) for row in results),
            "admissible_proposals": sum(int(row["admissible_proposals"]) for row in results),
            "input_tokens": sum(int(row["input_tokens"]) for row in results),
            "output_tokens": sum(int(row["output_tokens"]) for row in results),
            "wall_clock_seconds": round(sum(float(row["wall_clock_seconds"]) for row in results), 6),
        },
        "per_project": results,
        "metric_name": "AUTONOMOUS_RECOVERY",
        "not_full_benchmark_detection_rate": True,
        "no_leakage_pass": no_leakage["no_leakage_pass"],
        "native_preservation_pass": all(
            int(project.get("native_baseline", {}).get("candidate_path_count") or 0) == 0
            for project in detector_input.get("projects", ())
        ),
    }
    taxonomy = {"schema_version": 1, "classes": list(FAILURE_TAXONOMY), "counts": {name: taxonomy_counts.get(name, 0) for name in FAILURE_TAXONOMY}}
    _write_csv(output / "selected_cases.csv", results)
    _write_json(output / "aggregate_summary.json", aggregate)
    _write_json(output / "failure_taxonomy.json", taxonomy)
    _write_json(output / "no_leakage_audit.json", no_leakage)
    required = ("selected_cases.csv", "aggregate_summary.json", "failure_taxonomy.json", "no_leakage_audit.json")
    artifact_audit = {
        "schema_version": 1,
        "required_files_present": all((output / name).is_file() for name in required),
        "project_count": len(results),
        "project_contract_pass": all((output / "projects" / row["project_id"] / "detector_manifest.json").is_file() for row in results),
        "detector_freeze_validated": True,
    }
    _write_json(output / "artifact_audit.json", artifact_audit)
    manifest = {
        "schema_version": 1,
        "run_kind": "M7_AUTONOMOUS_KILLTEST_POST_FREEZE_EVALUATION",
        "detector_output_manifest_sha256": _sha256(output / "detector_output_manifest.json"),
        "selection_manifest_sha256": _sha256(frozen_inputs / "selection_manifest.json"),
        "evaluator_version": EVALUATOR_VERSION,
        "output_hashes": {name: _sha256(output / name) for name in (*required, "artifact_audit.json")},
        "m7_11_required": len(recovered_rows) > 0,
    }
    _write_json(output / "manifest.json", manifest)
    return aggregate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate frozen M7 detector outputs")
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--freeze-root", type=Path, required=True)
    parser.add_argument("--m6-root", type=Path, required=True)
    args = parser.parse_args(argv)
    print(canonical_json(evaluate(output_root=args.output_root, freeze_root=args.freeze_root, m6_root=args.m6_root)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
