"""Artifact emission for M7 controller runs, including fail-closed runs."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Iterable, Mapping

from java_vuln_research.work1_agent.proposal.model import canonical_json

from .controller import AgentControllerResult
from .trace import TraceEventType


PROJECT_ARTIFACT_FILES = (
    "agent_trace.jsonl",
    "model_calls.jsonl",
    "tool_calls.jsonl",
    "evidence_refs.jsonl",
    "proposals.jsonl",
    "gate_results.jsonl",
    "graph_nodes.jsonl",
    "graph_edges.jsonl",
    "candidate_paths.jsonl",
    "path_diagnostics.jsonl",
    "summary.json",
    "manifest.json",
)


def _jsonl(values: Iterable[Mapping[str, Any]]) -> str:
    return "".join(canonical_json(dict(item)) + "\n" for item in values)


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_controller_artifacts(
    result: AgentControllerResult,
    output_root: str | Path,
    *,
    run_manifest: Mapping[str, Any],
    input_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    output = Path(output_root)
    output.mkdir(parents=True, exist_ok=True)
    latest_graph = result.graph_results[-1] if result.graph_results else None
    model_calls = [
        dict(event.payload["response"])
        for event in result.trace.events
        if event.event_type is TraceEventType.MODEL_CALL
    ]
    traced_evidence = [
        dict(event.payload)
        for event in result.trace.events
        if event.event_type is TraceEventType.EVIDENCE
    ]
    evidence_by_id = {
        str(item["evidence_id"]): dict(item)
        for gate_result in result.gate_results
        for item in gate_result.resolved_evidence
        if item.get("evidence_id")
    }
    for item in traced_evidence:
        evidence_by_id[str(item["evidence_id"])] = item
    candidate_paths: list[Mapping[str, Any]] = []
    diagnostics: list[Mapping[str, Any]] = []
    if latest_graph is not None:
        candidate_paths.extend(latest_graph.path_search.native_paths)
        candidate_paths.extend(item.to_dict() for item in latest_graph.path_search.hybrid_paths)
        diagnostics.extend(latest_graph.path_search.diagnostics)
        diagnostics.extend(item.to_dict() for item in latest_graph.graph.diagnostics)

    _write(output / "agent_trace.jsonl", result.trace.to_jsonl_text())
    _write(output / "model_calls.jsonl", _jsonl(model_calls))
    _write(output / "tool_calls.jsonl", _jsonl(item.to_dict() for item in result.tool_results))
    _write(output / "evidence_refs.jsonl", _jsonl(evidence_by_id[key] for key in sorted(evidence_by_id)))
    _write(output / "proposals.jsonl", _jsonl(item.to_dict() for item in result.proposals))
    _write(output / "gate_results.jsonl", _jsonl(item.to_dict() for item in result.gate_results))
    _write(output / "graph_nodes.jsonl", _jsonl(item.to_dict() for item in latest_graph.graph.nodes) if latest_graph else "")
    _write(output / "graph_edges.jsonl", _jsonl(item.to_dict() for item in latest_graph.graph.edges) if latest_graph else "")
    _write(output / "candidate_paths.jsonl", _jsonl(candidate_paths))
    _write(output / "path_diagnostics.jsonl", _jsonl(diagnostics))
    summary = {
        **result.summary(),
        "candidate_path_count": len(candidate_paths),
        "graph_node_count": len(latest_graph.graph.nodes) if latest_graph else 0,
        "graph_edge_count": len(latest_graph.graph.edges) if latest_graph else 0,
        "interpretation": "Candidate paths and ADMISSIBLE proposals are not confirmed vulnerabilities.",
    }
    _write(output / "summary.json", canonical_json(summary) + "\n")
    manifest = {
        **dict(run_manifest),
        "project_id": result.state.project_id,
        "controller_summary": result.summary(),
        "system_prompt_sha256": run_manifest.get("system_prompt_sha256"),
        "budget": result.state.budget.to_dict(),
        "detector_input_manifest": dict(input_manifest),
        "failure_manifest": [item.to_dict() for item in result.failures],
        "artifact_contract": list(PROJECT_ARTIFACT_FILES),
    }
    _write(output / "manifest.json", canonical_json(manifest) + "\n")

    artifact_rows = [
        {"file": name, "sha256": _sha256(output / name), "bytes": (output / name).stat().st_size}
        for name in PROJECT_ARTIFACT_FILES
        if name != "manifest.json"
    ]
    audit = {
        "project_id": result.state.project_id,
        "required_files_present": all((output / name).is_file() for name in PROJECT_ARTIFACT_FILES),
        "artifact_count": len(PROJECT_ARTIFACT_FILES),
        "artifacts": artifact_rows,
        "no_leakage_pass": bool(input_manifest.get("no_leakage_pass", False)),
    }
    _write(output / "artifact_audit.json", canonical_json(audit) + "\n")
    return audit
