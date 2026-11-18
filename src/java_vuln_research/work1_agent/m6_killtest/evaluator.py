from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from .io import read_json, read_jsonl, sha256_file, write_json


EVALUATOR_VERSION = "WORK1_V11_M6_POST_FREEZE_EVALUATOR_V1"


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
        file_match = not file_hint or relative.endswith(file_hint) or Path(relative).name == Path(file_hint).name
        if not file_match:
            continue
        node_start = int(node.get("start_line") or 0)
        node_end = int(node.get("end_line") or node_start or 0)
        if start and not (node_start <= end and start <= node_end):
            continue
        return True, "METHOD" if method_name or start else "FILE"
    return False, "NONE"


def evaluate_frozen_run(
    *,
    run_root: str | Path,
    baseline: Mapping[str, Any],
    annotation: Mapping[str, Any],
    output_json: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(run_root)
    manifest = read_json(root / "detector_manifest.json")
    if not manifest.get("detector_frozen"):
        raise ValueError("detector output must be frozen before evaluation")
    for name, expected in manifest.get("artifact_hashes", {}).items():
        if sha256_file(root / name) != expected:
            raise ValueError(f"frozen detector artifact changed before evaluation: {name}")
    paths = read_jsonl(root / "candidate_paths.jsonl")
    matches: list[dict[str, Any]] = []
    for path in paths:
        consistent, granularity = _path_matches(path, annotation)
        structural = int(path.get("support_summary", {}).get("structural_edge_count") or 0)
        deterministic = int(path.get("support_summary", {}).get("deterministic_edge_count") or 0)
        proposal_edges = int(path.get("support_summary", {}).get("proposal_edge_count") or 0)
        non_anchor = any(
            edge.get("relation_kind") not in {"EXTERNAL_INPUT", "SECURITY_EFFECT"}
            for edge in path.get("ordered_edges", ())
        )
        causal_shape = proposal_edges > 0 and non_anchor and structural + deterministic > 0
        if consistent and causal_shape:
            matches.append(
                {
                    "candidate_path_id": path["candidate_path_id"],
                    "match_granularity": granularity,
                    "proposal_ids": path.get("proposal_ids", []),
                    "support_summary": path.get("support_summary", {}),
                }
            )
    baseline_miss = not bool(baseline.get("baseline_detected"))
    recovered = baseline_miss and bool(matches)
    result = {
        "schema_version": 1,
        "evaluator_version": EVALUATOR_VERSION,
        "evaluation_started_after_detector_freeze": True,
        "detector_manifest_hash": sha256_file(root / "detector_manifest.json"),
        "baseline_miss": baseline_miss,
        "candidate_path_count": len(paths),
        "benchmark_consistent_path_count": len(matches),
        "mechanism_recovered": recovered,
        "matched_paths": matches,
        "eligible_for_detection_metric": False,
        "metric_name": "MECHANISM_RECOVERY",
    }
    if output_json is not None:
        write_json(output_json, result)
    return result
