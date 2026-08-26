from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

PRIMARY_REASONS = {
    "SAME_METHOD",
    "CALL_ADJACENT",
    "SAME_RECEIVER",
    "FIELD_RELATED",
    "NEAR_CALL_REGION",
    "OTHER_STRUCTURAL",
}


def load_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    if not path.exists():
        return rows, issues
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            issues.append({"file": str(path), "line": line_no, "error": str(exc)})
            continue
        if not isinstance(value, dict):
            issues.append({"file": str(path), "line": line_no, "error": "record is not an object"})
            continue
        rows.append(value)
    return rows, issues


def load_json(path: Path) -> tuple[Any, list[dict[str, Any]]]:
    if not path.exists():
        return {}, []
    try:
        return json.loads(path.read_text(encoding="utf-8")), []
    except json.JSONDecodeError as exc:
        return {}, [{"file": str(path), "line": 1, "error": str(exc)}]


def find_value(record: Any, key: str, default: Any = None) -> Any:
    if isinstance(record, dict):
        if key in record:
            return record[key]
        for child in record.values():
            found = find_value(child, key, default)
            if found is not default:
                return found
    elif isinstance(record, list):
        for child in record:
            found = find_value(child, key, default)
            if found is not default:
                return found
    return default


def find_dict(record: Any, *preferred_keys: str) -> dict[str, Any]:
    if isinstance(record, dict):
        for key in preferred_keys:
            child = record.get(key)
            if isinstance(child, dict):
                return child
        for child in record.values():
            found = find_dict(child, *preferred_keys)
            if found:
                return found
    elif isinstance(record, list):
        for child in record:
            found = find_dict(child, *preferred_keys)
            if found:
                return found
    return {}


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return None
    return None


def distance_bucket(value: Any) -> str:
    number = _as_int(value)
    if number is None or number < 0:
        return "UNKNOWN"
    return "3+" if number >= 3 else str(number)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _node_kind(node: Any) -> str:
    if not isinstance(node, dict):
        return "UNKNOWN"
    value = node.get("kind") or node.get("node_kind") or node.get("role")
    return str(value).upper() if value is not None else "UNKNOWN"


def _anchor(record: dict[str, Any], side: str) -> dict[str, Any]:
    preferred = (
        ("input_analysis_anchor", "input_anchor", "analysis_anchor")
        if side == "input"
        else ("effect_analysis_anchor", "effect_anchor", "analysis_anchor")
    )
    anchor = find_dict(record, *preferred)
    if anchor:
        return anchor
    keys = (
        "candidate_id",
        "project_id",
        "anchor_kind",
        "value_role",
        "method_identity",
        "call_identity",
        "argument_index",
        "location",
        "mapping_status",
        "mapping_reason",
        "query_status",
    )
    return {key: find_value(record, key) for key in keys if find_value(record, key) is not None}


def _candidate_id(record: dict[str, Any], side: str) -> str:
    key = "input_candidate_id" if side == "input" else "effect_candidate_id"
    value = record.get(key)
    if value is None:
        value = _anchor(record, side).get("candidate_id")
    return str(value) if value is not None else "UNKNOWN"


def _project_id(record: dict[str, Any]) -> str:
    value = record.get("project_id") or find_value(record, "project")
    return str(value) if value is not None else "UNKNOWN"


def discover_p0a_dir(run_dir: Path, explicit: Path | None = None) -> Path | None:
    if explicit is not None:
        return explicit
    candidates = sorted(
        run_dir.parent.glob("W1-E1-DEV8-P0A-*"),
        key=lambda item: item.stat().st_mtime if item.exists() else 0,
    )
    return candidates[-1] if candidates else None


def _candidate_map(p0a_dir: Path | None, filename: str) -> dict[str, dict[str, Any]]:
    if p0a_dir is None:
        return {}
    rows, _ = load_jsonl(p0a_dir / filename)
    return {str(row.get("candidate_id")): row for row in rows if row.get("candidate_id")}


def classify_frontier(row: dict[str, Any]) -> tuple[str, str, str]:
    reason = str(row.get("frontier_reason") or "OTHER_STRUCTURAL")
    primary = reason if reason in PRIMARY_REASONS else "OTHER_STRUCTURAL"
    fw = row.get("fw_frontier_node") or {}
    bw = row.get("bw_frontier_node") or {}
    kinds = {_node_kind(fw), _node_kind(bw)}
    input_anchor = _anchor(row, "input")
    effect_anchor = _anchor(row, "effect")
    roles = {
        str(input_anchor.get("value_role") or "").upper(),
        str(effect_anchor.get("value_role") or "").upper(),
    }
    explicit_field = any("FIELD" in kind for kind in kinds) or any(
        key in fw or key in bw for key in ("field", "field_identity", "field_relation")
    )
    if explicit_field:
        return "FIELD_STATE_LIKE", "explicit field node/relation", "HIGH"
    if "RECEIVER" in kinds or "RECEIVER" in roles or primary == "SAME_RECEIVER":
        return "OBJECT_RECEIVER_RELATED", "explicit receiver node/role or SAME_RECEIVER", "HIGH"
    if primary == "SAME_METHOD":
        return "SAME_METHOD_UNRESOLVED", "frontier_reason=SAME_METHOD", "HIGH"
    if primary == "CALL_ADJACENT":
        return "DIRECT_DATA_CALL_NEAR_MISS", "frontier_reason=CALL_ADJACENT", "MEDIUM"
    if primary == "NEAR_CALL_REGION":
        return "CALL_BOUNDARY_UNRESOLVED", "frontier_reason=NEAR_CALL_REGION", "MEDIUM"
    return "UNKNOWN_STRUCTURAL", "insufficient explicit semantic structure", "LOW"


def _frontier_row(
    row: dict[str, Any],
    effect_map: dict[str, dict[str, Any]],
    input_map: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    input_id = _candidate_id(row, "input")
    effect_id = _candidate_id(row, "effect")
    input_anchor = _anchor(row, "input")
    effect_anchor = _anchor(row, "effect")
    likely, evidence, confidence = classify_frontier(row)
    return {
        "frontier_id": row.get("structural_frontier_id", "UNKNOWN"),
        "project_id": _project_id(row),
        "input_candidate_id": input_id,
        "effect_candidate_id": effect_id,
        "frontier_reason": row.get("frontier_reason", "OTHER_STRUCTURAL"),
        "structural_distance": row.get("structural_distance"),
        "distance_bucket": distance_bucket(row.get("structural_distance")),
        "fw_node_kind": _node_kind(row.get("fw_frontier_node")),
        "bw_node_kind": _node_kind(row.get("bw_frontier_node")),
        "fw_node": row.get("fw_frontier_node") or {},
        "bw_node": row.get("bw_frontier_node") or {},
        "input_method": input_anchor.get("method_identity", ""),
        "effect_method": effect_anchor.get("method_identity", ""),
        "input_mechanism": input_map.get(input_id, {}).get("mechanism", "UNKNOWN"),
        "effect_type": effect_map.get(effect_id, {}).get("effect_type", "UNKNOWN"),
        "likely_class": likely,
        "evidence_basis": evidence,
        "confidence": confidence,
        "diagnostic_only": row.get("diagnostic_only") is True,
        "adds_propagation_edge": row.get("adds_propagation_edge") is True,
    }


def _write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def _aggregate(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    counts = Counter(str(row.get(key) or "UNKNOWN") for row in rows)
    total = len(rows)
    return [
        {key: value, "count": count, "percentage": round(count / total * 100, 4) if total else 0.0}
        for value, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def _dedup_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    node_pairs = {
        (
            row["project_id"],
            row["input_candidate_id"],
            row["effect_candidate_id"],
            _canonical(row["fw_node"]),
            _canonical(row["bw_node"]),
        )
        for row in rows
    }
    input_effect_pairs = {
        (row["project_id"], row["input_candidate_id"], row["effect_candidate_id"])
        for row in rows
    }
    method_regions = {
        (row["project_id"], row["input_method"], row["effect_method"], row["frontier_reason"])
        for row in rows
    }
    return {
        "raw_frontier_count": len(rows),
        "unique_frontier_node_pair_count": len(node_pairs),
        "unique_input_effect_pair_count": len(input_effect_pairs),
        "unique_project_method_region_count": len(method_regions),
    }


def _bw_case(row: dict[str, Any], effect_map: dict[str, dict[str, Any]]) -> dict[str, Any]:
    anchor = _anchor(row, "effect")
    effect_id = str(row.get("candidate_id") or anchor.get("candidate_id") or "UNKNOWN")
    mapping = str(find_value(row, "mapping_status", "UNKNOWN"))
    mapping_reason = str(find_value(row, "mapping_reason", "UNKNOWN"))
    query_status = str(find_value(row, "query_status", "UNKNOWN"))
    funnel = str(row.get("funnel_status") or "UNKNOWN")
    reachable = _as_int(row.get("reachable_node_count")) or 0
    active = reachable > 0 or funnel in {"ACTIVE_BW", "BW_ACTIVE", "ACTIVE"}
    if mapping not in {"MAPPED", "SUCCESS"}:
        primary, secondary = "ANCHOR_UNMAPPABLE", "UNKNOWN"
    elif query_status not in {"SUCCESS", "OK"}:
        primary, secondary = "QUERY_ERROR", "UNKNOWN"
    elif active:
        primary, secondary = "BW_ACTIVE", "NOT_APPLICABLE"
    else:
        primary = "MAPPED_BUT_EMPTY_BW"
        role = str(anchor.get("value_role") or find_value(row, "value_role", "UNKNOWN"))
        call_identity = anchor.get("call_identity") or find_value(row, "call_identity")
        if role in {"UNKNOWN", "", "None"}:
            secondary = "UNSUPPORTED_VALUE_ROLE"
        elif not call_identity:
            secondary = "CALLSITE_RESOLUTION_LIMITATION"
        else:
            secondary = "NO_PREDECESSOR_IN_BASE_DATA_CALL"
    critical = effect_map.get(effect_id, {}).get("critical_roles", [])
    if isinstance(critical, list):
        critical = ",".join(str(value) for value in critical)
    return {
        "candidate_id": effect_id,
        "project_id": str(row.get("project_id") or anchor.get("project_id") or "UNKNOWN"),
        "effect_type": effect_map.get(effect_id, {}).get("effect_type", "UNKNOWN"),
        "critical_role": critical or "UNKNOWN",
        "anchor_kind": anchor.get("anchor_kind", find_value(row, "anchor_kind", "UNKNOWN")),
        "value_role": anchor.get("value_role", find_value(row, "value_role", "UNKNOWN")),
        "argument_index": anchor.get("argument_index", find_value(row, "argument_index", "")),
        "mapping_status": mapping,
        "mapping_reason": mapping_reason,
        "query_status": query_status,
        "funnel_status": funnel,
        "reachable_node_count": reachable,
        "bw_active": active,
        "root_cause": primary,
        "secondary_root_cause": secondary,
    }


def _recommend(frontier_rows: list[dict[str, Any]]) -> tuple[str, bool]:
    project_counts = Counter(row["project_id"] for row in frontier_rows)
    top_share = max(project_counts.values()) / len(frontier_rows) if frontier_rows else 0.0
    class_counts = Counter(row["likely_class"] for row in frontier_rows)
    unknown_share = class_counts.get("UNKNOWN_STRUCTURAL", 0) / len(frontier_rows) if frontier_rows else 1.0
    if top_share >= 0.8:
        return "PROJECT_CONCENTRATED_EVIDENCE; INSUFFICIENT_EVIDENCE_FOR_E2", True
    if unknown_share >= 0.5:
        return "INSUFFICIENT_EVIDENCE_FOR_E2", False
    return "FIX_W1_E1_IMPLEMENTATION", False


def _markdown_table(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "_none_"
    fields = list(rows[0])
    lines = ["| " + " | ".join(fields) + " |", "| " + " | ".join("---" for _ in fields) + " |"]
    lines.extend("| " + " | ".join(str(row.get(field, "")) for field in fields) + " |" for row in rows)
    return "\n".join(lines)


def analyze(run_dir: Path, output_dir: Path, p0a_dir: Path | None = None) -> dict[str, Any]:
    run_dir = Path(run_dir)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    p0a_dir = discover_p0a_dir(run_dir, p0a_dir)
    effect_map = _candidate_map(p0a_dir, "security_effects.jsonl")
    input_map = _candidate_map(p0a_dir, "external_inputs.jsonl")
    frontier_raw, frontier_issues = load_jsonl(run_dir / "structural_frontiers.jsonl")
    bw_raw, bw_issues = load_jsonl(run_dir / "effect_backward_funnel.jsonl")
    issues = frontier_issues + bw_issues
    frontier_rows = [_frontier_row(row, effect_map, input_map) for row in frontier_raw]
    bw_rows = [_bw_case(row, effect_map) for row in bw_raw]
    primary = _aggregate(frontier_rows, "frontier_reason")
    likely = _aggregate(frontier_rows, "likely_class")
    distances = _aggregate(frontier_rows, "distance_bucket")
    mechanisms = _aggregate(frontier_rows, "input_mechanism")
    effects = _aggregate(frontier_rows, "effect_type")
    dedup = _dedup_summary(frontier_rows)
    projects: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in frontier_rows:
        projects[row["project_id"]].append(row)
    project_table = [
        {
            "project": project,
            "frontier_count": len(rows),
            "unique_input_effect_pairs": len({(r["input_candidate_id"], r["effect_candidate_id"]) for r in rows}),
            "percentage": round(len(rows) / len(frontier_rows) * 100, 4) if frontier_rows else 0.0,
        }
        for project, rows in sorted(projects.items(), key=lambda item: (-len(item[1]), item[0]))
    ]
    top1 = project_table[0]["frontier_count"] / len(frontier_rows) if project_table and frontier_rows else 0.0
    top3 = sum(row["frontier_count"] for row in project_table[:3]) / len(frontier_rows) if frontier_rows else 0.0
    bw_effect: list[dict[str, Any]] = []
    for effect_type in sorted({row["effect_type"] for row in bw_rows}):
        group = [row for row in bw_rows if row["effect_type"] == effect_type]
        active = sum(row["bw_active"] for row in group)
        bw_effect.append(
            {
                "effect_type": effect_type,
                "total_candidates": len(group),
                "mapped": sum(row["mapping_status"] in {"MAPPED", "SUCCESS"} for row in group),
                "bw_active": active,
                "bw_inactive": len(group) - active,
                "bw_active_rate": round(active / len(group), 6) if group else 0.0,
            }
        )
    bw_role: list[dict[str, Any]] = []
    for role in sorted({str(row["value_role"] or "UNKNOWN") for row in bw_rows}):
        group = [row for row in bw_rows if str(row["value_role"] or "UNKNOWN") == role]
        active = sum(row["bw_active"] for row in group)
        bw_role.append(
            {
                "anchor_role": role,
                "total": len(group),
                "mapped": sum(row["mapping_status"] in {"MAPPED", "SUCCESS"} for row in group),
                "bw_active": active,
                "bw_inactive": len(group) - active,
                "bw_active_rate": round(active / len(group), 6) if group else 0.0,
            }
        )
    recommendation, concentrated = _recommend(frontier_rows)
    summary = {
        "status": "SUCCESS" if not issues else "SUCCESS_WITH_DATA_QUALITY_WARNINGS",
        "run_dir": str(run_dir),
        "output_dir": str(output_dir),
        "p0a_dir": str(p0a_dir) if p0a_dir else None,
        "raw_frontier_count": len(frontier_rows),
        "deduplicated_frontier_count": dedup["unique_frontier_node_pair_count"],
        "top_frontier_reason": primary[0]["frontier_reason"] if primary else "UNKNOWN",
        "top_likely_semantic_class": likely[0]["likely_class"] if likely else "UNKNOWN_STRUCTURAL",
        "project_concentration": {
            "top1_project_share": round(top1, 6),
            "top3_project_share": round(top3, 6),
            "project_concentrated": concentrated,
        },
        "bw_inactive_count": sum(not row["bw_active"] for row in bw_rows),
        "bw_active_count": sum(row["bw_active"] for row in bw_rows),
        "bw_inactive_root_causes": dict(Counter(row["secondary_root_cause"] for row in bw_rows if not row["bw_active"])),
        "scientific_method_changed": "NO",
        "codeql_rerun_performed": False,
        "gt_used_in_detector_diagnosis": False,
        "post_hoc_gt_overlay": "NOT_AVAILABLE",
        "next_recommended_experiment": recommendation,
        "generalization_caution": "PROJECT_CONCENTRATED evidence" if concentrated else "not project-concentrated",
        "data_quality_issues": issues,
        "frontier_primary_reason": primary,
        "frontier_likely_class": likely,
        "frontier_distance_bucket": distances,
        "frontier_by_project": project_table,
        "frontier_by_input_mechanism": mechanisms,
        "frontier_by_effect_type": effects,
        "bw_by_effect_type": bw_effect,
        "bw_by_anchor_role": bw_role,
    }
    _write_csv(output_dir / "frontier_taxonomy.csv", frontier_rows, list(frontier_rows[0]) if frontier_rows else ["frontier_id"])
    _write_csv(output_dir / "frontier_by_project.csv", project_table, ["project", "frontier_count", "unique_input_effect_pairs", "percentage"])
    _write_csv(output_dir / "frontier_by_effect_type.csv", effects, ["effect_type", "count", "percentage"])
    _write_csv(output_dir / "frontier_by_input_mechanism.csv", mechanisms, ["input_mechanism", "count", "percentage"])
    _write_csv(output_dir / "bw_inactive_cases.csv", bw_rows, list(bw_rows[0]) if bw_rows else ["candidate_id"])
    _write_csv(output_dir / "bw_by_effect_type.csv", bw_effect, ["effect_type", "total_candidates", "mapped", "bw_active", "bw_inactive", "bw_active_rate"])
    _write_csv(output_dir / "bw_by_anchor_role.csv", bw_role, ["anchor_role", "total", "mapped", "bw_active", "bw_inactive", "bw_active_rate"])
    (output_dir / "frontier_taxonomy.json").write_text(json.dumps({"raw_frontier_count": len(frontier_rows), "primary_reason": primary, "likely_class": likely, "distance_bucket": distances, "project": project_table, "input_mechanism": mechanisms, "effect_type": effects}, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "frontier_dedup_summary.json").write_text(json.dumps(dedup, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "bw_inactive_root_cause.json").write_text(json.dumps({"total_candidates": len(bw_rows), "mapped": sum(row["mapping_status"] in {"MAPPED", "SUCCESS"} for row in bw_rows), "bw_active": sum(row["bw_active"] for row in bw_rows), "bw_inactive": sum(not row["bw_active"] for row in bw_rows), "primary_root_cause": dict(Counter(row["root_cause"] for row in bw_rows)), "secondary_root_cause": dict(Counter(row["secondary_root_cause"] for row in bw_rows if not row["bw_active"]))}, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    report = f"""# W1-E1 Attribution Analysis

## 1. Scope

Read-only attribution of frozen W1-E1 artifacts. No new detector run, no CodeQL
rerun, no scientific method change, no semantic edge, no LLM, and no Route B.

## 2. Frozen W1-E1 facts

8/8 projects; 114 ExternalInput; 78 FW-active; 23 SecurityEffect; 5 BW-active;
287 structural frontiers; 0 static connected paths.

## 3. Frontier taxonomy

{_markdown_table(primary)}

Distance buckets:

{_markdown_table(distances)}

## 4. Deduplicated frontier distribution

{json.dumps(dedup, ensure_ascii=False, indent=2)}

## 5. Frontier by project

{_markdown_table(project_table)}

top1_project_share={top1:.6f}; top3_project_share={top3:.6f}

## 6. Frontier by input mechanism

{_markdown_table(mechanisms)}

## 7. Frontier by effect type

{_markdown_table(effects)}

## 8. Likely semantic class

These are LIKELY_FRONTIER_CLASS attributions, not confirmed semantic gaps.

{_markdown_table(likely)}

## 9. SecurityEffect BW funnel

{_markdown_table(bw_effect)}

## 10. BW inactive root causes

{_markdown_table([{"root_cause": key, "count": value} for key, value in sorted(Counter(row["secondary_root_cause"] for row in bw_rows if not row["bw_active"]).items())])}

## 11. BW failure by effect type

{_markdown_table(bw_effect)}

## 12. BW failure by anchor/value role

{_markdown_table(bw_role)}

## 13. Key findings

Raw frontier count={len(frontier_rows)}; deduplicated node-pair count={dedup["unique_frontier_node_pair_count"]}.
Top frontier reason={summary["top_frontier_reason"]}; top likely class={summary["top_likely_semantic_class"]}.
Project concentration={summary["generalization_caution"]}; post-hoc GT overlay=NOT_AVAILABLE.

## 14. NEXT_RECOMMENDED_EXPERIMENT

{recommendation}

Do not start E2 from this Dev8 result. Preserve the current W1-E1 scientific
method; if implementation fixes are pursued, validate them under W1-E1 before
selecting a new semantic mechanism.
"""
    (output_dir / "W1_E1_ATTRIBUTION_REPORT.md").write_text(report, encoding="utf-8")
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline W1-E1 frontier/BW attribution")
    parser.add_argument("--run-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--p0a-dir", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = analyze(args.run_dir, args.output_dir, args.p0a_dir)
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if summary["status"].startswith("SUCCESS") else 2


if __name__ == "__main__":
    raise SystemExit(main())
