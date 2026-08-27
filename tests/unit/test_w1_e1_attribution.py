from __future__ import annotations

import json
from pathlib import Path

from java_vuln_research.analysis.w1_e1_attribution import analyze, classify_frontier


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(row) for row in rows) + ("\n" if rows else ""), encoding="utf-8")


def _fixture(tmp_path: Path, frontier_rows: list[dict] | None = None) -> tuple[Path, Path]:
    run = tmp_path / "run"
    p0a = tmp_path / "p0a"
    frontier = frontier_rows or [
        {
            "structural_frontier_id": "f1",
            "project_id": "P1",
            "input_candidate_id": "in1",
            "effect_candidate_id": "eff1",
            "frontier_reason": "CALL_ADJACENT",
            "structural_distance": 1,
            "fw_frontier_node": {"kind": "CALL_RESULT", "entity": "A.m"},
            "bw_frontier_node": {"kind": "CALL_ARGUMENT", "entity": "B.n"},
            "input_analysis_anchor": {
                "candidate_id": "in1",
                "method_identity": "A.source/0",
                "value_role": "CALL_RESULT",
            },
            "effect_analysis_anchor": {
                "candidate_id": "eff1",
                "method_identity": "B.sink/1",
                "call_identity": "B.n@file:10",
                "value_role": "CALL_ARGUMENT",
            },
            "diagnostic_only": True,
            "adds_propagation_edge": False,
        }
    ]
    _write_jsonl(run / "structural_frontiers.jsonl", frontier)
    _write_jsonl(
        run / "effect_backward_funnel.jsonl",
        [
            {
                "candidate_id": "eff1",
                "project_id": "P1",
                "analysis_anchor": {
                    "candidate_id": "eff1",
                    "project_id": "P1",
                    "anchor_kind": "CALL_ARGUMENT",
                    "value_role": "CALL_ARGUMENT",
                    "call_identity": "B.n@file:10",
                    "argument_index": 0,
                    "mapping_status": "MAPPED",
                    "mapping_reason": "SECURITY_CRITICAL_CALL_VALUE",
                    "query_status": "SUCCESS",
                },
                "reachable_node_count": 0,
                "funnel_status": "EMPTY_BW",
            }
        ],
    )
    _write_jsonl(
        p0a / "security_effects.jsonl",
        [
            {
                "candidate_id": "eff1",
                "effect_type": "PROCESS_EXECUTION",
                "critical_roles": ["arg0"],
            }
        ],
    )
    _write_jsonl(
        p0a / "external_inputs.jsonl",
        [{"candidate_id": "in1", "mechanism": "SERVLET_PARAMETER"}],
    )
    (run / "candidate_paths.jsonl").write_text("", encoding="utf-8")
    return run, p0a


def test_taxonomy_mapping_is_deterministic(tmp_path: Path) -> None:
    run, p0a = _fixture(tmp_path)
    first = analyze(run, tmp_path / "out1", p0a)
    second = analyze(run, tmp_path / "out2", p0a)
    assert first["frontier_likely_class"] == second["frontier_likely_class"]
    assert first["frontier_primary_reason"] == second["frontier_primary_reason"]


def test_dedup_works(tmp_path: Path) -> None:
    run, p0a = _fixture(tmp_path)
    row = json.loads((run / "structural_frontiers.jsonl").read_text().splitlines()[0])
    _write_jsonl(run / "structural_frontiers.jsonl", [row, row])
    summary = analyze(run, tmp_path / "out", p0a)
    assert summary["raw_frontier_count"] == 2
    assert summary["deduplicated_frontier_count"] == 1


def test_unknown_frontier_remains_unknown() -> None:
    likely, evidence, confidence = classify_frontier(
        {"frontier_reason": "UNSEEN_REASON", "fw_frontier_node": {}, "bw_frontier_node": {}}
    )
    assert likely == "UNKNOWN_STRUCTURAL"
    assert confidence == "LOW"
    assert "insufficient" in evidence


def test_bw_mapped_empty_is_classified(tmp_path: Path) -> None:
    run, p0a = _fixture(tmp_path)
    summary = analyze(run, tmp_path / "out", p0a)
    cases = list(csv_rows(tmp_path / "out" / "bw_inactive_cases.csv"))
    assert summary["bw_inactive_count"] == 1
    assert cases[0]["root_cause"] == "MAPPED_BUT_EMPTY_BW"
    assert cases[0]["secondary_root_cause"] == "NO_PREDECESSOR_IN_BASE_DATA_CALL"


def test_project_names_do_not_change_classification(tmp_path: Path) -> None:
    run, p0a = _fixture(tmp_path)
    rows = [json.loads(line) for line in (run / "structural_frontiers.jsonl").read_text().splitlines()]
    rows.append({**rows[0], "structural_frontier_id": "f2", "project_id": "another-project"})
    _write_jsonl(run / "structural_frontiers.jsonl", rows)
    summary = analyze(run, tmp_path / "out", p0a)
    assert {row["likely_class"] for row in csv_rows(tmp_path / "out" / "frontier_taxonomy.csv")} == {
        "DIRECT_DATA_CALL_NEAR_MISS"
    }
    assert summary["project_concentration"]["project_concentrated"] is False


def test_malformed_artifact_is_reported(tmp_path: Path) -> None:
    run, p0a = _fixture(tmp_path)
    (run / "structural_frontiers.jsonl").write_text("{bad json\n", encoding="utf-8")
    summary = analyze(run, tmp_path / "out", p0a)
    assert summary["status"] == "SUCCESS_WITH_DATA_QUALITY_WARNINGS"
    assert summary["data_quality_issues"]


def test_empty_candidate_paths_does_not_crash(tmp_path: Path) -> None:
    run, p0a = _fixture(tmp_path)
    (run / "candidate_paths.jsonl").write_text("", encoding="utf-8")
    summary = analyze(run, tmp_path / "out", p0a)
    assert summary["status"].startswith("SUCCESS")
    assert (tmp_path / "out" / "W1_E1_ATTRIBUTION_REPORT.md").exists()


def test_287_raw_frontiers_have_stable_aggregate(tmp_path: Path) -> None:
    run, p0a = _fixture(tmp_path)
    row = json.loads((run / "structural_frontiers.jsonl").read_text().splitlines()[0])
    rows = [{**row, "structural_frontier_id": f"f{i}"} for i in range(287)]
    _write_jsonl(run / "structural_frontiers.jsonl", rows)
    summary = analyze(run, tmp_path / "out", p0a)
    assert summary["raw_frontier_count"] == 287
    assert summary["frontier_primary_reason"][0]["count"] == 287




def test_effect_aggregation_uses_unique_candidate_id_not_frontier_rows(tmp_path: Path) -> None:
    run, p0a = _fixture(tmp_path)
    base = json.loads((run / "structural_frontiers.jsonl").read_text().splitlines()[0])
    _write_jsonl(
        run / "structural_frontiers.jsonl",
        [
            {**base, "structural_frontier_id": "f1", "input_candidate_id": "in1"},
            {**base, "structural_frontier_id": "f2", "input_candidate_id": "in2"},
            {**base, "structural_frontier_id": "f3", "input_candidate_id": "in3"},
        ],
    )
    summary = analyze(run, tmp_path / "out", p0a)

    assert summary["raw_frontier_count"] == 3
    assert summary["security_effect_candidate_count"] == 1
    assert summary["frontier_by_effect_type"] == [
        {"effect_type": "PROCESS_EXECUTION", "count": 1, "percentage": 100.0}
    ]


def test_bw_aggregation_deduplicates_candidate_and_ors_activity(tmp_path: Path) -> None:
    run, p0a = _fixture(tmp_path)
    rows = [
        json.loads(line)
        for line in (run / "effect_backward_funnel.jsonl").read_text().splitlines()
    ]
    active = {
        **rows[0],
        "reachable_node_count": 2,
        "funnel_status": "ACTIVE",
    }
    _write_jsonl(run / "effect_backward_funnel.jsonl", [rows[0], active])
    summary = analyze(run, tmp_path / "out", p0a)

    assert summary["bw_active_count"] == 1
    assert summary["bw_inactive_count"] == 0
    assert summary["bw_by_effect_type"][0]["total_candidates"] == 1
    assert summary["bw_by_effect_type"][0]["bw_active"] == 1

def csv_rows(path: Path):
    import csv

    with path.open(encoding="utf-8", newline="") as handle:
        yield from csv.DictReader(handle)
