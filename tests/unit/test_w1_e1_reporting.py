from __future__ import annotations

import json

from java_vuln_research.common.io import write_json, write_jsonl
from java_vuln_research.reporting import generate_w1_e1_report


def test_w1_e1_report_merges_detector_and_evaluator_outputs(tmp_path) -> None:
    raw = tmp_path / "raw"
    write_json(
        raw / "detector_metrics.json",
        {
            "status": "SUCCESS", "projects_total": 1, "projects_runnable": 1,
            "external_input_candidates": 2, "security_effect_candidates": 1,
            "candidate_paths_total": 3, "static_connected_paths": 2,
            "frontier_candidate_paths": 1, "frontier_reason_counts": {"OTHER": 1},
            "candidate_paths_per_project": {"P001": 3},
            "codeql_query_time": 1.25, "error_count": 0, "unknown_count": 0,
        },
    )
    write_json(
        raw / "coverage_metrics.json",
        {
                "ground_truth_evaluable": 1, "evaluable_vulnerabilities": 1, "file_level_covered": 1,
            "method_level_covered": 1, "line_level_covered": "NOT_EVALUABLE",
            "baseline_coverage": 0, "e1_coverage": 1,
            "baseline_miss_recovered": 1, "recovered_case_ids": ["demo:CVE-1"],
        },
    )
    write_jsonl(raw / "baseline_reference" / "baseline" / "baseline_output.jsonl", [{"status": "SUCCESS", "path_count": 2}])
    config = tmp_path / "p0.yaml"
    config.write_text("experiment: W1-E1\n", encoding="utf-8")
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "schema_version: 1\nprojects:\n"
        "  - project: P001\n    revision: abc\n    source_path: /src/P001\n    codeql_db_path: /db/P001\n",
        encoding="utf-8",
    )

    summary = generate_w1_e1_report(
        run_id="W1-E1-test", raw_run_dir=raw, baseline_raw_dir=raw / "baseline_reference", project_root=tmp_path,
        dataset_name="test", dataset_revision="abc", detector_manifest=manifest,
        config=config, started_at="2026-08-26T00:00:00Z", command="test-command",
    )

    assert summary["candidate_expansion_factor"] == 1.5
    assert summary["baseline_miss_recovered"] == 1
    persisted = json.loads((raw / "run_manifest.json").read_text(encoding="utf-8"))
    assert persisted["detector_ground_truth_access"] is False
    assert persisted["candidate_schema_version"] == 2
    assert persisted["analysis_anchor_schema_version"] == 1
    assert persisted["projects"] == [{"project_id": "P001", "revision": "abc", "db_id": "/db/P001"}]
