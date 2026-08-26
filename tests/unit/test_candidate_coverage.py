from __future__ import annotations

import json

from java_vuln_research.common.io import write_csv, write_jsonl
from java_vuln_research.evaluation import evaluate_candidate_coverage


def _path() -> dict:
    return {
        "candidate_path_id": "path-1",
        "project_id": "P001",
        "source_locations": [
            {"file": "src/main/java/demo/A.java", "line": 15},
            {"file": "src/main/java/demo/B.java", "line": 30},
        ],
    }


def test_candidate_coverage_reports_method_coverage_and_baseline_miss_recovery(tmp_path) -> None:
    paths = tmp_path / "candidate_paths.jsonl"
    write_jsonl(paths, [_path()])
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "schema_version: 1\nprojects:\n  - project: P001\n    revision: abc123\n    source_path: /projects/P001\n    codeql_db_path: /db/P001\n",
        encoding="utf-8",
    )
    project_info = tmp_path / "project_info.csv"
    write_csv(
        project_info,
        ["project_slug", "cve_id", "buggy_commit_id"],
        [{"project_slug": "demo/project", "cve_id": "CVE-1", "buggy_commit_id": "abc123"}],
    )
    fix_info = tmp_path / "fix_info.csv"
    write_csv(
        fix_info,
        ["project_slug", "cve_id", "file", "method_start", "method_end"],
        [{"project_slug": "demo/project", "cve_id": "CVE-1", "file": "src/main/java/demo/A.java", "method_start": 10, "method_end": 20}],
    )
    baseline = tmp_path / "e0"
    (baseline / "baseline").mkdir(parents=True)
    (baseline / "baseline" / "P001.sarif").write_text(
        json.dumps({"runs": [{"results": [{"locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/main/java/demo/A.java"}, "region": {"startLine": 5}}}]}]}]}),
        encoding="utf-8",
    )

    output = tmp_path / "evaluation"
    summary = evaluate_candidate_coverage(
        candidate_paths_file=paths,
        detector_manifest=manifest,
        project_info_csv=project_info,
        fix_info_csv=fix_info,
        baseline_raw_dir=baseline,
        output_root=output,
    )

    assert summary["ground_truth_evaluable"] == 1
    assert summary["file_level_covered"] == 1
    assert summary["method_level_covered"] == 1
    assert summary["line_level_covered"] == "NOT_EVALUABLE"
    assert summary["baseline_coverage"] == 0
    assert summary["e1_coverage"] == 1
    assert summary["baseline_miss_recovered"] == 1
    assert summary["recovered_case_ids"] == ["demo/project:CVE-1"]
    assert (output / "coverage_cases.jsonl").read_text(encoding="utf-8").count("path-1") == 1
