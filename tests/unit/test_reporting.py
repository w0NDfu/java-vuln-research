from __future__ import annotations

import json

from java_vuln_research.common.io import write_json, write_jsonl
from java_vuln_research.reporting import generate_e0_report


def test_report_preserves_failures_and_not_applicable_semantic_metrics(tmp_path) -> None:
    raw = tmp_path / "raw"
    (raw / "baseline").mkdir(parents=True)
    write_json(
        raw / "run_manifest.json",
        {
            "run_id": "MSA-P0-E0-test",
            "status": "PARTIAL",
            "git_commit": "abc",
            "git_branch": "main",
            "timestamp_start": "start",
            "timestamp_end": "end",
            "codeql_version": "CodeQL test",
            "java_version": "Java test",
            "maven_version": None,
            "gradle_version": None,
            "python_version": "3.test",
            "projects_requested": 2,
            "projects_runnable": 1,
        },
    )
    write_jsonl(
        raw / "baseline" / "baseline_output.jsonl",
        [
            {
                "project": "ok",
                "status": "SUCCESS",
                "exit_code": 0,
                "alert_count": 2,
                "path_count": 1,
                "runtime_seconds": 1.0,
            },
            {
                "project": "bad",
                "status": "FAILED",
                "stage": "CODEQL_ANALYZE",
                "exit_code": 2,
                "error_class": "QUERY_FAILURE",
                "runtime_seconds": 0.5,
            },
        ],
    )
    target = tmp_path / "report"

    summary = generate_e0_report(raw_run_dir=raw, report_dir=target)

    assert summary["baseline_alerts"] == 2
    assert summary["new_inputs"] == "NOT_APPLICABLE"
    failures = (target / "failures.jsonl").read_text(encoding="utf-8")
    assert "QUERY_FAILURE" in failures
    assert "failed projects as negative samples" in (target / "report.md").read_text(
        encoding="utf-8"
    )


def test_report_marks_empty_baseline_as_infrastructure_blocker(tmp_path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    write_json(
        raw / "run_manifest.json",
        {
            "run_id": "MSA-P0-E0-empty",
            "status": "FAILED",
            "git_commit": "abc",
            "git_branch": "main",
            "timestamp_start": "start",
            "timestamp_end": "end",
            "projects_requested": 0,
            "projects_runnable": 0,
        },
    )

    generate_e0_report(raw_run_dir=raw, report_dir=tmp_path / "report")

    report = (tmp_path / "report" / "report.md").read_text(encoding="utf-8")
    failures = (tmp_path / "report" / "failures.jsonl").read_text(encoding="utf-8")
    assert "NO_RUNNABLE_PROJECTS" in report
    assert "NO_RUNNABLE_PROJECTS" in failures
    assert "Resolve recorded execution failures" in report
