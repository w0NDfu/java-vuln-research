from __future__ import annotations

from java_vuln_research.common.io import write_csv, write_jsonl
from java_vuln_research.evaluation import evaluate_p0a


def _candidate(candidate_id: str, kind: str, line: int, source: str) -> dict:
    return {
        "candidate_id": candidate_id,
        "kind": kind,
        "source": source,
        "evidence": [
            {
                "project": "P001",
                "revision": "abc123",
                "file": "src/main/java/demo/A.java",
                "line": line,
            }
        ],
    }


def test_evaluate_p0a_keeps_unreviewed_candidates_unknown(tmp_path) -> None:
    detector = tmp_path / "detector"
    write_jsonl(
        detector / "external_inputs.jsonl",
        [_candidate("ext-1", "EXTERNAL_INPUT", 15, "STATIC")],
    )
    write_jsonl(
        detector / "security_effects.jsonl",
        [_candidate("effect-1", "SECURITY_EFFECT", 30, "STATIC_DERIVED")],
    )

    project_info = tmp_path / "project_info.csv"
    write_csv(
        project_info,
        ["project_slug", "buggy_commit_id"],
        [{"project_slug": "demo/project", "buggy_commit_id": "abc123"}],
    )
    fix_info = tmp_path / "fix_info.csv"
    write_csv(
        fix_info,
        ["project_slug", "file", "class", "method", "method_start", "method_end"],
        [
            {
                "project_slug": "demo/project",
                "file": "src/main/java/demo/A.java",
                "class": "demo.A",
                "method": "read",
                "method_start": 10,
                "method_end": 20,
            }
        ],
    )

    output = tmp_path / "evaluation"
    summary = evaluate_p0a(detector, project_info, fix_info, output)

    assert summary == {
        "status": "SUCCESS",
        "native_source_count": "NOT_APPLICABLE",
        "discovered_external_input_count": 1,
        "new_external_input_count": "NOT_APPLICABLE",
        "native_sink_count": "NOT_APPLICABLE",
        "discovered_security_effect_count": 1,
        "new_security_effect_count": "NOT_APPLICABLE",
        "wrapper_count": 1,
        "manual_confirmed_count": "NOT_APPLICABLE",
        "false_candidate_count": "NOT_APPLICABLE",
        "unknown_count": 2,
        "projects_observed": 1,
        "ground_truth_projects_mapped": 1,
        "unmapped_projects": [],
        "ground_truth_location_match_count": 1,
        "evaluation_basis": "FIX_LOCATION_OVERLAP_ONLY",
        "manual_review_status": "NOT_PERFORMED",
    }
    rows = (output / "candidate_evaluation.jsonl").read_text(encoding="utf-8")
    assert rows.count('"decision": "UNKNOWN"') == 2
    assert rows.count('"ground_truth_location_match": true') == 1
