from __future__ import annotations

import json

from java_vuln_research.common.paths import normalise_program_path, same_program_file
from java_vuln_research.evaluation.sanity import evaluate_e0_sanity


def test_common_path_normalizer_matches_uri_absolute_and_relative_paths() -> None:
    assert normalise_program_path("file:///workspace/repo/src/A%20B.java") == "workspace/repo/src/a b.java"
    assert same_program_file("file:///workspace/repo/src/main/java/demo/A.java", "src/main/java/demo/A.java")
    assert same_program_file(r"C:\repo\src\A.java", "src/A.java")
    assert not same_program_file("src/demo/A.java", "src/other/A.java")


def test_e0_sanity_audits_sarif_parser_and_location_matching(tmp_path) -> None:
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "schema_version: 1\nprojects:\n"
        "  - project: P001\n"
        "    revision: abc123\n"
        "    source_path: /workspace/P001\n"
        "    codeql_db_path: /workspace/db/P001\n",
        encoding="utf-8",
    )
    project_info = tmp_path / "project_info.csv"
    project_info.write_text(
        "project_slug,cve_id,buggy_commit_id\ndemo/project,CVE-TEST,abc123\n",
        encoding="utf-8",
    )
    fix_info = tmp_path / "fix_info.csv"
    fix_info.write_text(
        "project_slug,cve_id,file,method_start,method_end,line_start,line_end\n"
        "demo/project,CVE-TEST,src/main/java/demo/A.java,10,20,15,15\n",
        encoding="utf-8",
    )
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    (baseline / "baseline_output.jsonl").write_text(
        json.dumps({"project": "P001", "alert_count": 1, "path_count": 1}) + "\n",
        encoding="utf-8",
    )
    sarif = {
        "runs": [{
            "results": [{
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "file:///workspace/P001/src/main/java/demo/A.java"},
                    "region": {"startLine": 15},
                }}],
                "codeFlows": [{"threadFlows": [{"locations": [{"location": {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/main/java/demo/A.java"},
                        "region": {"startLine": 18},
                    }
                }}]}]}],
            }]
        }]
    }
    (baseline / "P001.sarif").write_text(json.dumps(sarif), encoding="utf-8")

    result = evaluate_e0_sanity(
        detector_manifest=manifest,
        project_info_csv=project_info,
        fix_info_csv=fix_info,
        baseline_raw_dir=tmp_path,
        output_root=tmp_path / "out",
    )

    assert result["native_alert_count"] == 1
    assert result["native_path_count"] == 1
    assert result["native_location_count"] == 2
    assert result["same_file_count"] == 2
    assert result["same_method_count_if_available"] == 2
    assert result["exact_line_overlap_count"] == 1
    assert result["nearest_line_distance_distribution"] == {"0": 2}
    assert (tmp_path / "out" / "e0_evaluator_sanity.md").is_file()
