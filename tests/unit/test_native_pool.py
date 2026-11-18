from __future__ import annotations

import json
from pathlib import Path

import pytest

from java_vuln_research.evaluation.coverage import iter_sarif_native_paths
from java_vuln_research.native_pool import NativePoolError, adapt_native_path, run_p0_a1_native_pool


def _sarif(path: Path, *, locations: list[tuple[str, int]] | None = None) -> None:
    locations = locations or [("src/Main.java", 10), ("src/Main.java", 20)]
    path.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "ruleId": "java/test-rule",
                                "codeFlows": [
                                    {
                                        "threadFlows": [
                                            {
                                                "locations": [
                                                    {
                                                        "location": {
                                                            "physicalLocation": {
                                                                "artifactLocation": {"uri": file},
                                                                "region": {"startLine": line},
                                                            }
                                                        }
                                                    }
                                                    for file, line in locations
                                                ]
                                            }
                                        ]
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )


def test_sarif_native_path_is_path_preserving(tmp_path: Path) -> None:
    sarif = tmp_path / "P001.sarif"
    _sarif(sarif)
    rows = iter_sarif_native_paths(sarif, project_id="P001")
    assert len(rows) == 1
    assert rows[0]["native_path_id"].startswith("P001:r0:result0:flow0:thread0")
    adapted = adapt_native_path(rows[0], revision="abc", codeql_version="2.26.3", detector_commit="commit")
    assert adapted["path_origin"] == "CODEQL_NATIVE"
    assert adapted["native_path_id"] == rows[0]["native_path_id"]
    assert adapted["confidence_tier"] == "NATIVE_HIGH"
    assert adapted["unresolved_semantics"] == []


def test_native_candidate_id_and_provenance_are_stable(tmp_path: Path) -> None:
    sarif = tmp_path / "P001.sarif"
    _sarif(sarif)
    row = iter_sarif_native_paths(sarif, project_id="P001")[0]
    first = adapt_native_path(row, revision="abc", codeql_version="2.26.3", detector_commit="commit")
    second = adapt_native_path(row, revision="abc", codeql_version="2.26.3", detector_commit="commit")
    assert first == second
    assert first["provenance"]["sarif_file"] == str(sarif)
    assert first["provenance"]["query_or_rule"] == "java/test-rule"
    assert first["candidate_type_hypothesis"] == "CODEQL_RULE:java/test-rule"


def test_duplicate_native_path_adaptation_is_not_accidental_duplicate(tmp_path: Path) -> None:
    sarif = tmp_path / "P001.sarif"
    _sarif(sarif)
    row = iter_sarif_native_paths(sarif, project_id="P001")[0]
    first = adapt_native_path(row, revision="abc", codeql_version="unknown", detector_commit="commit")
    second = adapt_native_path(row, revision="abc", codeql_version="unknown", detector_commit="commit")
    assert first["candidate_path_id"] == second["candidate_path_id"]
    assert first["native_path_id"] == second["native_path_id"]


def test_malformed_native_path_fails_explicitly() -> None:
    with pytest.raises(NativePoolError):
        adapt_native_path({"project_id": "P001", "native_path_id": "P001:x", "locations": []}, revision="abc", codeql_version="unknown", detector_commit="commit")


def test_empty_sarif_has_no_native_paths(tmp_path: Path) -> None:
    sarif = tmp_path / "empty.sarif"
    sarif.write_text(json.dumps({"runs": []}), encoding="utf-8")
    assert iter_sarif_native_paths(sarif, project_id="P001") == []


def test_baseline_preservation_invariant(tmp_path: Path) -> None:
    baseline = tmp_path / "e0" / "baseline"
    baseline.mkdir(parents=True)
    _sarif(baseline / "P001.sarif")
    manifest = tmp_path / "manifest.yaml"
    manifest.write_text(
        "schema_version: 1\nprojects:\n  - project: P001\n    revision: abc\n    source_path: /src/P001\n    codeql_db_path: /db/P001\n",
        encoding="utf-8",
    )
    output = tmp_path / "run"
    summary = run_p0_a1_native_pool(
        detector_manifest=manifest,
        baseline_raw_dir=tmp_path / "e0",
        output_root=output,
        project_root=tmp_path,
        codeql="missing-codeql",
        run_id="P0-A1-TEST",
    )
    assert summary["status"] == "SUCCESS"
    assert summary["native_paths_parsed"] == summary["native_paths_adapted"] == 1
    assert summary["baseline_preservation_loss_count"] == 0
    assert json.loads((output / "baseline_preservation.json").read_text())["status"] == "PASS"


def test_detector_evaluator_import_boundary_remains_explicit() -> None:
    import java_vuln_research.native_pool as native_pool

    assert "ground_truth" not in native_pool.run_p0_a1_native_pool.__code__.co_names
    assert native_pool.evaluate_native_pool.__name__ == "evaluate_native_pool"
