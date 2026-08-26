from __future__ import annotations

import json

from java_vuln_research.frontier.runner import (
    connected_paths_from_sarif,
    frontier_paths_from_rows,
)


def _endpoint(candidate_id: str, kind: str, file_name: str, line: int) -> dict:
    return {
        "candidate_id": candidate_id,
        "kind": kind,
        "entity": f"demo.{candidate_id}",
        "source": "STATIC",
        "evidence": [
            {
                "project": "P001",
                "revision": "abc123",
                "file": file_name,
                "line": line,
            }
        ],
    }


def test_connected_sarif_paths_keep_existing_endpoint_ids(tmp_path) -> None:
    sarif = tmp_path / "connected.sarif"
    sarif.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "results": [
                            {
                                "codeFlows": [
                                    {
                                        "threadFlows": [
                                            {
                                                "locations": [
                                                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/A.java"}, "region": {"startLine": 10}}}},
                                                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/A.java"}, "region": {"startLine": 20}}}},
                                                    {"location": {"physicalLocation": {"artifactLocation": {"uri": "src/B.java"}, "region": {"startLine": 30}}}},
                                                ]
                                            }
                                        ]
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    paths, unmapped = connected_paths_from_sarif(
        project_id="P001",
        sarif_file=sarif,
        inputs=[_endpoint("ext-1", "EXTERNAL_INPUT", "src/A.java", 10)],
        effects=[_endpoint("eff-1", "SECURITY_EFFECT", "src/B.java", 30)],
        detector_commit="commit-1",
    )

    assert unmapped == 0
    assert len(paths) == 1
    assert paths[0]["input_candidate_id"] == "ext-1"
    assert paths[0]["effect_candidate_id"] == "eff-1"
    assert paths[0]["path_status"] == "COMPLETE_STATIC"
    assert paths[0]["semantic_mechanisms"] == ["DATA"]


def test_frontier_rows_are_not_claimed_as_static_dataflow() -> None:
    paths, unmapped = frontier_paths_from_rows(
        project_id="P001",
        rows=[
            {
                "source_file": "src/A.java",
                "source_line": "10",
                "effect_file": "src/B.java",
                "effect_line": "30",
                "call_file": "src/A.java",
                "call_line": "20",
                "frontier_reason": "OTHER",
            }
        ],
        inputs=[_endpoint("ext-1", "EXTERNAL_INPUT", "src/A.java", 10)],
        effects=[_endpoint("eff-1", "SECURITY_EFFECT", "src/B.java", 30)],
        detector_commit="commit-1",
    )

    assert unmapped == 0
    assert len(paths) == 1
    assert paths[0]["path_status"] == "FRONTIER_GAP"
    assert paths[0]["frontier_reason"] == "OTHER"
    assert paths[0]["semantic_mechanisms"] == ["CALL"]
