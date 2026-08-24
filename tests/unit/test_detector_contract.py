from __future__ import annotations

import pytest

from java_vuln_research.common.contracts import (
    DetectorManifestError,
    validate_detector_manifest,
)


def test_detector_manifest_accepts_only_runtime_location_fields() -> None:
    value = {
        "schema_version": 1,
        "projects": [
            {
                "project": "demo",
                "revision": "abc123",
                "source_path": "/workspace/demo",
                "codeql_db_path": "/workspace/db/demo",
            }
        ],
    }

    projects = validate_detector_manifest(value)

    assert projects[0]["project"] == "demo"


@pytest.mark.parametrize(
    "forbidden_field",
    ["cve", "cwe", "fix_patch", "ground_truth", "vulnerable_line", "sink_annotation"],
)
def test_detector_manifest_rejects_ground_truth_fields(forbidden_field: str) -> None:
    project = {
        "project": "demo",
        "revision": "abc123",
        "source_path": "/workspace/demo",
        "codeql_db_path": "/workspace/db/demo",
        forbidden_field: "leak",
    }

    with pytest.raises(DetectorManifestError, match="ground-truth fields"):
        validate_detector_manifest({"schema_version": 1, "projects": [project]})


def test_detector_manifest_rejects_unknown_non_ground_truth_fields() -> None:
    project = {
        "project": "demo",
        "revision": "abc123",
        "source_path": "/workspace/demo",
        "codeql_db_path": "/workspace/db/demo",
        "notes": "not permitted",
    }

    with pytest.raises(DetectorManifestError, match="extra=notes"):
        validate_detector_manifest({"schema_version": 1, "projects": [project]})

