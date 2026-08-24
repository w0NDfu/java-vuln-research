from __future__ import annotations

from java_vuln_research.common.io import load_yaml


def test_yaml_subset_loads_nested_detector_manifest(tmp_path) -> None:
    path = tmp_path / "detector.yaml"
    path.write_text(
        """schema_version: 1
projects:
  - project: demo
    revision: abc123
    source_path: /workspace/demo
    codeql_db_path: /workspace/db/demo
flags:
  enabled: true
  model: null
  kinds:
    - DATA_CALL
    - LIBRARY
""",
        encoding="utf-8",
    )

    value = load_yaml(path)

    assert value["projects"][0]["revision"] == "abc123"
    assert value["flags"]["enabled"] is True
    assert value["flags"]["model"] is None
    assert value["flags"]["kinds"] == ["DATA_CALL", "LIBRARY"]

