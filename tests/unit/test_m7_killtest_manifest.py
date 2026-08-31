from __future__ import annotations

import csv
import json
from pathlib import Path

import jsonschema

from java_vuln_research.work1_agent.agent import LLMClientConfig
from java_vuln_research.work1_agent.agent.killtest_manifest import freeze_killtest_manifest


def _write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def test_freeze_separates_benchmark_selection_from_detector_input(tmp_path: Path) -> None:
    selected_rows: list[dict[str, object]] = []
    inventory_rows: list[dict[str, object]] = []
    for index in range(10):
        project_id = f"P{index:03d}"
        source = tmp_path / "projects" / project_id
        database = tmp_path / "dbs" / project_id
        source.mkdir(parents=True)
        database.mkdir(parents=True)
        (source / "Sample.java").write_text("class Sample {}\n", encoding="utf-8")
        (database / "codeql-database.yml").write_text("name: test\n", encoding="utf-8")
        selected_rows.append(
            {
                "project_id": project_id,
                "case_id": f"secret_CVE-2026-{index:04d}",
                "cwe": "CWE-999",
                "diagnostic_cause": "SECRET_CAUSE",
                "source_revision": f"rev-{index}",
            }
        )
        inventory_rows.append(
            {
                "project_id": project_id,
                "project_name": f"Safe Project {index}",
                "source_root": str(source),
                "source_exists": "true",
                "codeql_db_path": str(database),
                "codeql_db_ready": "true",
            }
        )
    selected_path = tmp_path / "selected.csv"
    inventory_path = tmp_path / "inventory.csv"
    _write_csv(selected_path, selected_rows)
    _write_csv(inventory_path, inventory_rows)
    components: dict[str, Path] = {}
    for name in ("M1", "M2", "M3", "M4", "M5"):
        root = tmp_path / name
        root.mkdir()
        (root / "manifest.json").write_text('{"safe":true}\n', encoding="utf-8")
        components[name] = root
    baseline = tmp_path / "baseline"
    baseline.mkdir()
    (baseline / "run_manifest.json").write_text('{"safe":true}\n', encoding="utf-8")
    output = tmp_path / "freeze"
    schema_root = Path(__file__).resolve().parents[2] / "schemas"
    config = LLMClientConfig(
        "openlux",
        "claude-opus-5",
        "https://api.openlux.ai/v1",
        "do-not-serialize-this-secret",
        endpoint_url="https://api.openlux.ai/v1/chat/completions",
        seed=None,
    )

    summary = freeze_killtest_manifest(
        selected_cases_csv=selected_path,
        project_inventory_csv=inventory_path,
        component_roots=components,
        baseline_root=baseline,
        schema_root=schema_root,
        output_root=output,
        git_sha="abc123",
        model_config=config,
    )

    detector_text = (output / "detector_manifest.json").read_text(encoding="utf-8")
    selection_text = (output / "selection_manifest.json").read_text(encoding="utf-8")
    audit = json.loads((output / "no_leakage_audit.json").read_text(encoding="utf-8"))
    detector = json.loads(detector_text)
    schema = json.loads((schema_root / "work1_agent_killtest_detector_manifest.schema.json").read_text(encoding="utf-8"))
    jsonschema.validate(detector, schema)
    assert summary["selected_project_count"] == 10
    assert summary["killtest_started"] is False
    assert set(summary["artifact_hashes"]) == {"detector_manifest.json", "selection_manifest.json", "no_leakage_audit.json"}
    assert audit["no_leakage_pass"] is True
    assert "CVE-" not in detector_text and "CWE-" not in detector_text
    assert "SECRET_CAUSE" not in detector_text
    assert "do-not-serialize-this-secret" not in detector_text
    assert "secret_CVE-2026-0000" in selection_text
    assert detector["selection_manifest_allowed_for_agent_runtime"] is False
    assert detector["controller"]["max_model_output_retries"] == 2
    assert detector["baseline_lineage"]["codeql_version"] == "UNKNOWN"
    assert all(item["native_baseline"]["preservation_required"] for item in detector["projects"])
