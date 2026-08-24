from __future__ import annotations

import json

from java_vuln_research.common.run_manifest import RunManifest


def test_run_manifest_persists_required_provenance_and_null_model_fields(tmp_path) -> None:
    config = tmp_path / "p0.yaml"
    config.write_text("experiment: MSA-P0-E0\n", encoding="utf-8")
    prompt_dir = tmp_path / "prompts"
    prompt_dir.mkdir()
    (prompt_dir / "one.md").write_text("local only\n", encoding="utf-8")
    output = tmp_path / "run_manifest.json"
    builder = RunManifest(
        run_id="MSA-P0-E0-test",
        experiment="MSA-P0-E0",
        project_root=tmp_path,
        dataset_name="synthetic-infrastructure-test",
        dataset_revision="test",
        config_paths=[config],
        semantic_rule_paths=[],
        prompt_paths=[prompt_dir],
    )

    value = builder.finish(
        output,
        projects_requested=1,
        projects_runnable=1,
        projects_build_failed="NOT_APPLICABLE",
        status="SUCCESS",
    )

    persisted = json.loads(output.read_text(encoding="utf-8"))
    required = {
        "run_id",
        "experiment",
        "timestamp_start",
        "timestamp_end",
        "git_commit",
        "git_branch",
        "codeql_version",
        "java_version",
        "maven_version",
        "gradle_version",
        "python_version",
        "dataset_name",
        "dataset_revision",
        "config_hash",
        "semantic_rule_hash",
        "prompt_hash",
        "model_id",
        "temperature",
        "top_p",
        "random_seed",
        "projects_requested",
        "projects_runnable",
        "projects_build_failed",
        "wall_clock_seconds",
        "status",
    }
    assert required <= set(persisted)
    assert value["model_id"] is None
    assert value["temperature"] is None
    assert value["projects_build_failed"] == "NOT_APPLICABLE"

