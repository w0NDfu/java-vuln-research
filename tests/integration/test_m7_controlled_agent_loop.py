from __future__ import annotations

import json
from pathlib import Path

from java_vuln_research.work1_agent.agent.controlled_smoke import run_controlled_smoke


def test_controlled_agent_loop_writes_audited_path_artifacts(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    summary = run_controlled_smoke(
        repository_root=root / "tests" / "fixtures" / "work1_agent_m4",
        schema_root=root / "schemas",
        artifact_root=tmp_path / "m7_agent",
        git_sha="TEST-SHA",
    )
    project = tmp_path / "m7_agent" / "CONTROLLED"
    audit = json.loads((project / "artifact_audit.json").read_text(encoding="utf-8"))

    assert summary["stop_reason"] == "PATH_FORMED"
    assert summary["artifact_audit_pass"] is True
    assert summary["no_leakage_pass"] is True
    assert audit["required_files_present"] is True
    assert (project / "evidence_refs.jsonl").stat().st_size > 0
    assert (project / "candidate_paths.jsonl").stat().st_size > 0
