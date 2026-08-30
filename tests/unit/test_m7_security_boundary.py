from __future__ import annotations

import json
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.agent import (
    BoundaryViolationCode,
    RuntimeInputKind,
    RuntimeSecurityBoundary,
    SecurityBoundaryViolation,
    runtime_roots,
)


ROOT = Path(__file__).parents[2]


def _boundary(tmp_path: Path) -> RuntimeSecurityBoundary:
    source = tmp_path / "source"
    artifacts = tmp_path / "artifacts"
    schemas = tmp_path / "schemas"
    source.mkdir(exist_ok=True)
    artifacts.mkdir(exist_ok=True)
    schemas.mkdir(exist_ok=True)
    return RuntimeSecurityBoundary(
        project_id="P1",
        repository_identity="repo@abc",
        allowed_roots=runtime_roots(source_roots=[source], artifact_roots=[artifacts], schema_roots=[schemas]),
    )


def test_boundary_allows_source_and_safe_structured_input_and_hashes_every_read(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path)
    java = tmp_path / "source" / "Example.java"
    java.write_text("// CVE/CWE words in repository source are not benchmark metadata\nclass Example {}\n", encoding="utf-8")
    config = tmp_path / "artifacts" / "runtime.json"
    config.write_text(
        json.dumps({"benchmark_informed": False, "allowed_for_agent_runtime": True, "benchmark_cwe": None}),
        encoding="utf-8",
    )

    assert "class Example" in boundary.read_text(java, kind=RuntimeInputKind.JAVA_SOURCE, logical_name="source:Example.java")
    boundary.read_text(config, kind=RuntimeInputKind.RUNTIME_CONFIG, logical_name="runtime-config")
    manifest = boundary.seal()

    assert manifest["no_leakage_pass"] is True
    assert manifest["all_inputs_hashed"] is True
    assert [item["logical_name"] for item in manifest["entries"]] == ["runtime-config", "source:Example.java"]
    assert all(len(item["sha256"]) == 64 for item in manifest["entries"])
    assert boundary.audit()["status"] == "PASS"


@pytest.mark.parametrize(
    "relative",
    [
        "m6_killtest/diagnostic_proposals/P1/proposals.jsonl",
        "renamed/diagnostic_analysis.json",
        "benchmark_answers/innocent.json",
        "evaluator/patches/fix.patch",
        "project_info.csv",
    ],
)
def test_explicit_runtime_path_denylist_is_fail_closed(tmp_path: Path, relative: str) -> None:
    boundary = _boundary(tmp_path)
    path = tmp_path / "artifacts" / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}", encoding="utf-8")

    with pytest.raises(SecurityBoundaryViolation, match="SECURITY_BOUNDARY_VIOLATION") as caught:
        boundary.read_text(path, kind=RuntimeInputKind.RUNTIME_CONFIG, logical_name="attempt")

    payload = caught.value.decision.to_trace_payload()
    assert payload["failure_class"] == "SECURITY_BOUNDARY_VIOLATION"
    assert payload["code"] == BoundaryViolationCode.PATH_DENIED.value
    assert boundary.seal()["no_leakage_pass"] is False


@pytest.mark.parametrize(
    "payload",
    [
        {"benchmark_informed": True, "allowed_for_agent_runtime": False},
        {"opaque": {"root_cause": "callback relation missing"}},
        {"renamed": {"proposal_origin": "BENCHMARK_INFORMED_DIAGNOSTIC"}},
        {"input": "/safe-looking/m6_killtest/diagnostic_proposals/P1/proposals.jsonl"},
        {"benchmark_annotation": {"method": "knownVulnerable", "line": 42}},
        {"cwe_id": "CWE-79"},
    ],
)
def test_content_scan_rejects_renamed_or_embedded_answer_artifacts(tmp_path: Path, payload: object) -> None:
    boundary = _boundary(tmp_path)
    path = tmp_path / "artifacts" / "ordinary-name.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SecurityBoundaryViolation) as caught:
        boundary.read_bytes(path, kind=RuntimeInputKind.RUNTIME_CONFIG, logical_name="renamed-answer")

    assert caught.value.decision.code is BoundaryViolationCode.CONTENT_DENIED
    assert caught.value.decision.rule_id.startswith("DENY_")


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("renamed.yaml", "opaque:\n  benchmark_informed: true\n"),
        ("renamed.csv", "project,value,cve_id\nP1,x,CVE-2024-0001\n"),
    ],
)
def test_non_json_structured_answer_metadata_cannot_bypass_scan(tmp_path: Path, name: str, text: str) -> None:
    boundary = _boundary(tmp_path)
    path = tmp_path / "artifacts" / name
    path.write_text(text, encoding="utf-8")
    with pytest.raises(SecurityBoundaryViolation) as caught:
        boundary.read_text(path, kind=RuntimeInputKind.RUNTIME_CONFIG, logical_name="renamed-structured")
    assert caught.value.decision.code is BoundaryViolationCode.CONTENT_DENIED


def test_boundary_rejects_root_escape_and_access_after_freeze(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path)
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    with pytest.raises(SecurityBoundaryViolation) as caught:
        boundary.read_text(outside, kind=RuntimeInputKind.RUNTIME_CONFIG, logical_name="outside")
    assert caught.value.decision.code is BoundaryViolationCode.ROOT_ESCAPE

    allowed = tmp_path / "artifacts" / "allowed.json"
    allowed.write_text("{}", encoding="utf-8")
    other = _boundary(tmp_path)
    other.read_text(allowed, kind=RuntimeInputKind.RUNTIME_CONFIG, logical_name="allowed")
    first = other.seal()
    assert other.seal() == first
    with pytest.raises(SecurityBoundaryViolation) as sealed:
        other.read_text(allowed, kind=RuntimeInputKind.RUNTIME_CONFIG, logical_name="after-seal")
    assert sealed.value.decision.code is BoundaryViolationCode.BOUNDARY_SEALED


def test_manifest_schema_and_hash_audit_detect_post_read_mutation(tmp_path: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    boundary = _boundary(tmp_path)
    path = tmp_path / "artifacts" / "baseline.json"
    path.write_text(json.dumps({"paths": []}), encoding="utf-8")
    boundary.read_text(path, kind=RuntimeInputKind.CODEQL_NATIVE_BASELINE, logical_name="native-baseline")
    manifest = boundary.seal()

    schema = json.loads((ROOT / "schemas" / "work1_agent_runtime_input_manifest.schema.json").read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(manifest)
    path.write_text(json.dumps({"paths": ["changed"]}), encoding="utf-8")
    audit = boundary.audit()
    assert audit["status"] == "FAIL"
    assert audit["hash_mismatches"][0]["logical_name"] == "native-baseline"


def test_invalid_json_is_not_allowed_to_bypass_content_audit(tmp_path: Path) -> None:
    boundary = _boundary(tmp_path)
    path = tmp_path / "artifacts" / "broken.json"
    path.write_text('{"benchmark_informed": true', encoding="utf-8")
    with pytest.raises(SecurityBoundaryViolation) as caught:
        boundary.read_text(path, kind=RuntimeInputKind.RUNTIME_CONFIG, logical_name="broken")
    assert caught.value.decision.rule_id == "DENY_INVALID_STRUCTURED_INPUT"
