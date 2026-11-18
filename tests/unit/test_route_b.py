from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from java_vuln_research.common.contracts import DetectorManifestError, validate_detector_manifest
from java_vuln_research.common.io import write_jsonl
from java_vuln_research.evaluation.route_b import RouteBEvaluationError, evaluate_p0_b_route_b
from java_vuln_research.route_b_detector import (
    adapt_gated_pairs,
    build_unified_pool,
    route_b_candidate_from_row,
    run_p0_b_route_b,
    static_paths_from_rows,
)


def _input_row() -> dict[str, str]:
    return {
        "structural_reason": "ANNOTATED_BOUNDARY",
        "entity": "demo.Controller.handle/1 parameter request",
        "method_identity": "demo.Controller.handle/1",
        "call_identity": "",
        "value_role": "PARAMETER",
        "argument_index": "0",
        "file": "src/Controller.java",
        "line": "10",
        "evidence_kind": "FRAMEWORK_HANDLER_ANNOTATION",
        "confidence_tier": "STRUCTURE_HIGH",
        "unresolved_semantics": "",
    }


def _effect_row() -> dict[str, str]:
    return {
        "structural_reason": "PROCESS_ABSTRACTION",
        "entity": "demo.Controller.handle/1 -> demo.CommandExecutor.execute",
        "method_identity": "demo.Controller.handle/1",
        "call_identity": "demo.CommandExecutor.execute/1@src/Controller.java:20",
        "value_role": "CALL_ARGUMENT",
        "argument_index": "0",
        "file": "src/Controller.java",
        "line": "20",
        "evidence_kind": "PROCESS_RECEIVER_AND_METHOD",
        "confidence_tier": "STRUCTURE_HIGH",
        "effect_category": "PROCESS_EXECUTION",
    }


def _candidates() -> tuple[dict, dict]:
    input_candidate = route_b_candidate_from_row(
        project_id="P1", revision="rev-1", candidate_kind="EXTERNAL_INPUT",
        row=_input_row(), detector_commit="commit-1",
    )
    effect_candidate = route_b_candidate_from_row(
        project_id="P1", revision="rev-1", candidate_kind="SECURITY_EFFECT",
        row=_effect_row(), detector_commit="commit-1",
    )
    return input_candidate, effect_candidate


def _pair_row() -> dict[str, str]:
    return {
        "input_entity": _input_row()["entity"],
        "input_file": "src/Controller.java",
        "input_line": "10",
        "input_reason": "ANNOTATED_BOUNDARY",
        "effect_entity": _effect_row()["entity"],
        "effect_file": "src/Controller.java",
        "effect_line": "20",
        "effect_reason": "PROCESS_ABSTRACTION",
        "gate_reason": "SAME_METHOD",
        "gate_distance": "0",
    }


def _native_path(path_id: str = "native-1", *, input_line: int = 1, effect_line: int = 2) -> dict:
    return {
        "candidate_path_id": path_id,
        "native_path_id": "P1:r0:result0:flow0:thread0",
        "project_id": "P1",
        "path_origin": "CODEQL_NATIVE",
        "input_anchor": {"location": {"file": "src/Controller.java", "line": input_line}},
        "effect_anchor": {"location": {"file": "src/Controller.java", "line": effect_line}},
        "source_locations": [
            {"file": "src/Controller.java", "line": input_line},
            {"file": "src/Controller.java", "line": effect_line},
        ],
    }


def test_route_b_candidate_id_is_deterministic_and_evidence_is_preserved() -> None:
    first = route_b_candidate_from_row(
        project_id="P1", revision="rev-1", candidate_kind="EXTERNAL_INPUT",
        row=_input_row(), detector_commit="commit-1",
    )
    second = route_b_candidate_from_row(
        project_id="P1", revision="rev-1", candidate_kind="EXTERNAL_INPUT",
        row=_input_row(), detector_commit="commit-1",
    )
    assert first["candidate_id"] == second["candidate_id"]
    assert first["discovery_route"] == "ROUTE_B_STATIC"
    assert first["static_evidence"][0]["structural_reason"] == "ANNOTATED_BOUNDARY"
    assert first["provenance"]["seed_independent"] is True


def test_route_b_detector_has_no_seed_or_gt_inputs() -> None:
    parameters = set(inspect.signature(run_p0_b_route_b).parameters)
    assert "endpoint_output_dir" not in parameters
    assert not {"project_info_csv", "fix_info_csv", "cve_id", "ground_truth"} & parameters
    query = Path("codeql/route_b/RouteBConnected.ql").read_text(encoding="utf-8")
    assert "EndpointCandidates" not in query
    assert "RouteBFlow::flow" in query
    assert query.index("routeBPairGate") < query.index("RouteBFlow::flow")


def test_structural_pair_adapter_never_invents_ungated_pairs() -> None:
    input_candidate, effect_candidate = _candidates()
    rows, unmapped = adapt_gated_pairs(
        [_pair_row()], [input_candidate], [effect_candidate],
        connected_pairs={(input_candidate["candidate_id"], effect_candidate["candidate_id"])},
    )
    assert unmapped == 0
    assert len(rows) == 1
    assert rows[0]["connected"] is True
    assert rows[0]["static_evidence"] == [
        {"kind": "STRUCTURAL_GATE", "reason": "SAME_METHOD", "distance": 0}
    ]


def test_structural_pair_adapter_deduplicates_multiple_gate_reasons() -> None:
    input_candidate, effect_candidate = _candidates()
    second_gate = {**_pair_row(), "gate_reason": "SAME_PACKAGE", "gate_distance": "3"}
    rows, unmapped = adapt_gated_pairs(
        [_pair_row(), second_gate], [input_candidate], [effect_candidate]
    )
    assert unmapped == 0
    assert len(rows) == 1
    assert rows[0]["static_evidence"] == [
        {"kind": "STRUCTURAL_GATE", "reason": "SAME_METHOD", "distance": 0},
        {"kind": "STRUCTURAL_GATE", "reason": "SAME_PACKAGE", "distance": 3},
    ]


def test_connected_route_b_path_is_static_augmented() -> None:
    input_candidate, effect_candidate = _candidates()
    paths, connected, unmapped = static_paths_from_rows(
        project_id="P1", rows=[_pair_row()], inputs=[input_candidate],
        effects=[effect_candidate], detector_commit="commit-1", native_paths=[],
    )
    assert unmapped == 0
    assert connected == {(input_candidate["candidate_id"], effect_candidate["candidate_id"])}
    assert len(paths) == 1
    assert paths[0]["path_origin"] == "STATIC_AUGMENTED"
    assert paths[0]["path_status"] == "COMPLETE_STATIC"
    assert paths[0]["discovery_route"] == "ROUTE_B_STATIC"
    assert paths[0]["augmentation_reason"] == "NEW_BOTH_ENDPOINTS"


def test_native_static_dedup_and_native_preservation() -> None:
    native = _native_path(input_line=10, effect_line=20)
    input_candidate, effect_candidate = _candidates()
    static, _, _ = static_paths_from_rows(
        project_id="P1", rows=[_pair_row()], inputs=[input_candidate],
        effects=[effect_candidate], detector_commit="commit-1", native_paths=[native],
    )
    assert static[0]["augmentation_reason"] == "NATIVE_DUPLICATE"
    unified, duplicates, preservation = build_unified_pool([native], static)
    assert unified == [native]
    assert len(duplicates) == 1
    assert preservation["native_pool_subset_unified_pool"] is True
    assert preservation["baseline_preservation_loss"] == 0
    assert preservation["native_objects_unchanged"] is True


def test_gt_fields_are_rejected_before_detector_execution() -> None:
    manifest = {
        "schema_version": 1,
        "projects": [{
            "project": "P1", "revision": "rev-1", "source_path": "/src/P1",
            "codeql_db_path": "/db/P1", "cve_id": "CVE-TEST",
        }],
    }
    with pytest.raises(DetectorManifestError, match="ground-truth fields"):
        validate_detector_manifest(manifest)


def test_post_hoc_evaluator_reports_static_gain_and_recovery(tmp_path: Path) -> None:
    native = _native_path()
    static = {
        "candidate_path_id": "static-1",
        "project_id": "P1",
        "path_origin": "STATIC_AUGMENTED",
        "augmentation_reason": "NEW_BOTH_ENDPOINTS",
        "source_locations": [{"file": "src/Vuln.java", "line": 15}],
        "static_evidence": [{"kind": "CODEQL_BASE_GRAPH_FLOW"}],
        "provenance": {
            "route_b_input": {"candidate_id": "in-1", "structural_reason": "ANNOTATED_BOUNDARY"},
            "route_b_effect": {"candidate_id": "eff-1", "structural_reason": "PROCESS_ABSTRACTION"},
        },
    }
    native_file = tmp_path / "native.jsonl"
    unified_file = tmp_path / "unified.jsonl"
    write_jsonl(native_file, [native])
    write_jsonl(unified_file, [native, static])
    (tmp_path / "run_manifest.json").write_text(
        json.dumps({"detector_frozen": True, "detector_ground_truth_access": False}),
        encoding="utf-8",
    )
    detector_manifest = tmp_path / "manifest.yaml"
    detector_manifest.write_text(
        "schema_version: 1\nprojects:\n  - project: P1\n    revision: rev-1\n"
        "    source_path: /src/P1\n    codeql_db_path: /db/P1\n",
        encoding="utf-8",
    )
    project_info = tmp_path / "project_info.csv"
    project_info.write_text(
        "project_slug,cve_id,buggy_commit_id,cwe_id\ndemo,CVE-1,rev-1,CWE-78\n",
        encoding="utf-8",
    )
    fix_info = tmp_path / "fix_info.csv"
    fix_info.write_text(
        "project_slug,cve_id,file,method_start,method_end\n"
        "demo,CVE-1,src/Vuln.java,10,20\n",
        encoding="utf-8",
    )
    result = evaluate_p0_b_route_b(
        native_pool_path=native_file,
        unified_pool_path=unified_file,
        detector_manifest=detector_manifest,
        project_info_csv=project_info,
        fix_info_csv=fix_info,
        output_root=tmp_path,
    )
    assert result["native_ground_truth_candidate_coverage"] == 0
    assert result["native_plus_route_b_ground_truth_candidate_coverage"] == 1
    assert result["static_aug_gain"] == 1
    assert result["baseline_miss_recovery_count"] == 1
    recovery = json.loads((tmp_path / "baseline_miss_recovery.jsonl").read_text(encoding="utf-8"))
    assert recovery["candidate_path_id"] == "static-1"
    assert recovery["route_b_input_source"]["structural_reason"] == "ANNOTATED_BOUNDARY"


def test_post_hoc_evaluator_rejects_unfrozen_detector_artifacts(tmp_path: Path) -> None:
    native_file = tmp_path / "native.jsonl"
    unified_file = tmp_path / "unified.jsonl"
    write_jsonl(native_file, [_native_path()])
    write_jsonl(unified_file, [_native_path()])
    (tmp_path / "run_manifest.json").write_text(
        json.dumps({"detector_frozen": False, "detector_ground_truth_access": False}),
        encoding="utf-8",
    )
    with pytest.raises(RouteBEvaluationError, match="not marked frozen"):
        evaluate_p0_b_route_b(
            native_pool_path=native_file,
            unified_pool_path=unified_file,
            detector_manifest=tmp_path / "unused.yaml",
            project_info_csv=tmp_path / "unused-project.csv",
            fix_info_csv=tmp_path / "unused-fix.csv",
            output_root=tmp_path,
        )


def test_detector_module_does_not_import_evaluator() -> None:
    source = Path("src/java_vuln_research/route_b_detector.py").read_text(encoding="utf-8")
    assert ".evaluation" not in source
    assert "project_info_csv" not in source
    assert "fix_info_csv" not in source
