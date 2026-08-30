from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.m6_killtest import detector as detector_module
from java_vuln_research.work1_agent.m6_killtest.contracts import DiagnosticCause, FailureReason, M6_PROPOSAL_BUDGET
from java_vuln_research.work1_agent.m6_killtest.detector import run_detector
from java_vuln_research.work1_agent.m6_killtest.diagnostic import analyse_case
from java_vuln_research.work1_agent.m6_killtest.evaluator import evaluate_frozen_run
from java_vuln_research.work1_agent.m6_killtest.inventory import build_case_inventory, select_cases
from java_vuln_research.work1_agent.m6_killtest.io import read_json, read_jsonl, sha256_file, write_jsonl
from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind


@pytest.fixture
def m6_case(tmp_path: Path):
    source = tmp_path / "source"
    java = source / "src" / "Foo.java"
    java.parent.mkdir(parents=True)
    java.write_text(
        "package example;\nclass Foo {\n  void handle(String value) {\n    danger(value);\n  }\n  void danger(String value) {}\n}\n",
        encoding="utf-8",
    )
    method = ProgramEntity.create(
        kind=ProgramEntityKind.METHOD,
        repository_relative_path="src/Foo.java",
        start_line=3,
        end_line=5,
        simple_name="handle",
        qualified_name="example.Foo.handle",
        enclosing_type="example.Foo",
        signature="handle(String)",
        type_text="void",
        provenance={"extractor": "test"},
    )
    call = ProgramEntity.create(
        kind=ProgramEntityKind.CALL,
        repository_relative_path="src/Foo.java",
        start_line=4,
        end_line=4,
        simple_name="danger",
        qualified_name="example.Foo.handle(String)::danger",
        enclosing_type="example.Foo",
        enclosing_callable="example.Foo.handle(String)",
        signature="danger/1",
        provenance={"extractor": "test", "argument_count": 1},
    )
    entity_index = tmp_path / "entities.jsonl"
    write_jsonl(entity_index, [method, call])
    case_root = tmp_path / "case"
    hint = {"project_id": "T001", "case_id": "T001:case", "file_path": "src/Foo.java", "method_name": "handle", "start_line": 3, "end_line": 5}
    analysis = analyse_case(
        project_id="T001",
        case_id="T001:case",
        source_root=source,
        entity_index=entity_index,
        hint=hint,
        output_root=case_root,
    )
    baseline = {"baseline_detected": False}
    return case_root, hint, baseline, analysis


def _run(m6_case, tmp_path: Path, ids=None, name="run"):
    case_root, _, _, _ = m6_case
    output = tmp_path / name
    run_detector(
        detector_input_json=case_root / "detector_input.json",
        proposals_jsonl=case_root / "proposals.jsonl",
        output_root=output,
        proposal_ids=ids,
        git_sha="TEST-SHA",
    )
    return output


def test_baseline_miss_eligibility_and_deterministic_selection(tmp_path: Path):
    inventory = tmp_path / "projects.csv"
    inventory.write_text(
        "project_id,project_name,source_root,source_exists,codeql_db_path,codeql_db_ready\n"
        "B,Beta,/b,true,/db/b,true\nA,Alpha,/a,true,/db/a,true\nC,Gamma,/c,true,/db/c,false\n",
        encoding="utf-8",
    )
    coverage = tmp_path / "coverage.jsonl"
    write_jsonl(coverage, [
        {"project_id": "B", "case_id": "z", "baseline_detected": False, "comparison_level": "METHOD"},
        {"project_id": "A", "case_id": "a", "baseline_detected": False, "comparison_level": "METHOD"},
        {"project_id": "C", "case_id": "x", "baseline_detected": False, "comparison_level": "METHOD"},
        {"project_id": "A", "case_id": "covered", "baseline_detected": True, "comparison_level": "METHOD"},
    ])
    hints = tmp_path / "hints.jsonl"
    write_jsonl(hints, [{"project_id": pid, "case_id": cid} for pid, cid in (("A", "a"), ("B", "z"), ("C", "x"))])
    rows = build_case_inventory(project_inventory_csv=inventory, coverage_cases_jsonl=coverage, diagnostic_hints_jsonl=hints, output_csv=tmp_path / "inventory.csv")
    selected = select_cases(rows, tmp_path / "selected.csv")
    assert [(row["project_id"], row["case_id"]) for row in selected] == [("A", "a"), ("B", "z")]


def test_detector_does_not_import_diagnostic_or_evaluator():
    source = inspect.getsource(detector_module)
    assert "m6_killtest.diagnostic" not in source
    assert "m6_killtest.evaluator" not in source
    assert "fix_info" not in source.lower()
    assert "ground_truth" not in source.lower()


def test_diagnostic_proposals_are_flagged_and_runtime_disabled(m6_case):
    case_root, _, _, analysis = m6_case
    proposals = read_jsonl(case_root / "proposals.jsonl")
    assert analysis["benchmark_informed"] is True
    assert analysis["allowed_for_agent_runtime"] is False
    assert all(row["provenance"]["proposal_origin"] == "BENCHMARK_INFORMED_DIAGNOSTIC" for row in proposals)
    assert all(row["provenance"]["benchmark_informed"] is True for row in proposals)
    assert all(row["provenance"]["allowed_for_agent_runtime"] is False for row in proposals)
    assert all(row["provenance"]["eligible_for_detection_metric"] is False for row in proposals)


def test_proposal_budget_is_enforced(m6_case, tmp_path: Path):
    case_root, _, _, _ = m6_case
    proposals = read_jsonl(case_root / "proposals.jsonl")
    write_jsonl(tmp_path / "too-many.jsonl", [proposals[0]] * (M6_PROPOSAL_BUDGET + 1))
    with pytest.raises(ValueError, match="proposal budget exceeded"):
        run_detector(detector_input_json=case_root / "detector_input.json", proposals_jsonl=tmp_path / "too-many.jsonl", output_root=tmp_path / "bad")


def test_recovery_evaluation_occurs_after_freeze(m6_case, tmp_path: Path):
    case_root, hint, baseline, _ = m6_case
    run = _run(m6_case, tmp_path)
    result = evaluate_frozen_run(run_root=run, baseline=baseline, annotation=hint)
    assert result["evaluation_started_after_detector_freeze"] is True
    assert result["mechanism_recovered"] is True
    manifest = read_json(run / "detector_manifest.json")
    assert manifest["detector_frozen"] is True


def test_counterfactual_removes_recovery(m6_case, tmp_path: Path):
    _, hint, baseline, _ = m6_case
    full = _run(m6_case, tmp_path, name="full")
    zero = _run(m6_case, tmp_path, ids=[], name="zero")
    assert evaluate_frozen_run(run_root=full, baseline=baseline, annotation=hint)["mechanism_recovered"]
    assert not evaluate_frozen_run(run_root=zero, baseline=baseline, annotation=hint)["mechanism_recovered"]


def test_leave_one_out_minimality(m6_case, tmp_path: Path):
    case_root, hint, baseline, _ = m6_case
    ids = [row["proposal_id"] for row in read_jsonl(case_root / "proposals.jsonl")]
    assert len(ids) == 3
    for position, omitted in enumerate(ids):
        run = _run(m6_case, tmp_path, ids=[item for item in ids if item != omitted], name=f"loo-{position}")
        assert not evaluate_frozen_run(run_root=run, baseline=baseline, annotation=hint)["mechanism_recovered"]


def test_failure_taxonomies_are_exact_and_complete():
    assert {item.value for item in DiagnosticCause} == {
        "INPUT_SEMANTIC_MISSING", "EFFECT_SEMANTIC_MISSING", "WRAPPER_OR_LIBRARY_FLOW_MISSING",
        "FIELD_OR_STATE_FLOW_MISSING", "FRAMEWORK_OR_CALLBACK_RELATION_MISSING",
        "MULTIPLE_SEMANTIC_RELATIONS_REQUIRED", "NOT_EXPRESSIBLE_BY_V11", "NOT_A_SEMANTIC_GAP", "UNCERTAIN",
    }
    assert {item.value for item in FailureReason} == {
        "NO_RECOVERY_AFTER_VALID_PROPOSALS", "GATE_BLOCKED", "PATH_BUILDER_LIMITATION",
        "ENTITY_MAPPING_LIMITATION", "CODEQL_TOOL_LIMITATION", "INSUFFICIENT_PROGRAM_EVIDENCE",
        "NOT_EXPRESSIBLE_BY_CURRENT_PROPOSAL_TYPES", "NOT_SEMANTIC_GAP", "INFRASTRUCTURE_FAILURE", "UNCERTAIN",
    }


def test_artifact_lineage_hashes_are_bound(m6_case, tmp_path: Path):
    run = _run(m6_case, tmp_path)
    manifest = read_json(run / "detector_manifest.json")
    for name, digest in manifest["artifact_hashes"].items():
        assert sha256_file(run / name) == digest
    (run / "summary.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="artifact changed"):
        evaluate_frozen_run(run_root=run, baseline={"baseline_detected": False}, annotation={"file_name": "Foo.java"})


def test_case_specific_facts_are_not_implementation_conditionals():
    package = Path(__file__).parents[2] / "src" / "java_vuln_research" / "work1_agent" / "m6_killtest"
    source = "\n".join(path.read_text(encoding="utf-8") for path in package.glob("*.py"))
    for forbidden in ("P006", "P007", "P010", "P012", "D003", "V001", "V004", "V005", "V009", "V023", "Retrofit", "Hutool"):
        assert forbidden not in source


def test_diagnostic_module_is_not_imported_by_agent_runtime():
    root = Path(__file__).parents[2] / "src" / "java_vuln_research" / "work1_agent"
    runtime_files = [path for path in root.rglob("*.py") if "m6_killtest" not in path.parts]
    source = "\n".join(path.read_text(encoding="utf-8") for path in runtime_files)
    assert "m6_killtest.diagnostic" not in source
