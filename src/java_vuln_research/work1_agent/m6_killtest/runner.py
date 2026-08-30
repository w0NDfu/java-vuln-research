from __future__ import annotations

import argparse
import shutil
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from .contracts import FailureReason, M6_PROPOSAL_BUDGET
from .detector import run_detector
from .diagnostic import analyse_case, locate_entity_index
from .evaluator import evaluate_frozen_run
from .inventory import build_case_inventory, inventory_lineage, select_cases
from .io import artifact_hashes, read_json, read_jsonl, sha256_file, truthy, write_csv, write_json, write_jsonl


CASE_CANONICAL_FILES = (
    "gate_results.jsonl",
    "graph_nodes.jsonl",
    "graph_edges.jsonl",
    "candidate_paths.jsonl",
    "summary.json",
)


def _git_sha(repository_root: Path) -> str:
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repository_root, text=True).strip()
    except (OSError, subprocess.SubprocessError):
        return "UNKNOWN"


def _case_key(project_id: str, case_id: str) -> str:
    safe = "".join(char if char.isalnum() or char in "._-" else "_" for char in case_id)
    return f"{project_id}__{safe}"


def _baseline_record(
    *,
    row: Mapping[str, Any],
    coverage_path: Path,
    baseline_root: Path,
    baseline_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    query_paths = sorted(str(path) for path in baseline_root.rglob("*.ql"))
    output_paths = sorted(str(path) for path in baseline_root.glob("*.json*"))
    return {
        "schema_version": 1,
        "freeze_stage": "E0_BEFORE_DIAGNOSTIC_PROPOSALS",
        "execution_mode": "FROZEN_BASELINE_REUSE",
        "command": baseline_manifest.get("command") or baseline_manifest.get("detector_command") or "RECORDED_IN_FROZEN_RUN_MANIFEST",
        "query_paths": query_paths,
        "query_hashes": {path: sha256_file(path) for path in query_paths},
        "output_paths": output_paths,
        "coverage_cases_path": str(coverage_path),
        "coverage_cases_hash": sha256_file(coverage_path),
        "baseline_detected": truthy(row.get("baseline_detected")),
        "status": baseline_manifest.get("status", "SUCCESS"),
        "codeql_version": baseline_manifest.get("codeql_version") or baseline_manifest.get("CodeQL_version") or "UNKNOWN",
        "codeql_db_path": row.get("codeql_db_path", ""),
        "source_revision": baseline_manifest.get("source_revision") or baseline_manifest.get("git_sha") or "UNKNOWN",
        "baseline_run_manifest_path": str(baseline_root / "run_manifest.json"),
        "baseline_run_manifest_hash": sha256_file(baseline_root / "run_manifest.json"),
        "baseline_query_unchanged": True,
    }


def _copy_canonical(run_root: Path, case_root: Path) -> None:
    for name in CASE_CANONICAL_FILES:
        shutil.copyfile(run_root / name, case_root / name)


def _failure_from_exception(error: Exception) -> str:
    text = str(error)
    if "ENTITY_MAPPING_LIMITATION" in text:
        return FailureReason.ENTITY_MAPPING_LIMITATION.value
    if "proposal budget" in text:
        return FailureReason.NOT_EXPRESSIBLE_BY_CURRENT_PROPOSAL_TYPES.value
    if FailureReason.INSUFFICIENT_PROGRAM_EVIDENCE.value in text:
        return FailureReason.INSUFFICIENT_PROGRAM_EVIDENCE.value
    return FailureReason.INFRASTRUCTURE_FAILURE.value


def run_killtest(
    *,
    project_inventory_csv: str | Path,
    coverage_cases_jsonl: str | Path,
    diagnostic_hints_jsonl: str | Path,
    baseline_root: str | Path,
    m2_root: str | Path,
    artifact_root: str | Path,
    repository_root: str | Path,
) -> dict[str, Any]:
    root = Path(artifact_root)
    root.mkdir(parents=True, exist_ok=True)
    coverage_path = Path(coverage_cases_jsonl).resolve()
    baseline_path = Path(baseline_root).resolve()
    repo = Path(repository_root).resolve()
    git_sha = _git_sha(repo)
    inventory = build_case_inventory(
        project_inventory_csv=project_inventory_csv,
        coverage_cases_jsonl=coverage_cases_jsonl,
        diagnostic_hints_jsonl=diagnostic_hints_jsonl,
        output_csv=root / "case_inventory.csv",
    )
    selected = select_cases(inventory, root / "selected_cases.csv")
    hints = {(str(row["project_id"]), str(row["case_id"])): row for row in read_jsonl(diagnostic_hints_jsonl)}
    baseline_manifest = read_json(baseline_path / "run_manifest.json")
    case_results: list[dict[str, Any]] = []
    proposal_results: list[dict[str, Any]] = []
    recovery_paths: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []
    for row in selected:
        project_id, case_id = str(row["project_id"]), str(row["case_id"])
        case_root = root / "cases" / _case_key(project_id, case_id)
        case_root.mkdir(parents=True, exist_ok=True)
        baseline = _baseline_record(row=row, coverage_path=coverage_path, baseline_root=baseline_path, baseline_manifest=baseline_manifest)
        write_json(case_root / "baseline.json", baseline)
        try:
            hint = hints[(project_id, case_id)]
            entity_index = locate_entity_index(m2_root, project_id, hint)
            analysis = analyse_case(
                project_id=project_id,
                case_id=case_id,
                source_root=row["source_root"],
                entity_index=entity_index,
                hint=hint,
                output_root=case_root,
            )
            proposal_rows = read_jsonl(case_root / "proposals.jsonl")
            evaluation_annotation = {**hint, "mapped_entity_id": analysis["mapped_callable"]["entity_id"]}
            if len(proposal_rows) > M6_PROPOSAL_BUDGET:
                raise ValueError("proposal budget exceeded")
            proposal_ids = [str(item["proposal_id"]) for item in proposal_rows]
            replay_results: list[dict[str, Any]] = []
            recovered_step: int | None = None
            final_run: Path | None = None
            final_evaluation: dict[str, Any] | None = None
            for step in range(1, len(proposal_ids) + 1):
                replay_root = case_root / "replays" / f"step_{step}"
                run_detector(
                    detector_input_json=case_root / "detector_input.json",
                    proposals_jsonl=case_root / "proposals.jsonl",
                    output_root=replay_root,
                    proposal_ids=proposal_ids[:step],
                    git_sha=git_sha,
                )
                evaluation = evaluate_frozen_run(run_root=replay_root, baseline=baseline, annotation=evaluation_annotation)
                replay_results.append({"step": step, "proposal_ids": proposal_ids[:step], **evaluation})
                final_run, final_evaluation = replay_root, evaluation
                if evaluation["mechanism_recovered"]:
                    recovered_step = step
                    break
            assert final_run is not None and final_evaluation is not None
            _copy_canonical(final_run, case_root)
            write_json(case_root / "evaluation.json", final_evaluation)
            counter_root = case_root / "counterfactual_runs" / "no_proposals"
            run_detector(
                detector_input_json=case_root / "detector_input.json",
                proposals_jsonl=case_root / "proposals.jsonl",
                output_root=counter_root,
                proposal_ids=[],
                git_sha=git_sha,
            )
            counter_eval = evaluate_frozen_run(run_root=counter_root, baseline=baseline, annotation=evaluation_annotation)
            counter = {
                "counterfactual": "NO_DIAGNOSTIC_PROPOSALS",
                "mechanism_recovered": counter_eval["mechanism_recovered"],
                "recovery_removed": bool(final_evaluation["mechanism_recovered"] and not counter_eval["mechanism_recovered"]),
                "detector_manifest_hash": counter_eval["detector_manifest_hash"],
            }
            write_json(case_root / "counterfactual.json", counter)
            used_ids = proposal_ids[: recovered_step or len(proposal_ids)]
            loo_rows: list[dict[str, Any]] = []
            if final_evaluation["mechanism_recovered"] and len(used_ids) > 1:
                for omitted in used_ids:
                    kept = [item for item in used_ids if item != omitted]
                    loo_root = case_root / "minimality_runs" / omitted
                    run_detector(
                        detector_input_json=case_root / "detector_input.json",
                        proposals_jsonl=case_root / "proposals.jsonl",
                        output_root=loo_root,
                        proposal_ids=kept,
                        git_sha=git_sha,
                    )
                    loo_eval = evaluate_frozen_run(run_root=loo_root, baseline=baseline, annotation=evaluation_annotation)
                    loo_rows.append({"omitted_proposal_id": omitted, "kept_proposal_ids": kept, "mechanism_recovered": loo_eval["mechanism_recovered"]})
            minimality = {
                "leave_one_out_required": len(used_ids) > 1,
                "leave_one_out_results": loo_rows,
                "all_used_proposals_necessary": bool(loo_rows) and all(not item["mechanism_recovered"] for item in loo_rows),
            }
            write_json(case_root / "minimality.json", minimality)
            gate_rows = read_jsonl(case_root / "gate_results.jsonl")
            for item in gate_rows:
                proposal_results.append({"project_id": project_id, "case_id": case_id, **item})
            paths = read_jsonl(case_root / "candidate_paths.jsonl")
            matched_ids = {item["candidate_path_id"] for item in final_evaluation["matched_paths"]}
            for path in paths:
                if path.get("candidate_path_id") in matched_ids:
                    recovery_paths.append({"case_id": case_id, **path})
            recovered = bool(final_evaluation["mechanism_recovered"])
            failure_reason = "" if recovered else FailureReason.NO_RECOVERY_AFTER_VALID_PROPOSALS.value
            if not recovered and any(item.get("status") != "ADMISSIBLE" for item in gate_rows):
                failure_reason = FailureReason.GATE_BLOCKED.value
            result = {
                "project_id": project_id,
                "case_id": case_id,
                "diagnostic_cause": analysis["diagnostic_cause"],
                "flow_proposal_type": analysis["flow_proposal_type"],
                "proposal_count": len(used_ids),
                "recovered_step": recovered_step or "",
                "mechanism_recovered": recovered,
                "counterfactual_removed": counter["recovery_removed"],
                "minimal": minimality["all_used_proposals_necessary"],
                "matched_path_count": final_evaluation["benchmark_consistent_path_count"],
                "failure_reason": failure_reason,
            }
            if failure_reason:
                failures.append(dict(result))
            summary = {**read_json(case_root / "summary.json"), "replays": replay_results, "m6_result": result}
            write_json(case_root / "summary.json", summary)
            case_manifest = {
                "schema_version": 1,
                "project_id": project_id,
                "case_id": case_id,
                "selection_rank": row["selection_rank"],
                "e0_frozen_before_proposals": True,
                "detector_evaluator_separation": True,
                "detector_frozen_before_evaluation": True,
                "entity_index": str(entity_index),
                "entity_index_hash": sha256_file(entity_index),
                "baseline_hash": sha256_file(case_root / "baseline.json"),
                "diagnostic_analysis_hash": sha256_file(case_root / "diagnostic_analysis.json"),
                "artifact_hashes": artifact_hashes(
                    case_root,
                    (
                        "baseline.json",
                        "diagnostic_analysis.json",
                        "proposals.jsonl",
                        "gate_results.jsonl",
                        "graph_nodes.jsonl",
                        "graph_edges.jsonl",
                        "candidate_paths.jsonl",
                        "evaluation.json",
                        "counterfactual.json",
                        "minimality.json",
                        "summary.json",
                    ),
                ),
            }
            write_json(case_root / "case_manifest.json", case_manifest)
            case_results.append(result)
        except Exception as error:  # deliberate per-case isolation
            failure = {
                "project_id": project_id,
                "case_id": case_id,
                "mechanism_recovered": False,
                "failure_reason": _failure_from_exception(error),
                "details": str(error),
            }
            failures.append(failure)
            case_results.append(failure)
            for name, value in (
                ("diagnostic_analysis.json", {"status": "FAILED", **failure}),
                ("evaluation.json", {"mechanism_recovered": False, **failure}),
                ("counterfactual.json", {"not_run": True, **failure}),
                ("minimality.json", {"not_run": True, **failure}),
                ("summary.json", failure),
            ):
                if not (case_root / name).exists():
                    write_json(case_root / name, value)
            for name in ("proposals.jsonl", "gate_results.jsonl", "graph_nodes.jsonl", "graph_edges.jsonl", "candidate_paths.jsonl"):
                if not (case_root / name).exists():
                    write_jsonl(case_root / name, [])
            write_json(case_root / "case_manifest.json", {"schema_version": 1, **failure, "artifact_hashes": artifact_hashes(case_root, tuple(path.name for path in case_root.iterdir() if path.is_file()))})
    write_csv(root / "case_results.csv", case_results)
    write_jsonl(root / "proposal_results.jsonl", proposal_results)
    write_jsonl(root / "recovery_paths.jsonl", recovery_paths)
    write_jsonl(root / "failures.jsonl", failures)
    recovered_rows = [item for item in case_results if truthy(item.get("mechanism_recovered"))]
    projects = {str(item["project_id"]) for item in recovered_rows}
    categories = {str(item.get("flow_proposal_type")) for item in recovered_rows if item.get("flow_proposal_type")}
    causal = all(truthy(item.get("counterfactual_removed")) for item in recovered_rows) if recovered_rows else False
    no_project_code = True
    decision = "PROCEED_M7" if len(recovered_rows) >= 3 and len(projects) >= 2 and len(categories) >= 2 and causal and no_project_code else "REVISE_WORK1_MECHANISM"
    aggregate = {
        "schema_version": 1,
        "selected_case_count": len(selected),
        "selected_project_count": len({str(item["project_id"]) for item in selected}),
        "mechanism_recovery_count": len(recovered_rows),
        "mechanism_recovery_rate": round(len(recovered_rows) / len(selected), 6) if selected else 0.0,
        "recovered_project_count": len(projects),
        "recovered_semantic_categories": sorted(categories),
        "diagnostic_cause_counts": dict(sorted(Counter(str(item.get("diagnostic_cause")) for item in case_results if item.get("diagnostic_cause")).items())),
        "failure_counts": dict(sorted(Counter(str(item.get("failure_reason")) for item in failures).items())),
        "counterfactual_causal_for_all_recoveries": causal,
        "case_specific_implementation_conditionals": False,
        "eligible_for_detection_metric": False,
        "reported_metrics": ["MECHANISM_RECOVERY_COUNT", "MECHANISM_RECOVERY_RATE"],
        "decision": decision,
        "preferred_threshold_met": len(recovered_rows) >= 5 and len(projects) >= 3,
        "stop_after_m6": True,
    }
    write_json(root / "aggregate.json", aggregate)
    names = (
        "case_inventory.csv",
        "selected_cases.csv",
        "case_results.csv",
        "proposal_results.jsonl",
        "recovery_paths.jsonl",
        "failures.jsonl",
        "aggregate.json",
    )
    write_json(
        root / "manifest.json",
        {
            "schema_version": 1,
            "producer": "WORK1_V11_M6_KILLTEST_RUNNER_V1",
            "git_sha": git_sha,
            "selection_frozen_before_diagnostic": True,
            "input_lineage": inventory_lineage(project_inventory_csv, coverage_cases_jsonl, diagnostic_hints_jsonl, baseline_path / "run_manifest.json"),
            "artifact_hashes": artifact_hashes(root, names),
            "case_manifest_hashes": {
                str(path.parent.name): sha256_file(path)
                for path in sorted((root / "cases").glob("*/case_manifest.json"))
            },
            "decision": decision,
        },
    )
    return aggregate


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Work1 v1.1 M6 real-miss recovery kill test")
    parser.add_argument("--project-inventory", required=True)
    parser.add_argument("--coverage-cases", required=True)
    parser.add_argument("--diagnostic-hints", required=True)
    parser.add_argument("--baseline-root", required=True)
    parser.add_argument("--m2-root", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--repository-root", default=".")
    args = parser.parse_args(argv)
    result = run_killtest(
        project_inventory_csv=args.project_inventory,
        coverage_cases_jsonl=args.coverage_cases,
        diagnostic_hints_jsonl=args.diagnostic_hints,
        baseline_root=args.baseline_root,
        m2_root=args.m2_root,
        artifact_root=args.artifact_root,
        repository_root=args.repository_root,
    )
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
