from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .baseline import run_frozen_baseline
from .common.contracts import DetectorManifestError, load_detector_manifest
from .common.inventory import inventory_codeql_databases, inventory_datasets
from .common.io import load_yaml
from .common.run_manifest import RunManifest
from .discovery import DiscoveryError, run_p0a_discovery
from .evaluation import (
    CandidateCoverageError,
    P0AEvaluationError,
    evaluate_candidate_coverage,
    evaluate_p0a,
)
from .frontier import CandidatePathRunError, run_w1_e1_paths
from .preflight import PreflightError, run_preflight
from .reporting import generate_e0_report


def _run_id() -> str:
    now = datetime.now(timezone.utc)
    return now.strftime("MSA-P0-E0-%Y%m%d-%H%M%S")


def _json_print(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2))


def _command_validate_detector(args: argparse.Namespace) -> int:
    projects = load_detector_manifest(args.manifest)
    _json_print({"status": "PASS", "projects": len(projects)})
    return 0


def _command_inventory_datasets(args: argparse.Namespace) -> int:
    rows = inventory_datasets(args.root, args.output)
    _json_print({"status": "SUCCESS", "rows": len(rows), "output": args.output})
    return 0


def _command_inventory_dbs(args: argparse.Namespace) -> int:
    rows = inventory_codeql_databases(args.root, args.output)
    _json_print({"status": "SUCCESS", "rows": len(rows), "output": args.output})
    return 0


def _command_preflight(args: argparse.Namespace) -> int:
    result = run_preflight(
        project_root=args.project_root,
        paths_config=args.paths_config,
        environment_output=args.environment_output,
    )
    _json_print(result)
    return 0


def _command_baseline(args: argparse.Namespace) -> int:
    rows = run_frozen_baseline(
        detector_manifest=args.detector_manifest,
        output_root=args.output_root,
        query_suite=args.query_suite,
        threads=args.threads,
        ram_mb=args.ram_mb,
        codeql_executable=args.codeql,
    )
    successes = sum(1 for row in rows if row["status"] == "SUCCESS")
    _json_print({"projects": len(rows), "success": successes, "failed": len(rows) - successes})
    return 0 if successes else 2


def _command_report(args: argparse.Namespace) -> int:
    summary = generate_e0_report(
        raw_run_dir=args.raw_run_dir,
        report_dir=args.report_dir,
    )
    _json_print(summary)
    return 0


def _command_discover_p0a(args: argparse.Namespace) -> int:
    summary = run_p0a_discovery(
        detector_manifest=args.detector_manifest,
        query_root=args.query_root,
        output_root=args.output_root,
        threads=args.threads,
        ram_mb=args.ram_mb,
        codeql_executable=args.codeql,
    )
    _json_print(summary)
    return 0 if summary["status"] == "SUCCESS" else 2


def _command_evaluate_p0a(args: argparse.Namespace) -> int:
    summary = evaluate_p0a(
        detector_output_dir=args.detector_output,
        project_info_csv=args.project_info,
        fix_info_csv=args.fix_info,
        output_root=args.output_root,
    )
    _json_print(summary)
    return 0 if summary["status"] == "SUCCESS" else 2


def _command_evaluate_w1_e1(args: argparse.Namespace) -> int:
    summary = evaluate_candidate_coverage(
        candidate_paths_file=args.candidate_paths,
        detector_manifest=args.detector_manifest,
        project_info_csv=args.project_info,
        fix_info_csv=args.fix_info,
        baseline_raw_dir=args.baseline_raw_dir,
        output_root=args.output_root,
    )
    _json_print(summary)
    return 0


def _command_run_w1_e1_paths(args: argparse.Namespace) -> int:
    summary = run_w1_e1_paths(
        detector_manifest=args.detector_manifest,
        endpoint_output_dir=args.endpoint_output_dir,
        query_root=args.query_root,
        output_root=args.output_root,
        threads=args.threads,
        ram_mb=args.ram_mb,
        codeql_executable=args.codeql,
    )
    _json_print(summary)
    return 0 if summary["status"] == "SUCCESS" else 2


def _command_run_e0(args: argparse.Namespace) -> int:
    project_root = Path(args.project_root).resolve()
    paths = load_yaml(args.paths_config)
    config = load_yaml(args.config)
    if not isinstance(paths, dict) or not isinstance(config, dict):
        raise ValueError("paths and experiment configs must be mappings")
    run_id = args.run_id or _run_id()
    raw_run_dir = Path(str(paths["experiment_output_root"])) / run_id
    inventory_dir = raw_run_dir / "inventory"
    environment_output = raw_run_dir / "environment.txt"

    run_preflight(
        project_root=project_root,
        paths_config=args.paths_config,
        environment_output=environment_output,
    )
    inventory_datasets(paths["dataset_root"], inventory_dir / "dataset_inventory.csv")
    inventory_codeql_databases(
        paths["codeql_db_root"], inventory_dir / "codeql_db_inventory.csv"
    )

    projects = load_detector_manifest(args.detector_manifest)
    baseline_config = config.get("baseline") or {}
    manifest_builder = RunManifest(
        run_id=run_id,
        experiment="MSA-P0-E0",
        project_root=project_root,
        dataset_name=args.dataset_name,
        dataset_revision=args.dataset_revision,
        config_paths=[Path(args.config), Path(args.detector_manifest)],
        semantic_rule_paths=[project_root / "codeql"],
        prompt_paths=[project_root / "prompts"],
    )
    rows = run_frozen_baseline(
        detector_manifest=args.detector_manifest,
        output_root=raw_run_dir,
        query_suite=str(baseline_config["query_suite"]),
        threads=int(baseline_config.get("threads", 0)),
        ram_mb=baseline_config.get("ram_mb"),
        codeql_executable=args.codeql,
    )
    successes = sum(1 for row in rows if row["status"] == "SUCCESS")
    runnable = sum(
        1
        for row in rows
        if row.get("stage") not in {"PREFLIGHT", "DATABASE_PRECHECK"}
    )
    status = "SUCCESS" if rows and successes == len(rows) else "PARTIAL" if successes else "FAILED"
    manifest_builder.finish(
        raw_run_dir / "run_manifest.json",
        projects_requested=len(projects),
        projects_runnable=runnable,
        projects_build_failed="NOT_APPLICABLE",
        status=status,
    )
    report_dir = project_root / "reports" / "runs" / run_id
    summary = generate_e0_report(raw_run_dir=raw_run_dir, report_dir=report_dir)
    _json_print({"raw_run_dir": str(raw_run_dir), "report_dir": str(report_dir), **summary})
    return 0 if status == "SUCCESS" else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="java-vuln-research")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate-detector")
    validate.add_argument("manifest")
    validate.set_defaults(func=_command_validate_detector)

    datasets = commands.add_parser("inventory-datasets")
    datasets.add_argument("--root", required=True)
    datasets.add_argument("--output", required=True)
    datasets.set_defaults(func=_command_inventory_datasets)

    databases = commands.add_parser("inventory-dbs")
    databases.add_argument("--root", required=True)
    databases.add_argument("--output", required=True)
    databases.set_defaults(func=_command_inventory_dbs)

    preflight = commands.add_parser("preflight")
    preflight.add_argument("--project-root", required=True)
    preflight.add_argument("--paths-config", required=True)
    preflight.add_argument("--environment-output")
    preflight.set_defaults(func=_command_preflight)

    baseline = commands.add_parser("baseline")
    baseline.add_argument("--detector-manifest", required=True)
    baseline.add_argument("--output-root", required=True)
    baseline.add_argument("--query-suite", required=True)
    baseline.add_argument("--threads", type=int, default=0)
    baseline.add_argument("--ram-mb", type=int)
    baseline.add_argument("--codeql", default="codeql")
    baseline.set_defaults(func=_command_baseline)

    report = commands.add_parser("report")
    report.add_argument("--raw-run-dir", required=True)
    report.add_argument("--report-dir", required=True)
    report.set_defaults(func=_command_report)

    discover_p0a = commands.add_parser("discover-p0a")
    discover_p0a.add_argument("--detector-manifest", required=True)
    discover_p0a.add_argument("--query-root", required=True)
    discover_p0a.add_argument("--output-root", required=True)
    discover_p0a.add_argument("--threads", type=int, default=0)
    discover_p0a.add_argument("--ram-mb", type=int)
    discover_p0a.add_argument("--codeql", default="codeql")
    discover_p0a.set_defaults(func=_command_discover_p0a)

    evaluate = commands.add_parser("evaluate-p0a")
    evaluate.add_argument("--detector-output", required=True)
    evaluate.add_argument("--project-info", required=True)
    evaluate.add_argument("--fix-info", required=True)
    evaluate.add_argument("--output-root", required=True)
    evaluate.set_defaults(func=_command_evaluate_p0a)

    evaluate_w1_e1 = commands.add_parser("evaluate-w1-e1")
    evaluate_w1_e1.add_argument("--candidate-paths", required=True)
    evaluate_w1_e1.add_argument("--detector-manifest", required=True)
    evaluate_w1_e1.add_argument("--project-info", required=True)
    evaluate_w1_e1.add_argument("--fix-info", required=True)
    evaluate_w1_e1.add_argument("--baseline-raw-dir", required=True)
    evaluate_w1_e1.add_argument("--output-root", required=True)
    evaluate_w1_e1.set_defaults(func=_command_evaluate_w1_e1)

    candidate_paths = commands.add_parser("run-w1-e1-paths")
    candidate_paths.add_argument("--detector-manifest", required=True)
    candidate_paths.add_argument("--endpoint-output-dir", required=True)
    candidate_paths.add_argument("--query-root", required=True)
    candidate_paths.add_argument("--output-root", required=True)
    candidate_paths.add_argument("--threads", type=int, default=0)
    candidate_paths.add_argument("--ram-mb", type=int)
    candidate_paths.add_argument("--codeql", default="codeql")
    candidate_paths.set_defaults(func=_command_run_w1_e1_paths)

    run_e0 = commands.add_parser("run-e0")
    run_e0.add_argument("--project-root", required=True)
    run_e0.add_argument("--paths-config", required=True)
    run_e0.add_argument("--detector-manifest", required=True)
    run_e0.add_argument("--config", required=True)
    run_e0.add_argument("--dataset-name", required=True)
    run_e0.add_argument("--dataset-revision", required=True)
    run_e0.add_argument("--run-id")
    run_e0.add_argument("--codeql", default="codeql")
    run_e0.set_defaults(func=_command_run_e0)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (
        DetectorManifestError,
        CandidateCoverageError,
        CandidatePathRunError,
        DiscoveryError,
        P0AEvaluationError,
        PreflightError,
        KeyError,
        ValueError,
    ) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
