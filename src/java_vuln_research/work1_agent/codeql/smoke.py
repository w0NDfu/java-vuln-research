from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from ..repository.entity import ProgramEntity
from .analysis_tools import CodeQLAnalysisTools
from .executor import CodeQLExecutor


READY_COHORT = (
    "P006", "P007", "P010", "P012",
    "D001", "D002", "D003", "D004",
    "V001", "V004", "V005", "V007", "V009", "V011", "V021", "V022", "V023", "V025",
)
SAMPLE_PLAN = (("TYPE", 2), ("METHOD", 3), ("CONSTRUCTOR", 1), ("FIELD", 2), ("CALL", 3))
SUCCESS_STATUSES = {"OK", "EMPTY"}


@dataclass(frozen=True, slots=True)
class ProjectInput:
    project_id: str
    project_name: str
    source_root: Path
    database: Path
    entities_path: Path


def _truth(value: Any) -> bool:
    return str(value).strip().casefold() in {"1", "true", "yes", "y"}


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return round(ordered[index], 6)


def _load_entities(path: Path) -> list[ProgramEntity]:
    entities: list[ProgramEntity] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                entities.append(ProgramEntity.from_dict(json.loads(line)))
    return sorted(
        entities,
        key=lambda item: (
            item.repository_relative_path,
            item.start_line,
            item.end_line,
            item.kind.value,
            item.entity_id,
        ),
    )


def _sample(entities: Iterable[ProgramEntity]) -> tuple[list[ProgramEntity], dict[str, int]]:
    values = sorted(
        entities,
        key=lambda item: (
            item.repository_relative_path,
            item.start_line,
            item.end_line,
            item.kind.value,
            item.entity_id,
        ),
    )
    selected: list[ProgramEntity] = []
    missing: dict[str, int] = {}
    for kind, requested in SAMPLE_PLAN:
        candidates = [item for item in values if item.kind.value == kind]
        chosen = candidates[:requested]
        selected.extend(chosen)
        if len(chosen) < requested:
            missing[kind] = requested - len(chosen)
    return selected, missing


def _find_entities(index_roots: Sequence[Path], project_id: str) -> Path:
    matches = [root / project_id / "entities.jsonl" for root in index_roots]
    for candidate in matches:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"M2 entities.jsonl not found for {project_id}: {matches}")


def load_inventory(inventory_csv: Path, index_roots: Sequence[Path]) -> list[ProjectInput]:
    with inventory_csv.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    by_id = {str(row.get("project_id") or "").strip(): row for row in rows}
    ready = {project_id for project_id, row in by_id.items() if _truth(row.get("codeql_db_ready"))}
    expected = set(READY_COHORT)
    if ready != expected:
        raise ValueError(f"ready cohort mismatch: missing={sorted(expected-ready)}, unexpected={sorted(ready-expected)}")
    projects: list[ProjectInput] = []
    for project_id in READY_COHORT:
        row = by_id[project_id]
        source_root = Path(str(row["source_root"]))
        database = Path(str(row["codeql_db_path"]))
        if not source_root.is_dir() or not database.is_dir():
            raise FileNotFoundError(f"inventory path is no longer ready for {project_id}")
        projects.append(
            ProjectInput(
                project_id=project_id,
                project_name=str(row.get("project_name") or ""),
                source_root=source_root,
                database=database,
                entities_path=_find_entities(index_roots, project_id),
            )
        )
    return projects


def _record_call(project: ProjectInput, entity: ProgramEntity, result: Any) -> dict[str, Any]:
    return {
        "project_id": project.project_id,
        "project_name": project.project_name,
        "entity_id": entity.entity_id,
        "entity_kind": entity.kind.value,
        "entity_path": entity.repository_relative_path,
        "entity_start_line": entity.start_line,
        **result.to_dict(),
    }


def run_project(
    project: ProjectInput,
    *,
    executable: Path,
    query_root: Path,
    artifact_root: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    started = time.monotonic()
    executor = CodeQLExecutor(
        executable,
        artifact_root=artifact_root / "calls" / project.project_id,
        timeout_seconds=timeout_seconds,
    )
    tools = CodeQLAnalysisTools(executor, query_root)
    entities = _load_entities(project.entities_path)
    samples, missing = _sample(entities)
    calls: list[dict[str, Any]] = []
    mappings: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    def invoke(entity: ProgramEntity, function: Callable[..., Any], **kwargs: Any) -> None:
        try:
            result = function(database=project.database, entity=entity, **kwargs)
            record = _record_call(project, entity, result)
        except Exception as error:  # keep the rest of a project runnable
            record = {
                "project_id": project.project_id,
                "project_name": project.project_name,
                "entity_id": entity.entity_id,
                "entity_kind": entity.kind.value,
                "entity_path": entity.repository_relative_path,
                "tool_name": getattr(function, "__name__", "UNKNOWN"),
                "status": "ERROR",
                "failure": {"reason": "SMOKE_DRIVER_ERROR", "message": repr(error)},
                "metrics": {"wall_clock_seconds": 0.0},
            }
        calls.append(record)
        mapping = ((record.get("provenance") or {}).get("mapping"))
        if mapping and not any(item.get("entity_id") == entity.entity_id for item in mappings):
            mappings.append({"project_id": project.project_id, **mapping})
        if record.get("status") not in SUCCESS_STATUSES:
            failures.append(record)

    for entity in samples:
        invoke(entity, tools.codeql_entity_facts)

    callables = [item for item in samples if item.kind.value in {"METHOD", "CONSTRUCTOR"}][:3]
    flow_nodes = [item for item in samples if item.kind.value == "CALL"][:3]
    for entity in callables:
        invoke(entity, tools.codeql_callers)
        invoke(entity, tools.codeql_callees)
    for entity in flow_nodes:
        invoke(entity, tools.codeql_local_flow)
    for entity in flow_nodes:
        invoke(entity, tools.codeql_dataflow_neighbors, direction="FORWARD", max_depth=1)
        invoke(entity, tools.codeql_dataflow_neighbors, direction="BACKWARD", max_depth=1)
    for entity in callables:
        invoke(entity, tools.codeql_cfg_neighbors, direction="BOTH", max_depth=1)

    statuses = Counter(str(item.get("status")) for item in calls)
    mapping_statuses = Counter(str(item.get("status")) for item in mappings)
    latencies = [float((item.get("metrics") or {}).get("wall_clock_seconds") or 0.0) for item in calls]
    summary = {
        "project_id": project.project_id,
        "project_name": project.project_name,
        "source_root": str(project.source_root),
        "codeql_db_path": str(project.database),
        "sample_requested": sum(value for _, value in SAMPLE_PLAN),
        "sample_available": len(samples),
        "sample_missing": json.dumps(missing, sort_keys=True),
        "mapping_unique": mapping_statuses["MAPPED_UNIQUE"],
        "mapping_ambiguous": mapping_statuses["MAPPED_AMBIGUOUS"],
        "mapping_not_mapped": mapping_statuses["NOT_MAPPED"],
        "mapping_unsupported": mapping_statuses["UNSUPPORTED_KIND"],
        "tool_calls": len(calls),
        "tool_ok": statuses["OK"],
        "tool_empty": statuses["EMPTY"],
        "tool_error": statuses["ERROR"],
        "tool_entity_not_mapped": statuses["ENTITY_NOT_MAPPED"],
        "tool_unsupported": statuses["UNSUPPORTED"],
        "tool_success_rate": round(sum(statuses[value] for value in SUCCESS_STATUSES) / len(calls), 6) if calls else 0.0,
        "avg_latency_seconds": round(statistics.fmean(latencies), 6) if latencies else 0.0,
        "p95_latency_seconds": _percentile(latencies, 0.95),
        "returned_nodes": sum(len(item.get("nodes") or []) for item in calls),
        "returned_edges": sum(len(item.get("edges") or []) for item in calls),
        "wall_clock_seconds": round(time.monotonic() - started, 6),
    }
    return {"summary": summary, "calls": calls, "mappings": mappings, "failures": failures}


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def _aggregate(results: Sequence[dict[str, Any]], elapsed: float) -> dict[str, Any]:
    calls = [item for result in results for item in result["calls"]]
    mappings = [item for result in results for item in result["mappings"]]
    latencies = [float((item.get("metrics") or {}).get("wall_clock_seconds") or 0.0) for item in calls]
    by_tool: dict[str, Counter[str]] = {}
    for item in calls:
        by_tool.setdefault(str(item.get("tool_name")), Counter())[str(item.get("status"))] += 1
    failure_reasons = Counter(
        str((item.get("failure") or {}).get("reason") or "UNKNOWN")
        for item in calls
        if item.get("status") == "ERROR"
    )
    return {
        "cohort": list(READY_COHORT),
        "project_count": len(results),
        "tool_call_count": len(calls),
        "tool_status_counts": dict(Counter(str(item.get("status")) for item in calls)),
        "tool_success_rate": round(sum(item.get("status") in SUCCESS_STATUSES for item in calls) / len(calls), 6) if calls else 0.0,
        "mapping_status_counts": dict(Counter(str(item.get("status")) for item in mappings)),
        "failure_reason_counts": dict(failure_reasons),
        "tool_breakdown": {name: dict(counts) for name, counts in sorted(by_tool.items())},
        "latency_seconds": {
            "avg": round(statistics.fmean(latencies), 6) if latencies else 0.0,
            "p50": _percentile(latencies, 0.50),
            "p95": _percentile(latencies, 0.95),
            "max": round(max(latencies), 6) if latencies else 0.0,
        },
        "returned_nodes": sum(len(item.get("nodes") or []) for item in calls),
        "returned_edges": sum(len(item.get("edges") or []) for item in calls),
        "wall_clock_seconds": round(elapsed, 6),
    }


def run(args: argparse.Namespace) -> int:
    started = time.monotonic()
    output = Path(args.artifact_root)
    output.mkdir(parents=True, exist_ok=True)
    projects = load_inventory(Path(args.inventory_csv), [Path(item) for item in args.index_root])
    checkpoint_root = output / "checkpoints"
    checkpoint_root.mkdir(exist_ok=True)
    results_by_id: dict[str, dict[str, Any]] = {}

    def worker(project: ProjectInput) -> tuple[str, dict[str, Any]]:
        checkpoint = checkpoint_root / f"{project.project_id}.json"
        if args.resume and checkpoint.is_file():
            return project.project_id, json.loads(checkpoint.read_text(encoding="utf-8"))
        result = run_project(
            project,
            executable=Path(args.codeql),
            query_root=Path(args.query_root),
            artifact_root=output,
            timeout_seconds=args.timeout,
        )
        temporary = checkpoint.with_suffix(".json.tmp")
        temporary.write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
        temporary.replace(checkpoint)
        return project.project_id, result

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(worker, project): project.project_id for project in projects}
        for future in as_completed(futures):
            project_id, result = future.result()
            results_by_id[project_id] = result
            print(json.dumps({"project_id": project_id, **result["summary"]}, ensure_ascii=False), flush=True)

    results = [results_by_id[project_id] for project_id in READY_COHORT]
    summaries = [result["summary"] for result in results]
    with (output / "project_summary.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(summaries[0]))
        writer.writeheader()
        writer.writerows(summaries)
    _write_jsonl(output / "tool_calls.jsonl", (item for result in results for item in result["calls"]))
    _write_jsonl(output / "entity_mapping.jsonl", (item for result in results for item in result["mappings"]))
    _write_jsonl(output / "failures.jsonl", (item for result in results for item in result["failures"]))
    aggregate = _aggregate(results, time.monotonic() - started)
    (output / "aggregate.json").write_text(json.dumps(aggregate, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(aggregate, ensure_ascii=False), flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Work1 V11 M3 smoke on the manifest-backed ready cohort")
    parser.add_argument("--inventory-csv", required=True)
    parser.add_argument("--index-root", action="append", required=True)
    parser.add_argument("--query-root", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--codeql", required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--resume", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.workers < 1 or args.workers > 4:
        raise SystemExit("--workers must be between 1 and 4")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
