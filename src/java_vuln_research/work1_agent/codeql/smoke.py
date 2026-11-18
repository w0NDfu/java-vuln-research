from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
import subprocess
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence

from ...common.io import load_yaml
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
SMOKE_SCHEMA_VERSION = "WORK1_V11_M3_SMOKE_V2"


@dataclass(frozen=True, slots=True)
class ProjectInput:
    project_id: str
    project_name: str
    source_root: Path
    database: Path
    entities_path: Path
    source_head: str | None = None
    source_head_origin: str = "UNAVAILABLE"


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


def _load_source_revisions(manifest_paths: Sequence[Path]) -> dict[str, str]:
    revisions: dict[str, str] = {}
    for manifest_path in manifest_paths:
        value = load_yaml(manifest_path) or {}
        for row in value.get("projects") or []:
            project_id = str(row.get("project") or row.get("project_id") or "").strip()
            revision = str(row.get("revision") or "").strip()
            if not project_id or not revision:
                continue
            previous = revisions.get(project_id)
            if previous is not None and previous != revision:
                raise ValueError(f"conflicting source revisions for {project_id}: {previous} != {revision}")
            revisions[project_id] = revision
    return revisions


def load_inventory(
    inventory_csv: Path,
    index_roots: Sequence[Path],
    source_revisions: dict[str, str] | None = None,
) -> list[ProjectInput]:
    with inventory_csv.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    by_id = {str(row.get("project_id") or "").strip(): row for row in rows}
    ready = {project_id for project_id, row in by_id.items() if _truth(row.get("codeql_db_ready"))}
    expected = set(READY_COHORT)
    if ready != expected:
        raise ValueError(f"ready cohort mismatch: missing={sorted(expected-ready)}, unexpected={sorted(ready-expected)}")
    projects: list[ProjectInput] = []
    revisions = source_revisions or {}
    for project_id in READY_COHORT:
        row = by_id[project_id]
        source_root = Path(str(row["source_root"]))
        database = Path(str(row["codeql_db_path"]))
        if not source_root.is_dir() or not database.is_dir():
            raise FileNotFoundError(f"inventory path is no longer ready for {project_id}")
        inventory_head = next(
            (
                str(row.get(key)).strip()
                for key in (
                    "source_head",
                    "source_git_sha",
                    "git_sha",
                    "commit_sha",
                    "commit",
                    "revision",
                )
                if row.get(key) not in {None, ""}
            ),
            None,
        )
        source_git_head = _git_head(source_root, require_local_marker=True)
        source_head = inventory_head or revisions.get(project_id) or source_git_head
        source_head_origin = (
            "inventory"
            if inventory_head
            else "frozen_manifest"
            if revisions.get(project_id)
            else "source_git"
            if source_git_head
            else "UNAVAILABLE"
        )
        projects.append(
            ProjectInput(
                project_id=project_id,
                project_name=str(row.get("project_name") or ""),
                source_root=source_root,
                database=database,
                entities_path=_find_entities(index_roots, project_id),
                source_head=source_head,
                source_head_origin=source_head_origin,
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


def _git_head(path: Path, *, require_local_marker: bool = False) -> str | None:
    if require_local_marker and not ((path / ".git").is_dir() or (path / ".git").is_file()):
        return None
    try:
        completed = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    value = completed.stdout.strip()
    return value if completed.returncode == 0 and value else None


def run_project(
    project: ProjectInput,
    *,
    executable: Path,
    query_root: Path,
    artifact_root: Path,
    timeout_seconds: int,
    query_threads: int,
    v11_git_sha: str,
) -> dict[str, Any]:
    started = time.monotonic()
    executor = CodeQLExecutor(
        executable,
        artifact_root=artifact_root / "calls" / project.project_id,
        timeout_seconds=timeout_seconds,
        threads=query_threads,
    )
    tools = CodeQLAnalysisTools(executor, query_root)
    entities = _load_entities(project.entities_path)
    samples, missing = _sample(entities)
    calls: list[dict[str, Any]] = []
    mappings: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    if samples:
        tools.prefetch_entity_facts(database=project.database, entities=samples)

    def invoke(entity: ProgramEntity, function: Callable[..., Any], **kwargs: Any) -> None:
        try:
            result = function(database=project.database, entity=entity, **kwargs)
            result.provenance.update(
                {
                    "v11_git_sha": v11_git_sha,
                    "project_source_head": project.source_head,
                    "project_source_head_origin": project.source_head_origin,
                }
            )
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
                "provenance": {
                    "v11_git_sha": v11_git_sha,
                    "project_source_head": project.source_head,
                    "project_source_head_origin": project.source_head_origin,
                },
            }
        calls.append(record)
        mapping = ((record.get("provenance") or {}).get("mapping"))
        if mapping and not any(item.get("entity_id") == entity.entity_id for item in mappings):
            mappings.append(
                {
                    "project_id": project.project_id,
                    "v11_git_sha": v11_git_sha,
                    "project_source_head": project.source_head,
                    "project_source_head_origin": project.source_head_origin,
                    **mapping,
                }
            )
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
    query_hashes = sorted(
        {
            str((item.get("provenance") or {}).get("query_hash"))
            for item in calls
            if (item.get("provenance") or {}).get("query_hash")
        }
    )
    summary = {
        "smoke_schema_version": SMOKE_SCHEMA_VERSION,
        "project_id": project.project_id,
        "project_name": project.project_name,
        "source_root": str(project.source_root),
        "codeql_db_path": str(project.database),
        "v11_git_sha": v11_git_sha,
        "project_source_head": project.source_head or "UNAVAILABLE",
        "project_source_head_available": bool(project.source_head),
        "project_source_head_origin": project.source_head_origin,
        "codeql_version": next(
            (
                str((item.get("provenance") or {}).get("codeql_version"))
                for item in calls
                if (item.get("provenance") or {}).get("codeql_version")
            ),
            "UNKNOWN",
        ),
        "query_timeout_seconds": timeout_seconds,
        "query_threads": query_threads,
        "query_hashes": json.dumps(query_hashes, separators=(",", ":")),
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
        "truncated_calls": sum(bool(item.get("truncated")) for item in calls),
        "wall_clock_seconds": round(time.monotonic() - started, 6),
    }
    return {"summary": summary, "calls": calls, "mappings": mappings, "failures": failures}


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")


def _aggregate(
    results: Sequence[dict[str, Any]],
    elapsed: float,
    *,
    v11_git_sha: str,
    workers: int | None = None,
) -> dict[str, Any]:
    calls = [item for result in results for item in result["calls"]]
    mappings = [item for result in results for item in result["mappings"]]
    latencies = [float((item.get("metrics") or {}).get("wall_clock_seconds") or 0.0) for item in calls]
    by_tool: dict[str, list[dict[str, Any]]] = {}
    for item in calls:
        by_tool.setdefault(str(item.get("tool_name")), []).append(item)
    failure_reasons = Counter(
        str((item.get("failure") or {}).get("reason") or "UNKNOWN")
        for item in calls
        if item.get("status") == "ERROR"
    )
    return {
        "smoke_schema_version": SMOKE_SCHEMA_VERSION,
        "v11_git_sha": v11_git_sha,
        "workers": workers,
        "query_timeout_seconds": sorted(
            {int(result["summary"].get("query_timeout_seconds") or 0) for result in results}
        ),
        "query_threads": sorted(
            {int(result["summary"].get("query_threads") or 0) for result in results}
        ),
        "codeql_versions": sorted(
            {
                str((item.get("provenance") or {}).get("codeql_version"))
                for item in calls
                if (item.get("provenance") or {}).get("codeql_version")
            }
        ),
        "query_hashes": sorted(
            {
                str((item.get("provenance") or {}).get("query_hash"))
                for item in calls
                if (item.get("provenance") or {}).get("query_hash")
            }
        ),
        "database_paths": sorted(
            {
                str((item.get("provenance") or {}).get("database_path"))
                for item in calls
                if (item.get("provenance") or {}).get("database_path")
            }
        ),
        "project_source_heads": {
            str(result["summary"]["project_id"]): str(result["summary"]["project_source_head"])
            for result in results
        },
        "cohort": list(READY_COHORT),
        "project_count": len(results),
        "tool_call_count": len(calls),
        "tool_status_counts": dict(Counter(str(item.get("status")) for item in calls)),
        "tool_success_rate": round(sum(item.get("status") in SUCCESS_STATUSES for item in calls) / len(calls), 6) if calls else 0.0,
        "mapping_status_counts": dict(Counter(str(item.get("status")) for item in mappings)),
        "failure_reason_counts": dict(failure_reasons),
        "tool_breakdown": {
            name: {
                "tool_calls": len(items),
                "status_counts": dict(Counter(str(item.get("status")) for item in items)),
                "success_rate": round(
                    sum(item.get("status") in SUCCESS_STATUSES for item in items) / len(items),
                    6,
                ),
                "latency_seconds": {
                    "avg": round(
                        statistics.fmean(
                            float((item.get("metrics") or {}).get("wall_clock_seconds") or 0.0)
                            for item in items
                        ),
                        6,
                    ),
                    "p50": _percentile(
                        [float((item.get("metrics") or {}).get("wall_clock_seconds") or 0.0) for item in items],
                        0.50,
                    ),
                    "p95": _percentile(
                        [float((item.get("metrics") or {}).get("wall_clock_seconds") or 0.0) for item in items],
                        0.95,
                    ),
                    "max": round(
                        max(float((item.get("metrics") or {}).get("wall_clock_seconds") or 0.0) for item in items),
                        6,
                    ),
                },
                "returned_nodes": sum(len(item.get("nodes") or []) for item in items),
                "returned_edges": sum(len(item.get("edges") or []) for item in items),
                "truncation_rate": round(sum(bool(item.get("truncated")) for item in items) / len(items), 6),
            }
            for name, items in sorted(by_tool.items())
        },
        "latency_seconds": {
            "avg": round(statistics.fmean(latencies), 6) if latencies else 0.0,
            "p50": _percentile(latencies, 0.50),
            "p95": _percentile(latencies, 0.95),
            "max": round(max(latencies), 6) if latencies else 0.0,
        },
        "returned_nodes": sum(len(item.get("nodes") or []) for item in calls),
        "returned_edges": sum(len(item.get("edges") or []) for item in calls),
        "truncation_rate": round(sum(bool(item.get("truncated")) for item in calls) / len(calls), 6) if calls else 0.0,
        "wall_clock_seconds": round(elapsed, 6),
    }


def run(args: argparse.Namespace) -> int:
    started = time.monotonic()
    output = Path(args.artifact_root)
    output.mkdir(parents=True, exist_ok=True)
    query_root = Path(args.query_root).resolve()
    manifest_paths = [Path(item) for item in (args.source_manifest or [])]
    if not manifest_paths:
        manifest_paths = [query_root.parents[1] / "experiments" / "frozen_configs" / "w1_e1_dev16_manifest.yaml"]
    source_revisions = _load_source_revisions(manifest_paths)
    missing_revisions = sorted(set(READY_COHORT) - set(source_revisions))
    if missing_revisions:
        raise ValueError(f"source revisions missing from manifest: {missing_revisions}")
    projects = load_inventory(
        Path(args.inventory_csv),
        [Path(item) for item in args.index_root],
        source_revisions,
    )
    v11_git_sha = _git_head(query_root.parents[1]) or "UNKNOWN"
    checkpoint_root = output / "checkpoints"
    checkpoint_root.mkdir(exist_ok=True)
    results_by_id: dict[str, dict[str, Any]] = {}

    def worker(project: ProjectInput) -> tuple[str, dict[str, Any]]:
        checkpoint = checkpoint_root / f"{project.project_id}.json"
        if args.resume and checkpoint.is_file():
            cached = json.loads(checkpoint.read_text(encoding="utf-8"))
            summary = cached.get("summary") or {}
            if (
                summary.get("smoke_schema_version") == SMOKE_SCHEMA_VERSION
                and summary.get("v11_git_sha") == v11_git_sha
                and int(summary.get("query_timeout_seconds") or 0) == args.timeout
                and int(summary.get("query_threads") or 0) == args.query_threads
            ):
                return project.project_id, cached
        result = run_project(
            project,
            executable=Path(args.codeql),
            query_root=Path(args.query_root),
            artifact_root=output,
            timeout_seconds=args.timeout,
            query_threads=args.query_threads,
            v11_git_sha=v11_git_sha,
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
    aggregate = _aggregate(
        results,
        time.monotonic() - started,
        v11_git_sha=v11_git_sha,
        workers=args.workers,
    )
    (output / "aggregate.json").write_text(json.dumps(aggregate, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(aggregate, ensure_ascii=False), flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Work1 V11 M3 smoke on the manifest-backed ready cohort")
    parser.add_argument("--inventory-csv", required=True)
    parser.add_argument("--index-root", action="append", required=True)
    parser.add_argument("--query-root", required=True)
    parser.add_argument("--source-manifest", action="append")
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--codeql", required=True)
    parser.add_argument("--query-threads", type=int, default=0)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--resume", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.workers < 1 or args.workers > 4:
        raise SystemExit("--workers must be between 1 and 4")
    if args.query_threads < 0:
        raise SystemExit("--query-threads must be non-negative")
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
