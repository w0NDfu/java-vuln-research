from __future__ import annotations

import csv
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable, Sequence

from ..common.contracts import load_detector_manifest
from ..common.io import write_json, write_jsonl


EXTERNAL_COLUMNS = ("mechanism", "entity", "evidence_kind", "file", "line", "source")
EFFECT_COLUMNS = (
    "effect_type",
    "mechanism",
    "entity",
    "critical_role",
    "evidence_kind",
    "file",
    "line",
    "source",
    "primitive_rule_id",
    "callee_identity",
    "method_identity",
    "call_identity",
    "argument_index",
    "anchor_kind",
)


class DiscoveryError(RuntimeError):
    """Raised when deterministic P0-A discovery cannot execute safely."""


def _candidate_id(prefix: str, project: str, row: dict[str, str]) -> str:
    material = json.dumps(
        {"project": project, **row}, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return f"{prefix}-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:20]}"


def external_candidate(
    *, project: str, revision: str, row: dict[str, str]
) -> dict[str, Any]:
    evidence = {
        "project": project,
        "revision": revision,
        "kind": row["evidence_kind"],
        "file": row["file"],
        "line": int(row["line"]),
    }
    return {
        "candidate_id": _candidate_id("ext", project, row),
        "kind": "EXTERNAL_INPUT",
        "entity": row["entity"],
        "mechanism": row["mechanism"],
        "confidence": "HIGH",
        "evidence": [evidence],
        "source": row["source"],
    }


def security_effect_candidate(
    *, project: str, revision: str, row: dict[str, str]
) -> dict[str, Any]:
    argument_index = int(row["argument_index"])
    location = {"file": row["file"], "line": int(row["line"])}
    evidence = {
        "project": project,
        "revision": revision,
        "mechanism": row["mechanism"],
        "kind": row["evidence_kind"],
        **location,
        "primitive_rule_id": row["primitive_rule_id"],
        "callee_identity": row["callee_identity"],
        "method_identity": row["method_identity"],
        "call_identity": row["call_identity"],
        "argument_index": argument_index,
        "anchor_kind": row["anchor_kind"],
    }
    return {
        "candidate_id": _candidate_id("eff", project, row),
        "project_id": project,
        "kind": "SECURITY_EFFECT",
        "effect_type": row["effect_type"],
        "entity": row["entity"],
        "callee_identity": row["callee_identity"],
        "method_identity": row["method_identity"],
        "call_identity": row["call_identity"],
        "critical_role": row["critical_role"],
        "critical_roles": [row["critical_role"]],
        "argument_index": argument_index,
        "anchor_kind": row["anchor_kind"],
        "location": location,
        "discovery_route": "ROUTE_A",
        "evidence_kind": row["evidence_kind"],
        "primitive_rule_id": row["primitive_rule_id"],
        "provenance": {
            "project": project,
            "revision": revision,
            "source": row["source"],
            "mechanism": row["mechanism"],
        },
        "mechanism": row["mechanism"],
        "confidence": "HIGH",
        "evidence": [evidence],
        "source": row["source"],
    }


def deduplicate_candidates(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(row["candidate_id"]): row for row in rows}
    return [by_id[key] for key in sorted(by_id)]


def _decode_csv(text: str, columns: Sequence[str]) -> list[dict[str, str]]:
    decoded: list[dict[str, str]] = []
    for values in csv.reader(text.splitlines()):
        if not values:
            continue
        if tuple(values) == tuple(columns):
            continue
        if len(values) != len(columns):
            raise DiscoveryError(
                f"unexpected CodeQL row width: expected {len(columns)}, got {len(values)}"
            )
        decoded.append(dict(zip(columns, values, strict=True)))
    return decoded


def _run_query(
    *,
    codeql: str,
    database: Path,
    query: Path,
    bqrs: Path,
    log: Path,
    threads: int,
    ram_mb: int | None,
) -> list[dict[str, str]]:
    command = [
        codeql,
        "query",
        "run",
        str(query),
        f"--database={database}",
        f"--output={bqrs}",
        f"--threads={threads}",
    ]
    if ram_mb is not None:
        command.append(f"--ram={ram_mb}")
    completed = subprocess.run(
        command,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    log.write_text(completed.stdout or "", encoding="utf-8")
    if completed.returncode != 0:
        raise DiscoveryError(f"query failed with exit code {completed.returncode}: {query.name}")

    decoded = subprocess.run(
        [codeql, "bqrs", "decode", "--format=csv", "--no-titles", str(bqrs)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if decoded.returncode != 0:
        with log.open("a", encoding="utf-8") as handle:
            handle.write("\nBQRS DECODE ERROR\n" + (decoded.stderr or ""))
        raise DiscoveryError(f"BQRS decode failed with exit code {decoded.returncode}: {query.name}")
    columns = EXTERNAL_COLUMNS if query.name.startswith("External") else EFFECT_COLUMNS
    return _decode_csv(decoded.stdout, columns)


def run_p0a_discovery(
    *,
    detector_manifest: str | Path,
    query_root: str | Path,
    output_root: str | Path,
    threads: int = 0,
    ram_mb: int | None = None,
    codeql_executable: str = "codeql",
) -> dict[str, Any]:
    projects = load_detector_manifest(detector_manifest)
    codeql = shutil.which(codeql_executable)
    if codeql is None:
        raise DiscoveryError("CodeQL executable is unavailable")

    query_path = Path(query_root)
    queries = {
        "external": query_path / "external_input" / "ExternalInputDiscovery.ql",
        "effect": query_path / "security_effect" / "SecurityEffectDiscovery.ql",
    }
    missing = [str(path) for path in queries.values() if not path.is_file()]
    if missing:
        raise DiscoveryError("missing discovery queries: " + ", ".join(missing))

    output = Path(output_root)
    bqrs_dir = output / "bqrs"
    logs_dir = output / "logs"
    bqrs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    external: list[dict[str, Any]] = []
    effects: list[dict[str, Any]] = []
    statuses: list[dict[str, Any]] = []
    started_run = time.monotonic()
    for project in projects:
        started = time.monotonic()
        name = project["project"]
        database = Path(project["codeql_db_path"])
        status: dict[str, Any] = {
            "project": name,
            "revision": project["revision"],
        }
        if not database.is_dir():
            status.update(
                status="FAILED",
                stage="DATABASE_PRECHECK",
                error_class="DATABASE_UNAVAILABLE",
            )
        else:
            try:
                external_rows = _run_query(
                    codeql=codeql,
                    database=database,
                    query=queries["external"],
                    bqrs=bqrs_dir / f"{name}.external.bqrs",
                    log=logs_dir / f"{name}.external.codeql.log",
                    threads=threads,
                    ram_mb=ram_mb,
                )
                effect_rows = _run_query(
                    codeql=codeql,
                    database=database,
                    query=queries["effect"],
                    bqrs=bqrs_dir / f"{name}.effect.bqrs",
                    log=logs_dir / f"{name}.effect.codeql.log",
                    threads=threads,
                    ram_mb=ram_mb,
                )
            except DiscoveryError as error:
                status.update(
                    status="FAILED",
                    stage="CODEQL_QUERY",
                    error_class="QUERY_FAILURE",
                    detail=str(error),
                )
            else:
                project_external = [
                    external_candidate(project=name, revision=project["revision"], row=row)
                    for row in external_rows
                ]
                project_effects = [
                    security_effect_candidate(
                        project=name, revision=project["revision"], row=row
                    )
                    for row in effect_rows
                ]
                external.extend(project_external)
                effects.extend(project_effects)
                status.update(
                    status="SUCCESS",
                    external_input_count=len(project_external),
                    security_effect_count=len(project_effects),
                    wrapper_count=sum(
                        1
                        for row in [*project_external, *project_effects]
                        if row["source"] == "STATIC_DERIVED"
                    ),
                )
        status["runtime_seconds"] = round(time.monotonic() - started, 3)
        statuses.append(status)

    external = deduplicate_candidates(external)
    effects = deduplicate_candidates(effects)
    write_jsonl(output / "external_inputs.jsonl", external)
    write_jsonl(output / "security_effects.jsonl", effects)
    write_jsonl(output / "project_status.jsonl", statuses)
    successes = sum(1 for row in statuses if row["status"] == "SUCCESS")
    summary = {
        "status": "SUCCESS" if successes == len(statuses) and statuses else "PARTIAL" if successes else "FAILED",
        "projects_requested": len(statuses),
        "projects_success": successes,
        "projects_failed": len(statuses) - successes,
        "discovered_external_input_count": len(external),
        "discovered_security_effect_count": len(effects),
        "wrapper_count": sum(
            1 for row in [*external, *effects] if row["source"] == "STATIC_DERIVED"
        ),
        "runtime_seconds": round(time.monotonic() - started_run, 3),
    }
    write_json(output / "summary.json", summary)
    return summary
