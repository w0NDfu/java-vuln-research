from __future__ import annotations

import csv
import json
import shutil
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..common.contracts import load_detector_manifest
from ..common.io import read_jsonl, write_json, write_jsonl
from ..common.provenance import git_metadata
from .candidate_path import CandidatePathError, build_candidate_path


FRONTIER_COLUMNS = (
    "source_file",
    "source_line",
    "effect_file",
    "effect_line",
    "call_file",
    "call_line",
    "frontier_reason",
)


class CandidatePathRunError(RuntimeError):
    """Raised when the W1-E1 Data/Call detector cannot run safely."""


def _normalise_path(value: str) -> str:
    return value.replace("\\", "/").lstrip("./").lower()


def _location(value: Mapping[str, Any]) -> dict[str, Any] | None:
    try:
        file_name = str(value["file"])
        line = int(value["line"])
    except (KeyError, TypeError, ValueError):
        return None
    return {"file": file_name, "line": line} if file_name and line > 0 else None


def _physical_location(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    physical = value.get("physicalLocation")
    if not isinstance(physical, Mapping):
        return None
    artifact, region = physical.get("artifactLocation"), physical.get("region")
    if not isinstance(artifact, Mapping) or not isinstance(region, Mapping):
        return None
    return _location({"file": artifact.get("uri"), "line": region.get("startLine")})


def _thread_flow_locations(result: Mapping[str, Any]) -> list[list[dict[str, Any]]]:
    flows: list[list[dict[str, Any]]] = []
    for code_flow in result.get("codeFlows", []) or []:
        if not isinstance(code_flow, Mapping):
            continue
        for thread_flow in code_flow.get("threadFlows", []) or []:
            if not isinstance(thread_flow, Mapping):
                continue
            locations: list[dict[str, Any]] = []
            for item in thread_flow.get("locations", []) or []:
                if isinstance(item, Mapping):
                    location = _physical_location(item.get("location"))
                    if location:
                        locations.append(location)
            if len(locations) >= 2:
                flows.append(locations)
    return flows


def _sarif_thread_flows(path: Path) -> list[list[dict[str, Any]]]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CandidatePathRunError(f"invalid connected-path SARIF {path}: {error}") from error
    flows: list[list[dict[str, Any]]] = []
    for run in document.get("runs", []) or []:
        if not isinstance(run, Mapping):
            continue
        for result in run.get("results", []) or []:
            if isinstance(result, Mapping):
                flows.extend(_thread_flow_locations(result))
    return flows


def _decode_csv(text: str, columns: tuple[str, ...]) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for values in csv.reader(text.splitlines()):
        if not values:
            continue
        if len(values) != len(columns):
            raise CandidatePathRunError(
                f"unexpected frontier row width: expected {len(columns)}, got {len(values)}"
            )
        rows.append(dict(zip(columns, values, strict=True)))
    return rows


def _endpoint_index(candidates: Iterable[Mapping[str, Any]]) -> dict[tuple[str, int], list[dict[str, Any]]]:
    index: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for candidate in candidates:
        evidence = candidate.get("evidence")
        if not isinstance(evidence, list) or not evidence or not isinstance(evidence[0], Mapping):
            raise CandidatePathRunError(f"candidate {candidate.get('candidate_id')} has no usable evidence")
        location = _location(evidence[0])
        if not location:
            raise CandidatePathRunError(f"candidate {candidate.get('candidate_id')} has invalid evidence")
        index[(_normalise_path(location["file"]), location["line"])].append(dict(candidate))
    for rows in index.values():
        rows.sort(key=lambda row: str(row["candidate_id"]))
    return index


def _unique_match(index: Mapping[tuple[str, int], list[dict[str, Any]]], location: Mapping[str, Any]) -> dict[str, Any] | None:
    key = (_normalise_path(str(location["file"])), int(location["line"]))
    matches = index.get(key, [])
    return dict(matches[0]) if len(matches) == 1 else None


def _codeql_node(location: Mapping[str, Any], index: int) -> dict[str, Any]:
    return {
        "node_id": f"codeql:{index}:{_normalise_path(str(location['file']))}:{int(location['line'])}",
        "entity": f"{location['file']}:{location['line']}",
        "kind": "CODEQL_PATH_NODE",
        "location": {"file": str(location["file"]), "line": int(location["line"])},
    }


def connected_paths_from_sarif(
    *,
    project_id: str,
    sarif_file: str | Path,
    inputs: Iterable[Mapping[str, Any]],
    effects: Iterable[Mapping[str, Any]],
    detector_commit: str,
) -> tuple[list[dict[str, Any]], int]:
    """Map CodeQL-proven flow paths to immutable, existing endpoint IDs."""

    input_index, effect_index = _endpoint_index(inputs), _endpoint_index(effects)
    paths: list[dict[str, Any]] = []
    unmapped = 0
    for flow_index, locations in enumerate(_sarif_thread_flows(Path(sarif_file))):
        input_candidate = _unique_match(input_index, locations[0])
        effect_candidate = _unique_match(effect_index, locations[-1])
        if input_candidate is None or effect_candidate is None:
            unmapped += 1
            continue
        nodes = [_codeql_node(location, index) for index, location in enumerate(locations[1:-1], start=1)]
        all_node_ids = [f"input:{input_candidate['candidate_id']}", *[node["node_id"] for node in nodes], f"effect:{effect_candidate['candidate_id']}"]
        edges = [
            {
                "from_node_id": all_node_ids[index],
                "to_node_id": all_node_ids[index + 1],
                "mechanism": "DATA",
                "evidence": {"kind": "CODEQL_INTERPROCEDURAL_DATAFLOW"},
            }
            for index in range(len(all_node_ids) - 1)
        ]
        try:
            paths.append(
                build_candidate_path(
                    project_id=project_id,
                    input_candidate=input_candidate,
                    effect_candidate=effect_candidate,
                    intermediate_nodes=nodes,
                    edges=edges,
                    path_status="COMPLETE_STATIC",
                    detector_commit=detector_commit,
                    provenance={
                        "query": "candidate_path/DataCallConnected.ql",
                        "analysis_mode": "CODEQL_INTERPROCEDURAL_DATAFLOW",
                    },
                )
            )
        except CandidatePathError as error:
            raise CandidatePathRunError(str(error)) from error
    return paths, unmapped


def frontier_paths_from_rows(
    *,
    project_id: str,
    rows: Iterable[Mapping[str, str]],
    inputs: Iterable[Mapping[str, Any]],
    effects: Iterable[Mapping[str, Any]],
    detector_commit: str,
) -> tuple[list[dict[str, Any]], int]:
    input_index, effect_index = _endpoint_index(inputs), _endpoint_index(effects)
    paths: list[dict[str, Any]] = []
    unmapped = 0
    for row_index, row in enumerate(rows):
        input_location = {"file": row["source_file"], "line": int(row["source_line"])}
        effect_location = {"file": row["effect_file"], "line": int(row["effect_line"])}
        input_candidate = _unique_match(input_index, input_location)
        effect_candidate = _unique_match(effect_index, effect_location)
        if input_candidate is None or effect_candidate is None:
            unmapped += 1
            continue
        call_node = _codeql_node({"file": row["call_file"], "line": int(row["call_line"])}, row_index)
        edges = [
            {"from_node_id": f"input:{input_candidate['candidate_id']}", "to_node_id": call_node["node_id"], "mechanism": "CALL", "evidence": {"kind": "DIRECT_CALL_FRONTIER"}},
            {"from_node_id": call_node["node_id"], "to_node_id": f"effect:{effect_candidate['candidate_id']}", "mechanism": "CALL", "evidence": {"kind": "CALLEE_EFFECT_FRONTIER"}},
        ]
        try:
            paths.append(
                build_candidate_path(
                    project_id=project_id,
                    input_candidate=input_candidate,
                    effect_candidate=effect_candidate,
                    intermediate_nodes=[call_node],
                    edges=edges,
                    path_status="FRONTIER_GAP",
                    frontier_nodes=[call_node],
                    frontier_reason=row["frontier_reason"],
                    unresolved_relations=[{"relation_type": "DATA_CALL_FRONTIER", "location": call_node["location"]}],
                    detector_commit=detector_commit,
                    provenance={"query": "candidate_path/DataCallFrontier.ql", "analysis_mode": "DIRECT_CALL_FRONTIER"},
                )
            )
        except (CandidatePathError, KeyError, ValueError) as error:
            raise CandidatePathRunError(str(error)) from error
    return paths, unmapped


def _run_connected_query(*, codeql: str, database: Path, query: Path, output: Path, log: Path, threads: int, ram_mb: int | None) -> float:
    command = [codeql, "database", "analyze", str(database), str(query), "--format=sarif-latest", f"--output={output}", f"--threads={threads}"]
    if ram_mb is not None:
        command.append(f"--ram={ram_mb}")
    started = time.monotonic()
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    log.write_text(completed.stdout or "", encoding="utf-8")
    if completed.returncode != 0:
        raise CandidatePathRunError(f"connected query failed with exit code {completed.returncode}")
    if not output.is_file():
        raise CandidatePathRunError("connected query did not create SARIF")
    return time.monotonic() - started


def _run_frontier_query(*, codeql: str, database: Path, query: Path, output: Path, log: Path, threads: int, ram_mb: int | None) -> tuple[list[dict[str, str]], float]:
    command = [codeql, "query", "run", str(query), f"--database={database}", f"--output={output}", f"--threads={threads}"]
    if ram_mb is not None:
        command.append(f"--ram={ram_mb}")
    started = time.monotonic()
    completed = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    log.write_text(completed.stdout or "", encoding="utf-8")
    if completed.returncode != 0:
        raise CandidatePathRunError(f"frontier query failed with exit code {completed.returncode}")
    decoded = subprocess.run([codeql, "bqrs", "decode", "--format=csv", "--no-titles", str(output)], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if decoded.returncode != 0:
        raise CandidatePathRunError(f"frontier BQRS decode failed with exit code {decoded.returncode}")
    return _decode_csv(decoded.stdout, FRONTIER_COLUMNS), time.monotonic() - started


def _deduplicate(paths: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_id = {str(path["candidate_path_id"]): dict(path) for path in paths}
    return [by_id[path_id] for path_id in sorted(by_id)]


def run_w1_e1_paths(*, detector_manifest: str | Path, endpoint_output_dir: str | Path, query_root: str | Path, output_root: str | Path, threads: int = 0, ram_mb: int | None = None, codeql_executable: str = "codeql") -> dict[str, Any]:
    """Run the frozen W1-E1 detector without reading evaluator or ground truth data."""
    projects = load_detector_manifest(detector_manifest)
    codeql = shutil.which(codeql_executable)
    if codeql is None:
        raise CandidatePathRunError("CodeQL executable is unavailable")
    endpoint_root, query_path, output = Path(endpoint_output_dir), Path(query_root), Path(output_root)
    try:
        external = read_jsonl(endpoint_root / "external_inputs.jsonl")
        effects = read_jsonl(endpoint_root / "security_effects.jsonl")
    except (OSError, ValueError) as error:
        raise CandidatePathRunError(f"invalid endpoint output: {error}") from error
    connected_query = query_path / "candidate_path" / "DataCallConnected.ql"
    frontier_query = query_path / "candidate_path" / "DataCallFrontier.ql"
    if not connected_query.is_file() or not frontier_query.is_file():
        raise CandidatePathRunError("missing W1-E1 CodeQL query")
    detector_commit, _ = git_metadata(query_path.parent)
    bqrs_dir, logs_dir = output / "bqrs", output / "logs"
    bqrs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    all_paths: list[dict[str, Any]] = []
    statuses: list[dict[str, Any]] = []
    total_query_time = 0.0
    for project in projects:
        project_id, database = project["project"], Path(project["codeql_db_path"])
        project_inputs = [row for row in external if row.get("evidence", [{}])[0].get("project") == project_id]
        project_effects = [row for row in effects if row.get("evidence", [{}])[0].get("project") == project_id]
        status: dict[str, Any] = {"project_id": project_id, "revision": project["revision"], "external_input_candidates": len(project_inputs), "security_effect_candidates": len(project_effects)}
        started = time.monotonic()
        if not database.is_dir():
            status.update(status="FAILED", stage="DATABASE_PRECHECK", error_class="DATABASE_UNAVAILABLE")
        elif not project_inputs or not project_effects:
            status.update(status="SUCCESS", static_connected_paths=0, frontier_candidate_paths=0, unmapped_query_results=0, stage="NO_ANCHOR_PAIR")
        else:
            try:
                connected_sarif = bqrs_dir / f"{project_id}.connected.sarif"
                total_query_time += _run_connected_query(codeql=codeql, database=database, query=connected_query, output=connected_sarif, log=logs_dir / f"{project_id}.connected.codeql.log", threads=threads, ram_mb=ram_mb)
                connected, unmapped_connected = connected_paths_from_sarif(project_id=project_id, sarif_file=connected_sarif, inputs=project_inputs, effects=project_effects, detector_commit=detector_commit)
                frontier_bqrs = bqrs_dir / f"{project_id}.frontier.bqrs"
                frontier_rows, frontier_time = _run_frontier_query(codeql=codeql, database=database, query=frontier_query, output=frontier_bqrs, log=logs_dir / f"{project_id}.frontier.codeql.log", threads=threads, ram_mb=ram_mb)
                total_query_time += frontier_time
                frontier, unmapped_frontier = frontier_paths_from_rows(project_id=project_id, rows=frontier_rows, inputs=project_inputs, effects=project_effects, detector_commit=detector_commit)
            except CandidatePathRunError as error:
                status.update(status="FAILED", stage="CODEQL_QUERY", error_class="QUERY_FAILURE", detail=str(error))
            else:
                project_paths = _deduplicate([*connected, *frontier])
                all_paths.extend(project_paths)
                status.update(status="SUCCESS", static_connected_paths=sum(1 for row in project_paths if row["path_status"] == "COMPLETE_STATIC"), frontier_candidate_paths=sum(1 for row in project_paths if row["path_status"] == "FRONTIER_GAP"), unmapped_query_results=unmapped_connected + unmapped_frontier)
        status["runtime_seconds"] = round(time.monotonic() - started, 3)
        statuses.append(status)
    all_paths = _deduplicate(all_paths)
    write_jsonl(output / "endpoint_candidates.jsonl", sorted([*external, *effects], key=lambda row: str(row["candidate_id"])))
    write_jsonl(output / "candidate_paths.jsonl", all_paths)
    write_jsonl(output / "frontier_cases.jsonl", [row for row in all_paths if row["path_status"] == "FRONTIER_GAP"])
    write_jsonl(output / "project_status.jsonl", statuses)
    successes = sum(1 for row in statuses if row["status"] == "SUCCESS")
    per_project = {row["project_id"]: row.get("static_connected_paths", 0) + row.get("frontier_candidate_paths", 0) for row in statuses if row["status"] == "SUCCESS"}
    summary = {"status": "SUCCESS" if successes == len(statuses) and statuses else "PARTIAL" if successes else "FAILED", "projects_total": len(statuses), "projects_runnable": successes, "external_input_candidates": len(external), "security_effect_candidates": len(effects), "candidate_paths_total": len(all_paths), "static_connected_paths": sum(1 for row in all_paths if row["path_status"] == "COMPLETE_STATIC"), "frontier_candidate_paths": sum(1 for row in all_paths if row["path_status"] == "FRONTIER_GAP"), "candidate_paths_per_project": per_project, "codeql_query_time": round(total_query_time, 3), "error_count": len(statuses) - successes, "unknown_count": sum(int(row.get("unmapped_query_results", 0)) for row in statuses)}
    write_json(output / "metrics.json", summary)
    return summary
