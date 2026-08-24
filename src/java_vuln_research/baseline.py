from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from .common.contracts import load_detector_manifest


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "project"


def summarize_sarif(path: str | Path) -> tuple[int, int]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    alert_count = 0
    path_count = 0
    for run in value.get("runs", []):
        for result in run.get("results", []) or []:
            alert_count += 1
            code_flows = result.get("codeFlows") or []
            path_count += len(code_flows)
    return alert_count, path_count


def run_frozen_baseline(
    *,
    detector_manifest: str | Path,
    output_root: str | Path,
    query_suite: str,
    threads: int = 0,
    ram_mb: int | None = None,
    codeql_executable: str = "codeql",
) -> list[dict[str, Any]]:
    projects = load_detector_manifest(detector_manifest)
    output_path = Path(output_root)
    baseline_dir = output_path / "baseline"
    logs_dir = output_path / "logs"
    baseline_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)
    detector_output = baseline_dir / "baseline_output.jsonl"

    codeql_path = shutil.which(codeql_executable)
    rows: list[dict[str, Any]] = []
    with detector_output.open("w", encoding="utf-8", newline="\n") as handle:
        for project in projects:
            started = time.monotonic()
            project_name = project["project"]
            safe_name = _safe_name(project_name)
            database = Path(project["codeql_db_path"])
            sarif_path = baseline_dir / f"{safe_name}.sarif"
            log_path = logs_dir / f"{safe_name}.codeql.log"

            if codeql_path is None:
                row: dict[str, Any] = {
                    "project": project_name,
                    "revision": project["revision"],
                    "status": "FAILED",
                    "stage": "PREFLIGHT",
                    "exit_code": None,
                    "error_class": "CODEQL_UNAVAILABLE",
                    "runtime_seconds": round(time.monotonic() - started, 3),
                }
            elif not database.is_dir():
                row = {
                    "project": project_name,
                    "revision": project["revision"],
                    "status": "FAILED",
                    "stage": "DATABASE_PRECHECK",
                    "exit_code": None,
                    "error_class": "DATABASE_UNAVAILABLE",
                    "runtime_seconds": round(time.monotonic() - started, 3),
                }
            else:
                command = [
                    codeql_path,
                    "database",
                    "analyze",
                    str(database),
                    query_suite,
                    "--format=sarif-latest",
                    f"--output={sarif_path}",
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
                log_path.write_text(completed.stdout or "", encoding="utf-8")
                if completed.returncode != 0:
                    row = {
                        "project": project_name,
                        "revision": project["revision"],
                        "status": "FAILED",
                        "stage": "CODEQL_ANALYZE",
                        "exit_code": completed.returncode,
                        "error_class": "QUERY_FAILURE",
                        "runtime_seconds": round(time.monotonic() - started, 3),
                    }
                elif not sarif_path.is_file():
                    row = {
                        "project": project_name,
                        "revision": project["revision"],
                        "status": "FAILED",
                        "stage": "OUTPUT_VALIDATION",
                        "exit_code": completed.returncode,
                        "error_class": "SARIF_MISSING",
                        "runtime_seconds": round(time.monotonic() - started, 3),
                    }
                else:
                    try:
                        alert_count, path_count = summarize_sarif(sarif_path)
                    except (OSError, UnicodeError, json.JSONDecodeError, TypeError):
                        row = {
                            "project": project_name,
                            "revision": project["revision"],
                            "status": "FAILED",
                            "stage": "OUTPUT_VALIDATION",
                            "exit_code": completed.returncode,
                            "error_class": "SARIF_INVALID",
                            "runtime_seconds": round(time.monotonic() - started, 3),
                        }
                    else:
                        row = {
                            "project": project_name,
                            "revision": project["revision"],
                            "status": "SUCCESS",
                            "exit_code": completed.returncode,
                            "alert_count": alert_count,
                            "path_count": path_count,
                            "runtime_seconds": round(time.monotonic() - started, 3),
                        }
            rows.append(row)
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
            handle.flush()
    return rows

