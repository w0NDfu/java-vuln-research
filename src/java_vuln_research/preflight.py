from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .common.io import load_yaml
from .common.provenance import git_metadata, machine_summary, tool_versions, utc_now


class PreflightError(RuntimeError):
    """Raised when an official Cloud run must be aborted."""


def _git_status(project_root: Path) -> str:
    completed = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=normal"],
        cwd=project_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode != 0:
        raise PreflightError(f"git status failed: {completed.stderr.strip()}")
    return completed.stdout.strip()


def run_preflight(
    *,
    project_root: str | Path,
    paths_config: str | Path,
    environment_output: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(project_root).resolve()
    paths = load_yaml(paths_config)
    if not isinstance(paths, dict):
        raise PreflightError("cloud paths config must be a mapping")

    dirty = _git_status(root)
    if dirty:
        raise PreflightError(
            "tracked or untracked research files make the source tree dirty; "
            "official experiment ABORTED:\n" + dirty
        )

    required_path_keys = ("project_root", "dataset_root", "codeql_db_root", "experiment_output_root")
    missing_values = [key for key in required_path_keys if not paths.get(key)]
    if missing_values:
        raise PreflightError(
            "cloud path config has unresolved values: " + ", ".join(missing_values)
        )

    configured_root = Path(str(paths["project_root"])).resolve()
    if configured_root != root:
        raise PreflightError(
            f"project_root mismatch: configured={configured_root}, actual={root}"
        )
    for key in ("dataset_root", "codeql_db_root"):
        if not Path(str(paths[key])).is_dir():
            raise PreflightError(f"{key} does not exist or is not a directory: {paths[key]}")

    if shutil.which("codeql") is None:
        raise PreflightError("CodeQL executable is unavailable")

    commit, branch = git_metadata(root)
    if commit == "UNBORN":
        raise PreflightError("official experiment requires a committed HEAD")
    result: dict[str, Any] = {
        "status": "PASS",
        "timestamp": utc_now(),
        "git_commit": commit,
        "git_branch": branch,
        **tool_versions(),
        **machine_summary(root),
        "paths": paths,
    }
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if environment_output:
        output_path = Path(environment_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    return result

