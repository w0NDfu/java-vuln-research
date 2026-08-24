from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .io import write_json
from .provenance import git_metadata, sha256_paths, tool_versions, utc_now


@dataclass
class RunManifest:
    run_id: str
    experiment: str
    project_root: Path
    dataset_name: str
    dataset_revision: str
    config_paths: list[Path]
    semantic_rule_paths: list[Path]
    prompt_paths: list[Path]
    model_id: str | None = None
    temperature: float | None = None
    top_p: float | None = None
    random_seed: int | None = None
    timestamp_start: str = field(default_factory=utc_now)
    _monotonic_start: float = field(default_factory=time.monotonic, repr=False)

    def finish(
        self,
        output_path: str | Path,
        *,
        projects_requested: int,
        projects_runnable: int,
        projects_build_failed: int | str,
        status: str,
    ) -> dict[str, Any]:
        git_commit, git_branch = git_metadata(self.project_root)
        versions = tool_versions()
        value: dict[str, Any] = {
            "run_id": self.run_id,
            "experiment": self.experiment,
            "timestamp_start": self.timestamp_start,
            "timestamp_end": utc_now(),
            "git_commit": git_commit,
            "git_branch": git_branch,
            **versions,
            "dataset_name": self.dataset_name,
            "dataset_revision": self.dataset_revision,
            "config_hash": sha256_paths(self.config_paths, self.project_root),
            "semantic_rule_hash": sha256_paths(
                self.semantic_rule_paths, self.project_root
            ),
            "prompt_hash": sha256_paths(self.prompt_paths, self.project_root),
            "model_id": self.model_id,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "random_seed": self.random_seed,
            "projects_requested": projects_requested,
            "projects_runnable": projects_runnable,
            "projects_build_failed": projects_build_failed,
            "wall_clock_seconds": round(time.monotonic() - self._monotonic_start, 3),
            "status": status,
        }
        write_json(output_path, value)
        return value
