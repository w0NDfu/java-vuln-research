from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_paths(paths: Iterable[str | Path], root: str | Path | None = None) -> str:
    root_path = Path(root).resolve() if root else None
    files: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            continue
        if path.is_file():
            files.append(path)
        else:
            files.extend(candidate for candidate in path.rglob("*") if candidate.is_file())

    digest = hashlib.sha256()
    for path in sorted(files, key=lambda item: item.as_posix()):
        resolved = path.resolve()
        try:
            name = resolved.relative_to(root_path).as_posix() if root_path else resolved.as_posix()
        except ValueError:
            name = resolved.as_posix()
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(sha256_file(resolved).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def run_text(command: list[str], cwd: str | Path | None = None) -> str | None:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=30,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return None
    output = completed.stdout.strip()
    return output if output else None


def first_line(value: str | None) -> str | None:
    return value.splitlines()[0].strip() if value else None


def git_metadata(project_root: str | Path) -> tuple[str, str]:
    commit = run_text(["git", "rev-parse", "HEAD"], cwd=project_root)
    branch = run_text(["git", "branch", "--show-current"], cwd=project_root)
    return commit or "UNBORN", branch or "DETACHED_OR_UNBORN"


def tool_versions() -> dict[str, str | None]:
    return {
        "codeql_version": first_line(run_text(["codeql", "version"])),
        "java_version": first_line(run_text(["java", "-version"])),
        "maven_version": first_line(run_text(["mvn", "-version"])),
        "gradle_version": first_line(run_text(["gradle", "--version"])),
        "python_version": platform.python_version(),
    }


def machine_summary(path: str | Path) -> dict[str, object]:
    disk = shutil.disk_usage(Path(path))
    summary: dict[str, object] = {
        "platform": platform.platform(),
        "cpu_count": os.cpu_count(),
        "disk_total_bytes": disk.total,
        "disk_free_bytes": disk.free,
    }
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        for line in meminfo.read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                summary["memory_total_kib"] = int(line.split()[1])
                break
    return summary

