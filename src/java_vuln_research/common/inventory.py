from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterable

from .io import YamlSubsetError, load_yaml, write_csv


DATASET_FIELDS = [
    "dataset",
    "path",
    "exists",
    "kind",
    "revision_hint",
    "project_count_hint",
]

CODEQL_DB_FIELDS = [
    "project",
    "path",
    "exists",
    "db_ready",
    "language",
    "source_location",
    "size",
    "build_status_if_known",
]


def _is_within_depth(path: Path, root: Path, max_depth: int) -> bool:
    try:
        return len(path.relative_to(root).parts) <= max_depth
    except ValueError:
        return False


def _walk_directories(root: Path, max_depth: int) -> Iterable[Path]:
    for current, directories, _files in os.walk(root, followlinks=False):
        current_path = Path(current)
        relative_depth = len(current_path.relative_to(root).parts)
        if relative_depth >= max_depth:
            directories[:] = []
        yield current_path


def inventory_datasets(root: str | Path, output_csv: str | Path) -> list[dict[str, Any]]:
    root_path = Path(root).expanduser().resolve()
    rows: list[dict[str, Any]] = []
    if not root_path.exists():
        rows.append(
            {
                "dataset": root_path.name or "UNKNOWN",
                "path": str(root_path),
                "exists": False,
                "kind": "MISSING_ROOT",
                "revision_hint": "UNKNOWN",
                "project_count_hint": "UNKNOWN",
            }
        )
        write_csv(output_csv, DATASET_FIELDS, rows)
        return rows

    seen: set[Path] = set()
    for directory in _walk_directories(root_path, max_depth=5):
        lowered = directory.name.lower()
        marker_names = {child.name for child in directory.iterdir() if child.is_file()}
        is_named_dataset = "iris" in lowered or ("cwe" in lowered and "bench" in lowered)
        is_java_project = bool(
            marker_names
            & {"pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle"}
        )
        if not (is_named_dataset or is_java_project):
            continue
        candidate = directory if is_named_dataset else directory.parent
        if candidate in seen or not _is_within_depth(candidate, root_path, 5):
            continue
        seen.add(candidate)
        git_head = candidate / ".git" / "HEAD"
        revision_hint = (
            git_head.read_text(encoding="utf-8", errors="replace").strip()
            if git_head.is_file()
            else "UNKNOWN"
        )
        project_count = sum(
            1
            for child in candidate.iterdir()
            if child.is_dir()
            and any(
                (child / marker).exists()
                for marker in ("pom.xml", "build.gradle", "build.gradle.kts")
            )
        )
        rows.append(
            {
                "dataset": candidate.name,
                "path": str(candidate),
                "exists": True,
                "kind": "NAMED_DATASET" if is_named_dataset else "JAVA_PROJECT_COLLECTION",
                "revision_hint": revision_hint,
                "project_count_hint": project_count or "UNKNOWN",
            }
        )

    if not rows:
        rows.append(
            {
                "dataset": root_path.name,
                "path": str(root_path),
                "exists": True,
                "kind": "ROOT_NO_RECOGNIZED_DATASET",
                "revision_hint": "UNKNOWN",
                "project_count_hint": "UNKNOWN",
            }
        )
    rows.sort(key=lambda row: str(row["path"]))
    write_csv(output_csv, DATASET_FIELDS, rows)
    return rows


def _directory_size(path: Path) -> int:
    total = 0
    for current, _directories, files in os.walk(path, followlinks=False):
        for file_name in files:
            file_path = Path(current) / file_name
            try:
                total += file_path.stat().st_size
            except OSError:
                continue
    return total


def _read_codeql_metadata(metadata_path: Path) -> dict[str, Any]:
    try:
        value = load_yaml(metadata_path) or {}
    except (OSError, YamlSubsetError, UnicodeError):
        return {}
    return value if isinstance(value, dict) else {}


def inventory_codeql_databases(
    root: str | Path, output_csv: str | Path
) -> list[dict[str, Any]]:
    root_path = Path(root).expanduser().resolve()
    rows: list[dict[str, Any]] = []
    if not root_path.exists():
        rows.append(
            {
                "project": root_path.name or "UNKNOWN",
                "path": str(root_path),
                "exists": False,
                "db_ready": False,
                "language": "UNKNOWN",
                "source_location": "UNKNOWN",
                "size": 0,
                "build_status_if_known": "UNKNOWN",
            }
        )
        write_csv(output_csv, CODEQL_DB_FIELDS, rows)
        return rows

    metadata_files: list[Path] = []
    for current, directories, files in os.walk(root_path, followlinks=False):
        current_path = Path(current)
        depth = len(current_path.relative_to(root_path).parts)
        if depth >= 6:
            directories[:] = []
        if "codeql-database.yml" in files:
            metadata_files.append(current_path / "codeql-database.yml")
            directories[:] = []

    for metadata_file in metadata_files:
        database = metadata_file.parent
        metadata = _read_codeql_metadata(metadata_file)
        language = str(
            metadata.get("primaryLanguage")
            or metadata.get("language")
            or ("java" if (database / "db-java").exists() else "UNKNOWN")
        )
        source_location = str(
            metadata.get("sourceLocationPrefix")
            or metadata.get("sourceLocation")
            or "UNKNOWN"
        )
        db_ready = (database / "db-java").is_dir() and metadata_file.is_file()
        rows.append(
            {
                "project": database.name,
                "path": str(database),
                "exists": True,
                "db_ready": db_ready,
                "language": language,
                "source_location": source_location,
                "size": _directory_size(database),
                "build_status_if_known": "SUCCESS" if db_ready else "INCOMPLETE",
            }
        )

    if not rows:
        rows.append(
            {
                "project": root_path.name,
                "path": str(root_path),
                "exists": True,
                "db_ready": False,
                "language": "UNKNOWN",
                "source_location": "UNKNOWN",
                "size": _directory_size(root_path),
                "build_status_if_known": "NO_CODEQL_DATABASE_FOUND",
            }
        )
    rows.sort(key=lambda row: str(row["path"]))
    write_csv(output_csv, CODEQL_DB_FIELDS, rows)
    return rows
