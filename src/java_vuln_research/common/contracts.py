from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from .io import load_yaml


DETECTOR_PROJECT_FIELDS = frozenset(
    {"project", "revision", "source_path", "codeql_db_path"}
)

FORBIDDEN_GROUND_TRUTH_KEYS = frozenset(
    {
        "cve",
        "cve_id",
        "cve_description",
        "cwe",
        "cwe_id",
        "fix",
        "fix_commit",
        "fix_info",
        "fix_patch",
        "ground_truth",
        "source_annotation",
        "sink_annotation",
        "vulnerable_file",
        "vulnerable_function",
        "vulnerable_line",
        "vulnerable_location",
    }
)


class DetectorManifestError(ValueError):
    """Raised when detector input violates the non-leakage contract."""


def _walk_keys(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key).lower()
            yield from _walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_keys(child)


def validate_detector_manifest(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict):
        raise DetectorManifestError("detector manifest must be a mapping")

    forbidden = sorted(set(_walk_keys(value)) & FORBIDDEN_GROUND_TRUTH_KEYS)
    if forbidden:
        raise DetectorManifestError(
            "ground-truth fields are forbidden in detector input: "
            + ", ".join(forbidden)
        )

    allowed_top_level = {"schema_version", "projects"}
    unexpected_top_level = set(value) - allowed_top_level
    if unexpected_top_level:
        raise DetectorManifestError(
            "unexpected top-level detector fields: "
            + ", ".join(sorted(unexpected_top_level))
        )

    projects = value.get("projects")
    if not isinstance(projects, list):
        raise DetectorManifestError("detector manifest projects must be a list")

    validated: list[dict[str, Any]] = []
    seen_projects: set[str] = set()
    for index, project in enumerate(projects):
        if not isinstance(project, dict):
            raise DetectorManifestError(f"projects[{index}] must be a mapping")
        fields = set(project)
        missing = DETECTOR_PROJECT_FIELDS - fields
        extra = fields - DETECTOR_PROJECT_FIELDS
        if missing or extra:
            details: list[str] = []
            if missing:
                details.append("missing=" + ",".join(sorted(missing)))
            if extra:
                details.append("extra=" + ",".join(sorted(extra)))
            raise DetectorManifestError(
                f"projects[{index}] violates detector field contract ({'; '.join(details)})"
            )
        if not all(isinstance(project[name], str) and project[name] for name in fields):
            raise DetectorManifestError(
                f"projects[{index}] fields must be non-empty strings"
            )
        if project["project"] in seen_projects:
            raise DetectorManifestError(
                f"duplicate detector project: {project['project']}"
            )
        seen_projects.add(project["project"])
        validated.append(dict(project))
    return validated


def load_detector_manifest(path: str | Path) -> list[dict[str, Any]]:
    return validate_detector_manifest(load_yaml(path))

