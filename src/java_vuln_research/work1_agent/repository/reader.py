from __future__ import annotations

from pathlib import Path
from typing import Any

from .entity import ProgramEntity, normalise_repository_path


DEFAULT_MAX_LINES = 250
DEFAULT_MAX_BYTES = 64 * 1024
ABSOLUTE_MAX_LINES = 1_000
ABSOLUTE_MAX_BYTES = 1024 * 1024


class SourceReadError(ValueError):
    """Raised when a bounded source read would be unsafe or ambiguous."""

    def __init__(self, error_class: str, message: str) -> None:
        super().__init__(message)
        self.error_class = error_class


def _repository_root(value: str | Path) -> Path:
    root = Path(value).resolve()
    if not root.is_dir():
        raise SourceReadError("REPOSITORY_UNAVAILABLE", f"repository root is not a directory: {root}")
    return root


def _confined_file(root: Path, relative_path: str) -> tuple[Path, str]:
    try:
        normalised = normalise_repository_path(relative_path)
    except ValueError as error:
        raise SourceReadError("PATH_TRAVERSAL", str(error)) from error
    candidate = (root / Path(*normalised.split("/"))).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as error:
        raise SourceReadError("PATH_TRAVERSAL", "source path resolves outside repository root") from error
    if not candidate.is_file():
        raise SourceReadError("FILE_UNAVAILABLE", f"source file does not exist: {normalised}")
    return candidate, normalised


def _bounded_limit(value: int, *, name: str, absolute_maximum: int) -> int:
    try:
        resolved = int(value)
    except (TypeError, ValueError) as error:
        raise SourceReadError("INVALID_LIMIT", f"{name} must be an integer") from error
    if resolved < 1 or resolved > absolute_maximum:
        raise SourceReadError(
            "INVALID_LIMIT",
            f"{name} must be between 1 and {absolute_maximum}",
        )
    return resolved


def read_file_range(
    repository_root: str | Path,
    repository_relative_path: str,
    start_line: int,
    end_line: int,
    *,
    max_lines: int = DEFAULT_MAX_LINES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    """Read one UTF-8 source range with hard path, line, and byte bounds."""

    root = _repository_root(repository_root)
    source, normalised = _confined_file(root, repository_relative_path)
    line_limit = _bounded_limit(max_lines, name="max_lines", absolute_maximum=ABSOLUTE_MAX_LINES)
    byte_limit = _bounded_limit(max_bytes, name="max_bytes", absolute_maximum=ABSOLUTE_MAX_BYTES)
    try:
        first, last = int(start_line), int(end_line)
    except (TypeError, ValueError) as error:
        raise SourceReadError("INVALID_RANGE", "start_line and end_line must be integers") from error
    if first < 1 or last < first:
        raise SourceReadError("INVALID_RANGE", "source range must be positive and ordered")
    requested_count = last - first + 1
    if requested_count > line_limit:
        raise SourceReadError(
            "LINE_LIMIT_EXCEEDED",
            f"requested {requested_count} lines, maximum is {line_limit}",
        )
    raw = source.read_bytes()
    if len(raw) > ABSOLUTE_MAX_BYTES * 64:
        raise SourceReadError("FILE_TOO_LARGE", "source file exceeds the bounded reader file-size ceiling")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SourceReadError("UTF8_DECODE_ERROR", f"source is not valid UTF-8: {normalised}") from error
    lines = decoded.splitlines()
    if first > len(lines) and not (first == 1 and not lines):
        raise SourceReadError(
            "RANGE_OUT_OF_BOUNDS",
            f"start_line {first} exceeds file length {len(lines)}",
        )
    actual_last = min(last, len(lines))
    selected = lines[first - 1 : actual_last]
    encoded_size = sum(len(line.encode("utf-8")) + 1 for line in selected)
    if encoded_size > byte_limit:
        raise SourceReadError(
            "BYTE_LIMIT_EXCEEDED",
            f"selected source uses {encoded_size} bytes, maximum is {byte_limit}",
        )
    numbered = [
        {"line": number, "text": lines[number - 1]}
        for number in range(first, actual_last + 1)
    ]
    return {
        "repository_relative_path": normalised,
        "requested_start_line": first,
        "requested_end_line": last,
        "start_line": first,
        "end_line": actual_last,
        "total_file_lines": len(lines),
        "encoding": "utf-8",
        "truncated": actual_last < last,
        "byte_count": encoded_size,
        "lines": numbered,
        "text": "\n".join(f"{row['line']:>6} | {row['text']}" for row in numbered),
        "provenance": {
            "kind": "BOUNDED_SOURCE_READ",
            "max_lines": line_limit,
            "max_bytes": byte_limit,
        },
    }


def inspect_entity(
    repository_root: str | Path,
    entity: ProgramEntity,
    *,
    context_lines: int = 0,
    max_lines: int = DEFAULT_MAX_LINES,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> dict[str, Any]:
    try:
        context = int(context_lines)
    except (TypeError, ValueError) as error:
        raise SourceReadError("INVALID_RANGE", "context_lines must be an integer") from error
    if context < 0 or context > 100:
        raise SourceReadError("INVALID_RANGE", "context_lines must be between 0 and 100")
    result = read_file_range(
        repository_root,
        entity.repository_relative_path,
        max(1, entity.start_line - context),
        entity.end_line + context,
        max_lines=max_lines,
        max_bytes=max_bytes,
    )
    result["entity"] = entity.to_dict()
    result["provenance"] = {
        **result["provenance"],
        "entity_id": entity.entity_id,
        "context_lines": context,
    }
    return result
