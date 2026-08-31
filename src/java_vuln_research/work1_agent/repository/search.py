from __future__ import annotations

import fnmatch
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

from .entity import ProgramEntity, ProgramEntityKind
from .indexer import RepositoryIndex


DEFAULT_MAX_HITS = 30
ABSOLUTE_MAX_HITS = 100
MAX_QUERY_LENGTH = 512
MAX_SNIPPET_LENGTH = 500


def _query(value: str) -> str:
    resolved = str(value)
    if not resolved or not resolved.strip():
        raise ValueError("query must be non-empty")
    if len(resolved) > MAX_QUERY_LENGTH:
        raise ValueError(f"query exceeds {MAX_QUERY_LENGTH} characters")
    return resolved


def _limit(value: int) -> int:
    try:
        resolved = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("max_hits must be an integer") from error
    if resolved < 1 or resolved > ABSOLUTE_MAX_HITS:
        raise ValueError(f"max_hits must be between 1 and {ABSOLUTE_MAX_HITS}")
    return resolved


def _base_entity_ref(entity: ProgramEntity) -> dict[str, Any]:
    return {
        "entity_id": entity.entity_id,
        "kind": entity.kind.value,
        "simple_name": entity.simple_name,
        "qualified_name": entity.qualified_name,
        "signature": entity.signature,
        "repository_relative_path": entity.repository_relative_path,
        "start_line": entity.start_line,
        "end_line": entity.end_line,
        "enclosing_type": entity.enclosing_type,
        "enclosing_callable": entity.enclosing_callable,
    }


def _callable_identity(entity: ProgramEntity) -> str:
    if entity.signature and entity.signature.startswith(entity.simple_name):
        return entity.qualified_name + entity.signature[len(entity.simple_name) :]
    return entity.qualified_name


def _owning_callable(index: RepositoryIndex, entity: ProgramEntity) -> ProgramEntity | None:
    identity = entity.enclosing_callable
    if not identity:
        return None
    candidates = [
        item
        for item in index.entities
        if item.kind in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}
        and item.repository_relative_path == entity.repository_relative_path
        and item.start_line <= entity.start_line <= item.end_line
        and _callable_identity(item) == identity
    ]
    if not candidates:
        return None
    return min(candidates, key=lambda item: (item.end_line - item.start_line, item.entity_id))


def _entity_ref(index: RepositoryIndex, entity: ProgramEntity) -> dict[str, Any]:
    value = _base_entity_ref(entity)
    owner = _owning_callable(index, entity)
    if owner is not None:
        value["owner_callable"] = _base_entity_ref(owner)
    return value


def _nearest_entity(entities: Iterable[ProgramEntity], line: int) -> ProgramEntity | None:
    containing = [
        item
        for item in entities
        if item.start_line <= line <= item.end_line
        and item.kind not in {ProgramEntityKind.FILE, ProgramEntityKind.PACKAGE}
    ]
    if containing:
        return min(
            containing,
            key=lambda item: (
                item.end_line - item.start_line,
                0 if item.kind in {ProgramEntityKind.CALL, ProgramEntityKind.ANNOTATION} else 1,
                item.entity_id,
            ),
        )
    return next((item for item in entities if item.kind == ProgramEntityKind.FILE), None)


def _snippet(text: str) -> str:
    value = text.strip()
    return value if len(value) <= MAX_SNIPPET_LENGTH else value[: MAX_SNIPPET_LENGTH - 1] + "…"


def search_code(
    index: RepositoryIndex,
    query: str,
    *,
    file_glob: str | None = None,
    max_hits: int = DEFAULT_MAX_HITS,
    case_sensitive: bool = False,
) -> list[dict[str, Any]]:
    """Search repository text and return bounded neutral program facts."""

    needle = _query(query)
    limit = _limit(max_hits)
    compared_needle = needle if case_sensitive else needle.casefold()
    by_file: dict[str, list[ProgramEntity]] = defaultdict(list)
    for entity in index.entities:
        by_file[entity.repository_relative_path].append(entity)
    results: list[dict[str, Any]] = []
    for relative_path in sorted(by_file):
        if file_glob and not fnmatch.fnmatch(relative_path, file_glob):
            continue
        source = index.repository_root / Path(*relative_path.split("/"))
        try:
            lines = source.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for line_number, line in enumerate(lines, start=1):
            compared_line = line if case_sensitive else line.casefold()
            start = 0
            while True:
                column = compared_line.find(compared_needle, start)
                if column < 0:
                    break
                entity = _nearest_entity(by_file[relative_path], line_number)
                results.append(
                    {
                        "entity": _entity_ref(index, entity) if entity else None,
                        "location": {
                            "repository_relative_path": relative_path,
                            "line": line_number,
                            "column": column + 1,
                        },
                        "snippet": _snippet(line),
                        "kind": entity.kind.value if entity else "TEXT_MATCH",
                        "query": needle,
                        "provenance": {
                            "kind": "NEUTRAL_REPOSITORY_TEXT_SEARCH",
                            "case_sensitive": bool(case_sensitive),
                            "file_glob": file_glob,
                        },
                    }
                )
                if len(results) >= limit:
                    return results
                start = column + max(1, len(compared_needle))
    return results


def search_symbols(
    index: RepositoryIndex,
    query: str,
    *,
    kind: ProgramEntityKind | str | None = None,
    max_hits: int = DEFAULT_MAX_HITS,
    case_sensitive: bool = False,
) -> list[dict[str, Any]]:
    """Search indexed names/signatures without assigning security meaning."""

    needle = _query(query)
    limit = _limit(max_hits)
    resolved_kind = ProgramEntityKind(kind) if kind is not None else None
    compared_needle = needle if case_sensitive else needle.casefold()
    results: list[dict[str, Any]] = []
    for entity in index.sorted_entities():
        if resolved_kind is not None and entity.kind != resolved_kind:
            continue
        haystack = "\n".join(
            value
            for value in (entity.simple_name, entity.qualified_name, entity.signature)
            if value
        )
        compared_haystack = haystack if case_sensitive else haystack.casefold()
        if compared_needle not in compared_haystack:
            continue
        source = index.repository_root / Path(*entity.repository_relative_path.split("/"))
        try:
            line = source.read_text(encoding="utf-8").splitlines()[entity.start_line - 1]
        except (OSError, UnicodeDecodeError, IndexError):
            line = ""
        results.append(
            {
                "entity": _entity_ref(index, entity),
                "location": {
                    "repository_relative_path": entity.repository_relative_path,
                    "line": entity.start_line,
                    "column": None,
                },
                "snippet": _snippet(line),
                "kind": entity.kind.value,
                "query": needle,
                "provenance": {
                    "kind": "NEUTRAL_REPOSITORY_SYMBOL_SEARCH",
                    "case_sensitive": bool(case_sensitive),
                    "symbol_kind_filter": resolved_kind.value if resolved_kind else None,
                },
            }
        )
        if len(results) >= limit:
            break
    return results
