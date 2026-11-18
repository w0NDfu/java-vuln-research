"""Bounded repository-tool facade built on the neutral M1 index."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .entity import ProgramEntity, ProgramEntityKind
from .indexer import RepositoryIndex, build_repository_index
from .reader import inspect_entity, read_file_range
from .search import search_code, search_symbols


@dataclass(slots=True)
class RepositoryTools:
    """Expose bounded, security-neutral repository operations."""

    index: RepositoryIndex

    @classmethod
    def open(cls, repository_root: str | Path) -> "RepositoryTools":
        return cls(build_repository_index(repository_root))

    def _find(self, entity_id: str) -> ProgramEntity:
        for entity in self.index.entities:
            if entity.entity_id == entity_id:
                return entity
        raise ValueError(f"entity not found: {entity_id}")

    def search_code(self, query: str, **kwargs: Any) -> list[dict[str, Any]]:
        return search_code(self.index, query, **kwargs)

    def search_symbols(self, query: str, **kwargs: Any) -> list[dict[str, Any]]:
        return search_symbols(self.index, query, **kwargs)

    def read_file_range(self, repository_relative_path: str, start_line: int, end_line: int, **kwargs: Any) -> dict[str, Any]:
        return read_file_range(self.index.repository_root, repository_relative_path, start_line, end_line, **kwargs)

    def inspect_entity(self, entity_id: str, **kwargs: Any) -> dict[str, Any]:
        return inspect_entity(self.index.repository_root, self._find(entity_id), **kwargs)

    def inspect_method(self, entity_id: str, **kwargs: Any) -> dict[str, Any]:
        entity = self._find(entity_id)
        if entity.kind != ProgramEntityKind.METHOD:
            raise ValueError(f"entity is not a method: {entity_id}")
        return self.inspect_entity(entity_id, **kwargs)

    def inspect_type(self, entity_id: str, **kwargs: Any) -> dict[str, Any]:
        entity = self._find(entity_id)
        if entity.kind != ProgramEntityKind.TYPE:
            raise ValueError(f"entity is not a type: {entity_id}")
        return self.inspect_entity(entity_id, **kwargs)

    def related_entities(self, entity_id: str, relation: str) -> dict[str, Any]:
        """Return an explicit empty result where M1 has no structural relation."""
        self._find(entity_id)
        if relation not in {"callers", "callees", "implementations", "overrides", "fields", "annotations"}:
            raise ValueError(f"unsupported relation: {relation}")
        return {"entity_id": entity_id, "relation": relation, "items": [], "provenance": {"kind": "M1_RELATION_UNAVAILABLE"}}

    def get_callers(self, entity_id: str) -> dict[str, Any]:
        return self.related_entities(entity_id, "callers")

    def get_callees(self, entity_id: str) -> dict[str, Any]:
        return self.related_entities(entity_id, "callees")

    def get_implementations(self, entity_id: str) -> dict[str, Any]:
        return self.related_entities(entity_id, "implementations")

    def get_overrides(self, entity_id: str) -> dict[str, Any]:
        return self.related_entities(entity_id, "overrides")

    def get_fields(self, entity_id: str) -> dict[str, Any]:
        return self.related_entities(entity_id, "fields")

    def get_annotations(self, entity_id: str) -> dict[str, Any]:
        return self.related_entities(entity_id, "annotations")
