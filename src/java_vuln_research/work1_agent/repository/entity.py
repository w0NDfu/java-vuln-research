from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Mapping


ENTITY_SCHEMA_VERSION = 1
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


class ProgramEntityKind(str, Enum):
    FILE = "FILE"
    PACKAGE = "PACKAGE"
    TYPE = "TYPE"
    METHOD = "METHOD"
    CONSTRUCTOR = "CONSTRUCTOR"
    PARAMETER = "PARAMETER"
    FIELD = "FIELD"
    CALL = "CALL"
    ANNOTATION = "ANNOTATION"
    RETURN = "RETURN"
    LOCAL = "LOCAL"
    CALL_ARGUMENT = "CALL_ARGUMENT"
    FIELD_READ = "FIELD_READ"
    FIELD_WRITE = "FIELD_WRITE"


class ExtractionConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


def normalise_repository_path(value: str) -> str:
    """Return one canonical repository-relative POSIX path.

    Absolute paths and parent traversal are deliberately rejected so neither
    entity identity nor source access can escape the indexed repository.
    """

    text = str(value).strip().replace("\\", "/")
    if not text or text.startswith("/") or _WINDOWS_DRIVE.match(text):
        raise ValueError("repository path must be non-empty and relative")
    parts = [part for part in text.split("/") if part not in {"", "."}]
    if not parts or any(part == ".." for part in parts):
        raise ValueError("repository path must not contain parent traversal")
    return PurePosixPath(*parts).as_posix()


def _identity_digest(material: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        material,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class ProgramEntity:
    entity_id: str
    codeql_identity: str | None
    kind: ProgramEntityKind
    repository_relative_path: str
    start_line: int
    end_line: int
    simple_name: str
    qualified_name: str
    enclosing_type: str | None
    enclosing_callable: str | None
    signature: str | None
    type_text: str | None
    provenance: Mapping[str, Any]
    extraction_confidence: ExtractionConfidence

    def __post_init__(self) -> None:
        path = normalise_repository_path(self.repository_relative_path)
        if path != self.repository_relative_path:
            raise ValueError("repository_relative_path is not canonical")
        if not self.entity_id or not self.simple_name or not self.qualified_name:
            raise ValueError("entity_id, simple_name, and qualified_name are required")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("entity source range must be positive and ordered")
        if not isinstance(self.provenance, Mapping):
            raise ValueError("provenance must be an object")

    @classmethod
    def create(
        cls,
        *,
        kind: ProgramEntityKind | str,
        repository_relative_path: str,
        start_line: int,
        end_line: int,
        simple_name: str,
        qualified_name: str,
        enclosing_type: str | None = None,
        enclosing_callable: str | None = None,
        signature: str | None = None,
        type_text: str | None = None,
        provenance: Mapping[str, Any] | None = None,
        extraction_confidence: ExtractionConfidence | str = ExtractionConfidence.HIGH,
        identity_discriminator: str | int | None = None,
        codeql_identity: str | None = None,
    ) -> "ProgramEntity":
        resolved_kind = ProgramEntityKind(kind)
        resolved_confidence = ExtractionConfidence(extraction_confidence)
        path = normalise_repository_path(repository_relative_path)
        resolved_provenance = dict(provenance or {})
        material = {
            "schema_version": ENTITY_SCHEMA_VERSION,
            "kind": resolved_kind.value,
            "path": path,
            "start_line": int(start_line),
            "end_line": int(end_line),
            "simple_name": str(simple_name),
            "qualified_name": str(qualified_name),
            "enclosing_type": enclosing_type,
            "enclosing_callable": enclosing_callable,
            "signature": signature,
            "type_text": type_text,
            "identity_discriminator": identity_discriminator,
        }
        return cls(
            entity_id="entity-" + _identity_digest(material),
            codeql_identity=codeql_identity,
            kind=resolved_kind,
            repository_relative_path=path,
            start_line=int(start_line),
            end_line=int(end_line),
            simple_name=str(simple_name),
            qualified_name=str(qualified_name),
            enclosing_type=enclosing_type,
            enclosing_callable=enclosing_callable,
            signature=signature,
            type_text=type_text,
            provenance=resolved_provenance,
            extraction_confidence=resolved_confidence,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "codeql_identity": self.codeql_identity,
            "kind": self.kind.value,
            "repository_relative_path": self.repository_relative_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "simple_name": self.simple_name,
            "qualified_name": self.qualified_name,
            "enclosing_type": self.enclosing_type,
            "enclosing_callable": self.enclosing_callable,
            "signature": self.signature,
            "type_text": self.type_text,
            "provenance": dict(self.provenance),
            "extraction_confidence": self.extraction_confidence.value,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProgramEntity":
        return cls(
            entity_id=str(value["entity_id"]),
            codeql_identity=(
                str(value["codeql_identity"])
                if value.get("codeql_identity") is not None
                else None
            ),
            kind=ProgramEntityKind(value["kind"]),
            repository_relative_path=normalise_repository_path(
                str(value["repository_relative_path"])
            ),
            start_line=int(value["start_line"]),
            end_line=int(value["end_line"]),
            simple_name=str(value["simple_name"]),
            qualified_name=str(value["qualified_name"]),
            enclosing_type=(
                str(value["enclosing_type"])
                if value.get("enclosing_type") is not None
                else None
            ),
            enclosing_callable=(
                str(value["enclosing_callable"])
                if value.get("enclosing_callable") is not None
                else None
            ),
            signature=(
                str(value["signature"]) if value.get("signature") is not None else None
            ),
            type_text=(
                str(value["type_text"]) if value.get("type_text") is not None else None
            ),
            provenance=dict(value.get("provenance") or {}),
            extraction_confidence=ExtractionConfidence(value["extraction_confidence"]),
        )
