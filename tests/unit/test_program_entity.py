from __future__ import annotations

import json

import pytest

from java_vuln_research.work1_agent.repository.entity import (
    ExtractionConfidence,
    ProgramEntity,
    ProgramEntityKind,
    normalise_repository_path,
)


def _entity(path: str = "src/main/java/example/Thing.java") -> ProgramEntity:
    return ProgramEntity.create(
        kind=ProgramEntityKind.METHOD,
        repository_relative_path=path,
        start_line=10,
        end_line=12,
        simple_name="run",
        qualified_name="example.Thing.run",
        enclosing_type="example.Thing",
        signature="run(java.lang.String)",
        type_text="void",
        provenance={"extractor": "TEST"},
        extraction_confidence=ExtractionConfidence.HIGH,
    )


def test_entity_id_and_json_serialization_are_deterministic() -> None:
    first = _entity()
    second = _entity()
    assert first.entity_id == second.entity_id
    assert first.to_json() == second.to_json()
    assert ProgramEntity.from_dict(json.loads(first.to_json())) == first


def test_windows_and_posix_paths_normalise_to_same_identity() -> None:
    assert normalise_repository_path(r"src\main\java\example\Thing.java") == (
        "src/main/java/example/Thing.java"
    )
    windows = _entity(r"src\main\java\example\Thing.java")
    posix = _entity("src/main/java/example/Thing.java")
    assert windows.entity_id == posix.entity_id
    assert windows.repository_relative_path == posix.repository_relative_path


@pytest.mark.parametrize(
    "path",
    ["../Thing.java", "src/../../Thing.java", "/tmp/Thing.java", r"C:\tmp\Thing.java", ""],
)
def test_entity_path_rejects_escape_and_absolute_paths(path: str) -> None:
    with pytest.raises(ValueError):
        _entity(path)


def test_overload_signature_changes_identity() -> None:
    string = _entity()
    integer = ProgramEntity.create(
        **{
            **{
                key: value
                for key, value in string.to_dict().items()
                if key not in {"entity_id", "kind", "extraction_confidence"}
            },
            "kind": ProgramEntityKind.METHOD,
            "signature": "run(int)",
            "extraction_confidence": ExtractionConfidence.HIGH,
        }
    )
    assert string.entity_id != integer.entity_id


def test_codeql_enrichment_does_not_change_repository_identity() -> None:
    lexical = _entity()
    enriched = ProgramEntity.create(
        **{
            **{
                key: value
                for key, value in lexical.to_dict().items()
                if key
                not in {
                    "entity_id",
                    "kind",
                    "extraction_confidence",
                    "codeql_identity",
                }
            },
            "kind": ProgramEntityKind.METHOD,
            "extraction_confidence": ExtractionConfidence.HIGH,
            "codeql_identity": "codeql://example.Thing.run(java.lang.String)",
        }
    )
    assert enriched.entity_id == lexical.entity_id
    assert enriched.codeql_identity is not None
