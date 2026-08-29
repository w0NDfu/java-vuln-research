from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.repository.entity import (
    ExtractionConfidence,
    ProgramEntityKind,
)
from java_vuln_research.work1_agent.repository.indexer import build_repository_index
from java_vuln_research.work1_agent.repository.reader import (
    SourceReadError,
    inspect_entity,
    read_file_range,
)
from java_vuln_research.work1_agent.repository.search import search_code, search_symbols


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "work1_agent_repository"


@pytest.fixture(scope="module")
def repository_index():
    return build_repository_index(FIXTURE)


def test_index_covers_required_neutral_entity_kinds(repository_index) -> None:
    counts = Counter(entity.kind for entity in repository_index.entities)
    for kind in (
        ProgramEntityKind.FILE,
        ProgramEntityKind.PACKAGE,
        ProgramEntityKind.TYPE,
        ProgramEntityKind.METHOD,
        ProgramEntityKind.CONSTRUCTOR,
        ProgramEntityKind.PARAMETER,
        ProgramEntityKind.FIELD,
        ProgramEntityKind.CALL,
        ProgramEntityKind.ANNOTATION,
    ):
        assert counts[kind] > 0, kind


def test_index_is_deterministic_and_suppresses_duplicate_ids(repository_index) -> None:
    rebuilt = build_repository_index(FIXTURE)
    assert repository_index.to_jsonl_text() == rebuilt.to_jsonl_text()
    identifiers = [entity.entity_id for entity in repository_index.entities]
    assert len(identifiers) == len(set(identifiers))


def test_nested_type_and_callable_ownership(repository_index) -> None:
    nested = next(
        entity
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.TYPE and entity.simple_name == "Nested"
    )
    assert nested.enclosing_type == "com.example.RepositoryCases"
    constructor = next(
        entity
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.CONSTRUCTOR
        and entity.enclosing_type == "com.example.RepositoryCases.Nested"
    )
    parameter = next(
        entity
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.PARAMETER
        and entity.simple_name == "count"
        and entity.enclosing_type == "com.example.RepositoryCases.Nested"
    )
    assert constructor.signature == "Nested(int)"
    assert parameter.enclosing_callable and "Nested(int)" in parameter.enclosing_callable


def test_interface_implementation_and_constructor_kinds_are_preserved(repository_index) -> None:
    worker = next(
        entity
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.TYPE and entity.simple_name == "Worker"
    )
    implementation = next(
        entity
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.TYPE
        and entity.qualified_name == "com.example.RepositoryCases"
    )
    assert worker.provenance["declaration_kind"] == "INTERFACE"
    assert "implements Worker<T>" in (implementation.type_text or "")
    constructors = [
        entity
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.CONSTRUCTOR
        and entity.enclosing_type == "com.example.RepositoryCases"
    ]
    assert {entity.signature for entity in constructors} == {
        "RepositoryCases()",
        "RepositoryCases(String)",
    }
    assert not any(entity.kind == ProgramEntityKind.METHOD for entity in constructors)


def test_overloaded_methods_have_distinct_signatures_and_ids(repository_index) -> None:
    methods = [
        entity
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.METHOD and entity.simple_name == "process"
    ]
    assert len(methods) == 2
    assert len({entity.signature for entity in methods}) == 2
    assert len({entity.entity_id for entity in methods}) == 2
    assert any("java.util.List<T>" in (entity.signature or "") for entity in methods)


def test_fields_calls_annotations_and_comment_braces(repository_index) -> None:
    fields = {
        entity.simple_name: entity
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.FIELD
        and entity.enclosing_type == "com.example.RepositoryCases"
    }
    assert {"template", "values", "name"} <= fields.keys()
    assert fields["values"].type_text == "java.util.Map<String,java.util.List<T>>"
    calls = {
        entity.simple_name
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.CALL
    }
    assert {"this", "helper", "load", "toString", "sink", "nestedCall", "unresolved"} <= calls
    annotations = {
        entity.simple_name
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.ANNOTATION
    }
    assert {"Marker", "Override", "Named"} <= annotations
    outer = next(
        entity
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.TYPE
        and entity.qualified_name == "com.example.RepositoryCases"
    )
    source_lines = (FIXTURE / outer.repository_relative_path).read_text(encoding="utf-8").splitlines()
    assert source_lines[outer.end_line - 1] == "}"


def test_malformed_java_is_retained_with_warning_and_low_confidence(repository_index) -> None:
    broken = next(
        entity
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.TYPE and entity.simple_name == "Broken"
    )
    assert broken.extraction_confidence == ExtractionConfidence.LOW
    assert any(
        row.repository_relative_path.endswith("Broken.java")
        and row.error_class == "UNMATCHED_BRACE"
        for row in repository_index.diagnostics
    )


def test_bounded_reader_returns_exact_numbered_range(repository_index) -> None:
    method = next(
        entity
        for entity in repository_index.entities
        if entity.kind == ProgramEntityKind.METHOD and entity.signature == "process(String)"
    )
    result = inspect_entity(FIXTURE, method, max_lines=20)
    assert result["start_line"] == method.start_line
    assert result["end_line"] == method.end_line
    assert result["lines"][0]["line"] == method.start_line
    assert f"{method.start_line:>6} |" in result["text"]


def test_reader_enforces_line_byte_and_traversal_limits() -> None:
    relative = "src/main/java/com/example/RepositoryCases.java"
    with pytest.raises(SourceReadError, match="maximum") as line_error:
        read_file_range(FIXTURE, relative, 1, 20, max_lines=5)
    assert line_error.value.error_class == "LINE_LIMIT_EXCEEDED"
    with pytest.raises(SourceReadError) as byte_error:
        read_file_range(FIXTURE, relative, 1, 5, max_bytes=5)
    assert byte_error.value.error_class == "BYTE_LIMIT_EXCEEDED"
    with pytest.raises(SourceReadError) as traversal_error:
        read_file_range(FIXTURE, "../outside.java", 1, 1)
    assert traversal_error.value.error_class == "PATH_TRAVERSAL"


def test_utf8_failure_is_explicit_for_index_and_reader(tmp_path: Path) -> None:
    source = tmp_path / "Invalid.java"
    source.write_bytes(b"class Invalid { \xff }")
    index = build_repository_index(tmp_path)
    assert index.summary()["errors"] == 1
    assert index.diagnostics[0].error_class == "UTF8_DECODE_ERROR"
    with pytest.raises(SourceReadError) as read_error:
        read_file_range(tmp_path, "Invalid.java", 1, 1)
    assert read_error.value.error_class == "UTF8_DECODE_ERROR"


def test_default_index_excludes_generated_build_directories(tmp_path: Path) -> None:
    source = tmp_path / "src" / "main" / "java" / "Kept.java"
    generated = tmp_path / "target" / "generated-sources" / "Ignored.java"
    source.parent.mkdir(parents=True)
    generated.parent.mkdir(parents=True)
    source.write_text("class Kept {}\n", encoding="utf-8")
    generated.write_text("class Ignored {}\n", encoding="utf-8")
    index = build_repository_index(tmp_path)
    assert index.java_file_count == 1
    assert not any(entity.simple_name == "Ignored" for entity in index.entities)
    assert "target" in index.summary()["excluded_directories"]


def test_neutral_search_is_bounded_and_has_auditable_shape(repository_index) -> None:
    code_hits = search_code(repository_index, "helper", max_hits=1)
    assert len(code_hits) == 1
    symbol_hits = search_symbols(
        repository_index,
        "process",
        kind=ProgramEntityKind.METHOD,
        max_hits=1,
    )
    assert len(symbol_hits) == 1
    for hit in [*code_hits, *symbol_hits]:
        assert set(hit) == {"entity", "location", "snippet", "kind", "query", "provenance"}
        serialised = json.dumps(hit, sort_keys=True)
        assert "VULNERABLE" not in serialised
        assert "CWE-" not in serialised


def test_schema_required_fields_match_serialized_entity(repository_index) -> None:
    schema = json.loads((ROOT / "schemas" / "program_entity.schema.json").read_text(encoding="utf-8"))
    entity = repository_index.sorted_entities()[0].to_dict()
    assert set(schema["required"]) == set(entity)


def test_index_writes_jsonl_summary_and_diagnostics(repository_index, tmp_path: Path) -> None:
    entities = tmp_path / "entities.jsonl"
    summary = tmp_path / "summary.json"
    diagnostics = tmp_path / "diagnostics.jsonl"
    repository_index.write_jsonl(entities)
    repository_index.write_summary(summary)
    repository_index.write_diagnostics(diagnostics)
    rows = [json.loads(line) for line in entities.read_text(encoding="utf-8").splitlines()]
    assert len(rows) == repository_index.summary()["program_entity_count"]
    assert json.loads(summary.read_text(encoding="utf-8"))["java_file_count"] == 2
    assert len(diagnostics.read_text(encoding="utf-8").splitlines()) == 2
