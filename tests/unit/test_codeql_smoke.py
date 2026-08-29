from __future__ import annotations

from java_vuln_research.work1_agent.codeql.smoke import (
    SAMPLE_PLAN,
    SMOKE_SCHEMA_VERSION,
    _aggregate,
    _load_source_revisions,
    _percentile,
    _sample,
)
from java_vuln_research.work1_agent.repository.entity import ProgramEntity


def _entity(kind: str, line: int) -> ProgramEntity:
    return ProgramEntity.create(
        kind=kind,
        repository_relative_path="src/A.java",
        start_line=line,
        end_line=line,
        simple_name=f"n{line}",
        qualified_name=f"A.n{line}",
    )


def test_smoke_sampling_is_deterministic_and_reports_missing_quota() -> None:
    entities = [_entity("METHOD", 3), _entity("TYPE", 1), _entity("METHOD", 2), _entity("CALL", 4)]
    selected, missing = _sample(reversed(entities))
    assert [(item.kind.value, item.start_line) for item in selected] == [
        ("TYPE", 1), ("METHOD", 2), ("METHOD", 3), ("CALL", 4)
    ]
    assert missing == {"TYPE": 1, "METHOD": 1, "CONSTRUCTOR": 1, "FIELD": 2, "CALL": 2}
    assert sum(value for _, value in SAMPLE_PLAN) == 11


def test_percentile_uses_nearest_rank() -> None:
    assert _percentile([1.0, 2.0, 3.0, 4.0], 0.95) == 4.0


def test_aggregate_binds_schema_git_query_database_and_source_head() -> None:
    result = {
        "summary": {"project_id": "P006", "project_source_head": "source-sha"},
        "calls": [
            {
                "tool_name": "codeql_entity_facts",
                "status": "OK",
                "nodes": [],
                "edges": [],
                "metrics": {"wall_clock_seconds": 1.0},
                "provenance": {
                    "codeql_version": "2.26.3",
                    "query_hash": "query-sha",
                    "database_path": "/db/P006",
                },
            }
        ],
        "mappings": [],
    }
    aggregate = _aggregate([result], 2.0, v11_git_sha="v11-sha", workers=4)
    assert aggregate["smoke_schema_version"] == SMOKE_SCHEMA_VERSION
    assert aggregate["v11_git_sha"] == "v11-sha"
    assert aggregate["query_hashes"] == ["query-sha"]
    assert aggregate["database_paths"] == ["/db/P006"]
    assert aggregate["project_source_heads"] == {"P006": "source-sha"}
    assert aggregate["workers"] == 4


def test_source_revision_manifest_rejects_conflicts(tmp_path) -> None:
    first = tmp_path / "first.yaml"
    second = tmp_path / "second.yaml"
    first.write_text("projects:\n  - project: P006\n    revision: abc\n", encoding="utf-8")
    second.write_text("projects:\n  - project: P006\n    revision: def\n", encoding="utf-8")
    assert _load_source_revisions([first]) == {"P006": "abc"}
    import pytest

    with pytest.raises(ValueError, match="conflicting source revisions"):
        _load_source_revisions([first, second])
