from __future__ import annotations

from java_vuln_research.work1_agent.codeql.smoke import SAMPLE_PLAN, _percentile, _sample
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
