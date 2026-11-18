from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.codeql.entity_mapper import (
    MappingCandidate,
    MappingStatus,
    map_program_entity,
)
from java_vuln_research.work1_agent.codeql.analysis_tools import CodeQLAnalysisTools
from java_vuln_research.work1_agent.codeql.executor import CodeQLExecutor, QuerySpec
from java_vuln_research.work1_agent.codeql.result import (
    CodeQLToolResult,
    EvidenceKind,
    FailureReason,
    ToolStatus,
)
from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind


def _entity(kind: ProgramEntityKind = ProgramEntityKind.METHOD) -> ProgramEntity:
    return ProgramEntity.create(
        kind=kind,
        repository_relative_path="src/main/java/example/A.java",
        start_line=10,
        end_line=14,
        simple_name="run",
        qualified_name="example.A.run",
        enclosing_type="example.A",
        signature="run(String)",
    )


def _candidate(**overrides):
    values = {
        "codeql_identity": "METHOD@src/main/java/example/A.java:10:3",
        "kind": "METHOD",
        "repository_relative_path": "src/main/java/example/A.java",
        "start_line": 10,
        "end_line": 14,
        "qualified_name": "example.A.run",
        "signature": "run(String)",
        "declaring_type": "example.A",
        "enclosing_callable": "example.A.run",
    }
    values.update(overrides)
    return MappingCandidate(**values)


def _ready_db(tmp_path: Path) -> Path:
    db = tmp_path / "db"
    db.mkdir(exist_ok=True)
    (db / "codeql-database.yml").write_text("primaryLanguage: java\n", encoding="utf-8")
    return db


def _query(tmp_path: Path, text: str = "select {{LINE}}\n") -> QuerySpec:
    path = tmp_path / "Query.ql"
    path.write_text(text, encoding="utf-8")
    return QuerySpec("Query", path, ("value",), max_rows=2)


class Runner:
    def __init__(self, *, csv_text: str = "one\n", query_exit: int = 0, decode_exit: int = 0, query_stderr: str = ""):
        self.csv_text = csv_text
        self.query_exit = query_exit
        self.decode_exit = decode_exit
        self.query_stderr = query_stderr
        self.commands: list[list[str]] = []

    def __call__(self, command, **kwargs):
        self.commands.append(list(command))
        if "version" in command:
            return subprocess.CompletedProcess(command, 0, '{"version":"2.26.3"}', "")
        if "decode" in command:
            return subprocess.CompletedProcess(command, self.decode_exit, self.csv_text, "decode failed")
        output = next((item.split("=", 1)[1] for item in command if item.startswith("--output=")), None)
        if output and self.query_exit == 0:
            Path(output).write_bytes(b"bqrs")
        return subprocess.CompletedProcess(command, self.query_exit, "query stdout", self.query_stderr)


def test_mapping_requires_context_and_is_unique() -> None:
    result = map_program_entity(_entity(), [_candidate()], database_id="db")
    assert result.status == MappingStatus.MAPPED_UNIQUE
    assert result.codeql_identity.startswith("METHOD@")
    assert "qualified_name exact" in result.mapping_evidence


def test_mapping_preserves_entity_enrichment_facts() -> None:
    candidate = _candidate(
        parameter_positions="0:java.lang.String",
        return_information="boolean",
        type_information="declaring=example.A|return=boolean",
        annotation_facts="java.lang.Override",
        override_interface_facts="example.Base.run(java.lang.String)",
    )
    result = map_program_entity(_entity(), [candidate])
    encoded = result.candidates[0].to_dict()
    assert encoded["parameter_positions"] == "0:java.lang.String"
    assert encoded["return_information"] == "boolean"
    assert encoded["type_information"].startswith("declaring=example.A")
    assert encoded["annotation_facts"] == "java.lang.Override"
    assert encoded["override_interface_facts"].startswith("example.Base.run")


def test_mapping_never_selects_first_ambiguous_candidate() -> None:
    result = map_program_entity(
        _entity(),
        [_candidate(codeql_identity="one"), _candidate(codeql_identity="two")],
    )
    assert result.status == MappingStatus.MAPPED_AMBIGUOUS
    assert result.codeql_identity is None
    assert result.candidate_count == 2


def test_mapping_not_mapped_and_unsupported() -> None:
    assert map_program_entity(_entity(), [_candidate(repository_relative_path="other/A.java")]).status == MappingStatus.NOT_MAPPED
    assert map_program_entity(_entity(ProgramEntityKind.FILE), []).status == MappingStatus.UNSUPPORTED_KIND
    assert map_program_entity(_entity(ProgramEntityKind.CALL_ARGUMENT), []).status == MappingStatus.UNSUPPORTED_KIND


def test_executor_constructs_command_materializes_template_and_records_provenance(tmp_path: Path) -> None:
    runner = Runner(csv_text="one\ntwo\nthree\n")
    executor = CodeQLExecutor(
        "codeql",
        artifact_root=tmp_path / "artifacts",
        runner=runner,
    )
    result = executor.execute(
        database=_ready_db(tmp_path),
        query=_query(tmp_path),
        tool_name="test",
        template_values={"LINE": 10},
        queried_entity_ids=["entity-1"],
        threads=2,
        ram_mb=512,
    )
    assert result.status == ToolStatus.OK
    assert result.truncated is True
    assert len(result.nodes) == 2
    assert result.provenance["codeql_version"] == "2.26.3"
    assert result.provenance["arguments"] == {"LINE": 10}
    query_command = next(command for command in runner.commands if "query" in command)
    assert "--threads=2" in query_command
    assert "--ram=512" in query_command
    materialized = Path(query_command[3]).read_text(encoding="utf-8")
    assert materialized == "select 10\n"


def test_executor_uses_configured_default_threads(tmp_path: Path) -> None:
    runner = Runner()
    executor = CodeQLExecutor(
        "codeql",
        artifact_root=tmp_path / "artifacts",
        threads=3,
        runner=runner,
    )
    result = executor.execute(
        database=_ready_db(tmp_path),
        query=_query(tmp_path),
        tool_name="test",
        template_values={"LINE": 10},
    )
    assert result.status == ToolStatus.OK
    query_command = next(command for command in runner.commands if "query" in command)
    assert "--threads=3" in query_command


def test_executor_preserves_qlpack_context_for_materialized_query(tmp_path: Path) -> None:
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "qlpack.yml").write_text("name: test/pack\nversion: 0.0.1\n", encoding="utf-8")
    (pack / "codeql-pack.lock.yml").write_text("lockVersion: 1.0.0\n", encoding="utf-8")
    query = QuerySpec("Query", pack / "Query.ql", ("value",))
    query.path.write_text("select {{LINE}}\n", encoding="utf-8")
    runner = Runner()
    result = CodeQLExecutor("codeql", artifact_root=tmp_path / "out", runner=runner).execute(
        database=_ready_db(tmp_path), query=query, tool_name="test", template_values={"LINE": 1}
    )
    assert result.status == ToolStatus.OK
    materialized = Path(next(command for command in runner.commands if "query" in command)[3])
    assert (materialized.parent / "qlpack.yml").is_file()
    assert (materialized.parent / "codeql-pack.lock.yml").is_file()
    assert result.provenance["query_pack_root"] == str(pack)


class AnalysisRunner:
    def __init__(self) -> None:
        self.calls = 0
        self.last_edge_kwargs = None

    def execute(self, **kwargs):
        self.calls += 1
        if self.calls == 1:
            return CodeQLToolResult(
                tool_call_id="mapping",
                tool_name=kwargs["tool_name"],
                status=ToolStatus.OK,
                nodes=[_candidate().to_dict()],
                provenance={"query_hash": "hash"},
            )
        self.last_edge_kwargs = kwargs
        return CodeQLToolResult(
            tool_call_id="edges",
            tool_name=kwargs["tool_name"],
            status=ToolStatus.OK,
            nodes=[
                {"source_identity": "caller", "target_identity": "target", "edge_kind": "CALLER"},
                {"source_identity": "target", "target_identity": "callee", "edge_kind": "CALLEE"},
            ],
        )


class BatchAnalysisRunner:
    def __init__(self, nodes) -> None:
        self.calls = 0
        self.nodes = nodes
        self.kwargs = None

    def execute(self, **kwargs):
        self.calls += 1
        self.kwargs = kwargs
        return CodeQLToolResult(
            tool_call_id="batch",
            tool_name=kwargs["tool_name"],
            status=ToolStatus.OK,
            nodes=self.nodes,
            provenance={"query_hash": "batch-hash"},
            metrics={"wall_clock_seconds": 11.0},
        )


def test_analysis_tools_filter_call_direction_and_return_bounded_nodes(tmp_path: Path) -> None:
    runner = AnalysisRunner()
    tools = CodeQLAnalysisTools(runner, tmp_path)
    result = tools.codeql_callers(database=tmp_path / "db", entity=_entity())
    assert [edge["edge_kind"] for edge in result.edges] == ["CALLER"]
    assert {node["codeql_identity"] for node in result.nodes} == {"caller", "target"}
    assert result.metrics["returned_nodes"] == 2
    assert runner.last_edge_kwargs["template_values"]["CODEQL_IDENTITY"].startswith("METHOD@")


class LocalFlowRunner:
    def execute(self, **kwargs):
        if kwargs["tool_name"] == "map_program_entity":
            values = kwargs["template_values"]
            kind = values["KIND_0"]
            start = int(values["START_LINE_0"])
            signature = "run/1" if kind == "METHOD" else ""
            return CodeQLToolResult(
                tool_call_id=f"mapping-{kind}-{start}",
                tool_name="map_program_entity",
                status=ToolStatus.OK,
                nodes=[
                    _candidate(
                        codeql_identity=f"{kind}@src/main/java/example/A.java:{start}:3",
                        kind=kind,
                        start_line=start,
                        end_line=start,
                        qualified_name="example.A.run",
                        signature=signature,
                        enclosing_callable="example.A.run",
                    ).to_dict()
                ],
                provenance={"query_hash": "mapping-hash"},
            )
        return CodeQLToolResult(
            tool_call_id="flow",
            tool_name="codeql_local_flow",
            status=ToolStatus.OK,
            nodes=[
                {
                    "source_identity": "source",
                    "target_identity": "wanted",
                    "edge_kind": "DATAFLOW",
                    "repository_relative_path": "src/main/java/example/A.java",
                    "start_line": 20,
                    "end_line": 20,
                    "callable_identity": "example.A.run/1",
                },
                {
                    "source_identity": "source",
                    "target_identity": "wrong-scope",
                    "edge_kind": "DATAFLOW",
                    "repository_relative_path": "src/main/java/example/A.java",
                    "start_line": 20,
                    "end_line": 20,
                    "callable_identity": "example.Other.run/1",
                },
                {
                    "source_identity": "source",
                    "target_identity": "wrong-target",
                    "edge_kind": "DATAFLOW",
                    "repository_relative_path": "src/main/java/example/A.java",
                    "start_line": 99,
                    "end_line": 99,
                    "callable_identity": "example.A.run/1",
                },
            ],
        )


def test_local_flow_optional_target_and_scope_are_enforced(tmp_path: Path) -> None:
    source = _entity(ProgramEntityKind.CALL)
    target = ProgramEntity.create(
        kind=ProgramEntityKind.CALL,
        repository_relative_path="src/main/java/example/A.java",
        start_line=20,
        end_line=20,
        simple_name="target",
        qualified_name="example.A.target",
        enclosing_type="example.A",
        enclosing_callable="example.A.run",
    )
    scope = ProgramEntity.create(
        kind=ProgramEntityKind.METHOD,
        repository_relative_path="src/main/java/example/A.java",
        start_line=30,
        end_line=30,
        simple_name="run",
        qualified_name="example.A.run",
        enclosing_type="example.A",
        signature="run/1",
    )
    tools = CodeQLAnalysisTools(LocalFlowRunner(), tmp_path)
    result = tools.codeql_local_flow(
        database=tmp_path / "db",
        entity=source,
        target_entity=target,
        scope_entity=scope,
    )
    assert [edge["target_identity"] for edge in result.edges] == ["wanted"]
    assert result.provenance["target_entity_id"] == target.entity_id
    assert result.provenance["scope_entity_id"] == scope.entity_id


def test_analysis_tools_cache_mapping_per_database_and_entity(tmp_path: Path) -> None:
    runner = AnalysisRunner()
    tools = CodeQLAnalysisTools(runner, tmp_path)
    first, _ = tools.map_entity(database=tmp_path / "db", entity=_entity())
    second, cached_result = tools.map_entity(database=tmp_path / "db", entity=_entity())
    assert first.status == second.status == MappingStatus.MAPPED_UNIQUE
    assert runner.calls == 1
    assert cached_result.provenance["mapping_cache_hit"] is True


def test_analysis_tools_prefetches_entity_mapping_in_one_bounded_query(tmp_path: Path) -> None:
    first = _entity()
    second = ProgramEntity.create(
        kind=ProgramEntityKind.FIELD,
        repository_relative_path="src/main/java/example/A.java",
        start_line=20,
        end_line=20,
        simple_name="value",
        qualified_name="example.A.value",
        enclosing_type="example.A",
    )
    runner = BatchAnalysisRunner(
        [
            _candidate().to_dict(),
            _candidate(
                codeql_identity="FIELD@src/main/java/example/A.java:20:3",
                kind="FIELD",
                start_line=20,
                end_line=20,
                qualified_name="example.A.value",
                signature="",
                enclosing_callable="",
            ).to_dict(),
        ]
    )
    tools = CodeQLAnalysisTools(runner, tmp_path)
    batch = tools.prefetch_entity_facts(database=tmp_path / "db", entities=[first, second])
    first_result = tools.codeql_entity_facts(database=tmp_path / "db", entity=first)
    second_result = tools.codeql_entity_facts(database=tmp_path / "db", entity=second)

    assert batch.status == ToolStatus.OK
    assert runner.calls == 1
    assert runner.kwargs["query"].max_rows == 200
    assert runner.kwargs["template_values"]["PATH_0"] == first.repository_relative_path
    assert runner.kwargs["template_values"]["KIND_1"] == "FIELD"
    assert first_result.status == second_result.status == ToolStatus.OK
    assert first_result.provenance["batch_parent_tool_call_id"] == "batch"
    assert first_result.metrics["batch_wall_clock_seconds"] == 11.0
    assert first_result.metrics["wall_clock_seconds"] == 5.5


def test_entity_fact_batch_rejects_more_than_eleven_targets() -> None:
    with pytest.raises(ValueError, match="at most eleven"):
        CodeQLAnalysisTools._entity_target_values([_entity()] * 12)


def test_one_step_neighbor_tools_reject_depth_above_one(tmp_path: Path) -> None:
    tools = CodeQLAnalysisTools(AnalysisRunner(), tmp_path)
    with pytest.raises(ValueError, match="max_depth"):
        tools.codeql_dataflow_neighbors(database=tmp_path / "db", entity=_entity(), max_depth=2)


@pytest.mark.parametrize(
    ("stderr", "reason"),
    [
        ("could not resolve module java", FailureReason.QUERY_COMPILE_ERROR),
        ("Java heap space", FailureReason.OOM),
        ("evaluation failed", FailureReason.QUERY_EXECUTION_ERROR),
        ("Compiled query. Starting evaluation. Invalid checksum on pool file /db/cache/x", FailureReason.DB_CACHE_CORRUPTION),
        ("Compiling query plan. Compiled query. evaluation failed", FailureReason.QUERY_EXECUTION_ERROR),
    ],
)
def test_executor_classifies_query_failures(tmp_path: Path, stderr: str, reason: FailureReason) -> None:
    runner = Runner(query_exit=2, query_stderr=stderr)
    result = CodeQLExecutor("codeql", artifact_root=tmp_path / "out", runner=runner).execute(
        database=_ready_db(tmp_path),
        query=_query(tmp_path, "select 1\n"),
        tool_name="test",
    )
    assert result.status == ToolStatus.ERROR
    assert result.failure and result.failure.reason == reason


def test_executor_timeout(tmp_path: Path) -> None:
    def runner(command, **kwargs):
        if "version" in command:
            return subprocess.CompletedProcess(command, 0, "2.26.3", "")
        raise subprocess.TimeoutExpired(command, 1)

    result = CodeQLExecutor("codeql", artifact_root=tmp_path / "out", runner=runner).execute(
        database=_ready_db(tmp_path), query=_query(tmp_path, "select 1\n"), tool_name="test"
    )
    assert result.failure and result.failure.reason == FailureReason.TIMEOUT


def test_executor_decode_and_parse_failures(tmp_path: Path) -> None:
    decode = CodeQLExecutor("codeql", artifact_root=tmp_path / "decode", runner=Runner(decode_exit=2)).execute(
        database=_ready_db(tmp_path), query=_query(tmp_path, "select 1\n"), tool_name="test"
    )
    assert decode.failure and decode.failure.reason == FailureReason.BQRS_DECODE_ERROR

    parse = CodeQLExecutor("codeql", artifact_root=tmp_path / "parse", runner=Runner(csv_text="one,two\n")).execute(
        database=_ready_db(tmp_path), query=_query(tmp_path, "select 1\n"), tool_name="test"
    )
    assert parse.failure and parse.failure.reason == FailureReason.OUTPUT_PARSE_ERROR


def test_executor_preflight_failures_are_explicit(tmp_path: Path) -> None:
    missing_codeql = CodeQLExecutor(str(tmp_path / "no-codeql"), artifact_root=tmp_path / "a").execute(
        database=tmp_path / "db", query=_query(tmp_path), tool_name="test"
    )
    assert missing_codeql.failure and missing_codeql.failure.reason == FailureReason.CODEQL_UNAVAILABLE

    runner = Runner()
    missing_db = CodeQLExecutor("codeql", artifact_root=tmp_path / "b", runner=runner).execute(
        database=tmp_path / "missing-db", query=_query(tmp_path), tool_name="test"
    )
    assert missing_db.failure and missing_db.failure.reason == FailureReason.DB_NOT_FOUND

    db = tmp_path / "not-ready"
    db.mkdir()
    not_ready = CodeQLExecutor("codeql", artifact_root=tmp_path / "c", runner=runner).execute(
        database=db, query=_query(tmp_path), tool_name="test"
    )
    assert not_ready.failure and not_ready.failure.reason == FailureReason.DB_NOT_READY


def test_result_schema_and_evidence_sources_remain_distinct() -> None:
    result = CodeQLToolResult(
        tool_call_id="call-1",
        tool_name="codeql_callers",
        status=ToolStatus.OK,
        edges=[{"evidence_kind": EvidenceKind.CODEQL_CALL.value}],
    )
    encoded = result.to_dict()
    assert encoded["status"] == "OK"
    assert EvidenceKind.CODEQL_CALL.value != EvidenceKind.LEXICAL_CALL.value
    assert encoded["edges"][0]["evidence_kind"] == "CODEQL_CALL"


def test_error_result_requires_failure() -> None:
    with pytest.raises(ValueError):
        CodeQLToolResult(tool_call_id="x", tool_name="x", status=ToolStatus.ERROR)
