from __future__ import annotations

from pathlib import Path

from java_vuln_research.work1_agent.agent import (
    ActionType,
    AgentAction,
    AgentToolStatus,
    RepositoryCodeQLToolAdapter,
    RuntimeSecurityBoundary,
    runtime_roots,
)
from java_vuln_research.work1_agent.codeql.result import CodeQLToolResult, ToolStatus
from java_vuln_research.work1_agent.repository.entity import ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import build_repository_index


SOURCE = """package demo;
@interface Mark {}
interface Contract { void run(); }
class Impl implements Contract {
  @Mark private String value;
  public void run() { helper(); }
  void helper() {}
}
class Caller { void invoke() { new Impl().run(); } }
"""


def _setup(tmp_path: Path, *, codeql_tools: object | None = None, codeql_ready: bool = False) -> tuple[RepositoryCodeQLToolAdapter, object]:
    source_root = tmp_path / "repo"
    source = source_root / "src" / "Demo.java"
    source.parent.mkdir(parents=True)
    source.write_text(SOURCE, encoding="utf-8")
    index = build_repository_index(source_root)
    artifact_root = tmp_path / "artifacts"
    schema_root = tmp_path / "schemas"
    artifact_root.mkdir()
    schema_root.mkdir()
    boundary = RuntimeSecurityBoundary(
        project_id="P",
        repository_identity="repo@abc",
        allowed_roots=runtime_roots(source_roots=[source_root], artifact_roots=[artifact_root], schema_roots=[schema_root]),
    )
    adapter = RepositoryCodeQLToolAdapter(
        project_id="P",
        repository_index=index,
        security_boundary=boundary,
        codeql_tools=codeql_tools,
        codeql_database=tmp_path / "db" if codeql_ready else None,
        codeql_ready=codeql_ready,
    )
    return adapter, boundary


def _action(action_type: ActionType, arguments: dict[str, object], round: int = 1) -> AgentAction:
    return AgentAction.create(
        project_id="P",
        round=round,
        action_type=action_type,
        arguments=arguments,
        reason="Collect neutral bounded facts.",
        provenance={"producer": "test"},
    )


def _find(adapter: RepositoryCodeQLToolAdapter, kind: ProgramEntityKind, name: str):
    return next(item for item in adapter.index.entities if item.kind is kind and item.simple_name == name)


def test_repository_tools_are_bounded_audited_and_relation_candidates_are_not_facts(tmp_path: Path) -> None:
    adapter, boundary = _setup(tmp_path)
    run = next(
        item
        for item in adapter.index.entities
        if item.kind is ProgramEntityKind.METHOD
        and item.simple_name == "run"
        and (item.enclosing_type or "").endswith("Impl")
    )
    contract = _find(adapter, ProgramEntityKind.TYPE, "Contract")
    impl = _find(adapter, ProgramEntityKind.TYPE, "Impl")

    search = adapter.execute(_action(ActionType.SEARCH_CODE, {"query": "helper", "max_hits": 10}))
    assert search.status is AgentToolStatus.OK
    inspect = adapter.execute(_action(ActionType.INSPECT_METHOD, {"entity_id": run.entity_id, "context_lines": 1}))
    assert inspect.status is AgentToolStatus.OK

    callers = adapter.execute(_action(ActionType.GET_CALLERS, {"entity_id": run.entity_id, "max_results": 10}))
    callees = adapter.execute(_action(ActionType.GET_CALLEES, {"entity_id": run.entity_id, "max_results": 10}))
    implementations = adapter.execute(_action(ActionType.GET_IMPLEMENTATIONS, {"entity_id": contract.entity_id, "max_results": 10}))
    fields = adapter.execute(_action(ActionType.GET_FIELDS, {"entity_id": impl.entity_id, "max_results": 10}))
    assert callers.status is AgentToolStatus.OK
    assert callees.status is AgentToolStatus.OK
    assert implementations.status is AgentToolStatus.OK
    assert fields.status is AgentToolStatus.OK
    assert "M1_RELATION_IS_STRUCTURAL_CANDIDATE_NOT_SEMANTIC_FACT" in callers.warnings
    assert all(item["provenance"]["deterministic_relation"] is False for item in callers.items)

    manifest = boundary.seal()
    assert manifest["no_leakage_pass"] is True
    assert manifest["entries"][0]["logical_name"] == "java:src/Demo.java"


def test_codeql_unavailable_is_structured_and_not_negative_evidence(tmp_path: Path) -> None:
    adapter, _ = _setup(tmp_path)
    run = _find(adapter, ProgramEntityKind.METHOD, "run")
    result = adapter.execute(_action(ActionType.CODEQL_DATAFLOW_NEIGHBORS, {"entity_id": run.entity_id, "max_depth": 1}))
    assert result.status is AgentToolStatus.UNAVAILABLE
    assert result.failure["reason"] == "CODEQL_UNAVAILABLE"
    assert "UNAVAILABLE_IS_NOT_NEGATIVE_EVIDENCE" in result.warnings
    assert result.provenance["codeql_unavailable_is_not_absence"] is True


class _FakeCodeQL:
    def codeql_entity_facts(self, **kwargs: object) -> CodeQLToolResult:
        entity = kwargs["entity"]
        return CodeQLToolResult(
            tool_call_id="codeql-call-test",
            tool_name="codeql_entity_facts",
            status=ToolStatus.OK,
            queried_entity_ids=[entity.entity_id],
            nodes=[{"entity_id": entity.entity_id, "evidence_kind": "CODEQL_ENTITY_FACT"}],
            provenance={"fixed_query": True},
        )


def test_ready_codeql_action_uses_fixed_m3_api(tmp_path: Path) -> None:
    adapter, _ = _setup(tmp_path, codeql_tools=_FakeCodeQL(), codeql_ready=True)
    run = _find(adapter, ProgramEntityKind.METHOD, "run")
    result = adapter.execute(_action(ActionType.CODEQL_ENTITY_FACTS, {"entity_id": run.entity_id}))
    assert result.status is AgentToolStatus.OK
    assert result.items[0]["tool_name"] == "codeql_entity_facts"
    assert result.items[0]["provenance"]["fixed_query"] is True


def test_adapter_rejects_cross_project_and_non_tool_actions(tmp_path: Path) -> None:
    adapter, _ = _setup(tmp_path)
    wrong = AgentAction.create(project_id="OTHER", round=1, action_type=ActionType.SEARCH_CODE, arguments={"query": "x"}, reason="x", provenance={"producer": "test"})
    try:
        adapter.execute(wrong)
    except ValueError as error:
        assert "cross-project" in str(error)
    else:
        raise AssertionError("cross-project action must be rejected")
