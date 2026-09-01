from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from java_vuln_research.work1_agent.agent import (
    MockLLMClient,
    RepositoryCodeQLToolAdapter,
    RuntimeSecurityBoundary,
    runtime_roots,
)
from java_vuln_research.work1_agent.m8_multiagent import (
    BRIDGE_ALLOWED_TOOLS,
    COORDINATOR_AGENT,
    EFFECT_AGENT,
    INPUT_AGENT,
    M8_AGENT_REGISTRY,
    SEMANTIC_BRIDGE_AGENT,
    BridgeAgentRuntime,
    EffectAgentRuntime,
    InputAgentRuntime,
    SpecialistResultStatus,
    SpecialistRole,
    SpecialistTaskSpec,
)
from java_vuln_research.work1_agent.m8_multiagent.prompts import (
    BRIDGE_PROMPT_VERSION,
    BRIDGE_SYSTEM_PROMPT,
    EFFECT_PROMPT_VERSION,
    EFFECT_SYSTEM_PROMPT,
    INPUT_PROMPT_VERSION,
    INPUT_SYSTEM_PROMPT,
    prompt_sha256,
)
from java_vuln_research.work1_agent.repository.entity import ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import build_repository_index


SOURCE = """package demo;
class Sample {
  void handle(String value) { helper(value); }
  void helper(String value) {}
}
"""


def _decision(
    action_type: str,
    *,
    tool_name: str | None = None,
    arguments: dict[str, object] | None = None,
    findings: list[dict[str, object]] | None = None,
    status: str | None = None,
    next_suggested_evidence: list[str] | None = None,
    uncertainty: list[str] | None = None,
) -> dict[str, object]:
    return {
        "action_type": action_type,
        "tool_name": tool_name,
        "arguments": arguments or {},
        "findings": findings or [],
        "status": status,
        "next_suggested_evidence": next_suggested_evidence or [],
        "uncertainty": uncertainty or [],
        "reason": "Collect or report one bounded program fact.",
    }


def _setup(
    tmp_path: Path,
    responses: list[object],
    runtime_type: type[InputAgentRuntime | EffectAgentRuntime | BridgeAgentRuntime] = InputAgentRuntime,
):
    root = tmp_path / "repo"
    source = root / "src" / "Sample.java"
    source.parent.mkdir(parents=True)
    source.write_text(SOURCE, encoding="utf-8")
    index = build_repository_index(root)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    boundary = RuntimeSecurityBoundary(
        project_id="P",
        repository_identity="repo@abc",
        allowed_roots=runtime_roots(source_roots=[root], artifact_roots=[artifacts]),
    )
    adapter = RepositoryCodeQLToolAdapter(
        project_id="P",
        repository_index=index,
        security_boundary=boundary,
        codeql_ready=False,
    )
    client = MockLLMClient(responses)
    runtime = runtime_type(
        project_id="P",
        repository_index=index,
        llm_client=client,
        tool_adapter=adapter,
    )
    method = next(
        item
        for item in index.entities
        if item.kind is ProgramEntityKind.METHOD and item.simple_name == "handle"
    )
    return runtime, client, method


def _task(
    role: SpecialistRole,
    *,
    allowed_tools: tuple[str, ...] = ("INSPECT_METHOD",),
    project_id: str = "P",
    seed_entity_ids: tuple[str, ...] = (),
    known_findings: tuple[dict[str, object], ...] = (),
    max_rounds: int = 4,
    max_tools: int = 6,
    coordinator_round: int = 1,
    dispatch_index: int = 1,
) -> SpecialistTaskSpec:
    return SpecialistTaskSpec.create(
        project_id=project_id,
        specialist_agent=role,
        coordinator_round=coordinator_round,
        dispatch_index=dispatch_index,
        objective="Find one role-specific, program-grounded candidate",
        seed_entity_ids=seed_entity_ids,
        known_findings=known_findings,
        unresolved_question="Is there sufficient local program evidence?",
        allowed_tools=allowed_tools,
        remaining_specialist_budget={
            "max_internal_rounds": max_rounds,
            "max_tool_calls": max_tools,
            "max_finding_batches": 1,
        },
        provenance={"producer": "TEST_COORDINATOR", "benchmark_informed": False},
    )


def test_agent_registry_freezes_requested_models_and_identical_ids() -> None:
    assert set(M8_AGENT_REGISTRY) == {
        "coordinator_agent",
        "input_agent",
        "effect_agent",
        "semantic_bridge_agent",
    }
    assert COORDINATOR_AGENT.model_id == "claude-opus-5"
    assert {INPUT_AGENT.model_id, EFFECT_AGENT.model_id, SEMANTIC_BRIDGE_AGENT.model_id} == {
        "claude-sonnet-5"
    }
    assert all(item.id == item.name for item in M8_AGENT_REGISTRY.values())


def test_prompts_are_distinct_and_role_bounded() -> None:
    assert len({INPUT_SYSTEM_PROMPT, EFFECT_SYSTEM_PROMPT, BRIDGE_SYSTEM_PROMPT}) == 3
    assert "Do not search for effects" in INPUT_SYSTEM_PROMPT
    assert "Role: Effect Discovery Agent" in EFFECT_SYSTEM_PROMPT
    assert "Do not conduct repository-wide free search" in BRIDGE_SYSTEM_PROMPT
    assert all(
        "SUBMIT_FINDINGS" in prompt and "Candidate Path is only" in prompt
        for prompt in (INPUT_SYSTEM_PROMPT, EFFECT_SYSTEM_PROMPT, BRIDGE_SYSTEM_PROMPT)
    )
    assert (INPUT_PROMPT_VERSION, prompt_sha256(INPUT_SYSTEM_PROMPT)) == (
        "M8_INPUT_AGENT_V1",
        "5c16fc6b5337f2277ade342ba4c0b015e96e2a765cafe77f8411bbf26759320d",
    )
    assert (EFFECT_PROMPT_VERSION, prompt_sha256(EFFECT_SYSTEM_PROMPT)) == (
        "M8_EFFECT_AGENT_V1",
        "648f968268af323618c6cb8918415fe2da7dc79516139651f22a7b7839873384",
    )
    assert (BRIDGE_PROMPT_VERSION, prompt_sha256(BRIDGE_SYSTEM_PROMPT)) == (
        "M8_BRIDGE_AGENT_V1",
        "753396bfd91d9e377de253f3c0a5ca2304436f6e06e704541bded0c5971f33f6",
    )


def test_input_runtime_executes_tool_then_generates_canonical_finding(tmp_path: Path) -> None:
    runtime, client, method = _setup(tmp_path, [])

    def submit(request):
        context = request.observation["external_input_context"]
        evidence = next(
            item for item in context["recent_evidence_refs"] if method.entity_id in item["entity_ids"]
        )
        return _decision(
            "SUBMIT_FINDINGS",
            status="FINDINGS",
            findings=[
                {
                    "entity_ids": [method.entity_id],
                    "tool_call_ids": [evidence["tool_call_id"]],
                    "evidence_refs": [evidence["evidence_id"]],
                    "summary": "The inspected callback parameter is externally supplied.",
                    "details": {
                        "role": "PARAMETER",
                        "role_index": 0,
                        "inspected_context": "handle(String value)",
                        "why_externally_influenced": "The bounded fixture marks this as a callback boundary.",
                        "recommended_scope": "CALLABLE_LOCAL",
                        "codeql_corroboration": "NOT_ATTEMPTED_NO_CODEQL_IDENTITY",
                    },
                    "uncertainties": ["Framework registration is outside this fixture."],
                }
            ],
        )

    client._responses.extend(
        [
            _decision("TOOL", tool_name="INSPECT_METHOD", arguments={"entity_id": method.entity_id}),
            submit,
        ]
    )
    run = runtime.run(
        _task(SpecialistRole.INPUT, seed_entity_ids=(method.entity_id,))
    )

    assert run.result.status is SpecialistResultStatus.FINDINGS
    assert run.result.findings[0].finding_id.startswith("m8finding-")
    assert run.result.findings[0].specialist_agent is SpecialistRole.INPUT
    assert run.result.findings[0].provenance["specialist_agent"] == "input_agent"
    assert run.result.provenance["exact_model_id"] == "claude-sonnet-5"
    assert len(run.result.tool_calls) == len(client.requests) - 1 == 1
    assert len(run.result.evidence_refs) >= 1
    assert all(request.system_prompt == INPUT_SYSTEM_PROMPT for request in client.requests)
    assert "external_input_context" in run.observations[-1].payload
    assert "security_effect_context" not in run.observations[-1].payload
    assert run.observations[-1].serialized_bytes <= 16 * 1024


@pytest.mark.parametrize(
    ("runtime_type", "role", "context_key", "details"),
    [
        (
            EffectAgentRuntime,
            SpecialistRole.EFFECT,
            "security_effect_context",
            {
                "role": "CALL_RESULT",
                "effect_category": "DYNAMIC_INTERPRETATION",
                "semantic_reason": "The inspected method delegates a value to an interpreter boundary.",
                "local_code_excerpt_refs": ["fixture:3"],
                "unresolved_assumptions": ["Library implementation is not present in this fixture."],
                "proposed_scope": "CALLABLE_LOCAL",
                "codeql_corroboration": "NOT_ATTEMPTED_NO_CODEQL_IDENTITY",
            },
        ),
        (
            BridgeAgentRuntime,
            SpecialistRole.BRIDGE,
            "semantic_bridge_context",
            {
                "source": {"entity_id": "METHOD", "role": "PARAMETER", "index": 0},
                "target": {"entity_id": "METHOD", "role": "RETURN"},
                "relation_type": "WRAPPER_FLOW",
                "exact_local_scope": "CALLABLE_LOCAL",
                "structural_facts": ["The inspected body contains the local handoff."],
                "optional_codeql_evidence": [],
                "unresolved_semantics": ["Runtime library semantics remain unverified."],
                "minimality_explanation": "One callable-local argument-to-return relation.",
            },
        ),
    ],
)
def test_effect_and_bridge_runtime_emit_only_their_finding_type(
    tmp_path: Path,
    runtime_type,
    role: SpecialistRole,
    context_key: str,
    details: dict[str, object],
) -> None:
    runtime, client, method = _setup(tmp_path, [], runtime_type)
    resolved_details = {
        key: (
            {**value, "entity_id": method.entity_id}
            if isinstance(value, dict) and value.get("entity_id") == "METHOD"
            else value
        )
        for key, value in details.items()
    }

    def submit(request):
        evidence = next(
            item
            for item in request.observation[context_key]["recent_evidence_refs"]
            if method.entity_id in item["entity_ids"]
        )
        return _decision(
            "SUBMIT_FINDINGS",
            status="FINDINGS",
            findings=[
                {
                    "entity_ids": [method.entity_id],
                    "tool_call_ids": [evidence["tool_call_id"]],
                    "evidence_refs": [evidence["evidence_id"]],
                    "summary": "One bounded role-specific finding.",
                    "details": resolved_details,
                    "uncertainties": ["The fixture proves only a local program fact."],
                }
            ],
        )

    client._responses.extend(
        [
            _decision("TOOL", tool_name="INSPECT_METHOD", arguments={"entity_id": method.entity_id}),
            submit,
        ]
    )
    known = ()
    if role is SpecialistRole.BRIDGE:
        known = (
            {"finding_id": "input-1", "finding_type": "INPUT_FINDING"},
            {"finding_id": "effect-1", "finding_type": "EFFECT_FINDING"},
        )
    run = runtime.run(
        _task(
            role,
            seed_entity_ids=(method.entity_id,),
            known_findings=known,
        )
    )
    assert run.result.status is SpecialistResultStatus.FINDINGS
    assert run.result.findings[0].finding_type.value == {
        SpecialistRole.EFFECT: "EFFECT_FINDING",
        SpecialistRole.BRIDGE: "BRIDGE_FINDING",
    }[role]


def test_fabricated_finding_evidence_fails_closed(tmp_path: Path) -> None:
    runtime, _, method = _setup(
        tmp_path,
        [
            _decision(
                "SUBMIT_FINDINGS",
                status="FINDINGS",
                findings=[
                    {
                        "entity_ids": ["entity-000000000000000000000000"],
                        "tool_call_ids": ["invented-tool"],
                        "evidence_refs": ["invented-evidence"],
                        "summary": "Fabricated",
                        "details": {
                            "role": "PARAMETER",
                            "role_index": 0,
                            "inspected_context": "none",
                            "why_externally_influenced": "none",
                            "recommended_scope": "CALLABLE_LOCAL",
                            "codeql_corroboration": "none",
                        },
                        "uncertainties": [],
                    }
                ],
            )
        ],
    )
    run = runtime.run(_task(SpecialistRole.INPUT, seed_entity_ids=(method.entity_id,)))
    assert run.result.status is SpecialistResultStatus.FAILED
    assert run.failures[0].failure_class == "MODEL_OUTPUT_INVALID"
    assert not run.result.findings


@pytest.mark.parametrize(
    ("runtime_type", "role", "prompt", "context_key"),
    [
        (InputAgentRuntime, SpecialistRole.INPUT, INPUT_SYSTEM_PROMPT, "external_input_context"),
        (EffectAgentRuntime, SpecialistRole.EFFECT, EFFECT_SYSTEM_PROMPT, "security_effect_context"),
    ],
)
def test_roles_receive_only_their_prompt_and_observation(
    tmp_path: Path,
    runtime_type,
    role: SpecialistRole,
    prompt: str,
    context_key: str,
) -> None:
    runtime, client, method = _setup(
        tmp_path,
        [_decision("STOP", status="NO_SUPPORTED_FINDING")],
        runtime_type,
    )
    run = runtime.run(_task(role, seed_entity_ids=(method.entity_id,)))
    assert run.result.status is SpecialistResultStatus.NO_SUPPORTED_FINDING
    assert client.requests[0].system_prompt == prompt
    assert context_key in client.requests[0].observation
    other = {
        "external_input_context",
        "security_effect_context",
        "semantic_bridge_context",
    } - {context_key}
    assert other.isdisjoint(client.requests[0].observation)


def test_bridge_observation_separates_existing_input_and_effect_findings(tmp_path: Path) -> None:
    runtime, client, method = _setup(
        tmp_path,
        [_decision("STOP", status="NEED_MORE_EVIDENCE")],
        BridgeAgentRuntime,
    )
    known = (
        {"finding_id": "input-1", "finding_type": "INPUT_FINDING", "entity_ids": [method.entity_id]},
        {"finding_id": "effect-1", "finding_type": "EFFECT_FINDING", "entity_ids": [method.entity_id]},
    )
    run = runtime.run(
        _task(
            SpecialistRole.BRIDGE,
            allowed_tools=("CODEQL_LOCAL_FLOW",),
            seed_entity_ids=(method.entity_id,),
            known_findings=known,
        )
    )
    context = client.requests[0].observation["semantic_bridge_context"]
    assert [item["finding_id"] for item in context["input_findings"]] == ["input-1"]
    assert [item["finding_id"] for item in context["effect_findings"]] == ["effect-1"]
    assert run.result.status is SpecialistResultStatus.NEED_MORE_EVIDENCE


def test_bridge_rejects_free_search_and_missing_anchor_findings(tmp_path: Path) -> None:
    runtime, _, method = _setup(
        tmp_path,
        [_decision("STOP", status="NO_SUPPORTED_FINDING")],
        BridgeAgentRuntime,
    )
    with pytest.raises(ValueError, match="role allow-list"):
        runtime.run(
            _task(
                SpecialistRole.BRIDGE,
                allowed_tools=("SEARCH_CODE",),
                seed_entity_ids=(method.entity_id,),
                known_findings=(
                    {"finding_id": "input-1", "finding_type": "INPUT_FINDING"},
                    {"finding_id": "effect-1", "finding_type": "EFFECT_FINDING"},
                ),
            )
        )
    assert "SEARCH_CODE" not in BRIDGE_ALLOWED_TOOLS
    with pytest.raises(ValueError, match="requires existing input and effect"):
        runtime.run(
            _task(
                SpecialistRole.BRIDGE,
                allowed_tools=("CODEQL_LOCAL_FLOW",),
                seed_entity_ids=(method.entity_id,),
            )
        )


def test_model_cannot_use_a_tool_omitted_from_taskspec(tmp_path: Path) -> None:
    runtime, _, method = _setup(
        tmp_path,
        [_decision("TOOL", tool_name="SEARCH_CODE", arguments={"query": "helper"})],
    )
    run = runtime.run(
        _task(
            SpecialistRole.INPUT,
            allowed_tools=("INSPECT_METHOD",),
            seed_entity_ids=(method.entity_id,),
        )
    )
    assert run.result.status is SpecialistResultStatus.FAILED
    assert run.failures[0].failure_class == "MODEL_OUTPUT_INVALID"
    assert not run.result.tool_calls


def test_runtime_rejects_cross_project_task_and_adapter(tmp_path: Path) -> None:
    runtime, _, method = _setup(
        tmp_path,
        [_decision("STOP", status="NO_SUPPORTED_FINDING")],
    )
    with pytest.raises(ValueError, match="cross-project"):
        runtime.run(
            _task(
                SpecialistRole.INPUT,
                project_id="OTHER",
                seed_entity_ids=(method.entity_id,),
            )
        )


def test_runtime_rejects_real_client_with_wrong_role_model(tmp_path: Path) -> None:
    runtime, _, _ = _setup(tmp_path, [])

    class WrongModelClient:
        config = SimpleNamespace(model_id="claude-opus-5")

        def complete(self, request):  # pragma: no cover - constructor rejects first
            raise AssertionError(request)

    with pytest.raises(ValueError, match="frozen role assignment"):
        InputAgentRuntime(
            project_id="P",
            repository_index=runtime.repository_index,
            llm_client=WrongModelClient(),
            tool_adapter=runtime.tool_adapter,
        )


def test_repeated_tool_calls_in_separate_dispatches_have_distinct_ids(tmp_path: Path) -> None:
    runtime, client, method = _setup(tmp_path, [])
    scripted = [
        _decision("TOOL", tool_name="INSPECT_METHOD", arguments={"entity_id": method.entity_id}),
        _decision("STOP", status="NO_SUPPORTED_FINDING"),
    ]
    client._responses.extend(scripted + scripted)
    first = runtime.run(
        _task(SpecialistRole.INPUT, seed_entity_ids=(method.entity_id,), dispatch_index=1)
    )
    second = runtime.run(
        _task(SpecialistRole.INPUT, seed_entity_ids=(method.entity_id,), dispatch_index=2)
    )
    assert first.result.tool_calls[0]["action_id"] != second.result.tool_calls[0]["action_id"]
    assert first.result.tool_calls[0]["tool_call_id"] != second.result.tool_calls[0]["tool_call_id"]


def test_tool_budget_stops_before_second_execution(tmp_path: Path) -> None:
    runtime, client, method = _setup(tmp_path, [])
    client._responses.extend(
        [
            _decision("TOOL", tool_name="INSPECT_METHOD", arguments={"entity_id": method.entity_id}),
            _decision("TOOL", tool_name="INSPECT_METHOD", arguments={"entity_id": method.entity_id}),
        ]
    )
    run = runtime.run(
        _task(
            SpecialistRole.INPUT,
            seed_entity_ids=(method.entity_id,),
            max_rounds=2,
            max_tools=1,
        )
    )
    assert run.result.status is SpecialistResultStatus.BUDGET_EXHAUSTED
    assert run.result.tool_calls_used == 1
    assert len(run.model_responses) == 2


def test_codeql_unavailable_is_observed_but_not_converted_to_negative_evidence(tmp_path: Path) -> None:
    runtime, client, method = _setup(
        tmp_path,
        [
            _decision("TOOL", tool_name="CODEQL_ENTITY_FACTS", arguments={"entity_id": "placeholder"}),
            _decision(
                "STOP",
                status="NEED_MORE_EVIDENCE",
                uncertainty=["CodeQL is unavailable; absence was not inferred."],
            ),
        ],
    )
    first = client._responses[0]
    assert isinstance(first, dict)
    first["arguments"] = {"entity_id": method.entity_id}
    run = runtime.run(
        _task(
            SpecialistRole.INPUT,
            allowed_tools=("CODEQL_ENTITY_FACTS",),
            seed_entity_ids=(method.entity_id,),
        )
    )
    assert run.result.status is SpecialistResultStatus.NEED_MORE_EVIDENCE
    assert run.result.tool_calls[0]["status"] == "UNAVAILABLE"
    assert run.result.evidence_refs == ()
    assert client.requests[1].observation["runtime_rules"]["codeql_unavailable_is_negative"] is False
