"""Non-benchmark controlled M7 smoke used before the real kill test.

The scripted reasoner learns EvidenceRef identifiers only from prior tool
observations. No evidence or graph edge is preloaded into Agent state: a path
is possible only after search, inspection, and three gated proposals.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

from java_vuln_research.work1_agent.proposal import (
    EntityRole,
    EntityRoleRef,
    EvidenceGate,
    ProposalScope,
    ProposalType,
    ScopeKind,
    SecurityProposal,
)
from java_vuln_research.work1_agent.proposal.model import canonical_json
from java_vuln_research.work1_agent.repository.entity import ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import build_repository_index

from .actions import ActionType, StopReason
from .controller import AgentController
from .graph_adapter import AgentGraphPathAdapter
from .llm_client import (
    AnthropicMessagesLLMClient,
    LLMAPIProtocol,
    LLMClient,
    LLMClientConfig,
    LLMRequest,
    MockLLMClient,
    OpenAICompatibleLLMClient,
)
from .parser import StrictActionParser
from .prompt import build_system_prompt, prompt_sha256
from .observation import bounded_tool_catalog
from .runtime import write_controller_artifacts
from .security_boundary import RuntimeInputKind, RuntimeSecurityBoundary, runtime_roots
from .state import AgentState
from .tool_adapter import RepositoryCodeQLToolAdapter


def _decision(proposal: SecurityProposal | None = None, *, stop: StopReason | None = None) -> dict[str, object]:
    return {
        "action_type": "PROPOSE" if proposal else "STOP",
        "arguments": {},
        "proposal": proposal.to_dict() if proposal else None,
        "stop_reason": stop.value if stop else None,
        "reason": "Controlled evidence-only exploration.",
    }


def _tool_decision(action_type: ActionType, arguments: Mapping[str, object]) -> dict[str, object]:
    return {
        "action_type": action_type.value,
        "arguments": dict(arguments),
        "proposal": None,
        "stop_reason": None,
        "reason": "Collect bounded program evidence before proposing semantics.",
    }


def _observed_evidence(
    request: LLMRequest,
    *,
    entity_ids: Sequence[str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Select only EvidenceRefs exposed in model-visible prior feedback."""

    wanted = set(entity_ids)
    evidence_ids: list[str] = []
    tool_call_ids: list[str] = []
    feedback = request.observation.get("recent_feedback", ())
    if not isinstance(feedback, Sequence):
        raise ValueError("controlled observation lacks recent_feedback")
    for item in feedback:
        if not isinstance(item, Mapping):
            continue
        for evidence in item.get("evidence_refs", ()):
            if not isinstance(evidence, Mapping):
                continue
            grounded = {str(value) for value in evidence.get("entity_ids", ())}
            if not grounded.intersection(wanted):
                continue
            evidence_ids.append(str(evidence["evidence_id"]))
            if evidence.get("tool_call_id"):
                tool_call_ids.append(str(evidence["tool_call_id"]))
    if not evidence_ids:
        raise ValueError("controlled reasoner could not find model-visible evidence for requested entities")
    return tuple(dict.fromkeys(evidence_ids)), tuple(dict.fromkeys(tool_call_ids))


def _proposal_factory(
    *,
    proposal_type: ProposalType,
    subject: EntityRoleRef,
    scope: ProposalScope,
    evidence_entity_ids: Sequence[str],
    reason: str,
    semantic_category: str | None = None,
    source: EntityRoleRef | None = None,
    target: EntityRoleRef | None = None,
) -> Callable[[LLMRequest], dict[str, object]]:
    def decide(request: LLMRequest) -> dict[str, object]:
        evidence_ids, tool_call_ids = _observed_evidence(request, entity_ids=evidence_entity_ids)
        proposal = SecurityProposal.create(
            proposal_type=proposal_type,
            subject=subject,
            source=source,
            target=target,
            scope=scope,
            semantic_category=semantic_category,
            evidence_refs=evidence_ids,
            reason=reason,
            model_confidence=0.8,
            provenance={
                "producer": "M7_CONTROLLED_REASONER",
                "round": request.round,
                "originating_tool_call_ids": list(tool_call_ids),
                "benchmark_informed": False,
                "allowed_for_agent_runtime": True,
            },
        )
        return _decision(proposal)

    return decide


def run_controlled_smoke(*, repository_root: Path, schema_root: Path, artifact_root: Path, git_sha: str) -> dict[str, object]:
    index = build_repository_index(repository_root)
    pipeline = next(item for item in index.entities if item.kind is ProgramEntityKind.METHOD and item.simple_name == "controlledPipeline")
    pipeline_identity = "com.example.ControlledSecurityCases.controlledPipeline(String)"
    input_call = next(
        item
        for item in index.entities
        if item.kind is ProgramEntityKind.CALL
        and item.simple_name == "customExternalInput"
        and item.enclosing_callable == pipeline_identity
    )
    effect_call = next(
        item
        for item in index.entities
        if item.kind is ProgramEntityKind.CALL
        and item.simple_name == "customSecurityEffect"
        and item.enclosing_callable == pipeline_identity
    )
    input_ref = EntityRoleRef(input_call.entity_id, EntityRole.CALL_RESULT)
    effect_ref = EntityRoleRef(effect_call.entity_id, EntityRole.ARGUMENT, 0)
    input_scope = ProposalScope(ScopeKind.ENTITY, (input_call.entity_id,), "CONTROLLED")
    relation_scope = ProposalScope(
        ScopeKind.CALLABLE,
        (pipeline.entity_id, input_call.entity_id, effect_call.entity_id),
        "CONTROLLED",
    )
    effect_scope = ProposalScope(ScopeKind.ENTITY, (effect_call.entity_id,), "CONTROLLED")
    output = artifact_root / "CONTROLLED"
    output.mkdir(parents=True, exist_ok=True)
    boundary = RuntimeSecurityBoundary(project_id="CONTROLLED", repository_identity="controlled@" + git_sha, allowed_roots=runtime_roots(source_roots=[repository_root], artifact_roots=[artifact_root], schema_roots=[schema_root]))
    for source in sorted(repository_root.rglob("*.java")):
        boundary.read_bytes(source, kind=RuntimeInputKind.JAVA_SOURCE, logical_name="java:" + source.relative_to(repository_root).as_posix())
    gate = EvidenceGate(repository_root=repository_root, entities=index.entities, evidence_catalog={})
    graph_adapter = AgentGraphPathAdapter(project_id="CONTROLLED", entities=index.entities, evidence_gate=gate, git_sha=git_sha)
    state = AgentState.create(project_id="CONTROLLED", repository_identity="controlled@" + git_sha, provenance={"producer": "M7_CONTROLLED", "benchmark_informed": False})
    responses = [
        _tool_decision(ActionType.SEARCH_SYMBOLS, {"query": "controlledPipeline", "max_hits": 30}),
        _tool_decision(ActionType.INSPECT_METHOD, {"entity_id": pipeline.entity_id, "context_lines": 0}),
        _proposal_factory(
            proposal_type=ProposalType.EXTERNAL_INPUT,
            subject=input_ref,
            scope=input_scope,
            evidence_entity_ids=(input_call.entity_id, pipeline.entity_id),
            semantic_category="UNKNOWN",
            reason="The inspected controlled pipeline exposes one bounded input hypothesis.",
        ),
        _proposal_factory(
            proposal_type=ProposalType.LIBRARY_FLOW,
            subject=input_ref,
            source=input_ref,
            target=effect_ref,
            scope=relation_scope,
            evidence_entity_ids=(pipeline.entity_id, input_call.entity_id, effect_call.entity_id),
            reason="The inspected local assignment and following call support one bounded propagation hypothesis.",
        ),
        _proposal_factory(
            proposal_type=ProposalType.SECURITY_EFFECT,
            subject=effect_ref,
            scope=effect_scope,
            evidence_entity_ids=(effect_call.entity_id, pipeline.entity_id),
            semantic_category="UNKNOWN",
            reason="The inspected controlled pipeline exposes one bounded effect hypothesis.",
        ),
        _decision(stop=StopReason.PATH_FORMED),
    ]
    controller = AgentController(
        state=state,
        repository_index=index,
        codeql_status={"project_id": "CONTROLLED", "ready": False, "status": "UNAVAILABLE"},
        llm_client=MockLLMClient(responses),
        parser=StrictActionParser(schema_root),
        tool_adapter=RepositoryCodeQLToolAdapter(project_id="CONTROLLED", repository_index=index, security_boundary=boundary),
        evidence_gate=gate,
        graph_path_adapter=graph_adapter,
    )
    result = controller.run()
    input_manifest = boundary.seal()
    boundary.audit()
    prompt = build_system_prompt(bounded_tool_catalog())
    audit = write_controller_artifacts(result, output, run_manifest={"run_kind": "CONTROLLED_DETERMINISTIC_MOCK", "git_sha": git_sha, "repository_revision": git_sha, "model_provider": "deterministic-mock", "exact_model_id": "m7-mock-v1", "system_prompt_sha256": prompt_sha256(prompt), "benchmark_informed": False}, input_manifest=input_manifest)
    summary = {
        **result.summary(),
        "tool_sequence": [item.tool_name for item in result.tool_results],
        "proposal_sequence": [item.proposal_type.value for item in result.proposals],
        "gate_status_sequence": [item.status.value for item in result.gate_results],
        "candidate_path_count": len(result.state.active_candidate_path_ids),
        "artifact_root": str(output),
        "artifact_audit_pass": audit["required_files_present"],
        "no_leakage_pass": audit["no_leakage_pass"],
    }
    (artifact_root / "aggregate_summary.json").write_text(canonical_json(summary) + "\n", encoding="utf-8")
    (artifact_root / "no_leakage_audit.json").write_text(canonical_json(input_manifest) + "\n", encoding="utf-8")
    return summary


def run_controlled_real_llm_smoke(
    *,
    repository_root: Path,
    schema_root: Path,
    artifact_root: Path,
    git_sha: str,
    config: LLMClientConfig | None = None,
    llm_client: LLMClient | None = None,
) -> dict[str, object]:
    """Run the same non-benchmark fixture with an environment-backed reasoner."""

    resolved_config = config or LLMClientConfig.from_environment()
    client = llm_client or (
        AnthropicMessagesLLMClient(resolved_config)
        if resolved_config.api_protocol is LLMAPIProtocol.ANTHROPIC
        else OpenAICompatibleLLMClient(resolved_config)
    )
    index = build_repository_index(repository_root)
    output = artifact_root / "CONTROLLED_REAL_LLM"
    output.mkdir(parents=True, exist_ok=True)
    boundary = RuntimeSecurityBoundary(
        project_id="CONTROLLED",
        repository_identity="controlled-real@" + git_sha,
        allowed_roots=runtime_roots(
            source_roots=[repository_root],
            artifact_roots=[artifact_root],
            schema_roots=[schema_root],
        ),
    )
    for source_path in sorted(repository_root.rglob("*.java")):
        boundary.read_bytes(
            source_path,
            kind=RuntimeInputKind.JAVA_SOURCE,
            logical_name="java:" + source_path.relative_to(repository_root).as_posix(),
        )
    gate = EvidenceGate(repository_root=repository_root, entities=index.entities, evidence_catalog={})
    graph_adapter = AgentGraphPathAdapter(
        project_id="CONTROLLED",
        entities=index.entities,
        evidence_gate=gate,
        git_sha=git_sha,
    )
    state = AgentState.create(
        project_id="CONTROLLED",
        repository_identity="controlled-real@" + git_sha,
        provenance={"producer": "M7_CONTROLLED_REAL_LLM", "benchmark_informed": False},
    )
    controller = AgentController(
        state=state,
        repository_index=index,
        codeql_status={"project_id": "CONTROLLED", "ready": False, "status": "UNAVAILABLE"},
        llm_client=client,
        parser=StrictActionParser(schema_root),
        tool_adapter=RepositoryCodeQLToolAdapter(
            project_id="CONTROLLED",
            repository_index=index,
            security_boundary=boundary,
        ),
        evidence_gate=gate,
        graph_path_adapter=graph_adapter,
    )
    result = controller.run()
    input_manifest = boundary.seal()
    boundary.audit()
    prompt = build_system_prompt(bounded_tool_catalog())
    audit = write_controller_artifacts(
        result,
        output,
        run_manifest={
            "run_kind": "CONTROLLED_REAL_LLM",
            "git_sha": git_sha,
            "repository_revision": git_sha,
            **resolved_config.to_manifest_dict(),
            "system_prompt_sha256": prompt_sha256(prompt),
            "benchmark_informed": False,
        },
        input_manifest=input_manifest,
    )
    summary = {
        **result.summary(),
        "candidate_path_count": len(result.state.active_candidate_path_ids),
        "artifact_root": str(output),
        "artifact_audit_pass": audit["required_files_present"],
        "no_leakage_pass": audit["no_leakage_pass"],
        "model_configuration": resolved_config.to_manifest_dict(),
    }
    (artifact_root / "real_llm_summary.json").write_text(canonical_json(summary) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--mode", choices=("deterministic-mock", "real-llm"), default="deterministic-mock")
    args = parser.parse_args()
    runner = run_controlled_real_llm_smoke if args.mode == "real-llm" else run_controlled_smoke
    print(canonical_json(runner(repository_root=args.repository_root, schema_root=args.schema_root, artifact_root=args.artifact_root, git_sha=args.git_sha)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
