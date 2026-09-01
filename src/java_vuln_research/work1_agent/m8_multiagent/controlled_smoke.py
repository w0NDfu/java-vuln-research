"""Non-benchmark M8 controlled multi-agent smoke and audited artifacts."""

from __future__ import annotations

import argparse
import hashlib
import os
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from java_vuln_research.work1_agent.agent import (
    AgentGraphPathAdapter,
    AgentGraphRelation,
    AnthropicMessagesLLMClient,
    LLMAPIProtocol,
    LLMClient,
    LLMClientConfig,
    MockLLMClient,
    OpenAICompatibleLLMClient,
    RepositoryCodeQLToolAdapter,
    RuntimeInputKind,
    RuntimeSecurityBoundary,
    StopReason,
    StructuredOutputMode,
    bounded_tool_catalog,
    runtime_roots,
)
from java_vuln_research.work1_agent.hybrid_graph import RelationKind, SearchLimits, SupportClass
from java_vuln_research.work1_agent.proposal import (
    EntityRole,
    EntityRoleRef,
    EvidenceGate,
    EvidenceRef,
    EvidenceSourceKind,
    EvidenceStrength,
    ProposalType,
    SecurityProposal,
)
from java_vuln_research.work1_agent.proposal.model import canonical_json
from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind
from java_vuln_research.work1_agent.repository.indexer import RepositoryIndex, build_repository_index

from .agent_registry import COORDINATOR_AGENT, M8_AGENT_REGISTRY
from .board import SharedEvidenceBoard
from .contracts import SpecialistRole
from .coordinator import CoordinatorRunResult, CoordinatorRuntime
from .prompts import (
    BRIDGE_PROMPT_VERSION,
    BRIDGE_SYSTEM_PROMPT,
    COORDINATOR_PROMPT_VERSION,
    COORDINATOR_SYSTEM_PROMPT,
    EFFECT_PROMPT_VERSION,
    EFFECT_SYSTEM_PROMPT,
    INPUT_PROMPT_VERSION,
    INPUT_SYSTEM_PROMPT,
    prompt_sha256,
)
from .scope_helper import build_valid_scope
from .scope_helper import SCOPE_HELPER_VERSION
from .role_helper import ROLE_HELPER_VERSION
from .specialists import BridgeAgentRuntime, EffectAgentRuntime, InputAgentRuntime


CONTROLLED_PROJECT_ID = "CONTROLLED_M8"
CONTROLLED_PRODUCER = "M8_CONTROLLED_SMOKE_V1"
COORDINATOR_ENV_PREFIX = "M8_COORDINATOR_LLM_"
SPECIALIST_ENV_PREFIX = "M8_SPECIALIST_LLM_"

ARTIFACT_FILES = (
    "runtime_input_manifest.json",
    "coordinator_trace.jsonl",
    "specialist_traces/input_agent.jsonl",
    "specialist_traces/effect_agent.jsonl",
    "specialist_traces/semantic_bridge_agent.jsonl",
    "tool_calls.jsonl",
    "evidence_refs.jsonl",
    "input_findings.jsonl",
    "effect_findings.jsonl",
    "bridge_findings.jsonl",
    "proposals.jsonl",
    "gate_results.jsonl",
    "graph_nodes.jsonl",
    "graph_edges.jsonl",
    "candidate_paths.jsonl",
    "path_diagnostics.jsonl",
    "board_events.jsonl",
    "evidence_board.json",
    "failure_taxonomy.json",
    "summary.json",
    "no_leakage_audit.json",
    "manifest.json",
    "artifact_audit.json",
)


def _jsonl(values: Iterable[Mapping[str, Any]]) -> str:
    return "".join(canonical_json(dict(item)) + "\n" for item in values)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _value_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _prepare_output(output: Path) -> None:
    if output.exists() and any(output.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty M8 artifact root: {output}")
    output.mkdir(parents=True, exist_ok=True)


def _client(config: LLMClientConfig) -> LLMClient:
    if config.api_protocol is LLMAPIProtocol.ANTHROPIC:
        return AnthropicMessagesLLMClient(config)
    return OpenAICompatibleLLMClient(config)


@dataclass(frozen=True, slots=True)
class M8ModelConfigs:
    coordinator: LLMClientConfig
    specialist: LLMClientConfig

    def __post_init__(self) -> None:
        if self.coordinator.model_id != COORDINATOR_AGENT.model_id:
            raise ValueError("M8 Coordinator exact model must be claude-opus-5")
        if self.specialist.model_id != "claude-sonnet-5":
            raise ValueError("M8 specialist exact model must be claude-sonnet-5")
        for config in (self.coordinator, self.specialist):
            if config.endpoint_url is None:
                raise ValueError("M8 real smoke requires an exact endpoint URL")
            if config.temperature != 0 or config.seed is not None:
                raise ValueError("M8 real smoke freezes temperature=0 and seed omitted")
            if config.structured_output_mode is not StructuredOutputMode.JSON_OBJECT:
                raise ValueError("M8 role-specific JSON contracts require JSON_OBJECT mode")

    @classmethod
    def from_environment(cls, env: Mapping[str, str] | None = None) -> "M8ModelConfigs":
        return cls(
            coordinator=LLMClientConfig.from_environment(env, prefix=COORDINATOR_ENV_PREFIX),
            specialist=LLMClientConfig.from_environment(env, prefix=SPECIALIST_ENV_PREFIX),
        )

    def to_manifest_dict(self) -> dict[str, Any]:
        return {
            "coordinator": self.coordinator.to_manifest_dict(),
            "specialists": self.specialist.to_manifest_dict(),
        }


def _method(index: RepositoryIndex, name: str) -> ProgramEntity:
    matches = [
        item
        for item in index.entities
        if item.kind is ProgramEntityKind.METHOD and item.simple_name == name
    ]
    if len(matches) != 1:
        raise ValueError(f"controlled fixture requires exactly one method named {name}")
    return matches[0]


def _controlled_graph(
    index: RepositoryIndex,
) -> tuple[tuple[EvidenceRef, ...], tuple[AgentGraphRelation, ...]]:
    """Build fixture-only structural edges; never used by development/formal runs."""

    receive = _method(index, "receive")
    carry = _method(index, "carry")
    persist = _method(index, "persist")
    left = EvidenceRef.create(
        source_kind=EvidenceSourceKind.SOURCE_SNIPPET,
        entity_ids=(receive.entity_id, carry.entity_id),
        confidence=EvidenceStrength.DIRECT,
        repository_relative_path=receive.repository_relative_path,
        start_line=receive.start_line,
        end_line=receive.end_line,
        provenance={
            "producer": CONTROLLED_PRODUCER,
            "controlled_fixture_only": True,
            "benchmark_informed": False,
        },
    )
    right = EvidenceRef.create(
        source_kind=EvidenceSourceKind.SOURCE_SNIPPET,
        entity_ids=(carry.entity_id, persist.entity_id),
        confidence=EvidenceStrength.DIRECT,
        repository_relative_path=receive.repository_relative_path,
        start_line=receive.start_line,
        end_line=receive.end_line,
        provenance={
            "producer": CONTROLLED_PRODUCER,
            "controlled_fixture_only": True,
            "benchmark_informed": False,
        },
    )
    relations = (
        AgentGraphRelation(
            source_ref=EntityRoleRef(receive.entity_id, EntityRole.PARAMETER, 0),
            target_ref=EntityRoleRef(carry.entity_id, EntityRole.PARAMETER, 0),
            relation_kind=RelationKind.LEXICAL_CALL,
            support_class=SupportClass.STRUCTURAL_EVIDENCE,
            evidence_refs=(left.evidence_id,),
            repository_relation_ids=("controlled-receive-carry",),
            provenance={
                "producer": CONTROLLED_PRODUCER,
                "controlled_fixture_only": True,
                "benchmark_informed": False,
            },
        ),
        AgentGraphRelation(
            source_ref=EntityRoleRef(carry.entity_id, EntityRole.RETURN),
            target_ref=EntityRoleRef(persist.entity_id, EntityRole.PARAMETER, 0),
            relation_kind=RelationKind.LEXICAL_CALL,
            support_class=SupportClass.STRUCTURAL_EVIDENCE,
            evidence_refs=(right.evidence_id,),
            repository_relation_ids=("controlled-carry-persist",),
            provenance={
                "producer": CONTROLLED_PRODUCER,
                "controlled_fixture_only": True,
                "benchmark_informed": False,
            },
        ),
    )
    return (left, right), relations


def _repository_summary(index: RepositoryIndex, git_sha: str) -> dict[str, Any]:
    kinds = Counter(item.kind.value for item in index.entities)
    packages = sorted(
        {
            item.qualified_name
            for item in index.entities
            if item.kind is ProgramEntityKind.PACKAGE
        }
    )
    top_level = [
        {
            "entity_id": item.entity_id,
            "kind": item.kind.value,
            "simple_name": item.simple_name,
            "qualified_name": item.qualified_name,
            "signature": item.signature,
            "repository_relative_path": item.repository_relative_path,
            "start_line": item.start_line,
            "end_line": item.end_line,
        }
        for item in index.sorted_entities()
        if item.kind in {ProgramEntityKind.TYPE, ProgramEntityKind.METHOD}
    ][:16]
    return {
        "project_id": CONTROLLED_PROJECT_ID,
        "repository_identity": f"m8-controlled@{git_sha}",
        "java_file_count": len({item.repository_relative_path for item in index.entities}),
        "program_entity_count": len(index.entities),
        "entity_kind_counts": dict(sorted(kinds.items())),
        "top_packages": packages[:10],
        "top_level_entities": top_level,
        "benchmark_informed": False,
    }


def _build_runtime(
    *,
    repository_root: Path,
    schema_root: Path,
    artifact_root: Path,
    git_sha: str,
    coordinator_client: LLMClient,
    specialist_clients: Mapping[SpecialistRole, LLMClient],
) -> tuple[CoordinatorRuntime, RuntimeSecurityBoundary, tuple[EvidenceRef, ...]]:
    boundary = RuntimeSecurityBoundary(
        project_id=CONTROLLED_PROJECT_ID,
        repository_identity=f"m8-controlled@{git_sha}",
        allowed_roots=runtime_roots(
            source_roots=[repository_root],
            artifact_roots=[artifact_root],
            schema_roots=[schema_root],
        ),
    )
    for source in sorted(repository_root.rglob("*.java")):
        boundary.read_bytes(
            source,
            kind=RuntimeInputKind.JAVA_SOURCE,
            logical_name="java:" + source.relative_to(repository_root).as_posix(),
        )
    for schema in sorted(schema_root.glob("*.schema.json")):
        boundary.read_bytes(
            schema,
            kind=RuntimeInputKind.TRUSTED_SCHEMA,
            logical_name="schema:" + schema.name,
        )
    index = build_repository_index(repository_root)
    fixture_evidence, base_relations = _controlled_graph(index)
    gate = EvidenceGate(
        repository_root=repository_root,
        entities=index.entities,
        evidence_catalog={item.evidence_id: item for item in fixture_evidence},
    )
    adapter = RepositoryCodeQLToolAdapter(
        project_id=CONTROLLED_PROJECT_ID,
        repository_index=index,
        security_boundary=boundary,
        codeql_ready=False,
    )
    graph = AgentGraphPathAdapter(
        project_id=CONTROLLED_PROJECT_ID,
        entities=index.entities,
        evidence_gate=gate,
        base_relations=base_relations,
        git_sha=git_sha,
    )
    board = SharedEvidenceBoard.create(
        project_id=CONTROLLED_PROJECT_ID,
        repository_summary=_repository_summary(index, git_sha),
        codeql_status={
            "project_id": CONTROLLED_PROJECT_ID,
            "ready": False,
            "status": "UNAVAILABLE",
            "failure_reason": "Controlled fixture has no CodeQL database; absence is not inferred.",
        },
        budget_state={"coordinator_rounds_remaining": 12},
        round_state={"coordinator_round": 0},
        unresolved_questions=(
            "Find one program-grounded input, effect, and minimal bridge in this non-benchmark controlled repository.",
        ),
    )
    specialist_runtimes = {
        SpecialistRole.INPUT: InputAgentRuntime(
            project_id=CONTROLLED_PROJECT_ID,
            repository_index=index,
            llm_client=specialist_clients[SpecialistRole.INPUT],
            tool_adapter=adapter,
        ),
        SpecialistRole.EFFECT: EffectAgentRuntime(
            project_id=CONTROLLED_PROJECT_ID,
            repository_index=index,
            llm_client=specialist_clients[SpecialistRole.EFFECT],
            tool_adapter=adapter,
        ),
        SpecialistRole.BRIDGE: BridgeAgentRuntime(
            project_id=CONTROLLED_PROJECT_ID,
            repository_index=index,
            llm_client=specialist_clients[SpecialistRole.BRIDGE],
            tool_adapter=adapter,
        ),
    }
    runtime = CoordinatorRuntime(
        project_id=CONTROLLED_PROJECT_ID,
        repository_index=index,
        board=board,
        llm_client=coordinator_client,
        specialist_runtimes=specialist_runtimes,
        tool_adapter=adapter,
        evidence_gate=gate,
        graph_path_adapter=graph,
    )
    return runtime, boundary, fixture_evidence


def _decision(
    action_type: str,
    *,
    arguments: Mapping[str, Any] | None = None,
    proposal: Mapping[str, Any] | None = None,
    findings: Sequence[str] = (),
    stop_reason: str | None = None,
) -> dict[str, Any]:
    return {
        "action_type": action_type,
        "arguments": dict(arguments or {}),
        "proposal": dict(proposal) if proposal is not None else None,
        "supporting_finding_ids": list(findings),
        "stop_reason": stop_reason,
        "reason": "Choose one bounded controlled-smoke action from current evidence.",
    }


def _specialist_decision(
    action_type: str,
    *,
    tool_name: str | None = None,
    arguments: Mapping[str, Any] | None = None,
    findings: Sequence[Mapping[str, Any]] = (),
    status: str | None = None,
) -> dict[str, Any]:
    return {
        "action_type": action_type,
        "tool_name": tool_name,
        "arguments": dict(arguments or {}),
        "findings": [dict(item) for item in findings],
        "status": status,
        "next_suggested_evidence": [],
        "uncertainty": [],
        "reason": "Use one bounded controlled repository fact.",
    }


def _deterministic_clients(index: RepositoryIndex) -> tuple[LLMClient, Mapping[SpecialistRole, LLMClient]]:
    receive = _method(index, "receive")
    carry = _method(index, "carry")
    persist = _method(index, "persist")

    def finding_submit(role: SpecialistRole, entity: ProgramEntity) -> Callable[[Any], Mapping[str, Any]]:
        def submit(request: Any) -> Mapping[str, Any]:
            context_key = {
                SpecialistRole.INPUT: "external_input_context",
                SpecialistRole.EFFECT: "security_effect_context",
                SpecialistRole.BRIDGE: "semantic_bridge_context",
            }[role]
            evidence = next(
                item
                for item in request.observation[context_key]["recent_evidence_refs"]
                if entity.entity_id in item["entity_ids"]
            )
            if role is SpecialistRole.INPUT:
                details = {
                    "role": "PARAMETER",
                    "role_index": 0,
                    "inspected_context": "@RequestBoundary receive(String requestPath)",
                    "why_externally_influenced": "The inspected controlled boundary supplies parameter 0.",
                    "recommended_scope": "ENTITY_LOCAL",
                    "codeql_corroboration": "UNAVAILABLE_NOT_NEGATIVE",
                }
            elif role is SpecialistRole.EFFECT:
                details = {
                    "role": "PARAMETER",
                    "effect_category": "FILESYSTEM",
                    "semantic_reason": "The inspected method performs a filesystem write using parameter 0.",
                    "local_code_excerpt_refs": [evidence["evidence_id"]],
                    "unresolved_assumptions": ["This is not a vulnerability verdict."],
                    "proposed_scope": "ENTITY_LOCAL",
                    "codeql_corroboration": "UNAVAILABLE_NOT_NEGATIVE",
                }
            else:
                details = {
                    "source": {"entity_id": entity.entity_id, "role": "PARAMETER", "index": 0},
                    "target": {"entity_id": entity.entity_id, "role": "RETURN"},
                    "relation_type": "WRAPPER_FLOW",
                    "exact_local_scope": "CALLABLE_LOCAL",
                    "structural_facts": ["The inspected method returns its parameter."],
                    "optional_codeql_evidence": [],
                    "unresolved_semantics": ["Runtime object identity remains for Work2."],
                    "minimality_explanation": "One parameter-to-return wrapper relation.",
                }
            return _specialist_decision(
                "SUBMIT_FINDINGS",
                status="FINDINGS",
                findings=(
                    {
                        "entity_ids": [entity.entity_id],
                        "tool_call_ids": [evidence["tool_call_id"]],
                        "evidence_refs": [evidence["evidence_id"]],
                        "summary": f"Controlled {role.value} finding.",
                        "details": details,
                        "uncertainties": ["Controlled finding is not a vulnerability conclusion."],
                    },
                ),
            )

        return submit

    specialist_clients: Mapping[SpecialistRole, LLMClient] = {
        SpecialistRole.INPUT: MockLLMClient(
            [
                _specialist_decision(
                    "TOOL", tool_name="INSPECT_METHOD", arguments={"entity_id": receive.entity_id}
                ),
                finding_submit(SpecialistRole.INPUT, receive),
            ]
        ),
        SpecialistRole.EFFECT: MockLLMClient(
            [
                _specialist_decision(
                    "TOOL", tool_name="INSPECT_METHOD", arguments={"entity_id": persist.entity_id}
                ),
                finding_submit(SpecialistRole.EFFECT, persist),
            ]
        ),
        SpecialistRole.BRIDGE: MockLLMClient(
            [
                _specialist_decision(
                    "TOOL", tool_name="INSPECT_METHOD", arguments={"entity_id": carry.entity_id}
                ),
                finding_submit(SpecialistRole.BRIDGE, carry),
            ]
        ),
    }

    def dispatch(role: SpecialistRole, entity: ProgramEntity) -> dict[str, Any]:
        action = {
            SpecialistRole.INPUT: "DISPATCH_INPUT_AGENT",
            SpecialistRole.EFFECT: "DISPATCH_EFFECT_AGENT",
            SpecialistRole.BRIDGE: "DISPATCH_BRIDGE_AGENT",
        }[role]
        return _decision(
            action,
            arguments={
                "objective": "Find one controlled, project-local role-specific candidate.",
                "seed_entity_ids": [entity.entity_id],
                "unresolved_question": "Is one local finding supported by inspected source?",
                "allowed_tools": ["INSPECT_METHOD"],
            },
        )

    def proposal(proposal_type: ProposalType) -> Callable[[Any], Mapping[str, Any]]:
        def submit(request: Any) -> Mapping[str, Any]:
            finding_type = {
                ProposalType.EXTERNAL_INPUT: "INPUT_FINDING",
                ProposalType.SECURITY_EFFECT: "EFFECT_FINDING",
                ProposalType.WRAPPER_FLOW: "BRIDGE_FINDING",
            }[proposal_type]
            finding = next(
                item
                for item in request.observation["evidence_board"]["recent_findings"]
                if item["finding_type"] == finding_type
            )
            if proposal_type is ProposalType.EXTERNAL_INPUT:
                subject = EntityRoleRef(receive.entity_id, EntityRole.PARAMETER, 0)
                source = target = None
                semantic = "FRAMEWORK_INPUT"
            elif proposal_type is ProposalType.SECURITY_EFFECT:
                subject = EntityRoleRef(persist.entity_id, EntityRole.PARAMETER, 0)
                source = target = None
                semantic = "FILESYSTEM"
            else:
                subject = EntityRoleRef(carry.entity_id, EntityRole.METHOD)
                source = EntityRoleRef(carry.entity_id, EntityRole.PARAMETER, 0)
                target = EntityRoleRef(carry.entity_id, EntityRole.RETURN)
                semantic = None
            value = SecurityProposal.create(
                proposal_type=proposal_type,
                subject=subject,
                source=source,
                target=target,
                scope=build_valid_scope(
                    index,
                    project_id=CONTROLLED_PROJECT_ID,
                    subject=subject,
                    source=source,
                    target=target,
                    proposal_type=proposal_type,
                ).scope,
                semantic_category=semantic,
                evidence_refs=finding["evidence_refs"],
                reason="Controlled program-grounded proposal hypothesis.",
                provenance={"benchmark_informed": False},
            ).to_dict()
            value.pop("proposal_id")
            return _decision(
                "SUBMIT_PROPOSAL",
                proposal=value,
                findings=(finding["finding_id"],),
            )

        return submit

    coordinator = MockLLMClient(
        [
            dispatch(SpecialistRole.INPUT, receive),
            dispatch(SpecialistRole.EFFECT, persist),
            proposal(ProposalType.EXTERNAL_INPUT),
            proposal(ProposalType.SECURITY_EFFECT),
            dispatch(SpecialistRole.BRIDGE, carry),
            proposal(ProposalType.WRAPPER_FLOW),
            _decision("STOP", stop_reason=StopReason.PATH_FORMED.value),
        ]
    )
    return coordinator, specialist_clients


def _specialist_trace_rows(result: CoordinatorRunResult, role: SpecialistRole) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for run in result.specialist_runs:
        if run.result.specialist_agent is not role:
            continue
        rows.append(
            {
                "result": run.result.to_dict(),
                "observations": [item.to_dict() for item in run.observations],
                "model_responses": [dict(item) for item in run.model_responses],
                "failures": [item.to_dict() for item in run.failures],
            }
        )
    return rows


def _failure_taxonomy(result: CoordinatorRunResult) -> dict[str, Any]:
    labels = Counter(item.failure_class for item in result.failures)
    for run in result.specialist_runs:
        labels.update(item.failure_class for item in run.failures)
        if run.result.status.value != "FINDINGS":
            labels.update([run.result.stop_reason.value])
    return {"labels": dict(sorted(labels.items())), "failure_count": sum(labels.values())}


def _write_artifacts(
    *,
    result: CoordinatorRunResult,
    output: Path,
    git_sha: str,
    branch: str,
    schema_root: Path,
    runtime_seconds: float,
    input_manifest: Mapping[str, Any],
    boundary_audit: Mapping[str, Any],
    fixture_evidence: Sequence[EvidenceRef],
    model_manifest: Mapping[str, Any],
    secrets: Sequence[str],
) -> dict[str, Any]:
    latest_graph = result.graph_results[-1] if result.graph_results else None
    evidence = {item.evidence_id: item.to_dict() for item in fixture_evidence}
    evidence.update({str(item["evidence_id"]): dict(item) for item in result.board.evidence_refs})
    _write(output / "runtime_input_manifest.json", canonical_json(dict(input_manifest)) + "\n")
    _write(output / "coordinator_trace.jsonl", _jsonl(item.to_dict() for item in result.board.event_log))
    trace_names = {
        SpecialistRole.INPUT: "input_agent.jsonl",
        SpecialistRole.EFFECT: "effect_agent.jsonl",
        SpecialistRole.BRIDGE: "semantic_bridge_agent.jsonl",
    }
    for role, name in trace_names.items():
        _write(output / "specialist_traces" / name, _jsonl(_specialist_trace_rows(result, role)))
    _write(output / "tool_calls.jsonl", _jsonl(result.board.tool_calls))
    _write(output / "evidence_refs.jsonl", _jsonl(evidence[key] for key in sorted(evidence)))
    _write(output / "input_findings.jsonl", _jsonl(item.to_dict() for item in result.board.input_findings))
    _write(output / "effect_findings.jsonl", _jsonl(item.to_dict() for item in result.board.effect_findings))
    _write(output / "bridge_findings.jsonl", _jsonl(item.to_dict() for item in result.board.bridge_findings))
    _write(output / "proposals.jsonl", _jsonl(item.to_dict() for item in result.proposals))
    _write(output / "gate_results.jsonl", _jsonl(item.to_dict() for item in result.gate_results))
    _write(
        output / "graph_nodes.jsonl",
        _jsonl(item.to_dict() for item in latest_graph.graph.nodes) if latest_graph else "",
    )
    _write(
        output / "graph_edges.jsonl",
        _jsonl(item.to_dict() for item in latest_graph.graph.edges) if latest_graph else "",
    )
    _write(output / "candidate_paths.jsonl", _jsonl(result.board.candidate_paths))
    diagnostics: list[Mapping[str, Any]] = []
    if latest_graph:
        diagnostics.extend(latest_graph.path_search.diagnostics)
        diagnostics.extend(item.to_dict() for item in latest_graph.graph.diagnostics)
    _write(output / "path_diagnostics.jsonl", _jsonl(diagnostics))
    _write(output / "board_events.jsonl", _jsonl(item.to_dict() for item in result.board.event_log))
    _write(output / "evidence_board.json", canonical_json(result.board.to_dict()) + "\n")
    failure = _failure_taxonomy(result)
    _write(output / "failure_taxonomy.json", canonical_json(failure) + "\n")
    summary = {
        **result.summary(),
        "input_findings": len(result.board.input_findings),
        "effect_findings": len(result.board.effect_findings),
        "bridge_findings": len(result.board.bridge_findings),
        "gate_admission_rate": (
            sum(item.status.value == "ADMISSIBLE" for item in result.gate_results)
            / len(result.gate_results)
            if result.gate_results
            else 0.0
        ),
        "artifact_root": str(output),
        "interpretation": "Controlled Candidate Paths are not confirmed vulnerabilities.",
    }
    _write(output / "summary.json", canonical_json(summary) + "\n")

    secret_values = [item for item in secrets if len(item) >= 8]
    scanned = [path for path in output.rglob("*") if path.is_file()]
    secret_hits = [
        path.relative_to(output).as_posix()
        for path in scanned
        if any(secret.encode("utf-8") in path.read_bytes() for secret in secret_values)
    ]
    boundary_pass = (
        input_manifest.get("no_leakage_pass") is True
        and boundary_audit.get("status") == "PASS"
    )
    no_leakage = {
        "status": "PASS" if boundary_pass and not secret_hits else "FAIL",
        "no_leakage_pass": boundary_pass and not secret_hits,
        "runtime_boundary_pass": boundary_pass,
        "runtime_boundary_audit": dict(boundary_audit),
        "model_secret_scan_pass": not secret_hits,
        "secret_hit_files": secret_hits,
        "benchmark_informed": False,
    }
    _write(output / "no_leakage_audit.json", canonical_json(no_leakage) + "\n")
    prompt_manifest = {
        "coordinator": {
            "version": COORDINATOR_PROMPT_VERSION,
            "sha256": prompt_sha256(COORDINATOR_SYSTEM_PROMPT),
        },
        "input": {"version": INPUT_PROMPT_VERSION, "sha256": prompt_sha256(INPUT_SYSTEM_PROMPT)},
        "effect": {"version": EFFECT_PROMPT_VERSION, "sha256": prompt_sha256(EFFECT_SYSTEM_PROMPT)},
        "bridge": {"version": BRIDGE_PROMPT_VERSION, "sha256": prompt_sha256(BRIDGE_SYSTEM_PROMPT)},
    }
    schemas = {
        path.name: _sha256(path)
        for path in sorted(schema_root.glob("*.schema.json"))
    }
    source_root = Path(__file__).resolve().parents[1]
    component_manifest = {
        "m4_evidence_gate": {
            "version": "WORK1_V11_M4_EVIDENCE_GATE_V1",
            "source_sha256": _sha256(source_root / "proposal" / "gate.py"),
        },
        "m5_hybrid_graph": {
            "version": "WORK1_V11_M5_HYBRID_GRAPH_V1",
            "source_sha256": _sha256(source_root / "hybrid_graph" / "builder.py"),
        },
        "scope_helper": {
            "version": SCOPE_HELPER_VERSION,
            "source_sha256": _sha256(Path(__file__).with_name("scope_helper.py")),
        },
        "role_helper": {
            "version": ROLE_HELPER_VERSION,
            "source_sha256": _sha256(Path(__file__).with_name("role_helper.py")),
        },
    }
    limits = SearchLimits()
    input_hashes = {
        str(item["logical_name"]): str(item["sha256"])
        for item in input_manifest.get("entries", ())
    }
    hashable = [
        name
        for name in ARTIFACT_FILES
        if name not in {"manifest.json", "artifact_audit.json"}
    ]
    manifest = {
        "run_kind": "M8_CONTROLLED_MULTI_AGENT",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_sha": git_sha,
        "branch": branch,
        "project_revision": git_sha,
        "project_id": CONTROLLED_PROJECT_ID,
        "project_identity": input_manifest.get("repository_identity"),
        "producer": CONTROLLED_PRODUCER,
        "codeql": {
            "version": "UNAVAILABLE_CONTROLLED_FIXTURE",
            "database_identity": result.board.codeql_status.get("database_identity"),
            "status": dict(result.board.codeql_status),
        },
        "agents": {name: spec.to_dict() for name, spec in M8_AGENT_REGISTRY.items()},
        "models": dict(model_manifest),
        "prompts": prompt_manifest,
        "schema_hashes": schemas,
        "tool_catalog_sha256": _value_sha256(bounded_tool_catalog()),
        "components": component_manifest,
        "budget": dict(result.budget_state),
        "path_limits": {
            "max_depth": limits.max_depth,
            "max_paths": limits.max_paths,
            "max_nodes_expanded": limits.max_nodes_expanded,
        },
        "token_counts": dict(result.budget_state.get("usage", {})),
        "tool_counts": {
            "all": len(result.board.tool_calls),
            "codeql": len(result.codeql_results),
        },
        "runtime_seconds": round(runtime_seconds, 6),
        "detector_input_hashes": input_hashes,
        "runtime_input_manifest_sha256": _sha256(output / "runtime_input_manifest.json"),
        "no_leakage_audit_sha256": _sha256(output / "no_leakage_audit.json"),
        "output_hashes": {name: _sha256(output / name) for name in hashable},
        "benchmark_informed": False,
    }
    _write(output / "manifest.json", canonical_json(manifest) + "\n")
    audit_rows = [
        {
            "file": name,
            "sha256": _sha256(output / name),
            "bytes": (output / name).stat().st_size,
        }
        for name in ARTIFACT_FILES
        if name != "artifact_audit.json" and (output / name).is_file()
    ]
    audit = {
        "required_files_present": all((output / name).is_file() for name in ARTIFACT_FILES if name != "artifact_audit.json"),
        "artifact_count": len(ARTIFACT_FILES),
        "artifacts": audit_rows,
        "no_leakage_pass": no_leakage["no_leakage_pass"],
    }
    _write(output / "artifact_audit.json", canonical_json(audit) + "\n")
    summary.update(
        {
            "artifact_audit_pass": audit["required_files_present"],
            "no_leakage_pass": no_leakage["no_leakage_pass"],
        }
    )
    return summary


def run_controlled_smoke(
    *,
    repository_root: Path,
    schema_root: Path,
    artifact_root: Path,
    git_sha: str,
    branch: str = "UNKNOWN",
    coordinator_client: LLMClient | None = None,
    specialist_clients: Mapping[SpecialistRole, LLMClient] | None = None,
    model_configs: M8ModelConfigs | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    if (coordinator_client is None) != (specialist_clients is None):
        raise ValueError("coordinator and specialist clients must be supplied together")
    if coordinator_client is not None and model_configs is None:
        raise ValueError("explicit model configs are required with real clients")
    output = artifact_root.resolve()
    _prepare_output(output)
    if coordinator_client is None or specialist_clients is None:
        pre_index = build_repository_index(repository_root)
        coordinator_client, specialist_clients = _deterministic_clients(pre_index)
        model_manifest: Mapping[str, Any] = {
            "coordinator": {"provider": "deterministic-mock", "exact_model_id": "claude-opus-5"},
            "specialists": {"provider": "deterministic-mock", "exact_model_id": "claude-sonnet-5"},
        }
        secrets: Sequence[str] = ()
    else:
        model_manifest = model_configs.to_manifest_dict() if model_configs else {}
        secrets = (
            (model_configs.coordinator.api_key, model_configs.specialist.api_key)
            if model_configs
            else ()
        )
    runtime, boundary, fixture_evidence = _build_runtime(
        repository_root=repository_root.resolve(),
        schema_root=schema_root.resolve(),
        artifact_root=output,
        git_sha=git_sha,
        coordinator_client=coordinator_client,
        specialist_clients=specialist_clients,
    )
    result = runtime.run()
    input_manifest = boundary.seal()
    boundary_audit = boundary.audit()
    return _write_artifacts(
        result=result,
        output=output,
        git_sha=git_sha,
        branch=branch,
        schema_root=schema_root.resolve(),
        runtime_seconds=time.monotonic() - started,
        input_manifest=input_manifest,
        boundary_audit=boundary_audit,
        fixture_evidence=fixture_evidence,
        model_manifest=model_manifest,
        secrets=secrets,
    )


def run_controlled_real_llm_smoke(
    *,
    repository_root: Path,
    schema_root: Path,
    artifact_root: Path,
    git_sha: str,
    branch: str = "UNKNOWN",
    model_configs: M8ModelConfigs | None = None,
) -> dict[str, Any]:
    configs = model_configs or M8ModelConfigs.from_environment()
    specialists = {role: _client(configs.specialist) for role in SpecialistRole}
    return run_controlled_smoke(
        repository_root=repository_root,
        schema_root=schema_root,
        artifact_root=artifact_root,
        git_sha=git_sha,
        branch=branch,
        coordinator_client=_client(configs.coordinator),
        specialist_clients=specialists,
        model_configs=configs,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--schema-root", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--git-sha", required=True)
    parser.add_argument("--branch", default="UNKNOWN")
    parser.add_argument(
        "--mode",
        choices=("deterministic-mock", "real-llm"),
        default="deterministic-mock",
    )
    args = parser.parse_args()
    runner = run_controlled_real_llm_smoke if args.mode == "real-llm" else run_controlled_smoke
    summary = runner(
        repository_root=args.repository_root,
        schema_root=args.schema_root,
        artifact_root=args.artifact_root,
        git_sha=args.git_sha,
        branch=args.branch,
    )
    print(canonical_json(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
