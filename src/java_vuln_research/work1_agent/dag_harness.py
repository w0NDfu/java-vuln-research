"""Evidence-driven multi-agent DAG with bounded recovery rounds."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, TextIO

from .dag_cases import audit_note, contract_path_proposals, source_read_coverage, submit_path
from .dag_retrieval import StructuralRetrieval, retrieve_knowledge
from .evidence_chain import EFFECT_CATEGORIES, EvidenceChain, candidate_from_steps
from .graph_rag import CodeQLGraphIndex
from .harness import HarnessLimits, Policy, PolicyError, SUPPORTED_CWES, _Case
from .proposal.evidence import EvidenceRef, EvidenceSourceKind, EvidenceStrength
from .proposal.model import EXTERNAL_INPUT_CATEGORIES, SECURITY_EFFECT_CATEGORIES, canonical_json
from .repository.tools import RepositoryTools
from .value_paths import ValuePaths
from .evp_memory import DataflowFactLedger
from .state_dispatch import StateDispatchIndex, walk
from .experiment_policy import request_reserve


_CONTEXT_BYTES = 6_144
_VERIFICATION_BYTES = 12_288
_DISCOVERY_QUERIES = 3
_RETRIEVAL_READS = 2
_LIBRARY_BOUNDARY_READS = 7
_REASONING_ACTIONS = 7
_VERIFICATION_PATHS = 2
_JSON_FENCE = re.compile(r"\A```(?:json)?[ \t]*\r?\n(.*?)\r?\n```\Z", re.DOTALL | re.IGNORECASE)
_READ_ACTIONS = frozenset(("inspect_entity", "search_symbols", "search_code", "follow_graph"))
_MAX_READ_BATCH = 4
_REQUIRED_PATH_CHECKS = {"input_control": "supported", "value_flow": "supported",
                         "security_effect": "supported", "effective_protection": "absent"}


def normalize_source_citations(action, context):
    """Accept line-qualified citations only inside an actually supplied read."""
    proofs = context.get("source_evidence", {})
    changed = {}
    pending = [action]
    while pending:
        item = pending.pop()
        if isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, dict):
            for field, value in item.items():
                if field != "evidence_refs" or not isinstance(value, list):
                    if isinstance(value, (dict, list)):
                        pending.append(value)
                    continue
                for index, ref in enumerate(value):
                    match = re.fullmatch(r"(.+):(\d+)(?:-(\d+))?", ref) if isinstance(ref, str) else None
                    if match is None or match[1] not in proofs:
                        continue
                    proof = proofs[match[1]]
                    location = proof.get("location", {})
                    start = location.get("start_line")
                    if type(start) is not int:
                        continue
                    end = location.get("end_line", start + len(proof.get("source", "").splitlines()) - 1)
                    first, last = int(match[2]), int(match[3] or match[2])
                    if start <= first <= last <= end:
                        value[index] = match[1]
                        changed[ref] = match[1]
    return changed


def response_contract_error(role: str, context: dict, action: dict) -> str | None:
    if role == "discovery":
        if context.get("task") == "project_discovery":
            branches = action.get("branches")
            if not isinstance(branches, dict) or set(branches) != set(SUPPORTED_CWES):
                return "Return branches with exactly CWE-22, CWE-78, CWE-79 and CWE-94."
            for cwe, branch in branches.items():
                if not isinstance(branch, dict):
                    return "Each branch requires a queries list and optional hypotheses."
                error = response_contract_error(role, {"repository_inventory": context["inventories"][cwe],
                                                       "general_evp": context.get("general_evp", False)}, branch)
                if error:
                    return f"{cwe}: {error}"
            return None
        try:
            _strings(action["queries"], _DISCOVERY_QUERIES)
        except (KeyError, ValueError):
            return "Return queries as a list containing at most three search strings."
        hypotheses = action.get("hypotheses", [])
        known = {row["entity_id"] for row in context.get("repository_inventory", [])}
        if not isinstance(hypotheses, list) or len(hypotheses) > 2:
            return "Provide at most two hypotheses."
        for hypothesis in hypotheses:
            if (not isinstance(hypothesis, dict)
                    or not isinstance(hypothesis.get("anchor_entity_id"), str)
                    or hypothesis["anchor_entity_id"] not in known
                    or any(not isinstance(hypothesis.get(field), str)
                           or not 10 <= len(hypothesis[field].strip()) <= (1200 if context.get("general_evp") else 300)
                           for field in ("hypothesis", "evidence_question"))):
                return f"Each hypothesis needs an inventory anchor, hypothesis and evidence_question of 10 to {1200 if context.get('general_evp') else 300} characters."
        return None
    if role == "reasoning" and context.get("task") not in ("trace_library_contract", "trace_path_conditions"):
        allowed = context.get("allowed_actions", ())
        name = action.get("action")
        if name not in allowed:
            return "Return an action listed in allowed_actions. A verdict is a different response contract."
        required = {
            "search_symbols": ("query",), "search_code": ("query",), "inspect_entity": ("entity_id",),
            "follow_graph": ("entity_id",),
            "propose": ("proposal",), "submit_path": ("proposals",),
            "record_case": ("anchor_entity_id", "hypothesis", "next_question", "evidence_refs"),
            "propose_assumed_bridge": ("from_anchor", "to_anchor", "code_witness",
                                       "bridge_index", "proposals", "conditions", "reason"),
            "remember_witness_path": ("steps", "frontier_question"),
            "submit_witness_path": ("steps", "input_category", "effect_category", "conditions"),
            "read_static_spine": ("spine_id",),
            "recall_source": ("evidence_id",),
            "query_state_and_dispatch_bridge": ("symbol", "enclosing_type", "direction"),
            "record_verified_subpaths": ("verified_subpaths",),
        }
        if not all(field in action for field in required.get(name, ())):
            return "The selected action is missing its required fields."
        if name == "submit_witness_path":
            try:
                conditions = _strings(action.get("conditions"), 5, 400 if context.get("general_evp") else 150)
            except ValueError:
                conditions = []
            if not conditions:
                return f"Provide one to five concrete conditions, each at most {400 if context.get('general_evp') else 150} characters."
        if name == "record_case":
            refs = action["evidence_refs"]
            if not isinstance(refs, list) or not 1 <= len(refs) <= 4 or not all(isinstance(ref, str) for ref in refs):
                return "For record_case, cite one to four source evidence IDs, including an excerpt for the anchor."
        if name == "submit_path" and context.get("require_conditions"):
            try:
                conditions = _strings(action.get("conditions"), 5, 400 if context.get("general_evp") else 150)
            except ValueError:
                return "For submit_path, provide one to five concrete trigger or use conditions."
            if not conditions:
                return "For submit_path, provide one to five concrete trigger or use conditions."
        if name == "submit_bridge":
            available = {row["id"] for row in context.get("value_paths", []) if row["source_complete"]}
            if not isinstance(action.get("path_id"), str) or action["path_id"] not in available:
                return "Select a path_id from value_paths with source_complete true."
            if (not isinstance(action.get("input_category"), str) or action["input_category"] not in EXTERNAL_INPUT_CATEGORIES
                    or not isinstance(action.get("effect_category"), str) or action["effect_category"] not in SECURITY_EFFECT_CATEGORIES):
                return "Provide a valid input_category and effect_category."
            try:
                conditions = _strings(action.get("conditions"), 5, 400 if context.get("general_evp") else 150)
            except ValueError:
                conditions = []
            maximum = 1000 if context.get("general_evp") else 550
            if not conditions or not isinstance(action.get("reason"), str) or not 10 <= len(action["reason"]) <= maximum:
                return f"Provide one to five conditions of at most {400 if context.get('general_evp') else 150} characters and a reason of 10 to {maximum} characters."
        if name == "read_static_spine" and not any(
            row["id"] == action["spine_id"] for row in context.get("Static_Spine_Hints", ())
        ):
            return "Choose a spine_id from Static_Spine_Hints."
        if name == "finish" and context.get("final_synthesis") and action.get("outcome") != "EVIDENCE_GAP":
            return "In final synthesis, submit the best witnessed chain or identify the exact remaining gap."
        if name == "finish" and context.get("task") == "evidence_reasoning":
            if (action.get("outcome") not in ("NO_GROUNDED_LEAD", "PROTECTION_ESTABLISHED", "EVIDENCE_GAP")
                    or not isinstance(action.get("reason"), str) or not action["reason"].strip()):
                return "Finish with outcome NO_GROUNDED_LEAD, PROTECTION_ESTABLISHED or EVIDENCE_GAP and a reason."
            if action["outcome"] == "PROTECTION_ESTABLISHED" and (
                not isinstance(action.get("path_id"), str) or
                not any(row["id"] == action["path_id"] and row["source_complete"]
                        for row in context.get("value_paths", []))
            ):
                return "For PROTECTION_ESTABLISHED, choose the protected complete flow by path_id."
        return None
    if context.get("task") == "trace_path_conditions":
        if action.get("violation_status") not in ("VIOLATION_PROVEN", "GUARANTEE_HOLDS_ON_PATH", "EVIDENCE_GAP"):
            return "Return violation_status as VIOLATION_PROVEN, GUARANTEE_HOLDS_ON_PATH, or EVIDENCE_GAP."
        if action["violation_status"] == "VIOLATION_PROVEN":
            steps = action.get("steps")
            required = ("entry", "branch", "state", "output", "impact")
            if not isinstance(steps, dict) or set(steps) != set(required):
                return "A violation requires the five steps entry, branch, state, output and impact."
            for item in steps.values():
                if (not isinstance(item, dict) or not isinstance(item.get("claim"), str)
                    or not 8 <= len(item["claim"].strip()) <= 400
                    or not isinstance(item.get("evidence_refs"), list) or not item["evidence_refs"]
                    or not all(isinstance(ref, str) for ref in item["evidence_refs"])):
                    return "Each step must have a claim of 8 to 400 characters and a nonempty evidence_refs list."
            conditions = action.get("conditions")
            if (not isinstance(conditions, list) or not 1 <= len(conditions) <= 5
                or not all(isinstance(item, str) and 8 <= len(item.strip()) <= 250 for item in conditions)):
                return "List the concrete trigger and output-context conditions in conditions."
    elif action.get("verdict") not in ("SUPPORTED", "REJECTED", "UNRESOLVED"):
        return "Return a verdict of SUPPORTED, REJECTED, or UNRESOLVED."
    refs = action.get("evidence_refs")
    if not isinstance(refs, list) or not all(isinstance(ref, str) for ref in refs):
        return "Return evidence_refs as a list of evidence IDs from the current request."
    if not isinstance(action.get("reason"), str) or not action["reason"].strip():
        return "Provide the reasoning in the reason field."
    if assumed := context.get("assumed_bridges"):
        checks = action.get("bridge_checks")
        if not isinstance(checks, dict) or set(checks) != set(assumed):
            return "Return bridge_checks keyed by every supplied bridge proposal ID."
        for check in checks.values():
            if (not isinstance(check, dict)
                    or check.get("verdict") not in ("BRIDGE_CONFIRMED", "BRIDGE_REJECTED", "BRIDGE_UNRESOLVED")
                    or not isinstance(check.get("evidence_refs"), list)
                    or not all(isinstance(ref, str) for ref in check["evidence_refs"])):
                return "For each bridge provide its verdict and cited source evidence IDs."
    if context.get("review_kind") == "static_contract_obligation":
        if action.get("local_gap_assessment") not in ("SUPPORTED", "NOT_ESTABLISHED"):
            return "Provide a local_gap_assessment of SUPPORTED or NOT_ESTABLISHED."
    if context.get("claim_to_falsify"):
        for field in ("support", "counterevidence", "unproven_conditions"):
            entries = action.get(field)
            if not isinstance(entries, list) or len(entries) > 5 or not all(
                isinstance(entry, str) and 0 < len(entry.strip()) <= (1200 if context.get("general_evp") else 350) for entry in entries
            ):
                return "Provide support, counterevidence and unproven_conditions as lists of brief strings."
        if action.get("verdict") == "SUPPORTED" and not action["support"]:
            return "Identify what evidence supports the violation."
        if context.get("value_bridge") and action.get("verdict") == "SUPPORTED" and (
            action["unproven_conditions"] or action["counterevidence"]
        ):
            return ("SUPPORTED requires no facts contradicting the scoped claim or unresolved conditions. "
                    "Report a deployment boundary already covered by the claim in scope_notes. "
                    "For substantive gaps use UNRESOLVED or REJECTED.")
    return None


def _read_batch(content: str, context: dict) -> list[dict]:
    """Recover concatenated read requests without executing a partial response."""
    decoder = json.JSONDecoder()
    batch = {}
    frames = 0
    while content and frames < 16:
        item, end = decoder.raw_decode(content)
        if (not isinstance(item, dict) or not isinstance(item.get("action"), str)
                or item["action"] not in _READ_ACTIONS
                or response_contract_error("reasoning", context, item)):
            raise ValueError("batch contains a non-retrieval or invalid action")
        frames += 1
        batch.setdefault(canonical_json(item), item)
        if len(batch) > _MAX_READ_BATCH:
            raise ValueError("too many distinct read actions")
        content = content[end:].lstrip()
    if content or frames < 2:
        raise ValueError("expected two to four complete read actions")
    return list(batch.values())


def complete_run_limits(rounds: int) -> HarnessLimits:
    """Cover every scheduled action in the declared rounds without a global cutoff."""
    plan(rounds)
    branches = len(SUPPORTED_CWES) * rounds
    return HarnessLimits(
        branches * (2 + _REASONING_ACTIONS + _VERIFICATION_PATHS),
        len(SUPPORTED_CWES) * (rounds * (_DISCOVERY_QUERIES + _RETRIEVAL_READS + _REASONING_ACTIONS)
                              + _LIBRARY_BOUNDARY_READS),
    )


def _context_size(payload: Mapping[str, Any]) -> int:
    return len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))


def _source_ref(proof: EvidenceRef) -> dict:
    return {
        "evidence_id": proof.evidence_id, "entity_ids": list(proof.entity_ids),
        "start_line": proof.start_line, "end_line": proof.end_line,
    }


def _symbol(entity: Mapping[str, Any]) -> dict:
    return {key: entity[key] for key in
            ("entity_id", "kind", "simple_name", "repository_relative_path", "start_line", "end_line")}


def _window(item: Mapping[str, Any]) -> dict:
    evidence = item["evidence"]
    return {
        "entity": _symbol(item["entity"]),
        "evidence_id": evidence["evidence_id"],
        "start_line": evidence["start_line"],
        "source": "\n".join(line["text"] for line in item["lines"]),
    }


def _compact_relation(relation: Mapping[str, Any]) -> dict:
    if relation["kind"] == "CODEQL_DATAFLOW":
        return dict(relation)
    return {
        "kind": relation["kind"],
        **{side: {key: relation[side][key] for key in ("entity_id", "symbol", "line", "column")}
           for side in ("from", "to")},
    }


def _fit_context(payload: dict) -> dict:
    """Drop whole optional records. Never shorten a source excerpt tied to an evidence ID."""
    for field, keep in (
        ("repository_inventory", 0), ("prior_queries", 2), ("codeql_relation_context", 2),
        ("recent_actions", 1), ("native_flow_hints", 1),
        ("entity_ids", 3), ("retrieved", 1), ("evidence_refs", 4),
        ("native_flow_hints", 0), ("retrieved", 0), ("admitted_proposals", 1),
        ("review_gaps", 0), ("evidence_refs", 0), ("codeql_relation_context", 0),
        ("prior_queries", 0), ("recent_actions", 0), ("entity_ids", 0),
        ("admitted_proposals", 0), ("knowledge", 0),
    ):
        values = list(payload.get(field, ()))
        while len(values) > keep and _context_size(payload) > _CONTEXT_BYTES:
            dropped = values.pop()
            payload[field] = values
            if field == "retrieved":
                payload.setdefault("omitted_source_windows", []).append(dropped["evidence_id"])
            if field == "native_flow_hints":
                payload.setdefault("omitted_native_paths", []).append(dropped["path_id"])
    return payload


@dataclass(frozen=True, slots=True)
class Node:
    id: str
    role: str
    needs: tuple[str, ...]
    cwe: str = ""
    round: int = 0


def plan(rounds: int) -> tuple[Node, ...]:
    if type(rounds) is not int or not 1 <= rounds <= 6:
        raise ValueError("rounds must be in [1, 6]")
    nodes = [Node(f"discover:{cwe}", "discovery", (), cwe) for cwe in SUPPORTED_CWES]
    for number in range(1, rounds + 1):
        for cwe in SUPPORTED_CWES:
            needs = (f"discover:{cwe}",)
            if number > 1:
                needs += (f"route:{number - 1}",)
            retrieve = f"retrieve:{number}:{cwe}"
            reason = f"reason:{number}:{cwe}"
            verify = f"verify:{number}:{cwe}"
            nodes.extend((
                Node(retrieve, "retrieval", needs, cwe, number),
                Node(reason, "reasoning", (retrieve,), cwe, number),
                Node(verify, "verification", (reason,), cwe, number),
            ))
        nodes.append(Node(f"route:{number}", "router", tuple(
            f"verify:{number}:{cwe}" for cwe in SUPPORTED_CWES
        ), round=number))
    nodes.append(Node("report", "report", (f"route:{rounds}",)))
    return tuple(nodes)


@dataclass(frozen=True, slots=True)
class AgentTeam:
    discovery: Policy
    reasoning: Policy
    verification: Policy


def _read_count(case: _Case) -> int:
    return len({
        (item.entity_ids, item.repository_relative_path, item.start_line, item.end_line, item.content_hash)
        for item in case.evidence.values() if item.source_kind == EvidenceSourceKind.SOURCE_SNIPPET
    })


def _strings(value: Any, limit: int = 4, max_characters: int = 150) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"expected at most {limit} strings")
    if any(not isinstance(item, str) or not item.strip() or len(item) > max_characters for item in value):
        raise ValueError(f"expected non-empty strings of at most {max_characters} characters")
    return list(dict.fromkeys(item.strip() for item in value))


def bridge_verdicts(assumptions, action, cited_source):
    checks = action.get("bridge_checks")
    checks = checks if isinstance(checks, dict) else {}
    verdicts = {}
    for key, bridge in assumptions.items():
        check = checks.get(key)
        check = check if isinstance(check, dict) else {}
        witness_ids = {witness["evidence_id"] for witness in bridge["code_witness"].values()}
        refs = check.get("evidence_refs")
        refs = set(refs) if isinstance(refs, list) and all(isinstance(ref, str) for ref in refs) else set()
        verdict = check.get("verdict")
        if bridge.get("kind") == "SEMANTIC_BRIDGE" and check.get("condition_assessment") != "CONFIRMED":
            verdict = "BRIDGE_UNRESOLVED"
        if (verdict == "BRIDGE_CONFIRMED" and witness_ids <= refs <= cited_source
                or verdict == "BRIDGE_REJECTED" and refs and refs <= cited_source):
            verdicts[key] = verdict
        else:
            verdicts[key] = "BRIDGE_UNRESOLVED"
    return verdicts


class _Run:
    def __init__(self, tools: RepositoryTools, retrieval: StructuralRetrieval, team: AgentTeam,
                 limits: HarnessLimits, trace: TextIO, mode: str, rounds: int,
                 repair_protocol: bool = False, path_sensitive: bool = False, agentic_rag: bool = False,
                 adaptive_gaps: bool = False, value_paths: ValuePaths | None = None,
                 focus_scheduling: bool = False, request_headroom: Callable[[], int] | None = None,
                 token_headroom: Callable[[], int] | None = None, general_evp: bool = False) -> None:
        self.cases = {cwe: _Case(tools) for cwe in SUPPORTED_CWES}
        self.retrieval = retrieval
        self.team = team
        self.limits = limits
        self.trace = trace
        self.mode = mode
        self.rounds = rounds
        self.repair_protocol = repair_protocol
        self.path_sensitive = path_sensitive
        self.agentic_rag = agentic_rag
        self.adaptive_gaps = adaptive_gaps
        self.rag_requests: set[tuple[str, str, str]] = set()
        self.protocol_failures: dict[str, int] = defaultdict(int)
        self.protocol_repairs = 0
        self.protocol_failed_nodes: set[str] = set()
        self.branch_calls: dict[str, int] = defaultdict(int)
        self.searched: dict[str, dict[tuple[str, str], str]] = defaultdict(dict)
        self.catalogues = {cwe: retrieval.inventory(cwe) for cwe in SUPPORTED_CWES}
        self.queries: dict[str, list[str]] = defaultdict(list)
        self.discovery_hypotheses: dict[str, list[dict]] = defaultdict(list)
        self.focus: dict[str, list[str]] = defaultdict(list)
        self.context: dict[str, dict] = {}
        self.reviews: dict[tuple[str, str], dict] = {}
        self.audit_cases: dict[str, dict] = {}
        self.seed_methods: dict[str, list[str]] = {}
        self.library_boundaries: dict[str, dict] = {}
        self.contract_obligations: dict[str, dict] = {}
        self.contract_reasoned: set[str] = set()
        self.path_claims: dict[tuple[str, str], dict] = {}
        self.assumed_bridges: dict[tuple[str, str], dict] = {}
        self.case_reviews: list[dict] = []
        self.last_case_review: dict[str, tuple[dict, int]] = {}
        self.retrieval_tasks: dict[str, list[dict]] = defaultdict(list)
        self.model_calls = 0
        self.tool_calls = 0
        self.usage: dict[str, int] = defaultdict(int)
        self.stopped: str | None = None
        self.active = set(SUPPORTED_CWES)
        self.progress: dict[str, tuple[int, int, int]] = {}
        self.no_lead_reads: dict[str, int] = {}
        self.stalled_branches: set[str] = set()
        self.value_paths = value_paths
        self.visible_paths = defaultdict(dict)
        self.value_path_owners: dict[str, set[str]] = defaultdict(set)
        self.value_search_reads = defaultdict(lambda: -1)
        self.source_cache = {}
        self.search_cache = {}
        self.resolved_branches = {}
        self.protected_flows = {}
        self.protection_reviews = []
        self.witness_candidates = defaultdict(dict)
        self.exploration = defaultdict(lambda: {"Confirmed_Hops": {}, "Frontier_Questions": {}, "Dead_Ends": {}})
        self.review_followups = defaultdict(int)
        self.focus_scheduling = focus_scheduling and mode == "adaptive" and value_paths is not None
        self.focus_order = []
        self.focus_tool_caps = {}
        self.prefetched = set()
        self.request_headroom = request_headroom or (lambda: self.limits.max_turns - self.model_calls)
        self.pivots = {}
        self.pivot_evidence = defaultdict(list)
        self.pivot_history = defaultdict(set)
        self.last_reason_outcomes = {}
        self.spine_requests = defaultdict(set)
        self.token_headroom = token_headroom or (lambda: 150000)
        self.read_rounds = {}
        self.relay_reads = defaultdict(int)
        self.recalled = defaultdict(set)
        self.general_evp = general_evp
        self.fact_ledgers = defaultdict(DataflowFactLedger)
        self.state_index = StateDispatchIndex(retrieval) if general_evp else None
        if self.state_index is not None:
            retrieval.enable_semantic_priors(self.state_index)
            self.catalogues = {cwe: retrieval.inventory(cwe) for cwe in SUPPORTED_CWES}
        self.state_prefetched = set()
        self.semantic_probes = {}
        self.vitality_history = {}
        self.evp_last_facts = defaultdict(int)
        self.final_rounds = {}
        self.admitted_reason_rounds = defaultdict(set)
        self.unadmitted_branches = set()

    def event(self, node: Node, kind: str, **details: Any) -> None:
        self.trace.write(canonical_json({"node": node.id, "role": node.role, "event": kind, **details}) + "\n")
        self.trace.flush()

    def candidate_protocol_error(self, node: Node, action: dict) -> str | None:
        name = action.get("action")
        if not isinstance(name, str) or name not in {"propose", "submit_path"}:
            return None
        drafts = [action.get("proposal")] if name == "propose" else action.get("proposals")
        if not isinstance(drafts, list) or len(drafts) > 8 or not all(isinstance(item, dict) for item in drafts):
            return "Provide one proposal object or a proposals list containing at most eight objects."
        case = self.cases[node.cwe]
        before = dict(case.admitted)
        errors = []
        structural_checks = {"SCHEMA_VALIDITY", "ENTITY_EXISTENCE", "NO_FABRICATED_ENTITY",
                             "ROLE_COMPATIBILITY", "SCOPE_BOUND"}
        try:
            for index, draft in enumerate(drafts):
                try:
                    _, result = case.propose({"proposal": draft}, self.model_calls)
                except (KeyError, TypeError, ValueError, AttributeError) as error:
                    errors.append({"proposal_index": index, "schema_error": str(error)[:200]})
                    continue
                gate = result["gate"]
                if any(check["check"] in structural_checks and check["status"] == "FAIL"
                       for check in gate["checks"]):
                    errors.append({"proposal_index": index, "schema_errors": gate["rejection_reasons"],
                                   "repair_context": result.get("repair_context", {})})
        finally:
            case.admitted.clear()
            case.admitted.update(before)
        if errors:
            return canonical_json({
                "candidate_schema_errors": errors[:4],
                "required_fields": ["proposal_type", "subject", "scope", "evidence_refs", "reason"],
                "flow_fields": ["source", "target"],
                "guidance": "Correct the representation using indexed roles. Preserve claims and evidence.",
            })
        return None

    def ask(self, node: Node, context: dict, *, repair: str | None = None) -> dict:
        if self.model_calls >= self.limits.max_turns:
            self.stopped = "MODEL_BUDGET_EXHAUSTED"
            return {}
        payload = {"role": node.role, "cwe": node.cwe, "round": node.round,
                   "tool_calls_left": self.limits.max_tool_calls - self.tool_calls, **context}
        if self.general_evp:
            payload["general_evp"] = True
            context = {**context, "general_evp": True}
        if self.value_paths is not None:
            payload["verification_budget"] = {"pending_verification_count": self.pending_verification_count()}
        if repair:
            payload["response_error"] = repair + " Correct only the response protocol. Do not invent evidence."
        focused_contract = context.get("task") in ("trace_library_contract", "trace_path_conditions")
        if node.role != "verification" and not focused_contract:
            if context.get("task") not in ("project_discovery", "evidence_reasoning"):
                _fit_context(payload)
        size = _context_size(payload)
        ceiling = (_VERIFICATION_BYTES if node.role == "verification" or focused_contract
                   or context.get("task") in ("project_discovery", "evidence_reasoning") else _CONTEXT_BYTES)
        if self.path_sensitive and ceiling == _VERIFICATION_BYTES:
            ceiling *= 2
        if self.general_evp and node.role in {"discovery", "reasoning", "verification"}:
            ceiling = 262144
        if size > ceiling:
            self.event(node, "context_budget_exceeded", context_bytes=size, ceiling_bytes=ceiling)
            if node.role == "verification":
                return {"verdict": "UNRESOLVED", "reason": "Verification context exceeds its byte ceiling."}
            return {}
        self.model_calls += 1
        policy = getattr(self.team, node.role)
        self.event(node, "model_input", context_bytes=size, context=payload,
                   context_sha256=hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest())
        try:
            turn = policy(payload)
        except PolicyError as exc:
            if getattr(exc, "stop_reason", None) == "VERIFICATION_RESERVE":
                self.event(node, "verification_reserve_reached")
                if self.general_evp and node.role == "reasoning":
                    self.unadmitted_branches.add(node.cwe)
                return {}
            self.stopped = getattr(exc, "stop_reason", "MODEL_ERROR")
            self.event(node, "model_error", error=str(exc))
            return {}
        if self.general_evp and node.role == "reasoning":
            self.admitted_reason_rounds[node.cwe].add(node.round)
        for key, value in turn.usage.items():
            if type(value) is int and value >= 0:
                self.usage[key] += value
        self.event(node, "model_response", response=turn.content, usage=dict(turn.usage),
                   metadata=dict(turn.metadata))
        try:
            if turn.metadata.get("finish_reason") == "length":
                raise ValueError("Model response reached its output token limit.")
            content = turn.content.strip()
            if self.repair_protocol and (fenced := _JSON_FENCE.fullmatch(content)):
                content = fenced.group(1)
                self.protocol_repairs += 1
                self.event(node, "response_unwrapped")
            if self.repair_protocol and not content.startswith(("{", "[")):
                offset = content.find("{")
                if offset > 0 and "}" not in content[:offset]:
                    try:
                        recovered = json.loads(content[offset:])
                    except (ValueError, RecursionError):
                        pass
                    else:
                        if isinstance(recovered, dict):
                            # Recover only one complete trailing object. Its action,
                            # evidence and response contract are checked below.
                            content = content[offset:]
                            self.protocol_repairs += 1
                            self.event(node, "response_preamble_unwrapped", prefix_characters=offset)
            try:
                action = json.loads(content)
            except json.JSONDecodeError as exc:
                if (not self.repair_protocol or node.role != "reasoning"
                        or "allowed_actions" not in context or exc.msg != "Extra data"):
                    raise
                batch = _read_batch(content, context)
                self.protocol_repairs += 1
                self.event(node, "read_batch_recovered", actions=len(batch))
                return {"read_batch": batch}
            if not isinstance(action, dict):
                raise ValueError("model response must be a JSON object")
            if self.general_evp and node.role == "verification":
                aliases = {"REFUTED": "REJECTED", "INSUFFICIENT_EVIDENCE": "UNRESOLVED"}
                if action.get("verdict") in aliases:
                    action["verdict"] = aliases[action["verdict"]]
                normalized = normalize_source_citations(action, context)
                if normalized:
                    self.event(node, "source_citations_normalized", mapping=normalized)
            if context.get("task") == "project_discovery" and set(action) == set(SUPPORTED_CWES):
                action = {"branches": action}
                self.event(node, "discovery_envelope_normalized")
        except (ValueError, RecursionError) as exc:
            if not self.repair_protocol:
                self.event(node, "invalid_response", error=str(exc))
                return {}
            error_kind = "OUTPUT_TRUNCATED" if turn.metadata.get("finish_reason") == "length" else "JSON_FORMAT"
            guidance = "Return exactly one complete, concise JSON object within the output limit."
        else:
            guidance = response_contract_error(node.role, context, action) if self.repair_protocol else None
            if guidance is None and self.repair_protocol and node.role == "reasoning":
                guidance = self.candidate_protocol_error(node, action)
            if guidance is None:
                if self.general_evp and node.role == "reasoning" and action.get("verified_subpaths"):
                    self.merge_facts(node, action["verified_subpaths"])
                if repair:
                    self.protocol_repairs += 1
                    self.event(node, "protocol_recovered")
                return action
            error_kind = "RESPONSE_SCHEMA"
        self.protocol_failures[error_kind] += 1
        self.event(node, "protocol_failure", failure=error_kind, guidance=guidance, repair_attempt=bool(repair))
        if repair is None and self.model_calls < self.limits.max_turns:
            return self.ask(node, context, repair=guidance)
        self.event(node, "protocol_recovery_exhausted")
        self.protocol_failed_nodes.add(node.id)
        return {}

    def branch_remaining(self, node: Node) -> int:
        if self.focus_scheduling and node.round > 1:
            return max(0, min(self.limits.max_tool_calls - self.tool_calls,
                              self.focus_tool_caps.get(node.cwe, 0) - self.branch_calls[node.cwe]))
        index = SUPPORTED_CWES.index(node.cwe)
        quota, remainder = divmod(self.limits.max_tool_calls, len(SUPPORTED_CWES))
        quota += index < remainder
        reserve = min(4, quota // 3) if node.round == 1 and self.rounds > 1 and node.role != "verification" else 0
        return max(0, quota - reserve - self.branch_calls[node.cwe])

    def merge_facts(self, node, drafts):
        if not isinstance(drafts, list) or len(drafts) > 24 or not all(isinstance(row, dict) for row in drafts):
            raise ValueError("verified_subpaths must contain at most 24 new segments per turn.")
        ledger = self.fact_ledgers[node.cwe]
        checker = EvidenceChain(self.cases[node.cwe], self.retrieval, self.value_paths, general_evp=True)
        added, rejected = [], []
        for draft in drafts:
            try:
                identity = ledger.add(checker, draft)
                if identity:
                    added.append(identity)
            except (ValueError, KeyError, TypeError) as exc:
                rejected.append(str(exc)[:300])
        self.event(node, "dataflow_facts_merged", edge_ids=added, rejected=rejected, total=len(ledger.facts),
                   connected_partial_chains=ledger.context()["connected_partial_chains"])
        return {"edge_ids": added, "rejected": rejected, "total": len(ledger.facts)}

    def seed_dataflow_facts(self, node):
        """Ground syntactic assignment segments, preserving pending semantics."""
        case = self.cases[node.cwe]
        ledger = self.fact_ledgers[node.cwe]
        nav = self.retrieval.branch_navigation(node.cwe)
        checker = EvidenceChain(case, self.retrieval, self.value_paths)
        before = len(ledger.facts)
        for owner, assignments in self.state_index.assignments.items():
            method = case.entities[owner]
            parameters = [e for e in self.retrieval.by_callable[self.retrieval._scope_from_method(method)]
                          if e.kind.value == "PARAMETER"]
            tracked = {}
            for parameter in parameters:
                if owner not in nav.source_owners:
                    continue
                draft = {"file_path": method.repository_relative_path, "line_start": parameter.start_line,
                         "line_end": parameter.end_line, "method_symbol": owner,
                         "tracked_variable_or_expr": parameter.simple_name, "step_role": "SOURCE"}
                try:
                    tracked[parameter.simple_name] = checker.step(draft)[0]
                except ValueError:
                    pass
            for key, (a, b) in ledger.steps.items():
                if b["method_id"] == owner and ledger.facts[key]["status"] != "VERIFIER_REFUTED":
                    tracked.setdefault(b["tracked_variable_or_expr"], b)
            for assignment in sorted(set(assignments), key=lambda item: item.start_byte):
                left = assignment.child_by_field_name("left") or assignment.child_by_field_name("name")
                right = assignment.child_by_field_name("right") or assignment.child_by_field_name("value")
                if left is None or right is None or assignment.end_point.row - assignment.start_point.row >= 40:
                    continue
                tokens = {part.text.decode() for part in walk(right) if part.type == "identifier"
                          and not (part.parent is not None and part.parent.type == "method_invocation"
                                   and part.parent.child_by_field_name("name") == part)}
                origins = [step for symbol, step in tracked.items() if symbol.rsplit(".", 1)[-1] in tokens
                           and step["line_start"] <= assignment.start_point.row + 1]
                if not origins:
                    tracked.pop(left.text.decode(), None)
                    continue
                expression = left.text.decode()
                draft = {"file_path": method.repository_relative_path, "line_start": assignment.start_point.row + 1,
                         "line_end": assignment.end_point.row + 1, "method_symbol": owner,
                         "tracked_variable_or_expr": expression, "step_role": "PROPAGATION"}
                try:
                    target = checker.step(draft)[0]
                    origin = max(origins, key=lambda step: step["line_start"])
                    kind = "FIELD_STATE" if left.type == "field_access" else "DIRECT_CALL"
                    ledger.add_checked(origin, target, kind, "intra_method_hop", 0.5)
                    tracked[expression] = target
                except ValueError:
                    continue
        # Field declarations bind the two sites; same-object/lifecycle semantics
        # remain explicit pending review, even though this is useful navigation.
        for field_id, sites in self.state_index.accesses.items():
            field = self.state_index.fields[field_id]
            writers = [b for _, b in list(ledger.steps.values())
                       if b["tracked_variable_or_expr"].rsplit(".", 1)[-1] == field.simple_name
                       and any(s["access"] == "WRITE" and s["method_id"] == b["method_id"]
                               and b["line_start"] <= s["line"] <= b["line_end"] for s in sites)]
            for writer in writers[:4]:
                for site in sites:
                    if site["access"] != "READ" or site["method_id"] == writer["method_id"]:
                        continue
                    draft = {"file_path": site["file"], "line_start": site["line"], "line_end": site["line"],
                             "method_symbol": site["method_id"], "tracked_variable_or_expr": field.simple_name,
                             "step_role": "PROPAGATION"}
                    try:
                        target = checker.step(draft)[0]
                        ledger.add_checked(writer, target, "FIELD_STATE", "field_state_bridge", 0.4)
                    except ValueError:
                        continue
        if len(ledger.facts) > before:
            self.event(node, "dataflow_facts_seeded", added=len(ledger.facts) - before, **ledger.context())

    def state_query(self, node, action):
        case = self.cases[node.cwe]
        if self.state_index is None or not self.branch_remaining(node):
            return "TOOL_BUDGET_EXHAUSTED", {}
        case.tool_calls = self.tool_calls + 1
        self.tool_calls += 1
        self.branch_calls[node.cwe] += 1
        try:
            result = self.state_index.query(action["symbol"], action["enclosing_type"], action.get("direction", "both"),
                                            self.focus[node.cwe])
            result["matches"] = [{**row, "entity": _symbol(case.entities[row["method_id"]].to_dict())}
                                 for row in result["matches"]]
            status = "STATE_DISPATCH_MATCHES" if result["matches"] else "NO_STATE_DISPATCH_MATCH"
        except (KeyError, ValueError, TypeError) as exc:
            status, result = "INVALID_ACTION", {"error": str(exc)[:300]}
        self.event(node, "action_result", action=action, status=status, result=result)
        if result.get("matches"):
            sites = [(row["method_id"], row["line"], row["line"]) for row in result["matches"]]
            self.read_edge_windows(node, sites, limit=min(4, self.branch_remaining(node)))
        return status, result

    def prefetch_state(self, node, result):
        proof = result["evidence"]
        owner = self.retrieval.owner(self.cases[node.cwe].entities[result["entity"]["entity_id"]])
        used = sum(key[:2] == (node.cwe, node.round) for key in self.state_prefetched)
        if used >= 4:
            return
        sites = [site for field in sorted(self.state_index.field_uses.get(owner, ()))
                 for site in self.state_index.accesses[field] if site["method_id"] == owner
                 and proof["start_line"] <= site["line"] <= proof["end_line"]]
        for site in sorted(sites, key=lambda row: (row["line"], row["field_id"], row["access"])):
            direction = "forward" if site["access"] == "WRITE" else "backward"
            marker = node.cwe, node.round, site["field_id"], direction
            if marker in self.state_prefetched:
                continue
            if sum(key[:2] == (node.cwe, node.round) for key in self.state_prefetched) >= 4:
                break
            self.state_prefetched.add(marker)
            self.state_query(node, {"action": "query_state_and_dispatch_bridge", "symbol": site["field"],
                                   "enclosing_type": site["declaring_type"], "direction": direction})
            self.event(node, "state_bridge_prefetch", field_id=site["field_id"], direction=direction)

    def evp_anchor_steps(self, cwe):
        case = self.cases[cwe]
        nav = self.retrieval.branch_navigation(cwe)
        result = {"source": [], "sink": []}
        checker = EvidenceChain(case, self.retrieval, self.value_paths)
        for role, entities in (("source", nav.sources), ("sink", nav.sinks)):
            for entity in entities:
                owner = self.retrieval.owner(entity)
                if entity.kind.value in {"METHOD", "CONSTRUCTOR"}:
                    members = self.retrieval.by_callable[self.retrieval._scope_from_method(entity)]
                    options = [e for e in members if e.kind.value == ("PARAMETER" if role == "source" else "CALL")]
                else:
                    options = [entity]
                for option in options:
                    draft = {"file_path": option.repository_relative_path, "line_start": option.start_line,
                             "line_end": option.start_line, "method_symbol": owner,
                             "tracked_variable_or_expr": option.simple_name,
                             "step_role": "SOURCE" if role == "source" else "SINK"}
                    try:
                        step = checker.step(draft)[0]
                    except ValueError:
                        continue
                    if not any(row["method_id"] == step["method_id"] and row["line_start"] == step["line_start"]
                               for row in result[role]):
                        result[role].append(step)
                    if len(result[role]) >= 4:
                        break
                if len(result[role]) >= 4:
                    break
        return result

    def evp_synthesis_ready(self, cwe, anchors):
        endpoint_refs = {step["evidence_id"] for group in anchors.values() for step in group}
        intermediates = {ref for ref, proof in self.cases[cwe].evidence.items()
                         if proof.source_kind == EvidenceSourceKind.SOURCE_SNIPPET} - endpoint_refs
        return bool(anchors["source"] and anchors["sink"] and
                    (len(self.fact_ledgers[cwe].facts) >= 2 or len(intermediates) >= 2))

    def probe_semantic_bridges(self, node, path, assumed):
        key = node.cwe, path.candidate_path_id
        if key in self.semantic_probes:
            return self.semantic_probes[key]
        case = self.cases[node.cwe]
        before = set(case.evidence)
        probes = []
        for hop_id, hop in assumed.items():
            if hop.get("kind") != "SEMANTIC_BRIDGE":
                continue
            a, b = (case.entities[hop[side]["method_id"]] for side in ("from_step", "to_step"))
            fields = self.state_index.field_uses[a.entity_id] | self.state_index.field_uses[b.entity_id]
            queries = [(self.state_index.fields[identity].simple_name,
                        self.state_index.fields[identity].enclosing_type) for identity in sorted(fields)]
            queries.extend(((b.simple_name, a.enclosing_type), (a.simple_name, b.enclosing_type)))
            hits = []
            query_statuses = []
            for symbol, enclosing in list(dict.fromkeys(queries))[:6]:
                status, result = self.state_query(node, {"action": "query_state_and_dispatch_bridge", "symbol": symbol,
                                                        "enclosing_type": enclosing, "direction": "both"})
                query_statuses.append(status)
                hits.extend(result.get("matches", ()))
            # The exact endpoints and callers are also deterministic probes when
            # state indexing finds no implementation for a callback binding.
            sites = [(a.entity_id, hop["from_step"]["line_start"], hop["from_step"]["line_end"]),
                     (b.entity_id, hop["to_step"]["line_start"], hop["to_step"]["line_end"])]
            for target in (a.entity_id, b.entity_id):
                for _, witnesses in self.backward_callers(self.retrieval.branch_navigation(node.cwe), target)[:2]:
                    sites.extend(witnesses)
            self.read_edge_windows(node, sites, limit=min(6, self.branch_remaining(node)))
            probes.append({"hop_id": hop_id, "testable_condition": hop["semantic_bridge"]["testable_condition"],
                           "matches": hits, "query_statuses": query_statuses,
                           "status": "TARGETED_PASS_COMPLETED" if any(status in {
                               "STATE_DISPATCH_MATCHES", "NO_STATE_DISPATCH_MATCH"} for status in query_statuses)
                           else "TARGETED_PASS_NOT_EXECUTED"})
        record = {"probes": probes, "evidence_refs": sorted(set(case.evidence) - before)}
        self.semantic_probes[key] = record
        self.event(node, "semantic_bridge_probe", candidate_path_id=path.candidate_path_id, **record)
        return record

    def graph_context(self, node: Node, entity_ids: list[str], *, direction: str = "both",
                      kind: str | None = None, offset: int = 0) -> list[dict]:
        graph = self.retrieval.graph
        if graph is None:
            return []
        case = self.cases[node.cwe]
        records = []
        ranked = graph.context(entity_ids, direction=direction, kind=kind, offset=offset)
        selected = ranked[:4]
        if len(selected) == 4 and direction == "both" and kind is None and offset == 0:
            other_kind = next((relation for relation in ranked[4:] if relation["kind"] != selected[0]["kind"]), None)
            if other_kind is not None and all(relation["kind"] == selected[0]["kind"] for relation in selected):
                selected[-1] = other_kind
        for relation in selected:
            kind = relation["kind"]
            if kind in {"CODEQL_VIRTUAL_DISPATCH", "CODEQL_FIELD_STATE"}:
                records.append({**_compact_relation(relation), "navigation_only": True})
                continue
            digest = hashlib.sha256(canonical_json(relation).encode()).hexdigest()
            artifact = f"repository-graph:{digest}"
            proof = EvidenceRef.create(
                source_kind="CODEQL_CALL" if kind == "CODEQL_DIRECT_CALL" else kind,
                entity_ids=list(dict.fromkeys(point["entity_id"] for point in (relation["from"], relation["to"]))),
                confidence=EvidenceStrength.SUPPORTING,
                artifact_ref=artifact,
                result_hash=digest,
                provenance={"producer": "RepositoryGraph.ql", "csv_sha256": graph.sha256},
            )
            if proof.evidence_id not in case.evidence:
                case.evidence[proof.evidence_id] = proof
                case.tool_results[artifact] = relation
                self.event(node, "codeql_relation", evidence=proof.to_dict(), relation=relation)
            records.append({"evidence_id": proof.evidence_id, **_compact_relation(relation)})
        return records

    @staticmethod
    def proposal_gap(case: _Case, action: Mapping[str, Any]) -> str | None:
        if action.get("action") != "propose" or not isinstance(draft := action.get("proposal"), dict):
            return None
        subject = draft.get("subject")
        if draft.get("proposal_type") == "EXTERNAL_INPUT" and isinstance(subject, dict):
            subject_id = subject.get("entity_id")
            entity = case.entities.get(subject_id) if isinstance(subject_id, str) else None
            if entity and (entity.provenance.get("private") or entity.provenance.get("private_callable")):
                return "PRIVATE_CALLABLE_INPUT: trace to the exposed entry or framework input and propose the transfer."
        refs = draft.get("evidence_refs")
        if isinstance(refs, list):
            kinds = {case.evidence[ref].source_kind for ref in refs if isinstance(ref, str) and ref in case.evidence}
            graph_kinds = {EvidenceSourceKind.CODEQL_CALL, EvidenceSourceKind.CODEQL_LOCAL_FLOW}
            if kinds & graph_kinds:
                if draft.get("proposal_type") not in {"WRAPPER_FLOW", "LIBRARY_FLOW", "FIELD_STATE"}:
                    return "CODEQL_RELATION_IS_TRANSFER_SUPPORT_ONLY: cite source for an endpoint."
                if EvidenceSourceKind.SOURCE_SNIPPET not in kinds:
                    return "CODEQL_RELATION_NEEDS_SOURCE: read and cite the exact argument, assignment or return."
        return None

    def action(self, node: Node, action: Mapping[str, Any], *, prefetch=True) -> tuple[str, dict]:
        case = self.cases[node.cwe]
        name = action.get("action")
        if name == "record_verified_subpaths" and self.general_evp:
            result = self.merge_facts(node, action.get("verified_subpaths", []))
            self.event(node, "action_result", action=action, status="SUBPATHS_RECORDED", result=result)
            return "SUBPATHS_RECORDED", result
        if name == "query_state_and_dispatch_bridge" and self.general_evp:
            return self.state_query(node, action)
        if name == "recall_source" and self.value_paths is not None:
            ref = action.get("evidence_id")
            proof = case.evidence.get(ref) if isinstance(ref, str) else None
            if proof is None or proof.source_kind != EvidenceSourceKind.SOURCE_SNIPPET:
                status, result = "INVALID_ACTION", {"error": "Select a source evidence ID from this branch."}
            else:
                self.recalled[node.cwe, node.round].add(ref)
                self.read_rounds[node.cwe, ref] = node.round
                status, result = "SOURCE_RECALLED", {"evidence_id": ref}
            self.event(node, "action_result", action=action, status=status, result=result)
            return status, result
        if name == "read_static_spine" and self.value_paths is not None:
            return self.read_static_spine(node, action)
        search = name == "search_symbols"
        rag = self.agentic_rag and name in ("search_code", "follow_graph")
        tool = search or rag or name in ("inspect_entity", "inspect_output_contract")
        if search and action.get("kind") == "CLASS":
            action = {**action, "kind": "TYPE"}
        read_action = action
        source_key = None
        window_adjustment = None
        if name == "inspect_entity":
            entity_id = action.get("entity_id")
            entity = case.entities.get(entity_id) if isinstance(entity_id, str) else None
            if entity is not None:
                if (prefetch and self.value_paths is not None and entity.kind.value in {"METHOD", "CONSTRUCTOR"}
                        and not {"start_line", "end_line", "line_start", "line_end"}.intersection(action)):
                    sites = self.method_sites(node, entity_id)
                    if sites:
                        results = self.read_edge_windows(node, sites, limit=self.branch_remaining(node))
                        self.prefetch_neighbors(node, entity_id)
                        if results:
                            return results[0]
                start = action.get("start_line", action.get("line_start", entity.start_line))
                end = action.get("end_line", action.get("line_end"))
                if "end_line" not in action and "line_end" not in action and type(start) is int:
                    end = max(start, min(entity.end_line, start + 39))
                bounds = {"start_line": entity.start_line, "end_line": entity.end_line, "max_lines": 40}
                if type(start) is not int or type(end) is not int or start > end:
                    result = {"valid_range": bounds,
                              "guidance": "Supply ordered integer lines or omit both coordinates to read the declaration."}
                    self.event(node, "action_result", action=action, status="INVALID_SOURCE_RANGE", result=result)
                    return "INVALID_SOURCE_RANGE", result
                first = min(max(start, entity.start_line), entity.end_line)
                last = min(max(end, entity.start_line), entity.end_line, first + 39)
                if (first, last) != (start, end):
                    window_adjustment = {
                        "requested": {"start_line": start, "end_line": end},
                        "used": {"start_line": first, "end_line": last}, "valid_range": bounds,
                    }
                read_action = {**action, "start_line": first, "end_line": last}
                proof = source_read_coverage(case, entity_id, first, last)
                if proof is not None:
                    result = {"evidence_id": proof.evidence_id,
                              "guidance": "Reuse this source evidence or inspect an unread caller, branch or return."}
                    if window_adjustment is not None:
                        result["window_adjustment"] = window_adjustment
                    self.event(node, "action_result", action=action, status="SOURCE_ALREADY_READ", result=result)
                    if prefetch:
                        self.prefetch_neighbors(node, self.retrieval.owner(entity))
                    return "SOURCE_ALREADY_READ", result
                source_key = (entity_id, first, last)
                cached = next((value for (owner, low, high), value in self.source_cache.items()
                               if owner == entity_id and low <= first <= last <= high), None)
                if cached is not None:
                    data, proof = cached
                    case.evidence[proof.evidence_id] = proof
                    case.tool_results[proof.tool_call_id] = data
                    result = {key: value for key, value in data.items() if key != "window_adjustment"}
                    if window_adjustment is not None:
                        result["window_adjustment"] = window_adjustment
                    self.event(node, "action_result", action=action, status="SOURCE_CACHE_HIT", result=result)
                    self.read_rounds[node.cwe, proof.evidence_id] = node.round
                    if prefetch:
                        self.prefetch_neighbors(node, self.retrieval.owner(entity))
                    return "SOURCE_CACHE_HIT", result
        query_key = (str(action.get("query", "")).casefold().strip(), str(action.get("kind") or ""))
        if search and query_key in self.searched[node.cwe]:
            status = "REPEATED_QUERY"
            result = {"prior_status": self.searched[node.cwe][query_key]}
            self.event(node, "action_result", action=action, status=status, result=result)
            return status, result
        cache_key = (name, query_key)
        if self.value_paths is not None and name in {"search_symbols", "search_code"} and cache_key in self.search_cache:
            status, data = self.search_cache[cache_key]
            if search:
                self.searched[node.cwe][query_key] = status
            self.event(node, "action_result", action=action, status="SEARCH_CACHE_HIT", result=data)
            return "SEARCH_CACHE_HIT", data
        if tool and not self.branch_remaining(node):
            status = "BRANCH_TOOL_BUDGET_EXHAUSTED"
            self.event(node, "action_result", action=action, status=status, result={})
            return status, {}
        gap = self.proposal_gap(case, action)
        if gap is not None:
            result = {"missing_evidence": [gap]}
            self.event(node, "action_result", action=action, status="NEEDS_MORE_EVIDENCE", result=result)
            return "NEEDS_MORE_EVIDENCE", result
        case.tool_calls = self.tool_calls
        try:
            if rag:
                selector = action["query"] if name == "search_code" else action["entity_id"]
                if not isinstance(selector, str) or not 1 <= len(selector.strip()) <= 120:
                    raise ValueError("Supply a bounded query or an indexed entity ID.")
                request = (node.cwe, name, canonical_json(dict(action)))
                if request in self.rag_requests:
                    status, result = "REPEATED_QUERY", {}
                else:
                    case.tool_calls += 1
                    if name == "search_code":
                        hits = case.tools.search_code(selector, max_hits=5)
                        status, result = "LEXICAL_RESULT", {"hits": hits}
                    elif selector in case.entities:
                        direction = action.get("direction", "both")
                        kind = action.get("relation_kind")
                        offset = action.get("offset", 0)
                        relations = self.graph_context(node, [selector], direction=direction, kind=kind, offset=offset)
                        focus = {selector}
                        for relation in relations:
                            focus.update(relation[side]["entity_id"] for side in ("from", "to"))
                        native = [path for path in self.retrieval.static_flow_hints
                                  if any(point["entity_id"] in focus for point in path["nodes"])]
                        status, result = "GRAPH_RESULT", {
                            "relations": relations,
                            "next_offset": offset + 4 if len(relations) == 4 else None,
                            "native_flow_hints": native[offset:offset + 2],
                            "native_next_offset": offset + 2 if len(native) > offset + 2 else None,
                        }
                    else:
                        status, result = "UNKNOWN_ENTITY", {}
                    self.rag_requests.add(request)
            elif name == "record_case":
                result = audit_note(case, action)
                self.audit_cases[node.cwe] = result
                status = "CASE_RECORDED"
            elif name == "inspect_output_contract":
                graph = self.retrieval.graph
                spec = graph.output_contract(action["entity_id"]) if graph is not None else None
                if spec is None:
                    raise ValueError("The source graph has no documented output contract for that entity.")
                case.tool_calls += 1
                call_id = f"tool-{case.tool_calls:03d}"
                result = case.read_source(spec["entity_id"], spec["start_line"], spec["end_line"],
                                          call_id, contract_scope=spec["scope"])
                case.tool_results[call_id] = result
                status = "SOURCE_READ"
            elif name == "submit_path":
                conditions = _strings(action.get("conditions", []), 5)
                if self.path_sensitive and not conditions:
                    raise ValueError("Provide concrete trigger or use conditions before submitting a path.")
                status, result = submit_path(case, action.get("proposals"), self.model_calls, self.proposal_gap)
                if status == "PATH_SUBMITTED" and conditions:
                    for identity in result["candidate_path_ids"]:
                        self.path_claims[(node.cwe, identity)] = {"conditions": conditions}
                note = result.get("audit_case")
                previous = self.audit_cases.get(node.cwe)
                if note is not None and (previous is None or previous["anchor_entity_id"] == note["anchor_entity_id"]):
                    self.audit_cases[node.cwe] = note
                    self.event(node, "case_from_incomplete_path", case_id=note["case_id"],
                               missing_components=result["missing_components"])
            elif name == "submit_bridge" and self.value_paths is not None:
                status, result = self.submit_bridge(node, action)
            elif name == "propose_assumed_bridge" and self.value_paths is not None:
                status, result = self.propose_assumed_bridge(node, action)
            elif name in {"remember_witness_path", "submit_witness_path"} and self.value_paths is not None:
                status, result = self.witness_path(node, action, complete=name == "submit_witness_path")
            else:
                dispatch = {**action, "prefer_declarations": True} if search else read_action
                status, result = case.dispatch(dispatch, self.model_calls, self.limits)
                if status == "SOURCE_READ" and window_adjustment is not None:
                    result["window_adjustment"] = window_adjustment
        except (KeyError, ValueError, TypeError, AttributeError, OSError) as exc:
            status = "TOOL_ERROR" if self.repair_protocol and isinstance(exc, OSError) else "INVALID_ACTION"
            result = {"error": str(exc)[:300]}
        self.branch_calls[node.cwe] += case.tool_calls - self.tool_calls
        self.tool_calls = case.tool_calls
        if search and status != "TOOL_ERROR":
            self.searched[node.cwe][query_key] = status
        if self.value_paths is not None:
            if status == "SOURCE_READ" and source_key is not None:
                self.source_cache[source_key] = (result, case.evidence[result["evidence"]["evidence_id"]])
            if status in {"SYMBOLS_FOUND", "NO_SYMBOL_MATCH", "LEXICAL_RESULT"}:
                self.search_cache[cache_key] = status, result
        self.event(node, "action_result", action=action, status=status, result=result)
        if status == "SOURCE_READ" and "evidence" in result:
            self.read_rounds[node.cwe, result["evidence"]["evidence_id"]] = node.round
            if self.general_evp:
                self.prefetch_state(node, result)
        if prefetch and name == "inspect_entity" and status == "SOURCE_READ":
            self.prefetch_neighbors(node, self.retrieval.owner(case.entities[action["entity_id"]]))
        return status, result

    def link_priority(self, nav, owner, neighbor, link):
        return (link.kind != "VALUE_BRIDGE",
                self.retrieval.entities[owner].enclosing_type != self.retrieval.entities[neighbor].enclosing_type,
                not self.retrieval.same_package(owner, neighbor), nav.distance.get(neighbor, float("inf")),
                neighbor, link.sites)

    def method_sites(self, node, owner):
        nav = self.retrieval.branch_navigation(node.cwe)
        links = sorted(self.value_paths.strict_sites.get(owner, ()), key=lambda link: self.link_priority(
            nav, owner, link.target if link.origin == owner else link.origin, link))
        return list(dict.fromkeys(site for link in links for site in link.sites if site[0] == owner))

    def read_edge_windows(self, node, sites, *, limit):
        case = self.cases[node.cwe]
        missing = [site for site in sites if not self.value_paths.proof(case, site)]
        results = []
        for owner, first, last in self.retrieval.edge_windows(missing)[:limit]:
            if not self.branch_remaining(node):
                break
            result = self.action(node, {"action": "inspect_entity", "entity_id": owner,
                                       "start_line": first, "end_line": last}, prefetch=False)
            results.append(result)
        return results

    def static_spine_hints(self, node):
        nav = self.retrieval.branch_navigation(node.cwe)
        case = self.cases[node.cwe]
        return [{"id": spine["id"], "typed_source_to_sink": spine["typed_source_to_sink"],
                 "methods": [{"id": owner, "signature": case.entities[owner].signature or case.entities[owner].qualified_name,
                              "file": case.entities[owner].repository_relative_path} for owner in spine["methods"]],
                 "edge_kinds": spine["edge_kinds"],
                 "edge_sites": [{"method_id": owner, "start": start, "end": end,
                                 "read": self.value_paths.proof(case, (owner, start, end)) is not None}
                                for owner, start, end in spine["sites"]]}
                for spine in self.value_paths.static_spines(nav, node.cwe).values()]

    def read_static_spine(self, node, action):
        nav = self.retrieval.branch_navigation(node.cwe)
        identity = action.get("spine_id")
        spine = self.value_paths.static_spines(nav, node.cwe).get(identity) if isinstance(identity, str) else None
        if spine is None:
            status, result = "INVALID_ACTION", {"error": "Unknown static spine ID."}
        else:
            self.spine_requests[node.cwe].add(identity)
            results = self.read_edge_windows(node, spine["sites"], limit=self.branch_remaining(node))
            case = self.cases[node.cwe]
            missing = sum(self.value_paths.proof(case, site) is None for site in spine["sites"])
            status = ("SPINE_WINDOWS_INCOMPLETE" if missing else
                      "SPINE_WINDOWS_READ" if results else "SPINE_ALREADY_READ")
            result = {"spine_id": spine["id"], "missing_sites": missing, "source_windows": len(results)}
        self.event(node, "action_result", action=action, status=status, result=result)
        return status, result

    def prefetch_neighbors(self, node, owner, direction=None):
        if self.value_paths is None or not self.branch_remaining(node):
            return
        nav = self.retrieval.branch_navigation(node.cwe)
        if owner not in nav.eligible:
            return
        if direction is None:
            direction = 1 if owner in nav.sink_owners else 0
        marker = (node.cwe, owner, direction)
        if marker in self.prefetched:
            return
        self.prefetched.add(marker)
        case = self.cases[node.cwe]
        candidates = []
        for link in self.value_paths.strict_links[direction].get(owner, ()):
            other = link.target if direction == 0 else link.origin
            if other not in nav.eligible:
                continue
            if all(self.value_paths.proof(case, site) for site in link.sites):
                continue
            candidates.append((other, link))
        selected = set()
        for other, link in sorted(candidates, key=lambda item: self.link_priority(nav, owner, *item)):
            if len(selected) >= 2 or not self.branch_remaining(node):
                break
            if other in selected:
                continue
            results = self.read_edge_windows(node, link.sites, limit=4)
            selected.add(other)
            for status, result in results:
                self.event(node, "strict_neighbor_prefetch", owner=owner, neighbor=other,
                           direction="forward" if direction == 0 else "backward", edge_kind=link.kind,
                           sites=link.sites, line=result.get("evidence", {}).get("start_line"), status=status)
        self.prefetch_relays(node, owner)

    def prefetch_relays(self, node, owner):
        marker = node.cwe, node.round
        if self.relay_reads[marker] >= 2:
            return
        case = self.cases[node.cwe]
        nav = self.retrieval.branch_navigation(node.cwe)
        read = {self.retrieval.owner(case.entities[identity]) for proof in case.evidence.values()
                if proof.source_kind == EvidenceSourceKind.SOURCE_SNIPPET for identity in proof.entity_ids}
        endpoints = [owner, *self.focus[node.cwe], *(item["method_id"] for item in nav.context()["sinks"]),
                     *(item["method_id"] for item in nav.context()["sources"]), *sorted(read)]
        anchors = list(dict.fromkeys(endpoints))[:24]
        for (middle, kind, left, right), sites in self.value_paths.relay_sites(anchors, nav.eligible):
            if owner not in (left, right) or not read.intersection((left, right)):
                continue
            remaining = 2 - self.relay_reads[marker]
            if remaining <= 0 or not self.branch_remaining(node):
                break
            results = self.read_edge_windows(node, sites, limit=remaining)
            self.relay_reads[marker] += len(results)
            if results:
                self.event(node, "strict_relay_prefetch", middle=middle, relation=kind,
                           endpoints=[left, right], sites=sites, windows=len(results))

    def discover(self, node: Node) -> dict:
        if self.value_paths is not None:
            if node.cwe == SUPPORTED_CWES[0]:
                inventories = {}
                for cwe in SUPPORTED_CWES:
                    navigation = self.retrieval.branch_navigation(cwe).context()
                    catalog = [{key: value for key, value in row.items() if key != "file"}
                               for row in self.catalogues[cwe][:12]]
                    hints = [{key: value for key, value in row.items() if key not in {"file", "method_id"}}
                             | {"kind": kind}
                             for kind, label in (("SOURCE_HINT", "sources"), ("SINK_HINT", "sinks"))
                             for row in navigation[label][:3]]
                    inventories[cwe] = list({row["entity_id"]: row for row in [*catalog, *hints]}.values())
                action = self.ask(node, {"task": "project_discovery", "inventories": inventories})
                for cwe, branch in action.get("branches", {}).items():
                    self.queries[cwe] = _strings(branch["queries"], _DISCOVERY_QUERIES)
                    self.discovery_hypotheses[cwe] = branch.get("hypotheses", [])
                    if self.general_evp:
                        self.retrieval.add_inferred_anchors(cwe, branch.get("inferred_source_anchors", []),
                                                           branch.get("inferred_sink_anchors", []))
                        self.value_paths.spines.pop(cwe, None)
            return {"queries": self.queries[node.cwe], "hypotheses": self.discovery_hypotheses[node.cwe]}
        action = self.ask(node, {
            "knowledge": retrieve_knowledge(node.cwe, []),
            "repository_inventory": self.catalogues[node.cwe],
            "prior_queries": [{"query": key[0], "status": status}
                              for key, status in self.searched[node.cwe].items()][-16:],
        })
        try:
            queries = _strings(action.get("queries", []), _DISCOVERY_QUERIES)
        except ValueError as exc:
            self.event(node, "invalid_discovery", error=str(exc))
            queries = []
        self.queries[node.cwe] = queries
        self.discovery_hypotheses[node.cwe] = action.get("hypotheses", [])
        return {"queries": queries, "hypotheses": self.discovery_hypotheses[node.cwe]}

    def capture_script_obligation(self, node: Node, seed: str, document: dict, return_ref: str | None,
                                  boundary: dict) -> None:
        contract_text = _window(document)["source"].casefold()
        if "html script" not in contract_text and "<script>" not in contract_text:
            return
        graph = self.retrieval.graph
        dispatch = graph.script_dispatch(seed)
        if dispatch is None:
            return
        self.event(node, "script_contract_check", entity_id=seed, **dispatch)
        if dispatch["result"] != "LOCAL_GAP":
            return
        case = self.cases[node.cwe]
        entity = case.entities[seed]
        continuation = min(line for lines in dispatch["locally_unmodified_state_symbols"].values() for line in lines)
        start = max(entity.start_line, continuation - 5)
        end = min(entity.end_line, continuation + 2)
        status, value = self.action(node, {"action": "inspect_entity", "entity_id": seed,
                                           "start_line": start, "end_line": end})
        if status not in ("SOURCE_READ", "SOURCE_ALREADY_READ"):
            return
        ref = value["evidence"]["evidence_id"] if status == "SOURCE_READ" else value["evidence_id"]
        doc_ref = document["evidence"]["evidence_id"]
        entry = document["entity"]["entity_id"]
        read_line = dispatch["character_read_line"]
        input_witness = graph.character_input_witness(entry, seed, read_line)
        shared = graph.shared_field_return(entry, seed, read_line, boundary["return_site"]["line"])
        fallback_ref = None
        producer = boundary.get("return_producer")
        if shared is not None and producer is not None:
            fallback = case.entities[producer["entity_id"]]
            line = shared["fallback_line"]
            if fallback.repository_relative_path == shared["fallback_file"] and fallback.start_line <= line <= fallback.end_line:
                action = {"action": "inspect_entity", "entity_id": fallback.entity_id,
                          "start_line": max(fallback.start_line, min(line, shared["guard_line"]) - 1),
                          "end_line": min(fallback.end_line, line + 1)}
                fallback_status, result = self.action(node, action)
                if fallback_status == "SOURCE_READ":
                    fallback_ref = result["evidence"]["evidence_id"]
                elif fallback_status == "SOURCE_ALREADY_READ":
                    fallback_ref = result["evidence_id"]
        state = None
        state_refs = []
        if shared is not None and producer is not None:
            edge = next((edge for edge in boundary["call_sites"]
                         if edge["from"]["line"] == shared["process_call_line"]), None)
            if edge is not None:
                processor = case.entities[edge["to"]["entity_id"]]
                state = graph.output_state_windows(producer["entity_id"], processor.entity_id, shared["fallback_line"])
                if state is not None:
                    windows = [(state["initialize_line"], state["initialize_line"]), state["final_check"]]
                    for first, last in windows:
                        status, source = self.action(node, {
                            "action": "inspect_entity", "entity_id": processor.entity_id,
                            "start_line": max(processor.start_line, first - 2),
                            "end_line": min(processor.end_line, last + 3),
                        })
                        if status == "SOURCE_READ":
                            state_refs.append(source["evidence"]["evidence_id"])
                        elif status == "SOURCE_ALREADY_READ":
                            state_refs.append(source["evidence_id"])
        return_branch = []
        windows = []
        if state is not None and input_witness is not None:
            windows = graph.quoted_branch_windows(processor.entity_id, seed, state["final_check"][0])
            if windows:
                # Include the loop setup as well as the branch so intervening writes are visible.
                branch = windows[0]
                start = max(processor.start_line, state["initialize_line"] - 3)
                if branch["end_line"] - start >= 40:
                    windows = []
                else:
                    branch["start_line"] = start
            if windows:
                windows.extend((
                    {"role": "quoted_string_entry", "entity_id": seed,
                     "start_line": entity.start_line, "end_line": min(entity.end_line, entity.start_line + 32)},
                    {"role": "quoted_string_exit", "entity_id": seed,
                     "start_line": max(entity.start_line, entity.end_line - 4), "end_line": entity.end_line},
                    {"role": "before_finalization", "entity_id": processor.entity_id,
                     "start_line": max(processor.start_line, state["final_check"][0] - 13),
                     "end_line": state["final_check"][0] - 1},
                ))
            for window in windows:
                status, source = self.action(node, {"action": "inspect_entity", **{
                    key: window[key] for key in ("entity_id", "start_line", "end_line")
                }})
                if status in {"SOURCE_READ", "SOURCE_ALREADY_READ"}:
                    evidence_id = (source["evidence"]["evidence_id"] if status == "SOURCE_READ"
                                   else source["evidence_id"])
                    return_branch.append({"role": window["role"], "evidence_id": evidence_id})
        dispatch = {**dispatch, "entry_to_character_read": input_witness, "shared_field_return": shared,
                    "fallback_evidence_id": fallback_ref, "output_state": state, "state_evidence_ids": state_refs,
                    "return_branch_evidence": return_branch, "public_return_evidence_id": return_ref,
                    "return_branch_complete": bool(windows) and len(windows) == len(return_branch)}
        proof = source_read_coverage(case, seed, read_line, read_line)
        evidence_refs = [ref, doc_ref, *([return_ref] if return_ref else []),
                         *([proof.evidence_id] if proof is not None else [])]
        evidence_refs = list(dict.fromkeys(evidence_refs))
        note = audit_note(case, {
            "anchor_entity_id": seed, "evidence_refs": evidence_refs,
            "hypothesis": "The local character loop leaves the HTML script-data transition symbol classes unchanged.",
            "next_question": "Do these unmodified characters reach the documented public output through this audited branch?",
        })
        self.contract_obligations[node.cwe] = {
            "note": note, "obligation": dispatch, "local_gap_proof_refs": [ref, doc_ref],
        }
        self.event(node, "contract_obligation", case_id=note["case_id"], entity_id=seed,
                   evidence_refs=evidence_refs, rule=dispatch["rule"])

    def retrieve(self, node: Node) -> dict:
        pivot_owners = self.apply_pivot(node) if node.cwe in self.pivots else ()
        pending = self.retrieval_tasks.pop(node.cwe, [])
        for request in pending:
            status, _ = self.action(node, request)
            self.event(node, "retrieval_task_finished", action=request, status=status)
        if self.value_paths is not None:
            return self.retrieve_paths(node, new_anchors=pivot_owners)
        if node.round > 1 and self.mode == "adaptive":
            discovery = Node(node.id, "discovery", node.needs, node.cwe, node.round)
            self.discover(discovery)
        queries = self.queries[node.cwe]
        locations = self.retrieval.static_locations
        note = self.audit_cases.get(node.cwe)
        preserved = [note["anchor_entity_id"]] if note is not None else []
        hypotheses = [row["anchor_entity_id"] for row in self.discovery_hypotheses[node.cwe]]
        selected = dict.fromkeys([*self.focus[node.cwe], *preserved, *hypotheses, *list(locations)[:2]])
        other_hits = []
        exact_methods = []
        for query in queries:
            _, found = self.action(node, {"action": "search_symbols", "query": query})
            matches = sorted(found.get("matches", []), key=lambda hit: (
                hit["entity"]["simple_name"].casefold() != query.casefold(),
                hit["entity"]["kind"] not in {"METHOD", "CONSTRUCTOR"},
            ))
            if matches:
                first = matches[0]["entity"]
                selected.setdefault(first["entity_id"], None)
                if first["kind"] == "METHOD" and first["simple_name"].casefold() == query.rsplit(".", 1)[-1].casefold():
                    exact_methods.append((query, first["entity_id"]))
                other_hits.extend(hit["entity"]["entity_id"] for hit in matches[1:3])
        if exact_methods and node.cwe not in self.seed_methods:
            self.seed_methods[node.cwe] = [
                entity_id for _, entity_id in sorted(exact_methods, key=lambda item: -len(item[0]))
            ]
        for entity_id in other_hits:
            selected.setdefault(entity_id, None)
        if not selected:
            selected.update({row["entity_id"]: None for row in self.catalogues[node.cwe][:8]})
        case = self.cases[node.cwe]
        already_read = {item for proof in case.evidence.values()
                        if proof.source_kind == EvidenceSourceKind.SOURCE_SNIPPET for item in proof.entity_ids}
        for entity_id in list(selected)[:3]:
            for neighbor in self.retrieval.neighbors(entity_id):
                selected.setdefault(neighbor.entity_id, None)
        observations = []
        for entity_id in [key for key in selected if key not in already_read][:_RETRIEVAL_READS]:
            entity = case.entities[entity_id]
            anchor = locations.get(entity_id, entity.start_line)
            start = max(entity.start_line, anchor - 5)
            end = min(entity.end_line, max(anchor, start + 12))
            status, data = self.action(node, {"action": "inspect_entity", "entity_id": entity_id,
                                               "start_line": start, "end_line": end})
            if status == "SOURCE_READ":
                observations.append(data)
        if node.cwe == "CWE-79" and node.cwe not in self.library_boundaries and self.retrieval.graph is not None:
            for seed in self.seed_methods.get(node.cwe, ()):
                boundary = self.retrieval.graph.library_boundary(seed)
                if boundary is None:
                    continue
                entry = boundary["entry_entity_id"]
                status, doc = self.action(node, {"action": "inspect_output_contract", "entity_id": entry})
                if status != "SOURCE_READ":
                    continue
                returned = boundary["return_site"]
                entity = case.entities[entry]
                start = max(entity.start_line, returned["line"] - 3)
                end = min(entity.end_line, returned["line"] + 2)
                return_status, return_result = self.action(
                    node, {"action": "inspect_entity", "entity_id": entry, "start_line": start, "end_line": end},
                )
                return_ref = (return_result["evidence"]["evidence_id"] if return_status == "SOURCE_READ"
                              else return_result.get("evidence_id"))
                self.capture_script_obligation(node, seed, doc, return_ref, boundary)
                implementation = boundary["implementation_window"]
                branch_ref = None
                if implementation is not None:
                    impl_status, impl_result = self.action(node, {"action": "inspect_entity", "entity_id": seed,
                                                                   "start_line": implementation[0], "end_line": implementation[1]})
                    if impl_status == "SOURCE_READ":
                        branch_ref = impl_result["evidence"]["evidence_id"]
                    elif impl_status == "SOURCE_ALREADY_READ":
                        branch_ref = impl_result["evidence_id"]
                case.documented_returns[entry] = returned["line"]
                self.library_boundaries[node.cwe] = {
                    "entry": _symbol(entity.to_dict()), "contract_evidence_id": doc["evidence"]["evidence_id"],
                    "contract_scope": boundary["contract"]["scope"],
                    "documented_output": _window(doc)["source"],
                    "call_sites": [_compact_relation(edge) for edge in boundary["call_sites"]],
                    "return_site": returned, "return_producer": boundary["return_producer"],
                    "implementation_evidence_id": branch_ref, "return_witness": boundary["return_witness"],
                }
                self.event(node, "library_boundary", seed_entity_id=seed, boundary=self.library_boundaries[node.cwe])
                break
        self.context[node.cwe] = {
            **({"native_flow_hints": self.retrieval.static_flow_hints[:2]}
               if self.retrieval.static_flow_hints else {}),
            "knowledge": retrieve_knowledge(node.cwe, queries),
            "entity_ids": list(selected)[:8],
            "repository_inventory": self.catalogues[node.cwe][:5],
            "codeql_location_ids": [key for key in selected if key in locations][:8],
        }
        return {"anchors": len(selected), "new_source_windows": len(observations),
                "static_locations": len(locations)}

    @staticmethod
    def source_proofs(case: _Case, refs) -> dict:
        proofs = {}
        for ref in dict.fromkeys(refs):
            evidence = case.evidence[ref]
            proofs[ref] = {
                "location": {"start_line": evidence.start_line,
                             "repository_relative_path": evidence.repository_relative_path},
                "source": _window(case.tool_results[evidence.tool_call_id])["source"],
            }
        return proofs

    def reason_library_contract(self, node: Node, case: _Case) -> bool:
        obligation = self.contract_obligations.get(node.cwe)
        if obligation is None or node.cwe in self.contract_reasoned or case.paths().hybrid_paths:
            return False
        details = obligation["obligation"]
        witness = details["entry_to_character_read"]
        if not (witness and details["shared_field_return"] and details["fallback_evidence_id"]
                and details["public_return_evidence_id"] and len(details["state_evidence_ids"]) == 2
                and details["return_branch_complete"]):
            return False
        refs = list(dict.fromkeys([
            *obligation["note"]["evidence_refs"], details["fallback_evidence_id"],
            *details["state_evidence_ids"], *(window["evidence_id"] for window in details["return_branch_evidence"]),
        ]))
        self.contract_reasoned.add(node.cwe)
        task = "trace_path_conditions" if self.path_sensitive or self.repair_protocol else "trace_library_contract"
        action = self.ask(node, {"task": task, "contract": details,
                                 "source_evidence": self.source_proofs(case, refs)})
        cited = action.get("evidence_refs")
        reason = action.get("reason")
        if task == "trace_path_conditions":
            verdict = action.get("violation_status", "PROTOCOL_OR_MODEL_FAILURE")
            if verdict != "VIOLATION_PROVEN":
                self.event(node, "contract_path_not_submitted", reason=verdict)
                return True
            refs_used = {ref for step in action["steps"].values() for ref in step["evidence_refs"]}
            if refs_used != set(refs):
                self.event(node, "contract_path_not_submitted", reason="INCOMPLETE_STEP_CITATIONS",
                           missing=sorted(set(refs) - refs_used), unknown_count=len(refs_used - set(refs)))
                return True
        else:
            verdict = "VIOLATION_PROVEN" if action.get("verdict") == "SUPPORTED" else None
        if (verdict != "VIOLATION_PROVEN" or not isinstance(cited, list)
            or not all(isinstance(ref, str) for ref in cited) or set(cited) != set(refs)
            or not isinstance(reason, str) or not 10 <= len(reason.strip()) <= 1000):
            self.event(node, "contract_path_not_submitted")
            return True
        proposals = contract_path_proposals(obligation, self.library_boundaries[node.cwe], reason)
        status, result = self.action(node, {"action": "submit_path", "proposals": proposals})
        if self.path_sensitive and status == "PATH_SUBMITTED":
            for identity in result["candidate_path_ids"]:
                self.path_claims[(node.cwe, identity)] = {
                    "conditions": action["conditions"], "steps": action["steps"],
                }
        self.event(node, "contract_path_submission", status=status)
        return True

    def queue_retrieval(self, node: Node, action: dict) -> list[dict]:
        requests = action.get("retrieval_requests", [])
        if not isinstance(requests, list) or len(requests) > 3:
            self.event(node, "retrieval_task_rejected", reason="Expected at most three retrieval requests.")
            return []
        accepted = []
        context = {"allowed_actions": list(_READ_ACTIONS)}
        for request in requests:
            if (not isinstance(request, dict) or not isinstance(request.get("action"), str)
                    or request["action"] not in _READ_ACTIONS
                    or response_contract_error("reasoning", context, request)):
                self.event(node, "retrieval_task_rejected", reason="Invalid read action.")
                continue
            if request.get("action") in {"inspect_entity", "follow_graph"} and (
                not isinstance(request.get("entity_id"), str)
                or request["entity_id"] not in self.cases[node.cwe].entities
            ):
                self.event(node, "retrieval_task_rejected", reason="Unknown indexed entity.")
                continue
            if request not in self.retrieval_tasks[node.cwe]:
                self.retrieval_tasks[node.cwe].append(request)
                accepted.append(request)
                self.event(node, "retrieval_task_queued", action=request)
        return accepted

    def value_owners(self, case: _Case, anchors) -> dict:
        owners = {}
        for key in dict.fromkeys(anchors):
            entity = case.entities.get(key)
            if entity is None:
                continue
            if key in self.value_paths.by_owner:
                owners[key] = None
                continue
            owner = self.retrieval.owner(entity)
            if owner in self.value_paths.by_owner:
                owners[owner] = None
        return owners

    def retrieve_paths(self, node: Node, *, new_anchors=()) -> dict:
        case = self.cases[node.cwe]
        hypotheses = self.discovery_hypotheses[node.cwe]
        navigation = self.retrieval.branch_navigation(node.cwe)
        if self.focus_scheduling and not navigation.sinks:
            return {"value_paths": 0, "new_paths": 0, "new_source_windows": 0}
        anchors = [*self.focus[node.cwe], *(row["anchor_entity_id"] for row in hypotheses),
                   *list(self.retrieval.static_locations)[:4],
                   *(row["entity_id"] for row in self.catalogues[node.cwe][:10])]
        if hypotheses and not self.visible_paths[node.cwe]:
            for query in self.queries[node.cwe][:2]:
                _, result = self.action(node, {"action": "search_symbols", "query": query})
                anchors.extend(hit["entity"]["entity_id"] for hit in result.get("matches", [])[:2])
        visible = self.visible_paths[node.cwe]
        owners = self.value_owners(case, [*new_anchors, *anchors])
        explored = self.value_path_owners[node.cwe]
        focused = [owner for owner in owners if owner not in explored]
        reads = _read_count(case)
        explored.update(owners)
        added = 0
        if self.value_search_reads[node.cwe] != reads or focused:
            added = self.refresh_value_pool(node, case, navigation, hypotheses, focused)
        ranked = self.ranked_paths(node.cwe)
        read_before = _read_count(case)
        inspected = set()
        focused_owners = set(focused)
        read_candidates = [item for item in ranked
                           if any(focused_owners.intersection(edge["owners"]) for edge in item[0])]
        prioritized = {descriptor["id"]: (chain, descriptor) for chain, descriptor in [*read_candidates, *ranked]}
        for chain, _ in list(prioritized.values())[:5]:
            for requirement in dict.fromkeys(item for group in self.value_paths.obligations(case, chain)
                                             for item in group):
                if (_read_count(case) - read_before >= 5 or not self.branch_remaining(node)
                        or self.value_paths.proof(case, requirement)):
                    continue
                owner, first, last = requirement
                method = case.entities[owner]
                start = max(method.start_line, min(first, last - 34))
                end = min(method.end_line, max(last, start + 39))
                key = owner, start, end
                if key not in inspected:
                    inspected.add(key)
                    self.action(node, {"action": "inspect_entity", "entity_id": owner,
                                       "start_line": start, "end_line": end})
        for anchor in list(dict.fromkeys([*self.focus[node.cwe], *(row["anchor_entity_id"] for row in hypotheses)]))[:2]:
            if anchor in case.entities:
                self.action(node, {"action": "inspect_entity", "entity_id": anchor})
        if not visible and navigation.sources and navigation.sinks:
            endpoints = navigation.context()
            for endpoint in (endpoints["sources"][0], endpoints["sinks"][0]):
                owner = case.entities[endpoint["method_id"]]
                line = endpoint["line"]
                self.action(node, {"action": "inspect_entity", "entity_id": owner.entity_id,
                                   "start_line": max(owner.start_line, line - 10),
                                   "end_line": min(owner.end_line, line + 12)})
        # Framework entry wiring may live outside the callback's callable.
        if ranked and self.branch_remaining(node):
            chain, _ = ranked[0]
            owner = case.entities[chain[0]["owners"][0]]
            wiring = [entity for entity in self.retrieval.graph.methods[owner.repository_relative_path]
                      if entity.entity_id != owner.entity_id and entity.provenance.get("public")
                      and entity.end_line < owner.start_line and entity.enclosing_type == owner.enclosing_type]
            if wiring:
                self.action(node, {"action": "inspect_entity", "entity_id": wiring[-1].entity_id})
        return {"value_paths": len(visible), "new_paths": added, "new_source_windows": _read_count(case) - read_before}

    def refresh_value_pool(self, node, case, navigation, hypotheses, focused=()):
        self.value_search_reads[node.cwe] = _read_count(case)
        visible = self.visible_paths[node.cwe]
        added = []
        for chain in self.value_paths.paths(self.value_path_owners[node.cwe], navigation,
                                            exploratory=bool(hypotheses), case=case):
            descriptor = self.value_paths.describe(chain, case.entities)
            descriptor["distance_to_sink"] = navigation.distance.get(chain[-1]["owners"][1])
            if descriptor["id"] not in visible:
                added.append(descriptor["id"])
                visible[descriptor["id"]] = (chain, descriptor)
        if added:
            self.event(node, "value_paths_refreshed", owners=list(focused), new_path_ids=added)
        return len(added)

    def ranked_paths(self, cwe):
        navigation = self.retrieval.branch_navigation(cwe)
        dead_ends = self.exploration[cwe]["Dead_Ends"]
        return sorted((item for key, item in self.visible_paths[cwe].items() if key not in dead_ends),
                      key=lambda item: self.value_paths.priority(item[0], navigation))

    def candidate_paths(self, cwe):
        return [*self.witness_candidates[cwe].values(), *self.cases[cwe].paths().hybrid_paths]

    def pending_verification_count(self):
        pending = sum(self.reviews.get((cwe, path.candidate_path_id), {}).get("verdict")
                      not in {"SUPPORTED", "REJECTED"} for cwe in self.cases for path in self.candidate_paths(cwe))
        return pending + len(self.protected_flows)

    def reasoning_sources(self, node):
        case = self.cases[node.cwe]
        windows = {}
        for item in reversed(case.tool_results.values()):
            if "lines" in item:
                window = _window(item)
                if self.general_evp:
                    window["entity"]["enclosing_type"] = item["entity"].get("enclosing_type")
                windows.setdefault(item["evidence"]["evidence_id"], window)
        if node.round == 1 and not self.general_evp:
            return list(windows.values())[:10], [], 0
        frontier = {step["evidence_id"] for row in self.exploration[node.cwe]["Frontier_Questions"].values()
                    for step in row.get("steps", ())}
        frontier.update(ref for row in self.exploration[node.cwe]["Frontier_Questions"].values()
                        for ref in row.get("evidence_refs", ()))
        # A cached pivot/spine proof is still part of the active synthesis frontier.
        # Its original read round must not make it disappear from the stateless prompt.
        pivot_refs = set(self.pivots.get(node.cwe, {}).get("evidence_ids", ()))
        if node.round == 4:
            pivot_refs.update(self.pivot_evidence[node.cwe])
        spine_refs = set()
        nav = self.retrieval.branch_navigation(node.cwe)
        for spine in self.value_paths.static_spines(nav, node.cwe).values():
            if spine["id"] in self.spine_requests[node.cwe]:
                spine_refs.update(proof.evidence_id for site in spine["sites"]
                                  if (proof := self.value_paths.proof(case, site)))
        frontier.update(spine_refs)
        frontier.update(pivot_refs)
        if self.general_evp:
            frontier.update(ref for row in self.fact_ledgers[node.cwe].facts.values() for ref in row["evidence_refs"])
        recalled = self.recalled[node.cwe, node.round]
        current = {ref for ref in windows if self.read_rounds.get((node.cwe, ref)) == node.round}
        active = sorted((ref for ref in windows if ref in frontier | current | recalled),
                        key=lambda ref: (ref not in recalled, ref not in frontier, ref not in current,
                                         list(windows).index(ref)))
        capacity = 24 if self.general_evp else 10
        selected = [windows[ref] for ref in active[:capacity]]
        self.event(node, "active_frontier_sources", active_refs=active[:capacity], eligible_refs=active,
                   archived_count=len(windows) - len(selected))
        return selected, list(windows.values()), len(windows) - len(selected)

    def compact_reasoning_context(self, node, context, history):
        """Drop whole optional records while retaining an auditable source index."""
        if self.general_evp:
            pool = context.get("value_paths", [])
            chosen, pairs = [], set()
            for path in pool:
                ports = path.get("ports", [])
                pair = (ports[0]["entity_id"], ports[-1]["entity_id"]) if ports else (path["id"], path["id"])
                if pair in pairs:
                    continue
                chosen.append(path)
                pairs.add(pair)
                if len(chosen) == 8:
                    break
            for path in pool:
                if len(chosen) >= 8:
                    break
                if path not in chosen:
                    chosen.append(path)
            context["value_paths"] = chosen
            context["value_paths_available"] = len(pool)
            if len(pool) > len(chosen):
                self.event(node, "evp_path_view_bounded", available=len(pool), visible_ids=[row["id"] for row in chosen])
            for spine in context.get("Static_Spine_Hints", ()):
                sites = spine.get("edge_sites", [])
                if len(sites) > 16:
                    spine["omitted_edge_sites"] = len(sites) - 16
                    spine["edge_sites"] = sites[:8] + sites[-8:]
            for field in ("forward_prefixes", "backward_slices"):
                context["navigation"][field] = context["navigation"].get(field, [])[:2]
            selected = {row["evidence_id"] for row in context["retrieved"]}
            archives = []
            for window in history:
                if window["evidence_id"] in selected:
                    continue
                proof = self.cases[node.cwe].evidence[window["evidence_id"]]
                method = self.cases[node.cwe].entities[window["entity"]["entity_id"]]
                archives.append({"evidence_id": proof.evidence_id, "summary":
                    f"[Read & Archived] {proof.repository_relative_path}:{proof.start_line}-{proof.end_line} - {method.signature}"})
            context["archived_sources_total"] = len(archives)
            context["archived_sources"] = archives[:48]
            # The ledger and its connected chains are pinned ahead of optional
            # navigation records and remain present even if windows rotate out.
            ledger = self.fact_ledgers[node.cwe].context()
            if node.round == 1 and not context.get("final_synthesis"):
                ledger = {"verified_subpaths": [], "connected_partial_chains": [],
                          "persistent_fact_count": len(self.fact_ledgers[node.cwe].facts),
                          "meaning": "Full ledger is retained and pinned from round two; first probe uses the complete source windows."}
            context = {**ledger, **context}
            while _context_size(context) > 122880 and context["archived_sources"]:
                context["archived_sources"].pop()
            while _context_size(context) > 122880 and len(context.get("value_paths", [])) > 1:
                context["value_paths"].pop()
            return context
        if self.focus_scheduling:
            # Source comes first. Compress navigation metadata before considering
            # any complete source window; keep all five endpoint-diverse hints.
            context["repository_inventory"] = []
            context["navigation"] = {key: value for key, value in context["navigation"].items()
                                     if key not in {"forward_prefixes", "backward_slices"}}
            for field in ("sources", "sinks"):
                context["navigation"][field] = context["navigation"].get(field, [])[:2]
            context["value_paths"] = [
                {**{key: path[key] for key in ("id", "source_complete", "bridge_kinds", "guards") if key in path},
                 "ports": path.get("ports", [])}
                for path in context["value_paths"][:2]]
            for spine in context.get("Static_Spine_Hints", ()):
                # Full sites remain available to read_static_spine by the same ID.
                sites = spine.pop("edge_sites", [])
                spine["read_sites"] = sum(site["read"] for site in sites)
                spine["total_sites"] = len(sites)
                spine["edge_kinds"] = sorted(set(spine["edge_kinds"]))
                spine["methods"] = [{"id": row["id"], "signature": row["signature"]}
                                     for row in spine["methods"]]
            if "pivot" in context:
                symbols = context["pivot"].get("boundary_symbols", [])
                context["pivot"]["boundary_symbols"] = [
                    {key: row[key] for key in ("id", "name", "signature", "kind", "line") if key in row}
                    for row in symbols[:4]]
                context["pivot"]["omitted_symbols"] = max(0, len(symbols) - 4)
            context["recent_actions"] = context.get("recent_actions", [])[-1:]
        if self.focus_scheduling:
            ceilings = 9500, 14500
        else:
            ceilings = 16000, 21000
        omitted = []
        while _context_size(context) > ceilings[0] and len(context["value_paths"]) > 1:
            omitted.append(context["value_paths"].pop())
        if omitted:
            self.event(node, "value_paths_prompt_truncated", paths=omitted)
        for field in ("forward_prefixes", "backward_slices"):
            context["navigation"][field] = list(context["navigation"].get(field, ()))
            while _context_size(context) > ceilings[0] and context["navigation"][field]:
                context["navigation"][field].pop()
        while (not self.focus_scheduling and _context_size(context) > ceilings[0]
               and len(context.get("Static_Spine_Hints", ())) > 1):
            context["Static_Spine_Hints"].pop()
        for spine in context.get("Static_Spine_Hints", ()):
            if len(spine.get("edge_sites", ())) > 8:
                spine["omitted_sites"] = len(spine["edge_sites"]) - 8
                spine["edge_sites"] = spine["edge_sites"][:4] + spine["edge_sites"][-4:]
        if "pivot" in context:
            symbols = context["pivot"].get("boundary_symbols", [])
            if len(symbols) > 12:
                context["pivot"]["boundary_symbols"] = symbols[:12]
                context["pivot"]["omitted_symbols"] = len(symbols) - 12
        while (not self.focus_scheduling and _context_size(context) > ceilings[1] - 1500
               and len(context["retrieved"]) > 1):
            context["retrieved"].pop()
        selected = {window["evidence_id"] for window in context["retrieved"]}
        archives = []
        for window in history:
            ref = window["evidence_id"]
            if ref in selected:
                continue
            proof = self.cases[node.cwe].evidence[ref]
            entity = self.cases[node.cwe].entities[window["entity"]["entity_id"]]
            summary = (f"[Read & Archived] {entity.repository_relative_path}:{proof.start_line}-{proof.end_line}"
                       f" - {entity.signature or entity.qualified_name}")
            archives.append({"evidence_id": ref, "summary": summary})
        context["archived_sources_total"] = len(archives)
        context["archived_sources"] = archives[:16]
        while _context_size(context) > ceilings[1] and context["archived_sources"]:
            context["archived_sources"].pop()
        if self.focus_scheduling:
            # Leave room for ask() metadata and a bounded protocol repair below
            # the existing 24 KiB path-sensitive admission ceiling.
            ceiling = (_VERIFICATION_BYTES * (2 if self.path_sensitive else 1)) - 1024
            archived_refs = {row["evidence_id"] for row in archives}
            packed_refs = []
            while _context_size(context) > ceiling and len(context["retrieved"]) > 1:
                dropped = context["retrieved"].pop()
                ref = dropped["evidence_id"]
                packed_refs.append(ref)
                if ref not in archived_refs:
                    archived_refs.add(ref)
                    proof = self.cases[node.cwe].evidence[ref]
                    entity = self.cases[node.cwe].entities[dropped["entity"]["entity_id"]]
                    context["archived_sources"].append({"evidence_id": ref, "summary":
                        f"[Read & Archived] {entity.repository_relative_path}:{proof.start_line}-{proof.end_line}"
                        f" - {entity.signature or entity.qualified_name}"})
            context["archived_sources_total"] = len(archived_refs)
            while _context_size(context) > ceiling and context["archived_sources"]:
                context["archived_sources"].pop()
            if packed_refs:
                self.event(node, "active_sources_packed", archived_refs=packed_refs,
                           retained_refs=[row["evidence_id"] for row in context["retrieved"]],
                           context_bytes=_context_size(context), ceiling_bytes=ceiling)
        return context

    def witness_path(self, node, action, *, complete):
        case = self.cases[node.cwe]
        steps, keys, hops = EvidenceChain(case, self.retrieval, self.value_paths).validate(
            action["steps"], complete=complete, semantic_bridges=action.get("semantic_bridges"), general_evp=self.general_evp)
        memory = self.exploration[node.cwe]
        if complete:
            input_category, effect_category = action["input_category"], action["effect_category"]
            conditions = _strings(action["conditions"], 5, 400 if self.general_evp else 150)
            if (input_category not in EXTERNAL_INPUT_CATEGORIES - {"UNKNOWN"}
                    or effect_category not in EFFECT_CATEGORIES[node.cwe] or not conditions):
                raise ValueError("Supply input, branch-appropriate effect and concrete trigger conditions.")
            path = candidate_from_steps(steps, keys, hops, input_category, effect_category)
            identity = path.candidate_path_id
            if identity in memory["Dead_Ends"]:
                return "DEAD_END_ALREADY_REVIEWED", {}
            self.witness_candidates[node.cwe].setdefault(identity, path)
            self.path_claims.setdefault((node.cwe, identity), {"conditions": conditions})
            for hop, row in hops.items():
                self.assumed_bridges.setdefault((node.cwe, hop), row)
        else:
            question = action["frontier_question"]
            maximum = 1600 if self.general_evp else 600
            if not isinstance(question, str) or not 8 <= len(question.strip()) <= maximum:
                raise ValueError(f"Describe the missing relation and what to retrieve in a string of 8–{maximum} characters.")
            identity = keys[-1] if steps[0]["step_role"] == "SOURCE" else keys[0]
            memory["Frontier_Questions"][identity] = {"question": question.strip(), "steps": steps}
            if steps[0]["step_role"] == "SOURCE":
                self.prefetch_neighbors(node, steps[-1]["method_id"], direction=0)
            elif steps[-1]["step_role"] == "SINK":
                self.prefetch_neighbors(node, steps[0]["method_id"], direction=1)
        memory["Confirmed_Hops"].update(hops)
        if self.general_evp:
            self.fact_ledgers[node.cwe].remember_hops(hops)
            self.event(node, "dataflow_facts_autospliced", **self.fact_ledgers[node.cwe].context())
        if complete:
            for key in keys:
                memory["Frontier_Questions"].pop(key, None)
            return "PATH_SUBMITTED", {"candidate_path_ids": [identity]}
        return "FRONTIER_RECORDED", {"frontier_id": identity}

    def submit_bridge(self, node: Node, action: Mapping[str, Any]) -> tuple[str, dict]:
        case = self.cases[node.cwe]
        if action.get("path_id") in self.exploration[node.cwe]["Dead_Ends"]:
            return "DEAD_END_ALREADY_REVIEWED", {}
        selected = self.visible_paths[node.cwe].get(action.get("path_id"))
        if selected is None:
            return "UNKNOWN_PATH", {}
        chain, _ = selected
        refs = self.value_paths.evidence_for(case, chain)
        if refs is None:
            return "NEEDS_MORE_EVIDENCE", {"missing_evidence": ["Read the unresolved witness windows."]}
        first, last = chain[0]["from"], chain[-1]["to"]
        conditions = _strings(action.get("conditions"), 5, 400 if self.general_evp else 150)
        if not conditions:
            return "INVALID_ACTION", {"error": "Provide concrete trigger or use conditions."}

        def endpoint(kind, ref, category, proofs):
            return {"proposal_type": kind, "subject": ref.to_dict(), "semantic_category": category,
                    "scope": {"kind": "CALLABLE", "entity_ids": [ref.entity_id]},
                    "evidence_refs": proofs, "reason": action["reason"]}

        # Endpoint proofs are the actual source expressions. Transfer proofs also include
        # a callee's witness when the CodeQL summary crosses a callable boundary.
        def endpoint_proofs(ref, proofs):
            entity = case.entities[ref.entity_id]
            return [key for key in proofs if case.evidence[key].repository_relative_path == entity.repository_relative_path
                    and case.evidence[key].start_line <= entity.start_line <= case.evidence[key].end_line] or proofs

        drafts = [endpoint("EXTERNAL_INPUT", first, action["input_category"], endpoint_proofs(first, refs[0])),
                  *(self.value_paths.transfer(case, edge, proofs) for edge, proofs in zip(chain, refs)),
                  endpoint("SECURITY_EFFECT", last, action["effect_category"], endpoint_proofs(last, refs[-1]))]
        status, result = submit_path(case, drafts, self.model_calls, self.proposal_gap)
        if status == "PATH_SUBMITTED":
            self.exploration[node.cwe]["Frontier_Questions"].pop(action["path_id"], None)
            for identity in result["candidate_path_ids"]:
                self.path_claims[node.cwe, identity] = {"conditions": conditions}
            for edge, proof_ids, verdict in zip(chain, refs, result["proposals"][1:-1]):
                if edge["kind"] != "static":
                    self.assumed_bridges[node.cwe, verdict["proposal_id"]] = {
                        "kind": edge["kind"], "from_anchor": edge["from"].to_dict(), "to_anchor": edge["to"].to_dict(),
                        "code_witness": {ref: {"evidence_id": ref} for ref in proof_ids},
                    }
            self.event(node, "value_path_submitted", path_id=action["path_id"], drafts=drafts)
        return status, result

    def propose_assumed_bridge(self, node: Node, action: Mapping[str, Any]) -> tuple[str, dict]:
        """Admit a source-anchored hypothesis through the ordinary path gate."""
        case = self.cases[node.cwe]
        proposals = action["proposals"]
        position = action["bridge_index"]
        conditions = _strings(action["conditions"], 5, 400 if self.general_evp else 150)
        reason = action["reason"]
        if (not isinstance(proposals, list) or type(position) is not int
                or not 1 <= position < len(proposals) <= 7 or not conditions
                or not isinstance(reason, str) or not 10 <= len(reason.strip()) <= (1000 if self.general_evp else 550)):
            raise ValueError("Supply a bridge insertion index, a reason and concrete trigger conditions.")
        source, target = action["from_anchor"], action["to_anchor"]
        if source["entity_id"] == target["entity_id"]:
            raise ValueError("A bridge requires two distinct indexed anchors.")
        witnesses = action["code_witness"]
        refs = []
        for side, anchor in (("from", source), ("to", target)):
            entity = case.entities[anchor["entity_id"]]
            line = witnesses[side]["line"]
            proof = case.evidence.get(witnesses[side]["evidence_id"])
            if (type(line) is not int or proof is None or proof.source_kind != EvidenceSourceKind.SOURCE_SNIPPET
                    or proof.repository_relative_path != entity.repository_relative_path
                    or not entity.start_line <= line <= entity.end_line
                    or not proof.start_line <= line <= proof.end_line):
                raise ValueError("Each bridge witness must cite a read source line inside its indexed anchor.")
            refs.append(proof.evidence_id)
        bridge = {"proposal_type": "WRAPPER_FLOW", "subject": source, "source": source, "target": target,
                  "scope": {"kind": "CALLABLE", "entity_ids": [source["entity_id"], target["entity_id"]]},
                  "evidence_refs": list(dict.fromkeys(refs)), "reason": reason}
        status, result = submit_path(case, [*proposals[:position], bridge, *proposals[position:]],
                                     self.model_calls, self.proposal_gap)
        if status == "PATH_SUBMITTED":
            admitted = result["proposals"][position]
            if admitted["status"] == "ADMISSIBLE":
                self.assumed_bridges[node.cwe, admitted["proposal_id"]] = {
                    "kind": "llm_assumed_bridge", "from_anchor": source, "to_anchor": target,
                    "code_witness": witnesses,
                }
            for identity in result["candidate_path_ids"]:
                self.path_claims[node.cwe, identity] = {"conditions": conditions}
        return status, result

    def path_assumptions(self, cwe, path):
        hop_ids = [edge["provenance"].get("witness_hop_id") for edge in path.ordered_edges]
        return {key: self.assumed_bridges[cwe, key] for key in [*path.proposal_ids, *hop_ids]
                if (cwe, key) in self.assumed_bridges}

    def reason_paths(self, node: Node) -> dict:
        case = self.cases[node.cwe]
        hypotheses = self.discovery_hypotheses[node.cwe]
        visible = self.visible_paths[node.cwe]
        navigation = self.retrieval.branch_navigation(node.cwe)
        memory = self.exploration[node.cwe]
        if self.general_evp:
            self.seed_dataflow_facts(node)
        if self.focus_scheduling and not navigation.sinks:
            self.resolved_branches[node.cwe] = "NO_GROUNDED_LEAD"
            self.last_reason_outcomes[node.cwe] = "NO_GROUNDED_LEAD"
            return {"outcome": "NO_GROUNDED_LEAD"}
        spines = self.static_spine_hints(node)
        pivot = self.pivots.get(node.cwe)
        if (not visible and not hypotheses and not (navigation.sources and navigation.sinks)
                and not memory["Frontier_Questions"] and not spines and not pivot):
            self.resolved_branches[node.cwe] = "NO_GROUNDED_LEAD"
            self.last_reason_outcomes[node.cwe] = "NO_GROUNDED_LEAD"
            return {"outcome": "NO_GROUNDED_LEAD"}
        recent = []
        outcome = "EVIDENCE_GAP"
        steps = 3
        if self.focus_scheduling:
            if node.round == 1 and sum(bool(self.retrieval.branch_navigation(cwe).sinks) for cwe in self.active) > 2:
                steps = 1
            elif node.round > 1:
                steps = 2 if len(self.active) == 1 else 1
        for step in range(steps):
            if self.value_search_reads[node.cwe] != _read_count(case):
                self.refresh_value_pool(node, case, navigation, hypotheses)
            paths = [{**descriptor, "source_complete": self.value_paths.evidence_for(case, chain) is not None}
                     for chain, descriptor in self.ranked_paths(node.cwe)]
            windows, archived, _ = self.reasoning_sources(node)
            final_round = self.final_rounds.get(node.cwe, self.rounds) if self.general_evp else 4
            final = (self.focus_scheduling and not self.candidate_paths(node.cwe)
                     and (node.round >= final_round or self.request_headroom() <= (3 if self.general_evp else 2)
                          or self.token_headroom() <= 27000))
            allowed = ["finish"]
            if len({item["entity"]["entity_id"] for item in windows}) >= 2:
                allowed.append("propose_assumed_bridge")
            if windows:
                allowed.extend(("remember_witness_path", "submit_witness_path"))
            if any(path["source_complete"] for path in paths):
                allowed.append("submit_bridge")
            if step < 2 and self.branch_remaining(node):
                allowed.extend(sorted(_READ_ACTIONS))
                if spines:
                    allowed.append("read_static_spine")
                if archived:
                    allowed.append("recall_source")
                if self.general_evp:
                    allowed.extend(("query_state_and_dispatch_bridge", "record_verified_subpaths"))
            if final:
                allowed = ["submit_witness_path", "finish"]
            anchors = self.evp_anchor_steps(node.cwe) if self.general_evp else None
            synthesis_required = bool(final and self.general_evp and self.evp_synthesis_ready(node.cwe, anchors))
            if synthesis_required:
                allowed = ["submit_witness_path"]
            context = {"task": "evidence_reasoning", "hypotheses": hypotheses,
                       "value_paths": paths, "retrieved": windows,
                       "repository_inventory": self.catalogues[node.cwe][:5],
                       "navigation": navigation.context(),
                       "exploration_memory": {
                           "Confirmed_Hops": list(memory["Confirmed_Hops"].values())[-2:],
                           "Frontier_Questions": list(memory["Frontier_Questions"].values())[-2:],
                           "Dead_Ends": list(memory["Dead_Ends"].values())[-3:],
                       },
                       "allowed_actions": allowed, "recent_actions": recent[-4:]}
            if self.general_evp:
                context["source_anchor_steps"] = anchors["source"]
                context["sink_anchor_steps"] = anchors["sink"]
                context["synthesis_required"] = synthesis_required
                context["fact_ledger_contract"] = "Persist grounded segments with verified_subpaths; semantic bridges are hypotheses, not confirmed facts."
            if final:
                context["final_synthesis"] = {
                    "instruction": "[FINAL ROUND: EVIDENCE SYNTHESIS REQUIRED]",
                    "requirement": ("Inspect active prefix, suffix and current source windows. Submit the single best "
                                    "witnessed input-to-effect chain using submit_witness_path. Include guards and "
                                    "up to two source-backed uncertain transfers for independent review. If a "
                                    "required witness is absent, finish EVIDENCE_GAP with its exact location or relation."),
                }
                if self.general_evp:
                    context["final_synthesis"]["requirement"] = (
                        "Assemble the strongest source-to-effect candidate from the persistent ledger and source witnesses. "
                        "Use at most two explicit semantic_bridges for a remaining dispatch, DI, callback or field lifecycle gap. "
                        "State a falsifiable testable_condition for each bridge. Do not omit guards. "
                        + ("A bare EVIDENCE_GAP is forbidden because both endpoints and intermediate evidence are present."
                           if synthesis_required else "If an endpoint or required source witness is absent, report its exact location."))
            if spines:
                context["Static_Spine_Hints"] = self.static_spine_hints(node)
            if pivot:
                context["pivot"] = {key: value for key, value in pivot.items() if key != "sites"}
            context = self.compact_reasoning_context(node, context, archived)
            if (self.general_evp and not final and hasattr(self.team.reasoning, "system_prompt")
                    and hasattr(self.team.reasoning, "max_output_tokens")):
                estimate, _ = request_reserve(context, self.team.reasoning)
                closing_context = {**context, **self.fact_ledgers[node.cwe].context()}
                closing_estimate, _ = request_reserve(closing_context, self.team.reasoning)
                if self.token_headroom() <= estimate + closing_estimate + 12000:
                    final = True
                    context = closing_context
                    synthesis_required = self.evp_synthesis_ready(node.cwe, anchors)
                    context["synthesis_required"] = synthesis_required
                    context["allowed_actions"] = ["submit_witness_path"] if synthesis_required else ["submit_witness_path", "finish"]
                    context["final_synthesis"] = {
                        "instruction": "[FINAL ROUND: EVIDENCE SYNTHESIS REQUIRED]",
                        "requirement": "Use the persistent ledger and source witnesses to submit the best candidate, with at most two falsifiable semantic_bridges. "
                                       + ("Bare EVIDENCE_GAP is forbidden." if synthesis_required else "Identify an absent endpoint precisely if submission is impossible."),
                        "reason": "Remaining token capacity admits only a final synthesis and independent review.",
                    }
                    self.event(node, "evp_budget_synthesis", estimated_request_tokens=estimate,
                               estimated_closing_tokens=closing_estimate, token_headroom=self.token_headroom())
            action = self.ask(node, context)
            if not action:
                break
            if action.get("action") == "finish":
                outcome = action["outcome"]
                self.event(node, "reasoner_finished", outcome=outcome, reason=action["reason"][:550])
                if outcome == "PROTECTION_ESTABLISHED":
                    protected = visible.get(action.get("path_id"))
                    if protected and self.value_paths.evidence_for(case, protected[0]) is not None:
                        self.protected_flows[node.cwe] = protected
                    else:
                        outcome = "EVIDENCE_GAP"
                break
            before = _read_count(case)
            results = []
            for request in action.get("read_batch", [action]):
                status, result = self.action(node, request)
                results.append((status, result))
                adjustment = result.get("window_adjustment")
                if adjustment is None or not self.branch_remaining(node):
                    continue
                first = result.get("evidence", {}).get("end_line", adjustment["used"]["end_line"]) + 1
                last = min(adjustment["requested"]["end_line"], adjustment["valid_range"]["end_line"])
                if first <= last:
                    results.append(self.action(node, {"action": "inspect_entity", "entity_id": request["entity_id"],
                                                      "start_line": first, "end_line": last}))
            if any(status == "PATH_SUBMITTED" for status, _ in results):
                self.last_reason_outcomes[node.cwe] = "PATH_SUBMITTED"
                return {"outcome": "PATH_SUBMITTED", "candidate_paths": len(self.candidate_paths(node.cwe))}
            if self.general_evp:
                self.seed_dataflow_facts(node)
            if final:
                self.event(node, "final_synthesis_incomplete", statuses=[status for status, _ in results])
                break
            anchors = {}
            for status, result in results:
                for hit in [*result.get("matches", [])[:3], *result.get("hits", [])[:3], result]:
                    if entity := hit.get("entity"):
                        anchors[entity["entity_id"]] = None
                for relation in result.get("relations", []):
                    anchors.update(dict.fromkeys(relation[side]["entity_id"] for side in ("from", "to")))
                recent.append({"status": status,
                               "evidence_id": result.get("evidence_id", result.get("evidence", {}).get("evidence_id")),
                               "matches": [_symbol(hit["entity"]) for hit in result.get("matches", [])[:3]],
                               "relations": result.get("relations", [])[:2],
                               "hits": result.get("hits", [])[:2],
                               "missing_evidence": result.get("missing_evidence", []),
                               "gate_rejection": result.get("gate", {}).get("rejection_reasons", []),
                               "error": result.get("error"),
                               "missing_sites": result.get("missing_sites"),
                               **{key: result[key] for key in ("window_adjustment", "valid_range") if key in result}})
            refresh = self.retrieve_paths(node, new_anchors=list(anchors)[:8]) if anchors or _read_count(case) > before else {}
            if (action.get("action") in {"submit_witness_path", "remember_witness_path", "propose_assumed_bridge"}
                    and any(status == "INVALID_ACTION" for status, _ in results)):
                # Allow the next bounded turn to correct a source range or witness.
                continue
            if not refresh.get("new_paths") and all(status in {"SOURCE_ALREADY_READ", "SPINE_ALREADY_READ",
                              "REPEATED_QUERY", "SEARCH_CACHE_HIT",
                              "INVALID_ACTION", "NO_SYMBOL_MATCH", "TOOL_ERROR"}
                   for status, _ in results):
                outcome = "RETRIEVAL_STALLED"
                self.event(node, "retrieval_stalled", reason="NO_NEW_EVIDENCE")
                break
        self.last_reason_outcomes[node.cwe] = outcome
        if outcome == "EVIDENCE_GAP" and memory["Frontier_Questions"]:
            self.resolved_branches.pop(node.cwe, None)
        else:
            self.resolved_branches[node.cwe] = outcome
        return {"outcome": outcome}

    def reason(self, node: Node) -> dict:
        if self.value_paths is not None:
            return self.reason_paths(node)
        case = self.cases[node.cwe]
        focused = self.reason_library_contract(node, case)
        if focused and (case.paths().hybrid_paths or self.stopped):
            return {"admitted": len(case.admitted), "candidate_paths": len(case.paths().hybrid_paths)}
        observations: list[dict] = []
        graph_focus = self.context[node.cwe]["entity_ids"]
        closing = False
        preferred_read = None
        stalled_turns = 0
        starting_note = self.audit_cases.get(node.cwe)
        starting_reads = _read_count(case)
        for step in range(int(focused), _REASONING_ACTIONS + 1):
            synthesis = closing or step == _REASONING_ACTIONS or (self.adaptive_gaps and stalled_turns >= 2)
            current_note = self.audit_cases.get(node.cwe)
            needs_synthesis = (
                _read_count(case) > 0 and not case.paths().hybrid_paths
                and (not self.adaptive_gaps or case.admitted or current_note
                     or self.discovery_hypotheses[node.cwe]
                     or node.cwe in self.contract_obligations)
                and (current_note is None or (current_note == starting_note and _read_count(case) > starting_reads))
            )
            if synthesis and not needs_synthesis:
                if self.adaptive_gaps and stalled_turns >= 2:
                    self.no_lead_reads[node.cwe] = _read_count(case)
                    self.stalled_branches.add(node.cwe)
                break
            source_windows = [item for item in reversed(case.tool_results.values()) if "lines" in item]
            note = current_note
            if preferred_read is not None:
                source_windows.sort(key=lambda item: item["evidence"]["evidence_id"] != preferred_read)
            pinned = None
            if note:
                pinned = next((item for item in source_windows
                               if item["evidence"]["evidence_id"] in note["evidence_refs"]), None)
            else:
                library = self.library_boundaries.get(node.cwe)
                branch_ref = library.get("implementation_evidence_id") if library is not None else None
                pinned = next((item for item in source_windows if item["evidence"]["evidence_id"] == branch_ref), None)
                for seed in self.seed_methods.get(node.cwe, ()) if pinned is None else ():
                    pinned = next((item for item in source_windows if item["entity"]["entity_id"] == seed), None)
                    if pinned is not None:
                        break
            if pinned is not None and pinned is not source_windows[0]:
                latest = source_windows[0]
                source_windows = [pinned, latest] if synthesis else [latest, pinned]
            reads = [_window(item) for item in source_windows[:2]]
            boundary = self.library_boundaries.get(node.cwe)
            evidence_ids = dict.fromkeys([item["evidence_id"] for item in reads])
            if boundary is not None:
                evidence_ids.setdefault(boundary["contract_evidence_id"], None)
            evidence_ids.update({item.evidence_id: None for item in reversed(case.evidence.values())
                                 if item.source_kind == EvidenceSourceKind.SOURCE_SNIPPET})
            evidence = [_source_ref(case.evidence[ref]) for ref in list(evidence_ids)[:8]]
            allowed = ["submit_path", "record_case", "finish"]
            if not synthesis:
                allowed = ["search_symbols", "inspect_entity", "propose", *allowed]
                if self.agentic_rag:
                    allowed += ["search_code", "follow_graph"]
            action = self.ask(node, {
                **self.context[node.cwe],
                "hypotheses": self.discovery_hypotheses[node.cwe],
                "retrieved": reads,
                "codeql_relation_context": self.graph_context(node, graph_focus),
                "allowed_actions": allowed, "audit_case": note, "library_boundary": boundary,
                "contract_obligation": self.contract_obligations.get(node.cwe),
                "synthesis_required": synthesis, "evidence_refs": evidence,
                "require_conditions": self.path_sensitive,
                "branch_tool_calls_left": self.branch_remaining(node),
                "prior_queries": [{"query": key[0], "status": status}
                                  for key, status in self.searched[node.cwe].items()][-16:],
                "recent_actions": observations[-2:][::-1],
                "review_gaps": (
                    [r["reason"] for (cwe, _), r in self.reviews.items() if cwe == node.cwe and r["verdict"] == "UNRESOLVED"]
                    + [r["reason"] for r in self.case_reviews if r["cwe"] == node.cwe and r["verdict"] == "UNRESOLVED"]
                )[-2:]
                               if self.mode == "adaptive" else [],
                "admitted_proposals": [
                    {key: value for key, value in proposal.to_dict().items()
                     if key in {"proposal_id", "proposal_type", "subject", "source", "target", "semantic_category"}}
                    for proposal, _ in list(case.admitted.values())[-4:][::-1]
                ],
            })
            if not action or action.get("action") == "finish":
                if action.get("action") == "finish":
                    self.event(node, "reasoner_finished", has_grounded_lead=bool(current_note or case.admitted))
                    if self.adaptive_gaps and not (current_note or case.admitted or self.discovery_hypotheses[node.cwe]):
                        self.no_lead_reads[node.cwe] = _read_count(case)
                if not synthesis and needs_synthesis and not self.stopped:
                    closing = True
                    continue
                break
            actions = action.get("read_batch", [action])
            if synthesis and action.get("action") not in allowed:
                self.event(node, "synthesis_incomplete")
                break
            for selected_action in actions:
                status, result = self.action(node, selected_action)
                if status == "SOURCE_READ":
                    preferred_read = None
                    graph_focus = list(dict.fromkeys([result["entity"]["entity_id"], *graph_focus]))
                elif status == "SOURCE_ALREADY_READ":
                    preferred_read = result["evidence_id"]
                    graph_focus = list(dict.fromkeys([selected_action["entity_id"], *graph_focus]))
                if "gate" in result:
                    gate = result["gate"]
                    observations.append({"status": status, "proposal_id": gate["proposal_id"],
                                         "missing_evidence": gate["missing_evidence"],
                                         "reasons": gate["rejection_reasons"],
                                         "repair_context": result.get("repair_context", {})})
                elif status == "SOURCE_READ":
                    observations.append({"status": status, "evidence_id": result["evidence"]["evidence_id"],
                                         **({"window_adjustment": result["window_adjustment"]}
                                            if "window_adjustment" in result else {})})
                elif status == "SYMBOLS_FOUND":
                    observations.append({"status": status, "matches": [_symbol(hit["entity"]) for hit in result["matches"][:4]]})
                else:
                    observations.append({"status": status, **result})
            if self.adaptive_gaps:
                stalled_turns = stalled_turns + 1 if all(
                    item["status"] in {"SOURCE_ALREADY_READ", "REPEATED_QUERY", "INVALID_ACTION", "TOOL_ERROR"}
                    for item in observations[-len(actions):]
                ) else 0
                if stalled_turns == 2:
                    self.event(node, "retrieval_stalled", next_step="synthesize_or_finish")
            if synthesis:
                break
        return {"admitted": len(case.admitted), "candidate_paths": len(case.paths().hybrid_paths),
                "outcome": "RETRIEVAL_STALLED" if node.cwe in self.stalled_branches else "FINISHED"}

    def verify_partial_case(self, node: Node, case: _Case) -> bool:
        obligation = self.contract_obligations.get(node.cwe)
        note = obligation["note"] if obligation is not None else self.audit_cases.get(node.cwe)
        if note is None:
            return False
        reads = _read_count(case)
        version = (note, reads)
        if self.last_case_review.get(node.cwe) == version:
            return False
        extra = []
        if obligation:
            details = obligation["obligation"]
            if details.get("fallback_evidence_id"):
                extra.append(details["fallback_evidence_id"])
            extra.extend(details.get("state_evidence_ids", ()))
            extra.extend(window["evidence_id"] for window in details["return_branch_evidence"])
        refs = [*note["evidence_refs"], *extra]
        proofs = self.source_proofs(case, refs)
        review_context = {"review_kind": "partial_case", "audit_case": note, "source_evidence": proofs}
        if obligation is not None:
            review_context.update({
                "review_kind": "static_contract_obligation",
                "static_contract_obligation": obligation["obligation"],
                "local_gap_proof_refs": obligation["local_gap_proof_refs"],
            })
        action = self.ask(node, review_context)
        if self.stopped:
            return False
        if (obligation is not None and action
            and action.get("local_gap_assessment") not in ("SUPPORTED", "NOT_ESTABLISHED")
            and self.model_calls < self.limits.max_turns):
            retry_context = {**review_context, "response_error": "Missing or invalid local_gap_assessment."}
            retry_payload = {
                "role": node.role, "cwe": node.cwe, "round": node.round,
                "tool_calls_left": self.limits.max_tool_calls - self.tool_calls, **retry_context,
            }
            if _context_size(retry_payload) <= _VERIFICATION_BYTES:
                self.event(node, "contract_review_schema_retry")
                retry = self.ask(node, retry_context)
                if self.stopped:
                    return False
                if retry.get("local_gap_assessment") in ("SUPPORTED", "NOT_ESTABLISHED"):
                    action = retry
        cited = action.get("evidence_refs")
        citations = set(cited) if isinstance(cited, list) and all(isinstance(ref, str) for ref in cited) else set()
        verdict = "REJECTED" if action.get("verdict") == "REJECTED" and citations and citations <= proofs.keys() else "UNRESOLVED"
        try:
            targets = _strings(action.get("focus_entity_ids", []))
        except ValueError:
            targets = []
        targets = [entity for entity in targets if entity in case.entities]
        if verdict == "UNRESOLVED" and self.mode == "adaptive":
            self.focus[node.cwe] = list(dict.fromkeys([*targets, *self.focus[node.cwe]]))[:4]
            review_requests = self.queue_retrieval(node, action)
        else:
            review_requests = []
        review = {"cwe": node.cwe, "case_id": note["case_id"], "verdict": verdict,
                  "reason": str(action.get("reason", note["next_question"]))[:500],
                  "evidence_refs": sorted(citations & proofs.keys()), "focus_entity_ids": targets,
                  "retrieval_requests": review_requests}
        if obligation is not None:
            local_refs = set(obligation["local_gap_proof_refs"])
            supported = (action.get("local_gap_assessment") == "SUPPORTED" and local_refs <= citations
                         and citations <= proofs.keys() and verdict != "REJECTED")
            review["local_gap_assessment"] = "SUPPORTED" if supported else "NOT_ESTABLISHED"
        self.case_reviews.append(review)
        self.last_case_review[node.cwe] = version
        self.event(node, "case_review", **review)
        return True

    def review_protection(self, node: Node, protected, *, allow_retrieval: bool) -> None:
        chain, descriptor = protected
        case = self.cases[node.cwe]
        requirements = self.value_paths.evidence_for(case, chain)
        refs = {ref for edge_refs in requirements for ref in edge_refs}
        supplemental = [ref for ref, evidence in case.evidence.items()
                        if evidence.source_kind == EvidenceSourceKind.SOURCE_SNIPPET and ref not in refs]
        proof = self.source_proofs(case, [*sorted(refs), *supplemental[-4:]])
        context = {"review_kind": "protected_flow", "value_path": descriptor,
                   "source_evidence": proof, "retrieval_entities": self.catalogues[node.cwe][:8]}
        assumed = {f"hop-{index}": {"kind": edge["kind"], "from_anchor": edge["from"].to_dict(),
                   "to_anchor": edge["to"].to_dict(), "code_witness": {ref: {"evidence_id": ref} for ref in ids}}
                   for index, (edge, ids) in enumerate(zip(chain, requirements)) if edge["kind"] != "static"}
        if assumed:
            context["assumed_bridges"] = assumed
        action = self.ask(node, context)
        evidence_refs = action.get("evidence_refs")
        cited = set(evidence_refs) if isinstance(evidence_refs, list) and all(
            isinstance(ref, str) for ref in evidence_refs) else set()
        verdicts = bridge_verdicts(assumed, action, cited & proof.keys())
        connected = all(verdict == "BRIDGE_CONFIRMED" for verdict in verdicts.values())
        rejected = connected and action.get("verdict") == "REJECTED" and refs <= cited <= proof.keys()
        bypass = (connected and action.get("verdict") == "SUPPORTED" and refs <= cited <= proof.keys()
                  and action.get("checks") == _REQUIRED_PATH_CHECKS
                  and not action.get("counterevidence") and not action.get("unproven_conditions"))
        review = {"cwe": node.cwe, "value_path_id": descriptor["id"],
                  "verdict": "REJECTED" if rejected else "BYPASS_EVIDENCED" if bypass else "UNRESOLVED",
                  "evidence_refs": sorted(cited & proof.keys()), "reason": str(action.get("reason", ""))[:550]}
        if assumed:
            review["bridge_verdicts"] = verdicts
        self.protection_reviews.append(review)
        if rejected:
            self.exploration[node.cwe]["Dead_Ends"][descriptor["id"]] = {
                "path_id": descriptor["id"], "kind": "SANITIZED", "evidence_refs": review["evidence_refs"],
            }
        self.event(node, "protection_review", **review)
        if bypass:
            self.resolved_branches.pop(node.cwe, None)
            self.exploration[node.cwe]["Frontier_Questions"][descriptor["id"]] = {
                "path_id": descriptor["id"], "question": "Reconsider the verified bypass and submit the complete flow.",
                "evidence_refs": review["evidence_refs"],
            }
            return
        self.resolved_branches[node.cwe] = "PROTECTION_ESTABLISHED" if rejected else "PROTECTION_UNRESOLVED"
        if not rejected and allow_retrieval and self.mode == "adaptive":
            self.queue_retrieval(node, action)

    def verify(self, node: Node) -> dict:
        protected = self.protected_flows.pop(node.cwe, None)
        if protected is not None:
            self.review_protection(node, protected, allow_retrieval=True)
        result = self.verify_once(node)
        if self.value_paths is None or not self.retrieval_tasks[node.cwe] or self.stopped:
            return result
        case = self.cases[node.cwe]
        while (self.retrieval_tasks[node.cwe] and not self.stopped and self.review_followups[node.cwe] < 2):
            self.review_followups[node.cwe] += 1
            if not self.follow_up(node, case):
                break
            if protected is not None and self.resolved_branches[node.cwe] == "PROTECTION_UNRESOLVED":
                self.review_protection(node, protected, allow_retrieval=self.review_followups[node.cwe] < 2)
            result["reviewed"] += self.verify_once(node)["reviewed"]
        if self.review_followups[node.cwe] >= 2:
            self.retrieval_tasks.pop(node.cwe, None)
        return result

    def follow_up(self, node, case):
        before = _read_count(case)
        for request in self.retrieval_tasks.pop(node.cwe):
            status, data = self.action(node, request)
            self.event(node, "retrieval_task_finished", action=request, status=status)
            # Search and graph results are navigation. Open the indexed declaration or
            # the exact reported location before a second adjudication.
            targets = [hit["entity"]["entity_id"] for hit in data.get("matches", [])[:2]]
            targets.extend(endpoint["entity_id"] for relation in data.get("relations", [])[:2]
                           for endpoint in (relation["from"], relation["to"]))
            for target in dict.fromkeys(targets):
                self.action(node, {"action": "inspect_entity", "entity_id": target})
            for hit in data.get("hits", [])[:2]:
                location = hit["location"]
                point = self.retrieval.graph._locate(
                    location["repository_relative_path"], location["line"], location["column"])
                if point is not None:
                    owner = case.entities[point["entity_id"]]
                    self.action(node, {"action": "inspect_entity", "entity_id": owner.entity_id,
                                       "start_line": max(owner.start_line, point["line"] - 8),
                                       "end_line": min(owner.end_line, point["line"] + 12)})
        if _read_count(case) == before:
            self.event(node, "verification_retrieval_stalled", reason="NO_NEW_SOURCE")
            return False
        self.event(node, "candidate_evidence_updated", new_source_windows=_read_count(case) - before)
        return True

    def verify_once(self, node: Node) -> dict:
        case = self.cases[node.cwe]
        reviewed = 0
        paths = self.candidate_paths(node.cwe)
        if not paths and self.verify_partial_case(node, case):
            return {"reviewed": 0, "partial_cases_reviewed": 1}
        for path in paths:
            key = (node.cwe, path.candidate_path_id)
            previous = self.reviews.get(key)
            if previous and (previous["verdict"] != "UNRESOLVED" or previous["reads"] == _read_count(case)):
                continue
            if reviewed >= _VERIFICATION_PATHS:
                break
            focused = set(self.focus[node.cwe])
            path_files = {node["repository_relative_path"] for node in path.ordered_nodes
                          if node.get("repository_relative_path")}
            supplemental = [
                ref for ref, evidence in case.evidence.items()
                if (evidence.source_kind == EvidenceSourceKind.SOURCE_SNIPPET
                    and ref not in path.evidence_refs
                    and (focused.intersection(evidence.entity_ids)
                         or evidence.repository_relative_path in path_files and any(
                             case.entities[entity_id].provenance.get("public")
                             for entity_id in evidence.entity_ids if entity_id in case.entities)))
            ]
            proofs = {}
            relations = {}
            assumed = self.path_assumptions(node.cwe, path)
            probe = None
            if self.general_evp and any(row.get("kind") == "SEMANTIC_BRIDGE" for row in assumed.values()):
                probe = self.probe_semantic_bridges(node, path, assumed)
            bridge = assumed or any(case.evidence[ref].source_kind == EvidenceSourceKind.CODEQL_DATAFLOW
                                    for ref in path.evidence_refs)
            if bridge:
                supplemental = [ref for ref, evidence in case.evidence.items()
                                if evidence.source_kind == EvidenceSourceKind.SOURCE_SNIPPET
                                and ref not in path.evidence_refs]
            refs = path.evidence_refs if bridge else path.evidence_refs[:16]
            for ref in (*refs, *supplemental[-4:], *((probe or {}).get("evidence_refs", ()))):
                evidence = case.evidence[ref]
                if evidence.source_kind == EvidenceSourceKind.SOURCE_SNIPPET:
                    window = case.tool_results[evidence.tool_call_id]
                    proofs[ref] = {"location": {
                        **_source_ref(evidence), "repository_relative_path": evidence.repository_relative_path,
                    }, "source": _window(window)["source"], "origin": evidence.provenance.get("kind")}
                else:
                    relations[ref] = _compact_relation(case.tool_results[evidence.artifact_ref])
            conditional = any(case.admitted[proposal_id][0].semantic_category == "LIBRARY_OUTPUT_CONTRACT"
                              for proposal_id in path.proposal_ids)
            # Keep the verifier independent of proposal rationales and the reasoner's transcript.
            path_context = {"path": path.to_dict(), "source_evidence": proofs, "codeql_evidence": relations,
                            "review_kind": "library_contract_path" if conditional else "path",
                            "analysis_scope": "Static conditional finding. Establish program entry, value flow and effect from source. Evaluate external use under explicit conditions.",
                            "knowledge": retrieve_knowledge(node.cwe, self.queries[node.cwe])}
            contract = self.contract_obligations.get(node.cwe)
            focused_contract = conditional and contract and set(path.evidence_refs) <= proofs.keys()
            if focused_contract:
                # Avoid spending the verification window on redundant graph serialization.
                path_context = {
                    "review_kind": "library_contract_path",
                    "path": {"ordered_nodes": [
                        {key: row[key] for key in ("entity_id", "role", "start_line") if key in row}
                        for row in path.ordered_nodes if row.get("entity_id")
                    ]},
                    "contract": contract["obligation"],
                    "source_evidence": self.source_proofs(case, path.evidence_refs),
                }
            claim = self.path_claims.get(key)
            if claim:
                path_context["claim_to_falsify"] = claim
            if bridge:
                path_context["retrieval_entities"] = self.catalogues[node.cwe][:8]
                path_context["value_bridge"] = True
            if assumed:
                path_context["assumed_bridges"] = assumed
            if probe is not None:
                path_context["targeted_bridge_probe"] = probe
            if path.provenance.get("producer") == "source_witness_steps":
                path_context["path"] = {
                    "candidate_path_id": path.candidate_path_id,
                    "steps": [row["provenance"]["witness_step"] for row in path.ordered_nodes[1:-1]],
                    "input_category": path.input_anchor["provenance"]["category"],
                    "effect_category": path.effect_anchor["provenance"]["category"],
                }
                path_context["assumed_bridges"] = {
                    key: {"kind": row["kind"], "code_witness": row["code_witness"],
                          **({"semantic_bridge": row["semantic_bridge"]} if "semantic_bridge" in row else {})}
                    for key, row in assumed.items()
                }
            action = self.ask(node, path_context)
            if self.stopped:
                break
            reviewed += 1
            verdict = action.get("verdict")
            cited = action.get("evidence_refs")
            citations = set(cited) if isinstance(cited, list) and all(isinstance(x, str) for x in cited) else set()
            checks = action.get("checks")
            available = proofs.keys() | relations.keys()
            cited_source = citations & proofs.keys()
            valid = bool(cited_source) and citations <= available
            covered = all(cited_source.intersection(edge["evidence_refs"]) for edge in path.ordered_edges)
            if bridge:
                covered = covered and (set(path.evidence_refs) & proofs.keys()) <= cited_source
            verdicts = bridge_verdicts(assumed, action, cited_source)
            if verdict == "SUPPORTED" and probe is not None and any(
                    row["status"] != "TARGETED_PASS_COMPLETED" for row in probe["probes"]):
                verdict = "UNRESOLVED"
            if verdict == "SUPPORTED" and any(value != "BRIDGE_CONFIRMED" for value in verdicts.values()):
                verdict = "UNRESOLVED"
            if self.general_evp:
                for identity, value in verdicts.items():
                    if valid and value == "BRIDGE_CONFIRMED" and "from_step" in assumed[identity]:
                        try:
                            self.fact_ledgers[node.cwe].confirm(assumed[identity])
                        except ValueError as exc:
                            self.event(node, "fact_promotion_rejected", reason=str(exc))
                    elif valid and value == "BRIDGE_REJECTED" and "from_step" in assumed[identity]:
                        self.fact_ledgers[node.cwe].refute(assumed[identity])
            if focused_contract:
                covered = covered and set(path.evidence_refs) <= cited_source
            if verdict == "SUPPORTED" and not (valid and covered and checks == _REQUIRED_PATH_CHECKS):
                verdict = "UNRESOLVED"
            if verdict == "SUPPORTED" and path_context.get("claim_to_falsify") and (
                action.get("unproven_conditions") or action.get("counterevidence")
            ):
                verdict = "UNRESOLVED"
            if verdict == "REJECTED" and not valid:
                verdict = "UNRESOLVED"
            if verdict not in ("SUPPORTED", "REJECTED"):
                verdict = "UNRESOLVED"
            try:
                targets = _strings(action.get("focus_entity_ids", []))
            except ValueError:
                targets = []
            if verdict == "UNRESOLVED" and self.mode == "adaptive" and (
                self.value_paths is None or self.review_followups[node.cwe] < 2
            ):
                self.queue_retrieval(node, action)
                self.focus[node.cwe] = list(dict.fromkeys(
                    [*self.focus[node.cwe], *(entity for entity in targets if entity in case.entities)]
                ))[:4]
            review = {
                "cwe": node.cwe, "candidate_path_id": path.candidate_path_id, "verdict": verdict,
                "evidence_refs": sorted(citations.intersection(available)), "reads": _read_count(case),
                "edge_coverage": bool(valid and covered), "conditional_library_contract": conditional,
                "reason": str(action.get("reason", ""))[:500],
            }
            if path_context.get("claim_to_falsify"):
                for field in ("support", "counterevidence", "unproven_conditions"):
                    review[field] = action.get(field, [])
            if assumed:
                review["bridge_verdicts"] = verdicts
            if self.general_evp:
                review["evp_verdict"] = {"SUPPORTED": "SUPPORTED", "REJECTED": "REFUTED", "UNRESOLVED": "INSUFFICIENT_EVIDENCE"}[verdict]
                review["semantic_bridge_probe_completed"] = probe is not None and all(
                    row["status"] == "TARGETED_PASS_COMPLETED" for row in probe["probes"])
            if verdict == "REJECTED" and assumed:
                dead_reason = action.get("dead_end_reason")
                if (dead_reason in ("SANITIZED", "UNREACHABLE") and covered
                        and (dead_reason != "SANITIZED" or all(value == "BRIDGE_CONFIRMED" for value in verdicts.values()))):
                    review["dead_end_reason"] = dead_reason
                    self.exploration[node.cwe]["Dead_Ends"][path.candidate_path_id] = {
                        "candidate_path_id": path.candidate_path_id, "kind": dead_reason,
                        "evidence_refs": review["evidence_refs"],
                        "locations": [[row.get("repository_relative_path"), row.get("start_line")]
                                      for row in path.ordered_nodes if row.get("start_line")],
                    }
            self.reviews[key] = review
            self.event(node, "review", **review)
        branch_reviews = [self.reviews.get((node.cwe, path.candidate_path_id), {}) for path in paths]
        if (any(review.get("dead_end_reason") == "SANITIZED" for review in branch_reviews)
                and all(review.get("verdict") == "REJECTED" for review in branch_reviews)):
            self.resolved_branches[node.cwe] = "PROTECTION_ESTABLISHED"
        return {"reviewed": reviewed}

    def route_evp(self, node):
        metrics, reasons, viable = {}, {}, []
        for cwe in sorted(self.active):
            nav = self.retrieval.branch_navigation(cwe)
            ledger = self.fact_ledgers[cwe]
            case = self.cases[cwe]
            owners = {self.retrieval.owner(case.entities[identity]) for proof in case.evidence.values()
                      if proof.source_kind == EvidenceSourceKind.SOURCE_SNIPPET for identity in proof.entity_ids}
            known = owners & (nav.source_owners | nav.sink_owners)
            prior = self.vitality_history.get(cwe, {})
            distance = min((nav.distance[owner] for owner in owners if owner in nav.distance), default=None)
            count = sum(fact["status"] != "VERIFIER_REFUTED" for fact in ledger.facts.values())
            row = {"confirmed_subpaths_count": count, "viable_sinks": len(nav.sinks),
                   "sink_reachability_score": 0 if distance is None else 1 / (1 + distance),
                   "newly_resolved_anchors": len(known - set(prior.get("anchors", []))),
                   "anchors": sorted(known), "new_segments": len(ledger.facts) - prior.get("confirmed_subpaths_count", 0),
                   "count_semantics": "Source-bound segments; independent semantic verification is recorded separately."}
            metrics[cwe] = row
            self.vitality_history[cwe] = row
            paths = self.candidate_paths(cwe)
            if paths:
                reasons[cwe] = "FROZEN_AFTER_INDEPENDENT_REVIEW"
            elif cwe in self.unadmitted_branches:
                reasons[cwe] = "FROZEN_REASONING_NOT_ADMITTED"
            elif not row["viable_sinks"] or not row["confirmed_subpaths_count"]:
                reasons[cwe] = "FROZEN_NO_VIABLE_SINK" if not row["viable_sinks"] else "FROZEN_NO_PROPAGATION"
            elif node.round >= self.rounds:
                reasons[cwe] = ("FINAL_SYNTHESIS_COMPLETED" if node.round in self.admitted_reason_rounds[cwe]
                                else "FINAL_SYNTHESIS_NOT_ADMITTED")
            elif self.request_headroom() < 2 or self.token_headroom() < 15000:
                reasons[cwe] = "INSUFFICIENT_REASONING_AND_REVIEW_CAPACITY"
            else:
                viable.append(cwe)
                if node.round >= 3 and not row["new_segments"] and not row["newly_resolved_anchors"]:
                    self.final_rounds[cwe] = min(self.final_rounds.get(cwe, self.rounds), node.round + 1)
        viable.sort(key=lambda cwe: (-metrics[cwe]["confirmed_subpaths_count"],
                                    -metrics[cwe]["sink_reachability_score"],
                                    -metrics[cwe]["newly_resolved_anchors"], cwe))
        # A single growing slice gets the later rounds instead of repeatedly
        # splitting the same physical-request budget over stagnant branches.
        selected = viable[:1]
        for cwe in viable[1:]:
            reasons[cwe] = "FROZEN_REALLOCATED_TO_HIGHER_VITALITY"
        for cwe in selected:
            self.resolved_branches.pop(cwe, None)
            pivot = self.plan_pivot(node, cwe)
            self.pivots[cwe] = pivot
            reasons[cwe] = "EVP_ACTIVE_" + pivot["mode"]
        for cwe in set(self.active) - set(selected):
            self.resolved_branches[cwe] = reasons[cwe]
        self.active = set(selected)
        self.focus_order = selected
        self.allocate_focus_tools()
        self.event(node, "branch_vitality", metrics=metrics, active=selected, reasons=reasons,
                   maximum_rounds=self.rounds, physical_requests_remaining=self.request_headroom())
        return {"active": selected, "reasons": reasons, "vitality": metrics}

    def route(self, node: Node) -> dict:
        if self.mode == "fixed":
            return {"active": sorted(self.active), "policy": self.mode}
        if self.focus_scheduling and node.round == 1:
            return self.select_focus()
        if self.general_evp and node.round >= 2:
            return self.route_evp(node)
        next_active = set()
        reasons = {}
        for cwe in sorted(self.active):
            case = self.cases[cwe]
            paths = self.candidate_paths(cwe)
            if (self.focus_scheduling and cwe in self.focus_order and 2 <= node.round < self.rounds
                    and self.request_headroom() >= 3 and not paths
                    and self.last_reason_outcomes.get(cwe) in {"RETRIEVAL_STALLED", "EVIDENCE_GAP"}):
                pivot = self.plan_pivot(node, cwe)
                self.pivots[cwe] = pivot
                self.resolved_branches.pop(cwe, None)
                next_active.add(cwe)
                reasons[cwe] = pivot["mode"]
                self.event(node, "cognitive_pivot_scheduled", cwe=cwe, mode=pivot["mode"],
                           sites=pivot["sites"], physical_requests_remaining=self.request_headroom())
                continue
            if self.value_paths is not None and cwe in self.resolved_branches and not self.retrieval_tasks[cwe]:
                reasons[cwe] = self.resolved_branches[cwe]
                continue
            if (self.adaptive_gaps and not paths and not self.retrieval_tasks[cwe]
                    and self.no_lead_reads.get(cwe) == _read_count(case)):
                reasons[cwe] = "RETRIEVAL_STALLED" if cwe in self.stalled_branches else "NO_GROUNDED_HYPOTHESIS"
                continue
            if not paths and (self.queries[cwe] or case.evidence):
                reasons[cwe] = "MISSING_PATH"
            elif any(self.reviews.get((cwe, p.candidate_path_id), {}).get("verdict")
                     in {None, "UNRESOLVED"} for p in paths):
                if self.value_paths is not None and not self.retrieval_tasks[cwe]:
                    reasons[cwe] = "UNRESOLVED_WITHOUT_NEW_EVIDENCE"
                    self.resolved_branches[cwe] = reasons[cwe]
                    continue
                reasons[cwe] = "UNRESOLVED_REVIEW"
            if cwe in reasons:
                progress = self.branch_progress(cwe, paths)
                tools_left = (self.limits.max_tool_calls - self.tool_calls if self.focus_scheduling else
                              self.branch_remaining(Node(node.id, node.role, (), cwe, node.round + 1)))
                if self.adaptive_gaps and not tools_left:
                    reasons[cwe] = "BRANCH_TOOL_BUDGET_EXHAUSTED"
                    self.progress[cwe] = progress
                    continue
                if self.progress.get(cwe) == progress:
                    reasons[cwe] = "NO_PROGRESS"
                else:
                    next_active.add(cwe)
                self.progress[cwe] = progress
        self.active = next_active
        if self.focus_scheduling:
            self.allocate_focus_tools()
        return {"active": sorted(self.active), "reasons": reasons}

    def branch_progress(self, cwe, paths):
        case = self.cases[cwe]
        return (_read_count(case), len(case.admitted), len(paths),
                canonical_json(self.exploration[cwe]["Frontier_Questions"]))

    def plan_pivot(self, node, cwe):
        nav = self.retrieval.branch_navigation(cwe)
        case = self.cases[cwe]
        history = self.pivot_history[cwe]
        half = []
        for owner, links in self.value_paths.strict_sites.items():
            if owner not in nav.eligible:
                continue
            for link in links:
                if link.kind != "VALUE_BRIDGE" or owner != link.origin or link.target not in nav.eligible:
                    continue
                covered = {site[0] for site in link.sites if self.value_paths.proof(case, site)}
                missing = [site for site in link.sites if not self.value_paths.proof(case, site)]
                if missing and covered.intersection((link.origin, link.target)):
                    half.append(((link.origin == link.target,
                                  self.link_priority(nav, link.origin, link.target, link)), missing))
        backward = []
        sink_hints = nav.context()["sinks"]
        for sink in sink_hints:
            owner, line = sink["method_id"], sink["line"]
            sites = [(owner, line, line)]
            frontier = [owner]
            visited = {owner}
            for _ in range(2):
                callers = []
                for current in frontier:
                    for caller, witness in self.backward_callers(nav, current)[:2]:
                        if caller in visited:
                            continue
                        visited.add(caller)
                        callers.append(caller)
                        sites.extend(witness)
                frontier = callers
            if any(not self.value_paths.proof(case, site) for site in sites):
                backward = list(dict.fromkeys(sites))
                break
        if half and "STRICT_EDGE_GAP" not in history:
            mode = "STRICT_EDGE_GAP"
            sites = list(dict.fromkeys(site for _, missing in sorted(half)[:4] for site in missing))
            detail = "Reconstruct the strict transfer using the newly read missing edge endpoints."
            extra = {}
        elif backward and "BACKWARD_FROM_SINK" not in history:
            mode, sites = "BACKWARD_FROM_SINK", backward
            detail = "Start from the sink call and work backward through its callers to meet the input prefix."
            extra = {}
        else:
            mode = "BRIDGE_GAP"
            sources = nav.context()["sources"]
            frontiers = self.exploration[cwe]["Frontier_Questions"]
            prefixes = list(dict.fromkeys([*(row["steps"][-1]["method_id"] for row in frontiers.values()
                                             if row.get("steps") and row["steps"][0]["step_role"] == "SOURCE"),
                                           *(item["method_id"] for item in sources)]))
            suffixes = list(dict.fromkeys([*(row["steps"][0]["method_id"] for row in frontiers.values()
                                             if row.get("steps") and row["steps"][-1]["step_role"] == "SINK"),
                                           *(item["method_id"] for item in sink_hints)]))
            pairs = [(left, right) for left in prefixes for right in suffixes if left != right
                     and (self.retrieval.same_package(left, right) or self.retrieval.same_module(left, right))]
            owners = min(pairs, key=lambda pair: (
                case.entities[pair[0]].enclosing_type != case.entities[pair[1]].enclosing_type,
                prefixes.index(pair[0]), suffixes.index(pair[1]))) if pairs else (*prefixes[:1], *suffixes[:1])
            types = {case.entities[owner].enclosing_type for owner in owners}
            symbols = {}
            for enclosing_type in sorted(types):
                for entity in [*self.retrieval.fields_by_type[enclosing_type],
                               *self.retrieval.methods_by_type[enclosing_type]]:
                    symbols[entity.entity_id] = {"id": entity.entity_id, "name": entity.qualified_name,
                                                 "signature": entity.signature, "kind": entity.kind.value,
                                                 "file": entity.repository_relative_path, "line": entity.start_line}
            for owner in owners:
                for site in nav.dispatch_by_target.get(owner, ()):
                    for target in sorted(nav.dispatch_sites[site]):
                        entity = case.entities[target]
                        symbols.setdefault(target, {"id": target, "name": entity.qualified_name,
                                                     "signature": entity.signature, "kind": "IMPLEMENTATION",
                                                     "file": entity.repository_relative_path, "line": entity.start_line})
            sites = [site for owner in owners for site in self.method_sites(
                Node(node.id, node.role, (), cwe, node.round), owner)[:2]]
            detail = "Check fields and callback implementations across the gap; propose a witnessed bridge if supported."
            extra = {"boundary_symbols": list(symbols.values()), "boundary_methods": list(owners)}
        history.add(mode)
        return {"mode": mode, "instruction": f"[PIVOT MODE: {mode}] {detail}", "sites": sites,
                "round": node.round + 1, **extra}

    def backward_callers(self, nav, owner):
        ranked = sorted(self.value_paths.strict_links[1].get(owner, ()),
                        key=lambda link: self.link_priority(nav, owner, link.origin, link))
        result = {}
        for link in ranked:
            if link.origin in nav.eligible:
                result.setdefault(link.origin, tuple(site for site in link.sites if site[0] in nav.eligible))
        for relation in self.retrieval.graph.callers.get(owner, ()):
            caller, line = relation["from"]["entity_id"], relation["from"]["line"]
            if caller in nav.eligible and not relation.get("background_only"):
                result.setdefault(caller, ((caller, line, line),))
        return list(result.items())

    def apply_pivot(self, node):
        pivot = self.pivots[node.cwe]
        if pivot["round"] != node.round:
            return ()
        self.read_edge_windows(node, pivot["sites"], limit=6)
        case = self.cases[node.cwe]
        pivot["evidence_ids"] = list(dict.fromkeys(proof.evidence_id for site in pivot["sites"]
                                                    if (proof := self.value_paths.proof(case, site))))
        self.pivot_evidence[node.cwe] = list(dict.fromkeys(
            [*pivot["evidence_ids"], *self.pivot_evidence[node.cwe]]))[:10]
        self.event(node, "cognitive_pivot_applied", mode=pivot["mode"], evidence_ids=pivot["evidence_ids"],
                   missing_sites=sum(not self.value_paths.proof(case, site) for site in pivot["sites"]))
        return tuple(dict.fromkeys(site[0] for site in pivot["sites"] if self.value_paths.proof(case, site)))

    def select_focus(self):
        scores, reasons, eligible = {}, {}, []
        for cwe in SUPPORTED_CWES:
            case = self.cases[cwe]
            nav = self.retrieval.branch_navigation(cwe)
            frontiers = self.exploration[cwe]["Frontier_Questions"]
            candidates = self.candidate_paths(cwe)
            read_owners = {self.retrieval.owner(case.entities[entity_id]) for proof in case.evidence.values()
                           if proof.source_kind == EvidenceSourceKind.SOURCE_SNIPPET for entity_id in proof.entity_ids}
            distance = min((nav.distance[owner] for owner in read_owners if owner in nav.distance), default=None)
            anchored = [chain for chain, _ in self.ranked_paths(cwe)
                        if nav.source_ref(chain[0]["from"]) and chain[-1]["to"].entity_id in nav.sink_ids
                        and any(owner in read_owners for edge in chain for owner in edge["owners"])]
            requested_spine = any(
                spine["id"] in self.spine_requests[cwe] and spine["methods"][0] in nav.source_owners
                and spine["methods"][-1] in nav.sink_owners
                and any(self.value_paths.proof(case, site) for site in spine["sites"])
                for spine in self.value_paths.static_spines(nav, cwe).values())
            active_path = bool(candidates or anchored or requested_spine)
            best = next(iter(anchored), ())
            score = 4 if candidates else 3 if frontiers else 2 if (
                best and all(edge["kind"] == "static" for edge in best)
                and self.value_paths.evidence_for(case, best) is not None) else int(active_path)
            scores[cwe] = {"production_sinks": len(nav.sinks), "sources": len(nav.sources),
                           "has_active_path": active_path, "frontiers": len(frontiers),
                           "distance_to_sink": distance, "evidence_score": score}
            complete = candidates and all(self.reviews.get((cwe, path.candidate_path_id), {}).get("verdict")
                                          in {"SUPPORTED", "REJECTED"} for path in candidates)
            if complete or self.resolved_branches.get(cwe) == "PROTECTION_ESTABLISHED":
                reasons[cwe] = self.resolved_branches.get(cwe, "REVIEW_COMPLETE")
            elif not nav.sinks or not (active_path or frontiers):
                self.resolved_branches[cwe] = reasons[cwe] = "PRUNED_LOW_POTENTIAL"
            else:
                eligible.append(cwe)
                self.progress[cwe] = self.branch_progress(cwe, candidates)
        self.focus_order = sorted(eligible, key=lambda cwe: (
            -scores[cwe]["evidence_score"], not scores[cwe]["sources"],
            scores[cwe]["distance_to_sink"] if scores[cwe]["distance_to_sink"] is not None else float("inf"),
            not scores[cwe]["has_active_path"], cwe))[:2]
        self.active = set(self.focus_order)
        for cwe in eligible:
            if cwe in self.active:
                reasons[cwe] = "FOCUS_SELECTED"
                self.resolved_branches.pop(cwe, None)
            else:
                self.resolved_branches[cwe] = reasons[cwe] = "FOCUS_NOT_SELECTED"
        self.allocate_focus_tools()
        return {"active": self.focus_order, "reasons": reasons, "branch_progress": scores}

    def allocate_focus_tools(self):
        ranked = [cwe for cwe in self.focus_order if cwe in self.active]
        if ranked:
            quota, remainder = divmod(max(0, self.limits.max_tool_calls - self.tool_calls), len(ranked))
            self.focus_tool_caps = {cwe: self.branch_calls[cwe] + quota + (index < remainder)
                                    for index, cwe in enumerate(ranked)}


def _execution_order(nodes: tuple[Node, ...], run: _Run):
    """Prioritize discovery leads, retaining each branch's independent review."""
    yield from (node.id for node in nodes if node.role == "discovery")
    for number in range(1, run.rounds + 1):
        focus = {cwe: index for index, cwe in enumerate(run.focus_order)}
        ranked = sorted(SUPPORTED_CWES, key=lambda cwe: (
            focus.get(cwe, len(focus)), -len(run.discovery_hypotheses[cwe])))
        for cwe in ranked:
            yield from (node.id for node in nodes if node.round == number and node.cwe == cwe)
        yield from (node.id for node in nodes if node.round == number and node.role == "router")
    yield from (node.id for node in nodes if node.role == "report")


def run_dag(
    repository_root: str | Path, output_root: str | Path, team: AgentTeam, *,
    rounds: int = 2, mode: str = "adaptive", static_report: Path | None = None,
    static_graph: Path | None = None, static_return_witness: Path | None = None,
    static_character_witness: Path | None = None, static_shared_field: Path | None = None,
    limits: HarnessLimits = HarnessLimits(48, 40), policy_ids: Mapping[str, str] | None = None,
    repair_protocol: bool = False, path_sensitive: bool = False, agentic_rag: bool = False,
    adaptive_gaps: bool = False, static_value_bridges: Path | None = None,
    source_witness_navigation: bool = False,
    focus_scheduling: bool | None = None,
    request_headroom: Callable[[], int] | None = None,
    token_headroom: Callable[[], int] | None = None,
    general_evp: bool = False,
) -> dict:
    if mode not in {"fixed", "adaptive"}:
        raise ValueError("mode must be fixed or adaptive")
    if path_sensitive and not repair_protocol:
        raise ValueError("path-sensitive claims require protocol validation")
    repository = Path(repository_root).resolve()
    output = Path(output_root).resolve()
    if output.is_relative_to(repository):
        raise ValueError("output must be outside the model-visible source repository")
    nodes = plan(rounds)
    by_id = {node.id: node for node in nodes}
    tools = RepositoryTools.open(repository)
    if any(path is not None for path in (static_return_witness, static_character_witness, static_shared_field,
                                         static_value_bridges)) and static_graph is None:
        raise ValueError("A CodeQL witness requires its matching static graph.")
    navigation = source_witness_navigation or static_value_bridges is not None
    focus_scheduling = rounds >= 4 if focus_scheduling is None else focus_scheduling
    graph = (CodeQLGraphIndex(repository, tools.index.entities, static_graph,
                             static_return_witness, static_character_witness, static_shared_field)
             if static_graph is not None or navigation else None)
    retrieval = StructuralRetrieval(tools.index.entities, static_report, graph)
    value_paths = ValuePaths(graph, static_value_bridges) if navigation else None
    output.mkdir(parents=True, exist_ok=False)
    (output / "dag.json").write_text(canonical_json([asdict(node) for node in nodes]) + "\n", encoding="utf-8")
    state = {}
    with (output / "trace.jsonl").open("x", encoding="utf-8") as trace:
        run = _Run(tools, retrieval, team, limits, trace, mode, rounds, repair_protocol,
                   path_sensitive, agentic_rag, adaptive_gaps, value_paths, focus_scheduling, request_headroom, token_headroom, general_evp)
        handlers = {"discovery": run.discover, "retrieval": run.retrieve,
                    "reasoning": run.reason, "verification": run.verify, "router": run.route}
        for identity in _execution_order(nodes, run):
            node = by_id[identity]
            if node.role == "report":
                state[identity] = {"status": "REPORT"}
            elif run.stopped or (node.cwe and node.cwe not in run.active):
                state[identity] = {"status": "SKIPPED", "reason": run.stopped or "NO_RECOVERY_NEEDED"}
            else:
                try:
                    result = handlers[node.role](node)
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    run.stopped = "TOOL_OR_STATE_ERROR"
                    run.event(node, "node_error", error_type=type(exc).__name__, error=str(exc)[:300])
                    result = {}
                state[identity] = {"status": "INTERRUPTED" if run.stopped else "COMPLETE", **result}
                if identity in run.protocol_failed_nodes:
                    state[identity].update(status="FAILED", reason="PROTOCOL_RECOVERY_EXHAUSTED")
            run.event(node, "node_finished", **state[identity])
            checkpoint = {
                "nodes": state, "model_calls": run.model_calls, "tool_calls": run.tool_calls,
                "stop_reason": run.stopped, "pending_retrieval": dict(run.retrieval_tasks),
                "candidates": [{"cwe": cwe, **path.to_dict()} for cwe in run.cases
                               for path in run.candidate_paths(cwe)],
                "exploration_memory": dict(run.exploration),
                "dataflow_fact_ledgers": {cwe: ledger.context() for cwe, ledger in run.fact_ledgers.items()},
                "branch_vitality": run.vitality_history,
                "semantic_bridge_probes": [{"cwe": key[0], "candidate_path_id": key[1], **value}
                                           for key, value in run.semantic_probes.items()],
                "reviews": list(run.reviews.values()), "case_reviews": run.case_reviews,
                "evidence": {cwe: [proof.to_dict() for proof in case.evidence.values()]
                             for cwe, case in run.cases.items()},
            }
            temporary = output / "checkpoint.json.tmp"
            temporary.write_text(canonical_json(checkpoint) + "\n", encoding="utf-8")
            temporary.replace(output / "checkpoint.json")
    paths = [{"cwe": cwe, **path.to_dict(), "assumed_bridges": assumed} if (assumed := run.path_assumptions(cwe, path))
             else {"cwe": cwe, **path.to_dict()}
             for cwe in run.cases for path in run.candidate_paths(cwe)]
    for item in paths:
        key = item["cwe"], item["candidate_path_id"]
        if key in run.path_claims:
            item["path_claim"] = run.path_claims[key]
    artifacts = {
        "hypotheses": [{"cwe": cwe, **hypothesis} for cwe, hypotheses in run.discovery_hypotheses.items()
                       for hypothesis in hypotheses],
        "candidates": paths, "reviews": list(run.reviews.values()),
        "audit_cases": [{"cwe": cwe, **note} for cwe, note in run.audit_cases.items()],
        "case_reviews": run.case_reviews,
        "protection_reviews": run.protection_reviews,
        "contract_obligations": [{"cwe": cwe, **item} for cwe, item in run.contract_obligations.items()],
        "verified_subpaths": [{"cwe": cwe, **fact} for cwe, ledger in run.fact_ledgers.items() for fact in ledger.facts.values()],
        "semantic_bridge_probes": [{"cwe": key[0], "candidate_path_id": key[1], **value}
                                   for key, value in run.semantic_probes.items()],
    }
    for name, records in artifacts.items():
        (output / (name + ".jsonl")).write_text(
            "".join(canonical_json(record) + "\n" for record in records), encoding="utf-8",
        )
    summary = {
        "stage": "M7_DAG_GRAPH_RAG_VALUE_PATHS" if value_paths is not None else "M7_DAG_GRAPH_RAG_V10",
        "general_evp": general_evp,
        "reasoning_rounds_admitted": {cwe: sorted(rounds) for cwe, rounds in run.admitted_reason_rounds.items()},
        "dataflow_fact_counts": {cwe: len(ledger.facts) for cwe, ledger in run.fact_ledgers.items()},
        "semantic_bridge_probes": len(run.semantic_probes),
        "codeql_graph": graph.summary() if static_graph is not None else None,
        "value_graph": value_paths.summary() if value_paths is not None else None,
        "branch_outcomes": run.resolved_branches,
        "protection_rejected": (sum(review["verdict"] == "REJECTED" for review in run.protection_reviews)
                                + sum(review.get("dead_end_reason") == "SANITIZED" for review in run.reviews.values())),
        "branch_tool_calls": dict(run.branch_calls), "mode": mode, "rounds": rounds,
        "policies": dict(policy_ids or {}), "limits": asdict(limits),
        "model_calls": run.model_calls, "tool_calls": run.tool_calls, "reported_usage": dict(run.usage),
        "stop_reason": run.stopped or "GRAPH_COMPLETE", "nodes": state,
        "static_report_sha256": run.retrieval.static_sha256, "candidate_paths": len(paths),
        "verifier_supported": sum(review["verdict"] == "SUPPORTED" and not review["conditional_library_contract"]
                                  for review in run.reviews.values()),
        "conditionally_supported": sum(review["verdict"] == "SUPPORTED" and review["conditional_library_contract"]
                                       for review in run.reviews.values()),
        "audit_cases": len(run.audit_cases), "partial_case_reviews": len(run.case_reviews),
        "contract_obligations": len(run.contract_obligations),
        "protocol_failures": dict(run.protocol_failures), "protocol_repairs": run.protocol_repairs,
        "protocol_failed_nodes": sorted(run.protocol_failed_nodes),
        "stalled_branches": sorted(run.stalled_branches),
        "eligible_for_detection_metric": False,
    }
    (output / "run.json").write_text(canonical_json(summary) + "\n", encoding="utf-8")
    return summary
