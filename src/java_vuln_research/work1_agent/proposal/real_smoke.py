from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from java_vuln_research.work1_agent.repository.entity import ProgramEntity, ProgramEntityKind

from .evidence import EvidenceRef, EvidenceSourceKind, EvidenceStrength
from .gate import EvidenceGate, EvidenceGateResult, GateStatus
from .model import EntityRole, EntityRoleRef, ProposalScope, ProposalType, ScopeKind, SecurityProposal
from .serialization import read_evidence, read_proposals, write_jsonl
from .smoke import summarize


REAL_PROJECT_COHORT = ("P006", "P007", "D001", "D002", "V001", "V002", "V003", "V004")
CODEQL_KINDS = {
    "codeql_entity_facts": EvidenceSourceKind.CODEQL_ENTITY_FACT,
    "codeql_callers": EvidenceSourceKind.CODEQL_CALL,
    "codeql_callees": EvidenceSourceKind.CODEQL_CALL,
    "codeql_local_flow": EvidenceSourceKind.CODEQL_LOCAL_FLOW,
    "codeql_dataflow_neighbors": EvidenceSourceKind.CODEQL_DATAFLOW,
    "codeql_cfg_neighbors": EvidenceSourceKind.CODEQL_CFG,
}


def _load_entities(path: Path) -> list[ProgramEntity]:
    return sorted(
        (ProgramEntity.from_dict(json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()),
        key=lambda item: (item.repository_relative_path, item.start_line, item.kind.value, item.entity_id),
    )


def _entities_path(index_roots: Sequence[Path], project_id: str) -> Path:
    for root in index_roots:
        candidate = root / project_id / "entities.jsonl"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"entities.jsonl unavailable for {project_id}")


def _source_evidence(root: Path, entity: ProgramEntity, project_id: str) -> EvidenceRef:
    source = root / Path(*entity.repository_relative_path.split("/"))
    lines = source.read_text(encoding="utf-8").splitlines()
    selected = "\n".join(lines[entity.start_line - 1 : entity.end_line])
    return EvidenceRef.create(
        source_kind=EvidenceSourceKind.SOURCE_SNIPPET,
        entity_ids=[entity.entity_id],
        repository_relative_path=entity.repository_relative_path,
        start_line=entity.start_line,
        end_line=entity.end_line,
        content_hash=hashlib.sha256(selected.encode("utf-8")).hexdigest(),
        confidence=EvidenceStrength.DIRECT,
        provenance={"producer": "WORK1_V11_M4_REAL_PROJECT_SMOKE", "project_id": project_id, "llm_used": False},
    )


def _role_for(entity: ProgramEntity) -> EntityRoleRef:
    if entity.kind in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}:
        return EntityRoleRef(entity.entity_id, EntityRole.RETURN)
    if entity.kind == ProgramEntityKind.CALL:
        return EntityRoleRef(entity.entity_id, EntityRole.CALL_RESULT)
    if entity.kind == ProgramEntityKind.FIELD:
        return EntityRoleRef(entity.entity_id, EntityRole.FIELD)
    if entity.kind == ProgramEntityKind.PARAMETER:
        return EntityRoleRef(entity.entity_id, EntityRole.PARAMETER, int(entity.provenance.get("parameter_index", 0)))
    return EntityRoleRef(entity.entity_id, EntityRole.ENTITY)


def _proposal(project_id: str, entity: ProgramEntity, evidence_ids: Sequence[str], *, category: str) -> SecurityProposal:
    subject = _role_for(entity)
    return SecurityProposal.create(
        proposal_type=ProposalType.EXTERNAL_INPUT,
        subject=subject,
        scope=ProposalScope(ScopeKind.ENTITY, (entity.entity_id,), project_id),
        evidence_refs=evidence_ids,
        reason="Deterministic real-project grounding hypothesis; not a vulnerability or confirmed source classification.",
        semantic_category=category,
        provenance={
            "producer": "WORK1_V11_M4_REAL_PROJECT_SMOKE",
            "project_id": project_id,
            "selection": "LEXICOGRAPHIC_ENTITY_ORDER_WITH_OPTIONAL_EXISTING_M3_FACT",
            "llm_used": False,
            "benchmark_or_patch_input_used": False,
        },
    )


def _load_tool_calls(path: Path) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Mapping[str, Any]]]:
    by_project: dict[str, list[dict[str, Any]]] = {}
    artifact_index: dict[str, Mapping[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        call_id = str(item.get("tool_call_id") or "")
        if call_id:
            artifact_index[call_id] = item
        if item.get("status") == "OK" and item.get("tool_name") == "codeql_entity_facts":
            by_project.setdefault(str(item.get("project_id")), []).append(item)
    for values in by_project.values():
        values.sort(key=lambda item: (str(item.get("entity_path")), int(item.get("entity_start_line") or 0), str(item.get("entity_id"))))
    return by_project, artifact_index


def run_real(
    *,
    inventory_csv: str | Path,
    index_roots: Sequence[str | Path],
    tool_calls_jsonl: str | Path,
    artifact_root: str | Path,
) -> dict[str, Any]:
    with Path(inventory_csv).open(encoding="utf-8-sig", newline="") as handle:
        inventory = {str(row["project_id"]): row for row in csv.DictReader(handle)}
    tool_calls_by_project, artifact_index = _load_tool_calls(Path(tool_calls_jsonl))
    roots = [Path(item) for item in index_roots]
    all_proposals: list[SecurityProposal] = []
    all_evidence: list[EvidenceRef] = []
    all_results: list[EvidenceGateResult] = []
    projects: list[dict[str, Any]] = []
    for project_id in REAL_PROJECT_COHORT:
        row = inventory[project_id]
        source_root = Path(str(row["source_root"]))
        entities = _load_entities(_entities_path(roots, project_id))
        by_id = {item.entity_id: item for item in entities}
        callables = [item for item in entities if item.kind in {ProgramEntityKind.METHOD, ProgramEntityKind.CONSTRUCTOR}]
        if not callables:
            raise ValueError(f"no callable entity for {project_id}")
        first = callables[0]
        evidence: list[EvidenceRef] = [_source_evidence(source_root, first, project_id)]
        proposals: list[SecurityProposal] = [_proposal(project_id, first, [evidence[0].evidence_id], category="UNKNOWN")]
        codeql_call = next((item for item in tool_calls_by_project.get(project_id, ()) if str(item.get("entity_id")) in by_id and str(item.get("entity_id")) != first.entity_id), None)
        if codeql_call is not None:
            entity = by_id[str(codeql_call["entity_id"])]
            source = _source_evidence(source_root, entity, project_id)
            provenance = codeql_call.get("provenance") or {}
            codeql = EvidenceRef.create(
                source_kind=CODEQL_KINDS[str(codeql_call["tool_name"])],
                entity_ids=[entity.entity_id],
                repository_relative_path=entity.repository_relative_path,
                start_line=entity.start_line,
                end_line=entity.end_line,
                tool_call_id=str(codeql_call["tool_call_id"]),
                result_hash=str(provenance.get("result_hash")) if provenance.get("result_hash") else None,
                confidence=EvidenceStrength.DIRECT,
                provenance={
                    "producer": "WORK1_V11_M4_REAL_PROJECT_SMOKE",
                    "project_id": project_id,
                    "m3_v11_git_sha": provenance.get("v11_git_sha"),
                    "query_hash": provenance.get("query_hash"),
                },
            )
            evidence.extend((source, codeql))
            proposals.append(_proposal(project_id, entity, [source.evidence_id, codeql.evidence_id], category="OTHER"))
        gate = EvidenceGate(
            repository_root=source_root,
            entities=entities,
            evidence_catalog={item.evidence_id: item for item in evidence},
            artifact_index=artifact_index,
        )
        results = gate.evaluate_many(proposals)
        all_proposals.extend(proposals)
        all_evidence.extend(evidence)
        all_results.extend(results)
        projects.append({
            "project_id": project_id,
            "proposal_count": len(proposals),
            "status_counts": dict(Counter(item.status.value for item in results)),
            "repository_only_admission_count": sum(item.provenance.get("admission_basis") == "REPOSITORY_ONLY" for item in results),
            "codeql_assisted_admission_count": sum(item.provenance.get("admission_basis") == "CODEQL_ASSISTED" for item in results),
            "codeql_ready": str(row.get("codeql_db_ready", "")).casefold() == "true",
        })
    output = Path(artifact_root)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "proposals.jsonl", all_proposals)
    write_jsonl(output / "gate_results.jsonl", all_results)
    write_jsonl(output / "evidence_index.jsonl", all_evidence)
    write_jsonl(output / "failures.jsonl", (item for item in all_results if item.status != GateStatus.ADMISSIBLE))
    summary = summarize(all_proposals, all_results, expected_invalid_count=0)
    summary.update({
        "cohort": list(REAL_PROJECT_COHORT),
        "selection_rule": "first two P, first two D, first four V by project_id",
        "project_count": len(REAL_PROJECT_COHORT),
        "projects": projects,
        "benchmark_vulnerability_location_patch_cve_cwe_used": False,
        "max_proposals_per_project": max(item["proposal_count"] for item in projects),
    })
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def combine_artifacts(controlled_root: str | Path, real_root: str | Path, output_root: str | Path) -> dict[str, Any]:
    controlled, real, output = Path(controlled_root), Path(real_root), Path(output_root)
    proposals = read_proposals(controlled / "proposals.jsonl") + read_proposals(real / "proposals.jsonl")
    evidence = read_evidence(controlled / "evidence_index.jsonl") + read_evidence(real / "evidence_index.jsonl")
    results = [json.loads(line) for source in (controlled, real) for line in (source / "gate_results.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
    failures = [item for item in results if item["status"] != "ADMISSIBLE"]
    status_counts = Counter(item["status"] for item in results)
    controlled_summary = json.loads((controlled / "summary.json").read_text(encoding="utf-8"))
    real_summary = json.loads((real / "summary.json").read_text(encoding="utf-8"))
    summary = {
        "proposal_count": len(proposals),
        "evidence_count": len(evidence),
        "status_counts": dict(sorted(status_counts.items())),
        "status_rates": {key: round(value / len(results), 6) for key, value in sorted(status_counts.items())},
        "proposal_type_counts": dict(sorted(Counter(item.proposal_type.value for item in proposals).items())),
        "repository_only_admission_count": controlled_summary["repository_only_admission_count"] + real_summary["repository_only_admission_count"],
        "codeql_assisted_admission_count": controlled_summary["codeql_assisted_admission_count"] + real_summary["codeql_assisted_admission_count"],
        "invalid_or_fabricated_non_admission_rate": controlled_summary["invalid_or_fabricated_non_admission_rate"],
        "controlled_fixture": controlled_summary,
        "real_project_smoke": real_summary,
        "detection_rate": None,
        "interpretation": "Mechanism metrics only; no vulnerability evaluation was performed.",
    }
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "proposals.jsonl", proposals)
    write_jsonl(output / "gate_results.jsonl", results)
    write_jsonl(output / "evidence_index.jsonl", evidence)
    write_jsonl(output / "failures.jsonl", failures)
    (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run deterministic M4 grounding smoke on eight real projects")
    parser.add_argument("--inventory-csv", required=True)
    parser.add_argument("--index-root", action="append", required=True)
    parser.add_argument("--tool-calls", required=True)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--controlled-root")
    parser.add_argument("--combined-root")
    args = parser.parse_args(argv)
    summary = run_real(
        inventory_csv=args.inventory_csv,
        index_roots=args.index_root,
        tool_calls_jsonl=args.tool_calls,
        artifact_root=args.artifact_root,
    )
    if args.controlled_root and args.combined_root:
        summary = combine_artifacts(args.controlled_root, args.artifact_root, args.combined_root)
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
