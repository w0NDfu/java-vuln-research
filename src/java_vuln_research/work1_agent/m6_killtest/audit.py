from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from .contracts import FailureReason, M6_PROPOSAL_BUDGET
from .io import read_csv, read_json, read_jsonl, sha256_file, truthy, write_json


REQUIRED_CASE_FILES = (
    "case_manifest.json",
    "baseline.json",
    "diagnostic_analysis.json",
    "proposals.jsonl",
    "gate_results.jsonl",
    "graph_nodes.jsonl",
    "graph_edges.jsonl",
    "candidate_paths.jsonl",
    "evaluation.json",
    "counterfactual.json",
    "minimality.json",
    "summary.json",
)
REQUIRED_SCHEMA_BINDINGS = {
    "M1_ProgramEntity",
    "M2_RepositoryTools",
    "M3_CodeQLTools",
    "M4_SecurityProposal",
    "M4_EvidenceGate",
    "M5_HybridEvidenceGraph",
    "M5_HybridCandidatePath",
    "LegacyCandidatePath",
}


def audit_artifacts(artifact_root: str | Path, output_json: str | Path | None = None) -> dict[str, Any]:
    root = Path(artifact_root)
    violations: list[str] = []
    selected = read_csv(root / "selected_cases.csv")
    results = read_csv(root / "case_results.csv")
    result_index = {(row["project_id"], row["case_id"]): row for row in results}
    case_dirs = sorted(path for path in (root / "cases").iterdir() if path.is_dir()) if (root / "cases").is_dir() else []
    if len(case_dirs) != len(selected):
        violations.append(f"CASE_DIRECTORY_COUNT:{len(case_dirs)}!={len(selected)}")
    audited_cases: list[dict[str, Any]] = []
    allowed_failures = {item.value for item in FailureReason}
    for case_root in case_dirs:
        missing = [name for name in REQUIRED_CASE_FILES if not (case_root / name).is_file()]
        if missing:
            violations.append(f"MISSING_CASE_FILES:{case_root.name}:{','.join(missing)}")
            continue
        manifest = read_json(case_root / "case_manifest.json")
        key = (str(manifest.get("project_id")), str(manifest.get("case_id")))
        result = result_index.get(key, {})
        for field in ("git_sha", "project_revision", "codeql_version", "codeql_db_identity"):
            if not manifest.get(field):
                violations.append(f"CASE_BINDING_MISSING:{case_root.name}:{field}")
        if not REQUIRED_SCHEMA_BINDINGS.issubset(set(manifest.get("bound_schema_versions", {}))):
            violations.append(f"SCHEMA_BINDING_MISSING:{case_root.name}")
        for name, digest in manifest.get("artifact_hashes", {}).items():
            if not (case_root / name).is_file() or sha256_file(case_root / name) != digest:
                violations.append(f"CASE_HASH_MISMATCH:{case_root.name}:{name}")
        baseline = read_json(case_root / "baseline.json")
        for field in ("command_template", "query_paths", "output_paths", "baseline_detected", "codeql_version", "codeql_db_identity", "source_revision", "output_hashes"):
            if field not in baseline:
                violations.append(f"BASELINE_BINDING_MISSING:{case_root.name}:{field}")
        if baseline.get("baseline_detected") is not False or not baseline.get("baseline_query_unchanged"):
            violations.append(f"BASELINE_NOT_FROZEN_MISS:{case_root.name}")
        diagnostic = read_json(case_root / "diagnostic_analysis.json")
        if diagnostic.get("benchmark_informed") is not True or diagnostic.get("allowed_for_agent_runtime") is not False:
            violations.append(f"DIAGNOSTIC_FLAG_INVALID:{case_root.name}")
        proposals = read_jsonl(case_root / "proposals.jsonl")
        if len(proposals) > M6_PROPOSAL_BUDGET:
            violations.append(f"PROPOSAL_BUDGET_EXCEEDED:{case_root.name}")
        if any(item.get("provenance", {}).get("allowed_for_agent_runtime") is not False for item in proposals):
            violations.append(f"PROPOSAL_RUNTIME_FLAG_INVALID:{case_root.name}")
        recovered = truthy(result.get("mechanism_recovered"))
        if recovered:
            evaluation = read_json(case_root / "evaluation.json")
            counterfactual = read_json(case_root / "counterfactual.json")
            minimality = read_json(case_root / "minimality.json")
            if not evaluation.get("evaluation_started_after_detector_freeze") or not evaluation.get("mechanism_recovered"):
                violations.append(f"RECOVERY_FREEZE_INVALID:{case_root.name}")
            if not counterfactual.get("recovery_removed"):
                violations.append(f"COUNTERFACTUAL_NOT_CAUSAL:{case_root.name}")
            if len(proposals) > 1 and not minimality.get("all_used_proposals_necessary"):
                violations.append(f"PROPOSAL_SET_NOT_MINIMAL:{case_root.name}")
            matched = {item["candidate_path_id"] for item in evaluation.get("matched_paths", ())}
            paths = [item for item in read_jsonl(case_root / "candidate_paths.jsonl") if item.get("candidate_path_id") in matched]
            if not paths:
                violations.append(f"RECOVERY_PATH_MISSING:{case_root.name}")
            for path in paths:
                edges = path.get("ordered_edges", ())
                if not any(edge.get("relation_kind") not in {"EXTERNAL_INPUT", "SECURITY_EFFECT"} for edge in edges):
                    violations.append(f"TRIVIAL_RECOVERY_PATH:{case_root.name}")
                support = path.get("support_summary", {})
                if int(support.get("structural_edge_count") or 0) + int(support.get("deterministic_edge_count") or 0) < 1:
                    violations.append(f"NO_PROGRAM_RELATION:{case_root.name}")
        else:
            reason = str(result.get("failure_reason") or "")
            if reason not in allowed_failures:
                violations.append(f"FAILURE_TAXONOMY_INVALID:{case_root.name}:{reason}")
        audited_cases.append({"project_id": key[0], "case_id": key[1], "recovered": recovered, "proposal_count": len(proposals)})
    aggregate_manifest = read_json(root / "manifest.json")
    for name, digest in aggregate_manifest.get("artifact_hashes", {}).items():
        if not (root / name).is_file() or sha256_file(root / name) != digest:
            violations.append(f"AGGREGATE_HASH_MISMATCH:{name}")
    diagnostic_root = root / "diagnostic_proposals"
    if not (diagnostic_root / "manifest.json").is_file():
        violations.append("DIAGNOSTIC_MANIFEST_MISSING")
    if len(list(diagnostic_root.glob("*.proposals.jsonl"))) != len(selected):
        violations.append("DIAGNOSTIC_PROPOSAL_COPY_COUNT_MISMATCH")
    report = {
        "schema_version": 1,
        "status": "PASS" if not violations else "FAIL",
        "selected_case_count": len(selected),
        "audited_case_count": len(audited_cases),
        "recovered_case_count": sum(item["recovered"] for item in audited_cases),
        "required_case_files": list(REQUIRED_CASE_FILES),
        "violations": violations,
        "cases": audited_cases,
    }
    if output_json:
        write_json(output_json, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit Work1 v1.1 M6 artifacts")
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    report = audit_artifacts(args.artifact_root, args.output)
    print(report)
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
