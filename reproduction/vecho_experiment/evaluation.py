"""Offline-only benchmark metrics. Labels are never passed to analysis workers."""
import csv
from pathlib import Path
from .io import read, write


def labels(dataset, project):
    with (Path(dataset) / "metadata/fix_info.csv").open(encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    exact = [r for r in rows if r["project_slug"] == project["project_slug"]]
    if exact:
        return exact, "exact_slug"
    fixes = set(project["fix_commit_ids"].split(";")) - {""}
    return [r for r in rows if r["cve_id"] == project["cve_id"] and r["commit"] in fixes
            and r["github_username"].casefold() == project["github_username"].casefold()
            and r["github_repository_name"].casefold() == project["github_repository_name"].casefold()], "cve_repository_fix"


def evaluate(repo, records, fixes):
    from tree_sitter import Language, Parser
    import tree_sitter_java
    parser = Parser(Language(tree_sitter_java.language()))
    repo = Path(repo).resolve()
    targets = {(r["file"], r["class"], r["method"]) for r in fixes if "/test/" not in "/" + r["file"]}
    if not targets:
        return {"status": "unavailable_no_labels", "recall": None, "precision": None, "f1": None,
                "location_match": {"status": "unavailable_no_labels", "hit": None, "matches": []},
                "alerts": len(records), "paths": sum(len(r.get("tainted_data_flow", [])) for r in records)}
    cache, parse_errors, invalid_nodes = {}, [], []
    def method_at(node):
        rel = node["file_path"]
        path = (repo / rel).resolve()
        if not path.is_relative_to(repo) or not path.is_file() or path.suffix != ".java":
            invalid_nodes.append(node); return None
        if rel not in cache:
            source = path.read_bytes()
            # Same line-preserving Maven template normalization as pilot metric.
            if "src/main/resources/archetype-resources/" in rel:
                import re
                source = re.sub(rb"(?m)^[ \t]*##[^\r\n]*", lambda m: b" " * len(m[0]), source)
                source = source.replace(b"${package}", b"p_________")
            tree = parser.parse(source)
            if tree.root_node.has_error: parse_errors.append(rel)
            cache[rel] = tree
        tree = cache[rel]
        line = node["line_number"] - 1
        if line < 0 or line >= tree.root_node.end_point.row + 1:
            invalid_nodes.append(node); return None
        def visit(n, cls=None):
            if not n.start_point.row <= line <= n.end_point.row: return None
            if n.type in {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration", "annotation_type_declaration"}:
                field = n.child_by_field_name("name")
                if field: cls = field.text.decode()
            # Descend first so local/nested class methods bind to their own class.
            for child in n.named_children:
                match = visit(child, cls)
                if match: return match
            if n.type in {"method_declaration", "constructor_declaration", "compact_constructor_declaration"} and cls:
                name = n.child_by_field_name("name")
                if name: return (rel, cls, name.text.decode())
            return None
        return visit(tree.root_node)
    details, tp_paths, total = [], 0, 0
    location_hits, location_invalid, location_parse_errors = [], [], []
    for record in records:
        hits, matched_paths = set(), 0
        for flow in record.get("tainted_data_flow", []):
            total += 1
            match = {method_at(n) for n in flow} & targets
            if match: tp_paths += 1; matched_paths += 1; hits.update(match)
        details.append({"fingerprint": record["fingerprint"], "benchmark_hit": bool(hits),
                        "paths": len(record.get("tainted_data_flow", [])), "tp_paths": matched_paths,
                        "matched_methods": sorted(hits)})
    # Separate diagnostic: never turn a location-only finding into a path, and
    # never let its parsing failures change the original strict-path metric.
    path_errors, path_invalid = list(parse_errors), list(invalid_nodes)
    for record in records:
        for affected in record.get("affected_files", []):
            for line in affected["line_numbers"]:
                n = {"file_path": affected["file_path"], "line_number": line}
                old_invalid = len(invalid_nodes)
                match = method_at(n)
                if len(invalid_nodes) > old_invalid: location_invalid.append(n)
                if affected["file_path"] in cache and cache[affected["file_path"]].root_node.has_error:
                    location_parse_errors.append(affected["file_path"])
                if match in targets:
                    location_hits.append({"fingerprint": record["fingerprint"], "file": n["file_path"],
                                          "line": line, "method": match})
    parse_errors, invalid_nodes = path_errors, path_invalid
    recall = int(tp_paths > 0); precision = tp_paths / total if total else 0
    return {"status": "available" if not parse_errors and not invalid_nodes else "unscorable_source_or_locations",
            "metric": "IRIS path/method intersection, reconstructed with tree-sitter; not exact author evaluator",
            "recall": recall if not parse_errors and not invalid_nodes else None,
            "precision": precision if not parse_errors and not invalid_nodes else None,
            "f1": (2 * recall * precision / (recall + precision) if recall + precision else 0) if not parse_errors and not invalid_nodes else None,
            "alerts": len(records), "paths": total, "tp_paths": tp_paths, "tp_alerts": sum(d["benchmark_hit"] for d in details),
            "location_only_alerts": sum(not r.get("tainted_data_flow") for r in records),
            "targets": sorted(targets), "parse_error_files": parse_errors, "invalid_nodes": invalid_nodes,
            "location_match": {"status": "unscorable_source_or_locations" if location_invalid or location_parse_errors else "available",
                               "hit": None if location_invalid or location_parse_errors else bool(location_hits),
                               "matches": location_hits, "invalid_nodes": location_invalid,
                               "parse_error_files": sorted(set(location_parse_errors)),
                               "note": "Affected positions intersect labelled methods; not a vulnerability path or a replacement for path recall."},
            "details": details, "note": "Unmatched alerts are not independently proved false positives; no PoC verification implied."}


def summarize(workspace, expected):
    workspace = Path(workspace)
    outcomes = []
    for sample in expected:
        path = workspace / "projects" / f"sample_{sample:04d}" / "result.json"
        result = read(path) if path.exists() else {"status": "not_run"}
        outcomes.append({"id": sample, **result})
    valid = [r for r in outcomes if r["status"] == "complete" and r.get("evaluation", {}).get("status") == "available"]
    failed = [r["id"] for r in outcomes if r["status"] != "complete"]
    fdr = [1 - r["evaluation"]["precision"] for r in valid if r["evaluation"]["paths"] > 0]
    detected = sum(r["evaluation"]["recall"] for r in valid)
    return {"expected": len(expected), "completed": sum(r["status"] == "complete" for r in outcomes),
            "scorable": len(valid), "detected": detected,
            "detection_rate_completed_scorable": detected / len(valid) if valid else None,
            "avg_f1_completed_scorable": sum(r["evaluation"]["f1"] for r in valid) / len(valid) if valid else None,
            "avg_fdr_with_paths": sum(fdr) / len(fdr) if fdr else None,
            "failed_or_unrun": failed, "all_workflows_complete": not failed,
            "unknown_verdicts": sum(r.get("unknown_verdicts", 0) for r in outcomes),
            "paper_comparable_denominator": len(valid) == len(expected), "outcomes": outcomes}


def compare(left, right):
    a, b = read(left), read(right)
    aa = {x["id"]: x for x in a["outcomes"] if x["status"] == "complete" and x.get("evaluation", {}).get("status") == "available"}
    bb = {x["id"]: x for x in b["outcomes"] if x["status"] == "complete" and x.get("evaluation", {}).get("status") == "available"}
    paired = sorted(set(aa) & set(bb))
    if any(aa[i].get("sample_identity") != bb[i].get("sample_identity") for i in paired):
        raise ValueError("Paired sample IDs refer to different source identities")
    improvements = [i for i in paired if aa[i]["evaluation"]["recall"] < bb[i]["evaluation"]["recall"]]
    regressions = [i for i in paired if aa[i]["evaluation"]["recall"] > bb[i]["evaluation"]["recall"]]
    def metrics(rows):
        if not paired: return None
        return {k: sum(rows[i]["evaluation"][k] for i in paired) / len(paired) for k in ["recall", "precision", "f1"]}
    return {"paired_samples": paired, "left_only_or_right_missing": sorted(set(aa) - set(bb)),
            "right_only_or_left_missing": sorted(set(bb) - set(aa)), "improvements": improvements,
            "regressions": regressions, "net_detected_change": len(improvements) - len(regressions),
            "left_paired_means": metrics(aa), "right_paired_means": metrics(bb),
            "left_budget": a.get("budget"), "right_budget": b.get("budget"),
            "note": "Paired descriptive comparison; not a claim of statistical significance or exceeding the authors' experiment."}
