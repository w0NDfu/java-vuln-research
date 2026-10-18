"""IRIS v1 method-intersection rule, with tree-sitter replacing CodeQL locations.

This is an adapted metric implementation, not a bit-for-bit IRIS evaluator.
No labels from this module are included in scan or judge prompts.
"""
import argparse
import csv
import json
import re
from pathlib import Path, PurePosixPath

from common import DATASET, samples, write_json
from benchmark_labels import select_labels


def declarations(source):
    from tree_sitter import Language, Parser
    import tree_sitter_java
    tree = Parser(Language(tree_sitter_java.language())).parse(source)
    classes, methods = [], []
    def visit(node):
        if node.type in {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration", "annotation_type_declaration", "method_declaration", "constructor_declaration", "compact_constructor_declaration"}:
            name = node.child_by_field_name("name")
            if name:
                item = (name.text.decode("utf-8", "replace"), node.start_point.row + 1, node.end_point.row + 1)
                (methods if "method" in node.type or "constructor" in node.type else classes).append(item)
        for child in node.named_children:
            visit(child)
    visit(tree.root_node)
    return classes, methods, tree.root_node.has_error


def path_key(value, repo):
    value = str(value).replace("\\", "/")
    root = repo.as_posix().rstrip("/")
    if value.startswith(root + "/"):
        value = value[len(root) + 1:]
    value = value.lstrip("/")
    while value.startswith("./"):
        value = value[2:]
    if ".." in PurePosixPath(value).parts:
        raise ValueError("out-of-repository report path")
    return value


def template_source(source, file_name):
    """Render only the observed Maven package/comment template syntax in memory.

    Preserve bytes per line and all line numbers. Unknown syntax still produces
    a parser error; paths and flows remain in the scoring denominator.
    """
    if "src/main/resources/archetype-resources/" not in file_name:
        return source, []
    if not re.search(rb"(?m)^\s*package\s+\$\{package\}\s*;", source):
        return source, []
    rendered = re.sub(rb"(?m)^[ \t]*##[^\r\n]*", lambda m: b" " * len(m[0]), source)
    rendered = re.sub(rb"(?m)^(\s*package\s+)\$\{package\}(\s*;)",
                      lambda m: m[1] + b"p_________" + m[2], rendered)
    return rendered, ["Maven archetype Velocity ## comments and package placeholder; in-memory, line preserving"]


def method_at(repo, file_name, line, cache, normalizations=None):
    if file_name not in cache:
        path = repo / file_name
        if path.is_file() and path.suffix == ".java":
            source, changes = template_source(path.read_bytes(), file_name)
            if changes and normalizations is not None:
                normalizations[file_name] = changes
            cache[file_name] = declarations(source)
        else:
            cache[file_name] = ([], [], False)
    classes, methods, _ = cache[file_name]
    def enclosing(items):
        return next((name for name, start, end in sorted(items, key=lambda x: x[1], reverse=True) if start <= line <= end), None)
    cls, method = enclosing(classes), enclosing(methods)
    return (file_name, cls, method) if cls and method else None


def score(repo, records, fixes):
    targets = {(row["file"], row["class"], row["method"]) for row in fixes if "src/test" not in row["file"]}
    cache, details, normalizations = {}, [], {}
    total_paths = tp_paths = 0
    for record in records:
        hits, inspected = set(), 0
        for flow in record.get("tainted_data_flow", []):
            inspected += 1
            total_paths += 1
            passing = set()
            for node in flow:
                file_name = path_key(node.get("file_path", ""), repo)
                key = method_at(repo, file_name, int(node.get("line_number") or 0), cache, normalizations)
                if key:
                    passing.add(key)
            matched = passing & targets
            if matched:
                tp_paths += 1
                hits.update(matched)
        details.append({"fingerprint": record.get("fingerprint"), "paths": inspected, "benchmark_hit": bool(hits), "matched_methods": sorted(hits)})
    recall = int(tp_paths > 0)
    precision = tp_paths / total_paths if total_paths else 0
    return {"metric": "IRIS-v1 method-intersection adapted to vEcho JSON with tree-sitter method locations", "exact_iris_reproduction": False, "recall": recall, "alerts": len(records), "paths": total_paths, "tp_paths": tp_paths, "tp_alerts": sum(item["benchmark_hit"] for item in details), "precision": precision, "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0, "target_methods": sorted(targets), "parse_error_files": [file for file, (_, _, error) in cache.items() if error], "source_normalizations": normalizations, "details": details, "unmatched_alerts": "Unmatched to benchmark labels; not independently established false positives"}


def evaluate(slug, repo, report, output):
    with (DATASET / "metadata/fix_info.csv").open(encoding="utf-8-sig") as file:
        rows = list(csv.DictReader(file))
    project = next((r for r in samples() if r["project_slug"] == slug), None)
    if project is None:
        raise RuntimeError("Sample is absent from project_info.csv")
    fixes, selection = select_labels(project, rows)
    payload = json.loads(Path(report).read_text())
    records = payload if isinstance(payload, list) else payload.get("vulnerabilities", [])
    if not fixes:
        result = {"evaluation_status": "unavailable_no_labels", "exact_iris_reproduction": False,
                  "recall": None, "precision": None, "f1": None, "tp_paths": None,
                  "paths": sum(len(r.get("tainted_data_flow", [])) for r in records),
                  "alerts": len(records), "parse_error_files": [],
                  "note": "Scan stages completed, but benchmark has no matching method labels. This is not a negative detection result."}
    else:
        result = score(Path(repo).resolve(), records, fixes)
        result["evaluation_status"] = "available"
    result["label_selection"] = selection
    result.update(project_slug=slug, repo=str(repo), report=str(report))
    write_json(output, result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ["slug", "repo", "report", "out"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.slug, args.repo, args.report, args.out), indent=2))
