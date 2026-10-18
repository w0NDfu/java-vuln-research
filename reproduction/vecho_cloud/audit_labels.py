"""Offline audit of benchmark method labels against the vulnerable snapshots.

This does not change labels, prompts, reports or scoring. Fixes may legitimately
introduce methods that do not exist in the buggy commit; retain that distinction.
"""
import collections
import csv
import json

from common import DATASET, REPRO, samples, write_json
from evaluate import declarations, method_at
from benchmark_labels import select_labels


def audit():
    with (DATASET / "metadata/fix_info.csv").open(encoding="utf-8-sig") as stream:
        fixes = list(csv.DictReader(stream))
    results = []
    for sample in samples():
        slug = sample["project_slug"]
        repo = DATASET / "project-sources" / slug
        selected, selection = select_labels(sample, fixes)
        targets = sorted({(r["file"], r["class"], r["method"]) for r in selected
                          if "src/test" not in r["file"]})
        cache, details = {}, []
        for file, cls, method in targets:
            path = repo / file
            if not path.is_file():
                status = "missing_file_in_buggy_snapshot"
            else:
                if file not in cache:
                    cache[file] = declarations(path.read_bytes())
                classes, methods, error = cache[file]
                if cls not in {x[0] for x in classes}:
                    status = "missing_class_in_buggy_snapshot"
                elif method not in {x[0] for x in methods}:
                    status = "missing_method_in_buggy_snapshot"
                elif any(method_at(repo, file, line, cache) == (file, cls, method)
                         for name, start, end in methods if name == method
                         for line in (start, end)):
                    status = "mapped"
                else:
                    status = "unmapped_class_method_pair"
            details.append({"file": file, "class": cls, "method": method, "status": status})
        counts = collections.Counter(item["status"] for item in details)
        results.append({"sample": "sample_" + str(int(sample["id"])).zfill(4),
                        "project_slug": slug, "target_count": len(targets),
                        "label_selection": selection,
                        "mapped_target_count": counts["mapped"], "status_counts": dict(counts),
                        "parse_error_files": [f for f, (_, _, error) in cache.items() if error],
                        "labels": details})
    statuses = collections.Counter(item["status"] for sample in results for item in sample["labels"])
    report = {"sample_count": len(results), "target_count": sum(x["target_count"] for x in results),
              "status_counts": dict(statuses),
              "samples_without_labels": [x["sample"] for x in results if x["label_selection"]["selection"] == "no_matching_labels"],
              "samples_with_verified_slug_aliases": [x["sample"] for x in results if x["label_selection"]["selection"] == "cve_repository_and_fix_commit"],
              "samples_without_mapped_targets": [x["sample"] for x in results if not x["mapped_target_count"]],
              "samples_with_partially_unmapped_targets": [x["sample"] for x in results
                                                         if 0 < x["mapped_target_count"] < x["target_count"]],
              "samples_with_parse_errors": [x["sample"] for x in results if x["parse_error_files"]],
              "note": "Labels and metric are unchanged. Missing targets can be methods/files introduced by fixes. This audit is about evaluator representability, not proof of vulnerability relevance.",
              "samples": results}
    write_json(REPRO / "label-audit.json", report)
    return report


if __name__ == "__main__":
    report = audit()
    print(json.dumps({k: v for k, v in report.items() if k != "samples"}, indent=2))
