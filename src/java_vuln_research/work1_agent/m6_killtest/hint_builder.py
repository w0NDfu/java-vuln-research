from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Mapping

from .contracts import FailureReason
from .io import read_jsonl, write_jsonl


def _parameter_count(signature: str) -> int:
    if "(" not in signature or ")" not in signature:
        return 0
    body = signature.split("(", 1)[1].rsplit(")", 1)[0].strip()
    return 0 if not body else len([part for part in body.split(",") if part.strip()])


def _hint(row: Mapping[str, Any]) -> dict[str, Any]:
    base = {
        "project_id": str(row["project_id"]),
        "case_id": str(row["case_id"]),
        "benchmark_informed": True,
        "allowed_for_agent_runtime": False,
        "eligible_for_detection_metric": False,
        "annotation_revision": row.get("revision", "UNKNOWN"),
    }
    fixes = [dict(item) for item in row.get("fixes", ())]
    usable = [
        item
        for item in fixes
        if item.get("file") and item.get("method") and _parameter_count(str(item.get("signature") or "")) > 0
    ]
    if not usable:
        return {
            **base,
            "diagnostic_status": FailureReason.INSUFFICIENT_PROGRAM_EVIDENCE.value,
            "diagnostic_note": "No production parameterized fix method was present in the frozen annotation projection.",
        }
    selected = usable[0]
    return {
        **base,
        "file_path": str(selected["file"]),
        "method_name": str(selected["method"]),
        "start_line": int(selected["method_start"]) if str(selected.get("method_start") or "").isdigit() else 0,
        "end_line": int(selected["method_end"]) if str(selected.get("method_end") or "").isdigit() else 0,
        "signature": str(selected.get("signature") or ""),
        "selection_rule": "FIRST_ANNOTATED_PARAMETERIZED_METHOD_IN_FROZEN_ORDER",
    }


def build_hints(compact_fix_jsonl: str | Path, output_jsonl: str | Path) -> list[dict[str, Any]]:
    rows = [_hint(row) for row in read_jsonl(compact_fix_jsonl)]
    rows.sort(key=lambda item: (item["project_id"], item["case_id"]))
    write_jsonl(output_jsonl, rows)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build deterministic M6 diagnostic hints from frozen fix-method annotations")
    parser.add_argument("--compact-fixes", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    rows = build_hints(args.compact_fixes, args.output)
    print({"hint_count": len(rows), "output": args.output})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
