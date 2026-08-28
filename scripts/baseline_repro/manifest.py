#!/usr/bin/env python3
"""Small, dependency-free control helpers for the cloud-only reproduction runs."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = (
    PROJECT_ROOT / "experiments/frozen_configs/baseline_repro_dev18_manifest.csv"
)
EXPECTED_IDS = [
    "P006", "P007", "P010", "P012", "D001", "D002", "D003", "D004",
    "V001", "V004", "V005", "V007", "V021", "V022", "V023", "V025",
    "V009", "V011",
]


def load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    ids = [row["project_id"] for row in rows]
    if ids != EXPECTED_IDS:
        raise SystemExit(
            f"manifest project order/content mismatch: expected {EXPECTED_IDS}, got {ids}"
        )
    if len(set(ids)) != 18:
        raise SystemExit("manifest must contain 18 unique project ids")
    for row in rows:
        for key in ("observed_cloud_revision", "benchmark_buggy_revision"):
            value = row[key]
            if len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
                raise SystemExit(f"invalid {key} for {row['project_id']}: {value}")
    return rows


def find_row(path: Path, project_id: str) -> dict[str, str]:
    for row in load_rows(path):
        if row["project_id"] == project_id:
            return row
    raise SystemExit(f"unknown project_id: {project_id}")


def file_inventory(root: Path) -> list[dict[str, Any]]:
    if not root.exists():
        return []
    inventory: list[dict[str, Any]] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        inventory.append(
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": digest.hexdigest(),
            }
        )
    return inventory


def first_description(source: Path) -> str:
    candidates = ("README.md", "README.adoc", "README", "readme.md", "readme")
    readme = next((source / name for name in candidates if (source / name).is_file()), None)
    if readme is None:
        return source.name
    lines = readme.read_text(encoding="utf-8", errors="replace").splitlines()
    filtered: list[str] = []
    previous_empty = True
    for line in lines:
        if len(filtered) > 10:
            break
        stripped = line.strip()
        if not stripped:
            if not previous_empty:
                filtered.append("")
                previous_empty = True
        elif stripped[0].isalpha():
            filtered.append(stripped)
            previous_empty = False
        elif not previous_empty:
            filtered.append("")
            previous_empty = True
    return "\n".join(filtered) or source.name


def command_validate(args: argparse.Namespace) -> None:
    rows = load_rows(args.manifest)
    print(json.dumps({"projects_total": len(rows), "project_ids": EXPECTED_IDS}))


def command_get(args: argparse.Namespace) -> None:
    row = find_row(args.manifest, args.project_id)
    if args.field not in row:
        raise SystemExit(f"unknown manifest field: {args.field}")
    print(row[args.field])


def command_list(args: argparse.Namespace) -> None:
    for row in load_rows(args.manifest):
        print(row["project_id"])


def command_readme_head(args: argparse.Namespace) -> None:
    find_row(args.manifest, args.project_id)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(first_description(args.source), encoding="utf-8")


def command_record(args: argparse.Namespace) -> None:
    row = find_row(args.manifest, args.project_id)
    args.run_root.mkdir(parents=True, exist_ok=True)
    data = {
        "schema_version": 1,
        "method": args.method,
        "role": "PRIOR-ASSISTED POSITIVE CONTROL / SANITY BASELINE",
        "project_id": args.project_id,
        "benchmark_project_slug": row["benchmark_project_slug"],
        "cve_id": row["cve_id"],
        "cwe_id": row["cwe_id"],
        "frozen_source_revision": row["observed_cloud_revision"],
        "run_id": args.run_id,
        "started_at_utc": args.started_at,
        "ended_at_utc": args.ended_at,
        "status": args.status,
        "reason": args.reason,
        "exit_code": args.exit_code,
        "detector_ground_truth_access": args.method == "qlcoder",
        "provider_credential_present": args.credential_present,
        "command": args.command,
        "upstream_output": str(args.upstream_output),
        "artifact_inventory": file_inventory(args.upstream_output),
    }
    target = args.run_root / "run_manifest.json"
    target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    sub = result.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate")
    validate.set_defaults(func=command_validate)

    get = sub.add_parser("get")
    get.add_argument("project_id")
    get.add_argument("field")
    get.set_defaults(func=command_get)

    list_cmd = sub.add_parser("list")
    list_cmd.set_defaults(func=command_list)

    readme = sub.add_parser("readme-head")
    readme.add_argument("project_id")
    readme.add_argument("source", type=Path)
    readme.add_argument("output", type=Path)
    readme.set_defaults(func=command_readme_head)

    record = sub.add_parser("record")
    record.add_argument("--method", choices=("iris", "qlcoder"), required=True)
    record.add_argument("--project-id", required=True)
    record.add_argument("--run-id", required=True)
    record.add_argument("--run-root", type=Path, required=True)
    record.add_argument("--upstream-output", type=Path, required=True)
    record.add_argument("--started-at", required=True)
    record.add_argument("--ended-at", required=True)
    record.add_argument("--status", required=True)
    record.add_argument("--reason", required=True)
    record.add_argument("--exit-code", type=int, required=True)
    record.add_argument("--credential-present", action="store_true")
    record.add_argument("--command", required=True)
    record.set_defaults(func=command_record)
    return result


def main() -> None:
    args = parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
