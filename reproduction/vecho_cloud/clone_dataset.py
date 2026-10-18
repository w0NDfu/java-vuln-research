"""Fetch all benchmark source snapshots into a self-contained dataset directory."""
import argparse
import concurrent.futures
import csv
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from urllib.parse import urlparse


def git(args, cwd, log, capture=False):
    with log.open("a") as output:
        result = subprocess.run(["git", *args], cwd=cwd,
            env=dict(os.environ, GIT_TERMINAL_PROMPT="0"),
            stdout=subprocess.PIPE if capture else output, stderr=output,
            text=True, timeout=900)
    if result.returncode:
        raise RuntimeError("git command failed; inspect " + str(log))
    return result.stdout.strip() if capture else None


def fetch_group(url, rows, root):
    parts = urlparse(url).path.strip("/").removesuffix(".git").split("/")
    cache = root / "upstream-cache" / ("__".join(parts) + ".git")
    log = root / "logs" / ("__".join(parts) + ".log")
    if not cache.exists():
        git(["init", "--bare", str(cache)], root, log)
        git(["remote", "add", "origin", url], cache, log)
        git(["config", "gc.auto", "0"], cache, log)
    results = []
    for row in rows:
        slug, commit = row["project_slug"], row["buggy_commit_id"]
        target = root / "project-sources" / slug
        try:
            if not (cache / "refs/snapshots" / commit).exists():
                for attempt in range(3):
                    try:
                        git(["-c", "http.lowSpeedLimit=1024", "-c", "http.lowSpeedTime=90", "fetch", "--no-tags", "--depth=1", "origin", commit], cache, log)
                        git(["update-ref", "refs/snapshots/" + commit, commit], cache, log)
                        break
                    except Exception:
                        if attempt == 2:
                            raise
                        time.sleep(2 * (attempt + 1))
            if not target.exists():
                git(["init", str(target)], root, log)
                git(["remote", "add", "origin", str(cache)], target, log)
            head = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=target,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if head.returncode:
                if any(p.name != ".git" for p in target.iterdir()):
                    raise RuntimeError("Uninitialized target has existing files; preserved for inspection")
                # Git 2.25 does not borrow objects when cloning these shallow
                # caches. An explicit local fetch also copies the shallow boundary.
                git(["fetch", "--no-tags", "--depth=1", "origin", "refs/snapshots/" + commit], target, log)
                git(["checkout", "--detach", commit], target, log)
            actual = git(["rev-parse", "HEAD"], target, log, capture=True)
            if actual != commit or git(["status", "--porcelain", "--untracked-files=no"], target, log, capture=True):
                raise RuntimeError("Existing snapshot differs or has tracked edits; preserved for inspection")
            files = git(["ls-files"], target, log, capture=True).splitlines()
            results.append({"id": int(row["id"]), "project_slug": slug, "status": "verified", "commit": actual, "tracked_files": len(files)})
            print("VERIFIED", row["id"], slug, len(files), flush=True)
        except Exception as exc:
            results.append({"id": int(row["id"]), "project_slug": slug, "status": "failed", "error": str(exc)})
            print("FAILED", row["id"], str(exc), flush=True)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    artifact, root = Path(args.artifact).resolve(), Path(args.dataset).resolve()
    source = artifact / "Result/project_info.csv"
    with source.open(encoding="utf-8-sig") as file:
        rows = list(csv.DictReader(file))
    if {int(r["id"]) for r in rows} != set(range(1, 121)) or len(rows) != 120:
        raise RuntimeError("Expected exactly 120 benchmark samples")
    groups = {}
    for row in rows:
        slug, url = row["project_slug"], row["github_url"].rstrip("/")
        parsed = urlparse(url)
        if Path(slug).name != slug or slug in {".", ".."} or not re.fullmatch(r"[0-9a-f]{40}", row["buggy_commit_id"]):
            raise RuntimeError("Unsafe sample name or invalid commit")
        if parsed.scheme != "https" or parsed.netloc != "github.com" or len(parsed.path.strip("/").split("/")) != 2:
            raise RuntimeError("Expected public GitHub repository URL")
        groups.setdefault(url, []).append(row)
    print("PLAN", len(rows), "samples", len(groups), "repositories", "workers", args.workers, flush=True)
    if args.plan:
        return
    for name in ["metadata", "upstream-cache", "project-sources", "logs"]:
        (root / name).mkdir(parents=True, exist_ok=True)
    for name in ["project_info.csv", "fix_info.csv"]:
        path = root / "metadata" / name
        data = (artifact / "Result" / name).read_bytes()
        if path.exists() and path.read_bytes() != data:
            raise RuntimeError("Existing metadata differs; refusing overwrite")
        path.write_bytes(data)
    results = []
    def save():
        data = {"checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "expected_samples": 120, "repositories": len(groups), "verified_samples": sum(x["status"] == "verified" for x in results),
            "failed_samples": [x for x in results if x["status"] != "verified"],
            "tracked_files": sum(x.get("tracked_files", 0) for x in results),
            "git_storage": "Exact buggy commit snapshots; caches and self-contained snapshot Git objects retained inside dataset", "samples": sorted(results, key=lambda x: x["id"]),
            "metadata_sha256": {n: hashlib.sha256((root/"metadata"/n).read_bytes()).hexdigest() for n in ["project_info.csv", "fix_info.csv"]}}
        temp = root / "dataset-state.json.tmp"
        temp.write_text(json.dumps(data, indent=2))
        temp.replace(root / "dataset-state.json")
    save()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        pending = {pool.submit(fetch_group, url, members, root): members for url, members in groups.items()}
        for future in concurrent.futures.as_completed(pending):
            try:
                results.extend(future.result())
            except Exception as exc:
                results.extend({"id": int(r["id"]), "project_slug": r["project_slug"], "status": "failed", "error": str(exc)} for r in pending[future])
            save()
    if len(results) != 120 or any(x["status"] != "verified" for x in results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
