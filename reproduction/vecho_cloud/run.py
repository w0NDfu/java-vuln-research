"""Run scan -> judge -> one rescan -> judge -> benchmark scoring."""
import argparse
import datetime
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

from common import ROOT, REPRO, DATASET, load_env, required, samples, write_json


def deduplicate(records):
    unique = {}
    for item in records:
        key = item.get("metadata", {}).get("dedup_key") or item["fingerprint"]
        unique.setdefault(key, item)
    return list(unique.values())


def prepare(row, name):
    source = DATASET / "project-sources" / row["project_slug"]
    actual = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
    if actual != row["buggy_commit_id"]:
        raise RuntimeError("Source commit mismatch")
    target = REPRO / "targets" / name
    marker = REPRO / "targets" / (name + "-prepared.json")
    if marker.exists():
        if json.loads(marker.read_text())["commit"] != actual:
            raise RuntimeError("Prepared target commit mismatch")
        return target
    if target.exists():
        raise RuntimeError("Incomplete target exists; inspect it before preparing again")
    target.mkdir()
    archive = subprocess.Popen(["git", "archive", "HEAD"], cwd=source, stdout=subprocess.PIPE)
    with tarfile.open(fileobj=archive.stdout, mode="r|") as stream:
        for member in stream:
            path = target / member.name
            if not path.resolve().is_relative_to(target.resolve()):
                raise RuntimeError("Unsafe archive member")
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                path.parent.mkdir(parents=True, exist_ok=True)
                data = stream.extractfile(member).read()
                if b"\x00" not in data[:8192]:
                    data = re.sub(rb"CVE-\d{4}-\d{4,}", b"VULN-REDACTED", data, flags=re.I)
                path.write_bytes(data)
            # Git links are not followed outside the staged source snapshot.
    if archive.wait() != 0:
        raise RuntimeError("git archive failed")
    # Keep provenance outside model-visible source directory.
    write_json(REPRO / "targets" / (name + "-provenance.json"), {"commit": actual, "sample": row["project_slug"], "anonymization": "neutral directory; no Git history; CVE strings masked; original project/dependency names remain", "full_paper_anonymization": False})
    # Even the commit marker is outside the model-visible source tree.
    write_json(marker, {"commit": actual})
    return target


def execute(command, cwd, logfile, env):
    with logfile.open("w") as output:
        subprocess.run(command, cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT, check=True)


def score_report(slug, target, report, output):
    # Native parser failures must not kill the supervising runner and leave a
    # stale "running" manifest. This subprocess performs no model requests.
    with output.with_suffix(".log").open("w") as log:
        subprocess.run([sys.executable, str(REPRO / "evaluate.py"),
                        "--slug", slug, "--repo", str(target), "--report", str(report),
                        "--out", str(output)], stdout=log, stderr=subprocess.STDOUT, check=True)


def run_one(row, root, resume=False):
    load_env()
    key = required("SILICONFLOW_API_KEY")
    required("MEMORY_API_KEY")
    name = "sample_" + str(int(row["id"])).zfill(4)
    target = prepare(row, name)
    root.mkdir(parents=True, exist_ok=resume)
    if resume:
        old = json.loads((root / "run.json").read_text())
        assert old["sample"] == name and old["initial_source"] == row["buggy_commit_id"]
        assert old["scan_model"] == os.environ.get("VECHO_SCAN_MODEL")
        write_json(root / ("run-before-resume-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".json"), old)
    env = dict(os.environ, PYTHONPATH=str(ROOT / "judge"), VECHO_SCAN_API_KEY=key, VECHO_JUDGE_API_KEY=key, VECHO_MEMORY_PROJECT=name)
    from urllib.request import Request, urlopen
    probe = Request("http://127.0.0.1:5011/invoke", data=json.dumps({"tool":"query_knowledge","arguments":{"query":"knowledge-base availability"}}).encode(), headers={"Content-Type":"application/json", "project":name})
    with urlopen(probe, timeout=120) as response:
        result = json.load(response)
        if not result.get("ok"):
            raise RuntimeError("Memory adapter unavailable")
    config = {"source_revision": "68da10388878f8626f0a1d124e500c979ac1e82d", "scan_model": env.get("VECHO_SCAN_MODEL"), "judge_model": env.get("VECHO_JUDGE_MODEL"), "context_concurrency": int(env.get("VECHO_CONTEXT_CONCURRENCY", "1")), "rescan_rounds": 1, "initial_source": row["buggy_commit_id"], "sample": name, "status": "running"}
    config["judge_adapter"] = "explicit final-turn save_result within original 10-turn budget; checkpoint reuse; distinct input IDs v2"
    if resume:
        # Reused scanner sessions retain their original execution setting even
        # when the environment has been changed for future samples.
        config["context_concurrency"] = int(old.get("context_concurrency", config["context_concurrency"]))
    write_json(root / "run.json", config)
    scanner = str(REPRO / "bin/vecho-scan")
    flags = ["--repo", str(target), "--language", "java", "--project-id", name, "--project-name", name, "--memory-enabled", "--memory-url", env["VECHO_MEMORY_URL"], "--memory-project", name, "--memory-timeout-seconds", "120", "--context-concurrency", str(config["context_concurrency"])]
    try:
        scan_session = root / "scan/session.json"
        if resume and scan_session.exists():
            assert json.loads(scan_session.read_text())["status"] == "completed", "Incomplete scan must be resumed through scanner session API"
        else:
            execute([scanner, "scan", "run", *flags, "--out", str(root / "scan")], ROOT, root / "scan.log", env)
        report = root / "scan/vecho/report.json"
        report_payload = json.loads(report.read_text())
        if not report_payload.get("vulnerabilities"):
            score_report(row["project_slug"], target, report, root / "evaluation.json")
            config.update(status="complete", notes="No confirmed scan candidates; no judge/rescan calls were applicable")
        else:
            # Run service APIs directly: their output paths are returned unambiguously.
            sys.path.insert(0, str(ROOT / "judge"))
            from vecho_judge.app.config import default_config
            from judge_checkpoint import judge_checkpoint as judge_file
            cfg = default_config(ROOT)
            cfg.repo_root, cfg.state_dir, cfg.project_name = target, root / "judge", name
            cfg.api_key = key
            cfg.memory.enabled, cfg.memory.url, cfg.memory.project, cfg.memory.timeout_seconds = True, env["VECHO_MEMORY_URL"], name, 120
            judged, normalized, results, guidance = judge_file(report, "vecho_scan", cfg)
            summary = json.loads((judged / "summary.json").read_text())
            if summary["failures"] or any(item.judge_metadata.get("memory_errors") for item in results):
                raise RuntimeError("Judge failed or memory errors occurred; do not report this run as complete")
            confirmed = {item.fingerprint for item in results if item.vuln_status == "true"}
            final_records = [item.to_dict() for item in normalized if item.fingerprint in confirmed]
            if guidance:
                rescan_session = root / "rescan/session.json"
                if resume and rescan_session.exists():
                    assert json.loads(rescan_session.read_text())["status"] == "completed", "Incomplete rescan requires scanner session resume; refusing to overwrite"
                else:
                    execute([scanner, "rescan", "run", *flags, "--out", str(root / "rescan"), "--bundle", str(judged / "rescan_bundle.json"), "--guidance", str(judged / "guidance/guidance.json")], ROOT, root / "rescan.log", env)
                new_report = root / "rescan/vecho/report.json"
                if json.loads(new_report.read_text()).get("vulnerabilities"):
                    cfg.state_dir = root / "rescan-judge"
                    second, n2, r2, _ = judge_file(new_report, "vecho_scan", cfg)
                    if json.loads((second / "summary.json").read_text())["failures"] or any(x.judge_metadata.get("memory_errors") for x in r2):
                        raise RuntimeError("Rescan judge failed or memory errors occurred")
                    accepted = {x.fingerprint for x in r2 if x.vuln_status == "true"}
                    final_records.extend(x.to_dict() for x in n2 if x.fingerprint in accepted)
            unique = deduplicate(final_records)
            write_json(root / "final-report.json", {"vulnerabilities": unique})
            score_report(row["project_slug"], target, root / "final-report.json", root / "evaluation.json")
            config.update(status="complete", confirmed_alerts=len(unique))
    except Exception as exc:
        config.update(status="failed", error=type(exc).__name__)
        raise
    finally:
        write_json(root / "run.json", config)
    return config


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--sample-id", type=int, default=2)
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--resume-run", type=Path)
    args = parser.parse_args()
    chosen = samples() if args.all else [row for row in samples() if int(row["id"]) == args.sample_id]
    if not chosen:
        raise SystemExit("Unknown sample id")
    load_env()
    # Fail before preparing a source snapshot or making requests if credentials lack.
    required("SILICONFLOW_API_KEY")
    required("MEMORY_API_KEY")
    batch = REPRO / "runs" / datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for row in chosen:
        if args.resume_run:
            assert len(chosen) == 1 and args.resume_run.resolve().is_relative_to((REPRO / "runs").resolve())
        root = args.resume_run if args.resume_run else batch / ("sample_" + str(int(row["id"])).zfill(4))
        print(json.dumps(run_one(row, root, resume=bool(args.resume_run))), flush=True)
