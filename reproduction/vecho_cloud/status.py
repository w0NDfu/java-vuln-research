"""Credential-safe deployment status. No model calls."""
import json
import os
import re
import subprocess
from pathlib import Path

from common import ROOT, REPRO, DATASET, load_env, write_json

load_env()
keys = ["OPENLUX_API_KEY"] if not os.environ.get("OPENLUX_API_KEY", "").strip() else []
checks = (REPRO / "logs/final-checks.log").read_text() if (REPRO / "logs/final-checks.log").exists() else ""
python_checks = (REPRO / "logs/python-checks.log").read_text() if (REPRO / "logs/python-checks.log").exists() else checks
test_count = re.search(r"Ran (\d+) tests?", python_checks)
preflight_path = REPRO / "preflight.json"
preflight = json.loads(preflight_path.read_text()) if preflight_path.exists() else None
preflight_ok = bool(preflight and len(preflight.get("checks", [])) == 2 and all(x.get("ok") for x in preflight["checks"]))
state = "waiting_for_credentials" if keys else ("ready_for_single_sample" if preflight_ok else "live_preflight_failed" if preflight else "ready_for_live_preflight")
run_paths = sorted((REPRO / "runs").glob("*/sample_*/run.json"))
latest_run = json.loads(run_paths[-1].read_text()) if run_paths else None
completed_samples = set()
for path in run_paths:
    run = json.loads(path.read_text())
    if run.get("status") == "complete" and (path.parent / "evaluation.json").exists():
        completed_samples.add(run["sample"])
if not keys and latest_run:
    state = {"running": "live_run_in_progress", "failed": "live_run_failed", "complete": "single_sample_completed"}.get(latest_run.get("status"), state)
dataset = json.loads((DATASET / "verification.json").read_text())
patch = subprocess.check_output(["git", "diff", "--", "judge/vecho_judge/app/config.py", "judge/vecho_judge/runtime/llm_loop.py", "memory/services/mcp_service.py"], cwd=ROOT)
(REPRO / "upstream.patch").write_bytes(patch)
report = {
    "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
    "dataset_verified_samples": dataset["verified_samples"],
    "scanner_binary_exists": (REPRO / "bin/vecho-scan").is_file(),
    "go_checks_passed": "GO TESTS PASSED; SCANNER BUILT" in checks,
    "offline_checks_passed": bool(test_count and "\nOK\n" in python_checks),
    "offline_check_count": int(test_count.group(1)) if test_count else 0,
    "runtime_lock_exists": (REPRO / "requirements.lock.txt").exists(),
    "missing_credentials": keys,
    "live_reproduction_completed": len(completed_samples) == dataset["verified_samples"],
    "completed_live_samples": len(completed_samples),
    "latest_run": str(run_paths[-1].parent) if run_paths else None,
    "state": state,
    "live_preflight_passed": preflight_ok,
    "preflight_file": str(preflight_path) if preflight else None,
    "credentials_file": str(ROOT / ".env"),
    "scan_judge_model": os.environ.get("VECHO_SCAN_MODEL"),
    "api_base": os.environ.get("VECHO_JUDGE_BASE_URL"),
    "memory_models": [os.environ.get("MEMORY_EMBEDDING_MODEL"), os.environ.get("MEMORY_LLM_MODEL")],
    "next_commands": [
        "/workspace/venvs/vecho/bin/python /workspace/vEcho/repro/services.py",
        "/workspace/venvs/vecho/bin/python /workspace/vEcho/repro/run.py --sample-id 2",
    ],
}
write_json(REPRO / "deployment-status.json", report)
print(json.dumps(report, indent=2))
