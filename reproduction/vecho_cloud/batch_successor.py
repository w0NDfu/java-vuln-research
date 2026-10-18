"""Adopt the fixed supervisor after an existing supervisor exits.

Never interrupt a live process or retry an incomplete/failed model workflow.
The new batch supervisor's own flock remains the final duplicate-run guard.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import sys
import time

from batch import collect
from common import REPRO, samples, write_json


def process(pid):
    try:
        root = Path("/proc") / str(pid)
        fields = (root / "stat").read_text().rsplit(")", 1)[1].split()
        if fields[0] == "Z":
            return None
        return {"start_ticks": fields[19],
                "argv": (root / "cmdline").read_bytes().split(b"\x00")[:-1]}
    except (FileNotFoundError, ProcessLookupError):
        return None


def live_work():
    commands = {str(REPRO / "run.py").encode(), str(REPRO / "bin/vecho-scan").encode(),
                str(REPRO / "batch.py").encode()}
    return [int(path.name) for path in Path("/proc").iterdir() if path.name.isdigit()
            for info in [process(int(path.name))] if info and commands.intersection(info["argv"])]


def decision(state, done, total, live):
    if len(done) == total:
        return False, "all_workflows_complete"
    if live:
        return False, "another_work_process_is_live"
    if state.get("current_sample") not in done:
        return False, "current_workflow_not_verified_complete_manual_recovery_required"
    return True, "current_workflow_complete_safe_to_start_fixed_supervisor"


def main(pid):
    import fcntl
    lock = (REPRO / "batch-successor.lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    initial = process(pid)
    if not initial or str(REPRO / "batch.py").encode() not in initial["argv"]:
        raise RuntimeError("Expected live batch supervisor was not found; no work started")
    start = initial["start_ticks"]
    state = {"watcher_pid": os.getpid(), "watched_batch_pid": pid,
             "watched_start_ticks": start, "status": "waiting_for_existing_supervisor",
             "note": "No signals sent; failed/incomplete scans will not be retried"}
    while True:
        info = process(pid)
        if not info or info["start_ticks"] != start:
            break
        state["checked_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write_json(REPRO / "batch-successor-state.json", state)
        time.sleep(30)
    old = json.loads((REPRO / "batch-state.json").read_text())
    restart, reason = decision(old, collect(), len(samples()), live_work())
    state.update(status="starting_fixed_supervisor" if restart else "finished_without_restart", reason=reason)
    write_json(REPRO / "batch-successor-state.json", state)
    print(json.dumps(state), flush=True)
    if restart:
        # Python file descriptors are close-on-exec. The new supervisor acquires
        # its original batch.lock before it can start any model workflow.
        os.execv(sys.executable, [sys.executable, "-u", str(REPRO / "batch.py")])
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--watch-pid", type=int, required=True)
    raise SystemExit(main(parser.parse_args().watch_pid))
