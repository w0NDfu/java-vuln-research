import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run


class ScannerResumeTests(unittest.TestCase):
    def test_incomplete_stage_is_backed_up_and_resumed_without_overwriting(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stage = root / "scan"
            stage.mkdir()
            (stage / "session.json").write_text(json.dumps({"status": "failed", "config": {"timeout": 180000000000}}))
            (stage / "transcript.jsonl").write_text("original evidence\n")
            log = root / "scan.log"
            log.write_text("original process log")
            marker = root / "scanner-repair-installation.json"
            marker.write_text("{}")
            with patch.object(run, "REPRO", root), patch.dict(run.os.environ, {}, clear=True), patch.object(run, "execute") as execute:
                run.scanner_stage("scanner", "scan", [], stage, log, {}, resume=True)
            backups = list(root.glob("scan-before-resume-*"))
            self.assertEqual(len(backups), 1)
            self.assertEqual((backups[0] / "transcript.jsonl").read_text(), "original evidence\n")
            self.assertEqual((backups[0] / "stage-process.log").read_text(), "original process log")
            self.assertEqual(execute.call_args.args[0], ["scanner", "scan", "resume", "--session", str(stage), "--timeout", "180s"])

    def test_existing_complete_stage_requires_resume_and_makes_no_requests(self):
        with tempfile.TemporaryDirectory() as tmp:
            stage = Path(tmp) / "scan"
            stage.mkdir()
            (stage / "session.json").write_text('{"status":"completed"}')
            with patch.object(run, "execute") as execute:
                with self.assertRaises(RuntimeError):
                    run.scanner_stage("scanner", "scan", [], stage, stage / "log", {})
                run.scanner_stage("scanner", "scan", [], stage, stage / "log", {}, resume=True)
                execute.assert_not_called()

    def test_unpatched_incomplete_stage_is_not_retried(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "session.json").write_text('{"status":"failed"}')
            with patch.object(run, "REPRO", root), patch.object(run, "execute") as execute:
                with self.assertRaisesRegex(RuntimeError, "checkpoint repair"):
                    run.scanner_stage("scanner", "rescan", [], root, root / "log", {}, resume=True)
                execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
