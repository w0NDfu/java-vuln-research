import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from reproduction.vecho_experiment.runner import Backend, import_static
from reproduction.vecho_experiment.state import Stages
from reproduction.vecho_experiment.io import write, read, file_hash
from .support import config, finding


class ScannerBindingTests(unittest.TestCase):
    def test_resume_copies_case_checkpoints_and_only_rebinds_transport_paths(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); c = config(root); target = root / "source"; target.mkdir()
            stage = root / "stage"; previous = stage / "attempt-0001/scan"; previous.mkdir(parents=True)
            old = {"status": "incomplete", "out_dir": str(previous), "config": {
                   "model": "offline-fixture", "repo_path": str(target), "out_dir": str(previous),
                   "base_url": "http://127.0.0.1:1111/scan/v1/chat/completions", "memory_mcp": {"url": "old"},
                   "max_context_steps_per_case": 8, "context_concurrency": 5}}
            write(previous / "session.json", old)
            write(previous / "contextaudit/cases/case-000001/case.json", {"status": "confirmed", "source_sha256": "fixture"})
            before = file_hash(previous / "session.json")
            second = stage / "attempt-0002"; second.mkdir()
            backend = Backend(c, {"artifact": t, "scanner_binary": "fixture-scanner"}, "http://127.0.0.1:2222", "fake", "http://127.0.0.1:3333/invoke", "sample_0001", target)
            seen = []
            def execute(argv, cwd, output, env):
                seen.append(argv)
                self.assertEqual(argv[1:3], ["scan", "resume"])
                new = read(second / "scan/session.json")
                self.assertEqual(new["config"]["context_concurrency"], 5)
                self.assertEqual(new["config"]["base_url"], "http://127.0.0.1:2222/scan/v1/chat/completions")
                self.assertEqual(new["config"]["memory_mcp"]["url"], "http://127.0.0.1:3333/invoke")
                self.assertEqual(new["config"]["out_dir"], str(second / "scan"))
                self.assertEqual(read(second / "scan/contextaudit/cases/case-000001/case.json")["status"], "confirmed")
                new["status"] = "completed"; write(second / "scan/session.json", new)
                write(second / "scan/contextaudit/results.json", {"total": 1, "by_status": {"confirmed": 1}, "results": [{"status": "confirmed"}]})
                write(second / "scan/vecho/report.json", {"vulnerabilities": [finding()]})
            with patch("reproduction.vecho_experiment.runner.command", side_effect=execute):
                result = backend.scan("scan", second, [], [])
            self.assertEqual(len(read(result)["vulnerabilities"]), 1)
            self.assertEqual(file_hash(previous / "session.json"), before)

    def test_missing_required_static_report_fails_before_backend(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); c = config(root)
            c["static_sources"] = [{"tool": "CodeQL", "version": "fixture", "queries": "fixture", "format": "sarif", "path": "missing.json"}]
            with self.assertRaises(FileNotFoundError): import_static(c, {"id": "1", "buggy_commit_id": "fixture"}, Stages(root / "stages"), root)
            self.assertEqual(read(root / "stages/static-00/receipt.json")["status"], "failed")

    def test_failed_sarif_producer_cannot_be_empty_success(self):
        from reproduction.vecho_experiment.inputs import sarif
        with self.assertRaises(ValueError): sarif({"version": "2.1.0", "runs": [{"invocations": [{"executionSuccessful": False}], "results": []}]}, "CodeQL")
