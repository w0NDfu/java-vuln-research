import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from reproduction.vecho_experiment.runner import run
from reproduction.vecho_experiment.io import write, read
from .support import config


class CampaignTests(unittest.TestCase):
    def prepare(self, root):
        cfg = config(root); cfg["samples"] = [2, 1]
        metadata = Path(cfg["dataset"]) / "metadata"; metadata.mkdir(parents=True)
        with (metadata / "project_info.csv").open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["id"]); writer.writeheader(); writer.writerows([{"id": 1}, {"id": 2}])
        (metadata / "fix_info.csv").write_text("project_slug,file,class,method\n")
        root = Path(cfg["workspace"]); root.mkdir()
        return cfg, root

    def test_failed_project_continue_isolation_but_shared_memory_stops_order(self):
        for scope, expected in [("project", ["2", "1"]), ("campaign", ["2"])]:
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as t:
                c, root = self.prepare(t); c["memory"]["scope"] = scope
                calls = []
                def project(cfg, rt, row, directory, url, token, resume):
                    calls.append(row["id"]); raise RuntimeError("offline failure")
                with patch("reproduction.vecho_experiment.runner.runtime.verify", return_value={}), patch("reproduction.vecho_experiment.runner.run_project", side_effect=project), patch.dict("os.environ", {"VECHO_TEST_KEY": "fake"}):
                    summary = run(c)
                self.assertEqual(calls, expected); self.assertFalse(summary["all_workflows_complete"])
                self.assertEqual(read(root / "experiment.json")["status"], "incomplete")

    def test_zero_budget_and_stop_prevent_requests(self):
        with tempfile.TemporaryDirectory() as t:
            c, root = self.prepare(t); c["budget"]["limit_usd"] = 0
            with patch("reproduction.vecho_experiment.runner.runtime.verify", return_value={}):
                with self.assertRaises(ValueError): run(c)
            self.assertFalse((root / "budget.sqlite").exists())

    def test_finished_project_result_tampering_rejected_on_resume(self):
        with tempfile.TemporaryDirectory() as t:
            c, root = self.prepare(t)
            def project(cfg, rt, row, directory, url, token, resume):
                write(directory / "final-report.json", {}); write(directory / "evaluation.json", {})
                return {"status": "complete", "evaluation": {"status": "unavailable_no_labels"}}
            with patch("reproduction.vecho_experiment.runner.runtime.verify", return_value={}), patch("reproduction.vecho_experiment.runner.run_project", side_effect=project), patch.dict("os.environ", {"VECHO_TEST_KEY": "fake"}):
                run(c)
                write(root / "projects/sample_0002/result.json", {"status": "complete", "evaluation": {"recall": 1}})
                with self.assertRaises(ValueError): run(c, resume=True)
