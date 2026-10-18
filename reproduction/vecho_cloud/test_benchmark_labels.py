import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from benchmark_labels import select_labels
from batch import summarize
import evaluate


class LabelSelectionTests(unittest.TestCase):
    def setUp(self):
        self.project = {"project_slug": "current", "cve_id": "CVE-1", "github_username": "org",
                        "github_repository_name": "repo", "fix_commit_ids": "abc;def"}
        self.row = {"project_slug": "old", "cve_id": "CVE-1", "github_username": "org",
                    "github_repository_name": "repo", "commit": "abc"}

    def test_verified_alias_and_no_cross_identifier_matches(self):
        rows = [dict(self.row), dict(self.row, cve_id="CVE-2"),
                dict(self.row, github_repository_name="other"),
                dict(self.row, github_username="other"), dict(self.row, commit="unlisted")]
        selected, provenance = select_labels(self.project, rows)
        self.assertEqual(selected, [self.row])
        self.assertEqual(provenance["selection"], "cve_repository_and_fix_commit")
        self.assertEqual(provenance["matched_fix_commits"], ["abc"])

    def test_exact_slug_preserves_existing_selection(self):
        exact = dict(self.row, project_slug="current")
        selected, provenance = select_labels(self.project, [self.row, exact])
        self.assertEqual(selected, [exact])
        self.assertEqual(provenance["selection"], "exact_project_slug")

    def test_no_labels_is_unscorable_not_zero_recall(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "metadata").mkdir()
            (root / "metadata/fix_info.csv").write_text("project_slug,cve_id,github_username,github_repository_name,commit\n")
            report = root / "report.json"
            report.write_text('{"vulnerabilities": []}')
            with patch.object(evaluate, "DATASET", root), patch.object(evaluate, "samples", return_value=[self.project]):
                result = evaluate.evaluate("current", root, report, root / "evaluation.json")
            self.assertEqual(result["evaluation_status"], "unavailable_no_labels")
            self.assertIsNone(result["recall"])
            self.assertEqual(json.loads((root / "evaluation.json").read_text()), result)

    def test_summary_excludes_unscorable_denominator_and_accepts_legacy(self):
        done = {"one": {"evaluation": {"recall": 1, "tp_paths": 1, "paths": 2}},
                "two": {"evaluation": {"evaluation_status": "unavailable_no_labels", "recall": None,
                                       "tp_paths": None, "paths": 10}}}
        result = summarize(done, 2)
        self.assertEqual(result["completed_samples"], 2)
        self.assertEqual(result["scored_samples"], 1)
        self.assertEqual(result["unscorable_samples"], ["two"])
        self.assertEqual(result["recall_on_completed_samples"], 1)
        self.assertEqual(result["benchmark_path_precision"], 0.5)
        self.assertTrue(result["full_dataset_complete"])
        self.assertFalse(result["full_benchmark_evaluation_complete"])


if __name__ == "__main__":
    unittest.main()
