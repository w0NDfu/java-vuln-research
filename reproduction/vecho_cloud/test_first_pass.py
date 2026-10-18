import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import batch


class FirstPassTests(unittest.TestCase):
    def test_preserves_prior_attempt_and_continues_after_new_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "logs").mkdir()
            existing = root / "runs/prior/sample_0002/run.json"
            existing.parent.mkdir(parents=True)
            existing.write_text('{"status":"running"}')
            item = {"evaluation": {"recall": 0, "tp_paths": 0, "paths": 0}}
            before = {"sample_0001": item}
            after = {**before, "sample_0004": item}
            with patch.object(batch, "REPRO", root), patch.object(batch, "samples", return_value=[{"id": str(i)} for i in range(1, 5)]), patch.object(batch, "collect", side_effect=[before, before, after]), patch.object(batch.subprocess, "run", side_effect=[SimpleNamespace(returncode=1), SimpleNamespace(returncode=0)]) as run:
                self.assertEqual(batch.main(), 0)
            self.assertEqual([c.args[0][-1] for c in run.call_args_list], ["3", "4"])
            self.assertEqual(existing.read_text(), '{"status":"running"}')
            state = json.loads((root / "batch-state.json").read_text())
            self.assertEqual(state["failed_samples"], ["sample_0002", "sample_0003"])
            self.assertEqual((state["status"], state["completed_samples"], state["attempted_samples"]), ("first_pass_complete", 2, 4))
            self.assertTrue(state["needs_repair"])


if __name__ == "__main__":
    unittest.main()
