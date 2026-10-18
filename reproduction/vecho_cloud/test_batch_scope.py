import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import batch


class BatchScopeTests(unittest.TestCase):
    def test_ten_sample_scope_excludes_other_completed_results(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for number in range(1, 13):
                run = root / "runs" / "old" / f"sample_{number:04d}"
                run.mkdir(parents=True)
                (run / "run.json").write_text(json.dumps({"sample": run.name, "status": "complete"}))
                (run / "evaluation.json").write_text(json.dumps({"recall": 0, "paths": 0, "tp_paths": 0}))
            with patch.object(batch, "REPRO", root), patch.object(batch, "samples", return_value=[{"id": str(i)} for i in range(12, 0, -1)]), patch.object(batch.subprocess, "run") as execute:
                self.assertEqual(batch.main(["--limit", "10"]), 0)
                execute.assert_not_called()
            summary = json.loads((root / "batch-summary.json").read_text())
            state = json.loads((root / "batch-state.json").read_text())
            self.assertEqual(summary["expected_samples"], 10)
            self.assertEqual(summary["completed_samples"], 10)
            self.assertEqual(state["sample_ids"], list(range(1, 11)))
            self.assertEqual(state["status"], "complete")

    def test_invalid_scope_rejected_before_running_models(self):
        for limit in (0, 121):
            with self.subTest(limit=limit), patch.object(batch, "samples", return_value=[{"id": str(i)} for i in range(1, 121)]), patch.object(batch.subprocess, "run") as execute, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as result:
                    batch.main(["--limit", str(limit)])
                self.assertEqual(result.exception.code, 2)
                execute.assert_not_called()


if __name__ == "__main__":
    unittest.main()
