import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

from common import ROOT


class JudgeCheckpointTest(unittest.TestCase):
    def test_only_missing_verdict_is_requested(self):
        sys.path.insert(0, str(ROOT / "judge"))
        import judge_checkpoint as jc
        from vecho_judge.schemas.types import VulnerabilityRecord, JudgeResult, GuidanceRecord
        records = [VulnerabilityRecord(n, n, n, [], "vecho_scan") for n in ("saved", "missing")]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = root / "old"
            (old / "inputs").mkdir(parents=True)
            (old / "results").mkdir()
            (old / "inputs/normalized.json").write_text(json.dumps([r.to_dict() for r in records]))
            (old / "results/saved.json").write_text(json.dumps(JudgeResult("saved", "true", "Earlier evidence").to_dict()))
            cfg = NS(state_dir=root, project_name="test", repo_root=root, model="offline", base_url="http://127.0.0.1:9", api_key="offline", prompt_path=root / "unused", max_turns=10, memory=NS(enabled=False, url="", project="test", timeout_seconds=1))
            result = JudgeResult("missing", "unknown", "Insufficient evidence")
            output = NS(result=result, guidance=GuidanceRecord("missing", "vecho_judge", ""), transcript=[], tool_calls=[], usage={})
            with patch.object(jc, "normalize_file", return_value=records), patch.object(jc, "run_llm_judge", return_value=output) as model:
                directory, normalized, results, guidance = jc.judge_checkpoint(root / "unused", "vecho_scan", cfg)
            self.assertEqual(model.call_count, 1)
            self.assertEqual(model.call_args.args[0].fingerprint, "missing")
            self.assertEqual([r.vuln_status for r in results], ["true", "unknown"])
            self.assertEqual(json.loads((directory / "checkpoint.json").read_text())["reused_fingerprints"], ["saved"])
            self.assertTrue((old / "results/saved.json").exists())


if __name__ == "__main__":
    unittest.main()
