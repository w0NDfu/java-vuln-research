import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

from common import ROOT
from judge_identity import unique_records


class JudgeIdentityTests(unittest.TestCase):
    def types(self):
        sys.path.insert(0, str(ROOT / "judge"))
        from vecho_judge.schemas.types import VulnerabilityRecord, JudgeResult, GuidanceRecord
        return VulnerabilityRecord, JudgeResult, GuidanceRecord

    def test_distinct_inputs_with_one_fingerprint_have_stable_separate_ids(self):
        Record, _, _ = self.types()
        records = [Record("same", text, text, [], "vecho_scan", metadata={"dedup_key": "same-flow"}) for text in ("first", "second")]
        before = [r.to_dict() for r in records]
        first, second = unique_records(records), unique_records(records)
        self.assertEqual([r.fingerprint for r in first], [r.fingerprint for r in second])
        self.assertEqual(len({r.fingerprint for r in first}), 2)
        self.assertEqual([r.to_dict() for r in records], before)
        self.assertEqual([r.metadata["dedup_key"] for r in first], ["same-flow", "same-flow"])

    def test_identical_repeated_records_still_have_distinct_output_files(self):
        Record, _, _ = self.types()
        record = Record("same", "same", "same", [], "vecho_scan")
        records = unique_records([record, record])
        self.assertNotEqual(records[0].fingerprint, records[1].fingerprint)

    def migration(self, failed):
        Record, Result, Guidance = self.types()
        import judge_checkpoint as jc
        from vecho_judge.outputs import RunWriter
        records = [Record("dup", "first trace", "first", [], "vecho_scan"),
                   Record("unique", "other trace", "other", [], "vecho_scan"),
                   Record("dup", "last trace", "last", [], "vecho_scan")]
        new = unique_records(records)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            old = root / "20260101"
            writer = RunWriter(root)
            writer.write_normalized_inputs(old, records)
            (old / "results").mkdir()
            (old / "results/unique.json").write_text(json.dumps(Result("unique", "true", "Existing unique evidence").to_dict()))
            (old / "results/dup.json").write_text(json.dumps(Result("dup", "true" if failed else "unknown", "Existing last saved evidence").to_dict()))
            (old / "summary.json").write_text(json.dumps({"failures": [{"fingerprint": "dup"}] if failed else [], "result_count": 2 if failed else 3, "normalized_count": 3}))
            original = {str(p.relative_to(old)): p.read_bytes() for p in old.rglob("*") if p.is_file()}
            cfg = NS(state_dir=root, project_name="test", repo_root=root, model="offline", base_url="http://127.0.0.1:9", api_key="offline", prompt_path=root / "unused", max_turns=10, memory=NS(enabled=False, url="", project="test", timeout_seconds=1))
            outputs = [NS(result=Result(new[0].fingerprint, "true", "New first input evidence"), guidance=Guidance(new[0].fingerprint, "vecho_judge", ""), transcript=[], tool_calls=[], usage={})]
            if failed:
                outputs.append(NS(result=Result(new[2].fingerprint, "unknown", "New last input evidence"), guidance=Guidance(new[2].fingerprint, "vecho_judge", ""), transcript=[], tool_calls=[], usage={}))
            with patch.object(jc, "normalize_file", return_value=records), patch.object(jc, "run_llm_judge", side_effect=outputs) as model:
                directory, normalized, results, _ = jc.judge_checkpoint(root / "unused", "vecho_scan", cfg)
            self.assertEqual(model.call_count, 2 if failed else 1)
            self.assertEqual(model.call_args_list[0].args[0].description, "first trace")
            self.assertEqual([r.vuln_status for r in results], ["true", "true", "unknown"])
            self.assertEqual(len(list((directory / "results").glob("*.json"))), 3)
            self.assertEqual({str(p.relative_to(old)): p.read_bytes() for p in old.rglob("*") if p.is_file()}, original)
            self.assertEqual([r.fingerprint for r in records], ["dup", "unique", "dup"])

    def test_legacy_overwrite_reuses_only_proven_last_input(self):
        self.migration(False)

    def test_legacy_failed_duplicate_is_not_reused_for_another_input(self):
        self.migration(True)


if __name__ == "__main__":
    unittest.main()
