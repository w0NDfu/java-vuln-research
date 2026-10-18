from pathlib import Path
import tempfile
import unittest

from audit_completed import audit_judge, audit_stage
from common import write_json


class AuditGatesTests(unittest.TestCase):
    def judge_fixture(self, root):
        directory = root / "judge/20260101"
        write_json(directory / "inputs/normalized.json", [{"fingerprint": "a"}, {"fingerprint": "b"}])
        write_json(directory / "results/a.json", {"fingerprint": "a", "vuln_status": "true"})
        write_json(directory / "results/b.json", {"fingerprint": "b", "vuln_status": "unknown"})
        write_json(directory / "summary.json", {"normalized_count": 2, "result_count": 2, "failures": [],
                                               "status_counts": {"true": 1, "unknown": 1}, "usage": {}, "guidance_count": 2})
        return directory

    def stage_fixture(self, root, planned=2, completion=True, duplicate=False):
        import json
        directory = root / "scan"
        write_json(directory / "session.json", {"status": "completed", "session_id": "test"})
        events = [{"type": "contextaudit_started", "data": {"case_count": planned}},
                  {"type": "case_completed", "data": {"case_id": "a", "status": "blocked"}},
                  {"type": "case_completed", "data": {"case_id": "a" if duplicate else "b", "status": "dead_end"}}]
        if completion:
            events.append({"type": "scan_completed"})
        (directory / "events.ndjson").write_text("\n".join(json.dumps(e) for e in events))
        write_json(directory / "usage.json", {"total": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

    def test_unknown_verdict_never_becomes_a_final_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.judge_fixture(root)
            records, detail = audit_judge(root, "judge")
            self.assertEqual(records, [{"fingerprint": "a"}])
            self.assertEqual(detail["status_counts"]["unknown"], 1)

    def test_memory_failure_cannot_pass_complete_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = self.judge_fixture(root)
            write_json(directory / "results/a.json", {"fingerprint": "a", "vuln_status": "true", "judge_metadata": {"memory_errors": ["failed"]}})
            with self.assertRaisesRegex(ValueError, "memory errors"):
                audit_judge(root, "judge")

    def test_wrong_fingerprint_cannot_pass_even_when_counts_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            directory = self.judge_fixture(root)
            write_json(directory / "results/b.json", {"fingerprint": "wrong", "vuln_status": "unknown"})
            with self.assertRaisesRegex(ValueError, "fingerprints differ"):
                audit_judge(root, "judge")

    def test_unresolved_cases_are_counted_without_becoming_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.stage_fixture(root)
            detail = audit_stage(root, "scan")
            self.assertEqual(detail["case_statuses"], {"blocked": 1, "dead_end": 1})
            self.assertEqual(detail["closed_cases"], 2)

    def test_incomplete_or_duplicate_case_closures_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.stage_fixture(root, planned=3)
            with self.assertRaisesRegex(ValueError, "case count"):
                audit_stage(root, "scan")
            self.stage_fixture(root, duplicate=True)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                audit_stage(root, "scan")

    def test_completed_manifest_requires_actual_completion_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.stage_fixture(root, completion=False)
            with self.assertRaisesRegex(ValueError, "completion event"):
                audit_stage(root, "scan")


if __name__ == "__main__":
    unittest.main()
