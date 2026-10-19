import tempfile
import unittest
from pathlib import Path
from reproduction.vecho_experiment.io import read, write, file_hash, lock
from reproduction.vecho_experiment.state import Stages
from reproduction.vecho_experiment.snapshot import export, Redactor
from .support import config, git_repo, finding


class StateTests(unittest.TestCase):
    def test_checkpoint_reuses_success_and_rejects_changed_output_or_input(self):
        with tempfile.TemporaryDirectory() as t:
            stages = Stages(Path(t) / "stages")
            calls = []
            def action(p):
                calls.append(1); write(p / "result.json", {"ok": True}); return p / "result.json"
            result = stages.run("scan", {"input": 1}, action)
            resume = Stages(Path(t) / "stages", True)
            self.assertEqual(resume.run("scan", {"input": 1}, action), result)
            self.assertEqual(calls, [1])
            with self.assertRaises(ValueError): resume.run("scan", {"input": 2}, action)
            write(result, {"ok": False})
            with self.assertRaises(ValueError): resume.run("scan", {"input": 1}, action)

    def test_failed_attempt_kept_then_fresh_attempt(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / "stages"; s = Stages(root)
            def fail(p):
                (p / "evidence.txt").write_text("first attempt")
                raise RuntimeError("fixture failure")
            with self.assertRaises(RuntimeError): s.run("scan", {}, fail)
            def succeed(p): write(p / "result.json", {}); return p / "result.json"
            p = Stages(root, True).run("scan", {}, succeed)
            self.assertEqual(p.parent.name, "attempt-0002")
            self.assertEqual((root / "scan/attempt-0001/evidence.txt").read_text(), "first attempt")
            self.assertEqual(read(root / "scan/attempt-0001/failure.json")["status"], "failed")

    def test_os_lock_disallows_second_writer(self):
        with tempfile.TemporaryDirectory() as t:
            with lock(Path(t) / "lock"):
                with self.assertRaises(OSError):
                    with lock(Path(t) / "lock"): pass
            with lock(Path(t) / "lock"): pass


class SnapshotTests(unittest.TestCase):
    def test_snapshot_line_mapping_and_provenance_outside_target(self):
        import subprocess
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); source = root / "repo"; git_repo(source)
            data = b"// CVE-2020-12345 Acme\r\nclass A {}\r\n"
            (source / "A.java").write_bytes(data)
            subprocess.run(["git", "add", "."], cwd=source, check=True)
            subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "second"], cwd=source, check=True)
            commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=source, text=True).strip()
            policy = config(root)["anonymization"]; policy["tokens"] = ["Acme"]
            redactor = export(source, commit, root / "target", root / "private", policy, {})
            result = (root / "target/A.java").read_bytes()
            self.assertEqual(len(result), len(data)); self.assertEqual(result.count(b"\r\n"), 2)
            self.assertNotIn(b"CVE-", result); self.assertNotIn(b"Acme", result)
            self.assertFalse((root / "target/.git").exists()); self.assertFalse((root / "target/snapshot.json").exists())
            self.assertEqual(read(root / "private/snapshot.json")["commit"], commit)
            r = finding(); r["metadata"] = {"raw_cve": "CVE-2020-12345", "fix": commit}
            visible = redactor.report([r])[0]
            self.assertNotIn("raw_cve", visible["metadata"])
            self.assertEqual(visible["tainted_data_flow"][0][0]["line_number"], 3)
            r["description"] = None
            self.assertEqual(redactor.report([r])[0]["description"], "")

    def test_wrong_commit_dirty_source_and_existing_target_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            r = Path(t); source = r / "repo"; commit = git_repo(source); policy = config(r)["anonymization"]
            with self.assertRaises(ValueError): export(source, "0" * 40, r / "target", r / "private", policy, {})
            (source / "A.java").write_text("changed")
            with self.assertRaises(ValueError): export(source, commit, r / "target", r / "private", policy, {})

    def test_redactor_preserves_unicode_byte_length(self):
        data = "Acme 中文\nCVE-2020-12345\n".encode()
        result = Redactor(["Acme"]).mask(data)
        self.assertEqual(len(result), len(data)); self.assertEqual(result.count(b"\n"), 2)
