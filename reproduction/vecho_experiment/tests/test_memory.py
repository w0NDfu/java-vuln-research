import tempfile
import unittest
from pathlib import Path
from reproduction.vecho_experiment.memory import Knowledge
from reproduction.vecho_experiment.io import read, digest
from reproduction.vecho_experiment.snapshot import Redactor


class Engine:
    def __init__(self): self.updates = []; self.success = True
    def update_knowledge_base(self, project): self.updates.append(project); return self.success
    def query(self, query, project): return {"success": self.success, "common_results": [], "project_results": []}


class MemoryTests(unittest.TestCase):
    def test_manual_and_frozen_saves_not_automatically_indexed(self):
        with tempfile.TemporaryDirectory() as t:
            for policy in ["manual", "frozen"]:
                engine = Engine(); k = Knowledge(Path(t) / policy, policy, engine, Redactor())
                text = k.invoke("save_knowledge", {"type": "general", "title": "fixture", "content": "CVE-2020-12345"}, "sample_0001")
                self.assertIn("not in retrieval", text); self.assertEqual(engine.updates, [])
                files = list((k.root / "kb_tmp/common").glob("**/*.md")); self.assertEqual(len(files), 1)
                self.assertNotIn("CVE-", files[0].read_text())
                self.assertFalse((k.root / "kb").exists())

    def test_auto_promotes_and_records_hash_after_index_success(self):
        with tempfile.TemporaryDirectory() as t:
            engine = Engine(); k = Knowledge(t, "auto_index", engine)
            k.invoke("save_knowledge", {"type": "sanitizer", "title": "fixture", "content": "generic rule"}, "sample_0001")
            self.assertEqual(engine.updates, ["sample_0001"])
            self.assertEqual(len(list((Path(t) / "admissions").glob("*.json"))), 1)
            self.assertEqual(len(list((Path(t) / "kb/sample_0001").glob("**/*.md"))), 1)

    def test_index_failure_no_success_receipt(self):
        with tempfile.TemporaryDirectory() as t:
            engine = Engine(); engine.success = False; k = Knowledge(t, "auto_index", engine)
            with self.assertRaises(RuntimeError): k.invoke("save_knowledge", {"title": "fixture", "content": "rule"}, "sample_0001")
            self.assertEqual(list((Path(t) / "admissions").glob("*.json")), [])

    def test_cross_project_and_path_traversal_reads_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            k = Knowledge(t, "manual", Engine())
            for path in ["sample_0002/file.md", "../outside", "sample_0001/../../outside"]:
                with self.subTest(path=path), self.assertRaises(ValueError): k.invoke("get_document", {"file_path": path}, "sample_0001")
            with self.assertRaises(ValueError): k.invoke("save_knowledge", {}, "../../escape")

    def test_query_failure_and_verdict_validation(self):
        with tempfile.TemporaryDirectory() as t:
            engine = Engine(); engine.success = False; k = Knowledge(t, "manual", engine)
            with self.assertRaises(RuntimeError): k.invoke("query_knowledge", {"query": "fixture"}, "sample_0001")
            with self.assertRaises(ValueError): k.invoke("save_result", {"vuln_status": "invented"}, "sample_0001")
            k.invoke("save_result", {"vuln_status": "unknown", "fingerprint": "x"}, "sample_0001")
            self.assertEqual(len(list((Path(t) / "analysis_outputs/sample_0001").glob("*.json"))), 1)
