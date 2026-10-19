import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from reproduction.vecho_experiment.runner import feedback, run_project
from reproduction.vecho_experiment.snapshot import Redactor
from reproduction.vecho_experiment.state import Stages
from reproduction.vecho_experiment.io import write, read, digest
from reproduction.vecho_experiment import evaluation, config as config_module
from .support import config, finding, git_repo


class ScriptedBackend:
    """Offline protocol fixture; never described as detection quality evidence."""
    def __init__(self, *args):
        self.judged = []; self.scans = []
    def judge(self, record, attempt):
        self.judged.append(record)
        line = record["tainted_data_flow"][0][0]["line_number"]
        status = "true" if line == 3 else "false"
        write(attempt / "result.json", {"result": {"fingerprint": record["fingerprint"], "vuln_status": status, "analysis": "offline fixture"},
              "guidance": {"fingerprint": record["fingerprint"], "content": "Inspect sibling flows", "source": "fixture"}})
        return attempt / "result.json"
    def scan(self, stage, attempt, guidance, known):
        self.scans.append((stage, guidance, known))
        rows = [finding(6)] if stage == "scan" else [finding(3)]
        write(attempt / "canonical.json", {"vulnerabilities": rows})
        return attempt / "canonical.json"


class FeedbackTests(unittest.TestCase):
    def test_false_guidance_rescan_detects_new_candidate_then_stops_on_repeat(self):
        with tempfile.TemporaryDirectory() as t:
            c = config(t); b = ScriptedBackend(); root = Path(t) / "stages"
            result = feedback(c, Stages(root), [finding(6)], b, Redactor())
            self.assertEqual(len(b.judged), 2)
            self.assertEqual(result["stop_reason"], "no_new_candidates")
            self.assertEqual(len(result["vulnerabilities"]), 1)
            self.assertEqual(b.scans[0][1][0]["content"], "Inspect sibling flows")
            again = ScriptedBackend()
            restored = feedback(c, Stages(root, True), [finding(6)], again, Redactor())
            self.assertEqual(restored, result); self.assertEqual(again.judged, []); self.assertEqual(again.scans, [])

    def test_unknown_never_becomes_false_or_actionable_guidance(self):
        with tempfile.TemporaryDirectory() as t:
            c = config(t); b = ScriptedBackend()
            def judge(r, attempt):
                write(attempt / "result.json", {"result": {"fingerprint": r["fingerprint"], "vuln_status": "unknown"}, "guidance": {"content": "not evidence"}})
                return attempt / "result.json"
            b.judge = judge
            result = feedback(c, Stages(Path(t) / "stages"), [finding()], b, Redactor())
            self.assertEqual(result["unknown_verdicts"], 1)
            self.assertEqual(result["vulnerabilities"], [])
            self.assertEqual(result["stop_reason"], "no_actionable_guidance")

    def test_candidate_cap_fails_not_truncates(self):
        with tempfile.TemporaryDirectory() as t:
            c = config(t); c["loop"]["max_new_candidates"] = 1
            b = ScriptedBackend()
            with self.assertRaises(RuntimeError): feedback(c, Stages(Path(t) / "stages"), [finding(3), finding(6)], b, Redactor())
            self.assertEqual(b.judged, [])

    def test_zero_rescans_and_no_api_resume_after_failed_judge(self):
        with tempfile.TemporaryDirectory() as t:
            c = config(t); c["loop"]["max_rescans"] = 0
            b = ScriptedBackend()
            result = feedback(c, Stages(Path(t) / "stages"), [finding(3)], b, Redactor())
            self.assertEqual(result["stop_reason"], "max_rescans"); self.assertEqual(b.scans, [])


class EvaluationTests(unittest.TestCase):
    def test_paired_comparison_reports_gain_and_rejects_different_source(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            a = {"outcomes": [{"id": 1, "status": "complete", "sample_identity": {"commit": "same"}, "evaluation": {"status": "available", "recall": 0, "precision": 0, "f1": 0}}]}
            b = {"outcomes": [{"id": 1, "status": "complete", "sample_identity": {"commit": "same"}, "evaluation": {"status": "available", "recall": 1, "precision": .5, "f1": 2/3}}]}
            write(root / "a.json", a); write(root / "b.json", b)
            result = evaluation.compare(root / "a.json", root / "b.json")
            self.assertEqual(result["improvements"], [1]); self.assertEqual(result["net_detected_change"], 1)
            self.assertAlmostEqual(result["right_paired_means"]["f1"], 2/3)
            b["outcomes"][0]["sample_identity"]["commit"] = "different"; write(root / "b.json", b)
            with self.assertRaises(ValueError): evaluation.compare(root / "a.json", root / "b.json")

    def test_methods_match_and_same_file_miss(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); git_repo(root / "source")
            fixes = [{"file": "A.java", "class": "A", "method": "vulnerable"}]
            result = evaluation.evaluate(root / "source", [finding(3), finding(6)], fixes)
            self.assertEqual((result["recall"], result["tp_paths"], result["paths"]), (1, 1, 2))
            self.assertAlmostEqual(result["f1"], 2 / 3)

    def test_missing_labels_parse_errors_and_outside_source_are_unscorable(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); git_repo(root / "source")
            fixes = [{"file": "A.java", "class": "A", "method": "vulnerable"}]
            self.assertIsNone(evaluation.evaluate(root / "source", [], [])["recall"])
            r = finding(); r["tainted_data_flow"][0][0]["file_path"] = "../escape.java"
            self.assertIsNone(evaluation.evaluate(root / "source", [r], fixes)["recall"])
            (root / "source/A.java").write_text("class A { void v( invalid")
            self.assertIsNone(evaluation.evaluate(root / "source", [finding()], fixes)["recall"])

    def test_failed_unknown_and_unrun_not_zero_detection_denominator(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            write(root / "projects/sample_0001/result.json", {"status": "complete", "evaluation": {"status": "available", "recall": 1, "precision": .5, "f1": 2/3, "paths": 2}})
            write(root / "projects/sample_0002/result.json", {"status": "failed"})
            summary = evaluation.summarize(root, [1, 2, 3])
            self.assertEqual(summary["scorable"], 1); self.assertEqual(summary["failed_or_unrun"], [2, 3])
            self.assertEqual(summary["detection_rate_completed_scorable"], 1)
            self.assertFalse(summary["paper_comparable_denominator"])


class ProjectIntegrationTests(unittest.TestCase):
    def test_git_snapshot_static_merge_feedback_score_and_checkpoint_without_network(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); c = config(root)
            slug = "fixture__fixture_CVE-2020-12345_v1"
            source = root / "dataset/project-sources" / slug; commit = git_repo(source)
            row = {"id": "1", "project_slug": slug, "buggy_commit_id": commit, "cve_id": "CVE-2020-12345",
                   "github_username": "fixture", "github_repository_name": "fixture", "fix_commit_ids": "deadbeef"}
            metadata = root / "dataset/metadata"; metadata.mkdir()
            with (metadata / "fix_info.csv").open("w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["project_slug", "file", "class", "method"]); writer.writeheader()
                writer.writerow({"project_slug": slug, "file": "A.java", "class": "A", "method": "vulnerable"})
            # This static finding and ScanAgent's identical path must merge.
            write(root / "static.json", {"vulnerabilities": [finding(6)]})
            c["static_sources"] = [{"tool": "fixture", "version": "1", "queries": "fixture-only", "format": "canonical", "path": "static.json"}]
            project_root = root / "work/projects/sample_0001"; project_root.mkdir(parents=True)
            trace = []
            class Backend(ScriptedBackend):
                def judge(self, record, attempt):
                    self_outer.assertNotIn("CVE-2020", str(record)); trace.append(record)
                    return super().judge(record, attempt)
            self_outer = self
            rt = {"artifact": str(root / "artifact")}
            result = run_project(c, rt, row, project_root, "http://127.0.0.1:1", "offline", False, Backend)
            self.assertEqual(result["status"], "complete"); self.assertEqual(result["evaluation"]["recall"], 1)
            self.assertEqual(len(trace), 2)
            trace.clear()
            again = run_project(c, rt, row, project_root, "http://127.0.0.1:1", "offline", True, Backend)
            self.assertEqual(again["evaluation"], result["evaluation"]); self.assertEqual(trace, [])

    def test_configuration_requires_named_ablation_and_explicit_sampling(self):
        with tempfile.TemporaryDirectory() as t:
            c = config(t); config_module.validate(c)
            c["profile"] = "reconstruction"
            with self.assertRaises(ValueError): config_module.validate(c)
            c["profile"] = "ablation"; c["models"]["scan"]["sampling"] = {"model": "override"}
            with self.assertRaises(ValueError): config_module.validate(c)
