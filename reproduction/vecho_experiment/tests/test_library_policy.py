import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reproduction.vecho_experiment.config import validate
from reproduction.vecho_experiment.evaluation import evaluate
from reproduction.vecho_experiment import runtime
from reproduction.vecho_experiment.io import write, read, file_hash
from reproduction.vecho_experiment.runner import Backend
from .support import config, git_repo, finding


class LibraryPolicyTests(unittest.TestCase):
    def test_library_mode_is_explicit_and_cannot_claim_original_reconstruction(self):
        c = config('fixture'); c['analysis_policy'] = 'library-v1'; validate(c)
        c['profile'] = 'reconstruction'
        with self.assertRaisesRegex(ValueError, 'Library evidence'): validate(c)
        c['profile'] = 'ablation'; c['analysis_policy'] = 'unknown'
        with self.assertRaisesRegex(ValueError, 'Unknown analysis'): validate(c)

    def test_runtime_cannot_resume_under_changed_analysis_policy(self):
        with tempfile.TemporaryDirectory() as t:
            c = config(t); c['analysis_policy'] = 'library-v1'
            write(Path(c['workspace']) / 'runtime/runtime.json', {
                'upstream': c['artifact_commit'], 'judge_final_save_adapter': False,
                'analysis_policy': 'legacy'})
            with self.assertRaisesRegex(ValueError, 'analysis policy changed'): runtime.verify(c)

    def test_location_hit_kept_separate_from_path_recall(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / 'source'; git_repo(root)
            row = finding(); row['tainted_data_flow'] = []
            metric = evaluate(root, [row], [{'file': 'A.java', 'class': 'A', 'method': 'vulnerable'}])
            self.assertEqual((metric['recall'], metric['paths'], metric['tp_paths']), (0, 0, 0))
            self.assertTrue(metric['location_match']['hit'])
            self.assertEqual(metric['location_match']['matches'][0]['method'], ('A.java', 'A', 'vulnerable'))

    def test_invalid_location_does_not_change_valid_path_metric(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t) / 'source'; git_repo(root)
            row = finding(); row['affected_files'][0]['file_path'] = '../escape.java'
            metric = evaluate(root, [row], [{'file': 'A.java', 'class': 'A', 'method': 'vulnerable'}])
            self.assertEqual(metric['recall'], 1)
            self.assertIsNone(metric['location_match']['hit'])

    def blocked_scan(self, root, valid_window):
        c = config(root); c['analysis_policy'] = 'library-v1'
        source = root / 'source'; source.mkdir(); (source / 'A.java').write_text('class A { public String clean(String x) { return x; } }\n')
        attempt = root / 'attempt'; attempt.mkdir()
        backend = Backend(c, {'artifact': str(root), 'scanner_binary': 'offline'}, 'http://127.0.0.1:1', 'fake', '', 'sample_0001', source)
        def execute(argv, cwd, output, env):
            scan = attempt / 'scan'
            write(scan / 'session.json', {'status': 'completed'})
            write(scan / 'vecho/report.json', {'vulnerabilities': []})
            write(scan / 'contextaudit/results.json', {'total': 1, 'by_status': {'blocked': 1}, 'results': [{'case_id': 'case-000001', 'status': 'blocked'}]})
            write(scan / 'contextaudit/cases/case-000001/case.json', {'case_id': 'case-000001', 'status': 'blocked',
                'seed': {'title': 'Public API boundary unresolved', 'location': {'file': 'A.java', 'line': 1}},
                'reason': 'No in-repository callers', 'read_windows': [{'file': 'A.java', 'start_line': 1, 'end_line': 1,
                    'sha256': file_hash(source / 'A.java') if valid_window else 'wrong'}]})
        with patch('reproduction.vecho_experiment.runner.command', side_effect=execute):
            return read(backend.scan('scan', attempt, [], []))

    def test_unresolved_library_seed_reaches_judge_as_candidate_without_fake_path(self):
        with tempfile.TemporaryDirectory() as t:
            report = self.blocked_scan(Path(t), True)
            self.assertEqual(len(report['vulnerabilities']), 1)
            row = report['vulnerabilities'][0]
            self.assertTrue(row['metadata']['candidate_only'])
            self.assertEqual(row['tainted_data_flow'], [])
            self.assertIn('UNRESOLVED', row['description'])

    def test_unread_or_changed_unresolved_seed_is_not_forwarded(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(ValueError, 'verified read window'): self.blocked_scan(Path(t), False)
