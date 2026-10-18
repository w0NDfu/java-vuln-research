import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

from common import ROOT


class JudgeBudgetTest(unittest.TestCase):
    def run_fake(self, create, turns=10):
        sys.path.insert(0, str(ROOT / "judge"))
        from vecho_judge.runtime.llm_loop import JudgeRuntimeConfig, run_llm_judge
        from vecho_judge.schemas.types import VulnerabilityRecord
        fake = NS(OpenAI=lambda **kwargs: NS(chat=NS(completions=NS(create=create))))
        with tempfile.TemporaryDirectory() as tmp, patch.dict(sys.modules, {"openai": fake}):
            prompt = Path(tmp) / "prompt.txt"
            prompt.write_text("Judge using tools")
            cfg = JudgeRuntimeConfig(repo_root=Path(tmp), model="offline", base_url="http://127.0.0.1:9", api_key="offline", prompt_path=prompt, max_turns=turns)
            return run_llm_judge(VulnerabilityRecord("test", "test", "test", [], "vecho_scan"), cfg)

    def test_tool_only_loop_reserves_last_turn_for_unknown(self):
        choices = []
        def create(**kwargs):
            choices.append(kwargs["tool_choice"])
            if len(choices) < 10:
                call = NS(id=str(len(choices)), function=NS(name="get_dir_list", arguments='{"dir_path":"."}'))
            else:
                self.assertIn("unknown", kwargs["messages"][-1]["content"])
                call = NS(id="final", function=NS(name="save_result", arguments='{"fingerprint":"test","vuln_status":"unknown","analysis":"Insufficient evidence"}'))
            return NS(usage=None, choices=[NS(message=NS(content=None, tool_calls=[call]))])
        output = self.run_fake(create)
        self.assertEqual(len(choices), 10)
        self.assertEqual(choices[-1], {"type": "function", "function": {"name": "save_result"}})
        self.assertEqual(output.result.vuln_status, "unknown")

    def test_early_saved_verdict_needs_no_extra_calls(self):
        calls = []
        def create(**kwargs):
            calls.append(kwargs)
            tool = NS(id="early", function=NS(name="save_result", arguments='{"fingerprint":"test","vuln_status":"false","analysis":"Guard blocks the flow"}'))
            return NS(usage=None, choices=[NS(message=NS(content=None, tool_calls=[tool]))])
        output = self.run_fake(create)
        self.assertEqual(len(calls), 1)
        self.assertEqual(output.result.vuln_status, "false")

    def test_ignored_final_tool_requirement_is_still_a_failure(self):
        calls = []
        def create(**kwargs):
            calls.append(kwargs)
            return NS(usage=None, choices=[NS(message=NS(content="No tool call", tool_calls=[]))])
        with self.assertRaisesRegex(RuntimeError, "did not call save_result"):
            self.run_fake(create, turns=3)
        self.assertEqual(len(calls), 3)

    def test_text_only_responses_do_not_end_before_final_unknown_verdict(self):
        sys.path.insert(0, str(ROOT / "judge"))
        from vecho_judge.runtime.llm_loop import JudgeRuntimeConfig, run_llm_judge
        from vecho_judge.schemas.types import VulnerabilityRecord
        choices = []
        def create(**kwargs):
            choices.append(kwargs["tool_choice"])
            calls = []
            if len(choices) == 10:
                calls = [NS(id="final", function=NS(name="save_result", arguments='{"fingerprint":"wrong-model-id","vuln_status":"unknown","analysis":"Insufficient evidence"}'))]
            return NS(usage=None, choices=[NS(message=NS(content="Evidence is incomplete", tool_calls=calls))])
        fake = NS(OpenAI=lambda **kwargs: NS(chat=NS(completions=NS(create=create))))
        with tempfile.TemporaryDirectory() as tmp, patch.dict(sys.modules, {"openai": fake}):
            prompt = Path(tmp) / "prompt.txt"
            prompt.write_text("Judge using tools")
            cfg = JudgeRuntimeConfig(repo_root=Path(tmp), model="offline", base_url="http://127.0.0.1:9", api_key="offline", prompt_path=prompt)
            record = VulnerabilityRecord("test", "test", "test", [], "vecho_scan")
            output = run_llm_judge(record, cfg)
        self.assertEqual(len(choices), 10)
        self.assertEqual(choices[-1], {"type": "function", "function": {"name": "save_result"}})
        self.assertEqual(output.result.vuln_status, "unknown")
        self.assertEqual(output.result.fingerprint, "test")


if __name__ == "__main__":
    unittest.main()
