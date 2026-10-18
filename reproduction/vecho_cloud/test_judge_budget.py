import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import patch

from common import ROOT


class JudgeBudgetTest(unittest.TestCase):
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
