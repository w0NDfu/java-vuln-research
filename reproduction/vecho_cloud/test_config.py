import os
import unittest
from unittest.mock import patch

from common import apply_shared_key, required


class ConfigTests(unittest.TestCase):
    def test_shared_key_populates_every_stage(self):
        with patch.dict(os.environ, {"OPENLUX_API_KEY":"offline-test-key", "MEMORY_API_KEY":"old-key"}, clear=True):
            apply_shared_key()
            for name in ("SILICONFLOW_API_KEY", "VECHO_SCAN_API_KEY", "VECHO_JUDGE_API_KEY", "MEMORY_API_KEY"):
                self.assertEqual(required(name), "offline-test-key")

    def test_missing_key_names_the_single_user_field(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "Configure OPENLUX_API_KEY"):
                required("MEMORY_API_KEY")

    def test_selected_models_construct_without_requests(self):
        from llama_index.llms.openai import OpenAI
        from llama_index.embeddings.openai import OpenAIEmbedding
        llm = OpenAI(model="gpt-4.1-mini", api_key="offline-test-key", api_base="http://127.0.0.1:9/v1")
        self.assertGreater(llm.metadata.context_window, 0)
        embedding = OpenAIEmbedding(model="text-embedding-3-small", api_key="offline-test-key", api_base="http://127.0.0.1:9/v1")
        self.assertEqual(embedding.model_name, "text-embedding-3-small")


if __name__ == "__main__":
    unittest.main()
