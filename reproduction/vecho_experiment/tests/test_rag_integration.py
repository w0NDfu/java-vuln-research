"""Real upstream RAG index, admission and retrieval; loopback embeddings/LLM."""
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request, urlopen
from reproduction.vecho_experiment import memory
from reproduction.vecho_experiment.gateway import Gateway, Ledger
from .support import config


@unittest.skipUnless(os.environ.get("VECHO_TEST_REAL_RAG"), "Set VECHO_TEST_REAL_RAG=1 with full upstream memory dependencies")
class RealRAGTests(unittest.TestCase):
    def test_original_rag_auto_index_is_retrievable_with_loopback_models(self):
        upstream = Path(os.environ["VECHO_UPSTREAM_TEST_ROOT"])
        with tempfile.TemporaryDirectory() as t:
            c = config(t); c["artifact"] = str(upstream); c["memory"]["policy"] = "auto_index"
            c["models"]["memory"]["model"] = "gpt-3.5-turbo"
            seen = []
            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *a): pass
                def do_POST(self):
                    data = json.loads(self.rfile.read(int(self.headers["Content-Length"]))); seen.append(self.path)
                    if self.path.endswith("/embeddings"):
                        value = data["input"]
                        count = len(value) if isinstance(value, list) and value and isinstance(value[0], (str, list)) else 1
                        response = {"object": "list", "model": "text-embedding-ada-002", "data": [{"object": "embedding", "index": i, "embedding": [0.1] * 1536} for i in range(count)], "usage": {"prompt_tokens": 10, "total_tokens": 10}}
                    else:
                        response = {"id": "fixture", "object": "chat.completion", "created": 1, "model": "gpt-3.5-turbo", "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "Approved fixture knowledge"}}], "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
                    body = json.dumps(response).encode(); self.send_response(200)
                    self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            for model in c["models"].values(): model["base_url"] = f"http://127.0.0.1:{server.server_port}/v1"
            ledger = Ledger(Path(t) / "budget.sqlite", c["budget"], c["models"]); gateway = Gateway(c, ledger)
            def invoke(url, tool, arguments):
                req = Request(url, data=json.dumps({"tool": tool, "arguments": arguments}).encode(), headers={"Content-Type": "application/json", "project": "sample_0001"})
                with urlopen(req, timeout=60) as response: return json.load(response)
            try:
                with patch.dict(os.environ, {"VECHO_TEST_KEY": "fake-provider-key"}), gateway.serve() as base:
                    with memory.serve(c, Path(t) / "knowledge", base, gateway.token, "sample_0001") as url:
                        saved = invoke(url, "save_knowledge", {"type": "general", "title": "Offline fixture", "content": "A synthetic generic fixture for admission and retrieval."})
                        self.assertTrue(saved["ok"])
                        answer = invoke(url, "query_knowledge", {"query": "synthetic generic fixture"})
                        content = json.loads(answer["content"])
                        self.assertTrue(content["success"]); self.assertTrue(content["common_results"])
                self.assertTrue(any(p.endswith("/embeddings") for p in seen))
                self.assertEqual(ledger.summary()["states"], {"usage_received": len(seen)})
            finally:
                server.shutdown(); server.server_close(); thread.join()
