"""Exercise real upstream judge and real SDK against a loopback fake provider."""
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch
from reproduction.vecho_experiment.runner import Backend
from reproduction.vecho_experiment.gateway import Gateway, Ledger
from reproduction.vecho_experiment.io import read
from .support import config, finding


class NativeIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("VECHO_SCANNER_TEST_BINARY"), "Set VECHO_SCANNER_TEST_BINARY to the prepared scanner")
    def test_real_go_scan_and_guided_rescan_use_gateway(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); c = config(root); source = root / "source"; source.mkdir()
            (source / "A.java").write_text("class A { void fixture() {} }\n")
            calls = []
            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *a): pass
                def do_POST(self):
                    data = json.loads(self.rfile.read(int(self.headers["Content-Length"]))); calls.append(data)
                    action = {"thought": "offline fixture", "emit_seed": [], "update_block_status": {"status": "completed", "summary": "offline fixture", "static_analysis_hypothesis": "fixture"}}
                    result = {"choices": [{"finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(action)}}], "usage": {"prompt_tokens": 50, "completion_tokens": 20}}
                    body = json.dumps(result).encode(); self.send_response(200)
                    self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            for model in c["models"].values(): model["base_url"] = f"http://127.0.0.1:{server.server_port}/v1"
            ledger = Ledger(root / "budget.sqlite", c["budget"], c["models"]); gateway = Gateway(c, ledger)
            try:
                with patch.dict(os.environ, {"VECHO_TEST_KEY": "fake"}), gateway.serve() as url:
                    rt = {"artifact": os.environ["VECHO_UPSTREAM_TEST_ROOT"], "scanner_binary": os.environ["VECHO_SCANNER_TEST_BINARY"]}
                    b = Backend(c, rt, url, gateway.token, "", "sample_0001", source)
                    scan = root / "scan"; scan.mkdir(); rescan = root / "rescan"; rescan.mkdir()
                    self.assertEqual(read(b.scan("scan", scan, [], []))["vulnerabilities"], [])
                    self.assertEqual(read(b.scan("rescan", rescan, [{"fingerprint": "fixture", "source": "fixture", "content": "Inspect sibling code"}], []))["vulnerabilities"], [])
                self.assertGreater(len(calls), 1)
                self.assertEqual(ledger.summary()["requests"], len(calls))
                self.assertTrue(any("Rescan guidance input" in m["content"] for call in calls for m in call["messages"]))
            finally:
                server.shutdown(); server.server_close(); thread.join()

    @unittest.skipUnless(os.environ.get("VECHO_UPSTREAM_TEST_ROOT"), "Set VECHO_UPSTREAM_TEST_ROOT to a pinned upstream checkout")
    def test_real_judge_sdk_gateway_tool_save_and_request_transcripts(self):
        upstream = Path(os.environ["VECHO_UPSTREAM_TEST_ROOT"])
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); c = config(root); target = root / "source"; target.mkdir()
            (target / "A.java").write_text("class A {}")
            received = []
            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *a): pass
                def do_POST(self):
                    payload = json.loads(self.rfile.read(int(self.headers["Content-Length"]))); received.append(payload)
                    response = {"id": "fixture", "object": "chat.completion", "created": 1, "model": "offline-fixture",
                       "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {"role": "assistant", "content": None,
                         "tool_calls": [{"id": "fixture-save", "type": "function", "function": {"name": "save_result", "arguments": json.dumps({"fingerprint": "native-fixture", "vuln_status": "true", "analysis": "Offline protocol fixture; not a vulnerability finding."})}}]}}],
                       "usage": {"prompt_tokens": 50, "completion_tokens": 10, "total_tokens": 60}}
                    body = json.dumps(response).encode(); self.send_response(200)
                    self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
            for model in c["models"].values(): model["base_url"] = f"http://127.0.0.1:{server.server_port}/v1"
            ledger = Ledger(root / "budget.sqlite", c["budget"], c["models"]); gateway = Gateway(c, ledger)
            try:
                with patch.dict(os.environ, {"VECHO_TEST_KEY": "fake-provider-key"}), gateway.serve() as url:
                    backend = Backend(c, {"artifact": str(upstream)}, url, gateway.token, "", "sample_0001", target)
                    r = finding(); r["fingerprint"] = "native-fixture"
                    output = root / "judge"; output.mkdir()
                    result = read(backend.judge(r, output))
                self.assertEqual(result["result"]["vuln_status"], "true")
                self.assertEqual(len(received), 1)
                self.assertEqual(received[0]["max_tokens"], 100)
                self.assertEqual(ledger.summary()["requests"], 1)
                traces = list((root / "experiment/private/model-requests").glob("*.request.json"))
                self.assertEqual(len(traces), 1)
                self.assertNotIn("fake-provider-key", traces[0].read_text())
            finally:
                server.shutdown(); server.server_close(); thread.join()
