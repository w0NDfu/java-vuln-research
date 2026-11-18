import concurrent.futures
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from reproduction.vecho_experiment.gateway import Ledger, Gateway, BudgetExceeded
from .support import config


class LedgerTests(unittest.TestCase):
    def test_parallel_reservations_cannot_exceed_budget(self):
        with tempfile.TemporaryDirectory() as t:
            c = config(t); c["budget"].update(limit_usd=.01, max_requests=100)
            ledger = Ledger(Path(t) / "budget.sqlite", c["budget"], c["models"])
            def reserve(i):
                try: ledger.reserve("scan", {"id": i}, 3000); return True
                except BudgetExceeded: return False
            with concurrent.futures.ThreadPoolExecutor(8) as pool:
                accepted = list(pool.map(reserve, range(16)))
            self.assertEqual(sum(accepted), 3)
            self.assertAlmostEqual(ledger.summary()["charged_or_reserved_usd"], .009)
            reopened = Ledger(Path(t) / "budget.sqlite", c["budget"], c["models"])
            self.assertEqual(reopened.summary()["requests"], 3)

    def test_opening_spend_and_unknown_usage_retained_on_restart(self):
        with tempfile.TemporaryDirectory() as t:
            c = config(t); c["budget"].update(limit_usd=.01, opening_spend_usd=.005)
            p = Path(t) / "ledger.sqlite"; l = Ledger(p, c["budget"], c["models"])
            req = l.reserve("scan", {}, 4000); l.finish(req, None)
            reopened = Ledger(p, c["budget"], c["models"])
            with self.assertRaises(BudgetExceeded): reopened.reserve("scan", {}, 2000)
            c["budget"]["limit_usd"] = 1
            with self.assertRaises(ValueError): Ledger(p, c["budget"], c["models"])


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.c = config(self.temp.name)
        self.received = []; self.response = {"choices": [{"message": {"role": "assistant", "content": "fixture"}}], "usage": {"prompt_tokens": 10, "completion_tokens": 5}}
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                fixture.received.append({"payload": json.loads(self.rfile.read(int(self.headers["Content-Length"]))), "authorization": self.headers.get("Authorization")})
                body = json.dumps(fixture.response).encode(); self.send_response(200)
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        for model in self.c["models"].values(): model["base_url"] = f"http://127.0.0.1:{self.server.server_port}/v1"
        self.ledger = Ledger(Path(self.temp.name) / "budget.sqlite", self.c["budget"], self.c["models"])
        self.gateway = Gateway(self.c, self.ledger)
        self.env = patch.dict(os.environ, {"VECHO_TEST_KEY": "fixture-secret"}); self.env.start()

    def tearDown(self):
        self.env.stop(); self.server.shutdown(); self.server.server_close(); self.thread.join(); self.temp.cleanup()

    def call(self):
        return self.gateway.process("scan", "chat/completions", {"model": "wrong", "messages": [{"role": "user", "content": "fixture"}], "temperature": .9})

    def test_request_sampling_model_limits_and_exact_usage_settlement(self):
        self.call(); sent = self.received[-1]
        self.assertEqual(sent["payload"]["temperature"], .1)
        self.assertEqual(sent["payload"]["max_tokens"], 100)
        self.assertEqual(sent["payload"]["model"], "offline-fixture")
        self.assertEqual(sent["authorization"], "Bearer fixture-secret")
        self.assertAlmostEqual(self.ledger.summary()["charged_or_reserved_usd"], .00002)
        with self.ledger.connect() as db:
            values = str(db.execute("SELECT * FROM requests").fetchall())
        self.assertNotIn("fixture-secret", values); self.assertNotIn("messages", values)

    def test_missing_usage_is_not_zero_cost(self):
        self.response.pop("usage")
        with self.assertRaises(RuntimeError): self.call()
        self.assertAlmostEqual(self.ledger.summary()["charged_or_reserved_usd"], .0012)
        self.assertEqual(self.ledger.summary()["states"], {"uncertain": 1})

    def test_usage_bound_violation_persistently_blocks_future_calls(self):
        self.response["usage"]["prompt_tokens"] = 2000
        with self.assertRaises(RuntimeError): self.call()
        reopened = Gateway(self.c, Ledger(Path(self.temp.name) / "budget.sqlite", self.c["budget"], self.c["models"]))
        with self.assertRaises(BudgetExceeded): reopened.process("scan", "chat/completions", {"messages": [{"role": "user", "content": "fixture"}]})
        self.assertEqual(len(self.received), 1)

    def test_http_unauthorized_route_and_stop_denied_before_upstream(self):
        with self.gateway.serve() as base:
            req = Request(base + "/scan/v1/chat/completions", data=b'{}', headers={"Content-Type": "application/json"})
            with self.assertRaises(HTTPError) as caught: urlopen(req)
            self.assertEqual(caught.exception.code, 400)
        self.gateway.stop.parent.mkdir(parents=True); self.gateway.stop.touch()
        with self.assertRaises(BudgetExceeded): self.call()
        self.assertEqual(self.received, [])
