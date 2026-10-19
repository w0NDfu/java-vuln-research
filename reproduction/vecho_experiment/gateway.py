"""Loopback model gateway: explicit sampling and durable conservative reservations.

All retries (including ones issued by upstream SDKs) pass through the same
SQLite ledger. Missing usage, interrupted requests and uncertain bills keep
their full reservation. Prices/context limits are operator-declared estimates,
not provider billing guarantees; no response body or credentials enter ledger.
"""
import contextlib
import json
import os
import sqlite3
import threading
import uuid
from decimal import Decimal, ROUND_CEILING
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from .io import digest, now, write


def micros(dollars):
    return int((Decimal(str(dollars)) * 1_000_000).to_integral_value(rounding=ROUND_CEILING))


class BudgetExceeded(RuntimeError):
    pass


class Ledger:
    def __init__(self, path, budget, models):
        self.path = str(path)
        self.settings = digest({"budget": budget, "models": models})
        self.limit = micros(budget["limit_usd"])
        self.opening = micros(budget["opening_spend_usd"])
        self.max_requests = budget["max_requests"]
        with self.connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, identity TEXT)")
            previous = db.execute("SELECT identity FROM settings WHERE id=1").fetchone()
            if previous and previous[0] != self.settings:
                raise ValueError("Budget/prices changed; original ledger cannot be reset or reused")
            db.execute("INSERT OR IGNORE INTO settings VALUES(1,?)", (self.settings,))
            db.execute("CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, time TEXT, role TEXT, request_hash TEXT, reserved INTEGER, charged INTEGER, state TEXT, usage TEXT)")

    @contextlib.contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    def reserve(self, role, payload, amount):
        request_id = uuid.uuid4().hex
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM requests WHERE state='bound_exceeded'").fetchone():
                raise BudgetExceeded("Provider bound violation requires billing reconciliation")
            used, count = db.execute("SELECT COALESCE(SUM(charged),0),COUNT(*) FROM requests").fetchone()
            if self.opening + used + amount > self.limit or count >= self.max_requests:
                raise BudgetExceeded("Cumulative budget/request reservation exhausted")
            db.execute("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?)", (request_id, now(), role, digest(payload), amount, amount, "reserved", None))
        return request_id

    def finish(self, request_id, usage, amount=None, state="uncertain"):
        with self.connect() as db:
            old = db.execute("SELECT reserved FROM requests WHERE id=?", (request_id,)).fetchone()[0]
            # A response whose usage exceeds configured limits freezes its
            # actual higher cost, never silently caps the recorded bill.
            db.execute("UPDATE requests SET charged=?,state=?,usage=? WHERE id=?",
                       (amount if amount is not None else old, state, json.dumps(usage) if usage else None, request_id))

    def summary(self):
        with self.connect() as db:
            count, charged = db.execute("SELECT COUNT(*),COALESCE(SUM(charged),0) FROM requests").fetchone()
            states = dict(db.execute("SELECT state,COUNT(*) FROM requests GROUP BY state"))
        return {"requests": count, "opening_spend_usd": self.opening / 1e6,
                "charged_or_reserved_usd": (self.opening + charged) / 1e6,
                "limit_usd": self.limit / 1e6, "states": states,
                "cost_basis": "declared prices; uncertain requests retain full reservation"}


class Gateway:
    def __init__(self, cfg, ledger):
        self.models, self.ledger = cfg["models"], ledger
        self.timeout = cfg["scanner"]["timeout_seconds"]
        self.token = uuid.uuid4().hex
        from pathlib import Path
        self.stop = Path(cfg["workspace"]) / "STOP"

    def process(self, role, kind, payload):
        if self.stop.exists(): raise BudgetExceeded("Operator requested stop")
        model = self.models[role]
        payload = dict(payload)
        if kind == "chat/completions":
            if role == "embedding" or payload.get("stream"):
                raise ValueError("Unsupported streaming/role")
            # Every token-producing request has one completion, bounded output,
            # and the frozen sampling policy; unknown provider knobs fail early.
            payload.update(model=model["model"], stream=False, n=1)
            payload.pop("max_completion_tokens", None)
            payload["max_tokens"] = model["max_output_tokens"]
            for k in ["temperature", "top_p", "seed", "presence_penalty", "frequency_penalty"]:
                payload.pop(k, None)
            payload.update(model["sampling"])
            if not payload.get("messages"):
                raise ValueError("Empty chat messages")
            reserve_in = model["context_tokens"]
            reserve_out = model["max_output_tokens"]
        elif kind == "embeddings" and role == "embedding":
            payload["model"] = model["model"]
            inputs = payload.get("input")
            count = len(inputs) if isinstance(inputs, list) and inputs and isinstance(inputs[0], (str, list)) else 1
            if not inputs or count > 2048:
                raise ValueError("Invalid embedding batch")
            reserve_in, reserve_out = count * model["context_tokens"], 0
        else:
            raise ValueError("Unknown gateway route")
        price_in, price_out = Decimal(str(model["input_usd_per_million"])), Decimal(str(model["output_usd_per_million"]))
        reservation = int((reserve_in * price_in + reserve_out * price_out).to_integral_value(rounding=ROUND_CEILING))
        request_id = self.ledger.reserve(role, payload, reservation)
        traces = self.stop.parent / "private" / "model-requests"
        traces.mkdir(parents=True, exist_ok=True); traces.chmod(0o700)
        write(traces / (request_id + ".request.json"), {"role": role, "payload": payload, "at": now()})
        api_key = os.environ.get(model["key_env"], "")
        if not api_key:
            self.ledger.finish(request_id, None, 0, "not_sent_no_key")
            raise ValueError("Missing provider credential environment variable")
        endpoint = model["base_url"].rstrip("/") + "/" + kind
        req = Request(endpoint, data=json.dumps(payload).encode(), headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"})
        try:
            with urlopen(req, timeout=self.timeout) as response:
                result = json.load(response)
        except Exception:
            self.ledger.finish(request_id, None)
            write(traces / (request_id + ".failure.json"), {"status": "uncertain", "at": now()})
            raise RuntimeError("Provider request failed; cost retained conservatively") from None
        write(traces / (request_id + ".response.json"), result)
        usage = result.get("usage", {})
        incoming, outgoing = usage.get("prompt_tokens"), usage.get("completion_tokens", 0)
        valid = type(incoming) is int and incoming >= 0 and type(outgoing) is int and outgoing >= 0
        if not valid:
            self.ledger.finish(request_id, usage)
            raise RuntimeError("Provider usage missing/invalid; reservation retained")
        amount = int((incoming * price_in + outgoing * price_out).to_integral_value(rounding=ROUND_CEILING))
        exceeded = incoming > reserve_in or outgoing > reserve_out or amount > reservation
        self.ledger.finish(request_id, usage, amount, "bound_exceeded" if exceeded else "usage_received")
        if exceeded:
            # Block future requests; an incorrectly declared provider limit can
            # otherwise make the price ceiling look stronger than it is.
            self.ledger.limit = 0
            raise RuntimeError("Provider usage exceeded declared bound; gateway halted")
        return result

    @contextlib.contextmanager
    def serve(self):
        gateway = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_POST(self):
                try:
                    if self.headers.get("Authorization") != "Bearer " + gateway.token:
                        raise ValueError("Gateway authorization required")
                    parts = self.path.strip("/").split("/")
                    if len(parts) < 3 or parts[1] != "v1" or parts[0] not in gateway.models:
                        raise ValueError("Unknown route")
                    n = int(self.headers.get("Content-Length", 0))
                    if not 0 < n <= 16 * 1024 * 1024: raise ValueError("Invalid request size")
                    result = gateway.process(parts[0], "/".join(parts[2:]), json.loads(self.rfile.read(n)))
                    status = 200
                except BudgetExceeded:
                    result, status = {"error": {"message": "Experiment budget exhausted", "type": "budget_exhausted"}}, 402
                except ValueError:
                    result, status = {"error": {"message": "Invalid experiment request", "type": "invalid_request"}}, 400
                except Exception:
                    result, status = {"error": {"message": "Experiment provider call incomplete; inspect ledger", "type": "request_incomplete"}}, 502
                body = json.dumps(result).encode()
                self.send_response(status); self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = False  # Settle in-flight reservations before final summary.
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}"
        finally:
            server.shutdown(); server.server_close(); thread.join()
