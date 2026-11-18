"""Request receipts and bounded retries for the single-snapshot experiment."""
from __future__ import annotations

import json
import hashlib
import os
import math
import time
from functools import lru_cache
from pathlib import Path
from contextlib import contextmanager
from urllib.error import HTTPError, URLError

from .harness import PolicyError
from .harness import ModelTurn


class BudgetExceeded(PolicyError):
    stop_reason = "RESOURCE_BUDGET_EXHAUSTED"


class VerificationReserve(PolicyError):
    stop_reason = "VERIFICATION_RESERVE"


@lru_cache(maxsize=1)
def _token_encoding():
    try:
        import tiktoken
        return tiktoken.get_encoding("o200k_base")
    except (ImportError, OSError, ValueError):
        return None


def request_reserve(context, policy):
    """Estimate admission separately from the usage ultimately charged."""
    material = json.dumps({"context": context, "system": policy.system_prompt}, ensure_ascii=False, sort_keys=True)
    if callable(getattr(policy,"request_token_material",None)):
        material=policy.request_token_material(context)
    encoding = _token_encoding()
    if encoding is None:
        inputs = len(material.encode("utf-8"))
        method = "utf8_byte_upper_bound"
    else:
        inputs = len(encoding.encode(material, disallowed_special=()))
        method = "o200k_base_estimate"
    return inputs + max(512, inputs // 5) + policy.max_output_tokens, method


@contextmanager
def exclusive_run(path: Path):
    """Release the per-experiment writer lock automatically after process death."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        if os.name == "nt":
            import msvcrt
            stream.seek(0)
            if not stream.read(1):
                stream.write(b"0")
                stream.flush()
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


class RequestJournal:
    """Per-experiment durable responses and shared physical-request budgets."""

    def __init__(self, path: Path, *, max_requests: int, max_tokens: int,
                 max_seconds: float, binding: str, verification_reserve: bool = False):
        if (type(max_requests) is not int or type(max_tokens) is not int
                or not math.isfinite(max_seconds) or min(max_requests, max_tokens, max_seconds) <= 0 or not binding):
            raise ValueError("Positive budgets and a source/configuration binding are required.")
        self.path = path
        self.max_requests = max_requests
        self.max_tokens = max_tokens
        self.max_seconds = max_seconds
        self.binding = binding
        self.verification_reserve = verification_reserve
        self.started = time.monotonic()
        self.created_at = time.time()
        self.responses = {}
        self.requests = 0
        self.tokens = 0
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                self.created_at = min(self.created_at, row["created_at"])
                if row["binding"] != binding:
                    raise ValueError("Request journal belongs to different source or configuration.")
                if row["event"] == "request_started":
                    self.requests += 1
                    self.tokens += row["reserved_tokens"]
                elif row["event"] == "response":
                    self.tokens += row["charged_tokens"] - row["reserved_tokens"]
                    self.responses[row["request_key"]] = row

    def append(self, row):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"binding": self.binding, "created_at": self.created_at, **row}, ensure_ascii=False) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def wrap(self, policy):
        def call(context):
            encoded = json.dumps({"context": context, "system": policy.system_prompt,
                                  "model": policy.model, "endpoint": policy.endpoint,
                                  "output_limit": policy.max_output_tokens},
                                 ensure_ascii=False, sort_keys=True).encode("utf-8")
            key = hashlib.sha256(encoded).hexdigest()
            if key in self.responses:
                row = self.responses[key]
                return ModelTurn(row["content"], row["usage"], row.get("metadata", {}))
            budget = context.get("verification_budget")
            pending = None
            if context.get("benchmark_first"):
                reserve, estimate_method = request_reserve(context, policy)
                held_tokens = held_requests = 0
            elif self.verification_reserve and isinstance(budget, dict):
                pending = budget.get("pending_verification_count")
                if type(pending) is not int or pending < 0:
                    raise ValueError("Pending verification count must be a nonnegative integer.")
                reserve, estimate_method = request_reserve(context, policy)
                held_tokens = 12000 if pending == 0 else min(36000, 12000 * (pending + 1))
                held_requests = 1 if pending == 0 else min(3, pending + 1)
            else:
                # Preserve admission for legacy callers without a runtime candidate census.
                reserve = len(encoded) + 8192 + policy.max_output_tokens
                estimate_method = "legacy_utf8_reserve"
                held_tokens = min(36000, self.max_tokens // 4)
                held_requests = min(2, self.max_requests // 4)
            unclipped = reserve
            final = bool(isinstance(budget, dict) and pending == 0 and context["role"] == "reasoning"
                         and context.get("final_synthesis") and
                         self.max_tokens - self.tokens >= 15000)
            if final and not context.get("general_evp"):
                reserve = min(reserve, self.max_tokens - self.tokens - held_tokens)
            if self.verification_reserve and context["role"] != "verification":
                if (self.requests >= self.max_requests - held_requests
                        or self.tokens + reserve > self.max_tokens - held_tokens):
                    raise VerificationReserve("Remaining admission capacity is reserved for verification.")
            if (self.requests >= self.max_requests or self.tokens + reserve > self.max_tokens
                    or time.time() - self.created_at >= self.max_seconds):
                raise BudgetExceeded("Shared request, token admission, or wall-time budget reached.")
            started = time.monotonic()
            self.append({"event": "request_started", "request_key": key, "reserved_tokens": reserve,
                         "role": context["role"], "model": policy.model,
                         "reserve_estimate": unclipped, "reserve_method": estimate_method,
                         "held_verification_tokens": held_tokens, "held_verification_requests": held_requests,
                         "pending_verification_count": budget.get("pending_verification_count") if budget else None,
                         "final_admission_adjusted": reserve != unclipped})
            self.requests += 1
            self.tokens += reserve
            turn = policy(context)
            total = turn.usage.get("total_tokens")
            charged = total if type(total) is int and total >= 0 else reserve
            row = {"event": "response", "request_key": key, "reserved_tokens": reserve,
                   "charged_tokens": charged, "content": turn.content, "usage": dict(turn.usage),
                   "metadata": dict(turn.metadata), "role": context["role"], "model": policy.model,
                   "duration_s": round(time.monotonic() - started, 3)}
            self.append(row)
            self.tokens += charged - reserve
            self.responses[key] = row
            return turn
        for name in ("system_prompt", "max_output_tokens", "model", "endpoint"):
            setattr(call, name, getattr(policy, name))
        return call


def audited_policy(policy, record, *, input_rate: float, output_rate: float, sleep=time.sleep,
                   max_attempts: int = 3, retry_delay: float = 2, repair_in_harness: bool = False):
    retry_http = {408, 429, 500, 502, 503, 504}
    if not 1 <= max_attempts <= 3 or not 0 <= retry_delay <= 60:
        raise ValueError("attempts must be in [1, 3] and retry delay in [0, 60]")

    def call(context):
        role = context["role"]
        context_bytes = len(json.dumps(context, ensure_ascii=False).encode("utf-8"))
        output_limit = getattr(policy, "max_output_tokens", 1024)
        reserve = (context_bytes + len(policy.system_prompt.encode("utf-8")) + 2048) * input_rate + output_limit * output_rate
        for attempt in range(1, max_attempts + 1):
            started = time.monotonic()
            try:
                turn = policy(context)
            except BudgetExceeded:
                raise
            except PolicyError as error:
                cause = error.__cause__
                status = cause.code if isinstance(cause, HTTPError) else None
                transient = status in retry_http if status is not None else isinstance(cause, (URLError, OSError))
                record(role=role, attempt=attempt, state="provider_error", http_status=status,
                       duration_s=round(time.monotonic() - started, 3), context_bytes=context_bytes,
                       reserved_usd=reserve)
                if not transient or attempt == max_attempts:
                    raise
                sleep(attempt * retry_delay)
                continue

            usage = turn.usage
            input_tokens = usage.get("prompt_tokens")
            output_tokens = usage.get("completion_tokens")
            known_usage = type(input_tokens) is int and input_tokens >= 0 and type(output_tokens) is int and output_tokens >= 0
            cost = input_tokens * input_rate + output_tokens * output_rate if known_usage else reserve
            try:
                valid = isinstance(json.loads(turn.content), dict)
            except (ValueError, RecursionError):
                valid = False
            record(role=role, attempt=attempt, state="received" if valid else "invalid_response",
                   duration_s=round(time.monotonic() - started, 3), context_bytes=context_bytes,
                   usage=dict(usage), estimated_usd=cost, usage_estimated=not known_usage)
            if valid or repair_in_harness:
                return turn
            if attempt == max_attempts:
                raise PolicyError("Model repeatedly returned an invalid JSON action.")

    for name in ("system_prompt", "max_output_tokens", "model", "endpoint"):
        if hasattr(policy, name):
            setattr(call, name, getattr(policy, name))
    return call
