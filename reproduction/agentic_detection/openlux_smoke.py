"""Probe a single OpenLux capability and emit one credential-free JSON record."""
from __future__ import annotations

import argparse
import json
import math
import os
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def payload_for(model: str, check: str) -> dict:
    prompt = "Reply with exactly OK."
    options = {}
    schema = {
        "type": "object",
        "properties": {"ok": {"type": "boolean"}},
        "required": ["ok"],
        "additionalProperties": False,
    }
    if check == "schema":
        prompt = "Return a JSON object with ok set to true."
        options["response_format"] = {
            "type": "json_schema",
            "json_schema": {"name": "ping", "schema": schema, "strict": True},
        }
    elif check == "tool":
        prompt = "Call ping once with ok set to true."
        options["tools"] = [{
            "type": "function",
            "function": {"name": "ping", "parameters": schema},
        }]
        options["tool_choice"] = {"type": "function", "function": {"name": "ping"}}
        options["reasoning_effort"] = "none"
    elif check == "context":
        middle = "\n".join(f"Record {index:05d} contains inert test data." for index in range(4096))
        prompt = f"First marker: J7QX\n{middle}\nLast marker: M2BK\nReply with both markers separated by a space."
    return {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_completion_tokens": 512,
        **options,
    }


def matches(check: str, choice: dict) -> bool:
    message = choice["message"]
    if check == "tool":
        calls = message.get("tool_calls") or []
        if len(calls) != 1 or choice.get("finish_reason") != "tool_calls":
            return False
        function = calls[0]["function"]
        return function["name"] == "ping" and matches_json(function["arguments"])
    if choice.get("finish_reason") != "stop":
        return False
    content = message.get("content") or ""
    if check == "schema":
        return matches_json(content)
    expected = "J7QX M2BK" if check == "context" else "OK"
    return content.strip() == expected


def matches_json(content: str) -> bool:
    value = json.loads(content)
    return isinstance(value, dict) and set(value) == {"ok"} and value["ok"] is True


def probe(endpoint: str, model: str, check: str, key: str, timeout: float) -> dict:
    body = json.dumps(payload_for(model, check)).encode()
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "check": check,
        "requested_model": model,
        "request_bytes": len(body),
        "ok": False,
    }
    request = Request(endpoint, data=body, headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    })
    start = time.monotonic()
    try:
        with build_opener(NoRedirect).open(request, timeout=timeout) as response:
            record["http_status"] = response.status
            raw = response.read(262145)
        if len(raw) > 262144:
            record["failure"] = "response_size"
            return record
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("expected an object")
        usage = payload.get("usage") or {}
        record["usage"] = {
            name: usage[name]
            for name in ("prompt_tokens", "completion_tokens", "total_tokens")
            if type(usage.get(name)) is int and usage[name] >= 0
        }
        cost = usage.get("cost")
        record["reported_cost"] = cost if type(cost) in (int, float) and 0 <= cost < math.inf else None
        returned_model = payload.get("model")
        record["returned_model"] = returned_model.replace(key, "[REDACTED]")[:120] if isinstance(returned_model, str) else None
        if returned_model != model:
            record["failure"] = "model_identity"
        elif not matches(check, payload["choices"][0]):
            record["failure"] = "response_contract"
        else:
            record["ok"] = True
    except HTTPError as error:
        error.close()
        record.update(http_status=error.code, failure="http")
    except (URLError, OSError):
        record["failure"] = "transport"
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        record["failure"] = "response_parse"
    finally:
        record["latency_ms"] = round((time.monotonic() - start) * 1000)
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=os.getenv("OPENLUX_MODEL", "gpt-6.1-sol"))
    parser.add_argument("--base-url", default=os.getenv("OPENLUX_BASE_URL", "https://api.openlux.ai/v1"))
    parser.add_argument("--timeout", type=float, default=90)
    parser.add_argument("--check", choices=("chat", "schema", "tool", "context"), default="chat")
    parser.add_argument("--env-file", help="Existing OpenLux .env file. Requires python-dotenv.")
    args = parser.parse_args()
    url = urlsplit(args.base_url)
    if url.scheme != "https" or url.netloc != "api.openlux.ai" or url.query or url.fragment:
        parser.error("base URL must be on https://api.openlux.ai")
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("timeout must be finite and positive")
    if args.env_file:
        from dotenv import load_dotenv

        load_dotenv(args.env_file, override=False)
    key = os.environ.get("OPENLUX_API_KEY", "").strip()
    if not key or key.startswith("YOUR_"):
        parser.error("OPENLUX_API_KEY is unavailable")
    if not args.model.strip() or key in args.model:
        parser.error("invalid model ID")
    result = probe(args.base_url.rstrip("/") + "/chat/completions", args.model, args.check, key, args.timeout)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
