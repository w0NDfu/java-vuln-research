"""Two small live requests; never print credentials or response bodies."""
import datetime
import json
import os
import sys

import requests

from common import REPRO, load_env, required, write_json


def main():
    load_env()
    key = required("OPENLUX_API_KEY")
    base = os.environ["VECHO_JUDGE_BASE_URL"].rstrip("/")
    assert base == "https://api.openlux.ai/v1", "Unexpected provider; no request sent"
    result = {"timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "provider": base, "checks": []}
    checks = [
        ("chat_tools", "/chat/completions", {
            "model": os.environ["VECHO_SCAN_MODEL"],
            "messages": [{"role": "user", "content": "Call ping with ok=true."}],
            "tools": [{"type": "function", "function": {"name": "ping", "description": "Connectivity check", "parameters": {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"], "additionalProperties": False}}}],
            "tool_choice": {"type": "function", "function": {"name": "ping"}},
            "max_tokens": 48,
        }),
        ("embedding", "/embeddings", {"model": os.environ["MEMORY_EMBEDDING_MODEL"], "input": "connectivity check"}),
    ]
    for name, path, payload in checks:
        record = {"name": name, "model": payload["model"], "ok": False}
        try:
            response = requests.post(base + path, headers={"Authorization": "Bearer " + key}, json=payload, timeout=(15, 90))
            record["http_status"] = response.status_code
            body = response.json()
            if response.status_code != 200:
                error = body.get("error", {})
                if isinstance(error, dict):
                    record["error_type"] = str(error.get("type", ""))[:100]
                    record["error_message"] = str(error.get("message", "")).replace(key, "[REDACTED]")[:350]
                raise RuntimeError("Provider rejected request")
            record["usage"] = body.get("usage")
            if name == "chat_tools":
                calls = body["choices"][0]["message"].get("tool_calls", [])
                assert calls and calls[0]["function"]["name"] == "ping", "Tool call not returned"
                assert json.loads(calls[0]["function"]["arguments"]).get("ok") is True
            else:
                vector = body["data"][0]["embedding"]
                record["dimensions"] = len(vector)
                assert len(vector) == 1536 and all(isinstance(x, (int, float)) for x in vector)
            record["ok"] = True
        except Exception as exc:
            record["exception"] = type(exc).__name__
        result["checks"].append(record)
        write_json(REPRO / "preflight.json", result)
        print(json.dumps(record, ensure_ascii=False), flush=True)
        if not record["ok"]:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
