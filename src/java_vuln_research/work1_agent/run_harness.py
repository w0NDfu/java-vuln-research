"""CLI for the bounded Work1 source-only model pilot."""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .harness import ACTION_PROMPT, HarnessLimits, ModelTurn, PolicyError, run_harness


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ChatPolicy:
    def __init__(self, endpoint: str, model: str, api_key: str, *,
                 system_prompt: str = ACTION_PROMPT, timeout: float = 60,
                 max_output_tokens: int = 1024, json_mode: bool = False) -> None:
        url = urlsplit(endpoint)
        loopback_http = url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}
        if (url.scheme != "https" and not loopback_http) or not url.hostname:
            raise ValueError("endpoint must use HTTPS or loopback HTTP")
        if url.username is not None or url.password is not None or url.query or url.fragment:
            raise ValueError("endpoint must be a plain chat-completions URL")
        if not model.strip():
            raise ValueError("model must not be empty")
        if endpoint == OPENLUX_ENDPOINT and type(self) is ChatPolicy:
            raise ValueError('OpenLux requests must use OpenLuxChatPolicy (180s, retries=0).')
        if not math.isfinite(timeout) or timeout <= 0 or max_output_tokens < 1:
            raise ValueError("timeout and output token limit must be positive")
        self.endpoint = endpoint
        self.model = model
        self.system_prompt = system_prompt
        self.api_key = api_key
        self.timeout = timeout
        self.max_output_tokens = max_output_tokens
        self.json_mode = json_mode
        self.reasoning_model = model.startswith("gpt-6")
        self.identity = f"{url.netloc}/{model}"
        self.opener = build_opener(_NoRedirect)

    def request_body(self, context: Mapping[str, Any]) -> dict[str, Any]:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": json.dumps(context, ensure_ascii=False)},
            ],
        }
        if self.reasoning_model:
            body["max_completion_tokens"] = self.max_output_tokens
        else:
            body.update(max_tokens=self.max_output_tokens, temperature=0)
        if self.json_mode:
            body["response_format"] = {"type": "json_object"}
        return body

    def __call__(self, context: Mapping[str, Any]) -> ModelTurn:
        body = self.request_body(context)
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        request = Request(self.endpoint, data=json.dumps(body).encode("utf-8"), headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read(128 * 1024 + 1)
        except HTTPError as error:
            error.close()
            raise PolicyError(f"Model endpoint returned HTTP {error.code}.") from error
        except (URLError, OSError) as error:
            raise PolicyError("Model endpoint could not be reached or timed out.") from error
        return self.response_turn(raw)

    def response_turn(self, raw: bytes) -> ModelTurn:
        if len(raw) > 128 * 1024:
            raise PolicyError("Model response exceeded the transport size limit.")
        try:
            payload = json.loads(raw)
            if self.reasoning_model and payload.get("model") != self.model:
                raise PolicyError("Model endpoint returned a different or unidentified model.")
            message = payload["choices"][0]["message"]["content"]
            usage = payload.get("usage") or {}
            if not isinstance(message, str) or len(message.encode("utf-8")) > 16384 or not isinstance(usage, dict):
                raise ValueError("invalid model response fields")
        except (KeyError, IndexError, AttributeError, TypeError, ValueError) as error:
            raise PolicyError("Model endpoint returned an unsupported chat response.") from error
        return ModelTurn(message, usage, {"finish_reason": payload["choices"][0].get("finish_reason"),
                                         "returned_model": payload.get("model"),
                                         "reported_cost": payload.get("cost")})


OPENLUX_ENDPOINT = "https://api.openlux.ai/v1/chat/completions"


class OpenLuxChatPolicy(ChatPolicy):
    """Use the already verified SDK settings for every OpenLux role."""

    def __init__(self, *args, timeout=180.0, **kwargs):
        if timeout != 180.0:
            raise ValueError('New OpenLux experiments require a 180-second read timeout.')
        super().__init__(*args, timeout=timeout, **kwargs)
        self.deadline = None

    def __call__(self, context: Mapping[str, Any]) -> ModelTurn:
        import httpx
        from openai import OpenAI

        if self.endpoint != OPENLUX_ENDPOINT:
            raise ValueError("OpenLux policy requires its fixed endpoint.")
        seconds = 180.0 if self.deadline is None else min(180.0, self.deadline - time.monotonic())
        if seconds <= 0:
            from .experiment_policy import BudgetExceeded
            raise BudgetExceeded('Run deadline reached before transport submission.')
        timeout = httpx.Timeout(seconds, connect=min(15.0, seconds),
                                write=min(30.0, seconds), pool=min(15.0, seconds))
        started = time.monotonic()
        wire_observer=getattr(self,'record_wire_request',None)
        try:
            class PacedBody(httpx.SyncByteStream):
                def __init__(self, body):
                    self.body = body

                def __iter__(self):
                    for offset in range(0, len(self.body), 800):
                        yield self.body[offset : offset + 800]
                        if offset + 800 < len(self.body):
                            time.sleep(0.012)

            class PacedTransport(httpx.HTTPTransport):
                def handle_request(self, request):
                    if wire_observer is not None:wire_observer(request.content)
                    request.stream = PacedBody(request.content)
                    return super().handle_request(request)

            with OpenAI(api_key=self.api_key, base_url="https://api.openlux.ai/v1", max_retries=0,
                        timeout=timeout,
                        http_client=httpx.Client(transport=PacedTransport(), timeout=timeout)) as client:
                response = client.chat.completions.with_raw_response.create(
                    **self.request_body(context), timeout=timeout)
                raw = response.http_response.content
                metadata = {"transport": "openai_sdk", "max_retries": 0, "timeout": timeout.as_dict(),
                            "http_status": response.status_code,
                            "request_id": response.headers.get("x-request-id"),
                            "elapsed_seconds": round(time.monotonic() - started, 3)}
        except Exception as error:
            cause = error.__cause__ or error
            detail = {"error_type": type(error).__name__, "cause_type": type(cause).__name__,
                      "elapsed_seconds": round(time.monotonic() - started, 3),
                      "timeout": timeout.as_dict(), "max_retries": 0,
                      "http_status": getattr(error, "status_code", None),
                      "request_id": getattr(error, "request_id", None)}
            # Exception bodies may contain provider text. Only structured fields are logged.
            raise PolicyError("OpenLux request failed " + json.dumps(detail, sort_keys=True)) from None
        turn = self.response_turn(raw)
        return ModelTurn(turn.content, turn.usage, {**turn.metadata, **metadata})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, help="Prepared Java source snapshot")
    parser.add_argument("--output", required=True, help="New directory outside the snapshot")
    parser.add_argument("--endpoint", required=True, help="Full chat-completions URL")
    parser.add_argument("--model", required=True)
    parser.add_argument("--feedback", choices=("fixed", "adaptive"), default="adaptive")
    parser.add_argument("--max-turns", type=int, default=16)
    parser.add_argument("--max-tool-calls", type=int, default=12)
    args = parser.parse_args(argv)
    try:
        policy_type = OpenLuxChatPolicy if args.endpoint == OPENLUX_ENDPOINT else ChatPolicy
        policy = policy_type(args.endpoint, args.model, os.environ.get("WORK1_AGENT_API_KEY", ""))
        summary = run_harness(
            args.repository, args.output, policy,
            feedback=args.feedback,
            limits=HarnessLimits(args.max_turns, args.max_tool_calls),
            policy_id=policy.identity,
        )
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 2
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 2 if summary["stop_reason"] == "MODEL_ERROR" else 0


if __name__ == "__main__":
    raise SystemExit(main())
