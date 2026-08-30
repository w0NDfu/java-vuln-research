"""Provider-neutral LLM interface plus an OpenAI-compatible transport and mock."""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Protocol, Sequence

from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest


class ModelFailureClass(str, Enum):
    MODEL_UNAVAILABLE = "MODEL_UNAVAILABLE"
    MODEL_TIMEOUT = "MODEL_TIMEOUT"
    INVALID_JSON = "INVALID_JSON"
    INVALID_ACTION = "INVALID_ACTION"
    SCHEMA_VIOLATION = "SCHEMA_VIOLATION"
    TOOL_ARGUMENT_INVALID = "TOOL_ARGUMENT_INVALID"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"


class StructuredOutputMode(str, Enum):
    JSON_OBJECT = "JSON_OBJECT"
    TOOL_CALL = "TOOL_CALL"


class ModelCallError(RuntimeError):
    def __init__(
        self,
        failure_class: ModelFailureClass | str,
        message: str,
        *,
        model_call_id: str | None = None,
        retryable: bool = False,
    ) -> None:
        self.failure_class = ModelFailureClass(failure_class)
        self.model_call_id = model_call_id
        self.retryable = retryable
        super().__init__(f"{self.failure_class.value}: {message}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "failure_class": self.failure_class.value,
            "message": str(self).partition(": ")[2],
            "model_call_id": self.model_call_id,
            "retryable": self.retryable,
        }


@dataclass(frozen=True, slots=True)
class LLMClientConfig:
    provider: str
    model_id: str
    base_url: str
    api_key: str = field(repr=False)
    endpoint_url: str | None = None
    api_key_env: str = "M7_LLM_API_KEY"
    timeout_seconds: float = 60.0
    temperature: float = 0.0
    max_output_tokens: int = 2048
    seed: int | None = 0
    structured_output_mode: StructuredOutputMode | str = StructuredOutputMode.JSON_OBJECT

    def __post_init__(self) -> None:
        if not self.provider.strip() or not self.model_id.strip() or not self.api_key:
            raise ValueError("provider, model_id, and API key are required")
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("base_url must be an HTTP(S) origin/path without credentials, query, or fragment")
        if self.endpoint_url is not None:
            endpoint = urllib.parse.urlparse(self.endpoint_url)
            if endpoint.scheme not in {"http", "https"} or not endpoint.netloc or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
                raise ValueError("endpoint_url must be an HTTP(S) URL without credentials, query, or fragment")
        if not 1 <= float(self.timeout_seconds) <= 600:
            raise ValueError("timeout_seconds must be between 1 and 600")
        if not 0 <= float(self.temperature) <= 2:
            raise ValueError("temperature must be between 0 and 2")
        if not 1 <= int(self.max_output_tokens) <= 65_536:
            raise ValueError("max_output_tokens must be between 1 and 65536")
        object.__setattr__(self, "structured_output_mode", StructuredOutputMode(self.structured_output_mode))

    @classmethod
    def from_environment(
        cls,
        env: Mapping[str, str] | None = None,
        *,
        prefix: str = "M7_LLM_",
    ) -> "LLMClientConfig":
        values = os.environ if env is None else env
        required = {name: values.get(prefix + name, "").strip() for name in ("PROVIDER", "MODEL", "BASE_URL", "API_KEY")}
        missing = [prefix + name for name, value in required.items() if not value]
        if missing:
            raise ModelCallError(ModelFailureClass.MODEL_UNAVAILABLE, "missing model runtime configuration: " + ", ".join(missing))
        seed_text = values.get(prefix + "SEED", "0").strip()
        return cls(
            provider=required["PROVIDER"],
            model_id=required["MODEL"],
            base_url=required["BASE_URL"],
            api_key=required["API_KEY"],
            endpoint_url=values.get(prefix + "ENDPOINT", "").strip() or None,
            api_key_env=prefix + "API_KEY",
            timeout_seconds=float(values.get(prefix + "TIMEOUT_SECONDS", "60")),
            temperature=float(values.get(prefix + "TEMPERATURE", "0")),
            max_output_tokens=int(values.get(prefix + "MAX_OUTPUT_TOKENS", "2048")),
            seed=int(seed_text) if seed_text else None,
            structured_output_mode=values.get(prefix + "OUTPUT_MODE", "JSON_OBJECT").strip().upper(),
        )

    def to_manifest_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "exact_model_id": self.model_id,
            "base_url": self.base_url,
            "endpoint_url": self.endpoint_url,
            "endpoint_mode": "EXACT" if self.endpoint_url else "OPENAI_BASE_URL",
            "api_key_env": self.api_key_env,
            "api_key_present": bool(self.api_key),
            "timeout_seconds": self.timeout_seconds,
            "temperature": self.temperature,
            "max_output_tokens": self.max_output_tokens,
            "seed": self.seed,
            "structured_output_mode": self.structured_output_mode.value,
        }


@dataclass(frozen=True, slots=True)
class LLMRequest:
    request_id: str
    project_id: str
    round: int
    system_prompt: str
    observation: Mapping[str, Any]
    attempt: int = 1

    @classmethod
    def create(
        cls,
        *,
        project_id: str,
        round: int,
        system_prompt: str,
        observation: Mapping[str, Any],
        attempt: int = 1,
    ) -> "LLMRequest":
        if not project_id or round < 1 or not system_prompt.strip() or attempt < 1:
            raise ValueError("LLM request requires project, positive round/attempt, and prompt")
        material = {
            "project_id": project_id,
            "round": round,
            "system_prompt": system_prompt,
            "observation": dict(observation),
            "attempt": attempt,
        }
        return cls(stable_digest("modelreq", material), project_id, round, system_prompt, dict(observation), attempt)

    def user_content(self) -> str:
        return canonical_json({"project_id": self.project_id, "round": self.round, "observation": dict(self.observation)})


@dataclass(frozen=True, slots=True)
class LLMResponse:
    model_call_id: str
    request_id: str
    provider: str
    model_id: str
    raw_text: str
    wall_clock_seconds: float
    input_tokens: int = 0
    output_tokens: int = 0
    finish_reason: str | None = None
    provenance: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_call_id": self.model_call_id,
            "request_id": self.request_id,
            "provider": self.provider,
            "model_id": self.model_id,
            "raw_text": self.raw_text,
            "wall_clock_seconds": self.wall_clock_seconds,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "finish_reason": self.finish_reason,
            "provenance": dict(self.provenance),
        }


class LLMClient(Protocol):
    def complete(self, request: LLMRequest) -> LLMResponse: ...


Transport = Callable[[str, Mapping[str, str], bytes, float], Mapping[str, Any]]


def _post_json(url: str, headers: Mapping[str, str], body: bytes, timeout: float) -> Mapping[str, Any]:
    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        raw = response.read()
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("model response body must be a JSON object")
    return value


class OpenAICompatibleLLMClient:
    """One provider implementation behind the provider-neutral ``LLMClient`` protocol."""

    def __init__(self, config: LLMClientConfig, *, transport: Transport | None = None) -> None:
        self.config = config
        self._transport = transport or _post_json

    def complete(self, request: LLMRequest) -> LLMResponse:
        model_call_id = stable_digest(
            "modelcall",
            {
                "request_id": request.request_id,
                "provider": self.config.provider,
                "model_id": self.config.model_id,
                "temperature": self.config.temperature,
                "max_output_tokens": self.config.max_output_tokens,
                "seed": self.config.seed,
                "structured_output_mode": self.config.structured_output_mode.value,
            },
        )
        payload: dict[str, Any] = {
            "model": self.config.model_id,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_content()},
            ],
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_output_tokens,
        }
        if self.config.structured_output_mode is StructuredOutputMode.TOOL_CALL:
            payload["tools"] = [
                {
                    "type": "function",
                    "function": {
                        "name": "submit_agent_decision",
                        "description": "Submit exactly one structured M7 agent decision.",
                        "parameters": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["action_type", "arguments", "proposal", "stop_reason", "reason"],
                            "properties": {
                                "action_type": {
                                    "enum": [
                                        "SEARCH_CODE", "SEARCH_SYMBOLS", "INSPECT_METHOD", "INSPECT_TYPE", "READ_FILE_RANGE",
                                        "GET_CALLERS", "GET_CALLEES", "GET_IMPLEMENTATIONS", "GET_OVERRIDES", "GET_FIELDS", "GET_ANNOTATIONS",
                                        "CODEQL_ENTITY_FACTS", "CODEQL_CALLERS", "CODEQL_CALLEES", "CODEQL_LOCAL_FLOW",
                                        "CODEQL_DATAFLOW_NEIGHBORS", "CODEQL_CFG_NEIGHBORS", "PROPOSE", "STOP",
                                    ]
                                },
                                "arguments": {"type": "object"},
                                "proposal": {"type": ["object", "null"]},
                                "stop_reason": {
                                    "enum": ["PATH_FORMED", "INSUFFICIENT_EVIDENCE", "BUDGET_EXHAUSTED", "NO_FURTHER_ACTION", "TOOL_UNAVAILABLE", "OTHER", None]
                                },
                                "reason": {"type": "string"},
                            },
                        },
                    },
                }
            ]
            payload["tool_choice"] = {"type": "function", "function": {"name": "submit_agent_decision"}}
        else:
            payload["response_format"] = {"type": "json_object"}
        if self.config.seed is not None:
            payload["seed"] = self.config.seed
        endpoint = self.config.endpoint_url or (self.config.base_url.rstrip("/") + "/chat/completions")
        started = time.monotonic()
        try:
            response = self._transport(
                endpoint,
                {"Authorization": "Bearer " + self.config.api_key, "Content-Type": "application/json"},
                canonical_json(payload).encode("utf-8"),
                self.config.timeout_seconds,
            )
        except (TimeoutError, socket.timeout) as exc:
            raise ModelCallError(ModelFailureClass.MODEL_TIMEOUT, "model request timed out", model_call_id=model_call_id, retryable=True) from exc
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (TimeoutError, socket.timeout)):
                raise ModelCallError(ModelFailureClass.MODEL_TIMEOUT, "model request timed out", model_call_id=model_call_id, retryable=True) from exc
            raise ModelCallError(ModelFailureClass.MODEL_UNAVAILABLE, "model endpoint unavailable", model_call_id=model_call_id, retryable=True) from exc
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise ModelCallError(ModelFailureClass.MODEL_UNAVAILABLE, "model transport returned an unusable response", model_call_id=model_call_id, retryable=True) from exc
        try:
            choice = response["choices"][0]
            message = choice["message"]
            if self.config.structured_output_mode is StructuredOutputMode.TOOL_CALL:
                tool_calls = message["tool_calls"]
                matching = [
                    item
                    for item in tool_calls
                    if isinstance(item, Mapping)
                    and isinstance(item.get("function"), Mapping)
                    and item["function"].get("name") == "submit_agent_decision"
                ]
                if len(matching) != 1:
                    raise ValueError("unexpected structured tool call")
                arguments = matching[0]["function"].get("arguments")
                text = canonical_json(arguments) if isinstance(arguments, Mapping) else arguments
            else:
                text = message["content"]
            if not isinstance(text, str) or not text.strip():
                raise ValueError("empty content")
            usage = dict(response.get("usage") or {})
            finish_reason = str(choice["finish_reason"]) if choice.get("finish_reason") is not None else None
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ModelCallError(ModelFailureClass.MODEL_UNAVAILABLE, "model response lacks a usable structured choice", model_call_id=model_call_id) from exc
        return LLMResponse(
            model_call_id=model_call_id,
            request_id=request.request_id,
            provider=self.config.provider,
            model_id=self.config.model_id,
            raw_text=text,
            wall_clock_seconds=round(time.monotonic() - started, 6),
            input_tokens=int(usage.get("prompt_tokens") or 0),
            output_tokens=int(usage.get("completion_tokens") or 0),
            finish_reason=finish_reason,
            provenance={"response_id": response.get("id"), "configuration": self.config.to_manifest_dict()},
        )


MockResponse = str | Mapping[str, Any] | ModelCallError
MockResponseFactory = Callable[[LLMRequest], MockResponse]


class MockLLMClient:
    """Deterministic scripted client; it never accesses network or environment."""

    def __init__(self, responses: Sequence[MockResponse | MockResponseFactory]) -> None:
        self._responses = list(responses)
        self.requests: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        index = len(self.requests) - 1
        if index >= len(self._responses):
            raise ModelCallError(ModelFailureClass.MODEL_UNAVAILABLE, "mock response sequence exhausted", retryable=False)
        scripted = self._responses[index]
        if callable(scripted):
            scripted = scripted(request)
        if isinstance(scripted, ModelCallError):
            raise scripted
        raw_text = canonical_json(scripted) if isinstance(scripted, Mapping) else scripted
        call_id = stable_digest("modelcall", {"request_id": request.request_id, "mock_index": index})
        return LLMResponse(
            model_call_id=call_id,
            request_id=request.request_id,
            provider="deterministic-mock",
            model_id="m7-mock-v1",
            raw_text=raw_text,
            wall_clock_seconds=0.0,
            provenance={"mock_index": index, "deterministic": True},
        )
