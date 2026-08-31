"""Deterministic transport framing normalization for M7 model decisions.

Normalization never repairs decision fields or semantics.  It only unwraps one
unambiguous structured value before the existing strict parser validates it.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any

from java_vuln_research.work1_agent.proposal.model import canonical_json

from .llm_client import LLMResponse, ModelCallError, ModelFailureClass

NORMALIZER_VERSION = "M7_STRUCTURED_OUTPUT_NORMALIZER_V1"
_FENCE = re.compile(r"\A\s*```(?:json)?[ \t]*\r?\n(?P<body>[\s\S]*?)\r?\n```\s*\Z", re.IGNORECASE)


class NormalizationMode(str, Enum):
    BARE_JSON = "BARE_JSON"
    FENCED_JSON = "FENCED_JSON"
    OPENAI_TOOL_CALL = "OPENAI_TOOL_CALL"
    ANTHROPIC_TOOL_USE = "ANTHROPIC_TOOL_USE"
    CONTENT_OBJECT = "CONTENT_OBJECT"


@dataclass(frozen=True, slots=True)
class StructuredOutputNormalization:
    normalized_object: Mapping[str, Any]
    normalization_mode: NormalizationMode
    raw_response_hash: str
    provider_payload_shape: str
    ambiguity_detected: bool
    normalization_warnings: tuple[str, ...] = ()
    normalizer_version: str = NORMALIZER_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "normalizer_version": self.normalizer_version,
            "normalized_object": dict(self.normalized_object),
            "normalization_mode": self.normalization_mode.value,
            "raw_response_hash": self.raw_response_hash,
            "provider_payload_shape": self.provider_payload_shape,
            "ambiguity_detected": self.ambiguity_detected,
            "normalization_warnings": list(self.normalization_warnings),
        }


def _shape(value: Any) -> str:
    if value is None:
        return "TEXT_ONLY"
    if isinstance(value, Mapping):
        return "OBJECT[" + ",".join(sorted(str(key) for key in value)) + "]"
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return f"ARRAY[{len(value)}]"
    return type(value).__name__.upper()


def _raw_hash(response: LLMResponse) -> str:
    material = {
        "raw_text": response.raw_text,
        "provider_payload": response.provider_payload,
    }
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


def _error(response: LLMResponse, kind: ModelFailureClass, message: str) -> ModelCallError:
    return ModelCallError(kind, message, model_call_id=response.model_call_id)


def _decode_object(text: str, response: LLMResponse) -> Mapping[str, Any]:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _error(
            response,
            ModelFailureClass.INVALID_JSON,
            f"invalid JSON at line {exc.lineno} column {exc.colno}",
        ) from exc
    if not isinstance(value, Mapping):
        raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED, "structured output must decode to one object")
    return dict(value)


def _from_text(response: LLMResponse) -> tuple[Mapping[str, Any], NormalizationMode, tuple[str, ...]]:
    text = response.raw_text
    stripped = text.strip()
    if not stripped:
        raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED, "model response has no structured content")
    fenced = _FENCE.fullmatch(text)
    if fenced:
        body = fenced.group("body").strip()
        if "```" in body:
            raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_AMBIGUOUS, "multiple or nested JSON fences are ambiguous")
        return _decode_object(body, response), NormalizationMode.FENCED_JSON, ("JSON_FENCE_REMOVED",)
    if "```" in text:
        fence_count = text.count("```")
        kind = ModelFailureClass.STRUCTURED_OUTPUT_AMBIGUOUS if fence_count > 2 else ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED
        raise _error(response, kind, "fenced JSON must be the entire response and contain exactly one block")
    if not stripped.startswith("{") or not stripped.endswith("}"):
        raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED, "natural language mixed with JSON is not normalized")
    return _decode_object(stripped, response), NormalizationMode.BARE_JSON, ()


def _tool_arguments(arguments: Any, response: LLMResponse) -> Mapping[str, Any]:
    if isinstance(arguments, Mapping):
        return dict(arguments)
    if isinstance(arguments, str):
        return _decode_object(arguments, response)
    raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED, "tool arguments must be a JSON object")


def _from_payload(response: LLMResponse) -> tuple[Mapping[str, Any], NormalizationMode, tuple[str, ...]] | None:
    payload = response.provider_payload
    if payload is None:
        return None
    if isinstance(payload, Mapping):
        tool_calls = payload.get("tool_calls")
        if tool_calls is not None:
            if not isinstance(tool_calls, Sequence) or isinstance(tool_calls, (str, bytes, bytearray)):
                raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED, "OpenAI tool_calls must be an array")
            if len(tool_calls) != 1:
                raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_AMBIGUOUS, "exactly one OpenAI tool call is required")
            call = tool_calls[0]
            function = call.get("function") if isinstance(call, Mapping) else None
            if not isinstance(function, Mapping) or function.get("name") != "submit_agent_decision":
                raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED, "unexpected OpenAI tool call")
            return _tool_arguments(function.get("arguments"), response), NormalizationMode.OPENAI_TOOL_CALL, ()
        if "action_type" in payload:
            return dict(payload), NormalizationMode.CONTENT_OBJECT, ()
        content = payload.get("content")
        if isinstance(content, str):
            return None
        if content is not None:
            payload = content
        else:
            return None
    if not isinstance(payload, Sequence) or isinstance(payload, (str, bytes, bytearray)):
        raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED, "provider structured payload shape is unsupported")
    if len(payload) != 1:
        raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_AMBIGUOUS, "exactly one provider content item is required")
    item = payload[0]
    if not isinstance(item, Mapping):
        raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED, "provider content item must be structured")
    if item.get("type") == "tool_use":
        if item.get("name") != "submit_agent_decision":
            raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED, "unexpected Anthropic tool_use name")
        return _tool_arguments(item.get("input"), response), NormalizationMode.ANTHROPIC_TOOL_USE, ()
    if "action_type" in item:
        return dict(item), NormalizationMode.CONTENT_OBJECT, ()
    structured = item.get("json", item.get("object"))
    if isinstance(structured, Mapping):
        return dict(structured), NormalizationMode.CONTENT_OBJECT, ()
    if item.get("type") == "text" and isinstance(item.get("text"), str):
        projected = LLMResponse(
            response.model_call_id,
            response.request_id,
            response.provider,
            response.model_id,
            str(item["text"]),
            response.wall_clock_seconds,
            response.input_tokens,
            response.output_tokens,
            response.finish_reason,
            response.provenance,
        )
        return _from_text(projected)
    raise _error(response, ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED, "provider content item has no supported object")


class StructuredOutputNormalizer:
    """Unwrap one supported transport envelope without semantic repair."""

    version = NORMALIZER_VERSION

    def normalize(self, response: LLMResponse) -> StructuredOutputNormalization:
        payload_result = _from_payload(response)
        if payload_result is None:
            normalized, mode, warnings = _from_text(response)
        else:
            normalized, mode, warnings = payload_result
            if response.raw_text.strip():
                text_normalized, _, _ = _from_text(response)
                if canonical_json(text_normalized) != canonical_json(normalized):
                    raise _error(
                        response,
                        ModelFailureClass.STRUCTURED_OUTPUT_AMBIGUOUS,
                        "provider payload and text contain different structured objects",
                    )
        return StructuredOutputNormalization(
            normalized_object=normalized,
            normalization_mode=mode,
            raw_response_hash=_raw_hash(response),
            provider_payload_shape=_shape(response.provider_payload),
            ambiguity_detected=False,
            normalization_warnings=warnings,
        )
