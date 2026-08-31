from __future__ import annotations

import json
import socket

import pytest

from java_vuln_research.work1_agent.agent import (
    AnthropicMessagesLLMClient,
    LLMAPIProtocol,
    LLMClientConfig,
    LLMRequest,
    MockLLMClient,
    ModelCallError,
    ModelFailureClass,
    OpenAICompatibleLLMClient,
    StructuredOutputMode,
    StructuredOutputNormalizer,
)


def _request() -> LLMRequest:
    return LLMRequest.create(project_id="P", round=1, system_prompt="bounded prompt", observation={"budget": {"rounds": 14}})


def _stop() -> dict[str, object]:
    return {"action_type": "STOP", "arguments": {}, "proposal": None, "stop_reason": "INSUFFICIENT_EVIDENCE", "reason": "No grounded action remains."}


def test_mock_client_is_deterministic_and_exhaustion_is_classified() -> None:
    client = MockLLMClient([_stop()])
    response = client.complete(_request())
    assert StructuredOutputNormalizer().normalize(response).normalized_object == _stop()
    assert response.provider == "deterministic-mock"
    with pytest.raises(ModelCallError) as caught:
        client.complete(_request())
    assert caught.value.failure_class is ModelFailureClass.MODEL_UNAVAILABLE


def test_mock_client_factory_can_use_prior_observation() -> None:
    request = LLMRequest.create(
        project_id="P",
        round=2,
        system_prompt="bounded",
        observation={"recent_feedback": [{"evidence_refs": [{"evidence_id": "evidence-abc"}]}]},
    )
    client = MockLLMClient([
        lambda current: {
            **_stop(),
            "reason": current.observation["recent_feedback"][0]["evidence_refs"][0]["evidence_id"],
        }
    ])

    response = client.complete(request)

    assert json.loads(response.raw_text)["reason"] == "evidence-abc"


def test_config_comes_from_environment_and_never_serializes_secret() -> None:
    config = LLMClientConfig.from_environment(
        {
            "M7_LLM_PROVIDER": "compatible",
            "M7_LLM_MODEL": "exact-model-v1",
            "M7_LLM_BASE_URL": "https://model.example/v1",
            "M7_LLM_ENDPOINT": "https://model.example/v1/chat/completions",
            "M7_LLM_API_KEY": "super-secret",
            "M7_LLM_TEMPERATURE": "0.1",
            "M7_LLM_MAX_OUTPUT_TOKENS": "1024",
            "M7_LLM_SEED": "7",
            "M7_LLM_OUTPUT_MODE": "tool_call",
            "M7_LLM_API_PROTOCOL": "anthropic",
        }
    )
    manifest = config.to_manifest_dict()
    assert manifest["exact_model_id"] == "exact-model-v1"
    assert manifest["endpoint_url"] == "https://model.example/v1/chat/completions"
    assert manifest["endpoint_mode"] == "EXACT"
    assert manifest["seed"] == 7
    assert manifest["structured_output_mode"] == "TOOL_CALL"
    assert manifest["api_protocol"] == "ANTHROPIC"
    assert "super-secret" not in json.dumps(manifest)
    assert config.api_key_env == "M7_LLM_API_KEY"


def test_omitted_environment_seed_remains_none() -> None:
    config = LLMClientConfig.from_environment(
        {
            "M7_LLM_PROVIDER": "compatible",
            "M7_LLM_MODEL": "exact-model-v1",
            "M7_LLM_BASE_URL": "https://model.example/v1",
            "M7_LLM_API_KEY": "super-secret",
        }
    )

    assert config.seed is None
    assert config.to_manifest_dict()["seed"] is None


def test_missing_environment_configuration_is_model_unavailable() -> None:
    with pytest.raises(ModelCallError) as caught:
        LLMClientConfig.from_environment({})
    assert caught.value.failure_class is ModelFailureClass.MODEL_UNAVAILABLE


def test_openai_compatible_transport_is_auditable_without_leaking_key() -> None:
    captured: dict[str, object] = {}

    def transport(url: str, headers: dict[str, str], body: bytes, timeout: float) -> dict[str, object]:
        captured.update(url=url, headers=headers, body=json.loads(body), timeout=timeout)
        return {
            "id": "response-1",
            "choices": [{"message": {"content": json.dumps(_stop())}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 7},
        }

    config = LLMClientConfig("compatible", "exact-model", "https://model.example/v1", "secret", timeout_seconds=10)
    response = OpenAICompatibleLLMClient(config, transport=transport).complete(_request())
    assert captured["url"] == "https://model.example/v1/chat/completions"
    assert captured["body"]["response_format"] == {"type": "json_object"}
    assert response.input_tokens == 12 and response.output_tokens == 7
    assert "secret" not in json.dumps(response.to_dict())


def test_exact_endpoint_is_used_verbatim_without_concatenation() -> None:
    captured: dict[str, object] = {}

    def transport(url: str, _headers: dict[str, str], _body: bytes, _timeout: float) -> dict[str, object]:
        captured["url"] = url
        return {
            "id": "response-exact",
            "choices": [{"message": {"content": json.dumps(_stop())}, "finish_reason": "stop"}],
        }

    endpoint = "https://api.openlux.ai/v1/chat/completions"
    config = LLMClientConfig(
        "openlux",
        "claude-opus-5",
        "https://api.openlux.ai/v1",
        "secret",
        endpoint_url=endpoint,
    )

    OpenAICompatibleLLMClient(config, transport=transport).complete(_request())

    assert captured["url"] == endpoint
    assert config.to_manifest_dict()["endpoint_mode"] == "EXACT"


@pytest.mark.parametrize("tool_arguments", [json.dumps(_stop()), _stop()])
def test_tool_call_mode_forces_and_reads_one_structured_decision(tool_arguments: object) -> None:
    captured: dict[str, object] = {}

    def transport(_url: str, _headers: dict[str, str], body: bytes, _timeout: float) -> dict[str, object]:
        captured["body"] = json.loads(body)
        return {
            "id": "response-tool",
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "type": "function",
                                "function": {"name": "submit_agent_decision", "arguments": tool_arguments},
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
        }

    config = LLMClientConfig(
        "openlux",
        "claude-opus-5",
        "https://api.openlux.ai/v1",
        "secret",
        structured_output_mode=StructuredOutputMode.TOOL_CALL,
    )

    response = OpenAICompatibleLLMClient(config, transport=transport).complete(_request())

    body = captured["body"]
    assert "response_format" not in body
    assert body["tool_choice"]["function"]["name"] == "submit_agent_decision"
    assert body["tools"][0]["function"]["parameters"] == {"type": "object"}
    assert StructuredOutputNormalizer().normalize(response).normalized_object == _stop()


def test_anthropic_messages_tool_mode_reads_tool_use_input() -> None:
    captured: dict[str, object] = {}

    def transport(url: str, headers: dict[str, str], body: bytes, _timeout: float) -> dict[str, object]:
        captured.update(url=url, headers=headers, body=json.loads(body))
        return {
            "id": "msg-1",
            "content": [{"type": "tool_use", "name": "submit_agent_decision", "input": _stop()}],
            "stop_reason": "tool_use",
            "usage": {"input_tokens": 20, "output_tokens": 8},
        }

    config = LLMClientConfig(
        "openlux",
        "claude-opus-5",
        "https://api.openlux.ai/v1",
        "secret",
        endpoint_url="https://api.openlux.ai/v1/messages",
        structured_output_mode=StructuredOutputMode.TOOL_CALL,
        api_protocol=LLMAPIProtocol.ANTHROPIC,
    )

    response = AnthropicMessagesLLMClient(config, transport=transport).complete(_request())

    assert captured["url"] == "https://api.openlux.ai/v1/messages"
    assert captured["body"]["tool_choice"] == {"type": "tool", "name": "submit_agent_decision"}
    assert captured["body"]["tools"][0]["input_schema"] == {"type": "object"}
    assert captured["headers"]["anthropic-version"] == "2023-06-01"
    assert StructuredOutputNormalizer().normalize(response).normalized_object == _stop()
    assert response.input_tokens == 20 and response.output_tokens == 8


def test_transport_timeout_has_explicit_failure_class() -> None:
    def timeout(*_args: object) -> dict[str, object]:
        raise socket.timeout()

    config = LLMClientConfig("compatible", "model", "https://model.example/v1", "secret")
    with pytest.raises(ModelCallError) as caught:
        OpenAICompatibleLLMClient(config, transport=timeout).complete(_request())
    assert caught.value.failure_class is ModelFailureClass.MODEL_TIMEOUT
    assert caught.value.retryable is True
