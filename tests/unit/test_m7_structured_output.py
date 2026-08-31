from __future__ import annotations

import json
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.agent import (
    ActionType,
    LLMResponse,
    ModelCallError,
    ModelFailureClass,
    NormalizationMode,
    StrictActionParser,
    StructuredOutputNormalizer,
)

ROOT = Path(__file__).parents[2]


def _decision(action: str = "SEARCH_CODE") -> dict[str, object]:
    return {
        "action_type": action,
        "arguments": {"query": "request"} if action == "SEARCH_CODE" else {},
        "proposal": None,
        "stop_reason": None,
        "reason": "Collect bounded evidence.",
    }


def _response(text: str = "", payload: object | None = None) -> LLMResponse:
    return LLMResponse("modelcall-1", "request-1", "test", "model", text, 0.0, provider_payload=payload)


def test_bare_and_whole_fenced_json_normalize() -> None:
    normalizer = StructuredOutputNormalizer()
    bare = normalizer.normalize(_response(json.dumps(_decision())))
    fenced = normalizer.normalize(_response("```json\n" + json.dumps(_decision()) + "\n```"))
    assert bare.normalization_mode is NormalizationMode.BARE_JSON
    assert fenced.normalization_mode is NormalizationMode.FENCED_JSON
    assert fenced.normalization_warnings == ("JSON_FENCE_REMOVED",)
    assert bare.normalized_object == fenced.normalized_object


@pytest.mark.parametrize(
    "text",
    [
        "Here is JSON:\n```json\n{}\n```",
        "text " + json.dumps(_decision()),
        "```json\n{}\n```\n```json\n{}\n```",
    ],
)
def test_prose_mixing_and_multiple_blocks_are_rejected(text: str) -> None:
    with pytest.raises(ModelCallError) as caught:
        StructuredOutputNormalizer().normalize(_response(text))
    assert caught.value.failure_class in {
        ModelFailureClass.STRUCTURED_OUTPUT_AMBIGUOUS,
        ModelFailureClass.STRUCTURED_OUTPUT_UNSUPPORTED,
    }


def test_exactly_one_openai_tool_call_normalizes() -> None:
    payload = {
        "content": "",
        "tool_calls": [
            {"type": "function", "function": {"name": "submit_agent_decision", "arguments": json.dumps(_decision())}}
        ],
    }
    result = StructuredOutputNormalizer().normalize(_response(payload=payload))
    assert result.normalization_mode is NormalizationMode.OPENAI_TOOL_CALL
    assert result.normalized_object == _decision()


def test_exactly_one_anthropic_tool_use_and_content_object_normalize() -> None:
    tool = [{"type": "tool_use", "name": "submit_agent_decision", "input": _decision()}]
    direct = [_decision()]
    assert StructuredOutputNormalizer().normalize(_response(payload=tool)).normalization_mode is NormalizationMode.ANTHROPIC_TOOL_USE
    assert StructuredOutputNormalizer().normalize(_response(payload=direct)).normalization_mode is NormalizationMode.CONTENT_OBJECT


def test_multiple_tool_calls_are_ambiguous() -> None:
    call = {"type": "function", "function": {"name": "submit_agent_decision", "arguments": _decision()}}
    with pytest.raises(ModelCallError) as caught:
        StructuredOutputNormalizer().normalize(_response(payload={"tool_calls": [call, call]}))
    assert caught.value.failure_class is ModelFailureClass.STRUCTURED_OUTPUT_AMBIGUOUS


def test_unknown_action_still_reaches_strict_parser_and_fails() -> None:
    parser = StrictActionParser(ROOT / "schemas")
    with pytest.raises(ModelCallError) as caught:
        parser.parse(_response(json.dumps(_decision("WRITE_CODE"))), project_id="P", round=1)
    assert caught.value.failure_class is ModelFailureClass.INVALID_ACTION


def test_normalized_valid_tool_still_uses_exact_parser_validation() -> None:
    parser = StrictActionParser(ROOT / "schemas")
    response = _response("```json\n" + json.dumps(_decision()) + "\n```")
    action = parser.parse(response, project_id="P", round=1)
    assert action.action_type is ActionType.SEARCH_CODE
    assert action.provenance["structured_output_normalization"]["normalization_mode"] == "FENCED_JSON"


def test_normalized_proposal_cannot_fabricate_evidence_ref() -> None:
    entity_id = "entity-" + "1" * 24
    proposal = {
        "action_type": "PROPOSE",
        "arguments": {},
        "proposal": {
            "proposal_type": "EXTERNAL_INPUT",
            "subject": {"entity_id": entity_id, "role": "RETURN"},
            "source": None,
            "target": None,
            "scope": {"kind": "ENTITY", "entity_ids": [entity_id]},
            "semantic_category": "UNKNOWN",
            "evidence_refs": ["evidence-" + "9" * 24],
            "reason": "Candidate only after grounded inspection.",
            "model_confidence": 0.5,
            "provenance": {},
        },
        "stop_reason": None,
        "reason": "Submit grounded hypothesis.",
    }
    parser = StrictActionParser(ROOT / "schemas")
    with pytest.raises(ModelCallError) as caught:
        parser.parse(
            _response("```json\n" + json.dumps(proposal) + "\n```"),
            project_id="P",
            round=2,
            known_entity_ids={entity_id},
            known_evidence_refs=set(),
        )
    assert caught.value.failure_class is ModelFailureClass.SCHEMA_VIOLATION
