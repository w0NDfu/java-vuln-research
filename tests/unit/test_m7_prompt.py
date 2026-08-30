from __future__ import annotations

from java_vuln_research.work1_agent.agent import PROMPT_VERSION, build_system_prompt, prompt_sha256


def test_prompt_is_benchmark_agnostic_and_requires_evidence_first() -> None:
    prompt = build_system_prompt([{"name": "SEARCH_CODE", "bounds": {"max_hits": 100}}])
    lowered = prompt.casefold()
    assert "collect evidence before proposing" in lowered
    assert "candidate path is not a confirmed vulnerability" in lowered
    assert "do not infer that a relation is absent" in lowered
    assert "direct input-to-effect shortcut" in lowered
    assert "exact name of one tool" in lowered
    assert "never return tool_call" in lowered
    assert "proposal must have exactly these fields" in lowered
    assert "do not return proposal_id" in lowered
    assert "gap_type" in lowered
    assert prompt.endswith("Return no code fence, Markdown label, preface, or trailing prose.")
    assert PROMPT_VERSION == "M7_SECURITY_EXPLORATION_V2"
    assert "retrofit" not in lowered and "hutool" not in lowered
    assert "diagnostic_proposals" not in lowered and "root-cause table" not in lowered
    assert prompt_sha256(prompt) == prompt_sha256(prompt)
