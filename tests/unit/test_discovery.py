from __future__ import annotations

from java_vuln_research.discovery import (
    deduplicate_candidates,
    external_candidate,
    security_effect_candidate,
)


def test_external_candidate_has_stable_detector_schema() -> None:
    row = {
        "mechanism": "SERVLET_PARAMETER",
        "entity": "demo.Controller.read -> getParameter",
        "evidence_kind": "SERVLET_ACCESSOR_CALL",
        "file": "src/main/java/demo/Controller.java",
        "line": "17",
        "source": "STATIC",
    }

    first = external_candidate(project="P001", revision="abc", row=row)
    second = external_candidate(project="P001", revision="abc", row=row)

    assert first == second
    assert set(first) == {
        "candidate_id",
        "kind",
        "entity",
        "mechanism",
        "confidence",
        "evidence",
        "source",
    }
    assert first["kind"] == "EXTERNAL_INPUT"
    assert first["confidence"] == "HIGH"
    assert first["evidence"][0]["project"] == "P001"


def test_security_effect_preserves_critical_parameter_role() -> None:
    row = {
        "effect_type": "PROCESS_EXECUTION",
        "mechanism": "RUNTIME_EXEC",
        "entity": "demo.CommandService.run PROJECT_SPECIFIC_PROCESS_EXECUTION",
        "critical_role": "parameter:command",
        "evidence_kind": "DIRECT_PARAMETER_EFFECT_WRAPPER",
        "file": "src/main/java/demo/CommandService.java",
        "line": "21",
        "source": "STATIC_DERIVED",
        "primitive_rule_id": "JDK_RUNTIME_EXEC_ARG0",
        "callee_identity": "java.lang.Runtime.exec/1",
        "method_identity": "demo.CommandService.run/1",
        "call_identity": "java.lang.Runtime.exec/1@src/main/java/demo/CommandService.java:21",
        "argument_index": "0",
        "anchor_kind": "CALL_ARGUMENT",
    }

    candidate = security_effect_candidate(project="P002", revision="def", row=row)

    assert candidate["effect_type"] == "PROCESS_EXECUTION"
    assert candidate["critical_roles"] == ["parameter:command"]
    assert candidate["source"] == "STATIC_DERIVED"
    assert candidate["project_id"] == "P002"
    assert candidate["critical_role"] == "parameter:command"
    assert candidate["callee_identity"] == "java.lang.Runtime.exec/1"
    assert candidate["method_identity"] == "demo.CommandService.run/1"
    assert candidate["argument_index"] == 0
    assert candidate["anchor_kind"] == "CALL_ARGUMENT"
    assert candidate["location"] == {
        "file": "src/main/java/demo/CommandService.java",
        "line": 21,
    }
    assert candidate["discovery_route"] == "ROUTE_A"
    assert candidate["primitive_rule_id"] == "JDK_RUNTIME_EXEC_ARG0"
    assert candidate["provenance"]["revision"] == "def"


def test_deduplicate_candidates_is_stable_and_sorted() -> None:
    rows = [
        {"candidate_id": "ext-b", "value": 2},
        {"candidate_id": "ext-a", "value": 1},
        {"candidate_id": "ext-b", "value": 2},
    ]

    assert deduplicate_candidates(rows) == [
        {"candidate_id": "ext-a", "value": 1},
        {"candidate_id": "ext-b", "value": 2},
    ]

