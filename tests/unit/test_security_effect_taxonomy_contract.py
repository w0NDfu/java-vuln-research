from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / "codeql" / "security_effect" / "SecurityEffectModels.qll"
DISCOVERY = ROOT / "codeql" / "security_effect" / "SecurityEffectDiscovery.ql"
ENDPOINTS = ROOT / "codeql" / "candidate_path" / "EndpointCandidates.qll"
FIXTURE = (
    ROOT
    / "tests"
    / "fixtures"
    / "security_effect_taxonomy"
    / "src"
    / "toy"
    / "SecurityEffectCases.java"
)
CONTRACT_QUERY = (
    ROOT
    / "codeql"
    / "tests"
    / "security_effect"
    / "SecurityEffectContractTest.ql"
)


def test_discovery_and_endpoint_mapping_share_one_taxonomy() -> None:
    discovery = DISCOVERY.read_text(encoding="utf-8")
    endpoints = ENDPOINTS.read_text(encoding="utf-8")

    assert "import security_effect.SecurityEffectModels" in discovery
    assert "import security_effect.SecurityEffectModels" in endpoints
    assert "securityEffectCall(" in discovery
    assert "securityEffectCall(" in endpoints
    assert "predicate isFilesystemEffect(" not in endpoints
    assert "predicate effectTypeFor(" not in endpoints


def test_generic_families_are_type_qualified_and_have_stable_rule_ids() -> None:
    model = MODEL.read_text(encoding="utf-8")

    expected = {
        "REGEX_EVALUATION": "JDK_PATTERN_COMPILE_REGEX_ARG0",
        "DESERIALIZATION": "JDK_OBJECT_INPUT_STREAM_RECEIVER",
        "NETWORK_OUTPUT": "JDK_HTTP_CLIENT_REQUEST_ARG0",
        "CRYPTOGRAPHIC_CONFIGURATION": "JCA_ALGORITHM_NAME_ARG0",
        "FILESYSTEM_ACCESS": "JDK_CLASSLOADER_RESOURCE_NAME_ARG0",
        "RENDERING": "SERVLET_RESPONSE_HEADER_VALUE_ARG1",
    }
    for effect_type, rule_id in expected.items():
        assert effect_type in model
        assert rule_id in model

    for qualified_type in (
        '"java.util.regex", "Pattern"',
        '"java.io", "ObjectInputStream"',
        '"java.net.http", "HttpClient"',
        '"javax.crypto", ["Cipher", "KeyGenerator"]',
        '"java.lang", "ClassLoader"',
        '"HttpServletResponse"',
    ):
        assert qualified_type in model

    assert 'rule = "SERVLET_RESPONSE_HEADER_VALUE_ARG1"' in model
    assert 'index = 1' in model
    assert 'rule = "JDK_PROCESS_BUILDER_START_RECEIVER"' in model
    assert 'index = -1' in model


def test_fixture_contains_positive_and_same_name_wrong_type_cases() -> None:
    fixture = FIXTURE.read_text(encoding="utf-8")

    for positive in (
        "Pattern.compile(regex, Pattern.CASE_INSENSITIVE)",
        "input.readObject()",
        "client.send(request",
        "MessageDigest.getInstance(algorithm)",
        "new File(path).exists()",
        "response.sendRedirect(location)",
        'response.setHeader("X-Test", headerValue)',
    ):
        assert positive in fixture

    for negative in (
        "FakePattern.compile(value)",
        "new FakeReader().readObject()",
        "new FakeClient().send(value)",
        "new FakeFile().exists()",
        "FakeCipher.getInstance(value)",
        "new FakeResponse().sendRedirect(value)",
        'new FakeResponse().setHeader("X-Test", value)',
    ):
        assert negative in fixture


def test_executable_contract_query_checks_analysis_anchor_metadata() -> None:
    query = CONTRACT_QUERY.read_text(encoding="utf-8")

    assert "securityEffectCall(" in query
    assert "securityEffectAnalysisAnchor(" in query
    assert "mappedCallIdentity = seCallIdentity(call)" in query
    assert "argumentIndex = criticalIndex" in query
    assert 'mappingReason = "SECURITY_CRITICAL_CALL_VALUE"' in query
