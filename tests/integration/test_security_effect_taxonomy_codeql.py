from __future__ import annotations

import csv
import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests" / "fixtures" / "security_effect_taxonomy"
QUERY = (
    ROOT
    / "codeql"
    / "tests"
    / "security_effect"
    / "SecurityEffectContractTest.ql"
)


def _codeql() -> str:
    configured = os.environ.get("CODEQL_BIN", "codeql")
    executable = shutil.which(configured)
    if executable is None:
        pytest.skip("CodeQL executable is unavailable")
    return executable


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def test_typed_primitives_and_analysis_anchor_contract(tmp_path: Path) -> None:
    codeql = _codeql()
    database = tmp_path / "security-effect-db"
    bqrs = tmp_path / "security-effect-contract.bqrs"

    _run(
        [
            codeql,
            "database",
            "create",
            str(database),
            "--language=java",
            f"--source-root={FIXTURE}",
            "--build-mode=none",
            "--overwrite",
        ]
    )
    _run(
        [
            codeql,
            "query",
            "run",
            str(QUERY),
            f"--database={database}",
            f"--output={bqrs}",
        ]
    )
    decoded = _run(
        [codeql, "bqrs", "decode", "--format=csv", "--no-titles", str(bqrs)]
    )
    rows = list(csv.reader(decoded.stdout.splitlines()))

    assert rows
    assert all(len(row) == 10 for row in rows)
    assert not any(row[0] == "negativeSameNames" for row in rows)

    observed = {
        (row[0], row[1], row[2], row[3], row[4], int(row[5]), row[6], row[7])
        for row in rows
    }
    expected = {
        (
            "positiveRegex",
            "java.util.regex.Pattern",
            "compile",
            "REGEX_EVALUATION",
            "JDK_PATTERN_COMPILE_REGEX_ARG0",
            0,
            "arg0",
            "CALL_ARGUMENT",
        ),
        (
            "positiveStringRegex",
            "java.lang.String",
            "replaceAll",
            "REGEX_EVALUATION",
            "JDK_STRING_REGEX_ARG0",
            0,
            "arg0",
            "CALL_ARGUMENT",
        ),
        (
            "positiveDeserialization",
            "java.io.ObjectInputStream",
            "readObject",
            "DESERIALIZATION",
            "JDK_OBJECT_INPUT_STREAM_RECEIVER",
            -1,
            "receiver",
            "RECEIVER",
        ),
        (
            "positiveXmlDeserialization",
            "java.beans.XMLDecoder",
            "readObject",
            "DESERIALIZATION",
            "JDK_XML_DECODER_RECEIVER",
            -1,
            "receiver",
            "RECEIVER",
        ),
        (
            "positiveFilesystem",
            "java.io.File",
            "exists",
            "FILESYSTEM_ACCESS",
            "JDK_FILE_PATH_RECEIVER",
            -1,
            "receiver",
            "RECEIVER",
        ),
        (
            "positiveCrypto",
            "java.security.MessageDigest",
            "getInstance",
            "CRYPTOGRAPHIC_CONFIGURATION",
            "JCA_ALGORITHM_NAME_ARG0",
            0,
            "arg0",
            "CALL_ARGUMENT",
        ),
        (
            "positiveNetwork",
            "java.net.http.HttpClient",
            "send",
            "NETWORK_OUTPUT",
            "JDK_HTTP_CLIENT_REQUEST_ARG0",
            0,
            "arg0",
            "CALL_ARGUMENT",
        ),
        (
            "positiveRendering",
            "jakarta.servlet.http.HttpServletResponse",
            "sendRedirect",
            "RENDERING",
            "SERVLET_RESPONSE_REDIRECT_ARG0",
            0,
            "arg0",
            "CALL_ARGUMENT",
        ),
        (
            "positiveRendering",
            "jakarta.servlet.http.HttpServletResponse",
            "setHeader",
            "RENDERING",
            "SERVLET_RESPONSE_HEADER_VALUE_ARG1",
            1,
            "arg1",
            "CALL_ARGUMENT",
        ),
    }
    assert expected <= observed
    assert all(
        row[8:] == ["CALL_ARGUMENT", "SECURITY_CRITICAL_CALL_VALUE"]
        or row[8:] == ["RECEIVER", "SECURITY_CRITICAL_CALL_VALUE"]
        for row in rows
    )
