"""Evaluator-side keyed commitments for frozen M8 manifests.

The secret key and committed payload never become fields of the returned
commitment.  Detector-side artifacts may therefore persist ``compact()``
without gaining access to evaluator data or to an enumerable plain digest.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping, Protocol, runtime_checkable

from java_vuln_research.work1_agent.proposal.model import canonical_json


COMMITMENT_SCHEMA_VERSION = 1
COMMITMENT_ALGORITHM = "HMAC-SHA-256"
MINIMUM_COMMITMENT_KEY_BYTES = 32
_DOMAIN = b"java-vuln-research/work1/m8/manifest-commitment/v1\x00"
_TAG_RE = re.compile(r"^[0-9a-f]{64}$")


class CommitmentPurpose(str, Enum):
    SPLIT = "SPLIT"
    ELIGIBILITY = "ELIGIBILITY"


@runtime_checkable
class CanonicalManifest(Protocol):
    def to_dict(self) -> Mapping[str, Any]: ...


def _purpose(value: CommitmentPurpose | str) -> CommitmentPurpose:
    try:
        return value if isinstance(value, CommitmentPurpose) else CommitmentPurpose(str(value))
    except ValueError as exc:
        raise ValueError("unsupported manifest commitment purpose") from exc


def _secret_key(value: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise TypeError("secret_key must be bytes-like")
    key = bytes(value)
    if len(key) < MINIMUM_COMMITMENT_KEY_BYTES:
        raise ValueError(f"secret_key must contain at least {MINIMUM_COMMITMENT_KEY_BYTES} bytes")
    return key


def _payload(value: Mapping[str, Any] | CanonicalManifest) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        result = dict(value)
    elif isinstance(value, CanonicalManifest):
        result = dict(value.to_dict())
    else:
        raise TypeError("manifest must be a mapping or expose to_dict()")
    canonical_json(result)
    return result


def _message(value: Mapping[str, Any] | CanonicalManifest, purpose: CommitmentPurpose) -> bytes:
    encoded = canonical_json(_payload(value)).encode("utf-8")
    return _DOMAIN + purpose.value.encode("ascii") + b"\x00" + encoded


@dataclass(frozen=True, slots=True)
class ManifestCommitment:
    """A public, purpose-bound HMAC tag without key or manifest material."""

    purpose: CommitmentPurpose
    tag: str
    algorithm: str = COMMITMENT_ALGORITHM
    schema_version: int = COMMITMENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or not isinstance(self.schema_version, int):
            raise TypeError("manifest commitment schema_version must be an integer")
        if self.schema_version != COMMITMENT_SCHEMA_VERSION:
            raise ValueError("unsupported manifest commitment schema version")
        if not isinstance(self.algorithm, str):
            raise TypeError("manifest commitment algorithm must be a string")
        if self.algorithm != COMMITMENT_ALGORITHM:
            raise ValueError("unsupported manifest commitment algorithm")
        if not isinstance(self.purpose, CommitmentPurpose):
            raise TypeError("purpose must be a CommitmentPurpose")
        if not isinstance(self.tag, str):
            raise TypeError("manifest commitment tag must be a string")
        if not _TAG_RE.fullmatch(self.tag):
            raise ValueError("manifest commitment tag must be 64 lowercase hex characters")

    def compact(self) -> str:
        return f"m8c{self.schema_version}:{self.purpose.value}:{self.algorithm}:{self.tag}"

    @classmethod
    def parse(cls, value: str) -> "ManifestCommitment":
        if not isinstance(value, str):
            raise TypeError("manifest commitment must be a string")
        parts = value.split(":")
        if len(parts) != 4 or parts[0] != f"m8c{COMMITMENT_SCHEMA_VERSION}":
            raise ValueError("invalid manifest commitment encoding")
        return cls(
            purpose=_purpose(parts[1]),
            algorithm=parts[2],
            tag=parts[3],
            schema_version=COMMITMENT_SCHEMA_VERSION,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "algorithm": self.algorithm,
            "purpose": self.purpose.value,
            "tag": self.tag,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ManifestCommitment":
        expected = {"schema_version", "algorithm", "purpose", "tag"}
        keys = set(value)
        if keys != expected:
            raise ValueError(
                f"manifest commitment fields must be exactly {sorted(expected)}; "
                f"missing={sorted(expected - keys)} unknown={sorted(keys - expected)}"
            )
        if any(not isinstance(value[name], str) for name in ("purpose", "tag", "algorithm")):
            raise TypeError("manifest commitment purpose, tag, and algorithm must be strings")
        schema_version = value["schema_version"]
        if isinstance(schema_version, bool) or not isinstance(schema_version, int):
            raise TypeError("manifest commitment schema_version must be an integer")
        return cls(
            purpose=_purpose(value["purpose"]),
            tag=value["tag"],
            algorithm=value["algorithm"],
            schema_version=schema_version,
        )


def commit_manifest(
    manifest: Mapping[str, Any] | CanonicalManifest,
    *,
    secret_key: bytes | bytearray | memoryview,
    purpose: CommitmentPurpose | str,
) -> ManifestCommitment:
    resolved_purpose = _purpose(purpose)
    tag = hmac.new(_secret_key(secret_key), _message(manifest, resolved_purpose), hashlib.sha256).hexdigest()
    return ManifestCommitment(purpose=resolved_purpose, tag=tag)


def verify_manifest_commitment(
    manifest: Mapping[str, Any] | CanonicalManifest,
    commitment: ManifestCommitment | str,
    *,
    secret_key: bytes | bytearray | memoryview,
    purpose: CommitmentPurpose | str | None = None,
) -> bool:
    parsed = ManifestCommitment.parse(commitment) if isinstance(commitment, str) else commitment
    if not isinstance(parsed, ManifestCommitment):
        raise TypeError("commitment must be a ManifestCommitment or compact string")
    if purpose is not None and parsed.purpose is not _purpose(purpose):
        return False
    expected = commit_manifest(manifest, secret_key=secret_key, purpose=parsed.purpose)
    return hmac.compare_digest(parsed.tag, expected.tag)


def commit_split_manifest(
    manifest: Mapping[str, Any] | CanonicalManifest,
    *,
    secret_key: bytes | bytearray | memoryview,
) -> ManifestCommitment:
    return commit_manifest(manifest, secret_key=secret_key, purpose=CommitmentPurpose.SPLIT)


def commit_eligibility_manifest(
    manifest: Mapping[str, Any] | CanonicalManifest,
    *,
    secret_key: bytes | bytearray | memoryview,
) -> ManifestCommitment:
    return commit_manifest(manifest, secret_key=secret_key, purpose=CommitmentPurpose.ELIGIBILITY)
