from __future__ import annotations

import json

import pytest

from java_vuln_research.work1_agent.m8_experiment.commitments import (
    CommitmentPurpose,
    ManifestCommitment,
    commit_eligibility_manifest,
    commit_manifest,
    commit_split_manifest,
    verify_manifest_commitment,
)


KEY = bytes(range(32))
OTHER_KEY = bytes(reversed(range(32)))


def test_hmac_commitment_is_canonical_and_mapping_order_independent() -> None:
    first = {"schema_version": 1, "lineages": [{"id": "opaque", "split": "formal-holdout"}]}
    second = {"lineages": [{"split": "formal-holdout", "id": "opaque"}], "schema_version": 1}

    one = commit_split_manifest(first, secret_key=KEY)
    two = commit_split_manifest(second, secret_key=KEY)

    assert one == two
    assert len(one.tag) == 64
    assert ManifestCommitment.parse(one.compact()) == one
    assert ManifestCommitment.from_dict(one.to_dict()) == one


def test_commitments_are_purpose_bound_and_do_not_store_key_or_manifest() -> None:
    payload = {"repository_lineage_id": "lineage-secret", "target": "target-secret"}
    split = commit_split_manifest(payload, secret_key=KEY)
    eligibility = commit_eligibility_manifest(payload, secret_key=KEY)

    assert split.tag != eligibility.tag
    public = json.dumps({"split_commitment": split.compact(), "eligibility_commitment": eligibility.compact()})
    assert KEY.hex() not in public
    assert "lineage-secret" not in public
    assert "target-secret" not in public
    assert not hasattr(split, "secret_key")
    assert not hasattr(split, "manifest")


def test_verification_rejects_wrong_key_tamper_and_wrong_purpose() -> None:
    payload = {"schema_version": 1, "primary": ["lineage-a"]}
    commitment = commit_eligibility_manifest(payload, secret_key=KEY)

    assert verify_manifest_commitment(payload, commitment, secret_key=KEY)
    assert not verify_manifest_commitment(payload, commitment, secret_key=OTHER_KEY)
    assert not verify_manifest_commitment(
        {"schema_version": 1, "primary": ["lineage-b"]}, commitment, secret_key=KEY
    )
    assert not verify_manifest_commitment(
        payload,
        commitment,
        secret_key=KEY,
        purpose=CommitmentPurpose.SPLIT,
    )


def test_commitment_requires_at_least_256_bit_key() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        commit_split_manifest({"split": "formal-holdout"}, secret_key=b"short")


def test_commitment_parser_and_manifest_parser_fail_closed() -> None:
    with pytest.raises(ValueError, match="invalid manifest commitment encoding"):
        ManifestCommitment.parse("not-a-commitment")

    valid = commit_manifest(
        {"schema_version": 1}, secret_key=KEY, purpose=CommitmentPurpose.SPLIT
    ).to_dict()
    valid["manifest_sha256"] = "a" * 64
    with pytest.raises(ValueError, match="fields must be exactly"):
        ManifestCommitment.from_dict(valid)


def test_compact_commitment_verification_uses_constant_contract() -> None:
    payload = {"schema_version": 1, "lineages": []}
    commitment = commit_split_manifest(payload, secret_key=KEY)

    assert verify_manifest_commitment(payload, commitment.compact(), secret_key=KEY)
