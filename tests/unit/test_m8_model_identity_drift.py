from __future__ import annotations

from dataclasses import replace

import pytest

from java_vuln_research.work1_agent.m8_experiment import (
    FROZEN_MODEL_IDENTITY_DRIFT_POLICY,
    BackendIdentityStatus,
    ModelBackendIdentity,
    ModelIdentityDecision,
    audit_model_backend_identities,
    enforce_model_identity_drift_policy,
)


def _identity(
    *,
    arm_id: str = "m8_s1",
    agent_id: str = "single_agent",
    configured_model_id: str = "claude-sonnet-5",
    reported: str | None = "claude-sonnet-5-20260815",
    revision: str | None = "deployment-sonnet-r17",
    provider: str = "provider-a",
    attestation_status: BackendIdentityStatus = BackendIdentityStatus.ATTESTED,
) -> ModelBackendIdentity:
    return ModelBackendIdentity(
        block_id="subject-r1-block",
        arm_id=arm_id,
        agent_id=agent_id,
        configured_model_id=configured_model_id,
        provider=provider,
        endpoint_protocol="OPENAI_CHAT_COMPLETIONS_V1",
        response_reported_model=reported,
        provider_deployment_revision=revision,
        attestation_status=attestation_status,
    )


def _stable_block() -> list[ModelBackendIdentity]:
    return [
        _identity(),
        _identity(arm_id="m8_m1", agent_id="coordinator_agent"),
        _identity(
            arm_id="m8_m2",
            agent_id="coordinator_agent",
            configured_model_id="claude-opus-5",
            reported="claude-opus-5-20260815",
            revision="deployment-opus-r9",
        ),
    ]


def test_stable_provider_reported_revisions_are_attested_and_canonical() -> None:
    audit = audit_model_backend_identities(_stable_block())
    assert audit.decision is ModelIdentityDecision.CONTINUE_ATTESTED
    assert audit.reasons == ()
    assert set(audit.signatures_by_configured_model) == {
        "claude-sonnet-5",
        "claude-opus-5",
    }
    assert audit.policy_sha256 == FROZEN_MODEL_IDENTITY_DRIFT_POLICY.sha256
    assert len(audit.sha256) == 64
    assert _stable_block()[0].backend_identity_status is BackendIdentityStatus.ATTESTED


def test_missing_provider_revision_is_explicitly_not_attested_not_invented() -> None:
    observation = _identity(
        revision=None,
        attestation_status=BackendIdentityStatus.NOT_ATTESTED,
    )
    audit = enforce_model_identity_drift_policy([observation])
    assert observation.backend_identity_status is BackendIdentityStatus.NOT_ATTESTED
    assert audit.decision is ModelIdentityDecision.CONTINUE_NOT_ATTESTED
    assert (
        audit.to_dict()["signatures_by_configured_model"]["claude-sonnet-5"][
            "provider_deployment_revision"
        ]
        is None
    )


def test_revision_metadata_without_provider_attestation_remains_not_attested() -> None:
    observation = _identity(attestation_status=BackendIdentityStatus.NOT_ATTESTED)
    audit = audit_model_backend_identities([observation])
    assert audit.decision is ModelIdentityDecision.CONTINUE_NOT_ATTESTED


def test_attested_status_cannot_be_claimed_without_required_provider_identity() -> None:
    with pytest.raises(ValueError, match="ATTESTED backend identity requires"):
        _identity(revision=None)


def test_configured_model_mismatch_pauses_entire_project_block() -> None:
    invalid = _identity(configured_model_id="claude-opus-5")
    audit = audit_model_backend_identities([invalid])
    assert audit.decision is ModelIdentityDecision.PAUSE_ENTIRE_PROJECT_BLOCK
    assert any("expected claude-sonnet-5" in reason for reason in audit.reasons)
    with pytest.raises(ValueError, match="symmetric project-block pause"):
        enforce_model_identity_drift_policy([invalid])


@pytest.mark.parametrize(
    "changed",
    [
        _identity(reported="claude-sonnet-5-20260816"),
        _identity(revision="deployment-sonnet-r18"),
        _identity(provider="provider-b"),
    ],
)
def test_within_block_reported_identity_drift_requires_symmetric_pause(
    changed: ModelBackendIdentity,
) -> None:
    audit = audit_model_backend_identities([_identity(), changed])
    assert audit.decision is ModelIdentityDecision.PAUSE_ENTIRE_PROJECT_BLOCK
    with pytest.raises(ValueError, match="pause"):
        audit.assert_may_continue()


def test_cross_block_signature_change_is_not_silently_accepted() -> None:
    previous = audit_model_backend_identities([_identity()])
    current = _identity(revision="deployment-sonnet-r18")
    audit = audit_model_backend_identities(
        [current], reference_signatures=previous.signatures_by_configured_model
    )
    assert audit.decision is ModelIdentityDecision.PAUSE_ENTIRE_PROJECT_BLOCK
    assert any("across blocks" in reason for reason in audit.reasons)


def test_unregistered_agent_identity_fails_closed_at_block_audit() -> None:
    observation = replace(_identity(), agent_id="hidden_specialist")
    audit = audit_model_backend_identities([observation])
    assert audit.decision is ModelIdentityDecision.PAUSE_ENTIRE_PROJECT_BLOCK
    assert any("unregistered agent" in reason for reason in audit.reasons)
