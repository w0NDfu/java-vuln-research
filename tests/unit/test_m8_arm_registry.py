from __future__ import annotations

from dataclasses import replace

import pytest

from java_vuln_research.work1_agent.m8_experiment import (
    ARM_REGISTRY,
    COMMON_ARM_CONTRACT_FIELDS,
    M0,
    M1,
    M2,
    S0,
    S1,
    ArmExecutionContract,
    FeedbackVisibility,
    FormalProfile,
    RunKey,
    arm_registry_sha256,
    arm_registry_to_dict,
    get_arm_spec,
    validate_arm_only_differences,
)
from java_vuln_research.work1_agent.proposal.model import canonical_json


def _common_contract(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        key: f"frozen-{key}" for key in COMMON_ARM_CONTRACT_FIELDS
    }
    result.update(overrides)
    return result


def _contracts(
    profile: FormalProfile, **overrides: object
) -> list[ArmExecutionContract]:
    common = _common_contract()
    return [
        ArmExecutionContract(
            arm_id,
            {**common, **(overrides if arm_id == "m8_m2" else {})},
        )
        for arm_id in profile.confirmatory_arm_ids
    ]


def test_registry_has_canonical_machine_ids_and_frozen_m2_assignment() -> None:
    assert tuple(ARM_REGISTRY) == (
        "m8_n0",
        "m8_h0",
        "m8_s0",
        "m8_s1",
        "m8_m0",
        "m8_m1",
        "m8_m2",
        "m8_g1",
    )
    assert [item.id for item in M2.agents] == [
        "coordinator_agent",
        "input_agent",
        "effect_agent",
        "semantic_bridge_agent",
    ]
    assert all(item.id == item.name for item in M2.agents)
    assert M2.agent("coordinator_agent").model_id == "claude-opus-5"
    assert {item.model_id for item in M2.agents[1:]} == {"claude-sonnet-5"}
    assert {item.model_id for item in M0.agents + M1.agents} == {"claude-sonnet-5"}
    assert get_arm_spec("M2") is M2
    assert get_arm_spec("m8_m2") is M2
    with pytest.raises(ValueError, match="unregistered"):
        get_arm_spec("E1")


def test_feedback_enum_records_projection_not_verifier_execution() -> None:
    assert S0.feedback_visibility is FeedbackVisibility.HIDDEN
    assert S0.verifier_feedback_visible is False
    assert S1.feedback_visibility is FeedbackVisibility.VISIBLE
    assert S1.verifier_feedback_visible is True
    assert M0.verifier_feedback_visible is False
    assert M1.verifier_feedback_visible is True
    assert S0.to_dict()["feedback_visibility"] == "PROPOSAL_RECEIVED_ONLY"
    assert S1.to_dict()["feedback_visibility"] == "DETAILED_VERIFIER_FEEDBACK"


def test_registry_serialization_and_hash_are_canonical() -> None:
    first = arm_registry_to_dict()
    second = arm_registry_to_dict()
    assert canonical_json(first) == canonical_json(second)
    assert arm_registry_sha256() == arm_registry_sha256()
    assert len(arm_registry_sha256()) == 64
    assert all(len(item.sha256) == 64 for item in ARM_REGISTRY.values())


def test_run_key_is_canonical_sealed_and_profile_checked() -> None:
    key = RunKey(
        study_id="study-01",
        split="formal-holdout",
        subject_id="subject-9f31",
        arm_id="M2",
        replicate_index=1,
        run_id="run-0001",
    )
    assert key.arm_id == "m8_m2"
    assert RunKey.from_dict(key.to_sealed_dict()) == key
    key.validate_for_profile(FormalProfile.CORE)

    tampered = key.to_sealed_dict()
    tampered["subject_id"] = "subject-tampered"
    with pytest.raises(ValueError, match="hash is not canonical"):
        RunKey.from_dict(tampered)
    with pytest.raises(ValueError, match="traversal-free"):
        replace(key, subject_id="../oracle")
    with pytest.raises(ValueError, match="replicate_index"):
        replace(key, replicate_index=4)
    invalid_type = key.to_dict()
    invalid_type["replicate_index"] = True
    with pytest.raises(TypeError, match="must be an integer"):
        RunKey.from_dict(invalid_type)


def test_arm_only_difference_audit_accepts_only_complete_equal_core_contracts() -> None:
    rows = _contracts(FormalProfile.CORE)
    audit = validate_arm_only_differences(rows, FormalProfile.CORE)
    assert audit.to_dict()["status"] == "PASS"
    assert audit.arm_ids == FormalProfile.CORE.confirmatory_arm_ids
    assert len(audit.sha256) == 64

    with pytest.raises(ValueError, match="unregistered cross-arm contract difference"):
        validate_arm_only_differences(
            _contracts(
                FormalProfile.CORE, budget_price_table_sha256="larger-m2-budget"
            ),
            FormalProfile.CORE,
        )
    with pytest.raises(ValueError, match="missing"):
        validate_arm_only_differences(rows[:-1], FormalProfile.CORE)


def test_arm_execution_contract_rejects_unknown_or_missing_common_factors() -> None:
    missing = _common_contract()
    missing.pop("schedule_sha256")
    with pytest.raises(ValueError, match="missing"):
        ArmExecutionContract("m8_s0", missing)

    unknown = _common_contract(extra_override="forbidden")
    with pytest.raises(ValueError, match="unknown"):
        ArmExecutionContract("m8_s0", unknown)

    original = ArmExecutionContract("m8_s0", _common_contract())
    assert (
        ArmExecutionContract("m8_s0", original.common_contract).to_dict()
        == original.to_dict()
    )
