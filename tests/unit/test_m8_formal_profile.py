from __future__ import annotations

import pytest

from java_vuln_research.work1_agent.m8_experiment import (
    COMMON_ARM_CONTRACT_FIELDS,
    G1,
    M1,
    M2,
    ArmExecutionContract,
    ContrastFamily,
    FormalProfile,
    RunKey,
    contrast_registry_sha256,
    formal_arm_registry,
    preregistered_contrasts,
    validate_arm_only_differences,
)


def test_core_and_role_profiles_control_g1_before_freeze() -> None:
    assert FormalProfile.CORE.confirmatory_arm_ids == (
        "m8_s0",
        "m8_s1",
        "m8_m0",
        "m8_m1",
        "m8_m2",
    )
    assert FormalProfile.ROLE.confirmatory_arm_ids == (
        "m8_s0",
        "m8_s1",
        "m8_m0",
        "m8_m1",
        "m8_m2",
        "m8_g1",
    )
    assert "m8_g1" not in formal_arm_registry(FormalProfile.CORE)
    assert formal_arm_registry(FormalProfile.ROLE)["m8_g1"] is G1
    assert G1.formal_profiles == (FormalProfile.ROLE,)


def test_profile_contrasts_have_one_primary_and_frozen_holm_family() -> None:
    core = preregistered_contrasts(FormalProfile.CORE)
    role = preregistered_contrasts(FormalProfile.ROLE)
    assert [item.contrast_id for item in core] == [
        "m1_minus_s1",
        "m1_minus_m0",
        "s1_minus_s0",
        "m2_minus_m1",
        "m2_minus_s1",
    ]
    assert [item.contrast_id for item in role] == [
        *[item.contrast_id for item in core],
        "m1_minus_g1",
    ]
    assert sum(item.family is ContrastFamily.PRIMARY for item in role) == 1
    assert all(
        item.family is ContrastFamily.SECONDARY_HOLM
        for item in role
        if item.contrast_id != "m1_minus_s1"
    )
    assert role[-1].minuend_arm_id == M1.arm_id
    assert role[-1].subtrahend_arm_id == G1.arm_id


def test_profile_and_contrast_hashes_bind_g1_choice() -> None:
    assert FormalProfile.CORE.sha256 != FormalProfile.ROLE.sha256
    assert contrast_registry_sha256(FormalProfile.CORE) != contrast_registry_sha256(
        FormalProfile.ROLE
    )
    assert FormalProfile.CORE.to_dict()["primary_contrast_ids"] == ["m1_minus_s1"]


def test_role_arm_only_audit_requires_g1_in_same_contract_seal() -> None:
    common = {key: f"sealed-{key}" for key in COMMON_ARM_CONTRACT_FIELDS}
    rows = [
        ArmExecutionContract(arm_id, common)
        for arm_id in FormalProfile.ROLE.confirmatory_arm_ids
    ]
    assert (
        validate_arm_only_differences(rows, FormalProfile.ROLE).arm_ids[-1] == "m8_g1"
    )
    with pytest.raises(ValueError, match="missing"):
        validate_arm_only_differences(rows[:-1], FormalProfile.ROLE)


def test_g1_is_same_topology_and_model_family_but_generic_worker_bundle() -> None:
    assert G1.architecture == M1.architecture
    assert G1.feedback_visibility == M1.feedback_visibility
    assert G1.worker_bundle != M1.worker_bundle
    assert len(G1.agents) == len(M1.agents) == 4
    assert {item.model_id for item in G1.agents} == {"claude-sonnet-5"}
    assert M2.feedback_visibility == M1.feedback_visibility


def test_core_run_key_rejects_g1_while_role_accepts_it() -> None:
    key = RunKey(
        study_id="study-role",
        split="formal-holdout",
        subject_id="opaque-subject",
        arm_id="m8_g1",
        replicate_index=1,
        run_id="run-g1-r1",
    )
    with pytest.raises(ValueError, match="not scheduled"):
        key.validate_for_profile(FormalProfile.CORE)
    key.validate_for_profile(FormalProfile.ROLE)


def test_unknown_formal_profile_fails_closed() -> None:
    with pytest.raises(ValueError):
        formal_arm_registry("ROLE_IF_RESULTS_LOOK_GOOD")
