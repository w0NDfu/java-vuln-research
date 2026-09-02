"""Frozen arm registry and comparison contracts for the M8 study.

This module is intentionally independent from either detector runtime.  It is
the fail-closed control plane used to decide which runtimes may be compared;
it does not project verifier feedback into a model observation.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any

from java_vuln_research.work1_agent.m8_multiagent.agent_registry import (
    EFFECT_AGENT,
    INPUT_AGENT,
    SEMANTIC_BRIDGE_AGENT,
    AgentModelSpec,
)
from java_vuln_research.work1_agent.proposal.model import canonical_json

ARM_REGISTRY_SCHEMA_VERSION = 1
RUN_KEY_SCHEMA_VERSION = 1
SONNET_MODEL_ID = "claude-sonnet-5"
OPUS_MODEL_ID = "claude-opus-5"


class FormalProfile(str, Enum):
    """The pre-freeze choice controlling whether G1 is confirmatory."""

    CORE = "CORE"
    ROLE = "ROLE"

    @property
    def confirmatory_arm_ids(self) -> tuple[str, ...]:
        return confirmatory_arm_ids(self)

    @property
    def contrasts(self) -> tuple[PreRegisteredContrast, ...]:
        return preregistered_contrasts(self)

    def to_dict(self) -> dict[str, Any]:
        contrasts = self.contrasts
        return {
            "formal_profile": self.value,
            "confirmatory_arm_ids": list(self.confirmatory_arm_ids),
            "primary_contrast_ids": [
                item.contrast_id
                for item in contrasts
                if item.family is ContrastFamily.PRIMARY
            ],
            "secondary_holm_contrast_ids": [
                item.contrast_id
                for item in contrasts
                if item.family is ContrastFamily.SECONDARY_HOLM
            ],
        }

    @property
    def sha256(self) -> str:
        return _sha256(self.to_dict())


class FeedbackVisibility(str, Enum):
    """Model-visible projection of verifier results.

    HIDDEN still permits action-required repository/CodeQL results, parser
    errors, security-boundary errors, and a fixed ``PROPOSAL_RECEIVED``
    receipt.  It never means that verification is skipped.
    """

    NOT_APPLICABLE = "NOT_APPLICABLE"
    HIDDEN = "PROPOSAL_RECEIVED_ONLY"
    VISIBLE = "DETAILED_VERIFIER_FEEDBACK"

    @property
    def verifier_feedback_visible(self) -> bool | None:
        if self is FeedbackVisibility.NOT_APPLICABLE:
            return None
        return self is FeedbackVisibility.VISIBLE


class ArmArchitecture(str, Enum):
    NATIVE_CODEQL = "NATIVE_CODEQL"
    HISTORICAL_IMPORT = "HISTORICAL_IMPORT"
    SINGLE_AGENT = "SINGLE_AGENT"
    MULTI_AGENT = "MULTI_AGENT"


class WorkerBundle(str, Enum):
    NOT_APPLICABLE = "NOT_APPLICABLE"
    SINGLE_REASONER = "SINGLE_REASONER"
    ROLE_SPECIALISTS = "ROLE_SPECIALISTS"
    GENERIC_WORKERS = "GENERIC_WORKERS"


class ArmCausalStatus(str, Enum):
    DETERMINISTIC_REFERENCE = "DETERMINISTIC_REFERENCE"
    HISTORICAL_ONLY = "HISTORICAL_ONLY"
    CONFIRMATORY = "CONFIRMATORY"
    CONFIRMATORY_SYSTEM = "CONFIRMATORY_SYSTEM"
    PROFILE_CONDITIONAL = "PROFILE_CONDITIONAL"


class ReplicatePolicy(str, Enum):
    DETERMINISTIC_ONCE = "DETERMINISTIC_ONCE"
    HISTORICAL_IMPORT_ONCE = "HISTORICAL_IMPORT_ONCE"
    SEPARATELY_INITIALIZED_R3 = "SEPARATELY_INITIALIZED_R3"


@dataclass(frozen=True, slots=True)
class ArmSpec:
    arm_id: str
    shorthand: str
    architecture: ArmArchitecture
    worker_bundle: WorkerBundle
    feedback_visibility: FeedbackVisibility
    causal_status: ArmCausalStatus
    replicate_policy: ReplicatePolicy
    agents: tuple[AgentModelSpec, ...] = ()
    formal_profiles: tuple[FormalProfile, ...] = ()
    description: str = ""
    schema_version: int = ARM_REGISTRY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != ARM_REGISTRY_SCHEMA_VERSION:
            raise ValueError("unsupported arm registry schema version")
        expected_arm_id = f"m8_{self.shorthand.lower()}"
        if self.arm_id != expected_arm_id:
            raise ValueError(f"arm_id must be canonical: {expected_arm_id}")
        if not re.fullmatch(r"[A-Z][A-Z0-9]*", self.shorthand):
            raise ValueError("arm shorthand must be uppercase alphanumeric")
        if not self.description.strip():
            raise ValueError("arm description is required")
        if len({item.id for item in self.agents}) != len(self.agents):
            raise ValueError("arm agent identities must be unique")
        if any(item.id != item.name for item in self.agents):
            raise ValueError("arm agent id and name must be identical")

        profiles = tuple(FormalProfile(item) for item in self.formal_profiles)
        if len(set(profiles)) != len(profiles):
            raise ValueError("formal_profiles must not contain duplicates")
        object.__setattr__(self, "formal_profiles", profiles)

        stochastic = self.replicate_policy is ReplicatePolicy.SEPARATELY_INITIALIZED_R3
        if stochastic != bool(profiles):
            raise ValueError(
                "only stochastic confirmatory arms belong to formal profiles"
            )
        if stochastic and self.feedback_visibility is FeedbackVisibility.NOT_APPLICABLE:
            raise ValueError("confirmatory arms require an explicit feedback contract")
        if (
            not stochastic
            and self.feedback_visibility is not FeedbackVisibility.NOT_APPLICABLE
        ):
            raise ValueError(
                "reference and historical arms do not define feedback treatment"
            )

        expected_agent_count = {
            ArmArchitecture.NATIVE_CODEQL: 0,
            ArmArchitecture.HISTORICAL_IMPORT: 0,
            ArmArchitecture.SINGLE_AGENT: 1,
            ArmArchitecture.MULTI_AGENT: 4,
        }[self.architecture]
        if len(self.agents) != expected_agent_count:
            raise ValueError(
                f"{self.architecture.value} requires exactly {expected_agent_count} registered agents"
            )

    def agent(self, agent_id: str) -> AgentModelSpec:
        matches = [item for item in self.agents if item.id == agent_id]
        if len(matches) != 1:
            raise KeyError(f"arm {self.arm_id} has no unique agent {agent_id!r}")
        return matches[0]

    @property
    def verifier_feedback_visible(self) -> bool | None:
        return self.feedback_visibility.verifier_feedback_visible

    def treatment_dict(self) -> dict[str, Any]:
        """Return only execution factors, excluding labels and causal metadata."""

        return {
            "architecture": self.architecture.value,
            "worker_bundle": self.worker_bundle.value,
            "verifier_feedback_visible": self.verifier_feedback_visible,
            "feedback_visibility": self.feedback_visibility.value,
            "agent_assignments": [item.to_dict() for item in self.agents],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "arm_id": self.arm_id,
            "shorthand": self.shorthand,
            "architecture": self.architecture.value,
            "worker_bundle": self.worker_bundle.value,
            "feedback_visibility": self.feedback_visibility.value,
            "verifier_feedback_visible": self.verifier_feedback_visible,
            "causal_status": self.causal_status.value,
            "replicate_policy": self.replicate_policy.value,
            "agents": [item.to_dict() for item in self.agents],
            "formal_profiles": [item.value for item in self.formal_profiles],
            "description": self.description,
        }

    @property
    def sha256(self) -> str:
        return _sha256(self.to_dict())


SINGLE_SONNET_AGENT = AgentModelSpec(
    id="single_agent", name="single_agent", model_id=SONNET_MODEL_ID
)
SONNET_COORDINATOR_AGENT = AgentModelSpec(
    id="coordinator_agent", name="coordinator_agent", model_id=SONNET_MODEL_ID
)
OPUS_COORDINATOR_AGENT = AgentModelSpec(
    id="coordinator_agent", name="coordinator_agent", model_id=OPUS_MODEL_ID
)
GENERIC_WORKER_AGENTS = tuple(
    AgentModelSpec(
        id=f"generic_worker_{index}",
        name=f"generic_worker_{index}",
        model_id=SONNET_MODEL_ID,
    )
    for index in range(1, 4)
)
ROLE_SPECIALIST_AGENTS = (INPUT_AGENT, EFFECT_AGENT, SEMANTIC_BRIDGE_AGENT)


N0 = ArmSpec(
    arm_id="m8_n0",
    shorthand="N0",
    architecture=ArmArchitecture.NATIVE_CODEQL,
    worker_bundle=WorkerBundle.NOT_APPLICABLE,
    feedback_visibility=FeedbackVisibility.NOT_APPLICABLE,
    causal_status=ArmCausalStatus.DETERMINISTIC_REFERENCE,
    replicate_policy=ReplicatePolicy.DETERMINISTIC_ONCE,
    description="Exact frozen Native CodeQL deterministic reference.",
)
H0 = ArmSpec(
    arm_id="m8_h0",
    shorthand="H0",
    architecture=ArmArchitecture.HISTORICAL_IMPORT,
    worker_bundle=WorkerBundle.NOT_APPLICABLE,
    feedback_visibility=FeedbackVisibility.NOT_APPLICABLE,
    causal_status=ArmCausalStatus.HISTORICAL_ONLY,
    replicate_policy=ReplicatePolicy.HISTORICAL_IMPORT_ONCE,
    description="Frozen M7 historical provenance import; never a modern paired arm.",
)
S0 = ArmSpec(
    arm_id="m8_s0",
    shorthand="S0",
    architecture=ArmArchitecture.SINGLE_AGENT,
    worker_bundle=WorkerBundle.SINGLE_REASONER,
    feedback_visibility=FeedbackVisibility.HIDDEN,
    causal_status=ArmCausalStatus.CONFIRMATORY,
    replicate_policy=ReplicatePolicy.SEPARATELY_INITIALIZED_R3,
    agents=(SINGLE_SONNET_AGENT,),
    formal_profiles=(FormalProfile.CORE, FormalProfile.ROLE),
    description="Modern Sonnet single Agent with receipt-only verifier projection.",
)
S1 = ArmSpec(
    arm_id="m8_s1",
    shorthand="S1",
    architecture=ArmArchitecture.SINGLE_AGENT,
    worker_bundle=WorkerBundle.SINGLE_REASONER,
    feedback_visibility=FeedbackVisibility.VISIBLE,
    causal_status=ArmCausalStatus.CONFIRMATORY,
    replicate_policy=ReplicatePolicy.SEPARATELY_INITIALIZED_R3,
    agents=(SINGLE_SONNET_AGENT,),
    formal_profiles=(FormalProfile.CORE, FormalProfile.ROLE),
    description="Modern Sonnet single Agent with detailed verifier feedback.",
)
M0 = ArmSpec(
    arm_id="m8_m0",
    shorthand="M0",
    architecture=ArmArchitecture.MULTI_AGENT,
    worker_bundle=WorkerBundle.ROLE_SPECIALISTS,
    feedback_visibility=FeedbackVisibility.HIDDEN,
    causal_status=ArmCausalStatus.CONFIRMATORY,
    replicate_policy=ReplicatePolicy.SEPARATELY_INITIALIZED_R3,
    agents=(SONNET_COORDINATOR_AGENT, *ROLE_SPECIALIST_AGENTS),
    formal_profiles=(FormalProfile.CORE, FormalProfile.ROLE),
    description="Sonnet Coordinator and three Sonnet specialists, receipt-only feedback.",
)
M1 = ArmSpec(
    arm_id="m8_m1",
    shorthand="M1",
    architecture=ArmArchitecture.MULTI_AGENT,
    worker_bundle=WorkerBundle.ROLE_SPECIALISTS,
    feedback_visibility=FeedbackVisibility.VISIBLE,
    causal_status=ArmCausalStatus.CONFIRMATORY,
    replicate_policy=ReplicatePolicy.SEPARATELY_INITIALIZED_R3,
    agents=(SONNET_COORDINATOR_AGENT, *ROLE_SPECIALIST_AGENTS),
    formal_profiles=(FormalProfile.CORE, FormalProfile.ROLE),
    description="Configured-model-matched Sonnet role-specialized multi-Agent arm.",
)
M2 = ArmSpec(
    arm_id="m8_m2",
    shorthand="M2",
    architecture=ArmArchitecture.MULTI_AGENT,
    worker_bundle=WorkerBundle.ROLE_SPECIALISTS,
    feedback_visibility=FeedbackVisibility.VISIBLE,
    causal_status=ArmCausalStatus.CONFIRMATORY_SYSTEM,
    replicate_policy=ReplicatePolicy.SEPARATELY_INITIALIZED_R3,
    agents=(OPUS_COORDINATOR_AGENT, *ROLE_SPECIALIST_AGENTS),
    formal_profiles=(FormalProfile.CORE, FormalProfile.ROLE),
    description="Target Opus Coordinator plus three Sonnet specialist system.",
)
G1 = ArmSpec(
    arm_id="m8_g1",
    shorthand="G1",
    architecture=ArmArchitecture.MULTI_AGENT,
    worker_bundle=WorkerBundle.GENERIC_WORKERS,
    feedback_visibility=FeedbackVisibility.VISIBLE,
    causal_status=ArmCausalStatus.PROFILE_CONDITIONAL,
    replicate_policy=ReplicatePolicy.SEPARATELY_INITIALIZED_R3,
    agents=(SONNET_COORDINATOR_AGENT, *GENERIC_WORKER_AGENTS),
    formal_profiles=(FormalProfile.ROLE,),
    description="All-Sonnet generic-worker control for the role-specialization bundle.",
)


ARM_REGISTRY = MappingProxyType(
    {item.arm_id: item for item in (N0, H0, S0, S1, M0, M1, M2, G1)}
)
ARM_SHORTHAND_REGISTRY = MappingProxyType(
    {item.shorthand: item for item in ARM_REGISTRY.values()}
)
M8_ARM_REGISTRY = ARM_REGISTRY


def get_arm_spec(arm: str | ArmSpec) -> ArmSpec:
    if isinstance(arm, ArmSpec):
        registered = ARM_REGISTRY.get(arm.arm_id)
        if registered != arm:
            raise ValueError(f"arm spec does not match frozen registry: {arm.arm_id}")
        return registered
    key = str(arm).strip()
    result = ARM_REGISTRY.get(key) or ARM_SHORTHAND_REGISTRY.get(key.upper())
    if result is None:
        raise ValueError(f"unregistered M8 arm: {arm!r}")
    return result


def confirmatory_arm_ids(profile: FormalProfile | str) -> tuple[str, ...]:
    selected = FormalProfile(profile)
    core = (S0.arm_id, S1.arm_id, M0.arm_id, M1.arm_id, M2.arm_id)
    return core if selected is FormalProfile.CORE else (*core, G1.arm_id)


def formal_arm_registry(profile: FormalProfile | str) -> Mapping[str, ArmSpec]:
    ids = confirmatory_arm_ids(profile)
    return MappingProxyType({arm_id: ARM_REGISTRY[arm_id] for arm_id in ids})


def arm_registry_to_dict() -> dict[str, Any]:
    return {
        "schema_version": ARM_REGISTRY_SCHEMA_VERSION,
        "arms": [item.to_dict() for item in ARM_REGISTRY.values()],
    }


def arm_registry_sha256() -> str:
    return _sha256(arm_registry_to_dict())


class ContrastFamily(str, Enum):
    PRIMARY = "PRIMARY"
    SECONDARY_HOLM = "SECONDARY_HOLM"


@dataclass(frozen=True, slots=True)
class PreRegisteredContrast:
    contrast_id: str
    minuend_arm_id: str
    subtrahend_arm_id: str
    family: ContrastFamily
    estimand: str
    allowed_treatment_factors: tuple[str, ...]
    profiles: tuple[FormalProfile, ...]

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", self.contrast_id):
            raise ValueError("contrast_id must be canonical snake_case")
        left = get_arm_spec(self.minuend_arm_id)
        right = get_arm_spec(self.subtrahend_arm_id)
        if left is right:
            raise ValueError("contrast arms must differ")
        if not self.estimand.strip():
            raise ValueError("contrast estimand is required")
        if not self.allowed_treatment_factors:
            raise ValueError("contrast must pre-register its treatment factors")
        if tuple(sorted(set(self.allowed_treatment_factors))) != tuple(
            sorted(self.allowed_treatment_factors)
        ):
            raise ValueError("allowed treatment factors must be unique")
        profiles = tuple(FormalProfile(item) for item in self.profiles)
        if not profiles or len(set(profiles)) != len(profiles):
            raise ValueError("contrast profiles must be non-empty and unique")
        object.__setattr__(self, "profiles", profiles)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contrast_id": self.contrast_id,
            "minuend_arm_id": self.minuend_arm_id,
            "subtrahend_arm_id": self.subtrahend_arm_id,
            "family": self.family.value,
            "estimand": self.estimand,
            "allowed_treatment_factors": list(self.allowed_treatment_factors),
            "profiles": [item.value for item in self.profiles],
        }

    @property
    def sha256(self) -> str:
        return _sha256(self.to_dict())


PRIMARY_M1_MINUS_S1 = PreRegisteredContrast(
    contrast_id="m1_minus_s1",
    minuend_arm_id=M1.arm_id,
    subtrahend_arm_id=S1.arm_id,
    family=ContrastFamily.PRIMARY,
    estimand="role-specialized multi-Agent architecture bundle effect",
    allowed_treatment_factors=("architecture", "worker_bundle", "agent_assignments"),
    profiles=(FormalProfile.CORE, FormalProfile.ROLE),
)
SECONDARY_CONTRASTS = (
    PreRegisteredContrast(
        "m1_minus_m0",
        M1.arm_id,
        M0.arm_id,
        ContrastFamily.SECONDARY_HOLM,
        "multi-Agent verifier-feedback visibility effect",
        ("feedback_visibility", "verifier_feedback_visible"),
        (FormalProfile.CORE, FormalProfile.ROLE),
    ),
    PreRegisteredContrast(
        "s1_minus_s0",
        S1.arm_id,
        S0.arm_id,
        ContrastFamily.SECONDARY_HOLM,
        "single-Agent verifier-feedback visibility effect",
        ("feedback_visibility", "verifier_feedback_visible"),
        (FormalProfile.CORE, FormalProfile.ROLE),
    ),
    PreRegisteredContrast(
        "m2_minus_m1",
        M2.arm_id,
        M1.arm_id,
        ContrastFamily.SECONDARY_HOLM,
        "Coordinator configured-model routing effect",
        ("agent_assignments",),
        (FormalProfile.CORE, FormalProfile.ROLE),
    ),
    PreRegisteredContrast(
        "m2_minus_s1",
        M2.arm_id,
        S1.arm_id,
        ContrastFamily.SECONDARY_HOLM,
        "target-system bundle effect versus modern single Agent",
        ("architecture", "worker_bundle", "agent_assignments"),
        (FormalProfile.CORE, FormalProfile.ROLE),
    ),
    PreRegisteredContrast(
        "m1_minus_g1",
        M1.arm_id,
        G1.arm_id,
        ContrastFamily.SECONDARY_HOLM,
        "role-specialization bundle effect",
        ("worker_bundle", "agent_assignments"),
        (FormalProfile.ROLE,),
    ),
)
PREREGISTERED_CONTRASTS = (PRIMARY_M1_MINUS_S1, *SECONDARY_CONTRASTS)


def preregistered_contrasts(
    profile: FormalProfile | str,
) -> tuple[PreRegisteredContrast, ...]:
    selected = FormalProfile(profile)
    return tuple(item for item in PREREGISTERED_CONTRASTS if selected in item.profiles)


def contrast_registry_sha256(profile: FormalProfile | str) -> str:
    selected = FormalProfile(profile)
    return _sha256(
        {
            "formal_profile": selected.value,
            "contrasts": [item.to_dict() for item in preregistered_contrasts(selected)],
        }
    )


_RUN_COMPONENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_STUDY_SPLITS = frozenset(
    {
        "dev-tune",
        "dev-validation",
        "formal-holdout",
        "historical",
        "development-only",
    }
)


@dataclass(frozen=True, slots=True)
class RunKey:
    study_id: str
    split: str
    subject_id: str
    arm_id: str
    replicate_index: int
    run_id: str
    schema_version: int = RUN_KEY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if (
            not isinstance(self.schema_version, int)
            or isinstance(self.schema_version, bool)
            or self.schema_version != RUN_KEY_SCHEMA_VERSION
        ):
            raise ValueError("unsupported RunKey schema version")
        for name in ("study_id", "subject_id", "run_id"):
            _path_component(getattr(self, name), name)
        if not isinstance(self.split, str) or self.split not in _STUDY_SPLITS:
            raise ValueError(f"unsupported study split: {self.split!r}")
        if not isinstance(self.arm_id, str):
            raise TypeError("arm_id must be a canonical string")
        arm = get_arm_spec(self.arm_id)
        object.__setattr__(self, "arm_id", arm.arm_id)
        if not isinstance(self.replicate_index, int) or isinstance(
            self.replicate_index, bool
        ):
            raise TypeError("replicate_index must be an integer")
        if arm is N0 and self.replicate_index != 1:
            raise ValueError("N0 is deterministic and must use replicate_index=1")
        if arm is H0:
            if self.split != "historical" or self.replicate_index != 1:
                raise ValueError(
                    "H0 is an immutable historical import, not a new study run"
                )
        elif self.split == "historical":
            raise ValueError("only H0 may use the historical split")
        elif (
            arm.replicate_policy is ReplicatePolicy.SEPARATELY_INITIALIZED_R3
            and self.replicate_index not in (1, 2, 3)
        ):
            raise ValueError("confirmatory arms require replicate_index in {1,2,3}")

    def validate_for_profile(self, profile: FormalProfile | str) -> None:
        arm = get_arm_spec(self.arm_id)
        if arm in (N0, H0):
            return
        if arm.arm_id not in confirmatory_arm_ids(profile):
            raise ValueError(
                f"arm {arm.arm_id} is not scheduled by formal profile {FormalProfile(profile).value}"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "study_id": self.study_id,
            "split": self.split,
            "subject_id": self.subject_id,
            "arm_id": self.arm_id,
            "replicate_index": self.replicate_index,
            "run_id": self.run_id,
        }

    def to_sealed_dict(self) -> dict[str, Any]:
        return {**self.to_dict(), "run_key_sha256": self.sha256}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RunKey:
        required = {
            "schema_version",
            "study_id",
            "split",
            "subject_id",
            "arm_id",
            "replicate_index",
            "run_id",
        }
        permitted = required | {"run_key_sha256"}
        unknown = set(value) - permitted
        missing = required - set(value)
        if unknown or missing:
            raise ValueError(
                f"RunKey fields are not canonical; missing={sorted(missing)}, unknown={sorted(unknown)}"
            )
        result = cls(
            schema_version=value["schema_version"],
            study_id=value["study_id"],
            split=value["split"],
            subject_id=value["subject_id"],
            arm_id=value["arm_id"],
            replicate_index=value["replicate_index"],
            run_id=value["run_id"],
        )
        claimed = value.get("run_key_sha256")
        if claimed is not None and claimed != result.sha256:
            raise ValueError("RunKey hash is not canonical")
        return result

    @property
    def sha256(self) -> str:
        return _sha256(self.to_dict())


# Each value is itself a frozen identity or canonical hash.  A protocol-version
# bump is required to add/remove a field; arbitrary per-arm override fields are
# deliberately not accepted.
COMMON_ARM_CONTRACT_FIELDS = frozenset(
    {
        "provider",
        "endpoint_protocol",
        "generation_transport_sha256",
        "project_inputs_sha256",
        "analysis_contract_sha256",
        "tools_helpers_sha256",
        "verifier_path_sha256",
        "budget_price_table_sha256",
        "schema_parser_sha256",
        "no_leakage_sha256",
        "artifact_evaluator_sha256",
        "schedule_sha256",
    }
)


@dataclass(frozen=True, slots=True)
class ArmExecutionContract:
    """One arm's registered treatment plus its supposedly common contract."""

    arm_id: str
    common_contract: Mapping[str, Any] = field(repr=False)

    def __post_init__(self) -> None:
        arm = get_arm_spec(self.arm_id)
        object.__setattr__(self, "arm_id", arm.arm_id)
        material = _canonical_mapping(self.common_contract, "common_contract")
        keys = set(material)
        if keys != COMMON_ARM_CONTRACT_FIELDS:
            raise ValueError(
                "common_contract fields are not frozen; "
                f"missing={sorted(COMMON_ARM_CONTRACT_FIELDS - keys)}, "
                f"unknown={sorted(keys - COMMON_ARM_CONTRACT_FIELDS)}"
            )
        for key, value in material.items():
            if value is None or value == "" or value == {} or value == []:
                raise ValueError(f"common_contract.{key} must carry a frozen identity")
        object.__setattr__(self, "common_contract", MappingProxyType(material))

    @property
    def arm_spec(self) -> ArmSpec:
        return ARM_REGISTRY[self.arm_id]

    @property
    def common_contract_sha256(self) -> str:
        return _sha256(dict(self.common_contract))

    def to_dict(self) -> dict[str, Any]:
        return {
            "arm_id": self.arm_id,
            "arm_spec_sha256": self.arm_spec.sha256,
            "treatment": self.arm_spec.treatment_dict(),
            "common_contract": dict(self.common_contract),
            "common_contract_sha256": self.common_contract_sha256,
        }


@dataclass(frozen=True, slots=True)
class ArmOnlyDifferenceAudit:
    formal_profile: FormalProfile
    arm_ids: tuple[str, ...]
    common_contract_sha256: str
    arm_registry_sha256: str
    contrast_registry_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": "PASS",
            "formal_profile": self.formal_profile.value,
            "arm_ids": list(self.arm_ids),
            "common_contract_sha256": self.common_contract_sha256,
            "arm_registry_sha256": self.arm_registry_sha256,
            "contrast_registry_sha256": self.contrast_registry_sha256,
        }

    @property
    def sha256(self) -> str:
        return _sha256(self.to_dict())


def validate_arm_only_differences(
    contracts: Iterable[ArmExecutionContract],
    profile: FormalProfile | str,
) -> ArmOnlyDifferenceAudit:
    """Require a complete profile and byte-equivalent non-treatment contract."""

    selected = FormalProfile(profile)
    rows = tuple(contracts)
    by_arm = {item.arm_id: item for item in rows}
    if len(by_arm) != len(rows):
        raise ValueError("arm-only-difference audit received duplicate arm contracts")
    expected = set(confirmatory_arm_ids(selected))
    actual = set(by_arm)
    if actual != expected:
        raise ValueError(
            "arm contracts do not match selected formal profile; "
            f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}"
        )
    hashes = {item.common_contract_sha256 for item in rows}
    if len(hashes) != 1:
        details = {item.arm_id: item.common_contract_sha256 for item in rows}
        raise ValueError(f"unregistered cross-arm contract difference: {details}")

    _validate_preregistered_factor_differences(selected)
    return ArmOnlyDifferenceAudit(
        formal_profile=selected,
        arm_ids=confirmatory_arm_ids(selected),
        common_contract_sha256=next(iter(hashes)),
        arm_registry_sha256=arm_registry_sha256(),
        contrast_registry_sha256=contrast_registry_sha256(selected),
    )


class BackendIdentityStatus(str, Enum):
    ATTESTED = "ATTESTED"
    NOT_ATTESTED = "NOT_ATTESTED"


class ModelIdentityDecision(str, Enum):
    CONTINUE_ATTESTED = "CONTINUE_ATTESTED"
    CONTINUE_NOT_ATTESTED = "CONTINUE_NOT_ATTESTED"
    PAUSE_ENTIRE_PROJECT_BLOCK = "PAUSE_ENTIRE_PROJECT_BLOCK"


class DriftAction(str, Enum):
    PAUSE_ENTIRE_PROJECT_BLOCK = "PAUSE_ENTIRE_PROJECT_BLOCK"
    REPORT_NOT_ATTESTED_LIMITATION = "REPORT_NOT_ATTESTED_LIMITATION"
    WITHHOLD_EXACT_BACKEND_CAUSAL_CLAIM = "WITHHOLD_EXACT_BACKEND_CAUSAL_CLAIM"


@dataclass(frozen=True, slots=True)
class ModelIdentityDriftPolicy:
    configured_identity_mismatch: DriftAction = DriftAction.PAUSE_ENTIRE_PROJECT_BLOCK
    within_block_identity_change: DriftAction = DriftAction.PAUSE_ENTIRE_PROJECT_BLOCK
    observed_cross_block_identity_change: DriftAction = (
        DriftAction.PAUSE_ENTIRE_PROJECT_BLOCK
    )
    provider_revision_unavailable: DriftAction = (
        DriftAction.REPORT_NOT_ATTESTED_LIMITATION
    )
    unresolved_cross_block_drift: DriftAction = (
        DriftAction.WITHHOLD_EXACT_BACKEND_CAUSAL_CLAIM
    )

    def __post_init__(self) -> None:
        frozen = (
            DriftAction.PAUSE_ENTIRE_PROJECT_BLOCK,
            DriftAction.PAUSE_ENTIRE_PROJECT_BLOCK,
            DriftAction.PAUSE_ENTIRE_PROJECT_BLOCK,
            DriftAction.REPORT_NOT_ATTESTED_LIMITATION,
            DriftAction.WITHHOLD_EXACT_BACKEND_CAUSAL_CLAIM,
        )
        if (
            self.configured_identity_mismatch,
            self.within_block_identity_change,
            self.observed_cross_block_identity_change,
            self.provider_revision_unavailable,
            self.unresolved_cross_block_drift,
        ) != frozen:
            raise ValueError("the formal model-identity drift policy is frozen")

    def to_dict(self) -> dict[str, str]:
        return {
            "configured_identity_mismatch": self.configured_identity_mismatch.value,
            "within_block_identity_change": self.within_block_identity_change.value,
            "observed_cross_block_identity_change": self.observed_cross_block_identity_change.value,
            "provider_revision_unavailable": self.provider_revision_unavailable.value,
            "unresolved_cross_block_drift": self.unresolved_cross_block_drift.value,
        }

    @property
    def sha256(self) -> str:
        return _sha256(self.to_dict())


FROZEN_MODEL_IDENTITY_DRIFT_POLICY = ModelIdentityDriftPolicy()


@dataclass(frozen=True, slots=True)
class ModelBackendIdentity:
    """Configured identity and what one successful provider response reported."""

    block_id: str
    arm_id: str
    agent_id: str
    configured_model_id: str
    provider: str
    endpoint_protocol: str
    response_reported_model: str | None
    provider_deployment_revision: str | None
    attestation_status: BackendIdentityStatus = BackendIdentityStatus.NOT_ATTESTED

    def __post_init__(self) -> None:
        _path_component(self.block_id, "block_id")
        arm = get_arm_spec(self.arm_id)
        object.__setattr__(self, "arm_id", arm.arm_id)
        for name in (
            "agent_id",
            "configured_model_id",
            "provider",
            "endpoint_protocol",
        ):
            _non_empty(getattr(self, name), name)
        for name in ("response_reported_model", "provider_deployment_revision"):
            value = getattr(self, name)
            if value is not None:
                _non_empty(value, name)
        status = BackendIdentityStatus(self.attestation_status)
        object.__setattr__(self, "attestation_status", status)
        if status is BackendIdentityStatus.ATTESTED and (
            self.response_reported_model is None
            or self.provider_deployment_revision is None
        ):
            raise ValueError(
                "ATTESTED backend identity requires both response-reported model "
                "and provider-pinned deployment revision"
            )

    @property
    def backend_identity_status(self) -> BackendIdentityStatus:
        return self.attestation_status

    @property
    def signature(self) -> dict[str, str | None]:
        return {
            "provider": self.provider,
            "endpoint_protocol": self.endpoint_protocol,
            "response_reported_model": self.response_reported_model,
            "provider_deployment_revision": self.provider_deployment_revision,
            "backend_identity_status": self.attestation_status.value,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "block_id": self.block_id,
            "arm_id": self.arm_id,
            "agent_id": self.agent_id,
            "configured_model_id": self.configured_model_id,
            **self.signature,
        }

    @property
    def sha256(self) -> str:
        return _sha256(self.to_dict())


@dataclass(frozen=True, slots=True)
class ModelIdentityAudit:
    block_id: str
    decision: ModelIdentityDecision
    reasons: tuple[str, ...]
    signatures_by_configured_model: Mapping[str, Mapping[str, str | None]]
    policy_sha256: str

    def __post_init__(self) -> None:
        material = {
            model: MappingProxyType(dict(signature))
            for model, signature in sorted(self.signatures_by_configured_model.items())
        }
        object.__setattr__(
            self, "signatures_by_configured_model", MappingProxyType(material)
        )

    def assert_may_continue(self) -> None:
        if self.decision is ModelIdentityDecision.PAUSE_ENTIRE_PROJECT_BLOCK:
            raise ValueError(
                "model identity drift policy requires a symmetric project-block pause: "
                + "; ".join(self.reasons)
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "block_id": self.block_id,
            "decision": self.decision.value,
            "reasons": list(self.reasons),
            "signatures_by_configured_model": {
                model: dict(signature)
                for model, signature in self.signatures_by_configured_model.items()
            },
            "policy_sha256": self.policy_sha256,
        }

    @property
    def sha256(self) -> str:
        return _sha256(self.to_dict())


def audit_model_backend_identities(
    observations: Sequence[ModelBackendIdentity],
    *,
    reference_signatures: Mapping[str, Mapping[str, str | None]] | None = None,
    policy: ModelIdentityDriftPolicy = FROZEN_MODEL_IDENTITY_DRIFT_POLICY,
) -> ModelIdentityAudit:
    """Audit one interleaved project block without selecting a single arm to rerun."""

    if not observations:
        raise ValueError("at least one successful-response model identity is required")
    if policy != FROZEN_MODEL_IDENTITY_DRIFT_POLICY:
        raise ValueError("only the frozen formal drift policy is permitted")
    block_ids = {item.block_id for item in observations}
    if len(block_ids) != 1:
        raise ValueError("model identity audit must contain exactly one project block")
    block_id = next(iter(block_ids))
    reasons: list[str] = []

    providers = {(item.provider, item.endpoint_protocol) for item in observations}
    if len(providers) != 1:
        reasons.append("provider or endpoint protocol changed within the project block")

    grouped: dict[str, list[ModelBackendIdentity]] = {}
    for item in observations:
        arm = get_arm_spec(item.arm_id)
        try:
            expected = arm.agent(item.agent_id)
        except KeyError:
            reasons.append(f"{item.arm_id} reported unregistered agent {item.agent_id}")
            continue
        if item.configured_model_id != expected.model_id:
            reasons.append(
                f"{item.arm_id}/{item.agent_id} configured {item.configured_model_id}, "
                f"expected {expected.model_id}"
            )
        grouped.setdefault(item.configured_model_id, []).append(item)

    signatures: dict[str, dict[str, str | None]] = {}
    for configured_model, rows in sorted(grouped.items()):
        values = {_signature_tuple(item.signature) for item in rows}
        if len(values) != 1:
            reasons.append(
                f"response-reported backend identity changed within block for {configured_model}"
            )
            continue
        signature = dict(rows[0].signature)
        signatures[configured_model] = signature
        if (
            reference_signatures is not None
            and configured_model in reference_signatures
        ):
            reference = _normalise_signature(reference_signatures[configured_model])
            if _signature_tuple(signature) != _signature_tuple(reference):
                reasons.append(
                    f"response-reported backend identity changed across blocks for {configured_model}"
                )

    if reference_signatures is not None:
        unknown_reference_models = set(reference_signatures) - {
            SONNET_MODEL_ID,
            OPUS_MODEL_ID,
        }
        if unknown_reference_models:
            raise ValueError(
                f"reference signatures contain unregistered models: {sorted(unknown_reference_models)}"
            )

    if reasons:
        decision = ModelIdentityDecision.PAUSE_ENTIRE_PROJECT_BLOCK
    elif any(
        signature["backend_identity_status"] == BackendIdentityStatus.NOT_ATTESTED.value
        for signature in signatures.values()
    ):
        decision = ModelIdentityDecision.CONTINUE_NOT_ATTESTED
    else:
        decision = ModelIdentityDecision.CONTINUE_ATTESTED
    return ModelIdentityAudit(
        block_id=block_id,
        decision=decision,
        reasons=tuple(reasons),
        signatures_by_configured_model=signatures,
        policy_sha256=policy.sha256,
    )


def enforce_model_identity_drift_policy(
    observations: Sequence[ModelBackendIdentity],
    *,
    reference_signatures: Mapping[str, Mapping[str, str | None]] | None = None,
) -> ModelIdentityAudit:
    audit = audit_model_backend_identities(
        observations, reference_signatures=reference_signatures
    )
    audit.assert_may_continue()
    return audit


def _validate_registry() -> None:
    expected = {
        "m8_n0",
        "m8_h0",
        "m8_s0",
        "m8_s1",
        "m8_m0",
        "m8_m1",
        "m8_m2",
        "m8_g1",
    }
    if set(ARM_REGISTRY) != expected or len(ARM_SHORTHAND_REGISTRY) != len(expected):
        raise ValueError(
            "M8 arm registry is incomplete or contains duplicate shorthand"
        )
    if M2.agent("coordinator_agent").model_id != OPUS_MODEL_ID:
        raise ValueError("M2 Coordinator must use the frozen Opus configured model")
    if tuple(item.id for item in M2.agents) != (
        "coordinator_agent",
        "input_agent",
        "effect_agent",
        "semantic_bridge_agent",
    ):
        raise ValueError(
            "M2 requires the frozen Coordinator and three specialist identities"
        )
    if any(item.model_id != SONNET_MODEL_ID for item in M2.agents[1:]):
        raise ValueError(
            "M2 specialists must all use the frozen Sonnet configured model"
        )
    for arm in (S0, S1, M0, M1, G1):
        if any(item.model_id != SONNET_MODEL_ID for item in arm.agents):
            raise ValueError(f"{arm.arm_id} must be all-Sonnet")
    if confirmatory_arm_ids(FormalProfile.CORE)[-1] == G1.arm_id:
        raise ValueError("CORE must exclude G1")
    if G1.arm_id not in confirmatory_arm_ids(FormalProfile.ROLE):
        raise ValueError("ROLE must include G1")


def _validate_preregistered_factor_differences(profile: FormalProfile) -> None:
    for contrast in preregistered_contrasts(profile):
        left = get_arm_spec(contrast.minuend_arm_id).treatment_dict()
        right = get_arm_spec(contrast.subtrahend_arm_id).treatment_dict()
        actual = tuple(sorted(key for key in left if left[key] != right[key]))
        expected = tuple(sorted(contrast.allowed_treatment_factors))
        if actual != expected:
            raise ValueError(
                f"contrast {contrast.contrast_id} drifted: expected factors {expected}, got {actual}"
            )


def _path_component(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or not _RUN_COMPONENT.fullmatch(value)
        or value in {".", ".."}
    ):
        raise ValueError(f"{name} must be one canonical, traversal-free path component")
    return value


def _non_empty(value: str, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a non-empty canonical string")
    return value


def _canonical_mapping(value: Mapping[str, Any], name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{name} must be a JSON mapping")
    try:
        text = json.dumps(
            dict(value),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        result = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must contain strict JSON values") from exc
    if not isinstance(result, dict):
        raise TypeError(f"{name} must be a JSON object")
    return result


def _sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _normalise_signature(value: Mapping[str, str | None]) -> dict[str, str | None]:
    required = {
        "provider",
        "endpoint_protocol",
        "response_reported_model",
        "provider_deployment_revision",
        "backend_identity_status",
    }
    if set(value) != required:
        raise ValueError("backend reference signature fields are not canonical")
    result = {key: value[key] for key in sorted(required)}
    for key in ("provider", "endpoint_protocol"):
        _non_empty(result[key], key)  # type: ignore[arg-type]
    for key in ("response_reported_model", "provider_deployment_revision"):
        if result[key] is not None:
            _non_empty(result[key], key)  # type: ignore[arg-type]
    BackendIdentityStatus(result["backend_identity_status"])
    return result


def _signature_tuple(value: Mapping[str, str | None]) -> tuple[str | None, ...]:
    normalised = _normalise_signature(value)
    return tuple(normalised[key] for key in sorted(normalised))


_validate_registry()
_validate_preregistered_factor_differences(FormalProfile.CORE)
_validate_preregistered_factor_differences(FormalProfile.ROLE)
