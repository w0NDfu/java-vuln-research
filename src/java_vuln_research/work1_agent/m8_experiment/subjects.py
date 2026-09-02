"""Fail-closed subject and evaluator manifests for the M8 experiment."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Sequence

from java_vuln_research.work1_agent.proposal.model import stable_digest

from .arms import RunKey, get_arm_spec
from .commitments import CommitmentPurpose, ManifestCommitment


SUBJECT_MANIFEST_SCHEMA_VERSION = 1
EVALUATOR_MANIFEST_SCHEMA_VERSION = 1
LINEAGE_SPLIT_SCHEMA_VERSION = 1

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_CVE_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_CWE_RE = re.compile(r"^CWE-[0-9]+$")
_FORBIDDEN_DETECTOR_PATH_COMPONENT = re.compile(
    r"^(?:vulnerable|fixed|benign|evaluator|evaluations?|annotations?|targets?|"
    r"cve-[0-9]{4}-[0-9]+|cwe-[0-9]+)$",
    re.IGNORECASE,
)


class DatasetSplit(str, Enum):
    DEV_TUNE = "dev-tune"
    DEV_VALIDATION = "dev-validation"
    FORMAL_HOLDOUT = "formal-holdout"
    HISTORICAL = "historical"
    DEVELOPMENT_ONLY = "development-only"


class CodeQLDatabaseStatus(str, Enum):
    READY = "READY"
    NOT_READY = "NOT_READY"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID = "INVALID"


class GenericArtifactStage(str, Enum):
    M1 = "M1"
    M2 = "M2"
    M3 = "M3"
    M4 = "M4"
    M5 = "M5"


class RevisionRole(str, Enum):
    VULNERABLE = "VULNERABLE"
    FIXED = "FIXED"
    BENIGN = "BENIGN"
    OTHER_SAFETY = "OTHER_SAFETY"


def _non_empty(value: str, name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    text = value.strip()
    if not text:
        raise ValueError(f"{name} is required")
    if text != value:
        raise ValueError(f"{name} must not contain leading or trailing whitespace")
    return text


def _opaque_id(value: str, namespace: str) -> str:
    text = _non_empty(value, f"{namespace}_id")
    pattern = rf"^{re.escape(namespace)}-[0-9a-f]{{32}}$"
    if re.fullmatch(pattern, text) is None:
        raise ValueError(f"{namespace}_id must be a non-semantic {namespace}-<32 lowercase hex> identifier")
    return text


def _sha256(value: str, name: str) -> str:
    text = _non_empty(value, name)
    if _SHA256_RE.fullmatch(text) is None:
        raise ValueError(f"{name} must be 64 lowercase hex characters")
    return text


def _integer(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    return value


def _string_tuple(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise TypeError(f"{name} must be an array of strings")
    return tuple(_non_empty(item, name) for item in value)


def _detector_path(value: str, name: str) -> str:
    text = _non_empty(value, name)
    components = tuple(item for item in re.split(r"[\\/]", text) if item)
    forbidden = [item for item in components if _FORBIDDEN_DETECTOR_PATH_COMPONENT.fullmatch(item)]
    if forbidden:
        raise ValueError(f"{name} carries forbidden evaluator or revision-role semantics: {forbidden}")
    return text


def _unique_sorted(values: Sequence[str], name: str) -> tuple[str, ...]:
    result = tuple(_non_empty(item, name) for item in values)
    if len(result) != len(set(result)):
        raise ValueError(f"{name} must not contain duplicates")
    if result != tuple(sorted(result)):
        raise ValueError(f"{name} must be in canonical sorted order")
    return result


def _exact_keys(
    value: Mapping[str, Any],
    required: set[str],
    *,
    optional: set[str] | None = None,
    name: str,
) -> None:
    allowed = required | (optional or set())
    keys = set(value)
    missing = required - keys
    unknown = keys - allowed
    if missing or unknown:
        raise ValueError(f"{name} fields invalid: missing={sorted(missing)} unknown={sorted(unknown)}")


@dataclass(frozen=True, slots=True)
class ArtifactIdentity:
    identity_sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        _sha256(self.identity_sha256, "identity_sha256")
        if isinstance(self.size_bytes, bool) or not isinstance(self.size_bytes, int):
            raise TypeError("size_bytes must be an integer")
        if self.size_bytes < 0:
            raise ValueError("size_bytes must be non-negative")

    def to_dict(self) -> dict[str, Any]:
        return {"identity_sha256": self.identity_sha256, "size_bytes": self.size_bytes}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ArtifactIdentity":
        _exact_keys(value, {"identity_sha256", "size_bytes"}, name="artifact identity")
        return cls(
            identity_sha256=_non_empty(value["identity_sha256"], "identity_sha256"),
            size_bytes=_integer(value["size_bytes"], "size_bytes"),
        )


@dataclass(frozen=True, slots=True)
class GenericArtifactIdentity:
    stage: GenericArtifactStage
    artifact: ArtifactIdentity

    def __post_init__(self) -> None:
        if not isinstance(self.stage, GenericArtifactStage):
            raise TypeError("stage must be a GenericArtifactStage")
        if not isinstance(self.artifact, ArtifactIdentity):
            raise TypeError("artifact must be an ArtifactIdentity")

    def to_dict(self) -> dict[str, Any]:
        return {"stage": self.stage.value, "artifact": self.artifact.to_dict()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "GenericArtifactIdentity":
        _exact_keys(value, {"stage", "artifact"}, name="generic artifact identity")
        if not isinstance(value["artifact"], Mapping):
            raise TypeError("generic artifact identity artifact must be a mapping")
        return cls(
            stage=GenericArtifactStage(_non_empty(value["stage"], "stage")),
            artifact=ArtifactIdentity.from_dict(value["artifact"]),
        )


@dataclass(frozen=True, slots=True)
class DetectorSubjectManifest:
    """The complete subject/run metadata permitted on the Detector side."""

    manifest_id: str
    run_key: RunKey
    subject_id: str
    project_id: str
    dataset_split: DatasetSplit
    repository_revision: str
    source_root: str
    codeql_db_path: str
    codeql_db_status: CodeQLDatabaseStatus
    codeql_db_identity: ArtifactIdentity | None
    native_codeql_artifact_identity: ArtifactIdentity
    generic_artifact_identities: tuple[GenericArtifactIdentity, ...]
    arm_id: str
    replicate_index: int
    arm_spec_sha256: str
    schedule_sha256: str
    config_sha256: str
    budget_sha256: str
    split_commitment: ManifestCommitment
    eligibility_commitment: ManifestCommitment
    schema_version: int = SUBJECT_MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or not isinstance(self.schema_version, int):
            raise TypeError("detector subject manifest schema_version must be an integer")
        if self.schema_version != SUBJECT_MANIFEST_SCHEMA_VERSION:
            raise ValueError("unsupported detector subject manifest schema version")
        if not isinstance(self.run_key, RunKey):
            raise TypeError("run_key must be the frozen M8 RunKey")
        _opaque_id(self.subject_id, "subject")
        _opaque_id(self.project_id, "project")
        if self.subject_id.removeprefix("subject-") == self.project_id.removeprefix("project-"):
            raise ValueError("subject_id and project_id must be independently generated pseudonyms")
        if not isinstance(self.dataset_split, DatasetSplit):
            raise TypeError("dataset_split must be a DatasetSplit")
        if self.run_key.subject_id != self.subject_id:
            raise ValueError("run_key subject_id does not match detector subject_id")
        if self.run_key.split != self.dataset_split.value:
            raise ValueError("run_key split does not match detector dataset_split")
        revision = _non_empty(self.repository_revision, "repository_revision")
        if _GIT_COMMIT_RE.fullmatch(revision) is None:
            raise ValueError("repository_revision must be a full 40- or 64-character commit hash")
        _detector_path(self.source_root, "source_root")
        _detector_path(self.codeql_db_path, "codeql_db_path")
        if not isinstance(self.codeql_db_status, CodeQLDatabaseStatus):
            raise TypeError("codeql_db_status must be a CodeQLDatabaseStatus")
        if self.codeql_db_status is CodeQLDatabaseStatus.READY:
            if not isinstance(self.codeql_db_identity, ArtifactIdentity):
                raise ValueError("READY CodeQL database requires a frozen identity")
        elif self.codeql_db_identity is not None:
            raise ValueError("non-ready CodeQL database must not claim a frozen ready identity")
        if not isinstance(self.native_codeql_artifact_identity, ArtifactIdentity):
            raise TypeError("native_codeql_artifact_identity must be an ArtifactIdentity")
        if any(not isinstance(item, GenericArtifactIdentity) for item in self.generic_artifact_identities):
            raise TypeError("generic_artifact_identities must contain GenericArtifactIdentity values")
        stages = tuple(item.stage for item in self.generic_artifact_identities)
        canonical_stages = tuple(GenericArtifactStage)
        if stages != canonical_stages:
            raise ValueError("generic_artifact_identities must contain M1 through M5 exactly once in order")
        arm = get_arm_spec(self.arm_id)
        if arm.arm_id != self.arm_id:
            raise ValueError(f"arm_id must use canonical machine ID {arm.arm_id}")
        if isinstance(self.replicate_index, bool) or not isinstance(self.replicate_index, int):
            raise TypeError("replicate_index must be an integer")
        if self.run_key.arm_id != self.arm_id:
            raise ValueError("run_key arm_id does not match detector arm_id")
        if self.run_key.replicate_index != self.replicate_index:
            raise ValueError("run_key replicate_index does not match detector replicate_index")
        for name in ("arm_spec_sha256", "schedule_sha256", "config_sha256", "budget_sha256"):
            _sha256(getattr(self, name), name)
        if self.arm_spec_sha256 != arm.sha256:
            raise ValueError("arm_spec_sha256 does not match the frozen registered arm")
        if not isinstance(self.split_commitment, ManifestCommitment):
            raise TypeError("split_commitment must be a ManifestCommitment")
        if not isinstance(self.eligibility_commitment, ManifestCommitment):
            raise TypeError("eligibility_commitment must be a ManifestCommitment")
        if self.split_commitment.purpose is not CommitmentPurpose.SPLIT:
            raise ValueError("split_commitment has the wrong purpose")
        if self.eligibility_commitment.purpose is not CommitmentPurpose.ELIGIBILITY:
            raise ValueError("eligibility_commitment has the wrong purpose")
        if self.manifest_id != stable_digest("m8subject", self.identity_material()):
            raise ValueError("detector subject manifest_id is not canonical")

    def identity_material(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "run_key": self.run_key.to_sealed_dict(),
            "subject_id": self.subject_id,
            "project_id": self.project_id,
            "dataset_split": self.dataset_split.value,
            "repository_revision": self.repository_revision,
            "source_root": self.source_root,
            "codeql_db_path": self.codeql_db_path,
            "codeql_db_status": self.codeql_db_status.value,
            "codeql_db_identity": self.codeql_db_identity.to_dict() if self.codeql_db_identity else None,
            "native_codeql_artifact_identity": self.native_codeql_artifact_identity.to_dict(),
            "generic_artifact_identities": [item.to_dict() for item in self.generic_artifact_identities],
            "arm_id": self.arm_id,
            "replicate_index": self.replicate_index,
            "arm_spec_sha256": self.arm_spec_sha256,
            "schedule_sha256": self.schedule_sha256,
            "config_sha256": self.config_sha256,
            "budget_sha256": self.budget_sha256,
            "split_commitment": self.split_commitment.compact(),
            "eligibility_commitment": self.eligibility_commitment.compact(),
        }

    @classmethod
    def create(
        cls,
        *,
        run_key: RunKey,
        project_id: str,
        repository_revision: str,
        source_root: str,
        codeql_db_path: str,
        codeql_db_status: CodeQLDatabaseStatus | str,
        codeql_db_identity: ArtifactIdentity | None,
        native_codeql_artifact_identity: ArtifactIdentity,
        generic_artifact_identities: Sequence[GenericArtifactIdentity],
        schedule_sha256: str,
        config_sha256: str,
        budget_sha256: str,
        split_commitment: ManifestCommitment | str,
        eligibility_commitment: ManifestCommitment | str,
    ) -> "DetectorSubjectManifest":
        split_tag = (
            ManifestCommitment.parse(split_commitment)
            if isinstance(split_commitment, str)
            else split_commitment
        )
        eligibility_tag = (
            ManifestCommitment.parse(eligibility_commitment)
            if isinstance(eligibility_commitment, str)
            else eligibility_commitment
        )
        values = {
            "run_key": run_key,
            "subject_id": run_key.subject_id,
            "project_id": project_id,
            "dataset_split": DatasetSplit(run_key.split),
            "repository_revision": repository_revision,
            "source_root": source_root,
            "codeql_db_path": codeql_db_path,
            "codeql_db_status": CodeQLDatabaseStatus(codeql_db_status),
            "codeql_db_identity": codeql_db_identity,
            "native_codeql_artifact_identity": native_codeql_artifact_identity,
            "generic_artifact_identities": tuple(generic_artifact_identities),
            "arm_id": run_key.arm_id,
            "replicate_index": run_key.replicate_index,
            "arm_spec_sha256": get_arm_spec(run_key.arm_id).sha256,
            "schedule_sha256": schedule_sha256,
            "config_sha256": config_sha256,
            "budget_sha256": budget_sha256,
            "split_commitment": split_tag,
            "eligibility_commitment": eligibility_tag,
        }
        material = {
            "schema_version": SUBJECT_MANIFEST_SCHEMA_VERSION,
            "run_key": values["run_key"].to_sealed_dict(),
            "subject_id": values["subject_id"],
            "project_id": values["project_id"],
            "dataset_split": values["dataset_split"].value,
            "repository_revision": values["repository_revision"],
            "source_root": values["source_root"],
            "codeql_db_path": values["codeql_db_path"],
            "codeql_db_status": values["codeql_db_status"].value,
            "codeql_db_identity": (
                values["codeql_db_identity"].to_dict() if values["codeql_db_identity"] else None
            ),
            "native_codeql_artifact_identity": values[
                "native_codeql_artifact_identity"
            ].to_dict(),
            "generic_artifact_identities": [
                item.to_dict() for item in values["generic_artifact_identities"]
            ],
            "arm_id": values["arm_id"],
            "replicate_index": values["replicate_index"],
            "arm_spec_sha256": values["arm_spec_sha256"],
            "schedule_sha256": values["schedule_sha256"],
            "config_sha256": values["config_sha256"],
            "budget_sha256": values["budget_sha256"],
            "split_commitment": values["split_commitment"].compact(),
            "eligibility_commitment": values["eligibility_commitment"].compact(),
        }
        return cls(manifest_id=stable_digest("m8subject", material), **values)

    def to_dict(self) -> dict[str, Any]:
        return {"manifest_id": self.manifest_id, **self.identity_material()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "DetectorSubjectManifest":
        expected = {
            "schema_version", "manifest_id", "run_key", "subject_id", "project_id", "dataset_split",
            "repository_revision", "source_root", "codeql_db_path", "codeql_db_status",
            "codeql_db_identity", "native_codeql_artifact_identity", "generic_artifact_identities",
            "arm_id", "replicate_index", "arm_spec_sha256", "schedule_sha256", "config_sha256",
            "budget_sha256", "split_commitment", "eligibility_commitment",
        }
        _exact_keys(value, expected, name="detector subject manifest")
        db_identity = value["codeql_db_identity"]
        native_identity = value["native_codeql_artifact_identity"]
        generic_identities = value["generic_artifact_identities"]
        run_key = value["run_key"]
        if not isinstance(run_key, Mapping):
            raise TypeError("run_key must be a mapping")
        if db_identity is not None and not isinstance(db_identity, Mapping):
            raise TypeError("codeql_db_identity must be a mapping or null")
        if not isinstance(native_identity, Mapping):
            raise TypeError("native_codeql_artifact_identity must be a mapping")
        if not isinstance(generic_identities, Sequence) or isinstance(generic_identities, (str, bytes)):
            raise TypeError("generic_artifact_identities must be an array")
        return cls(
            manifest_id=_non_empty(value["manifest_id"], "manifest_id"),
            run_key=RunKey.from_dict(run_key),
            subject_id=_non_empty(value["subject_id"], "subject_id"),
            project_id=_non_empty(value["project_id"], "project_id"),
            dataset_split=DatasetSplit(_non_empty(value["dataset_split"], "dataset_split")),
            repository_revision=_non_empty(value["repository_revision"], "repository_revision"),
            source_root=_non_empty(value["source_root"], "source_root"),
            codeql_db_path=_non_empty(value["codeql_db_path"], "codeql_db_path"),
            codeql_db_status=CodeQLDatabaseStatus(
                _non_empty(value["codeql_db_status"], "codeql_db_status")
            ),
            codeql_db_identity=ArtifactIdentity.from_dict(db_identity) if db_identity is not None else None,
            native_codeql_artifact_identity=ArtifactIdentity.from_dict(native_identity),
            generic_artifact_identities=tuple(
                GenericArtifactIdentity.from_dict(item) for item in generic_identities
            ),
            arm_id=_non_empty(value["arm_id"], "arm_id"),
            replicate_index=_integer(value["replicate_index"], "replicate_index"),
            arm_spec_sha256=_non_empty(value["arm_spec_sha256"], "arm_spec_sha256"),
            schedule_sha256=_non_empty(value["schedule_sha256"], "schedule_sha256"),
            config_sha256=_non_empty(value["config_sha256"], "config_sha256"),
            budget_sha256=_non_empty(value["budget_sha256"], "budget_sha256"),
            split_commitment=ManifestCommitment.parse(
                _non_empty(value["split_commitment"], "split_commitment")
            ),
            eligibility_commitment=ManifestCommitment.parse(
                _non_empty(value["eligibility_commitment"], "eligibility_commitment")
            ),
            schema_version=_integer(value["schema_version"], "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class EligibleTargetAnnotation:
    target_id: str
    relative_file_path: str
    function_signature: str
    start_line: int
    end_line: int
    root_cause: str
    known_method: str
    native_codeql_uncovered: bool = True
    work1_contract_expressible: bool = True

    def __post_init__(self) -> None:
        _opaque_id(self.target_id, "target")
        path = PurePosixPath(_non_empty(self.relative_file_path, "relative_file_path"))
        if path.is_absolute() or ".." in path.parts or self.relative_file_path != path.as_posix():
            raise ValueError("relative_file_path must be a normalized project-relative POSIX path")
        _non_empty(self.function_signature, "function_signature")
        _integer(self.start_line, "start_line")
        _integer(self.end_line, "end_line")
        if self.start_line < 1 or self.end_line < self.start_line:
            raise ValueError("target line range is invalid")
        _non_empty(self.root_cause, "root_cause")
        _non_empty(self.known_method, "known_method")
        if self.native_codeql_uncovered is not True:
            raise ValueError("eligible target must be uncovered by frozen Native CodeQL")
        if self.work1_contract_expressible is not True:
            raise ValueError("eligible target must be expressible by the frozen Work1 contract")

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_id": self.target_id,
            "relative_file_path": self.relative_file_path,
            "function_signature": self.function_signature,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "root_cause": self.root_cause,
            "known_method": self.known_method,
            "native_codeql_uncovered": self.native_codeql_uncovered,
            "work1_contract_expressible": self.work1_contract_expressible,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EligibleTargetAnnotation":
        expected = {
            "target_id", "relative_file_path", "function_signature", "start_line", "end_line",
            "root_cause", "known_method", "native_codeql_uncovered", "work1_contract_expressible",
        }
        _exact_keys(value, expected, name="eligible target annotation")
        return cls(
            target_id=_non_empty(value["target_id"], "target_id"),
            relative_file_path=_non_empty(value["relative_file_path"], "relative_file_path"),
            function_signature=_non_empty(value["function_signature"], "function_signature"),
            start_line=_integer(value["start_line"], "start_line"),
            end_line=_integer(value["end_line"], "end_line"),
            root_cause=_non_empty(value["root_cause"], "root_cause"),
            known_method=_non_empty(value["known_method"], "known_method"),
            native_codeql_uncovered=value["native_codeql_uncovered"],
            work1_contract_expressible=value["work1_contract_expressible"],
        )


@dataclass(frozen=True, slots=True)
class EvaluatorSubjectAnnotation:
    annotation_id: str
    subject_id: str
    project_id: str
    repository_lineage_id: str
    dataset_split: DatasetSplit
    revision_role: RevisionRole
    cve_ids: tuple[str, ...]
    cwe_ids: tuple[str, ...]
    fix_revision: str | None
    eligible_targets: tuple[EligibleTargetAnnotation, ...]
    m6_diagnostics: tuple[str, ...]
    reviewer_annotations: tuple[str, ...]
    schema_version: int = EVALUATOR_MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or not isinstance(self.schema_version, int):
            raise TypeError("evaluator subject annotation schema_version must be an integer")
        if self.schema_version != EVALUATOR_MANIFEST_SCHEMA_VERSION:
            raise ValueError("unsupported evaluator subject annotation schema version")
        _opaque_id(self.subject_id, "subject")
        _opaque_id(self.project_id, "project")
        _opaque_id(self.repository_lineage_id, "lineage")
        if not isinstance(self.dataset_split, DatasetSplit):
            raise TypeError("dataset_split must be a DatasetSplit")
        if not isinstance(self.revision_role, RevisionRole):
            raise TypeError("revision_role must be a RevisionRole")
        _unique_sorted(self.cve_ids, "cve_ids")
        _unique_sorted(self.cwe_ids, "cwe_ids")
        if any(_CVE_RE.fullmatch(item) is None for item in self.cve_ids):
            raise ValueError("cve_ids must contain canonical CVE identifiers")
        if any(_CWE_RE.fullmatch(item) is None for item in self.cwe_ids):
            raise ValueError("cwe_ids must contain canonical CWE identifiers")
        if self.fix_revision is not None:
            _non_empty(self.fix_revision, "fix_revision")
        if any(not isinstance(item, EligibleTargetAnnotation) for item in self.eligible_targets):
            raise TypeError("eligible_targets must contain EligibleTargetAnnotation values")
        target_ids = tuple(item.target_id for item in self.eligible_targets)
        if len(target_ids) != len(set(target_ids)) or target_ids != tuple(sorted(target_ids)):
            raise ValueError("eligible_targets must have unique target_ids in canonical sorted order")
        if self.revision_role is not RevisionRole.VULNERABLE and self.eligible_targets:
            raise ValueError("only VULNERABLE revisions may carry eligible targets")
        _unique_sorted(self.m6_diagnostics, "m6_diagnostics")
        _unique_sorted(self.reviewer_annotations, "reviewer_annotations")
        if self.annotation_id != stable_digest("m8annotation", self.identity_material()):
            raise ValueError("evaluator annotation_id is not canonical")

    def identity_material(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "subject_id": self.subject_id,
            "project_id": self.project_id,
            "repository_lineage_id": self.repository_lineage_id,
            "dataset_split": self.dataset_split.value,
            "revision_role": self.revision_role.value,
            "cve_ids": list(self.cve_ids),
            "cwe_ids": list(self.cwe_ids),
            "fix_revision": self.fix_revision,
            "eligible_targets": [item.to_dict() for item in self.eligible_targets],
            "m6_diagnostics": list(self.m6_diagnostics),
            "reviewer_annotations": list(self.reviewer_annotations),
        }

    @classmethod
    def create(
        cls,
        *,
        subject_id: str,
        project_id: str,
        repository_lineage_id: str,
        dataset_split: DatasetSplit | str,
        revision_role: RevisionRole | str,
        cve_ids: Sequence[str] = (),
        cwe_ids: Sequence[str] = (),
        fix_revision: str | None = None,
        eligible_targets: Sequence[EligibleTargetAnnotation] = (),
        m6_diagnostics: Sequence[str] = (),
        reviewer_annotations: Sequence[str] = (),
    ) -> "EvaluatorSubjectAnnotation":
        values = {
            "subject_id": subject_id,
            "project_id": project_id,
            "repository_lineage_id": repository_lineage_id,
            "dataset_split": DatasetSplit(dataset_split),
            "revision_role": RevisionRole(revision_role),
            "cve_ids": tuple(sorted(cve_ids)),
            "cwe_ids": tuple(sorted(cwe_ids)),
            "fix_revision": fix_revision,
            "eligible_targets": tuple(sorted(eligible_targets, key=lambda item: item.target_id)),
            "m6_diagnostics": tuple(sorted(m6_diagnostics)),
            "reviewer_annotations": tuple(sorted(reviewer_annotations)),
        }
        material = {
            "schema_version": EVALUATOR_MANIFEST_SCHEMA_VERSION,
            "subject_id": values["subject_id"],
            "project_id": values["project_id"],
            "repository_lineage_id": values["repository_lineage_id"],
            "dataset_split": values["dataset_split"].value,
            "revision_role": values["revision_role"].value,
            "cve_ids": list(values["cve_ids"]),
            "cwe_ids": list(values["cwe_ids"]),
            "fix_revision": values["fix_revision"],
            "eligible_targets": [item.to_dict() for item in values["eligible_targets"]],
            "m6_diagnostics": list(values["m6_diagnostics"]),
            "reviewer_annotations": list(values["reviewer_annotations"]),
        }
        return cls(annotation_id=stable_digest("m8annotation", material), **values)

    def to_dict(self) -> dict[str, Any]:
        return {"annotation_id": self.annotation_id, **self.identity_material()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvaluatorSubjectAnnotation":
        expected = {
            "schema_version", "annotation_id", "subject_id", "project_id", "repository_lineage_id",
            "dataset_split", "revision_role", "cve_ids", "cwe_ids", "fix_revision",
            "eligible_targets", "m6_diagnostics", "reviewer_annotations",
        }
        _exact_keys(value, expected, name="evaluator subject annotation")
        targets = value["eligible_targets"]
        if not isinstance(targets, Sequence) or isinstance(targets, (str, bytes)):
            raise TypeError("eligible_targets must be an array")
        if any(not isinstance(item, Mapping) for item in targets):
            raise TypeError("eligible_targets must contain mappings")
        return cls(
            annotation_id=_non_empty(value["annotation_id"], "annotation_id"),
            subject_id=_non_empty(value["subject_id"], "subject_id"),
            project_id=_non_empty(value["project_id"], "project_id"),
            repository_lineage_id=_non_empty(
                value["repository_lineage_id"], "repository_lineage_id"
            ),
            dataset_split=DatasetSplit(_non_empty(value["dataset_split"], "dataset_split")),
            revision_role=RevisionRole(_non_empty(value["revision_role"], "revision_role")),
            cve_ids=_string_tuple(value["cve_ids"], "cve_ids"),
            cwe_ids=_string_tuple(value["cwe_ids"], "cwe_ids"),
            fix_revision=(
                _non_empty(value["fix_revision"], "fix_revision")
                if value["fix_revision"] is not None
                else None
            ),
            eligible_targets=tuple(EligibleTargetAnnotation.from_dict(item) for item in targets),
            m6_diagnostics=_string_tuple(value["m6_diagnostics"], "m6_diagnostics"),
            reviewer_annotations=_string_tuple(
                value["reviewer_annotations"], "reviewer_annotations"
            ),
            schema_version=_integer(value["schema_version"], "schema_version"),
        )


@dataclass(frozen=True, slots=True)
class EvaluatorAnnotationManifest:
    """Curator/evaluator-only annotation data; never a Detector input."""

    manifest_id: str
    annotations: tuple[EvaluatorSubjectAnnotation, ...]
    schema_version: int = EVALUATOR_MANIFEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or not isinstance(self.schema_version, int):
            raise TypeError("evaluator annotation manifest schema_version must be an integer")
        if self.schema_version != EVALUATOR_MANIFEST_SCHEMA_VERSION:
            raise ValueError("unsupported evaluator annotation manifest schema version")
        if not self.annotations:
            raise ValueError("evaluator annotation manifest requires at least one annotation")
        if any(not isinstance(item, EvaluatorSubjectAnnotation) for item in self.annotations):
            raise TypeError("annotations must contain EvaluatorSubjectAnnotation values")
        subject_ids = tuple(item.subject_id for item in self.annotations)
        if len(subject_ids) != len(set(subject_ids)):
            raise ValueError("evaluator annotation manifest has duplicate subject_id values")
        if subject_ids != tuple(sorted(subject_ids)):
            raise ValueError("evaluator annotations must be in canonical subject_id order")
        annotation_ids = tuple(item.annotation_id for item in self.annotations)
        if len(annotation_ids) != len(set(annotation_ids)):
            raise ValueError("evaluator annotation manifest has duplicate annotation_id values")
        project_lineage: dict[str, str] = {}
        for item in self.annotations:
            prior = project_lineage.setdefault(item.project_id, item.repository_lineage_id)
            if prior != item.repository_lineage_id:
                raise ValueError("one project_id cannot belong to multiple repository lineages")
        if self.manifest_id != stable_digest("m8evalmanifest", self.identity_material()):
            raise ValueError("evaluator manifest_id is not canonical")

    def identity_material(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "annotations": [item.to_dict() for item in self.annotations],
        }

    @classmethod
    def create(cls, annotations: Sequence[EvaluatorSubjectAnnotation]) -> "EvaluatorAnnotationManifest":
        values = tuple(sorted(annotations, key=lambda item: item.subject_id))
        material = {
            "schema_version": EVALUATOR_MANIFEST_SCHEMA_VERSION,
            "annotations": [item.to_dict() for item in values],
        }
        return cls(manifest_id=stable_digest("m8evalmanifest", material), annotations=values)

    def to_dict(self) -> dict[str, Any]:
        return {"manifest_id": self.manifest_id, **self.identity_material()}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "EvaluatorAnnotationManifest":
        expected = {"schema_version", "manifest_id", "annotations"}
        _exact_keys(value, expected, name="evaluator annotation manifest")
        annotations = value["annotations"]
        if not isinstance(annotations, Sequence) or isinstance(annotations, (str, bytes)):
            raise TypeError("annotations must be an array")
        if any(not isinstance(item, Mapping) for item in annotations):
            raise TypeError("annotations must contain mappings")
        return cls(
            manifest_id=_non_empty(value["manifest_id"], "manifest_id"),
            annotations=tuple(EvaluatorSubjectAnnotation.from_dict(item) for item in annotations),
            schema_version=_integer(value["schema_version"], "schema_version"),
        )

    def split_commitment_payload(self) -> dict[str, Any]:
        verify_repository_lineage_splits(self)
        grouped: dict[tuple[str, DatasetSplit], list[str]] = {}
        for annotation in self.annotations:
            grouped.setdefault(
                (annotation.repository_lineage_id, annotation.dataset_split), []
            ).append(annotation.subject_id)
        rows = [
            {
                "repository_lineage_id": lineage_id,
                "dataset_split": split.value,
                "subject_ids": sorted(subject_ids),
            }
            for (lineage_id, split), subject_ids in sorted(
                grouped.items(), key=lambda item: (item[0][0], item[0][1].value)
            )
        ]
        return {"schema_version": LINEAGE_SPLIT_SCHEMA_VERSION, "lineages": rows}


class LineageSplitViolation(ValueError):
    """Raised before any Detector run when lineage isolation is not proven."""


@dataclass(frozen=True, slots=True)
class LineageSplitVerification:
    verification_id: str
    subject_count: int
    lineage_count: int
    split_counts: tuple[tuple[DatasetSplit, int], ...]
    schema_version: int = LINEAGE_SPLIT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or not isinstance(self.schema_version, int):
            raise TypeError("lineage split verification schema_version must be an integer")
        if self.schema_version != LINEAGE_SPLIT_SCHEMA_VERSION:
            raise ValueError("unsupported lineage split verification schema version")
        if self.subject_count < 1 or self.lineage_count < 1:
            raise ValueError("lineage split verification counts must be positive")
        if any(count < 1 for _, count in self.split_counts):
            raise ValueError("lineage split counts must be positive")
        if tuple(split.value for split, _ in self.split_counts) != tuple(
            sorted(split.value for split, _ in self.split_counts)
        ):
            raise ValueError("split_counts must be in canonical order")
        if sum(count for _, count in self.split_counts) != self.lineage_count:
            raise ValueError("split_counts must account for every lineage")
        if self.verification_id != stable_digest("m8splitcheck", self.identity_material()):
            raise ValueError("lineage split verification_id is not canonical")

    def identity_material(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": "PASS",
            "subject_count": self.subject_count,
            "lineage_count": self.lineage_count,
            "split_counts": [
                {"dataset_split": split.value, "lineage_count": count}
                for split, count in self.split_counts
            ],
        }

    def to_dict(self) -> dict[str, Any]:
        return {"verification_id": self.verification_id, **self.identity_material()}


def _flatten_annotations(
    values: EvaluatorAnnotationManifest
    | Iterable[EvaluatorAnnotationManifest | EvaluatorSubjectAnnotation],
) -> tuple[EvaluatorSubjectAnnotation, ...]:
    if isinstance(values, EvaluatorAnnotationManifest):
        return values.annotations
    result: list[EvaluatorSubjectAnnotation] = []
    for value in values:
        if isinstance(value, EvaluatorAnnotationManifest):
            result.extend(value.annotations)
        elif isinstance(value, EvaluatorSubjectAnnotation):
            result.append(value)
        else:
            raise TypeError("lineage split verifier accepts evaluator manifests or annotations")
    return tuple(result)


def verify_repository_lineage_splits(
    values: EvaluatorAnnotationManifest
    | Iterable[EvaluatorAnnotationManifest | EvaluatorSubjectAnnotation],
) -> LineageSplitVerification:
    annotations = _flatten_annotations(values)
    if not annotations:
        raise LineageSplitViolation("lineage split verification requires evaluator annotations")

    subject_ids: set[str] = set()
    lineage_splits: dict[str, DatasetSplit] = {}
    project_lineages: dict[str, str] = {}
    for annotation in annotations:
        if annotation.subject_id in subject_ids:
            raise LineageSplitViolation(f"duplicate subject_id across split inputs: {annotation.subject_id}")
        subject_ids.add(annotation.subject_id)
        prior_split = lineage_splits.setdefault(annotation.repository_lineage_id, annotation.dataset_split)
        if prior_split is not annotation.dataset_split:
            raise LineageSplitViolation(
                f"repository lineage {annotation.repository_lineage_id} crosses "
                f"{prior_split.value} and {annotation.dataset_split.value}"
            )
        prior_lineage = project_lineages.setdefault(annotation.project_id, annotation.repository_lineage_id)
        if prior_lineage != annotation.repository_lineage_id:
            raise LineageSplitViolation(
                f"project {annotation.project_id} is assigned to multiple repository lineages"
            )

    counts: dict[DatasetSplit, int] = {}
    for split in lineage_splits.values():
        counts[split] = counts.get(split, 0) + 1
    split_counts = tuple(sorted(counts.items(), key=lambda item: item[0].value))
    material = {
        "schema_version": LINEAGE_SPLIT_SCHEMA_VERSION,
        "status": "PASS",
        "subject_count": len(subject_ids),
        "lineage_count": len(lineage_splits),
        "split_counts": [
            {"dataset_split": split.value, "lineage_count": count}
            for split, count in split_counts
        ],
    }
    return LineageSplitVerification(
        verification_id=stable_digest("m8splitcheck", material),
        subject_count=len(subject_ids),
        lineage_count=len(lineage_splits),
        split_counts=split_counts,
    )


class RepositoryLineageSplitVerifier:
    @staticmethod
    def verify(
        values: EvaluatorAnnotationManifest
        | Iterable[EvaluatorAnnotationManifest | EvaluatorSubjectAnnotation],
    ) -> LineageSplitVerification:
        return verify_repository_lineage_splits(values)
