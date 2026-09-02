from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import pytest

from java_vuln_research.work1_agent.m8_experiment.arms import RunKey, get_arm_spec
from java_vuln_research.work1_agent.m8_experiment.commitments import (
    commit_eligibility_manifest,
    commit_split_manifest,
)
from java_vuln_research.work1_agent.m8_experiment.subjects import (
    ArtifactIdentity,
    CodeQLDatabaseStatus,
    DatasetSplit,
    DetectorSubjectManifest,
    EligibleTargetAnnotation,
    EvaluatorAnnotationManifest,
    EvaluatorSubjectAnnotation,
    GenericArtifactIdentity,
    GenericArtifactStage,
    LineageSplitViolation,
    RevisionRole,
    verify_repository_lineage_splits,
)


KEY = bytes(range(32))


def _id(namespace: str, digit: str) -> str:
    return f"{namespace}-{digit * 32}"


def _target(digit: str = "a") -> EligibleTargetAnnotation:
    return EligibleTargetAnnotation(
        target_id=_id("target", digit),
        relative_file_path="src/main/java/example/Handler.java",
        function_signature="example.Handler.handle(java.lang.String)",
        start_line=41,
        end_line=47,
        root_cause="Untrusted request value reaches a process launch boundary",
        known_method="Manual source-to-effect trace",
    )


def _annotation(
    *,
    subject: str,
    project: str,
    lineage: str,
    split: DatasetSplit,
    role: RevisionRole = RevisionRole.BENIGN,
    targets: tuple[EligibleTargetAnnotation, ...] = (),
) -> EvaluatorSubjectAnnotation:
    return EvaluatorSubjectAnnotation.create(
        subject_id=_id("subject", subject),
        project_id=_id("project", project),
        repository_lineage_id=_id("lineage", lineage),
        dataset_split=split,
        revision_role=role,
        cve_ids=("CVE-2026-12345",) if role is RevisionRole.VULNERABLE else (),
        cwe_ids=("CWE-78",) if role is RevisionRole.VULNERABLE else (),
        fix_revision="f00df00d" if role is RevisionRole.VULNERABLE else None,
        eligible_targets=targets,
        m6_diagnostics=("curator-only diagnostic",),
        reviewer_annotations=("curator-only annotation",),
    )


def _artifact(digit: str = "a") -> ArtifactIdentity:
    return ArtifactIdentity(identity_sha256=digit * 64, size_bytes=100)


def _detector_manifest() -> DetectorSubjectManifest:
    split_tag = commit_split_manifest({"lineages": ["sealed"]}, secret_key=KEY)
    eligibility_tag = commit_eligibility_manifest({"eligible": ["sealed"]}, secret_key=KEY)
    run_key = RunKey(
        study_id="study-01",
        split="formal-holdout",
        subject_id=_id("subject", "1"),
        arm_id="m8_m1",
        replicate_index=1,
        run_id="run-0001",
    )
    return DetectorSubjectManifest.create(
        run_key=run_key,
        project_id=_id("project", "2"),
        repository_revision="698fb7248ae30cb7f7782d59c841f05ad70ea9cc",
        source_root="/workspace/cohort/subjects/11111111111111111111111111111111",
        codeql_db_path="/workspace/cohort/codeql/11111111111111111111111111111111",
        codeql_db_status=CodeQLDatabaseStatus.READY,
        codeql_db_identity=_artifact("1"),
        native_codeql_artifact_identity=_artifact("2"),
        generic_artifact_identities=tuple(
            GenericArtifactIdentity(stage=stage, artifact=_artifact(str(index)))
            for index, stage in enumerate(GenericArtifactStage, start=3)
        ),
        schedule_sha256="b" * 64,
        config_sha256="c" * 64,
        budget_sha256="d" * 64,
        split_commitment=split_tag,
        eligibility_commitment=eligibility_tag,
    )


def _keys(value: Any) -> set[str]:
    result: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            result.add(str(key).lower())
            result.update(_keys(item))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for item in value:
            result.update(_keys(item))
    return result


def test_detector_manifest_is_canonical_and_excludes_evaluator_fields() -> None:
    manifest = _detector_manifest()
    encoded = manifest.to_dict()

    assert DetectorSubjectManifest.from_dict(encoded) == manifest
    assert {
        "repository_lineage_id",
        "primary_vulnerable_subject_id",
        "revision_role",
        "cve_ids",
        "cwe_ids",
        "eligible_targets",
        "root_cause",
        "known_method",
        "m6_diagnostics",
        "reviewer_annotations",
    }.isdisjoint(_keys(encoded))
    assert encoded["split_commitment"].startswith("m8c1:SPLIT:HMAC-SHA-256:")
    assert encoded["eligibility_commitment"].startswith("m8c1:ELIGIBILITY:HMAC-SHA-256:")
    assert encoded["arm_id"] == "m8_m1"
    assert encoded["arm_spec_sha256"] == get_arm_spec("m8_m1").sha256
    assert encoded["run_key"]["run_key_sha256"]


def test_detector_manifest_rejects_unknown_or_tampered_fields() -> None:
    encoded = _detector_manifest().to_dict()
    encoded["repository_lineage_id"] = _id("lineage", "3")
    with pytest.raises(ValueError, match="unknown=.*repository_lineage_id"):
        DetectorSubjectManifest.from_dict(encoded)

    encoded = _detector_manifest().to_dict()
    encoded["repository_revision"] = "f" * 40
    with pytest.raises(ValueError, match="manifest_id is not canonical"):
        DetectorSubjectManifest.from_dict(encoded)

    encoded = _detector_manifest().to_dict()
    encoded["replicate_index"] = True
    with pytest.raises(TypeError, match="replicate_index must be an integer"):
        DetectorSubjectManifest.from_dict(encoded)

    encoded = _detector_manifest().to_dict()
    encoded["arm_spec_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="does not match the frozen registered arm"):
        DetectorSubjectManifest.from_dict(encoded)


def test_detector_manifest_rejects_role_or_annotation_semantics_in_paths() -> None:
    manifest = _detector_manifest()
    values = manifest.to_dict()
    values.pop("manifest_id")
    values["source_root"] = "/workspace/cohort/vulnerable/project"

    with pytest.raises(ValueError, match="forbidden evaluator or revision-role semantics"):
        DetectorSubjectManifest.create(
            run_key=RunKey.from_dict(values["run_key"]),
            project_id=values["project_id"],
            repository_revision=values["repository_revision"],
            source_root=values["source_root"],
            codeql_db_path=values["codeql_db_path"],
            codeql_db_status=values["codeql_db_status"],
            codeql_db_identity=ArtifactIdentity.from_dict(values["codeql_db_identity"]),
            native_codeql_artifact_identity=ArtifactIdentity.from_dict(
                values["native_codeql_artifact_identity"]
            ),
            generic_artifact_identities=tuple(
                GenericArtifactIdentity.from_dict(item)
                for item in values["generic_artifact_identities"]
            ),
            schedule_sha256=values["schedule_sha256"],
            config_sha256=values["config_sha256"],
            budget_sha256=values["budget_sha256"],
            split_commitment=values["split_commitment"],
            eligibility_commitment=values["eligibility_commitment"],
        )


def test_evaluator_manifest_keeps_ground_truth_in_evaluator_contract() -> None:
    vulnerable = _annotation(
        subject="1",
        project="2",
        lineage="3",
        split=DatasetSplit.FORMAL_HOLDOUT,
        role=RevisionRole.VULNERABLE,
        targets=(_target(),),
    )
    manifest = EvaluatorAnnotationManifest.create((vulnerable,))
    encoded = manifest.to_dict()

    assert EvaluatorAnnotationManifest.from_dict(encoded) == manifest
    annotation = encoded["annotations"][0]
    assert annotation["repository_lineage_id"] == _id("lineage", "3")
    assert annotation["revision_role"] == "VULNERABLE"
    assert annotation["cve_ids"] == ["CVE-2026-12345"]
    assert annotation["eligible_targets"][0]["relative_file_path"].endswith("Handler.java")


def test_lineage_split_verifier_passes_same_split_revisions_and_counts_lineages() -> None:
    records = (
        _annotation(subject="1", project="1", lineage="a", split=DatasetSplit.DEV_TUNE),
        _annotation(subject="2", project="1", lineage="a", split=DatasetSplit.DEV_TUNE),
        _annotation(subject="3", project="2", lineage="b", split=DatasetSplit.FORMAL_HOLDOUT),
    )

    result = verify_repository_lineage_splits(records)

    assert result.to_dict()["status"] == "PASS"
    assert result.subject_count == 3
    assert result.lineage_count == 2
    assert result.to_dict()["split_counts"] == [
        {"dataset_split": "dev-tune", "lineage_count": 1},
        {"dataset_split": "formal-holdout", "lineage_count": 1},
    ]


def test_lineage_split_verifier_fails_closed_when_lineage_crosses_splits() -> None:
    records = (
        _annotation(subject="1", project="1", lineage="a", split=DatasetSplit.DEV_TUNE),
        _annotation(subject="2", project="2", lineage="a", split=DatasetSplit.FORMAL_HOLDOUT),
    )

    with pytest.raises(LineageSplitViolation, match="crosses dev-tune and formal-holdout"):
        verify_repository_lineage_splits(records)

    invalid_manifest = EvaluatorAnnotationManifest.create(records)
    with pytest.raises(LineageSplitViolation, match="crosses dev-tune and formal-holdout"):
        invalid_manifest.split_commitment_payload()


def test_lineage_split_verifier_rejects_duplicate_subject_inputs() -> None:
    record = _annotation(subject="1", project="1", lineage="a", split=DatasetSplit.DEV_VALIDATION)
    with pytest.raises(LineageSplitViolation, match="duplicate subject_id"):
        verify_repository_lineage_splits((record, record))


def test_evaluator_contract_rejects_targets_on_fixed_or_benign_revisions() -> None:
    with pytest.raises(ValueError, match="only VULNERABLE"):
        _annotation(
            subject="1",
            project="1",
            lineage="a",
            split=DatasetSplit.FORMAL_HOLDOUT,
            role=RevisionRole.FIXED,
            targets=(_target(),),
        )
