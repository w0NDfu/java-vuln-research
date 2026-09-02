from __future__ import annotations

import pytest

from java_vuln_research.work1_agent.m8_experiment.commitments import (
    commit_eligibility_manifest,
    verify_manifest_commitment,
)
from java_vuln_research.work1_agent.m8_experiment.analysis_sets import (
    PreTreatmentAnalysisSetRegistry,
)
from java_vuln_research.work1_agent.m8_experiment.subjects import (
    DatasetSplit,
    EligibleTargetAnnotation,
    EvaluatorAnnotationManifest,
    EvaluatorSubjectAnnotation,
    RevisionRole,
)


def _id(namespace: str, digit: str) -> str:
    return f"{namespace}-{digit * 32}"


def _target(digit: str = "a") -> EligibleTargetAnnotation:
    return EligibleTargetAnnotation(
        target_id=_id("target", digit),
        relative_file_path="src/main/java/example/Controller.java",
        function_signature="example.Controller.execute(java.lang.String)",
        start_line=20,
        end_line=25,
        root_cause="Input reaches an effect without the required guard",
        known_method="Frozen curator trace",
    )


def _annotation(
    *,
    subject: str,
    project: str,
    lineage: str,
    role: RevisionRole,
    targets: tuple[EligibleTargetAnnotation, ...] = (),
) -> EvaluatorSubjectAnnotation:
    return EvaluatorSubjectAnnotation.create(
        subject_id=_id("subject", subject),
        project_id=_id("project", project),
        repository_lineage_id=_id("lineage", lineage),
        dataset_split=DatasetSplit.FORMAL_HOLDOUT,
        revision_role=role,
        cve_ids=("CVE-2026-22222",) if role is RevisionRole.VULNERABLE else (),
        cwe_ids=("CWE-22",) if role is RevisionRole.VULNERABLE else (),
        eligible_targets=targets,
    )


def _manifest(*, target_digit: str = "a") -> EvaluatorAnnotationManifest:
    return EvaluatorAnnotationManifest.create(
        (
            _annotation(
                subject="1",
                project="1",
                lineage="a",
                role=RevisionRole.VULNERABLE,
                targets=(_target(target_digit),),
            ),
            _annotation(subject="2", project="1", lineage="a", role=RevisionRole.FIXED),
            _annotation(subject="3", project="2", lineage="b", role=RevisionRole.BENIGN),
            _annotation(subject="4", project="3", lineage="c", role=RevisionRole.VULNERABLE),
        )
    )


def test_pre_treatment_registry_freezes_primary_denominator_and_safety_union() -> None:
    manifest = _manifest()
    registry = PreTreatmentAnalysisSetRegistry.create(
        manifest,
        primary_subject_by_lineage={_id("lineage", "a"): _id("subject", "1")},
    )

    assert registry.formal_primary_n == 1
    assert registry.formal_primary_analysis_set == (_id("lineage", "a"),)
    assert registry.safety_only_lineages == (_id("lineage", "b"), _id("lineage", "c"))
    assert registry.formal_safety_analysis_set == (
        _id("lineage", "a"),
        _id("lineage", "b"),
        _id("lineage", "c"),
    )
    assert registry.primary_eligible_lineages[0].primary_vulnerable_subject_id == _id("subject", "1")
    assert PreTreatmentAnalysisSetRegistry.from_dict(registry.to_dict()) == registry
    registry.validate_against(manifest)


def test_fixed_benign_and_targetless_vulnerable_lineages_are_safety_only() -> None:
    registry = PreTreatmentAnalysisSetRegistry.create(
        _manifest(),
        primary_subject_by_lineage={_id("lineage", "a"): _id("subject", "1")},
    )

    assert _id("lineage", "a") not in registry.safety_only_lineages
    assert {_id("lineage", "b"), _id("lineage", "c")} == set(registry.safety_only_lineages)


def test_eligible_lineage_without_primary_subject_is_rejected() -> None:
    with pytest.raises(ValueError, match="requires one primary vulnerable subject"):
        PreTreatmentAnalysisSetRegistry.create(_manifest(), primary_subject_by_lineage={})


def test_primary_subject_must_be_vulnerable_revision() -> None:
    with pytest.raises(ValueError, match="primary subject must have VULNERABLE revision role"):
        PreTreatmentAnalysisSetRegistry.create(
            _manifest(),
            primary_subject_by_lineage={_id("lineage", "a"): _id("subject", "2")},
        )


def test_primary_subject_must_itself_carry_an_eligible_target() -> None:
    base = _manifest()
    targetless = _annotation(
        subject="5", project="1", lineage="a", role=RevisionRole.VULNERABLE
    )
    manifest = EvaluatorAnnotationManifest.create((*base.annotations, targetless))

    with pytest.raises(ValueError, match="primary subject must contain at least one eligible target"):
        PreTreatmentAnalysisSetRegistry.create(
            manifest,
            primary_subject_by_lineage={_id("lineage", "a"): _id("subject", "5")},
        )


def test_analysis_registry_rejects_post_treatment_outcome_fields() -> None:
    registry = PreTreatmentAnalysisSetRegistry.create(
        _manifest(),
        primary_subject_by_lineage={_id("lineage", "a"): _id("subject", "1")},
    )
    encoded = registry.to_dict()
    encoded["arm_successes"] = {"M1": 1}

    with pytest.raises(ValueError, match="unknown=.*arm_successes"):
        PreTreatmentAnalysisSetRegistry.from_dict(encoded)


def test_registry_cross_check_detects_changed_eligibility_annotation() -> None:
    registry = PreTreatmentAnalysisSetRegistry.create(
        _manifest(target_digit="a"),
        primary_subject_by_lineage={_id("lineage", "a"): _id("subject", "1")},
    )

    with pytest.raises(ValueError, match="does not match evaluator annotations"):
        registry.validate_against(_manifest(target_digit="b"))


def test_eligibility_commitment_payload_binds_full_scheduled_annotations() -> None:
    key = bytes(range(32))
    original = _manifest()
    registry = PreTreatmentAnalysisSetRegistry.create(
        original,
        primary_subject_by_lineage={_id("lineage", "a"): _id("subject", "1")},
    )
    commitment = commit_eligibility_manifest(
        registry.eligibility_commitment_payload(original), secret_key=key
    )

    changed_target = EligibleTargetAnnotation(
        target_id=_id("target", "a"),
        relative_file_path="src/main/java/example/Controller.java",
        function_signature="example.Controller.execute(java.lang.String)",
        start_line=20,
        end_line=25,
        root_cause="Changed curator root-cause statement",
        known_method="Frozen curator trace",
    )
    changed_annotations = tuple(
        _annotation(
            subject="1",
            project="1",
            lineage="a",
            role=RevisionRole.VULNERABLE,
            targets=(changed_target,),
        )
        if item.subject_id == _id("subject", "1")
        else item
        for item in original.annotations
    )
    changed = EvaluatorAnnotationManifest.create(changed_annotations)

    assert not verify_manifest_commitment(
        registry.eligibility_commitment_payload(changed), commitment, secret_key=key
    )


def test_explicit_schedule_cannot_reference_non_formal_or_unknown_subject() -> None:
    with pytest.raises(ValueError, match="missing evaluator annotations"):
        PreTreatmentAnalysisSetRegistry.create(
            _manifest(),
            primary_subject_by_lineage={_id("lineage", "a"): _id("subject", "1")},
            scheduled_subject_ids=(_id("subject", "f"),),
        )
