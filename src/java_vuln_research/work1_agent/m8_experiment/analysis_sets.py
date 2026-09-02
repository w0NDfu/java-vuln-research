"""Pre-treatment primary and safety analysis-set registry for M8."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.proposal.model import stable_digest

from .subjects import (
    DatasetSplit,
    EvaluatorAnnotationManifest,
    EvaluatorSubjectAnnotation,
    RevisionRole,
    _exact_keys,
    _integer,
    _non_empty,
    _opaque_id,
    _string_tuple,
)


ANALYSIS_SET_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class PrimaryEligibleLineage:
    repository_lineage_id: str
    primary_vulnerable_subject_id: str
    eligible_target_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        _opaque_id(self.repository_lineage_id, "lineage")
        _opaque_id(self.primary_vulnerable_subject_id, "subject")
        if not self.eligible_target_ids:
            raise ValueError("primary eligible lineage requires at least one eligible target")
        for target_id in self.eligible_target_ids:
            _opaque_id(target_id, "target")
        if len(self.eligible_target_ids) != len(set(self.eligible_target_ids)):
            raise ValueError("eligible_target_ids must not contain duplicates")
        if self.eligible_target_ids != tuple(sorted(self.eligible_target_ids)):
            raise ValueError("eligible_target_ids must be in canonical sorted order")

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_lineage_id": self.repository_lineage_id,
            "primary_vulnerable_subject_id": self.primary_vulnerable_subject_id,
            "eligible_target_ids": list(self.eligible_target_ids),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PrimaryEligibleLineage":
        expected = {"repository_lineage_id", "primary_vulnerable_subject_id", "eligible_target_ids"}
        _exact_keys(value, expected, name="primary eligible lineage")
        return cls(
            repository_lineage_id=_non_empty(
                value["repository_lineage_id"], "repository_lineage_id"
            ),
            primary_vulnerable_subject_id=_non_empty(
                value["primary_vulnerable_subject_id"], "primary_vulnerable_subject_id"
            ),
            eligible_target_ids=_string_tuple(
                value["eligible_target_ids"], "eligible_target_ids"
            ),
        )


@dataclass(frozen=True, slots=True)
class PreTreatmentAnalysisSetRegistry:
    """Evaluator-only frozen denominator registry created before any arm runs."""

    registry_id: str
    dataset_split: DatasetSplit
    scheduled_subject_ids: tuple[str, ...]
    primary_eligible_lineages: tuple[PrimaryEligibleLineage, ...]
    safety_only_lineages: tuple[str, ...]
    schema_version: int = ANALYSIS_SET_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if isinstance(self.schema_version, bool) or not isinstance(self.schema_version, int):
            raise TypeError("analysis-set registry schema_version must be an integer")
        if self.schema_version != ANALYSIS_SET_SCHEMA_VERSION:
            raise ValueError("unsupported analysis-set registry schema version")
        if self.dataset_split is not DatasetSplit.FORMAL_HOLDOUT:
            raise ValueError("confirmatory analysis-set registry must use formal-holdout")
        if not self.scheduled_subject_ids:
            raise ValueError("analysis-set registry requires scheduled subjects")
        for subject_id in self.scheduled_subject_ids:
            _opaque_id(subject_id, "subject")
        if len(self.scheduled_subject_ids) != len(set(self.scheduled_subject_ids)):
            raise ValueError("scheduled_subject_ids must not contain duplicates")
        if self.scheduled_subject_ids != tuple(sorted(self.scheduled_subject_ids)):
            raise ValueError("scheduled_subject_ids must be in canonical sorted order")
        if any(not isinstance(item, PrimaryEligibleLineage) for item in self.primary_eligible_lineages):
            raise TypeError("primary_eligible_lineages must contain PrimaryEligibleLineage values")
        primary_ids = tuple(item.repository_lineage_id for item in self.primary_eligible_lineages)
        if len(primary_ids) != len(set(primary_ids)):
            raise ValueError("primary_eligible_lineages must not contain duplicate lineages")
        if primary_ids != tuple(sorted(primary_ids)):
            raise ValueError("primary_eligible_lineages must be in canonical lineage order")
        for lineage_id in self.safety_only_lineages:
            _opaque_id(lineage_id, "lineage")
        if len(self.safety_only_lineages) != len(set(self.safety_only_lineages)):
            raise ValueError("safety_only_lineages must not contain duplicates")
        if self.safety_only_lineages != tuple(sorted(self.safety_only_lineages)):
            raise ValueError("safety_only_lineages must be in canonical order")
        if set(primary_ids).intersection(self.safety_only_lineages):
            raise ValueError("primary and safety-only lineage sets must be disjoint")
        primary_subjects = tuple(item.primary_vulnerable_subject_id for item in self.primary_eligible_lineages)
        if len(primary_subjects) != len(set(primary_subjects)):
            raise ValueError("a primary vulnerable subject may represent only one lineage")
        if not set(primary_subjects).issubset(self.scheduled_subject_ids):
            raise ValueError("every primary vulnerable subject must be scheduled")
        if self.registry_id != stable_digest("m8analysisset", self.identity_material()):
            raise ValueError("analysis-set registry_id is not canonical")

    @property
    def formal_primary_analysis_set(self) -> tuple[str, ...]:
        return tuple(item.repository_lineage_id for item in self.primary_eligible_lineages)

    @property
    def formal_safety_analysis_set(self) -> tuple[str, ...]:
        return tuple(sorted((*self.formal_primary_analysis_set, *self.safety_only_lineages)))

    @property
    def formal_primary_n(self) -> int:
        return len(self.primary_eligible_lineages)

    def identity_material(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "dataset_split": self.dataset_split.value,
            "scheduled_subject_ids": list(self.scheduled_subject_ids),
            "primary_eligible_lineages": [item.to_dict() for item in self.primary_eligible_lineages],
            "safety_only_lineages": list(self.safety_only_lineages),
            "formal_primary_analysis_set": list(self.formal_primary_analysis_set),
            "formal_safety_analysis_set": list(self.formal_safety_analysis_set),
            "formal_primary_n": self.formal_primary_n,
        }

    def to_dict(self) -> dict[str, Any]:
        return {"registry_id": self.registry_id, **self.identity_material()}

    @classmethod
    def create(
        cls,
        annotations: EvaluatorAnnotationManifest,
        *,
        primary_subject_by_lineage: Mapping[str, str],
        scheduled_subject_ids: Sequence[str] | None = None,
    ) -> "PreTreatmentAnalysisSetRegistry":
        by_subject = {item.subject_id: item for item in annotations.annotations}
        selected_ids = tuple(
            sorted(
                scheduled_subject_ids
                if scheduled_subject_ids is not None
                else (
                    item.subject_id
                    for item in annotations.annotations
                    if item.dataset_split is DatasetSplit.FORMAL_HOLDOUT
                )
            )
        )
        if len(selected_ids) != len(set(selected_ids)):
            raise ValueError("scheduled_subject_ids must not contain duplicates")
        missing = sorted(set(selected_ids) - set(by_subject))
        if missing:
            raise ValueError(f"scheduled subjects missing evaluator annotations: {missing}")
        selected = tuple(by_subject[subject_id] for subject_id in selected_ids)
        if not selected:
            raise ValueError("formal analysis-set registry requires scheduled annotations")
        if any(item.dataset_split is not DatasetSplit.FORMAL_HOLDOUT for item in selected):
            raise ValueError("formal analysis-set subjects must all belong to formal-holdout")

        subjects_by_lineage: dict[str, list[EvaluatorSubjectAnnotation]] = {}
        for item in selected:
            subjects_by_lineage.setdefault(item.repository_lineage_id, []).append(item)

        requested = {str(lineage): str(subject) for lineage, subject in primary_subject_by_lineage.items()}
        unknown_lineages = sorted(set(requested) - set(subjects_by_lineage))
        if unknown_lineages:
            raise ValueError(f"primary mappings reference unscheduled lineages: {unknown_lineages}")

        primary: list[PrimaryEligibleLineage] = []
        safety: list[str] = []
        for lineage_id, lineage_subjects in sorted(subjects_by_lineage.items()):
            target_bearing = [item for item in lineage_subjects if item.eligible_targets]
            primary_subject_id = requested.get(lineage_id)
            if target_bearing and primary_subject_id is None:
                raise ValueError(f"eligible lineage {lineage_id} requires one primary vulnerable subject")
            if not target_bearing and primary_subject_id is not None:
                raise ValueError(f"safety-only lineage {lineage_id} cannot claim a primary subject")
            if primary_subject_id is None:
                safety.append(lineage_id)
                continue
            matches = [item for item in lineage_subjects if item.subject_id == primary_subject_id]
            if len(matches) != 1:
                raise ValueError(
                    f"primary subject {primary_subject_id} must occur exactly once in lineage {lineage_id}"
                )
            chosen = matches[0]
            if chosen.revision_role is not RevisionRole.VULNERABLE:
                raise ValueError("primary subject must have VULNERABLE revision role")
            if not chosen.eligible_targets:
                raise ValueError("primary subject must contain at least one eligible target")
            primary.append(
                PrimaryEligibleLineage(
                    repository_lineage_id=lineage_id,
                    primary_vulnerable_subject_id=chosen.subject_id,
                    eligible_target_ids=tuple(target.target_id for target in chosen.eligible_targets),
                )
            )

        values = {
            "dataset_split": DatasetSplit.FORMAL_HOLDOUT,
            "scheduled_subject_ids": selected_ids,
            "primary_eligible_lineages": tuple(primary),
            "safety_only_lineages": tuple(safety),
        }
        formal_primary = tuple(item.repository_lineage_id for item in values["primary_eligible_lineages"])
        formal_safety = tuple(sorted((*formal_primary, *values["safety_only_lineages"])))
        material = {
            "schema_version": ANALYSIS_SET_SCHEMA_VERSION,
            "dataset_split": values["dataset_split"].value,
            "scheduled_subject_ids": list(values["scheduled_subject_ids"]),
            "primary_eligible_lineages": [
                item.to_dict() for item in values["primary_eligible_lineages"]
            ],
            "safety_only_lineages": list(values["safety_only_lineages"]),
            "formal_primary_analysis_set": list(formal_primary),
            "formal_safety_analysis_set": list(formal_safety),
            "formal_primary_n": len(formal_primary),
        }
        return cls(registry_id=stable_digest("m8analysisset", material), **values)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PreTreatmentAnalysisSetRegistry":
        expected = {
            "schema_version", "registry_id", "dataset_split", "scheduled_subject_ids",
            "primary_eligible_lineages", "safety_only_lineages", "formal_primary_analysis_set",
            "formal_safety_analysis_set", "formal_primary_n",
        }
        _exact_keys(value, expected, name="analysis-set registry")
        primary_rows = value["primary_eligible_lineages"]
        if not isinstance(primary_rows, Sequence) or isinstance(
            primary_rows, (str, bytes, bytearray)
        ):
            raise TypeError("primary_eligible_lineages must be an array")
        if any(not isinstance(item, Mapping) for item in primary_rows):
            raise TypeError("primary_eligible_lineages must contain mappings")
        result = cls(
            registry_id=_non_empty(value["registry_id"], "registry_id"),
            dataset_split=DatasetSplit(_non_empty(value["dataset_split"], "dataset_split")),
            scheduled_subject_ids=_string_tuple(
                value["scheduled_subject_ids"], "scheduled_subject_ids"
            ),
            primary_eligible_lineages=tuple(
                PrimaryEligibleLineage.from_dict(item) for item in primary_rows
            ),
            safety_only_lineages=_string_tuple(
                value["safety_only_lineages"], "safety_only_lineages"
            ),
            schema_version=_integer(value["schema_version"], "schema_version"),
        )
        encoded_primary = _string_tuple(
            value["formal_primary_analysis_set"], "formal_primary_analysis_set"
        )
        encoded_safety = _string_tuple(
            value["formal_safety_analysis_set"], "formal_safety_analysis_set"
        )
        if result.formal_primary_analysis_set != encoded_primary:
            raise ValueError("formal_primary_analysis_set does not match primary lineage registry")
        if result.formal_safety_analysis_set != encoded_safety:
            raise ValueError("formal_safety_analysis_set does not match scheduled lineage registry")
        if _integer(value["formal_primary_n"], "formal_primary_n") != result.formal_primary_n:
            raise ValueError("formal_primary_n does not match the frozen primary denominator")
        return result

    def validate_against(self, annotations: EvaluatorAnnotationManifest) -> None:
        expected = type(self).create(
            annotations,
            primary_subject_by_lineage={
                item.repository_lineage_id: item.primary_vulnerable_subject_id
                for item in self.primary_eligible_lineages
            },
            scheduled_subject_ids=self.scheduled_subject_ids,
        )
        if expected.to_dict() != self.to_dict():
            raise ValueError("analysis-set registry does not match evaluator annotations")

    def eligibility_commitment_payload(
        self, annotations: EvaluatorAnnotationManifest
    ) -> dict[str, Any]:
        self.validate_against(annotations)
        scheduled = set(self.scheduled_subject_ids)
        annotation_rows = [
            item.to_dict() for item in annotations.annotations if item.subject_id in scheduled
        ]
        if len(annotation_rows) != len(scheduled):
            raise ValueError("eligibility commitment is missing scheduled evaluator annotations")
        return {
            "schema_version": ANALYSIS_SET_SCHEMA_VERSION,
            "analysis_set_registry": self.to_dict(),
            "scheduled_evaluator_annotations": annotation_rows,
        }
