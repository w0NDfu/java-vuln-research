from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

from java_vuln_research.work1_agent.repository.entity import ProgramEntity, normalise_repository_path

from .evidence import EvidenceRef, EvidenceSourceKind, EvidenceStrength
from .model import SecurityProposal, canonical_json
from .roles import proposal_role_refs, validate_role
from .validator import validate_proposal_shape, validate_scope


GATE_VERSION = "WORK1_V11_M4_EVIDENCE_GATE_V1"


class GateStatus(str, Enum):
    ADMISSIBLE = "ADMISSIBLE"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"
    REJECTED = "REJECTED"
    DUPLICATE = "DUPLICATE"
    ALREADY_SUPPORTED = "ALREADY_SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"


class CheckStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True, slots=True)
class GateCheck:
    check: str
    status: CheckStatus
    details: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"check": self.check, "status": self.status.value, "details": list(self.details)}


@dataclass(slots=True)
class EvidenceGateResult:
    proposal_id: str
    status: GateStatus
    checks: list[GateCheck]
    resolved_evidence: list[dict[str, Any]] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    rejection_reasons: list[str] = field(default_factory=list)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "status": self.status.value,
            "checks": [item.to_dict() for item in self.checks],
            "resolved_evidence": self.resolved_evidence,
            "missing_evidence": self.missing_evidence,
            "warnings": self.warnings,
            "rejection_reasons": self.rejection_reasons,
            "provenance": self.provenance,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())


class EvidenceGate:
    """Admit grounded semantic hypotheses without deciding truth or vulnerability."""

    def __init__(
        self,
        *,
        repository_root: str | Path,
        entities: Sequence[ProgramEntity],
        evidence_catalog: Mapping[str, EvidenceRef],
        artifact_index: Mapping[str, Mapping[str, Any]] | None = None,
        native_relation_ids: Sequence[str] = (),
        seen_proposal_ids: Sequence[str] = (),
    ) -> None:
        self.repository_root = Path(repository_root).resolve()
        self.entities = {item.entity_id: item for item in entities}
        self.evidence_catalog = dict(evidence_catalog)
        self.artifact_index = dict(artifact_index or {})
        self.native_relation_ids = frozenset(native_relation_ids)
        self.seen_proposal_ids = set(seen_proposal_ids)

    @staticmethod
    def _check(name: str, errors: Sequence[str]) -> GateCheck:
        return GateCheck(name, CheckStatus.FAIL if errors else CheckStatus.PASS, tuple(errors))

    def _source_path(self, relative: str) -> Path | None:
        try:
            normalised = normalise_repository_path(relative)
        except ValueError:
            return None
        candidate = (self.repository_root / Path(*normalised.split("/"))).resolve()
        try:
            candidate.relative_to(self.repository_root)
        except ValueError:
            return None
        return candidate

    def _location_errors(self, proposal: SecurityProposal) -> list[str]:
        errors: list[str] = []
        entity_ids = set(proposal.scope.entity_ids)
        entity_ids.update(ref.entity_id for ref in proposal_role_refs(proposal.subject, proposal.source, proposal.target))
        for entity_id in sorted(entity_ids):
            entity = self.entities.get(entity_id)
            if entity is None:
                continue
            path = self._source_path(entity.repository_relative_path)
            if path is None or not path.is_file():
                errors.append(f"ENTITY_FILE_NOT_FOUND:{entity_id}")
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                errors.append(f"ENTITY_FILE_UNREADABLE:{entity_id}")
                continue
            if entity.start_line < 1 or entity.end_line < entity.start_line or entity.end_line > len(lines):
                errors.append(f"ENTITY_RANGE_INVALID:{entity_id}")
        return errors

    def _resolve_evidence(self, evidence: EvidenceRef) -> tuple[dict[str, Any] | None, list[str]]:
        errors: list[str] = []
        for entity_id in evidence.entity_ids:
            if entity_id not in self.entities:
                errors.append(f"EVIDENCE_ENTITY_NOT_FOUND:{entity_id}")
        content_hash = None
        if evidence.repository_relative_path is not None:
            path = self._source_path(evidence.repository_relative_path)
            if path is None or not path.is_file():
                errors.append(f"EVIDENCE_FILE_NOT_FOUND:{evidence.repository_relative_path}")
            else:
                try:
                    lines = path.read_text(encoding="utf-8").splitlines()
                except (OSError, UnicodeDecodeError):
                    errors.append(f"EVIDENCE_FILE_UNREADABLE:{evidence.repository_relative_path}")
                else:
                    if evidence.start_line is not None:
                        assert evidence.end_line is not None
                        if evidence.end_line > len(lines):
                            errors.append(f"EVIDENCE_RANGE_INVALID:{evidence.evidence_id}")
                        else:
                            selected = "\n".join(lines[evidence.start_line - 1 : evidence.end_line])
                            content_hash = hashlib.sha256(selected.encode("utf-8")).hexdigest()
                            if evidence.content_hash and evidence.content_hash != content_hash:
                                errors.append(f"EVIDENCE_CONTENT_HASH_MISMATCH:{evidence.evidence_id}")
        if evidence.tool_call_id is not None and evidence.tool_call_id not in self.artifact_index:
            errors.append(f"TOOL_CALL_NOT_FOUND:{evidence.tool_call_id}")
        if evidence.artifact_ref is not None and evidence.artifact_ref not in self.artifact_index:
            artifact = Path(evidence.artifact_ref)
            if not artifact.is_absolute() or not artifact.is_file():
                errors.append(f"ARTIFACT_NOT_FOUND:{evidence.artifact_ref}")
        if errors:
            return None, errors
        return {
            **evidence.to_dict(),
            "resolved_content_hash": content_hash,
            "resolution_status": "RESOLVED",
        }, []

    def _locality_errors(self, proposal: SecurityProposal, evidence: Sequence[EvidenceRef]) -> list[str]:
        anchors = {
            ref.entity_id
            for ref in proposal_role_refs(proposal.subject, proposal.source, proposal.target)
        }
        anchor_entities = [self.entities[item] for item in anchors if item in self.entities]
        errors: list[str] = []
        for item in evidence:
            if anchors.intersection(item.entity_ids):
                continue
            related = False
            for evidence_id in item.entity_ids:
                evidence_entity = self.entities.get(evidence_id)
                if evidence_entity is None:
                    continue
                related = any(
                    evidence_entity.repository_relative_path == anchor.repository_relative_path
                    and (
                        (
                            evidence_entity.enclosing_callable is not None
                            and evidence_entity.enclosing_callable == anchor.enclosing_callable
                        )
                        or (
                            evidence_entity.enclosing_type is not None
                            and evidence_entity.enclosing_type == anchor.enclosing_type
                        )
                    )
                    for anchor in anchor_entities
                )
                if related:
                    break
            if not related:
                errors.append(f"UNRELATED_EVIDENCE:{item.evidence_id}")
        return errors

    def evaluate(self, proposal: SecurityProposal) -> EvidenceGateResult:
        checks: list[GateCheck] = [GateCheck("SCHEMA_VALIDITY", CheckStatus.PASS)]
        provenance = {
            "gate_version": GATE_VERSION,
            "proposal_hash": hashlib.sha256(proposal.to_json().encode("utf-8")).hexdigest(),
            "proposal_provenance": dict(proposal.provenance),
        }
        entity_ids = set(proposal.scope.entity_ids)
        entity_ids.update(ref.entity_id for ref in proposal_role_refs(proposal.subject, proposal.source, proposal.target))
        missing_entities = [f"ENTITY_NOT_FOUND:{item}" for item in sorted(entity_ids) if item not in self.entities]
        checks.append(self._check("ENTITY_EXISTENCE", missing_entities))
        checks.append(self._check("NO_FABRICATED_ENTITY", missing_entities))
        if missing_entities:
            return EvidenceGateResult(proposal.proposal_id, GateStatus.REJECTED, checks, rejection_reasons=missing_entities, provenance=provenance)

        location_errors = self._location_errors(proposal)
        checks.append(self._check("LOCATION_VALIDITY", location_errors))
        if location_errors:
            return EvidenceGateResult(proposal.proposal_id, GateStatus.REJECTED, checks, rejection_reasons=location_errors, provenance=provenance)

        role_errors = [
            reason or "ROLE_INVALID"
            for ref in proposal_role_refs(proposal.subject, proposal.source, proposal.target)
            for valid, reason in [validate_role(ref, self.entities)]
            if not valid
        ]
        role_errors.extend(validate_proposal_shape(proposal, self.entities))
        checks.append(self._check("ROLE_COMPATIBILITY", role_errors))
        if role_errors:
            return EvidenceGateResult(proposal.proposal_id, GateStatus.REJECTED, checks, rejection_reasons=role_errors, provenance=provenance)

        resolved: list[dict[str, Any]] = []
        resolved_objects: list[EvidenceRef] = []
        missing_refs: list[str] = []
        resolution_errors: list[str] = []
        for evidence_id in proposal.evidence_refs:
            evidence = self.evidence_catalog.get(evidence_id)
            if evidence is None:
                missing_refs.append(evidence_id)
                resolution_errors.append(f"EVIDENCE_ID_NOT_FOUND:{evidence_id}")
                continue
            value, errors = self._resolve_evidence(evidence)
            if errors:
                resolution_errors.extend(errors)
                continue
            assert value is not None
            resolved.append(value)
            resolved_objects.append(evidence)
        checks.append(self._check("EVIDENCE_RESOLUTION", resolution_errors))
        if resolution_errors:
            return EvidenceGateResult(
                proposal.proposal_id, GateStatus.REJECTED, checks,
                resolved_evidence=resolved, missing_evidence=missing_refs,
                rejection_reasons=resolution_errors, provenance=provenance,
            )

        locality_errors = self._locality_errors(proposal, resolved_objects)
        checks.append(self._check("EVIDENCE_LOCALITY", locality_errors))
        if locality_errors:
            return EvidenceGateResult(proposal.proposal_id, GateStatus.REJECTED, checks, resolved_evidence=resolved, rejection_reasons=locality_errors, provenance=provenance)

        scope_errors = validate_scope(proposal)
        checks.append(self._check("SCOPE_BOUND", scope_errors))
        if scope_errors:
            return EvidenceGateResult(proposal.proposal_id, GateStatus.REJECTED, checks, resolved_evidence=resolved, rejection_reasons=scope_errors, provenance=provenance)

        if proposal.proposal_id in self.native_relation_ids:
            checks.append(GateCheck("DUPLICATE_OR_NATIVE_SUPPORT", CheckStatus.PASS, ("NATIVE_RELATION_PRESENT",)))
            return EvidenceGateResult(proposal.proposal_id, GateStatus.ALREADY_SUPPORTED, checks, resolved_evidence=resolved, provenance=provenance)
        if proposal.proposal_id in self.seen_proposal_ids:
            checks.append(GateCheck("DUPLICATE_OR_NATIVE_SUPPORT", CheckStatus.PASS, ("DUPLICATE_PROPOSAL_ID",)))
            return EvidenceGateResult(proposal.proposal_id, GateStatus.DUPLICATE, checks, resolved_evidence=resolved, provenance=provenance)
        checks.append(GateCheck("DUPLICATE_OR_NATIVE_SUPPORT", CheckStatus.PASS))

        sufficiency_errors: list[str] = []
        if not resolved_objects:
            sufficiency_errors.append("NO_PROGRAM_EVIDENCE")
        elif all(item.confidence == EvidenceStrength.WEAK for item in resolved_objects):
            sufficiency_errors.append("ONLY_WEAK_EVIDENCE")
        if proposal.proposal_type.value == "FIELD_STATE":
            for item in resolved_objects:
                fields = [
                    self.entities[entity_id]
                    for entity_id in item.entity_ids
                    if entity_id in self.entities and self.entities[entity_id].kind.value == "FIELD"
                ]
                if len(fields) > 1 and len({field.simple_name for field in fields}) < len(fields):
                    sufficiency_errors.append("AMBIGUOUS_FIELD_ANCHOR")
                    break
        checks.append(self._check("EVIDENCE_SUFFICIENCY", sufficiency_errors))
        self.seen_proposal_ids.add(proposal.proposal_id)
        if sufficiency_errors:
            return EvidenceGateResult(
                proposal.proposal_id, GateStatus.NEEDS_MORE_EVIDENCE, checks,
                resolved_evidence=resolved, missing_evidence=sufficiency_errors,
                warnings=["model_confidence is metadata and did not affect admission"],
                provenance=provenance,
            )
        codeql_kinds = {
            EvidenceSourceKind.CODEQL_ENTITY_FACT, EvidenceSourceKind.CODEQL_CALL,
            EvidenceSourceKind.CODEQL_LOCAL_FLOW, EvidenceSourceKind.CODEQL_DATAFLOW,
            EvidenceSourceKind.CODEQL_CFG,
        }
        provenance["admission_basis"] = "CODEQL_ASSISTED" if any(item.source_kind in codeql_kinds for item in resolved_objects) else "REPOSITORY_ONLY"
        return EvidenceGateResult(
            proposal.proposal_id, GateStatus.ADMISSIBLE, checks,
            resolved_evidence=resolved,
            warnings=["ADMISSIBLE means grounded proposal, not confirmed fact or vulnerability"],
            provenance=provenance,
        )

    def evaluate_many(self, proposals: Sequence[SecurityProposal]) -> list[EvidenceGateResult]:
        return [self.evaluate(item) for item in proposals]
