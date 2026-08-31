"""Audited, fail-closed input boundary for the M7 detector runtime.

The boundary is deliberately independent from the evaluator.  It records every
file actually read by the detector, rejects known answer-artifact locations and
structured benchmark metadata, and seals a hash manifest before evaluation.
"""

from __future__ import annotations

import hashlib
import csv
import io
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from java_vuln_research.common.io import YamlSubsetError, _parse_yaml_subset
from java_vuln_research.work1_agent.proposal.model import canonical_json, stable_digest


POLICY_VERSION = "M7_RUNTIME_BOUNDARY_V2"
MAX_RUNTIME_INPUT_BYTES = 128 * 1024 * 1024


class RuntimeInputKind(str, Enum):
    JAVA_SOURCE = "JAVA_SOURCE"
    PROGRAM_ENTITY_INDEX = "PROGRAM_ENTITY_INDEX"
    REPOSITORY_TOOL_ARTIFACT = "REPOSITORY_TOOL_ARTIFACT"
    CODEQL_TOOL_ARTIFACT = "CODEQL_TOOL_ARTIFACT"
    CODEQL_NATIVE_BASELINE = "CODEQL_NATIVE_BASELINE"
    M4_ARTIFACT = "M4_ARTIFACT"
    M5_ARTIFACT = "M5_ARTIFACT"
    AGENT_TRACE = "AGENT_TRACE"
    RUNTIME_CONFIG = "RUNTIME_CONFIG"
    TRUSTED_SCHEMA = "TRUSTED_SCHEMA"


class RuntimeArtifactRole(str, Enum):
    PROJECT_SOURCE = "PROJECT_SOURCE"
    TRUSTED_DETECTOR_ASSET = "TRUSTED_DETECTOR_ASSET"
    DETECTOR_RUNTIME_ARTIFACT = "DETECTOR_RUNTIME_ARTIFACT"


def _artifact_role(kind: RuntimeInputKind) -> RuntimeArtifactRole:
    if kind is RuntimeInputKind.JAVA_SOURCE:
        return RuntimeArtifactRole.PROJECT_SOURCE
    if kind is RuntimeInputKind.TRUSTED_SCHEMA:
        return RuntimeArtifactRole.TRUSTED_DETECTOR_ASSET
    return RuntimeArtifactRole.DETECTOR_RUNTIME_ARTIFACT


class BoundaryViolationCode(str, Enum):
    SECURITY_BOUNDARY_VIOLATION = "SECURITY_BOUNDARY_VIOLATION"
    ROOT_ESCAPE = "ROOT_ESCAPE"
    PATH_DENIED = "PATH_DENIED"
    CONTENT_DENIED = "CONTENT_DENIED"
    INPUT_MISSING = "INPUT_MISSING"
    INPUT_NOT_FILE = "INPUT_NOT_FILE"
    INPUT_TOO_LARGE = "INPUT_TOO_LARGE"
    INPUT_CHANGED = "INPUT_CHANGED"
    INPUT_NOT_REGISTERED = "INPUT_NOT_REGISTERED"
    BOUNDARY_SEALED = "BOUNDARY_SEALED"


class SecurityBoundaryViolation(ValueError):
    def __init__(self, decision: "BoundaryDecision") -> None:
        self.decision = decision
        super().__init__(f"SECURITY_BOUNDARY_VIOLATION[{decision.rule_id}]: {decision.reason}")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _normal_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.casefold()).strip("_")


def _path_text(path: str | Path) -> str:
    return str(path).replace("\\", "/").casefold()


def _path_parts(path: str | Path) -> tuple[str, ...]:
    return tuple(part for part in _path_text(path).split("/") if part not in {"", "."})


_DENIED_EXACT_BASENAMES = {
    "diagnostic_analysis.json",
    "project_info.csv",
    "benchmark_annotation.json",
    "benchmark_annotations.jsonl",
    "ground_truth.json",
    "ground_truth.jsonl",
}
_DENIED_COMPONENTS = {
    "diagnostic_proposals",
    "benchmark_answers",
    "benchmark_answer",
    "benchmark_annotations",
    "benchmark_annotation",
    "benchmark_fixes",
    "benchmark_patches",
    "evaluator_inputs",
    "evaluator_input",
    "ground_truth",
    "ground-truth",
}
_ANSWER_CONTEXT_COMPONENTS = {"evaluator", "evaluation", "benchmark", "benchmarks", "dataset", "datasets"}
_ANSWER_DATA_COMPONENTS = {"answers", "annotations", "fix", "fixes", "patch", "patches", "cve", "cves", "cwe", "cwes"}


def _denied_path_rule(path: str | Path) -> tuple[str, str] | None:
    parts = _path_parts(path)
    basename = parts[-1] if parts else ""
    if basename in _DENIED_EXACT_BASENAMES:
        return "DENY_EXACT_ANSWER_ARTIFACT", f"runtime path basename is denied: {basename}"
    denied = sorted(set(parts).intersection(_DENIED_COMPONENTS))
    if denied:
        return "DENY_ANSWER_DIRECTORY", f"runtime path contains denied component: {denied[0]}"
    if set(parts).intersection(_ANSWER_CONTEXT_COMPONENTS) and set(parts).intersection(_ANSWER_DATA_COMPONENTS):
        return "DENY_EVALUATOR_ANSWER_INPUT", "runtime path combines evaluator/benchmark context with answer-data directory"
    if basename.endswith((".patch", ".diff")) and set(parts).intersection(_ANSWER_CONTEXT_COMPONENTS):
        return "DENY_BENCHMARK_PATCH", "runtime path points to an evaluator/benchmark patch or diff"
    return None


_DENIED_DATA_KEYS = {
    "cve",
    "cve_id",
    "cwe",
    "cwe_id",
    "benchmark_cve",
    "benchmark_cwe",
    "patch",
    "patch_path",
    "fix",
    "fix_diff",
    "fix_patch",
    "benchmark_vulnerability_location",
    "benchmark_method",
    "benchmark_line",
    "benchmark_annotation",
    "benchmark_annotations",
    "vulnerable_method",
    "vulnerable_location",
    "mapped_callable",
    "root_cause",
    "root_cause_label",
    "proposal_sequence",
    "diagnostic_proposals",
    "diagnostic_analysis",
    "ground_truth",
}


def _is_empty_declaration(value: Any) -> bool:
    return value is None or value is False or value == "" or value == [] or value == {}


def _scan_structured(value: Any, location: str = "$") -> tuple[str, str] | None:
    if isinstance(value, Mapping):
        for raw_key, item in value.items():
            key = _normal_key(str(raw_key))
            current = f"{location}.{raw_key}"
            if key in _DENIED_DATA_KEYS and not _is_empty_declaration(item):
                return "DENY_BENCHMARK_METADATA", f"forbidden benchmark/diagnostic field at {current}"
            if key == "benchmark_informed" and item is not False:
                return "DENY_BENCHMARK_INFORMED", f"benchmark_informed must be false at {current}"
            if key == "allowed_for_agent_runtime" and item is not True:
                return "DENY_RUNTIME_INELIGIBLE", f"allowed_for_agent_runtime must be true at {current}"
            if key == "proposal_origin" and "benchmark" in str(item).casefold():
                return "DENY_BENCHMARK_PROPOSAL", f"benchmark-derived proposal origin at {current}"
            nested = _scan_structured(item, current)
            if nested:
                return nested
        return None
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            nested = _scan_structured(item, f"{location}[{index}]")
            if nested:
                return nested
        return None
    if isinstance(value, str):
        denied = _denied_path_rule(value)
        if denied:
            return "DENY_EMBEDDED_ANSWER_PATH", f"embedded forbidden path at {location}: {denied[1]}"
    return None


def _scan_bytes(path: Path, raw: bytes) -> tuple[str, str] | None:
    suffix = path.suffix.casefold()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return "DENY_NON_UTF8_STRUCTURED_INPUT", "structured runtime input is not UTF-8"
    try:
        if suffix == ".json":
            return _scan_structured(json.loads(text))
        if suffix == ".jsonl":
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                denied = _scan_structured(json.loads(line), f"$line[{line_number}]")
                if denied:
                    return denied
        if suffix in {".yaml", ".yml"}:
            return _scan_structured(_parse_yaml_subset(text))
        if suffix == ".csv":
            for row_number, row in enumerate(csv.DictReader(io.StringIO(text)), start=2):
                denied = _scan_structured(row, f"$row[{row_number}]")
                if denied:
                    return denied
    except (json.JSONDecodeError, YamlSubsetError, csv.Error) as exc:
        detail = getattr(exc, "msg", str(exc))
        return "DENY_INVALID_STRUCTURED_INPUT", f"invalid {suffix} runtime input: {detail}"
    return None


@dataclass(frozen=True)
class BoundaryDecision:
    allowed: bool
    code: BoundaryViolationCode | None
    rule_id: str
    reason: str
    requested_path: str
    resolved_path: str | None
    input_kind: RuntimeInputKind
    logical_name: str

    def to_trace_payload(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "failure_class": "SECURITY_BOUNDARY_VIOLATION" if not self.allowed else None,
            "code": self.code.value if self.code else None,
            "rule_id": self.rule_id,
            "reason": self.reason,
            "requested_path": self.requested_path,
            "resolved_path": self.resolved_path,
            "input_kind": self.input_kind.value,
            "artifact_role": _artifact_role(self.input_kind).value,
            "logical_name": self.logical_name,
        }


@dataclass(frozen=True)
class RuntimeInputEntry:
    logical_name: str
    input_kind: RuntimeInputKind
    artifact_role: RuntimeArtifactRole
    requested_path: str
    resolved_path: str
    trusted_root: str
    size_bytes: int
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_name": self.logical_name,
            "input_kind": self.input_kind.value,
            "artifact_role": self.artifact_role.value,
            "requested_path": self.requested_path,
            "resolved_path": self.resolved_path,
            "trusted_root": self.trusted_root,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }


class RuntimeSecurityBoundary:
    """Read-through boundary whose final manifest is the detector input ledger."""

    def __init__(
        self,
        *,
        project_id: str,
        repository_identity: str,
        allowed_roots: Mapping[RuntimeInputKind | str, Sequence[str | Path]],
        max_input_bytes: int = MAX_RUNTIME_INPUT_BYTES,
    ) -> None:
        if not project_id or not repository_identity:
            raise ValueError("project_id and repository_identity are required")
        self.project_id = project_id
        self.repository_identity = repository_identity
        self.max_input_bytes = max_input_bytes
        self._roots: dict[RuntimeInputKind, tuple[Path, ...]] = {}
        for raw_kind, roots in allowed_roots.items():
            kind = raw_kind if isinstance(raw_kind, RuntimeInputKind) else RuntimeInputKind(str(raw_kind))
            self._roots[kind] = tuple(Path(root).resolve() for root in roots)
        self._entries: dict[str, RuntimeInputEntry] = {}
        self._decisions: list[BoundaryDecision] = []
        self._sealed_manifest: dict[str, Any] | None = None

    @property
    def decisions(self) -> tuple[BoundaryDecision, ...]:
        return tuple(self._decisions)

    def _deny(
        self,
        *,
        code: BoundaryViolationCode,
        rule_id: str,
        reason: str,
        path: str | Path,
        resolved: Path | None,
        kind: RuntimeInputKind,
        logical_name: str,
    ) -> SecurityBoundaryViolation:
        decision = BoundaryDecision(
            allowed=False,
            code=code,
            rule_id=rule_id,
            reason=reason,
            requested_path=str(path),
            resolved_path=str(resolved) if resolved else None,
            input_kind=kind,
            logical_name=logical_name,
        )
        self._decisions.append(decision)
        return SecurityBoundaryViolation(decision)

    def _resolve_allowed(self, path: str | Path, kind: RuntimeInputKind, logical_name: str) -> tuple[Path, Path]:
        if self._sealed_manifest is not None:
            raise self._deny(
                code=BoundaryViolationCode.BOUNDARY_SEALED,
                rule_id="BOUNDARY_ALREADY_SEALED",
                reason="runtime input boundary is already sealed",
                path=path,
                resolved=None,
                kind=kind,
                logical_name=logical_name,
            )
        role = _artifact_role(kind)
        if role is RuntimeArtifactRole.DETECTOR_RUNTIME_ARTIFACT:
            lexical_denied = _denied_path_rule(path)
            if lexical_denied:
                raise self._deny(
                    code=BoundaryViolationCode.PATH_DENIED,
                    rule_id=lexical_denied[0],
                    reason=lexical_denied[1],
                    path=path,
                    resolved=None,
                    kind=kind,
                    logical_name=logical_name,
                )
        candidate = Path(path)
        try:
            resolved = candidate.resolve(strict=True)
        except FileNotFoundError:
            raise self._deny(
                code=BoundaryViolationCode.INPUT_MISSING,
                rule_id="INPUT_MUST_EXIST",
                reason="runtime input does not exist",
                path=path,
                resolved=None,
                kind=kind,
                logical_name=logical_name,
            )
        if role is RuntimeArtifactRole.DETECTOR_RUNTIME_ARTIFACT:
            resolved_denied = _denied_path_rule(resolved)
            if resolved_denied:
                raise self._deny(
                    code=BoundaryViolationCode.PATH_DENIED,
                    rule_id=resolved_denied[0],
                    reason=resolved_denied[1],
                    path=path,
                    resolved=resolved,
                    kind=kind,
                    logical_name=logical_name,
                )
        roots = self._roots.get(kind, ())
        trusted_root: Path | None = None
        for root in roots:
            try:
                resolved.relative_to(root)
                trusted_root = root
                break
            except ValueError:
                continue
        if trusted_root is None:
            raise self._deny(
                code=BoundaryViolationCode.ROOT_ESCAPE,
                rule_id="INPUT_OUTSIDE_KIND_ROOTS",
                reason=f"runtime input is outside allowed roots for {kind.value}",
                path=path,
                resolved=resolved,
                kind=kind,
                logical_name=logical_name,
            )
        if not resolved.is_file():
            raise self._deny(
                code=BoundaryViolationCode.INPUT_NOT_FILE,
                rule_id="INPUT_MUST_BE_REGULAR_FILE",
                reason="runtime input is not a regular file",
                path=path,
                resolved=resolved,
                kind=kind,
                logical_name=logical_name,
            )
        return resolved, trusted_root

    def read_bytes(self, path: str | Path, *, kind: RuntimeInputKind, logical_name: str) -> bytes:
        if not logical_name.strip():
            raise ValueError("logical_name must be non-empty")
        resolved, trusted_root = self._resolve_allowed(path, kind, logical_name)
        raw = resolved.read_bytes()
        if len(raw) > self.max_input_bytes:
            raise self._deny(
                code=BoundaryViolationCode.INPUT_TOO_LARGE,
                rule_id="INPUT_SIZE_HARD_CEILING",
                reason=f"runtime input exceeds {self.max_input_bytes} bytes",
                path=path,
                resolved=resolved,
                kind=kind,
                logical_name=logical_name,
            )
        role = _artifact_role(kind)
        if role is RuntimeArtifactRole.DETECTOR_RUNTIME_ARTIFACT:
            denied = _scan_bytes(resolved, raw)
            if denied:
                raise self._deny(
                    code=BoundaryViolationCode.CONTENT_DENIED,
                    rule_id=denied[0],
                    reason=denied[1],
                    path=path,
                    resolved=resolved,
                    kind=kind,
                    logical_name=logical_name,
                )
        entry = RuntimeInputEntry(
            logical_name=logical_name,
            input_kind=kind,
            artifact_role=role,
            requested_path=str(path),
            resolved_path=str(resolved),
            trusted_root=str(trusted_root),
            size_bytes=len(raw),
            sha256=_sha256_bytes(raw),
        )
        previous = self._entries.get(logical_name)
        if previous is not None:
            stable_identity = (
                "input_kind",
                "artifact_role",
                "resolved_path",
                "trusted_root",
                "size_bytes",
                "sha256",
            )
            if any(getattr(previous, name) != getattr(entry, name) for name in stable_identity):
                raise self._deny(
                    code=BoundaryViolationCode.INPUT_CHANGED,
                    rule_id="LOGICAL_INPUT_IDENTITY_CHANGED",
                    reason="logical runtime input changed resolved path, kind, role, trusted root, size, or hash",
                    path=path,
                    resolved=resolved,
                    kind=kind,
                    logical_name=logical_name,
                )
            entry = previous
        self._entries[logical_name] = entry
        self._decisions.append(
            BoundaryDecision(True, None, "ALLOW_HASHED_RUNTIME_INPUT", "runtime input accepted and hashed", str(path), str(resolved), kind, logical_name)
        )
        return raw

    def read_text(self, path: str | Path, *, kind: RuntimeInputKind, logical_name: str) -> str:
        try:
            return self.read_bytes(path, kind=kind, logical_name=logical_name).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise self._deny(
                code=BoundaryViolationCode.CONTENT_DENIED,
                rule_id="RUNTIME_TEXT_MUST_BE_UTF8",
                reason="runtime text input is not UTF-8",
                path=path,
                resolved=Path(path).resolve(),
                kind=kind,
                logical_name=logical_name,
            ) from exc

    def seal(self) -> dict[str, Any]:
        if self._sealed_manifest is not None:
            return dict(self._sealed_manifest)
        entries = [self._entries[name].to_dict() for name in sorted(self._entries)]
        violations = [decision.to_trace_payload() for decision in self._decisions if not decision.allowed]
        material: dict[str, Any] = {
            "schema_version": 2,
            "policy_version": POLICY_VERSION,
            "project_id": self.project_id,
            "repository_identity": self.repository_identity,
            "detector_input_frozen": True,
            "all_inputs_hashed": True,
            "no_leakage_pass": not violations,
            "entries": entries,
            "violations": violations,
        }
        material["manifest_id"] = stable_digest("m7input", material)
        self._sealed_manifest = material
        return dict(material)

    def write_manifest(self, path: str | Path) -> dict[str, Any]:
        manifest = self.seal()
        Path(path).write_text(canonical_json(manifest) + "\n", encoding="utf-8")
        return manifest

    def audit(self) -> dict[str, Any]:
        manifest = self.seal()
        mismatches: list[dict[str, str]] = []
        for entry in manifest["entries"]:
            path = Path(entry["resolved_path"])
            actual = _sha256_bytes(path.read_bytes()) if path.is_file() else "MISSING"
            if actual != entry["sha256"]:
                mismatches.append({"logical_name": entry["logical_name"], "expected": entry["sha256"], "actual": actual})
        return {
            "schema_version": 2,
            "policy_version": POLICY_VERSION,
            "project_id": self.project_id,
            "manifest_id": manifest["manifest_id"],
            "status": "PASS" if manifest["no_leakage_pass"] and not mismatches else "FAIL",
            "input_count": len(manifest["entries"]),
            "violation_count": len(manifest["violations"]),
            "hash_mismatches": mismatches,
        }


def runtime_roots(
    *,
    source_roots: Iterable[str | Path] = (),
    artifact_roots: Iterable[str | Path] = (),
    schema_roots: Iterable[str | Path] = (),
) -> dict[RuntimeInputKind, tuple[Path, ...]]:
    """Build an explicit kind-to-root allow-list without inferring trust from names."""

    sources = tuple(Path(path) for path in source_roots)
    artifacts = tuple(Path(path) for path in artifact_roots)
    schemas = tuple(Path(path) for path in schema_roots)
    return {
        RuntimeInputKind.JAVA_SOURCE: sources,
        RuntimeInputKind.PROGRAM_ENTITY_INDEX: artifacts,
        RuntimeInputKind.REPOSITORY_TOOL_ARTIFACT: artifacts,
        RuntimeInputKind.CODEQL_TOOL_ARTIFACT: artifacts,
        RuntimeInputKind.CODEQL_NATIVE_BASELINE: artifacts,
        RuntimeInputKind.M4_ARTIFACT: artifacts,
        RuntimeInputKind.M5_ARTIFACT: artifacts,
        RuntimeInputKind.AGENT_TRACE: artifacts,
        RuntimeInputKind.RUNTIME_CONFIG: artifacts,
        RuntimeInputKind.TRUSTED_SCHEMA: schemas,
    }
