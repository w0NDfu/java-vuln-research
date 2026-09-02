from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, fields
from datetime import datetime
from decimal import Decimal, InvalidOperation
from enum import Enum
import hashlib
import json
import re
import threading
from typing import Any, Iterable, Mapping

from .arms import FormalProfile, RunKey


USAGE_LEDGER_SCHEMA_VERSION = "m8-usage-ledger-v1"
BUDGET_CONTRACT_VERSION = "m8-project-budget-v1"
CORE_CONFIRMATORY_ARM_IDS = FormalProfile.CORE.confirmatory_arm_ids
ROLE_CONFIRMATORY_ARM_IDS = FormalProfile.ROLE.confirmatory_arm_ids

_ZERO_SHA256 = "0" * 64
_SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ValueError(f"{context} keys mismatch; missing={missing}; extra={extra}")


def _require_identifier(value: str, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a non-empty, trimmed string")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{name} must not contain control characters")
    return value


def _require_optional_identifier(value: str | None, name: str) -> str | None:
    if value is None:
        return None
    return _require_identifier(value, name)


def _require_nonnegative_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _require_positive_int(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _require_sha256(value: str, name: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 hex digest")
    return value


def _require_timestamp(value: str, name: str) -> str:
    timestamp = _require_identifier(value, name)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{name} must include a UTC offset")
    return timestamp


def _parsed_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True, slots=True)
class ProjectBudgetCeilings:
    """Arm-independent, project/run-level resource ceilings.

    Dollar cost is intentionally absent. It is an observed outcome and must not
    become an arm-specific early-stop condition.
    """

    max_model_attempts: int
    max_canonical_input_tokens: int
    max_reserved_output_tokens: int
    max_repository_tool_calls: int
    max_codeql_calls: int
    max_proposal_families: int
    max_admissible_proposals: int
    max_candidate_paths: int
    max_wall_clock_ms: int

    def __post_init__(self) -> None:
        for item in fields(self):
            _require_positive_int(getattr(self, item.name), item.name)

    def to_dict(self) -> dict[str, int]:
        return {item.name: getattr(self, item.name) for item in fields(self)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProjectBudgetCeilings":
        expected = {item.name for item in fields(cls)}
        _require_exact_keys(value, expected, "project budget ceilings")
        return cls(**{name: value[name] for name in expected})

    @property
    def sha256(self) -> str:
        return _sha256(
            {
                "contract_version": BUDGET_CONTRACT_VERSION,
                "ceilings": self.to_dict(),
            }
        )

    def to_canonical_json(self) -> str:
        return _canonical_json(self.to_dict())


class BudgetComparabilityError(ValueError):
    pass


def confirmatory_arms_for_profile(profile: str) -> tuple[str, ...]:
    normalized = _require_identifier(profile, "profile").upper()
    try:
        return FormalProfile(normalized).confirmatory_arm_ids
    except ValueError as error:
        raise BudgetComparabilityError(f"unsupported formal profile: {profile}") from error


def assert_confirmatory_budget_comparability(
    arm_budgets: Mapping[str, ProjectBudgetCeilings],
    *,
    confirmatory_arm_ids: Iterable[str] = CORE_CONFIRMATORY_ARM_IDS,
) -> str:
    """Return the shared budget hash or fail on an incomplete/mixed registration."""

    expected = tuple(confirmatory_arm_ids)
    if not expected or len(set(expected)) != len(expected):
        raise BudgetComparabilityError("confirmatory arm IDs must be non-empty and unique")
    for arm_id in expected:
        _require_identifier(arm_id, "confirmatory arm ID")
    actual = set(arm_budgets)
    expected_set = set(expected)
    if actual != expected_set:
        raise BudgetComparabilityError(
            "confirmatory budget registration mismatch; "
            f"missing={sorted(expected_set - actual)}; extra={sorted(actual - expected_set)}"
        )
    for arm_id, budget in arm_budgets.items():
        if not isinstance(budget, ProjectBudgetCeilings):
            raise BudgetComparabilityError(f"{arm_id} does not have a ProjectBudgetCeilings value")
    hashes = {budget.sha256 for budget in arm_budgets.values()}
    if len(hashes) != 1:
        by_arm = {arm: arm_budgets[arm].sha256 for arm in sorted(arm_budgets)}
        raise BudgetComparabilityError(f"confirmatory project budgets differ: {by_arm}")
    return next(iter(hashes))


@dataclass(frozen=True, slots=True)
class BudgetUsage:
    model_attempts: int = 0
    canonical_input_tokens: int = 0
    output_tokens: int = 0
    repository_tool_calls: int = 0
    codeql_calls: int = 0
    proposal_families: int = 0
    admissible_proposals: int = 0
    candidate_paths: int = 0
    wall_clock_ms: int = 0

    def __post_init__(self) -> None:
        for item in fields(self):
            _require_nonnegative_int(getattr(self, item.name), item.name)

    def __add__(self, other: "BudgetUsage") -> "BudgetUsage":
        if not isinstance(other, BudgetUsage):
            return NotImplemented
        return BudgetUsage(
            **{
                item.name: getattr(self, item.name) + getattr(other, item.name)
                for item in fields(self)
            }
        )

    def to_dict(self) -> dict[str, int]:
        return {item.name: getattr(self, item.name) for item in fields(self)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BudgetUsage":
        expected = {item.name for item in fields(cls)}
        _require_exact_keys(value, expected, "budget usage")
        return cls(**{name: value[name] for name in expected})


_USAGE_TO_CEILING = {
    "model_attempts": "max_model_attempts",
    "canonical_input_tokens": "max_canonical_input_tokens",
    "output_tokens": "max_reserved_output_tokens",
    "repository_tool_calls": "max_repository_tool_calls",
    "codeql_calls": "max_codeql_calls",
    "proposal_families": "max_proposal_families",
    "admissible_proposals": "max_admissible_proposals",
    "candidate_paths": "max_candidate_paths",
    "wall_clock_ms": "max_wall_clock_ms",
}


class UsageActorKind(str, Enum):
    COORDINATOR = "coordinator"
    SPECIALIST = "specialist"
    SINGLE_AGENT = "single-agent"
    VERIFIER = "verifier"
    SCHEDULER = "scheduler"


class UsageActionKind(str, Enum):
    MODEL_ATTEMPT = "model-attempt"
    REPOSITORY_TOOL_CALL = "repository-tool-call"
    CODEQL_CALL = "codeql-call"
    PROPOSAL_FAMILY = "proposal-family"
    ADMISSIBLE_PROPOSAL = "admissible-proposal"
    CANDIDATE_PATH = "candidate-path"


class LedgerPhase(str, Enum):
    RESERVATION = "reservation"
    RECONCILIATION = "reconciliation"


class TerminalStatus(str, Enum):
    SUCCESS = "success"
    TIMEOUT = "timeout"
    INVALID_OUTPUT = "invalid-output"
    PROVIDER_ERROR = "provider-error"
    TOOL_ERROR = "tool-error"
    CANCELLED_BEFORE_SEND = "cancelled-before-send"


class TokenCountSource(str, Enum):
    PROVIDER_REPORTED = "PROVIDER_REPORTED"
    LOCALLY_ESTIMATED = "LOCALLY_ESTIMATED"
    NOT_REPORTED = "NOT_REPORTED"


@dataclass(frozen=True, slots=True)
class TokenMeasurement:
    count: int | None
    source: TokenCountSource

    def __post_init__(self) -> None:
        if not isinstance(self.source, TokenCountSource):
            raise ValueError("token source must be a TokenCountSource")
        if self.source is TokenCountSource.NOT_REPORTED:
            if self.count is not None:
                raise ValueError("NOT_REPORTED token measurements must use count=None")
        else:
            if self.count is None:
                raise ValueError(f"{self.source.value} token measurements require a count")
            _require_nonnegative_int(self.count, "token count")

    @classmethod
    def provider_reported(cls, count: int) -> "TokenMeasurement":
        return cls(count=count, source=TokenCountSource.PROVIDER_REPORTED)

    @classmethod
    def locally_estimated(cls, count: int) -> "TokenMeasurement":
        return cls(count=count, source=TokenCountSource.LOCALLY_ESTIMATED)

    @classmethod
    def not_reported(cls) -> "TokenMeasurement":
        return cls(count=None, source=TokenCountSource.NOT_REPORTED)

    def to_dict(self) -> dict[str, Any]:
        return {"count": self.count, "source": self.source.value}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "TokenMeasurement":
        _require_exact_keys(value, {"count", "source"}, "token measurement")
        return cls(count=value["count"], source=TokenCountSource(value["source"]))


@dataclass(frozen=True, slots=True)
class ModelTokenUsage:
    input_tokens: TokenMeasurement
    output_tokens: TokenMeasurement
    cache_read_tokens: TokenMeasurement
    cache_write_tokens: TokenMeasurement

    def __post_init__(self) -> None:
        for item in fields(self):
            if not isinstance(getattr(self, item.name), TokenMeasurement):
                raise ValueError(f"{item.name} must be a TokenMeasurement")

    @classmethod
    def all_not_reported(cls) -> "ModelTokenUsage":
        return cls(**{item.name: TokenMeasurement.not_reported() for item in fields(cls)})

    def to_dict(self) -> dict[str, Any]:
        return {item.name: getattr(self, item.name).to_dict() for item in fields(self)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelTokenUsage":
        expected = {item.name for item in fields(cls)}
        _require_exact_keys(value, expected, "model token usage")
        return cls(**{name: TokenMeasurement.from_dict(value[name]) for name in expected})


class CostSource(str, Enum):
    PROVIDER_REPORTED = "PROVIDER_REPORTED"
    LOCALLY_COMPUTED = "LOCALLY_COMPUTED"
    NOT_REPORTED = "NOT_REPORTED"


def _canonical_decimal(value: str, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(f"{name} must be a decimal string") from error
    if not parsed.is_finite() or parsed < 0:
        raise ValueError(f"{name} must be finite and non-negative")
    if parsed == 0:
        return "0"
    rendered = format(parsed.normalize(), "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    return rendered


@dataclass(frozen=True, slots=True)
class CostMeasurement:
    amount_usd: str | None
    source: CostSource
    price_table_id: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.source, CostSource):
            raise ValueError("cost source must be a CostSource")
        _require_optional_identifier(self.price_table_id, "price_table_id")
        if self.source is CostSource.NOT_REPORTED:
            if self.amount_usd is not None:
                raise ValueError("NOT_REPORTED cost measurements must use amount_usd=None")
            return
        if self.amount_usd is None:
            raise ValueError(f"{self.source.value} cost measurements require amount_usd")
        canonical = _canonical_decimal(self.amount_usd, "amount_usd")
        if canonical != self.amount_usd:
            raise ValueError(f"amount_usd is not canonical; expected {canonical}")
        if self.price_table_id is None:
            raise ValueError("known cost measurements require price_table_id")

    @classmethod
    def not_reported(cls, *, price_table_id: str | None = None) -> "CostMeasurement":
        return cls(amount_usd=None, source=CostSource.NOT_REPORTED, price_table_id=price_table_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "amount_usd": self.amount_usd,
            "source": self.source.value,
            "price_table_id": self.price_table_id,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "CostMeasurement":
        _require_exact_keys(value, {"amount_usd", "source", "price_table_id"}, "cost measurement")
        return cls(
            amount_usd=value["amount_usd"],
            source=CostSource(value["source"]),
            price_table_id=value["price_table_id"],
        )


@dataclass(frozen=True, slots=True)
class ModelAttemptRequest:
    attempt_index: int
    retry_index: int
    configured_model_id: str
    request_timestamp: str
    canonical_prompt_sha256: str
    observation_sha256: str
    tool_catalog_sha256: str
    serialized_request_bytes: int

    def __post_init__(self) -> None:
        _require_positive_int(self.attempt_index, "attempt_index")
        _require_nonnegative_int(self.retry_index, "retry_index")
        _require_identifier(self.configured_model_id, "configured_model_id")
        _require_timestamp(self.request_timestamp, "request_timestamp")
        for name in ("canonical_prompt_sha256", "observation_sha256", "tool_catalog_sha256"):
            _require_sha256(getattr(self, name), name)
        _require_positive_int(self.serialized_request_bytes, "serialized_request_bytes")

    def to_dict(self) -> dict[str, Any]:
        return {item.name: getattr(self, item.name) for item in fields(self)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelAttemptRequest":
        expected = {item.name for item in fields(cls)}
        _require_exact_keys(value, expected, "model attempt request")
        return cls(**{name: value[name] for name in expected})


@dataclass(frozen=True, slots=True)
class ModelAttemptResult:
    tokens: ModelTokenUsage
    billed_cost: CostMeasurement
    provider_request_id: str | None = None
    provider_status: str | None = None
    response_reported_model: str | None = None
    provider_deployment_revision: str | None = None
    repeated_observation_bytes: int = 0
    cache_hit: bool | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.tokens, ModelTokenUsage):
            raise ValueError("tokens must be ModelTokenUsage")
        if not isinstance(self.billed_cost, CostMeasurement):
            raise ValueError("billed_cost must be CostMeasurement")
        for name in (
            "provider_request_id",
            "provider_status",
            "response_reported_model",
            "provider_deployment_revision",
        ):
            _require_optional_identifier(getattr(self, name), name)
        _require_nonnegative_int(self.repeated_observation_bytes, "repeated_observation_bytes")
        if self.cache_hit is not None and not isinstance(self.cache_hit, bool):
            raise ValueError("cache_hit must be bool or None")

    def to_dict(self) -> dict[str, Any]:
        return {
            "tokens": self.tokens.to_dict(),
            "billed_cost": self.billed_cost.to_dict(),
            "provider_request_id": self.provider_request_id,
            "provider_status": self.provider_status,
            "response_reported_model": self.response_reported_model,
            "provider_deployment_revision": self.provider_deployment_revision,
            "repeated_observation_bytes": self.repeated_observation_bytes,
            "cache_hit": self.cache_hit,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ModelAttemptResult":
        expected = {
            "tokens",
            "billed_cost",
            "provider_request_id",
            "provider_status",
            "response_reported_model",
            "provider_deployment_revision",
            "repeated_observation_bytes",
            "cache_hit",
        }
        _require_exact_keys(value, expected, "model attempt result")
        return cls(
            tokens=ModelTokenUsage.from_dict(value["tokens"]),
            billed_cost=CostMeasurement.from_dict(value["billed_cost"]),
            provider_request_id=value["provider_request_id"],
            provider_status=value["provider_status"],
            response_reported_model=value["response_reported_model"],
            provider_deployment_revision=value["provider_deployment_revision"],
            repeated_observation_bytes=value["repeated_observation_bytes"],
            cache_hit=value["cache_hit"],
        )


@dataclass(frozen=True, slots=True)
class UsageLedgerEntry:
    sequence: int
    phase: LedgerPhase
    attempt_id: str
    action_kind: UsageActionKind
    run: RunKey
    actor_kind: UsageActorKind
    agent_id: str
    role: str
    action_name: str
    started_at: str
    ended_at: str | None
    terminal_status: TerminalStatus | None
    reserved_usage: BudgetUsage | None
    settled_usage: BudgetUsage | None
    model_request: ModelAttemptRequest | None
    model_result: ModelAttemptResult | None
    previous_entry_sha256: str
    entry_sha256: str

    def __post_init__(self) -> None:
        _require_positive_int(self.sequence, "sequence")
        if not isinstance(self.phase, LedgerPhase):
            raise ValueError("phase must be LedgerPhase")
        if not isinstance(self.action_kind, UsageActionKind):
            raise ValueError("action_kind must be UsageActionKind")
        if not isinstance(self.run, RunKey):
            raise ValueError("run must be the canonical arms.RunKey")
        if not isinstance(self.actor_kind, UsageActorKind):
            raise ValueError("actor_kind must be UsageActorKind")
        for name in ("attempt_id", "agent_id", "role", "action_name"):
            _require_identifier(getattr(self, name), name)
        _require_timestamp(self.started_at, "started_at")
        if self.ended_at is not None:
            _require_timestamp(self.ended_at, "ended_at")
            if _parsed_timestamp(self.ended_at) < _parsed_timestamp(self.started_at):
                raise ValueError("ended_at must not precede started_at")
        _require_sha256(self.previous_entry_sha256, "previous_entry_sha256")
        _require_sha256(self.entry_sha256, "entry_sha256")

        if self.phase is LedgerPhase.RESERVATION:
            if self.ended_at is not None or self.terminal_status is not None:
                raise ValueError("reservation entries cannot be terminal")
            if self.reserved_usage is None or self.settled_usage is not None or self.model_result is not None:
                raise ValueError("reservation entry usage fields are inconsistent")
        else:
            if self.ended_at is None or not isinstance(self.terminal_status, TerminalStatus):
                raise ValueError("reconciliation entries require terminal status and ended_at")
            if self.reserved_usage is not None or self.settled_usage is None:
                raise ValueError("reconciliation entry usage fields are inconsistent")

        if self.action_kind is UsageActionKind.MODEL_ATTEMPT:
            if self.phase is LedgerPhase.RESERVATION and self.model_request is None:
                raise ValueError("model reservation requires model_request")
            if self.phase is LedgerPhase.RECONCILIATION and self.model_result is None:
                raise ValueError("model reconciliation requires model_result")
            if self.phase is LedgerPhase.RECONCILIATION and self.model_request is not None:
                raise ValueError("model reconciliation must reference, not repeat, model_request")
        elif self.model_request is not None or self.model_result is not None:
            raise ValueError("non-model ledger entries cannot carry model fields")

        expected_hash = _sha256(self._material_dict())
        if self.entry_sha256 != expected_hash:
            raise ValueError(f"entry_sha256 is not canonical; expected {expected_hash}")

    def _material_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "phase": self.phase.value,
            "attempt_id": self.attempt_id,
            "action_kind": self.action_kind.value,
            "run": self.run.to_dict(),
            "actor_kind": self.actor_kind.value,
            "agent_id": self.agent_id,
            "role": self.role,
            "action_name": self.action_name,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "terminal_status": self.terminal_status.value if self.terminal_status else None,
            "reserved_usage": self.reserved_usage.to_dict() if self.reserved_usage else None,
            "settled_usage": self.settled_usage.to_dict() if self.settled_usage else None,
            "model_request": self.model_request.to_dict() if self.model_request else None,
            "model_result": self.model_result.to_dict() if self.model_result else None,
            "previous_entry_sha256": self.previous_entry_sha256,
        }

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        phase: LedgerPhase,
        attempt_id: str,
        action_kind: UsageActionKind,
        run: RunKey,
        actor_kind: UsageActorKind,
        agent_id: str,
        role: str,
        action_name: str,
        started_at: str,
        ended_at: str | None,
        terminal_status: TerminalStatus | None,
        reserved_usage: BudgetUsage | None,
        settled_usage: BudgetUsage | None,
        model_request: ModelAttemptRequest | None,
        model_result: ModelAttemptResult | None,
        previous_entry_sha256: str,
    ) -> "UsageLedgerEntry":
        material = {
            "sequence": sequence,
            "phase": phase.value,
            "attempt_id": attempt_id,
            "action_kind": action_kind.value,
            "run": run.to_dict(),
            "actor_kind": actor_kind.value,
            "agent_id": agent_id,
            "role": role,
            "action_name": action_name,
            "started_at": started_at,
            "ended_at": ended_at,
            "terminal_status": terminal_status.value if terminal_status else None,
            "reserved_usage": reserved_usage.to_dict() if reserved_usage else None,
            "settled_usage": settled_usage.to_dict() if settled_usage else None,
            "model_request": model_request.to_dict() if model_request else None,
            "model_result": model_result.to_dict() if model_result else None,
            "previous_entry_sha256": previous_entry_sha256,
        }
        return cls(entry_sha256=_sha256(material), **{
            "sequence": sequence,
            "phase": phase,
            "attempt_id": attempt_id,
            "action_kind": action_kind,
            "run": run,
            "actor_kind": actor_kind,
            "agent_id": agent_id,
            "role": role,
            "action_name": action_name,
            "started_at": started_at,
            "ended_at": ended_at,
            "terminal_status": terminal_status,
            "reserved_usage": reserved_usage,
            "settled_usage": settled_usage,
            "model_request": model_request,
            "model_result": model_result,
            "previous_entry_sha256": previous_entry_sha256,
        })

    def to_dict(self) -> dict[str, Any]:
        value = self._material_dict()
        value["entry_sha256"] = self.entry_sha256
        return value

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "UsageLedgerEntry":
        expected = {
            "sequence",
            "phase",
            "attempt_id",
            "action_kind",
            "run",
            "actor_kind",
            "agent_id",
            "role",
            "action_name",
            "started_at",
            "ended_at",
            "terminal_status",
            "reserved_usage",
            "settled_usage",
            "model_request",
            "model_result",
            "previous_entry_sha256",
            "entry_sha256",
        }
        _require_exact_keys(value, expected, "usage ledger entry")
        return cls(
            sequence=value["sequence"],
            phase=LedgerPhase(value["phase"]),
            attempt_id=value["attempt_id"],
            action_kind=UsageActionKind(value["action_kind"]),
            run=RunKey.from_dict(value["run"]),
            actor_kind=UsageActorKind(value["actor_kind"]),
            agent_id=value["agent_id"],
            role=value["role"],
            action_name=value["action_name"],
            started_at=value["started_at"],
            ended_at=value["ended_at"],
            terminal_status=TerminalStatus(value["terminal_status"]) if value["terminal_status"] else None,
            reserved_usage=BudgetUsage.from_dict(value["reserved_usage"]) if value["reserved_usage"] else None,
            settled_usage=BudgetUsage.from_dict(value["settled_usage"]) if value["settled_usage"] else None,
            model_request=ModelAttemptRequest.from_dict(value["model_request"]) if value["model_request"] else None,
            model_result=ModelAttemptResult.from_dict(value["model_result"]) if value["model_result"] else None,
            previous_entry_sha256=value["previous_entry_sha256"],
            entry_sha256=value["entry_sha256"],
        )


class UsageLedgerError(RuntimeError):
    pass


class DuplicateAttemptError(UsageLedgerError):
    pass


class ReconciliationError(UsageLedgerError):
    pass


class BudgetCeilingExceeded(UsageLedgerError):
    def __init__(self, resource: str, *, used: int, requested: int, ceiling: int) -> None:
        super().__init__(
            f"project budget exceeded for {resource}: used={used}; requested={requested}; ceiling={ceiling}"
        )
        self.resource = resource
        self.used = used
        self.requested = requested
        self.ceiling = ceiling


class ReservationExceeded(ReconciliationError):
    def __init__(self, attempt_id: str, resource: str, *, reserved: int, settled: int) -> None:
        super().__init__(
            f"reconciliation exceeded reservation for {attempt_id}/{resource}: "
            f"reserved={reserved}; settled={settled}"
        )
        self.attempt_id = attempt_id
        self.resource = resource
        self.reserved = reserved
        self.settled = settled


class LedgerBreachError(UsageLedgerError):
    pass


_ACTION_USAGE_FIELD = {
    UsageActionKind.REPOSITORY_TOOL_CALL: "repository_tool_calls",
    UsageActionKind.CODEQL_CALL: "codeql_calls",
    UsageActionKind.PROPOSAL_FAMILY: "proposal_families",
    UsageActionKind.ADMISSIBLE_PROPOSAL: "admissible_proposals",
    UsageActionKind.CANDIDATE_PATH: "candidate_paths",
}


class ProjectUsageLedger:
    """Thread-safe append-only ledger for one project/arm/replicate run."""

    __slots__ = ("_run", "_ceilings", "_entries", "_lock")

    def __init__(
        self,
        run: RunKey,
        ceilings: ProjectBudgetCeilings,
        *,
        _entries: tuple[UsageLedgerEntry, ...] = (),
    ) -> None:
        if not isinstance(run, RunKey):
            raise ValueError("run must be the canonical arms.RunKey")
        if not isinstance(ceilings, ProjectBudgetCeilings):
            raise ValueError("ceilings must be ProjectBudgetCeilings")
        self._run = run
        self._ceilings = ceilings
        self._entries = tuple(_entries)
        self._lock = threading.RLock()
        self._validate_history()

    @property
    def run(self) -> RunKey:
        return self._run

    @property
    def ceilings(self) -> ProjectBudgetCeilings:
        return self._ceilings

    @property
    def budget_sha256(self) -> str:
        return self._ceilings.sha256

    @property
    def entries(self) -> tuple[UsageLedgerEntry, ...]:
        return self._entries

    def _validate_history(self) -> None:
        reservations: dict[str, UsageLedgerEntry] = {}
        reconciled: set[str] = set()
        previous = _ZERO_SHA256
        for index, entry in enumerate(self._entries, start=1):
            if entry.sequence != index:
                raise ValueError(f"ledger sequence is not contiguous at {entry.sequence}")
            if entry.run != self._run:
                raise ValueError("ledger entry run identity mismatch")
            if entry.previous_entry_sha256 != previous:
                raise ValueError(f"ledger hash chain mismatch at sequence {entry.sequence}")
            if entry.phase is LedgerPhase.RESERVATION:
                if entry.attempt_id in reservations:
                    raise DuplicateAttemptError(f"duplicate attempt ID: {entry.attempt_id}")
                reservations[entry.attempt_id] = entry
            else:
                reservation = reservations.get(entry.attempt_id)
                if reservation is None:
                    raise ReconciliationError(f"reconciliation without reservation: {entry.attempt_id}")
                if entry.attempt_id in reconciled:
                    raise ReconciliationError(f"attempt already reconciled: {entry.attempt_id}")
                self._validate_pair(reservation, entry)
                reconciled.add(entry.attempt_id)
            previous = entry.entry_sha256

    @staticmethod
    def _validate_pair(reservation: UsageLedgerEntry, reconciliation: UsageLedgerEntry) -> None:
        immutable_names = ("action_kind", "run", "actor_kind", "agent_id", "role", "action_name", "started_at")
        for name in immutable_names:
            if getattr(reservation, name) != getattr(reconciliation, name):
                raise ReconciliationError(
                    f"reconciliation changed {name} for attempt {reservation.attempt_id}"
                )

    def _reservations_and_reconciliations(
        self,
    ) -> tuple[dict[str, UsageLedgerEntry], dict[str, UsageLedgerEntry]]:
        reservations: dict[str, UsageLedgerEntry] = {}
        reconciliations: dict[str, UsageLedgerEntry] = {}
        for entry in self._entries:
            if entry.phase is LedgerPhase.RESERVATION:
                reservations[entry.attempt_id] = entry
            else:
                reconciliations[entry.attempt_id] = entry
        return reservations, reconciliations

    def _effective_usage(self) -> BudgetUsage:
        reservations, reconciliations = self._reservations_and_reconciliations()
        total = BudgetUsage()
        for attempt_id, reservation in reservations.items():
            reconciliation = reconciliations.get(attempt_id)
            usage = (
                reconciliation.settled_usage
                if reconciliation is not None
                else reservation.reserved_usage
            )
            assert usage is not None
            total = total + usage
        return total

    def _remaining(self, usage: BudgetUsage | None = None) -> dict[str, int]:
        usage = usage or self._effective_usage()
        return {
            resource: getattr(self._ceilings, ceiling_name) - getattr(usage, resource)
            for resource, ceiling_name in _USAGE_TO_CEILING.items()
        }

    def _capacity_check(self, requested: BudgetUsage) -> None:
        overruns = self._reservation_overruns()
        if overruns:
            first = overruns[0]
            raise LedgerBreachError(
                "ledger has an unrecoverable reservation breach; "
                f"attempt={first['attempt_id']}; resource={first['resource']}"
            )
        used = self._effective_usage()
        for resource, ceiling_name in _USAGE_TO_CEILING.items():
            current = getattr(used, resource)
            increment = getattr(requested, resource)
            ceiling = getattr(self._ceilings, ceiling_name)
            if current > ceiling:
                raise BudgetCeilingExceeded(resource, used=current, requested=increment, ceiling=ceiling)
            if current + increment > ceiling:
                raise BudgetCeilingExceeded(resource, used=current, requested=increment, ceiling=ceiling)

    def _reservation_overruns(self) -> list[dict[str, Any]]:
        reservations, reconciliations = self._reservations_and_reconciliations()
        overruns: list[dict[str, Any]] = []
        for attempt_id, reconciliation in reconciliations.items():
            reservation = reservations[attempt_id]
            assert reservation.reserved_usage is not None
            assert reconciliation.settled_usage is not None
            for resource in _USAGE_TO_CEILING:
                reserved = getattr(reservation.reserved_usage, resource)
                settled = getattr(reconciliation.settled_usage, resource)
                if settled > reserved:
                    overruns.append(
                        {
                            "attempt_id": attempt_id,
                            "resource": resource,
                            "reserved": reserved,
                            "settled": settled,
                        }
                    )
        return sorted(overruns, key=lambda item: (item["attempt_id"], item["resource"]))

    def _append(self, entry: UsageLedgerEntry) -> None:
        expected_sequence = len(self._entries) + 1
        expected_previous = self._entries[-1].entry_sha256 if self._entries else _ZERO_SHA256
        if entry.sequence != expected_sequence or entry.previous_entry_sha256 != expected_previous:
            raise UsageLedgerError("attempted a non-append ledger mutation")
        self._entries = (*self._entries, entry)

    def _new_entry(self, **values: Any) -> UsageLedgerEntry:
        return UsageLedgerEntry.create(
            sequence=len(self._entries) + 1,
            run=self._run,
            previous_entry_sha256=self._entries[-1].entry_sha256 if self._entries else _ZERO_SHA256,
            **values,
        )

    def _ensure_new_attempt(self, attempt_id: str) -> None:
        _require_identifier(attempt_id, "attempt_id")
        reservations, _ = self._reservations_and_reconciliations()
        if attempt_id in reservations:
            raise DuplicateAttemptError(f"duplicate attempt ID: {attempt_id}")

    def reserve_model_attempt(
        self,
        *,
        attempt_id: str,
        actor_kind: UsageActorKind,
        agent_id: str,
        role: str,
        request: ModelAttemptRequest,
        canonical_input_tokens: int,
        max_output_tokens: int,
        max_wall_clock_ms: int,
    ) -> UsageLedgerEntry:
        if actor_kind not in {
            UsageActorKind.COORDINATOR,
            UsageActorKind.SPECIALIST,
            UsageActorKind.SINGLE_AGENT,
        }:
            raise ValueError("model attempts must be owned by coordinator, specialist, or single-agent")
        if not isinstance(request, ModelAttemptRequest):
            raise ValueError("request must be ModelAttemptRequest")
        reserved = BudgetUsage(
            model_attempts=1,
            canonical_input_tokens=_require_positive_int(
                canonical_input_tokens, "canonical_input_tokens"
            ),
            output_tokens=_require_positive_int(max_output_tokens, "max_output_tokens"),
            wall_clock_ms=_require_positive_int(max_wall_clock_ms, "max_wall_clock_ms"),
        )
        with self._lock:
            self._ensure_new_attempt(attempt_id)
            self._capacity_check(reserved)
            entry = self._new_entry(
                phase=LedgerPhase.RESERVATION,
                attempt_id=attempt_id,
                action_kind=UsageActionKind.MODEL_ATTEMPT,
                actor_kind=actor_kind,
                agent_id=agent_id,
                role=role,
                action_name="MODEL_REQUEST",
                started_at=request.request_timestamp,
                ended_at=None,
                terminal_status=None,
                reserved_usage=reserved,
                settled_usage=None,
                model_request=request,
                model_result=None,
            )
            self._append(entry)
            return entry

    def reserve_action(
        self,
        *,
        attempt_id: str,
        action_kind: UsageActionKind,
        actor_kind: UsageActorKind,
        agent_id: str,
        role: str,
        action_name: str,
        started_at: str,
        max_wall_clock_ms: int = 0,
    ) -> UsageLedgerEntry:
        if action_kind is UsageActionKind.MODEL_ATTEMPT:
            raise ValueError("use reserve_model_attempt for model attempts")
        if action_kind not in _ACTION_USAGE_FIELD:
            raise ValueError(f"unsupported action kind: {action_kind}")
        if not isinstance(actor_kind, UsageActorKind):
            raise ValueError("actor_kind must be UsageActorKind")
        usage_values = {
            _ACTION_USAGE_FIELD[action_kind]: 1,
            "wall_clock_ms": _require_nonnegative_int(max_wall_clock_ms, "max_wall_clock_ms"),
        }
        reserved = BudgetUsage(**usage_values)
        with self._lock:
            self._ensure_new_attempt(attempt_id)
            self._capacity_check(reserved)
            entry = self._new_entry(
                phase=LedgerPhase.RESERVATION,
                attempt_id=attempt_id,
                action_kind=action_kind,
                actor_kind=actor_kind,
                agent_id=agent_id,
                role=role,
                action_name=action_name,
                started_at=_require_timestamp(started_at, "started_at"),
                ended_at=None,
                terminal_status=None,
                reserved_usage=reserved,
                settled_usage=None,
                model_request=None,
                model_result=None,
            )
            self._append(entry)
            return entry

    def _pending_reservation(self, attempt_id: str) -> UsageLedgerEntry:
        _require_identifier(attempt_id, "attempt_id")
        reservations, reconciliations = self._reservations_and_reconciliations()
        reservation = reservations.get(attempt_id)
        if reservation is None:
            raise ReconciliationError(f"unknown attempt ID: {attempt_id}")
        if attempt_id in reconciliations:
            raise ReconciliationError(f"attempt already reconciled: {attempt_id}")
        return reservation

    def _append_reconciliation(
        self,
        reservation: UsageLedgerEntry,
        *,
        status: TerminalStatus,
        ended_at: str,
        settled_usage: BudgetUsage,
        model_result: ModelAttemptResult | None,
    ) -> UsageLedgerEntry:
        entry = self._new_entry(
            phase=LedgerPhase.RECONCILIATION,
            attempt_id=reservation.attempt_id,
            action_kind=reservation.action_kind,
            actor_kind=reservation.actor_kind,
            agent_id=reservation.agent_id,
            role=reservation.role,
            action_name=reservation.action_name,
            started_at=reservation.started_at,
            ended_at=_require_timestamp(ended_at, "ended_at"),
            terminal_status=status,
            reserved_usage=None,
            settled_usage=settled_usage,
            model_request=None,
            model_result=model_result,
        )
        self._append(entry)
        assert reservation.reserved_usage is not None
        for resource in _USAGE_TO_CEILING:
            reserved_value = getattr(reservation.reserved_usage, resource)
            settled_value = getattr(settled_usage, resource)
            if settled_value > reserved_value:
                # Preserve the observed overrun in the append-only audit before
                # failing closed. All subsequent reservations will also fail.
                raise ReservationExceeded(
                    reservation.attempt_id,
                    resource,
                    reserved=reserved_value,
                    settled=settled_value,
                )
        return entry

    def reconcile_model_attempt(
        self,
        *,
        attempt_id: str,
        status: TerminalStatus,
        ended_at: str,
        wall_clock_ms: int,
        result: ModelAttemptResult,
    ) -> UsageLedgerEntry:
        if not isinstance(status, TerminalStatus):
            raise ValueError("status must be TerminalStatus")
        if status is TerminalStatus.TOOL_ERROR:
            raise ValueError("TOOL_ERROR is not a model-attempt terminal status")
        if not isinstance(result, ModelAttemptResult):
            raise ValueError("result must be ModelAttemptResult")
        elapsed = _require_nonnegative_int(wall_clock_ms, "wall_clock_ms")
        with self._lock:
            reservation = self._pending_reservation(attempt_id)
            if reservation.action_kind is not UsageActionKind.MODEL_ATTEMPT:
                raise ReconciliationError(f"attempt {attempt_id} is not a model attempt")
            assert reservation.reserved_usage is not None

            if status is TerminalStatus.CANCELLED_BEFORE_SEND:
                if any(
                    measurement.source is not TokenCountSource.NOT_REPORTED
                    for measurement in fields(ModelTokenUsage)
                    for measurement in (getattr(result.tokens, measurement.name),)
                ):
                    raise ReconciliationError(
                        "cancelled-before-send model attempts cannot have reported token usage"
                    )
                output_charge = 0
                input_charge = 0
            else:
                output_measurement = result.tokens.output_tokens
                output_charge = (
                    output_measurement.count
                    if output_measurement.count is not None
                    else reservation.reserved_usage.output_tokens
                )
                input_charge = reservation.reserved_usage.canonical_input_tokens

            settled = BudgetUsage(
                model_attempts=1,
                canonical_input_tokens=input_charge,
                output_tokens=output_charge,
                wall_clock_ms=elapsed,
            )
            return self._append_reconciliation(
                reservation,
                status=status,
                ended_at=ended_at,
                settled_usage=settled,
                model_result=result,
            )

    def reconcile_action(
        self,
        *,
        attempt_id: str,
        status: TerminalStatus,
        ended_at: str,
        wall_clock_ms: int,
    ) -> UsageLedgerEntry:
        if not isinstance(status, TerminalStatus):
            raise ValueError("status must be TerminalStatus")
        elapsed = _require_nonnegative_int(wall_clock_ms, "wall_clock_ms")
        with self._lock:
            reservation = self._pending_reservation(attempt_id)
            if reservation.action_kind is UsageActionKind.MODEL_ATTEMPT:
                raise ReconciliationError(f"attempt {attempt_id} is a model attempt")
            assert reservation.reserved_usage is not None
            count = 0 if status is TerminalStatus.CANCELLED_BEFORE_SEND else 1
            settled = BudgetUsage(
                **{
                    _ACTION_USAGE_FIELD[reservation.action_kind]: count,
                    "wall_clock_ms": elapsed,
                }
            )
            return self._append_reconciliation(
                reservation,
                status=status,
                ended_at=ended_at,
                settled_usage=settled,
                model_result=None,
            )

    def summary(self) -> dict[str, Any]:
        with self._lock:
            reservations, reconciliations = self._reservations_and_reconciliations()
            charged = self._effective_usage()
            pending_usage = BudgetUsage()
            settled_usage = BudgetUsage()
            for attempt_id, reservation in reservations.items():
                if attempt_id not in reconciliations:
                    assert reservation.reserved_usage is not None
                    pending_usage = pending_usage + reservation.reserved_usage
            for reconciliation in reconciliations.values():
                assert reconciliation.settled_usage is not None
                settled_usage = settled_usage + reconciliation.settled_usage

            token_metrics: dict[str, dict[str, Any]] = {}
            for token_name in ("input_tokens", "output_tokens", "cache_read_tokens", "cache_write_tokens"):
                sources: Counter[str] = Counter()
                known_by_source: Counter[str] = Counter()
                for reconciliation in reconciliations.values():
                    if reconciliation.model_result is None:
                        continue
                    measurement = getattr(reconciliation.model_result.tokens, token_name)
                    sources[measurement.source.value] += 1
                    if measurement.count is not None:
                        known_by_source[measurement.source.value] += measurement.count
                token_metrics[token_name] = {
                    "known_total": sum(known_by_source.values()),
                    "known_by_source": dict(sorted(known_by_source.items())),
                    "attempts_by_source": dict(sorted(sources.items())),
                    "not_reported_attempts": sources[TokenCountSource.NOT_REPORTED.value],
                }

            cost_total = Decimal(0)
            cost_sources: Counter[str] = Counter()
            cost_unknown = 0
            for reconciliation in reconciliations.values():
                if reconciliation.model_result is None:
                    continue
                cost = reconciliation.model_result.billed_cost
                cost_sources[cost.source.value] += 1
                if cost.amount_usd is None:
                    cost_unknown += 1
                else:
                    cost_total += Decimal(cost.amount_usd)

            statuses = Counter(
                entry.terminal_status.value
                for entry in reconciliations.values()
                if entry.terminal_status is not None
            )
            actor_model_attempts = Counter(
                entry.actor_kind.value
                for entry in reservations.values()
                if entry.action_kind is UsageActionKind.MODEL_ATTEMPT
            )
            retry_attempts = sum(
                1
                for entry in reservations.values()
                if entry.model_request is not None and entry.model_request.retry_index > 0
            )
            remaining = self._remaining(charged)
            reservation_overruns = self._reservation_overruns()
            breaches = sorted(
                {
                    *(resource for resource, value in remaining.items() if value < 0),
                    *(item["resource"] for item in reservation_overruns),
                }
            )
            return {
                "charged_usage": charged.to_dict(),
                "settled_usage": settled_usage.to_dict(),
                "pending_reserved_usage": pending_usage.to_dict(),
                "remaining": remaining,
                "pending_attempt_ids": sorted(set(reservations) - set(reconciliations)),
                "terminal_status_counts": dict(sorted(statuses.items())),
                "model_attempts_by_actor": dict(sorted(actor_model_attempts.items())),
                "transport_retry_attempts": retry_attempts,
                "token_measurements": token_metrics,
                "billed_cost": {
                    "known_total_usd": _canonical_decimal(str(cost_total), "known_total_usd"),
                    "attempts_by_source": dict(sorted(cost_sources.items())),
                    "not_reported_attempts": cost_unknown,
                    "is_budget_ceiling": False,
                },
                "reservation_overruns": reservation_overruns,
                "breached_resources": breaches,
                "is_breached": bool(breaches),
            }

    def _payload_dict(self) -> dict[str, Any]:
        return {
            "schema_version": USAGE_LEDGER_SCHEMA_VERSION,
            "run": self._run.to_dict(),
            "budget": self._ceilings.to_dict(),
            "budget_sha256": self.budget_sha256,
            "entries": [entry.to_dict() for entry in self._entries],
            "summary": self.summary(),
        }

    @property
    def sha256(self) -> str:
        with self._lock:
            return _sha256(self._payload_dict())

    def to_dict(self) -> dict[str, Any]:
        with self._lock:
            value = self._payload_dict()
            value["ledger_sha256"] = _sha256(value)
            return value

    def to_canonical_json(self) -> str:
        return _canonical_json(self.to_dict())

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ProjectUsageLedger":
        expected = {
            "schema_version",
            "run",
            "budget",
            "budget_sha256",
            "entries",
            "summary",
            "ledger_sha256",
        }
        _require_exact_keys(value, expected, "project usage ledger")
        if value["schema_version"] != USAGE_LEDGER_SCHEMA_VERSION:
            raise ValueError(f"unsupported usage ledger schema: {value['schema_version']}")
        run = RunKey.from_dict(value["run"])
        budget = ProjectBudgetCeilings.from_dict(value["budget"])
        if value["budget_sha256"] != budget.sha256:
            raise ValueError("budget_sha256 does not match the canonical budget")
        if not isinstance(value["entries"], list):
            raise ValueError("entries must be a list")
        entries = tuple(UsageLedgerEntry.from_dict(item) for item in value["entries"])
        ledger = cls(run, budget, _entries=entries)
        if value["summary"] != ledger.summary():
            raise ValueError("serialized ledger summary does not match entries")
        material = {name: value[name] for name in expected if name != "ledger_sha256"}
        if value["ledger_sha256"] != _sha256(material):
            raise ValueError("ledger_sha256 does not match serialized ledger")
        return ledger

    @classmethod
    def from_canonical_json(cls, value: str) -> "ProjectUsageLedger":
        if not isinstance(value, str):
            raise ValueError("canonical ledger JSON must be a string")
        parsed = json.loads(value)
        if not isinstance(parsed, dict):
            raise ValueError("canonical ledger JSON must contain an object")
        if _canonical_json(parsed) != value:
            raise ValueError("ledger JSON is not canonical")
        return cls.from_dict(parsed)


SharedUsageLedger = ProjectUsageLedger


__all__ = [
    "BUDGET_CONTRACT_VERSION",
    "CORE_CONFIRMATORY_ARM_IDS",
    "ROLE_CONFIRMATORY_ARM_IDS",
    "USAGE_LEDGER_SCHEMA_VERSION",
    "BudgetCeilingExceeded",
    "BudgetComparabilityError",
    "BudgetUsage",
    "CostMeasurement",
    "CostSource",
    "DuplicateAttemptError",
    "LedgerBreachError",
    "LedgerPhase",
    "ModelAttemptRequest",
    "ModelAttemptResult",
    "ModelTokenUsage",
    "ProjectBudgetCeilings",
    "ProjectUsageLedger",
    "ReconciliationError",
    "ReservationExceeded",
    "RunKey",
    "SharedUsageLedger",
    "TerminalStatus",
    "TokenCountSource",
    "TokenMeasurement",
    "UsageActionKind",
    "UsageActorKind",
    "UsageLedgerEntry",
    "UsageLedgerError",
    "assert_confirmatory_budget_comparability",
    "confirmatory_arms_for_profile",
]
