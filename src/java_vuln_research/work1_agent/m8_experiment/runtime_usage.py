"""Runtime adapter for the append-only M8 project usage ledger."""

from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from java_vuln_research.work1_agent.agent.llm_client import (
    LLMClient,
    LLMRequest,
    LLMResponse,
    ModelCallError,
    ModelFailureClass,
)
from java_vuln_research.work1_agent.proposal.model import canonical_json

from .usage import (
    CostMeasurement,
    ModelAttemptRequest,
    ModelAttemptResult,
    ModelTokenUsage,
    ProjectUsageLedger,
    TerminalStatus,
    TokenMeasurement,
    UsageActionKind,
    UsageActorKind,
)


@dataclass(frozen=True, slots=True)
class RuntimeModelAttempt:
    attempt_id: str
    started_monotonic: float


@dataclass(frozen=True, slots=True)
class RuntimeActionAttempt:
    attempt_id: str
    started_monotonic: float


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def _elapsed_ms(started: float) -> int:
    return max(0, round((time.monotonic() - started) * 1000))


def _reported_or_unknown(value: int) -> TokenMeasurement:
    if value > 0:
        return TokenMeasurement.provider_reported(value)
    return TokenMeasurement.not_reported()


def _response_result(response: LLMResponse) -> ModelAttemptResult:
    raw_request_id = response.provenance.get("response_id")
    provider_request_id = (
        raw_request_id.strip()
        if isinstance(raw_request_id, str) and raw_request_id.strip()
        else None
    )
    return ModelAttemptResult(
        tokens=ModelTokenUsage(
            input_tokens=_reported_or_unknown(response.input_tokens),
            output_tokens=_reported_or_unknown(response.output_tokens),
            cache_read_tokens=TokenMeasurement.not_reported(),
            cache_write_tokens=TokenMeasurement.not_reported(),
        ),
        billed_cost=CostMeasurement.not_reported(),
        provider_request_id=provider_request_id,
        provider_status=response.finish_reason or "RESPONSE_RECEIVED",
        response_reported_model=response.model_id,
    )


def _error_result(error: BaseException) -> ModelAttemptResult:
    status = (
        error.failure_class.value
        if isinstance(error, ModelCallError)
        else type(error).__name__.upper()
    )
    return ModelAttemptResult(
        tokens=ModelTokenUsage.all_not_reported(),
        billed_cost=CostMeasurement.not_reported(),
        provider_status=status,
    )


class RuntimeUsageRecorder:
    """Reserve and reconcile real runtime work against one project ledger."""

    __slots__ = (
        "_default_max_output_tokens",
        "_default_timeout_seconds",
        "_ledger",
        "_lock",
        "_model_sequence",
        "_sequence",
        "_tool_catalog_sha256",
    )

    def __init__(
        self,
        ledger: ProjectUsageLedger,
        *,
        tool_catalog_sha256: str,
        default_max_output_tokens: int = 2_048,
        default_timeout_seconds: float = 60,
    ) -> None:
        if not isinstance(ledger, ProjectUsageLedger):
            raise TypeError("ledger must be ProjectUsageLedger")
        if len(tool_catalog_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in tool_catalog_sha256
        ):
            raise ValueError("tool_catalog_sha256 must be lowercase SHA-256")
        if default_max_output_tokens < 1 or default_timeout_seconds <= 0:
            raise ValueError("runtime model reservation defaults must be positive")
        self._ledger = ledger
        self._tool_catalog_sha256 = tool_catalog_sha256
        self._default_max_output_tokens = int(default_max_output_tokens)
        self._default_timeout_seconds = float(default_timeout_seconds)
        self._sequence = 0
        self._model_sequence = 0
        self._lock = threading.Lock()

    @property
    def ledger(self) -> ProjectUsageLedger:
        return self._ledger

    def _next_attempt_id(self, prefix: str, identity: Any) -> tuple[int, str]:
        with self._lock:
            self._sequence += 1
            sequence = self._sequence
        digest = _sha256({"sequence": sequence, "identity": identity})[:20]
        return sequence, f"{prefix}-{sequence:04d}-{digest}"

    def _next_model_attempt_id(self, identity: Any) -> tuple[int, str]:
        with self._lock:
            self._sequence += 1
            self._model_sequence += 1
            sequence = self._sequence
            model_sequence = self._model_sequence
        digest = _sha256({"sequence": sequence, "identity": identity})[:20]
        return model_sequence, f"model-{sequence:04d}-{digest}"

    def reserve_model_attempt(
        self,
        *,
        client: LLMClient,
        request: LLMRequest,
        actor_kind: UsageActorKind,
        agent_id: str,
        role: str,
        configured_model_id: str,
    ) -> RuntimeModelAttempt:
        config = getattr(client, "config", None)
        max_output_tokens = int(
            getattr(config, "max_output_tokens", self._default_max_output_tokens)
        )
        timeout_seconds = float(
            getattr(config, "timeout_seconds", self._default_timeout_seconds)
        )
        wire_request = {
            "project_id": request.project_id,
            "round": request.round,
            "attempt": request.attempt,
            "system_prompt": request.system_prompt,
            "observation": dict(request.observation),
        }
        serialized = canonical_json(wire_request).encode("utf-8")
        # The budget unit is a deterministic, provider-neutral approximation.
        # Provider-reported tokens remain separate measurements in reconciliation.
        canonical_input_tokens = max(1, (len(serialized) + 3) // 4)
        model_sequence, attempt_id = self._next_model_attempt_id(
            {
                "request_id": request.request_id,
                "agent_id": agent_id,
                "role": role,
            },
        )
        started_at = _timestamp()
        self._ledger.reserve_model_attempt(
            attempt_id=attempt_id,
            actor_kind=actor_kind,
            agent_id=agent_id,
            role=role,
            request=ModelAttemptRequest(
                attempt_index=model_sequence,
                retry_index=request.attempt - 1,
                configured_model_id=configured_model_id,
                request_timestamp=started_at,
                canonical_prompt_sha256=_sha256(request.system_prompt),
                observation_sha256=_sha256(dict(request.observation)),
                tool_catalog_sha256=self._tool_catalog_sha256,
                serialized_request_bytes=len(serialized),
            ),
            canonical_input_tokens=canonical_input_tokens,
            max_output_tokens=max_output_tokens,
            max_wall_clock_ms=max(1, round(timeout_seconds * 1000) + 5_000),
        )
        return RuntimeModelAttempt(attempt_id, time.monotonic())

    @staticmethod
    def status_for_model_error(error: ModelCallError) -> TerminalStatus:
        if error.failure_class is ModelFailureClass.MODEL_TIMEOUT:
            return TerminalStatus.TIMEOUT
        if error.failure_class is ModelFailureClass.MODEL_UNAVAILABLE:
            return TerminalStatus.PROVIDER_ERROR
        return TerminalStatus.INVALID_OUTPUT

    def reconcile_model_attempt(
        self,
        attempt: RuntimeModelAttempt,
        *,
        status: TerminalStatus,
        response: LLMResponse | None = None,
        error: BaseException | None = None,
    ) -> None:
        if (response is None) == (error is None):
            raise ValueError(
                "model reconciliation requires exactly one response or error"
            )
        result = (
            _response_result(response) if response is not None else _error_result(error)
        )
        self._ledger.reconcile_model_attempt(
            attempt_id=attempt.attempt_id,
            status=status,
            ended_at=_timestamp(),
            wall_clock_ms=_elapsed_ms(attempt.started_monotonic),
            result=result,
        )

    def reserve_action(
        self,
        *,
        action_kind: UsageActionKind,
        actor_kind: UsageActorKind,
        agent_id: str,
        role: str,
        action_name: str,
        identity: Any,
        max_wall_clock_ms: int,
    ) -> RuntimeActionAttempt:
        _, attempt_id = self._next_attempt_id(
            "action",
            {
                "action_kind": action_kind.value,
                "agent_id": agent_id,
                "role": role,
                "action_name": action_name,
                "identity": identity,
            },
        )
        self._ledger.reserve_action(
            attempt_id=attempt_id,
            action_kind=action_kind,
            actor_kind=actor_kind,
            agent_id=agent_id,
            role=role,
            action_name=action_name,
            started_at=_timestamp(),
            max_wall_clock_ms=max_wall_clock_ms,
        )
        return RuntimeActionAttempt(attempt_id, time.monotonic())

    def reconcile_action(
        self,
        attempt: RuntimeActionAttempt,
        *,
        status: TerminalStatus,
    ) -> None:
        self._ledger.reconcile_action(
            attempt_id=attempt.attempt_id,
            status=status,
            ended_at=_timestamp(),
            wall_clock_ms=_elapsed_ms(attempt.started_monotonic),
        )


__all__ = [
    "RuntimeActionAttempt",
    "RuntimeModelAttempt",
    "RuntimeUsageRecorder",
]
