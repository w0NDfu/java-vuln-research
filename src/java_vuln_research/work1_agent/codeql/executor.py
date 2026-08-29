from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from .result import CodeQLToolResult, FailureReason, ToolFailure, ToolStatus, bounded_text


@dataclass(frozen=True, slots=True)
class QuerySpec:
    name: str
    path: Path
    columns: tuple[str, ...]
    max_rows: int = 100


def _sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _query_pack_root(path: Path) -> Path | None:
    """Return the nearest qlpack root containing ``path``, if any."""

    for candidate in (path.parent, *path.parents):
        if (candidate / "qlpack.yml").is_file():
            return candidate
    return None


def _classify_failure(output: str) -> FailureReason:
    lowered = output.casefold()
    if any(token in lowered for token in ("out of memory", "java heap space", "exit code 137", "killed")):
        return FailureReason.OOM
    if any(token in lowered for token in ("could not resolve", "compiling query", "compile error", "query compilation")):
        return FailureReason.QUERY_COMPILE_ERROR
    return FailureReason.QUERY_EXECUTION_ERROR


def _ql_literal(value: str | int) -> str:
    if isinstance(value, bool):
        raise ValueError("boolean template values are not supported")
    if isinstance(value, int):
        return str(value)
    text = str(value)
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'


class CodeQLExecutor:
    """Shared, bounded CodeQL query/BQRS execution boundary."""

    def __init__(
        self,
        executable: str | Path = "codeql",
        *,
        artifact_root: str | Path,
        timeout_seconds: int = 90,
        max_log_chars: int = 4000,
        runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.executable = str(executable)
        self.artifact_root = Path(artifact_root)
        self.timeout_seconds = int(timeout_seconds)
        self.max_log_chars = int(max_log_chars)
        self._runner = runner
        self._version: str | None = None

    def _executable_path(self) -> str | None:
        if self._runner is not subprocess.run:
            return self.executable
        candidate = Path(self.executable)
        if candidate.is_file():
            return str(candidate)
        return shutil.which(self.executable)

    def _codeql_version(self, resolved: str) -> str:
        if self._version is not None:
            return self._version
        try:
            completed = self._runner(
                [resolved, "version", "--format=json"],
                capture_output=True,
                text=True,
                timeout=min(30, self.timeout_seconds),
                check=False,
            )
            text = completed.stdout or completed.stderr or ""
            try:
                parsed = json.loads(text)
                self._version = str(parsed.get("version") or parsed.get("versionNumber") or text.strip())
            except json.JSONDecodeError:
                self._version = text.strip().splitlines()[0] if text.strip() else "UNKNOWN"
        except (OSError, subprocess.TimeoutExpired):
            self._version = "UNKNOWN"
        return self._version

    @staticmethod
    def _database_ready(database: Path) -> bool:
        metadata = database / "codeql-database.yml"
        if not metadata.is_file():
            return False
        try:
            text = metadata.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        return "primaryLanguage: java" in text and "\ninProgress:" not in text

    @staticmethod
    def _error(
        *,
        tool_call_id: str,
        tool_name: str,
        reason: FailureReason,
        message: str,
        queried_entity_ids: Sequence[str],
        exit_code: int | None = None,
        provenance: Mapping[str, Any] | None = None,
        wall_clock_seconds: float = 0.0,
    ) -> CodeQLToolResult:
        return CodeQLToolResult(
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            status=ToolStatus.ERROR,
            queried_entity_ids=list(queried_entity_ids),
            failure=ToolFailure(reason=reason, message=message, exit_code=exit_code),
            provenance=dict(provenance or {}),
            metrics={"wall_clock_seconds": round(wall_clock_seconds, 6)},
        )

    def execute(
        self,
        *,
        database: str | Path,
        query: QuerySpec,
        tool_name: str,
        queried_entity_ids: Sequence[str] = (),
        template_values: Mapping[str, str | int] | None = None,
        threads: int = 0,
        ram_mb: int | None = None,
    ) -> CodeQLToolResult:
        started = time.monotonic()
        call_id = "codeql-call-" + uuid.uuid4().hex
        db = Path(database)
        resolved = self._executable_path()
        if resolved is None:
            return self._error(
                tool_call_id=call_id,
                tool_name=tool_name,
                reason=FailureReason.CODEQL_UNAVAILABLE,
                message=f"CodeQL executable is unavailable: {self.executable}",
                queried_entity_ids=queried_entity_ids,
            )
        if not db.is_dir():
            return self._error(
                tool_call_id=call_id,
                tool_name=tool_name,
                reason=FailureReason.DB_NOT_FOUND,
                message=f"CodeQL database does not exist: {db}",
                queried_entity_ids=queried_entity_ids,
            )
        if not self._database_ready(db):
            return self._error(
                tool_call_id=call_id,
                tool_name=tool_name,
                reason=FailureReason.DB_NOT_READY,
                message=f"CodeQL database metadata is missing or in progress: {db}",
                queried_entity_ids=queried_entity_ids,
            )
        if not query.path.is_file():
            return self._error(
                tool_call_id=call_id,
                tool_name=tool_name,
                reason=FailureReason.QUERY_NOT_FOUND,
                message=f"query does not exist: {query.path}",
                queried_entity_ids=queried_entity_ids,
            )

        call_dir = self.artifact_root / call_id
        call_dir.mkdir(parents=True, exist_ok=False)
        execution_query = query.path
        template_hash = _sha256(query.path)
        query_pack_root = _query_pack_root(query.path)
        if template_values:
            source = query.path.read_text(encoding="utf-8")
            for key, value in sorted(template_values.items()):
                source = source.replace("{{" + str(key) + "}}", _ql_literal(value))
            if "{{" in source or "}}" in source:
                return self._error(
                    tool_call_id=call_id,
                    tool_name=tool_name,
                    reason=FailureReason.QUERY_COMPILE_ERROR,
                    message="unresolved query template placeholder",
                    queried_entity_ids=queried_entity_ids,
                    provenance={"query_path": str(query.path), "template_hash": template_hash},
                )
            execution_query = call_dir / query.path.name
            execution_query.write_text(source, encoding="utf-8", newline="\n")
            # A generated query outside its original qlpack cannot resolve
            # imports such as ``java``.  Reproduce the minimal pack context in
            # the immutable call artifact so CodeQL also sees the exact lock
            # file used for dependency resolution.
            if query_pack_root is not None:
                for metadata_name in ("qlpack.yml", "codeql-pack.lock.yml"):
                    metadata = query_pack_root / metadata_name
                    if metadata.is_file():
                        shutil.copy2(metadata, call_dir / metadata_name)
        bqrs = call_dir / "result.bqrs"
        csv_path = call_dir / "result.csv"
        log_path = call_dir / "query.log"
        command = [
            resolved,
            "query",
            "run",
            str(execution_query),
            f"--database={db}",
            f"--output={bqrs}",
            f"--threads={int(threads)}",
        ]
        if ram_mb is not None:
            command.append(f"--ram={int(ram_mb)}")
        provenance: dict[str, Any] = {
            "codeql_version": self._codeql_version(resolved),
            "database_path": str(db),
            "database_id": db.name,
            "query_path": str(query.path),
            "query_hash": _sha256(execution_query),
            "query_template_hash": template_hash,
            "query_pack_root": str(query_pack_root) if query_pack_root is not None else None,
            "arguments": dict(template_values or {}),
            "command": command,
            "result_path": str(bqrs),
            "csv_path": str(csv_path),
        }
        try:
            completed = self._runner(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            elapsed = time.monotonic() - started
            return self._error(
                tool_call_id=call_id,
                tool_name=tool_name,
                reason=FailureReason.TIMEOUT,
                message=bounded_text(str(error), self.max_log_chars),
                queried_entity_ids=queried_entity_ids,
                provenance=provenance,
                wall_clock_seconds=elapsed,
            )
        except OSError as error:
            elapsed = time.monotonic() - started
            return self._error(
                tool_call_id=call_id,
                tool_name=tool_name,
                reason=FailureReason.QUERY_EXECUTION_ERROR,
                message=bounded_text(str(error), self.max_log_chars),
                queried_entity_ids=queried_entity_ids,
                provenance=provenance,
                wall_clock_seconds=elapsed,
            )
        query_output = (completed.stdout or "") + (completed.stderr or "")
        log_path.write_text(bounded_text(query_output, self.max_log_chars), encoding="utf-8")
        provenance.update(
            exit_code=completed.returncode,
            stdout_summary=bounded_text(completed.stdout, self.max_log_chars),
            stderr_summary=bounded_text(completed.stderr, self.max_log_chars),
            log_path=str(log_path),
        )
        if completed.returncode != 0:
            elapsed = time.monotonic() - started
            reason = _classify_failure(query_output)
            return self._error(
                tool_call_id=call_id,
                tool_name=tool_name,
                reason=reason,
                message=bounded_text(query_output, self.max_log_chars),
                queried_entity_ids=queried_entity_ids,
                exit_code=completed.returncode,
                provenance=provenance,
                wall_clock_seconds=elapsed,
            )

        decode_command = [resolved, "bqrs", "decode", "--format=csv", "--no-titles", str(bqrs)]
        try:
            decoded = self._runner(
                decode_command,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            elapsed = time.monotonic() - started
            return self._error(
                tool_call_id=call_id,
                tool_name=tool_name,
                reason=FailureReason.TIMEOUT,
                message=bounded_text(str(error), self.max_log_chars),
                queried_entity_ids=queried_entity_ids,
                provenance=provenance,
                wall_clock_seconds=elapsed,
            )
        if decoded.returncode != 0:
            elapsed = time.monotonic() - started
            return self._error(
                tool_call_id=call_id,
                tool_name=tool_name,
                reason=FailureReason.BQRS_DECODE_ERROR,
                message=bounded_text((decoded.stdout or "") + (decoded.stderr or ""), self.max_log_chars),
                queried_entity_ids=queried_entity_ids,
                exit_code=decoded.returncode,
                provenance=provenance,
                wall_clock_seconds=elapsed,
            )
        csv_path.write_text(decoded.stdout or "", encoding="utf-8")
        try:
            raw_rows = [row for row in csv.reader((decoded.stdout or "").splitlines()) if row]
            if any(len(row) != len(query.columns) for row in raw_rows):
                raise ValueError(f"expected {len(query.columns)} columns")
            rows = [dict(zip(query.columns, row, strict=True)) for row in raw_rows]
        except (csv.Error, ValueError) as error:
            elapsed = time.monotonic() - started
            return self._error(
                tool_call_id=call_id,
                tool_name=tool_name,
                reason=FailureReason.OUTPUT_PARSE_ERROR,
                message=str(error),
                queried_entity_ids=queried_entity_ids,
                provenance=provenance,
                wall_clock_seconds=elapsed,
            )
        truncated = len(rows) > query.max_rows
        selected = rows[: query.max_rows]
        provenance["result_hash"] = _sha256(csv_path)
        elapsed = time.monotonic() - started
        return CodeQLToolResult(
            tool_call_id=call_id,
            tool_name=tool_name,
            status=ToolStatus.OK if selected else ToolStatus.EMPTY,
            queried_entity_ids=list(queried_entity_ids),
            nodes=selected,
            truncated=truncated,
            provenance=provenance,
            metrics={
                "wall_clock_seconds": round(elapsed, 6),
                "returned_rows": len(selected),
                "decoded_rows": len(rows),
            },
        )
