"""Canonical SharedEvidenceBoard snapshot and event-log serialization."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from java_vuln_research.work1_agent.proposal.model import canonical_json

from .board import BoardEvent, SharedEvidenceBoard


def _write_text(path: str | Path, text: str) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")


def write_board_snapshot(path: str | Path, board: SharedEvidenceBoard) -> None:
    _write_text(path, canonical_json(board.to_dict()) + "\n")


def write_board_events(path: str | Path, events: Iterable[BoardEvent]) -> None:
    rows = [canonical_json(item.to_dict()) for item in events]
    _write_text(path, "\n".join(rows) + ("\n" if rows else ""))


def read_board_snapshot(path: str | Path) -> SharedEvidenceBoard:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("board snapshot must be a JSON object")
    return SharedEvidenceBoard.from_dict(value)


def replay_board(path: str | Path) -> SharedEvidenceBoard:
    events: list[BoardEvent] = []
    for line_number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"board event line {line_number} is not a JSON object")
        events.append(BoardEvent.from_dict(value))
    return SharedEvidenceBoard.replay(events)
