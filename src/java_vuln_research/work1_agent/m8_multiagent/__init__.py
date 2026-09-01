"""Deterministic contracts for the Work1 V11 M8 multi-agent experiment."""

from .board import BoardEvent, SharedEvidenceBoard, SpecialistAgentState
from .contracts import (
    FindingType,
    SpecialistFinding,
    SpecialistResult,
    SpecialistResultStatus,
    SpecialistRole,
    SpecialistStopReason,
    SpecialistTaskSpec,
)
from .serialization import read_board_snapshot, replay_board, write_board_events, write_board_snapshot

__all__ = [
    "BoardEvent",
    "FindingType",
    "SharedEvidenceBoard",
    "SpecialistAgentState",
    "SpecialistFinding",
    "SpecialistResult",
    "SpecialistResultStatus",
    "SpecialistRole",
    "SpecialistStopReason",
    "SpecialistTaskSpec",
    "read_board_snapshot",
    "replay_board",
    "write_board_events",
    "write_board_snapshot",
]
