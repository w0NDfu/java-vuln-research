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
from .role_helper import ProposalAnchor, RoleOption, RolePreview, build_role_guidance
from .scope_helper import ScopeBasis, ScopePreview, build_valid_scope

__all__ = [
    "BoardEvent",
    "FindingType",
    "ProposalAnchor",
    "RoleOption",
    "RolePreview",
    "ScopeBasis",
    "ScopePreview",
    "SharedEvidenceBoard",
    "SpecialistAgentState",
    "SpecialistFinding",
    "SpecialistResult",
    "SpecialistResultStatus",
    "SpecialistRole",
    "SpecialistStopReason",
    "SpecialistTaskSpec",
    "build_role_guidance",
    "build_valid_scope",
    "read_board_snapshot",
    "replay_board",
    "write_board_events",
    "write_board_snapshot",
]
