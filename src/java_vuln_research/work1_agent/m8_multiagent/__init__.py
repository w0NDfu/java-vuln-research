"""Deterministic contracts for the Work1 V11 M8 multi-agent experiment."""

from .board import BoardEvent, SharedEvidenceBoard, SpecialistAgentState
from .agent_registry import (
    COORDINATOR_AGENT,
    EFFECT_AGENT,
    INPUT_AGENT,
    M8_AGENT_REGISTRY,
    SEMANTIC_BRIDGE_AGENT,
    SPECIALIST_AGENT_REGISTRY,
    AgentModelSpec,
)
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
from .specialists import (
    BRIDGE_ALLOWED_TOOLS,
    EFFECT_ALLOWED_TOOLS,
    INPUT_ALLOWED_TOOLS,
    BridgeAgentRuntime,
    EffectAgentRuntime,
    InputAgentRuntime,
    SpecialistAgentRuntime,
    SpecialistRuntimeFailure,
    SpecialistRuntimeRun,
)

__all__ = [
    "BoardEvent",
    "AgentModelSpec",
    "BRIDGE_ALLOWED_TOOLS",
    "BridgeAgentRuntime",
    "COORDINATOR_AGENT",
    "EFFECT_AGENT",
    "EFFECT_ALLOWED_TOOLS",
    "EffectAgentRuntime",
    "FindingType",
    "INPUT_AGENT",
    "INPUT_ALLOWED_TOOLS",
    "InputAgentRuntime",
    "M8_AGENT_REGISTRY",
    "ProposalAnchor",
    "RoleOption",
    "RolePreview",
    "ScopeBasis",
    "ScopePreview",
    "SharedEvidenceBoard",
    "SEMANTIC_BRIDGE_AGENT",
    "SPECIALIST_AGENT_REGISTRY",
    "SpecialistAgentState",
    "SpecialistFinding",
    "SpecialistAgentRuntime",
    "SpecialistRuntimeFailure",
    "SpecialistRuntimeRun",
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
