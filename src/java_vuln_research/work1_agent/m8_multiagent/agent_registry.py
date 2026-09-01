"""Frozen M8 agent identities and exact model assignments."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from .contracts import SpecialistRole


@dataclass(frozen=True, slots=True)
class AgentModelSpec:
    id: str
    name: str
    model_id: str

    def __post_init__(self) -> None:
        if not self.id or self.id != self.id.strip() or self.id != self.name:
            raise ValueError("M8 agent id and name must be identical and non-empty")
        if not self.model_id or self.model_id != self.model_id.strip():
            raise ValueError("M8 exact model ID is required")

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "name": self.name, "exact_model_id": self.model_id}


COORDINATOR_AGENT = AgentModelSpec(
    id="coordinator_agent",
    name="coordinator_agent",
    model_id="claude-opus-5",
)
INPUT_AGENT = AgentModelSpec(
    id="input_agent",
    name="input_agent",
    model_id="claude-sonnet-5",
)
EFFECT_AGENT = AgentModelSpec(
    id="effect_agent",
    name="effect_agent",
    model_id="claude-sonnet-5",
)
SEMANTIC_BRIDGE_AGENT = AgentModelSpec(
    id="semantic_bridge_agent",
    name="semantic_bridge_agent",
    model_id="claude-sonnet-5",
)

SPECIALIST_AGENT_REGISTRY = MappingProxyType({
    SpecialistRole.INPUT: INPUT_AGENT,
    SpecialistRole.EFFECT: EFFECT_AGENT,
    SpecialistRole.BRIDGE: SEMANTIC_BRIDGE_AGENT,
})

M8_AGENT_REGISTRY = MappingProxyType({
    item.id: item
    for item in (
        COORDINATOR_AGENT,
        INPUT_AGENT,
        EFFECT_AGENT,
        SEMANTIC_BRIDGE_AGENT,
    )
})

if len(M8_AGENT_REGISTRY) != 4:
    raise ValueError("M8 agent identities must be unique")
