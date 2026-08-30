from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping


@dataclass(frozen=True, slots=True)
class AgentBudgetLimits:
    max_rounds_per_project: int = 15
    max_tool_calls_per_round: int = 4
    max_total_tool_calls_per_project: int = 40
    max_proposals_per_project: int = 10
    max_admissible_proposals_per_project: int = 8
    max_proposals_per_round: int = 1

    def __post_init__(self) -> None:
        ceilings = {
            "max_rounds_per_project": 100,
            "max_tool_calls_per_round": 20,
            "max_total_tool_calls_per_project": 500,
            "max_proposals_per_project": 100,
            "max_admissible_proposals_per_project": 100,
            "max_proposals_per_round": 1,
        }
        for name, ceiling in ceilings.items():
            value = int(getattr(self, name))
            if value < 1 or value > ceiling:
                raise ValueError(f"{name} must be between 1 and {ceiling}")
        if self.max_admissible_proposals_per_project > self.max_proposals_per_project:
            raise ValueError("admissible proposal budget cannot exceed proposal budget")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AgentBudgetLimits":
        return cls(**{name: int(raw) for name, raw in value.items()})

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


class BudgetExceeded(RuntimeError):
    def __init__(self, budget_name: str) -> None:
        super().__init__(f"budget exceeded: {budget_name}")
        self.budget_name = budget_name


@dataclass(slots=True)
class BudgetTracker:
    limits: AgentBudgetLimits
    current_round: int = 0
    tool_calls_total: int = 0
    tool_calls_current_round: int = 0
    model_calls: int = 0
    proposals_total: int = 0
    proposals_current_round: int = 0
    admissible_proposals: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    def begin_round(self) -> int:
        if self.current_round >= self.limits.max_rounds_per_project:
            raise BudgetExceeded("max_rounds_per_project")
        self.current_round += 1
        self.tool_calls_current_round = 0
        self.proposals_current_round = 0
        return self.current_round

    def record_tool_call(self) -> None:
        if self.tool_calls_current_round >= self.limits.max_tool_calls_per_round:
            raise BudgetExceeded("max_tool_calls_per_round")
        if self.tool_calls_total >= self.limits.max_total_tool_calls_per_project:
            raise BudgetExceeded("max_total_tool_calls_per_project")
        self.tool_calls_current_round += 1
        self.tool_calls_total += 1

    def record_model_call(self, *, input_tokens: int = 0, output_tokens: int = 0) -> None:
        if input_tokens < 0 or output_tokens < 0:
            raise ValueError("token counts must be non-negative")
        self.model_calls += 1
        self.input_tokens += int(input_tokens)
        self.output_tokens += int(output_tokens)

    def record_proposal(self) -> None:
        if self.proposals_current_round >= self.limits.max_proposals_per_round:
            raise BudgetExceeded("max_proposals_per_round")
        if self.proposals_total >= self.limits.max_proposals_per_project:
            raise BudgetExceeded("max_proposals_per_project")
        self.proposals_current_round += 1
        self.proposals_total += 1

    def record_admissible_proposal(self) -> None:
        if self.admissible_proposals >= self.limits.max_admissible_proposals_per_project:
            raise BudgetExceeded("max_admissible_proposals_per_project")
        self.admissible_proposals += 1

    @property
    def exhausted(self) -> bool:
        return (
            self.current_round >= self.limits.max_rounds_per_project
            or self.tool_calls_total >= self.limits.max_total_tool_calls_per_project
            or self.proposals_total >= self.limits.max_proposals_per_project
            or self.admissible_proposals >= self.limits.max_admissible_proposals_per_project
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "limits": self.limits.to_dict(),
            "usage": {
                "current_round": self.current_round,
                "tool_calls_total": self.tool_calls_total,
                "tool_calls_current_round": self.tool_calls_current_round,
                "model_calls": self.model_calls,
                "proposals_total": self.proposals_total,
                "proposals_current_round": self.proposals_current_round,
                "admissible_proposals": self.admissible_proposals,
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
            },
            "remaining": {
                "rounds": max(0, self.limits.max_rounds_per_project - self.current_round),
                "tool_calls_total": max(0, self.limits.max_total_tool_calls_per_project - self.tool_calls_total),
                "tool_calls_current_round": max(0, self.limits.max_tool_calls_per_round - self.tool_calls_current_round),
                "proposals": max(0, self.limits.max_proposals_per_project - self.proposals_total),
                "admissible_proposals": max(0, self.limits.max_admissible_proposals_per_project - self.admissible_proposals),
            },
            "exhausted": self.exhausted,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "BudgetTracker":
        usage = dict(value.get("usage") or {})
        return cls(limits=AgentBudgetLimits.from_dict(value["limits"]), **{name: int(raw) for name, raw in usage.items()})
