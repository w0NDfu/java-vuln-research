"""Frozen, role-specific M8 prompt contracts."""

from .bridge_agent import PROMPT_VERSION as BRIDGE_PROMPT_VERSION
from .bridge_agent import SYSTEM_PROMPT as BRIDGE_SYSTEM_PROMPT
from .common import prompt_sha256
from .effect_agent import PROMPT_VERSION as EFFECT_PROMPT_VERSION
from .effect_agent import SYSTEM_PROMPT as EFFECT_SYSTEM_PROMPT
from .input_agent import PROMPT_VERSION as INPUT_PROMPT_VERSION
from .input_agent import SYSTEM_PROMPT as INPUT_SYSTEM_PROMPT

__all__ = [
    "BRIDGE_PROMPT_VERSION",
    "BRIDGE_SYSTEM_PROMPT",
    "EFFECT_PROMPT_VERSION",
    "EFFECT_SYSTEM_PROMPT",
    "INPUT_PROMPT_VERSION",
    "INPUT_SYSTEM_PROMPT",
    "prompt_sha256",
]
