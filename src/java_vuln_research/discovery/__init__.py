"""Deterministic external-input and security-effect discovery."""

from .runner import (
    DiscoveryError,
    deduplicate_candidates,
    external_candidate,
    run_p0a_discovery,
    security_effect_candidate,
)

__all__ = [
    "DiscoveryError",
    "deduplicate_candidates",
    "external_candidate",
    "run_p0a_discovery",
    "security_effect_candidate",
]

