"""Neutral, CodeQL-independent repository facts for Work1 V11.

Operational modules are intentionally not imported eagerly: this keeps the
``python -m ...repository.indexer`` smoke-test entry point deterministic.
"""

from .entity import ExtractionConfidence, ProgramEntity, ProgramEntityKind

__all__ = ["ExtractionConfidence", "ProgramEntity", "ProgramEntityKind"]
