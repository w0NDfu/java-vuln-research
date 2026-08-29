"""Compatibility imports for the Work1 V11 M3 CodeQL tool package.

New code should import from :mod:`java_vuln_research.work1_agent.codeql`.
"""

from .codeql import (
    CodeQLAnalysisTools,
    CodeQLExecutor,
    CodeQLToolResult,
    EntityMappingResult,
    EvidenceKind,
    FailureReason,
    MappingStatus,
    QuerySpec,
    ToolStatus,
    map_program_entity,
)

__all__ = [
    "CodeQLAnalysisTools",
    "CodeQLExecutor",
    "CodeQLToolResult",
    "EntityMappingResult",
    "EvidenceKind",
    "FailureReason",
    "MappingStatus",
    "QuerySpec",
    "ToolStatus",
    "map_program_entity",
]
