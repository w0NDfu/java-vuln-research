"""Independent post-detector evaluation boundary.

Detector modules must never import this package.
"""

from .p0a import P0AEvaluationError, evaluate_p0a
from .coverage import CandidateCoverageError, evaluate_candidate_coverage

__all__ = [
    "CandidateCoverageError",
    "P0AEvaluationError",
    "evaluate_candidate_coverage",
    "evaluate_p0a",
]
