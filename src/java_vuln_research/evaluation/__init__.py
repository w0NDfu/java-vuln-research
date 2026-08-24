"""Independent post-detector evaluation boundary.

Detector modules must never import this package.
"""

from .p0a import P0AEvaluationError, evaluate_p0a

__all__ = ["P0AEvaluationError", "evaluate_p0a"]
