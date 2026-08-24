from __future__ import annotations

import ast
from pathlib import Path


def test_detector_modules_do_not_import_evaluation() -> None:
    package = Path(__file__).parents[2] / "src" / "java_vuln_research"
    detector_paths = [
        package / "baseline.py",
        package / "discovery",
        package / "frontier",
        package / "semantics",
        package / "llm",
        package / "validator",
        package / "vulnerability",
    ]
    violations: list[str] = []
    for detector_path in detector_paths:
        files = [detector_path] if detector_path.is_file() else detector_path.rglob("*.py")
        for file_path in files:
            tree = ast.parse(file_path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                module = None
                if isinstance(node, ast.ImportFrom):
                    module = node.module
                elif isinstance(node, ast.Import):
                    module = ",".join(alias.name for alias in node.names)
                if module and "evaluation" in module:
                    violations.append(str(file_path))
    assert not violations

