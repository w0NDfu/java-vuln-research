from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .evidence import EvidenceRef
from .model import SecurityProposal, canonical_json


def write_jsonl(path: str | Path, values: Iterable[Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for value in values:
        encoded = value.to_dict() if hasattr(value, "to_dict") else value
        rows.append(canonical_json(encoded))
    target.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8", newline="\n")


def read_proposals(path: str | Path) -> list[SecurityProposal]:
    return [SecurityProposal.from_dict(json.loads(line)) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def read_evidence(path: str | Path) -> list[EvidenceRef]:
    return [EvidenceRef.from_dict(json.loads(line)) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]


def stable_json(value: Mapping[str, Any]) -> str:
    return canonical_json(value)
