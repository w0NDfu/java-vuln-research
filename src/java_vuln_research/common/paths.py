from __future__ import annotations

from pathlib import PurePosixPath
from urllib.parse import unquote, urlparse


def normalise_program_path(value: str) -> str:
    """Canonicalise SARIF URIs, absolute paths, and repository-relative paths."""

    text = unquote(str(value).strip()).replace("\\", "/")
    if text.lower().startswith("file:"):
        parsed = urlparse(text)
        text = parsed.path or parsed.netloc
        if parsed.netloc and parsed.path:
            text = f"/{parsed.netloc}{parsed.path}"
    while text.startswith("./"):
        text = text[2:]
    parts = [part for part in PurePosixPath(text).parts if part not in {"/", "", "."}]
    collapsed: list[str] = []
    for part in parts:
        if part == ".." and collapsed:
            collapsed.pop()
        elif part != "..":
            collapsed.append(part)
    return "/".join(collapsed).casefold()


def same_program_file(left: str, right: str) -> bool:
    left_path, right_path = normalise_program_path(left), normalise_program_path(right)
    return bool(left_path and right_path) and (
        left_path == right_path
        or left_path.endswith("/" + right_path)
        or right_path.endswith("/" + left_path)
    )
