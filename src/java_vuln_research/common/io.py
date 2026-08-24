from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Any, Iterable, Mapping


class YamlSubsetError(ValueError):
    """Raised when input exceeds the intentionally small safe YAML subset."""


def _strip_comment(line: str) -> str:
    quote: str | None = None
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
            continue
        if character == "\\" and quote == '"':
            escaped = True
            continue
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
        elif character == "#" and quote is None and (index == 0 or line[index - 1].isspace()):
            return line[:index].rstrip()
    return line.rstrip()


def _split_mapping(text: str) -> tuple[str, str]:
    quote: str | None = None
    for index, character in enumerate(text):
        if character in {"'", '"'}:
            if quote is None:
                quote = character
            elif quote == character:
                quote = None
        elif character == ":" and quote is None:
            key = text[:index].strip()
            if not key:
                break
            return key, text[index + 1 :].strip()
    raise YamlSubsetError(f"expected key: value, got {text!r}")


def _scalar(text: str) -> Any:
    lowered = text.lower()
    if lowered in {"null", "~"}:
        return None
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if text in {"[]", "{}"}:
        return [] if text == "[]" else {}
    if text.startswith('"') or text.startswith("'"):
        if len(text) < 2 or text[-1] != text[0]:
            raise YamlSubsetError(f"unterminated quoted scalar: {text!r}")
        if text[0] == '"':
            return json.loads(text)
        return text[1:-1].replace("''", "'")
    if re.fullmatch(r"[-+]?\d+", text):
        return int(text)
    if re.fullmatch(r"[-+]?(?:\d+\.\d*|\d*\.\d+)(?:[eE][-+]?\d+)?", text):
        return float(text)
    return text


def _parse_yaml_subset(text: str) -> Any:
    tokens: list[tuple[int, str, int]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        if "\t" in raw_line[: len(raw_line) - len(raw_line.lstrip())]:
            raise YamlSubsetError(f"tabs are forbidden for indentation at line {line_number}")
        stripped_comment = _strip_comment(raw_line)
        if not stripped_comment.strip() or stripped_comment.lstrip().startswith("---"):
            continue
        indent = len(stripped_comment) - len(stripped_comment.lstrip(" "))
        tokens.append((indent, stripped_comment.strip(), line_number))
    if not tokens:
        return None

    def parse_block(index: int, indent: int) -> tuple[Any, int]:
        if index >= len(tokens) or tokens[index][0] != indent:
            line = tokens[index][2] if index < len(tokens) else "EOF"
            raise YamlSubsetError(f"invalid indentation near line {line}")
        is_list = tokens[index][1] == "-" or tokens[index][1].startswith("- ")
        container: Any = [] if is_list else {}
        while index < len(tokens):
            current_indent, content, line_number = tokens[index]
            if current_indent < indent:
                break
            if current_indent > indent:
                raise YamlSubsetError(f"unexpected indentation at line {line_number}")
            if is_list:
                if not (content == "-" or content.startswith("- ")):
                    break
                item_text = content[1:].strip()
                index += 1
                if not item_text:
                    if index >= len(tokens) or tokens[index][0] <= indent:
                        container.append(None)
                    else:
                        item, index = parse_block(index, tokens[index][0])
                        container.append(item)
                    continue
                try:
                    key, value_text = _split_mapping(item_text)
                except YamlSubsetError:
                    container.append(_scalar(item_text))
                    continue
                item_map: dict[str, Any] = {}
                if value_text:
                    item_map[key] = _scalar(value_text)
                elif index < len(tokens) and tokens[index][0] > indent:
                    item_map[key], index = parse_block(index, tokens[index][0])
                else:
                    item_map[key] = {}
                if index < len(tokens) and tokens[index][0] > indent:
                    continuation, index = parse_block(index, tokens[index][0])
                    if not isinstance(continuation, dict):
                        raise YamlSubsetError(
                            f"list mapping continuation must be a mapping at line {line_number}"
                        )
                    item_map.update(continuation)
                container.append(item_map)
            else:
                if content == "-" or content.startswith("- "):
                    break
                key, value_text = _split_mapping(content)
                index += 1
                if value_text:
                    container[key] = _scalar(value_text)
                elif index < len(tokens) and tokens[index][0] > indent:
                    container[key], index = parse_block(index, tokens[index][0])
                else:
                    container[key] = {}
        return container, index

    result, final_index = parse_block(0, tokens[0][0])
    if final_index != len(tokens):
        raise YamlSubsetError(f"unparsed YAML content at line {tokens[final_index][2]}")
    return result


def load_yaml(path: str | Path) -> Any:
    text = Path(path).read_text(encoding="utf-8")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return _parse_yaml_subset(text)


def write_json(path: str | Path, value: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def write_jsonl(path: str | Path, rows: Iterable[Mapping[str, Any]]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(dict(row), ensure_ascii=False) + "\n")


def read_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} must contain a JSON object")
            rows.append(value)
    return rows


def write_csv(
    path: str | Path,
    fieldnames: list[str],
    rows: Iterable[Mapping[str, Any]],
) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
