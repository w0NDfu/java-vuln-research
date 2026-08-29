from __future__ import annotations

import argparse
import json
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence

from .entity import (
    ENTITY_SCHEMA_VERSION,
    ExtractionConfidence,
    ProgramEntity,
    ProgramEntityKind,
    normalise_repository_path,
)


EXTRACTOR_NAME = "JAVA_CONSERVATIVE_LEXICAL_V1"
DEFAULT_EXCLUDED_DIRECTORIES = (
    ".git",
    ".gradle",
    ".idea",
    "build",
    "node_modules",
    "out",
    "target",
)
TYPE_KEYWORDS = frozenset({"class", "interface", "enum", "record"})
MODIFIERS = frozenset(
    {
        "public",
        "protected",
        "private",
        "abstract",
        "static",
        "final",
        "strictfp",
        "synchronized",
        "native",
        "transient",
        "volatile",
        "default",
        "sealed",
        "non",
        "final",
    }
)
CONTROL_NAMES = frozenset(
    {
        "if",
        "for",
        "while",
        "switch",
        "catch",
        "try",
        "do",
        "else",
        "return",
        "throw",
        "throws",
        "assert",
        "new",
        "case",
        "super",
        "this",
    }
)
NON_FIELD_PREFIXES = frozenset(
    {
        "package",
        "import",
        "return",
        "throw",
        "break",
        "continue",
        "assert",
        "case",
    }
)
TOKEN_RE = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*|\d+(?:\.\d+)?|\.\.\.|::|->|==|!=|<=|>=|&&|\|\||[{}()\[\]<>@,;.=?:&|!~+\-*/%]"
)
IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


@dataclass(frozen=True, slots=True)
class IndexDiagnostic:
    severity: str
    error_class: str
    repository_relative_path: str
    line: int | None
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "error_class": self.error_class,
            "repository_relative_path": self.repository_relative_path,
            "line": self.line,
            "message": self.message,
        }


@dataclass(frozen=True, slots=True)
class _Token:
    text: str
    start: int
    end: int
    line: int
    column: int


@dataclass(slots=True)
class _TypeDecl:
    keyword: str
    name: str
    keyword_index: int
    start_index: int
    open_index: int
    close_index: int
    body_depth: int
    qualified_name: str = ""
    enclosing_type: str | None = None
    confidence: ExtractionConfidence = ExtractionConfidence.HIGH


@dataclass(slots=True)
class _ParameterDecl:
    name: str
    type_text: str
    start_index: int
    end_index: int
    parameter_index: int


@dataclass(slots=True)
class _CallableDecl:
    kind: ProgramEntityKind
    name: str
    start_index: int
    name_index: int
    paren_index: int
    paren_close_index: int
    terminator_index: int
    body_open_index: int | None
    body_close_index: int | None
    enclosing_type: _TypeDecl
    parameters: list[_ParameterDecl] = field(default_factory=list)
    return_type: str | None = None
    signature: str = ""
    qualified_name: str = ""
    confidence: ExtractionConfidence = ExtractionConfidence.HIGH


@dataclass(slots=True)
class RepositoryIndex:
    repository_root: Path
    entities: list[ProgramEntity]
    diagnostics: list[IndexDiagnostic]
    java_file_count: int
    wall_clock_seconds: float
    excluded_directories: tuple[str, ...] = DEFAULT_EXCLUDED_DIRECTORIES

    def sorted_entities(self) -> list[ProgramEntity]:
        return sorted(
            self.entities,
            key=lambda item: (
                item.repository_relative_path,
                item.start_line,
                item.end_line,
                item.kind.value,
                item.qualified_name,
                item.signature or "",
                item.entity_id,
            ),
        )

    def to_jsonl_text(self) -> str:
        rows = [entity.to_json() for entity in self.sorted_entities()]
        return "\n".join(rows) + ("\n" if rows else "")

    def write_jsonl(self, output_path: str | Path) -> None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.to_jsonl_text(), encoding="utf-8", newline="\n")

    def write_diagnostics(self, output_path: str | Path) -> None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        rows = [
            json.dumps(row.to_dict(), ensure_ascii=False, sort_keys=True)
            for row in self.diagnostics
        ]
        target.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8", newline="\n")

    def summary(self) -> dict[str, Any]:
        kind_counts = Counter(entity.kind.value for entity in self.entities)
        confidence_counts = Counter(entity.extraction_confidence.value for entity in self.entities)
        diagnostic_counts = Counter(row.severity for row in self.diagnostics)
        return {
            "schema_version": ENTITY_SCHEMA_VERSION,
            "extractor": EXTRACTOR_NAME,
            "java_file_count": self.java_file_count,
            "program_entity_count": len(self.entities),
            "entity_kind_counts": dict(sorted(kind_counts.items())),
            "extraction_confidence_counts": dict(sorted(confidence_counts.items())),
            "errors": diagnostic_counts.get("ERROR", 0),
            "warnings": diagnostic_counts.get("WARNING", 0),
            "low_confidence_count": confidence_counts.get("LOW", 0),
            "unknown_confidence_count": confidence_counts.get("UNKNOWN", 0),
            "wall_clock_seconds": round(self.wall_clock_seconds, 6),
            "excluded_directories": list(self.excluded_directories),
        }

    def write_summary(self, output_path: str | Path) -> None:
        target = Path(output_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.summary(), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )


def _mask_non_code(source: str) -> str:
    chars = list(source)
    state = "CODE"
    index = 0
    while index < len(chars):
        current = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        third = chars[index + 2] if index + 2 < len(chars) else ""
        if state == "CODE":
            if current == "/" and following == "/":
                chars[index] = chars[index + 1] = " "
                state = "LINE_COMMENT"
                index += 2
                continue
            if current == "/" and following == "*":
                chars[index] = chars[index + 1] = " "
                state = "BLOCK_COMMENT"
                index += 2
                continue
            if current == '"' and following == '"' and third == '"':
                chars[index] = chars[index + 1] = chars[index + 2] = " "
                state = "TEXT_BLOCK"
                index += 3
                continue
            if current == '"':
                chars[index] = " "
                state = "STRING"
                index += 1
                continue
            if current == "'":
                chars[index] = " "
                state = "CHAR"
                index += 1
                continue
        elif state == "LINE_COMMENT":
            if current == "\n":
                state = "CODE"
            else:
                chars[index] = " "
            index += 1
            continue
        elif state == "BLOCK_COMMENT":
            if current == "*" and following == "/":
                chars[index] = chars[index + 1] = " "
                state = "CODE"
                index += 2
                continue
            if current != "\n":
                chars[index] = " "
            index += 1
            continue
        elif state in {"STRING", "CHAR"}:
            closing = '"' if state == "STRING" else "'"
            if current == "\\":
                chars[index] = " "
                if index + 1 < len(chars) and chars[index + 1] != "\n":
                    chars[index + 1] = " "
                index += 2
                continue
            if current == closing:
                chars[index] = " "
                state = "CODE"
                index += 1
                continue
            if current != "\n":
                chars[index] = " "
            index += 1
            continue
        elif state == "TEXT_BLOCK":
            if current == '"' and following == '"' and third == '"':
                chars[index] = chars[index + 1] = chars[index + 2] = " "
                state = "CODE"
                index += 3
                continue
            if current != "\n":
                chars[index] = " "
            index += 1
            continue
        index += 1
    return "".join(chars)


def _tokens(masked: str) -> list[_Token]:
    result: list[_Token] = []
    line = 1
    line_start = 0
    for match in TOKEN_RE.finditer(masked):
        preceding = masked[line_start : match.start()]
        newlines = preceding.count("\n")
        if newlines:
            line += newlines
            line_start = masked.rfind("\n", line_start, match.start()) + 1
        result.append(
            _Token(
                text=match.group(0),
                start=match.start(),
                end=match.end(),
                line=line,
                column=match.start() - line_start + 1,
            )
        )
    return result


def _pair_map(tokens: Sequence[_Token], opening: str, closing: str) -> tuple[dict[int, int], list[int]]:
    stack: list[int] = []
    pairs: dict[int, int] = {}
    unmatched: list[int] = []
    for index, token in enumerate(tokens):
        if token.text == opening:
            stack.append(index)
        elif token.text == closing:
            if stack:
                start = stack.pop()
                pairs[start] = index
            else:
                unmatched.append(index)
    unmatched.extend(stack)
    return pairs, unmatched


def _brace_depths(tokens: Sequence[_Token]) -> list[int]:
    depth = 0
    result: list[int] = []
    for token in tokens:
        if token.text == "}":
            depth = max(0, depth - 1)
        result.append(depth)
        if token.text == "{":
            depth += 1
    return result


def _is_identifier(token: _Token | None) -> bool:
    return token is not None and bool(IDENTIFIER_RE.match(token.text))


def _normalise_tokens(tokens: Iterable[_Token]) -> str:
    text = " ".join(token.text for token in tokens).strip()
    text = re.sub(r"\s*([.<>,\[\]&?])\s*", r"\1", text)
    text = re.sub(r"\s*\.\.\.\s*", "...", text)
    return re.sub(r"\s+", " ", text)


def _declaration_start(tokens: Sequence[_Token], index: int, depths: Sequence[int], boundary_depth: int) -> int:
    cursor = index - 1
    while cursor >= 0:
        if tokens[cursor].text in {";", "{", "}"} and depths[cursor] <= boundary_depth:
            return cursor + 1
        cursor -= 1
    return 0


def _skip_annotation(tokens: Sequence[_Token], start: int, limit: int) -> int:
    cursor = start + 1
    if cursor < limit and _is_identifier(tokens[cursor]):
        cursor += 1
        while (
            cursor + 1 < limit
            and tokens[cursor].text == "."
            and _is_identifier(tokens[cursor + 1])
        ):
            cursor += 2
    if cursor < limit and tokens[cursor].text == "(":
        depth = 0
        while cursor < limit:
            depth += tokens[cursor].text == "("
            depth -= tokens[cursor].text == ")"
            cursor += 1
            if depth == 0:
                break
    return cursor


def _strip_declaration_prefix(tokens: Sequence[_Token], parens: dict[int, int]) -> list[_Token]:
    cursor = 0
    while cursor < len(tokens):
        if tokens[cursor].text in MODIFIERS:
            cursor += 1
            continue
        if tokens[cursor].text == "@":
            cursor = _skip_annotation(tokens, cursor, len(tokens))
            continue
        break
    return list(tokens[cursor:])


def _package_name(tokens: Sequence[_Token]) -> tuple[str | None, int | None, int | None]:
    for index, token in enumerate(tokens):
        if token.text != "package":
            continue
        parts: list[str] = []
        cursor = index + 1
        while cursor < len(tokens) and tokens[cursor].text != ";":
            if _is_identifier(tokens[cursor]):
                parts.append(tokens[cursor].text)
            cursor += 1
        if parts and cursor < len(tokens):
            return ".".join(parts), token.line, tokens[cursor].line
    return None, None, None


def _discover_types(
    tokens: Sequence[_Token],
    braces: dict[int, int],
    depths: Sequence[int],
    package_name: str | None,
) -> list[_TypeDecl]:
    result: list[_TypeDecl] = []
    for index, token in enumerate(tokens):
        if token.text not in TYPE_KEYWORDS:
            continue
        name_index = index + 1
        if name_index >= len(tokens) or not _is_identifier(tokens[name_index]):
            continue
        cursor = name_index + 1
        open_index: int | None = None
        while cursor < len(tokens):
            if tokens[cursor].text == ";":
                break
            if tokens[cursor].text == "{":
                open_index = cursor
                break
            cursor += 1
        if open_index is None:
            continue
        close_index = braces.get(open_index, len(tokens) - 1)
        parent = next(
            (
                item
                for item in reversed(result)
                if item.open_index < index <= item.close_index
            ),
            None,
        )
        name = tokens[name_index].text
        enclosing = parent.qualified_name if parent else None
        qualified = f"{enclosing}.{name}" if enclosing else f"{package_name}.{name}" if package_name else name
        start = _declaration_start(tokens, index, depths, depths[open_index])
        result.append(
            _TypeDecl(
                keyword=token.text,
                name=name,
                keyword_index=index,
                start_index=start,
                open_index=open_index,
                close_index=close_index,
                body_depth=depths[open_index] + 1,
                qualified_name=qualified,
                enclosing_type=enclosing,
                confidence=(
                    ExtractionConfidence.HIGH
                    if open_index in braces
                    else ExtractionConfidence.LOW
                ),
            )
        )
    return result


def _split_parameter_ranges(
    tokens: Sequence[_Token], start: int, end: int
) -> list[tuple[int, int]]:
    if start >= end:
        return []
    ranges: list[tuple[int, int]] = []
    segment_start = start
    angle = square = paren = 0
    for index in range(start, end):
        text = tokens[index].text
        if text == "<":
            angle += 1
        elif text == ">":
            angle = max(0, angle - 1)
        elif text == "[":
            square += 1
        elif text == "]":
            square = max(0, square - 1)
        elif text == "(":
            paren += 1
        elif text == ")":
            paren = max(0, paren - 1)
        elif text == "," and angle == square == paren == 0:
            ranges.append((segment_start, index))
            segment_start = index + 1
    ranges.append((segment_start, end))
    return [(left, right) for left, right in ranges if left < right]


def _parameter_decls(
    tokens: Sequence[_Token],
    parens: dict[int, int],
    open_index: int,
    close_index: int,
) -> list[_ParameterDecl]:
    result: list[_ParameterDecl] = []
    for parameter_index, (start, end) in enumerate(
        _split_parameter_ranges(tokens, open_index + 1, close_index)
    ):
        segment = list(tokens[start:end])
        stripped = _strip_declaration_prefix(segment, parens)
        name_position = next(
            (
                index
                for index in range(len(stripped) - 1, -1, -1)
                if _is_identifier(stripped[index]) and stripped[index].text not in MODIFIERS
            ),
            None,
        )
        if name_position is None or name_position == 0:
            continue
        name = stripped[name_position].text
        type_tokens = [token for token in stripped[:name_position] if token.text != "final"]
        type_text = _normalise_tokens(type_tokens)
        if not type_text:
            continue
        result.append(
            _ParameterDecl(
                name=name,
                type_text=type_text,
                start_index=start,
                end_index=end - 1,
                parameter_index=parameter_index,
            )
        )
    return result


def _discover_callables(
    tokens: Sequence[_Token],
    types: Sequence[_TypeDecl],
    braces: dict[int, int],
    parens: dict[int, int],
    depths: Sequence[int],
) -> list[_CallableDecl]:
    result: list[_CallableDecl] = []
    for type_decl in types:
        for open_paren in range(type_decl.open_index + 1, type_decl.close_index):
            if tokens[open_paren].text != "(" or depths[open_paren] != type_decl.body_depth:
                continue
            close_paren = parens.get(open_paren)
            name_index = open_paren - 1
            if close_paren is None or name_index <= type_decl.open_index or not _is_identifier(tokens[name_index]):
                continue
            name = tokens[name_index].text
            if name in CONTROL_NAMES or (name_index > 0 and tokens[name_index - 1].text in {".", "new", "@"}):
                continue
            start_index = _declaration_start(tokens, name_index, depths, type_decl.body_depth)
            prefix = list(tokens[start_index:name_index])
            if any(token.text == "=" for token in prefix):
                continue
            stripped_prefix = _strip_declaration_prefix(prefix, parens)
            kind = ProgramEntityKind.CONSTRUCTOR if name == type_decl.name else ProgramEntityKind.METHOD
            if kind == ProgramEntityKind.METHOD and not stripped_prefix:
                continue
            cursor = close_paren + 1
            while cursor < type_decl.close_index and tokens[cursor].text not in {"{", ";", "="}:
                cursor += 1
            if cursor >= type_decl.close_index or tokens[cursor].text not in {"{", ";"}:
                continue
            body_open = cursor if tokens[cursor].text == "{" else None
            body_close = braces.get(body_open) if body_open is not None else None
            confidence = ExtractionConfidence.HIGH
            terminator = cursor
            if body_open is not None:
                if body_close is None:
                    body_close = type_decl.close_index
                    confidence = ExtractionConfidence.LOW
                terminator = body_close
            parameters = _parameter_decls(tokens, parens, open_paren, close_paren)
            signature = f"{name}({','.join(item.type_text for item in parameters)})"
            qualified = f"{type_decl.qualified_name}.{name}"
            return_type = None
            if kind == ProgramEntityKind.METHOD:
                return_tokens = stripped_prefix
                if return_tokens and return_tokens[0].text == "<":
                    level = 0
                    cut = 0
                    for cut, item in enumerate(return_tokens):
                        level += item.text == "<"
                        level -= item.text == ">"
                        if level == 0:
                            cut += 1
                            break
                    return_tokens = return_tokens[cut:]
                return_type = _normalise_tokens(return_tokens) or None
            result.append(
                _CallableDecl(
                    kind=kind,
                    name=name,
                    start_index=start_index,
                    name_index=name_index,
                    paren_index=open_paren,
                    paren_close_index=close_paren,
                    terminator_index=terminator,
                    body_open_index=body_open,
                    body_close_index=body_close,
                    enclosing_type=type_decl,
                    parameters=parameters,
                    return_type=return_type,
                    signature=signature,
                    qualified_name=qualified,
                    confidence=confidence,
                )
            )
    unique: dict[tuple[int, int], _CallableDecl] = {}
    for item in result:
        unique[(item.paren_index, item.terminator_index)] = item
    return sorted(unique.values(), key=lambda item: item.paren_index)


def _containing_callable(callables: Sequence[_CallableDecl], index: int) -> _CallableDecl | None:
    matches = [
        item
        for item in callables
        if item.body_open_index is not None
        and item.body_open_index < index <= (item.body_close_index or item.terminator_index)
    ]
    return min(matches, key=lambda item: item.terminator_index - (item.body_open_index or 0)) if matches else None


def _containing_type(types: Sequence[_TypeDecl], index: int) -> _TypeDecl | None:
    matches = [item for item in types if item.start_index <= index <= item.close_index]
    return min(matches, key=lambda item: item.close_index - item.start_index) if matches else None


def _field_entities(
    *,
    tokens: Sequence[_Token],
    types: Sequence[_TypeDecl],
    callables: Sequence[_CallableDecl],
    parens: dict[int, int],
    depths: Sequence[int],
    path: str,
) -> list[ProgramEntity]:
    result: list[ProgramEntity] = []
    callable_semicolons = {
        item.terminator_index
        for item in callables
        if item.body_open_index is None
    }
    for type_decl in types:
        for semicolon in range(type_decl.open_index + 1, type_decl.close_index):
            if tokens[semicolon].text != ";" or depths[semicolon] != type_decl.body_depth:
                continue
            if semicolon in callable_semicolons:
                continue
            start = _declaration_start(tokens, semicolon, depths, type_decl.body_depth)
            segment = list(tokens[start:semicolon])
            if not segment or segment[0].text in NON_FIELD_PREFIXES:
                continue
            if any(item.paren_index >= start and item.paren_index < semicolon for item in callables):
                continue
            stripped = _strip_declaration_prefix(segment, parens)
            if not stripped:
                continue
            angle = square = paren = 0
            first_equal = first_comma = len(stripped)
            for position, item in enumerate(stripped):
                if item.text == "<":
                    angle += 1
                elif item.text == ">":
                    angle = max(0, angle - 1)
                elif item.text == "[":
                    square += 1
                elif item.text == "]":
                    square = max(0, square - 1)
                elif item.text == "(":
                    paren += 1
                elif item.text == ")":
                    paren = max(0, paren - 1)
                elif item.text == "=" and angle == square == paren == 0:
                    first_equal = position
                    break
                elif item.text == "," and angle == square == paren == 0:
                    first_comma = position
                    break
            declaration_end = min(first_equal, first_comma)
            left = stripped[:declaration_end]
            name_position = next(
                (i for i in range(len(left) - 1, -1, -1) if _is_identifier(left[i])),
                None,
            )
            if name_position is None or name_position == 0:
                continue
            name = left[name_position].text
            type_text = _normalise_tokens(left[:name_position])
            if not type_text or type_text in CONTROL_NAMES:
                continue
            result.append(
                ProgramEntity.create(
                    kind=ProgramEntityKind.FIELD,
                    repository_relative_path=path,
                    start_line=tokens[start].line,
                    end_line=tokens[semicolon].line,
                    simple_name=name,
                    qualified_name=f"{type_decl.qualified_name}.{name}",
                    enclosing_type=type_decl.qualified_name,
                    signature=f"{name}:{type_text}",
                    type_text=type_text,
                    provenance={"extractor": EXTRACTOR_NAME, "declaration_kind": "FIELD"},
                    extraction_confidence=ExtractionConfidence.MEDIUM,
                    identity_discriminator=tokens[start + name_position].start if start + name_position < len(tokens) else tokens[start].start,
                )
            )
    return result


def _argument_count(tokens: Sequence[_Token], start: int, end: int) -> int:
    if start >= end:
        return 0
    return len(_split_parameter_ranges(tokens, start, end))


def _extract_entities(
    *,
    source: str,
    path: str,
    diagnostics: list[IndexDiagnostic],
) -> list[ProgramEntity]:
    masked = _mask_non_code(source)
    tokens = _tokens(masked)
    total_lines = max(1, source.count("\n") + 1)
    if not tokens:
        return []
    braces, unmatched_braces = _pair_map(tokens, "{", "}")
    parens, unmatched_parens = _pair_map(tokens, "(", ")")
    depths = _brace_depths(tokens)
    for index in unmatched_braces:
        diagnostics.append(
            IndexDiagnostic(
                severity="WARNING",
                error_class="UNMATCHED_BRACE",
                repository_relative_path=path,
                line=tokens[index].line,
                message="lexical scanner found an unmatched brace; affected ranges are low confidence",
            )
        )
    for index in unmatched_parens:
        diagnostics.append(
            IndexDiagnostic(
                severity="WARNING",
                error_class="UNMATCHED_PARENTHESIS",
                repository_relative_path=path,
                line=tokens[index].line,
                message="lexical scanner found an unmatched parenthesis",
            )
        )
    package_name, package_start, package_end = _package_name(tokens)
    entities: list[ProgramEntity] = []
    if package_name and package_start and package_end:
        entities.append(
            ProgramEntity.create(
                kind=ProgramEntityKind.PACKAGE,
                repository_relative_path=path,
                start_line=package_start,
                end_line=package_end,
                simple_name=package_name.rsplit(".", 1)[-1],
                qualified_name=package_name,
                signature=f"package {package_name}",
                provenance={"extractor": EXTRACTOR_NAME},
            )
        )
    types = _discover_types(tokens, braces, depths, package_name)
    callables = _discover_callables(tokens, types, braces, parens, depths)
    for item in types:
        header_tokens = tokens[item.keyword_index + 2 : item.open_index]
        relation_text = _normalise_tokens(header_tokens) or None
        entities.append(
            ProgramEntity.create(
                kind=ProgramEntityKind.TYPE,
                repository_relative_path=path,
                start_line=tokens[item.start_index].line,
                end_line=(tokens[item.close_index].line if item.close_index < len(tokens) else total_lines),
                simple_name=item.name,
                qualified_name=item.qualified_name,
                enclosing_type=item.enclosing_type,
                signature=f"{item.keyword} {item.name}",
                type_text=relation_text,
                provenance={
                    "extractor": EXTRACTOR_NAME,
                    "declaration_kind": item.keyword.upper(),
                    "structural_relations": relation_text,
                },
                extraction_confidence=item.confidence,
                identity_discriminator=tokens[item.keyword_index].start,
            )
        )
    for item in callables:
        end_index = item.body_close_index if item.body_close_index is not None else item.terminator_index
        callable_identity = f"{item.qualified_name}{item.signature[len(item.name):]}"
        entities.append(
            ProgramEntity.create(
                kind=item.kind,
                repository_relative_path=path,
                start_line=tokens[item.start_index].line,
                end_line=tokens[end_index].line,
                simple_name=item.name,
                qualified_name=item.qualified_name,
                enclosing_type=item.enclosing_type.qualified_name,
                signature=item.signature,
                type_text=(item.enclosing_type.qualified_name if item.kind == ProgramEntityKind.CONSTRUCTOR else item.return_type),
                provenance={
                    "extractor": EXTRACTOR_NAME,
                    "declaration_kind": item.kind.value,
                    "body_status": "DECLARATION_ONLY" if item.body_open_index is None else "BODY_PRESENT",
                },
                extraction_confidence=item.confidence,
                identity_discriminator=tokens[item.name_index].start,
            )
        )
        for parameter in item.parameters:
            entities.append(
                ProgramEntity.create(
                    kind=ProgramEntityKind.PARAMETER,
                    repository_relative_path=path,
                    start_line=tokens[parameter.start_index].line,
                    end_line=tokens[parameter.end_index].line,
                    simple_name=parameter.name,
                    qualified_name=f"{callable_identity}#{parameter.name}",
                    enclosing_type=item.enclosing_type.qualified_name,
                    enclosing_callable=callable_identity,
                    signature=f"{parameter.parameter_index}:{parameter.type_text}",
                    type_text=parameter.type_text,
                    provenance={
                        "extractor": EXTRACTOR_NAME,
                        "parameter_index": parameter.parameter_index,
                    },
                    extraction_confidence=item.confidence,
                    identity_discriminator=parameter.parameter_index,
                )
            )
    entities.extend(
        _field_entities(
            tokens=tokens,
            types=types,
            callables=callables,
            parens=parens,
            depths=depths,
            path=path,
        )
    )
    declaration_parens = {item.paren_index for item in callables}
    for open_paren, close_paren in sorted(parens.items()):
        if open_paren in declaration_parens:
            continue
        name_index = open_paren - 1
        if name_index < 0 or not _is_identifier(tokens[name_index]):
            continue
        name = tokens[name_index].text
        callable_decl = _containing_callable(callables, open_paren)
        if callable_decl is None or name in CONTROL_NAMES - {"this", "super"}:
            continue
        if name_index > 0 and tokens[name_index - 1].text == "@":
            continue
        invocation_kind = (
            "CONSTRUCTOR_CALL"
            if name_index > 0 and tokens[name_index - 1].text == "new"
            else "DELEGATING_CONSTRUCTOR_CALL"
            if name in {"this", "super"}
            else "METHOD_CALL"
        )
        callable_identity = f"{callable_decl.qualified_name}{callable_decl.signature[len(callable_decl.name):]}"
        arity = _argument_count(tokens, open_paren + 1, close_paren)
        entities.append(
            ProgramEntity.create(
                kind=ProgramEntityKind.CALL,
                repository_relative_path=path,
                start_line=tokens[name_index].line,
                end_line=tokens[close_paren].line,
                simple_name=name,
                qualified_name=f"{callable_identity}::{name}",
                enclosing_type=callable_decl.enclosing_type.qualified_name,
                enclosing_callable=callable_identity,
                signature=f"{name}/{arity}",
                provenance={
                    "extractor": EXTRACTOR_NAME,
                    "invocation_kind": invocation_kind,
                    "argument_count": arity,
                    "start_column": tokens[name_index].column,
                },
                extraction_confidence=ExtractionConfidence.MEDIUM,
                identity_discriminator=tokens[name_index].start,
            )
        )
    for index, token in enumerate(tokens):
        if token.text != "@" or index + 1 >= len(tokens) or not _is_identifier(tokens[index + 1]):
            continue
        if tokens[index + 1].text == "interface":
            continue
        cursor = index + 1
        name_parts: list[str] = []
        if cursor < len(tokens) and _is_identifier(tokens[cursor]):
            name_parts.append(tokens[cursor].text)
            cursor += 1
            while (
                cursor + 1 < len(tokens)
                and tokens[cursor].text == "."
                and _is_identifier(tokens[cursor + 1])
            ):
                name_parts.append(tokens[cursor + 1].text)
                cursor += 2
        if not name_parts:
            continue
        end_index = cursor - 1
        if cursor < len(tokens) and tokens[cursor].text == "(" and cursor in parens:
            end_index = parens[cursor]
        annotation_name = ".".join(name_parts)
        callable_decl = _containing_callable(callables, index)
        type_decl = _containing_type(types, index)
        enclosing_type = (
            callable_decl.enclosing_type.qualified_name
            if callable_decl
            else type_decl.qualified_name
            if type_decl
            else None
        )
        enclosing_callable = None
        owner = package_name or path
        if callable_decl:
            enclosing_callable = f"{callable_decl.qualified_name}{callable_decl.signature[len(callable_decl.name):]}"
            owner = enclosing_callable
        elif type_decl:
            owner = type_decl.qualified_name
        entities.append(
            ProgramEntity.create(
                kind=ProgramEntityKind.ANNOTATION,
                repository_relative_path=path,
                start_line=token.line,
                end_line=tokens[end_index].line,
                simple_name=name_parts[-1],
                qualified_name=f"{owner}@{annotation_name}",
                enclosing_type=enclosing_type,
                enclosing_callable=enclosing_callable,
                signature=f"@{annotation_name}",
                provenance={"extractor": EXTRACTOR_NAME, "annotation_name": annotation_name},
                extraction_confidence=ExtractionConfidence.HIGH,
                identity_discriminator=token.start,
            )
        )
    by_id: dict[str, ProgramEntity] = {}
    for entity in entities:
        existing = by_id.get(entity.entity_id)
        if existing is not None and existing.to_dict() != entity.to_dict():
            diagnostics.append(
                IndexDiagnostic(
                    severity="WARNING",
                    error_class="ENTITY_ID_COLLISION",
                    repository_relative_path=path,
                    line=entity.start_line,
                    message=f"duplicate entity identity suppressed: {entity.entity_id}",
                )
            )
        by_id[entity.entity_id] = entity
    return list(by_id.values())


def build_repository_index(
    repository_root: str | Path,
    *,
    excluded_directories: Iterable[str] = DEFAULT_EXCLUDED_DIRECTORIES,
) -> RepositoryIndex:
    started = time.monotonic()
    root = Path(repository_root).resolve()
    if not root.is_dir():
        raise ValueError(f"repository root is not a directory: {root}")
    diagnostics: list[IndexDiagnostic] = []
    entities: list[ProgramEntity] = []
    resolved_exclusions = tuple(sorted({str(item) for item in excluded_directories if str(item)}))
    java_files: list[tuple[str, Path]] = []
    for source in root.rglob("*.java"):
        if not source.is_file():
            continue
        try:
            resolved = source.resolve()
            relative = resolved.relative_to(root)
        except ValueError:
            continue
        if any(part in resolved_exclusions for part in relative.parts[:-1]):
            continue
        path = normalise_repository_path(relative.as_posix())
        java_files.append((path, resolved))
    java_files.sort(key=lambda item: item[0])
    for path, source in java_files:
        try:
            raw = source.read_bytes()
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            diagnostics.append(
                IndexDiagnostic(
                    severity="ERROR",
                    error_class="UTF8_DECODE_ERROR",
                    repository_relative_path=path,
                    line=None,
                    message="Java source is not valid UTF-8 and was not indexed",
                )
            )
            continue
        except OSError as error:
            diagnostics.append(
                IndexDiagnostic(
                    severity="ERROR",
                    error_class="SOURCE_READ_ERROR",
                    repository_relative_path=path,
                    line=None,
                    message=str(error),
                )
            )
            continue
        total_lines = max(1, text.count("\n") + 1)
        entities.append(
            ProgramEntity.create(
                kind=ProgramEntityKind.FILE,
                repository_relative_path=path,
                start_line=1,
                end_line=total_lines,
                simple_name=Path(path).name,
                qualified_name=path,
                signature=path,
                provenance={
                    "extractor": EXTRACTOR_NAME,
                    "byte_count": len(raw),
                    "encoding": "utf-8",
                },
                extraction_confidence=ExtractionConfidence.HIGH,
            )
        )
        entities.extend(_extract_entities(source=text, path=path, diagnostics=diagnostics))
    by_id: dict[str, ProgramEntity] = {}
    for entity in entities:
        by_id.setdefault(entity.entity_id, entity)
    return RepositoryIndex(
        repository_root=root,
        entities=list(by_id.values()),
        diagnostics=diagnostics,
        java_file_count=len(java_files),
        wall_clock_seconds=time.monotonic() - started,
        excluded_directories=resolved_exclusions,
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a neutral Work1 V11 ProgramEntity JSONL index")
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--output", required=True, help="ProgramEntity JSONL output")
    parser.add_argument("--summary", required=True, help="summary JSON output")
    parser.add_argument("--diagnostics", required=True, help="diagnostics JSONL output")
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=None,
        help="directory name to exclude; repeat to replace the default exclusion set",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    index = build_repository_index(
        args.repository_root,
        excluded_directories=(args.exclude_dir if args.exclude_dir is not None else DEFAULT_EXCLUDED_DIRECTORIES),
    )
    index.write_jsonl(args.output)
    index.write_summary(args.summary)
    index.write_diagnostics(args.diagnostics)
    print(json.dumps(index.summary(), ensure_ascii=False, sort_keys=True))
    return 1 if index.summary()["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
