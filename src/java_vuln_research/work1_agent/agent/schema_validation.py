"""Dependency-free validator for the JSON-Schema vocabulary used by M7.

This is intentionally not a general JSON-Schema implementation.  Unsupported
keywords fail closed so a schema change cannot silently weaken runtime checks.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


_ANNOTATION_KEYWORDS = {"$schema", "$id", "$defs", "title", "description", "default"}
_SUPPORTED_KEYWORDS = _ANNOTATION_KEYWORDS | {
    "$ref",
    "type",
    "const",
    "enum",
    "required",
    "properties",
    "additionalProperties",
    "minProperties",
    "maxProperties",
    "items",
    "minItems",
    "maxItems",
    "uniqueItems",
    "minLength",
    "maxLength",
    "pattern",
    "minimum",
    "maximum",
    "oneOf",
    "anyOf",
    "allOf",
    "not",
    "if",
    "then",
    "else",
}


@dataclass(frozen=True, slots=True)
class SchemaValidationError(ValueError):
    path: tuple[str | int, ...]
    message: str

    def __str__(self) -> str:
        location = "$" + "".join(f"[{item}]" if isinstance(item, int) else f".{item}" for item in self.path)
        return f"{location}: {self.message}"


def _resolve_pointer(document: Mapping[str, Any], fragment: str) -> Mapping[str, Any]:
    current: Any = document
    if fragment in {"", "#"}:
        return document
    pointer = fragment[1:] if fragment.startswith("#") else fragment
    if not pointer.startswith("/"):
        raise SchemaValidationError((), f"unsupported JSON pointer: {fragment}")
    for token in pointer[1:].split("/"):
        key = token.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, Mapping) or key not in current:
            raise SchemaValidationError((), f"unresolved JSON pointer: {fragment}")
        current = current[key]
    if not isinstance(current, Mapping):
        raise SchemaValidationError((), f"JSON pointer does not select a schema: {fragment}")
    return current


def _type_matches(value: Any, expected: str) -> bool:
    return {
        "null": value is None,
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "string": isinstance(value, str),
        "array": isinstance(value, list),
        "object": isinstance(value, Mapping),
    }.get(expected, False)


def validate_json_schema(
    value: Any,
    schema: Mapping[str, Any],
    *,
    store: Mapping[str, Mapping[str, Any]] | None = None,
) -> None:
    documents = dict(store or {})

    def walk(instance: Any, node: Mapping[str, Any], path: tuple[str | int, ...], document: Mapping[str, Any]) -> None:
        unsupported = set(node) - _SUPPORTED_KEYWORDS
        if unsupported:
            raise SchemaValidationError(path, "unsupported schema keyword(s): " + ", ".join(sorted(unsupported)))
        if "$ref" in node:
            reference = str(node["$ref"])
            base, marker, fragment = reference.partition("#")
            target_document = document if not base else documents.get(base)
            if target_document is None:
                raise SchemaValidationError(path, f"unresolved external schema: {base}")
            target = _resolve_pointer(target_document, ("#" + fragment) if marker else "#")
            walk(instance, target, path, target_document)
            return

        expected_type = node.get("type")
        if expected_type is not None:
            allowed_types = [expected_type] if isinstance(expected_type, str) else list(expected_type)
            if not any(_type_matches(instance, str(item)) for item in allowed_types):
                raise SchemaValidationError(path, "expected type " + " or ".join(str(item) for item in allowed_types))
        if "const" in node and instance != node["const"]:
            raise SchemaValidationError(path, f"expected constant {node['const']!r}")
        if "enum" in node and instance not in node["enum"]:
            raise SchemaValidationError(path, "value is not in enum")

        for keyword in ("allOf",):
            for child in node.get(keyword, []):
                walk(instance, child, path, document)
        for keyword, minimum_matches, maximum_matches in (("anyOf", 1, None), ("oneOf", 1, 1)):
            if keyword in node:
                matches = 0
                for child in node[keyword]:
                    try:
                        walk(instance, child, path, document)
                        matches += 1
                    except SchemaValidationError:
                        pass
                if matches < minimum_matches or (maximum_matches is not None and matches > maximum_matches):
                    raise SchemaValidationError(path, f"{keyword} matched {matches} branches")
        if "not" in node:
            try:
                walk(instance, node["not"], path, document)
            except SchemaValidationError:
                pass
            else:
                raise SchemaValidationError(path, "not subschema matched")
        if "if" in node:
            try:
                walk(instance, node["if"], path, document)
                condition = True
            except SchemaValidationError:
                condition = False
            selected = node.get("then") if condition else node.get("else")
            if selected is not None:
                walk(instance, selected, path, document)

        if isinstance(instance, Mapping):
            required = node.get("required", [])
            missing = [str(item) for item in required if item not in instance]
            if missing:
                raise SchemaValidationError(path, "missing required properties: " + ", ".join(missing))
            properties = node.get("properties", {})
            for key, item in instance.items():
                if key in properties:
                    walk(item, properties[key], path + (str(key),), document)
                elif node.get("additionalProperties") is False:
                    raise SchemaValidationError(path + (str(key),), "additional property is forbidden")
                elif isinstance(node.get("additionalProperties"), Mapping):
                    walk(item, node["additionalProperties"], path + (str(key),), document)
            if len(instance) < int(node.get("minProperties", 0)):
                raise SchemaValidationError(path, "object has too few properties")
            if "maxProperties" in node and len(instance) > int(node["maxProperties"]):
                raise SchemaValidationError(path, "object has too many properties")
        if isinstance(instance, list):
            if len(instance) < int(node.get("minItems", 0)):
                raise SchemaValidationError(path, "array has too few items")
            if "maxItems" in node and len(instance) > int(node["maxItems"]):
                raise SchemaValidationError(path, "array has too many items")
            if node.get("uniqueItems"):
                encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in instance]
                if len(set(encoded)) != len(encoded):
                    raise SchemaValidationError(path, "array items must be unique")
            if isinstance(node.get("items"), Mapping):
                for index, item in enumerate(instance):
                    walk(item, node["items"], path + (index,), document)
        if isinstance(instance, str):
            if len(instance) < int(node.get("minLength", 0)):
                raise SchemaValidationError(path, "string is too short")
            if "maxLength" in node and len(instance) > int(node["maxLength"]):
                raise SchemaValidationError(path, "string is too long")
            if "pattern" in node and re.search(str(node["pattern"]), instance) is None:
                raise SchemaValidationError(path, "string does not match pattern")
        if isinstance(instance, (int, float)) and not isinstance(instance, bool):
            if "minimum" in node and instance < node["minimum"]:
                raise SchemaValidationError(path, "number is below minimum")
            if "maximum" in node and instance > node["maximum"]:
                raise SchemaValidationError(path, "number is above maximum")

    walk(value, schema, (), schema)
