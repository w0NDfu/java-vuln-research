"""Conservative per-character checks for a documented HTML script-data boundary."""
from __future__ import annotations

import ast
import operator

_COMMENTS = {"line_comment", "block_comment"}
_COMPARISONS = {
    "<": operator.lt, "<=": operator.le, ">": operator.gt, ">=": operator.ge,
    "==": operator.eq, "!=": operator.ne,
}
# Separate symbol classes needed by the WHATWG script-data state transitions.
# These are checked individually; they are never assembled into input or run.
_SCRIPT_STATE_SYMBOLS = {
    "comment_escape_open": frozenset("<!-"),
    "double_escape_start": frozenset("<scriptSCRIPT>"),
}
_SCRIPT_STATE_REFERENCE = "https://html.spec.whatwg.org/multipage/parsing.html#script-data-double-escape-start-state"


def _text(node):
    return node.text.decode("utf-8") if node is not None else ""


def _statements(node):
    return [child for child in node.named_children if child.type not in _COMMENTS]


def _literal(node):
    if node is None:
        return None
    if node.type == "character_literal":
        try:
            value = ast.literal_eval(_text(node))
        except (ValueError, SyntaxError):
            return None
        return ord(value) if isinstance(value, str) and len(value) == 1 else None
    if node.type in {"decimal_integer_literal", "hex_integer_literal"}:
        value = _text(node).replace("_", "")
        return int(value, 16 if node.type == "hex_integer_literal" else 10)
    return None


def _expression(node, variable, value):
    if node is None:
        return None
    if node.type == "parenthesized_expression" and len(node.named_children) == 1:
        return _expression(node.named_children[0], variable, value)
    if node.type == "identifier":
        return value if _text(node) == variable else None
    if node.type == "binary_expression":
        op = _text(node.child_by_field_name("operator"))
        left = _expression(node.child_by_field_name("left"), variable, value)
        if (op == "&&" and left is False) or (op == "||" and left is True):
            return left
        right = _expression(node.child_by_field_name("right"), variable, value)
        if op in _COMPARISONS and type(left) is int and type(right) is int:
            return _COMPARISONS[op](left, right)
        if op in {"&&", "||"} and type(left) is bool and type(right) is bool:
            return left and right if op == "&&" else left or right
        return None
    return _literal(node)


def _unchanged_continue(statements, variable, value):
    """A line number proves the chosen path reaches a bare continue before any effect."""
    for stmt in statements:
        if stmt.type == "continue_statement" and not stmt.named_children:
            return stmt.start_point.row + 1
        if stmt.type != "if_statement":
            return None
        branch = _expression(stmt.child_by_field_name("condition"), variable, value)
        if type(branch) is not bool:
            return None
        target = stmt.child_by_field_name("consequence" if branch else "alternative")
        if target is not None:
            return _unchanged_continue(_statements(target) if target.type == "block" else [target], variable, value)
    return None


def audit_script_dispatch(declaration):
    """Find a local pass-through branch in a narrow charAt/switch loop shape."""
    body = declaration.child_by_field_name("body")
    if body is None:
        return None
    for loop in _statements(body):
        loop_body = loop.child_by_field_name("body") if loop.type == "for_statement" else None
        if loop_body is None or loop_body.type != "block":
            continue
        statements = _statements(loop_body)
        if len(statements) != 2:
            continue
        bind, switch = statements
        if bind.type != "local_variable_declaration" or switch.type != "switch_expression":
            continue
        variables = [n for n in bind.named_children if n.type == "variable_declarator"]
        if len(variables) != 1 or _text(bind.child_by_field_name("type")) != "char":
            continue
        variable = _text(variables[0].child_by_field_name("name"))
        read = variables[0].child_by_field_name("value")
        selector = switch.child_by_field_name("condition")
        if (read is None or read.type != "method_invocation" or _text(read.child_by_field_name("name")) != "charAt"
            or selector is None or len(selector.named_children) != 1 or _text(selector.named_children[0]) != variable):
            continue
        args = read.child_by_field_name("arguments")
        if args is None or len(args.named_children) != 1 or args.named_children[0].type != "identifier":
            continue
        index = _text(args.named_children[0])
        if _text(loop.child_by_field_name("update")) not in {f"++{index}", f"{index}++"}:
            continue

        groups = _statements(switch.child_by_field_name("body"))
        if any(group.type != "switch_block_statement_group" for group in groups):
            continue
        explicit = set()
        default = None
        default_line = None
        for group in groups:
            children = _statements(group)
            for label in (n for n in children if n.type == "switch_label"):
                if _text(label) == "default":
                    default_line = label.start_point.row + 1
                    default = [n for n in children if n.type != "switch_label"]
                else:
                    value = _literal(label.named_children[0]) if len(label.named_children) == 1 else None
                    if value is None:
                        return None
                    explicit.add(value)
        if default is None:
            continue
        lines = {}
        for name, chars in _SCRIPT_STATE_SYMBOLS.items():
            paths = [_unchanged_continue(default, variable, ord(char)) for char in sorted(chars)
                     if ord(char) not in explicit]
            if len(paths) == len(chars) and all(path is not None for path in paths):
                lines[name] = sorted(set(paths))
        return {
            "rule": "HTML_SCRIPT_DATA_LOCAL_PASSTHROUGH",
            "standard": _SCRIPT_STATE_REFERENCE,
            "html_parser_semantics": (
                "Comment-like syntax can enter escaped script data, then the script-name transition can "
                "enter double-escaped script data. In that state the next matching script end tag is emitted "
                "as characters and returns to the escaped state."
            ),
            "character_read_line": read.start_point.row + 1,
            "switch_line": switch.start_point.row + 1, "default_line": default_line,
            "locally_unmodified_state_symbols": lines,
            "result": "LOCAL_GAP" if lines else "NO_LOCAL_GAP_PROVED",
        }
    return None
