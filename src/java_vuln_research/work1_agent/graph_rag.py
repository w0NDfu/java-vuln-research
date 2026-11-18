"""Index CodeQL relations against Java ASTs in the model-visible snapshot."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import unquote

from .repository.entity import ProgramEntity, normalise_repository_path
from .script_contract import audit_script_dispatch

BACKGROUND_FANOUT = 8


class CodeQLGraphIndex:
    KINDS = {"CODEQL_CALL", "CODEQL_LOCAL_FLOW", "CODEQL_RETURN_SITE", "CODEQL_CFG",
             "CODEQL_VIRTUAL_DISPATCH", "CODEQL_FIELD_STATE", "CODEQL_DIRECT_CALL"}
    NAVIGATION_KINDS = {"CODEQL_CALL", "CODEQL_VIRTUAL_DISPATCH", "CODEQL_FIELD_STATE", "CODEQL_DIRECT_CALL"}
    OUTPUT_CONTEXT = re.compile(
        r"embed(?:ded|ding|dable).{0,100}(?:HTML|script|JavaScript)|"
        r"(?:HTML|script|JavaScript).{0,100}embed(?:ded|ding|dable)|"
        r"(?:safe|safely)\s+(?:to|for)\s+(?:embed|render)", re.IGNORECASE,
    )
    DOCUMENTED_RESULT = re.compile(r"@return[^\n]*(?:embed|safe|escap|saniti[sz])", re.IGNORECASE)

    def __init__(self, repo: Path, entities: list[ProgramEntity], csv_path: Path | None,
                 return_witness: Path | None = None, character_witness: Path | None = None,
                 shared_field: Path | None = None) -> None:
        from tree_sitter import Language, Parser
        import tree_sitter_java

        self.repo = repo.resolve()
        self.parser = Parser(Language(tree_sitter_java.language()))
        self.methods = defaultdict(list)
        self.entities = {entity.entity_id: entity for entity in entities}
        self.declarations = {}
        self.return_sites = defaultdict(list)
        self.callers = defaultdict(list)
        self.return_witnesses = defaultdict(list)
        self.character_witnesses = defaultdict(list)
        self.shared_fields = defaultdict(list)
        for entity in entities:
            if entity.kind.value in {"METHOD", "CONSTRUCTOR"}:
                self.methods[entity.repository_relative_path].append(entity)
        self.syntax = {}
        self.by_entity = defaultdict(list)
        self.navigation = defaultdict(dict)
        self.dispatch_sites = defaultdict(set)
        self.dispatch_fanout = defaultdict(set)
        self.field_pairs = defaultdict(set)
        self.constant_arguments = defaultdict(set)
        self.call_targets = {}
        self.receiver_value_calls = set()
        self.direct_edges = defaultdict(list)
        self.rows = 0
        self.mapped = 0
        self.skipped = 0
        self.sha256 = None
        if csv_path is None:
            return
        with csv_path.open("rb") as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("CodeQL relation export exceeds 16 MiB")
        self.sha256 = hashlib.sha256(raw).hexdigest()
        table = csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline=""))
        header = next(table, ())
        width = len(header)
        if width not in {7, 8}:
            raise ValueError("expected seven legacy or eight current RepositorySiteGraph columns")
        navigation = []
        for row in table:
            self.rows += 1
            if len(row) != width or row[0] not in self.KINDS | {"CODEQL_CONSTANT_ARGUMENT", "CODEQL_CALL_TARGET"}:
                raise ValueError("invalid CodeQL relation record")
            kind, left_path, left_line, left_col, right_path, right_line, right_col = row[:7]
            detail = row[7] if width == 8 else ""
            site = (normalise_repository_path(left_path), int(left_line), int(left_col))
            if kind in {"CODEQL_CONSTANT_ARGUMENT", "CODEQL_CALL_TARGET"}:
                if kind == "CODEQL_CONSTANT_ARGUMENT":
                    self.constant_arguments[site].add(int(detail))
                else:
                    self.call_targets[site] = detail
                self.mapped += 1
                continue
            if kind == "CODEQL_VIRTUAL_DISPATCH":
                self.dispatch_fanout[site].add((right_path, right_line, right_col))
            left = self._locate(left_path, int(left_line), int(left_col))
            right = self._locate(right_path, int(right_line), int(right_col))
            if left is None or right is None:
                self.skipped += 1
                continue
            relation = {"kind": kind, "from": left, "to": right, "artifact_sha256": self.sha256}
            self.mapped += 1
            if kind == "CODEQL_RETURN_SITE":
                if left["entity_id"] == right["entity_id"]:
                    self.return_sites[left["entity_id"]].append(right)
            if kind in {"CODEQL_CALL", "CODEQL_DIRECT_CALL"} and left["entity_id"] != right["entity_id"]:
                self.callers[right["entity_id"]].append(relation)
            if kind in self.NAVIGATION_KINDS and left["entity_id"] != right["entity_id"]:
                navigation.append((relation, site, detail))
            if kind == "CODEQL_VIRTUAL_DISPATCH":
                self.dispatch_sites[site].add(right["entity_id"])
            elif kind == "CODEQL_FIELD_STATE":
                self.field_pairs[detail or site].add((left["entity_id"], right["entity_id"]))
            elif kind == "CODEQL_DIRECT_CALL" and left["entity_id"] != right["entity_id"]:
                self.direct_edges[left["entity_id"]].append(relation)
            for key in dict.fromkeys((left["entity_id"], right["entity_id"])):
                self.by_entity[key].append(relation)
        for relation, site, detail in navigation:
            kind = relation["kind"]
            if kind == "CODEQL_FIELD_STATE":
                degree = len(self.field_pairs[detail or site])
            elif kind in {"CODEQL_CALL", "CODEQL_VIRTUAL_DISPATCH"}:
                degree = len(self.dispatch_fanout[site])
            else:
                degree = 0
            if degree > BACKGROUND_FANOUT:
                relation["background_only"] = True
            else:
                self.navigation[relation["from"]["entity_id"]].setdefault(relation["to"]["entity_id"], set()).add(kind)

        if return_witness is not None:
            for steps in self._read_witnesses(return_witness, "w0ndfu/library/public-string-return-witness"):
                sink = steps[-1]
                self.return_witnesses[(sink["entity_id"], sink["line"], sink["column"])].append(steps)
        if character_witness is not None:
            for steps in self._read_witnesses(character_witness, "w0ndfu/library/public-character-input"):
                sink = steps[-1]
                self.character_witnesses[(sink["entity_id"], sink["line"])].append(steps)

        if shared_field is not None:
            with shared_field.open("rb") as stream:
                raw = stream.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError("CodeQL shared-field witness exceeds 1 MiB")
            rows = csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline=""))
            if len(next(rows, ())) != 11:
                raise ValueError("Unexpected shared-field CSV header")
            for row in rows:
                entry_file, entry_line, process, returned, read_file, read, fallback_file, fallback, guard, branch, field = row
                if branch not in {"then", "else"}:
                    raise ValueError("Unexpected shared-field conditional branch")
                key = (normalise_repository_path(entry_file), int(returned), normalise_repository_path(read_file), int(read))
                self.shared_fields[key].append({
                    "entry_line": int(entry_line), "process_call_line": int(process), "return_line": int(returned),
                    "fallback_file": normalise_repository_path(fallback_file), "fallback_line": int(fallback),
                    "guard_line": int(guard), "branch": branch, "field": field,
                })

    def _read_witnesses(self, path: Path, rule_id: str):
        with path.open("rb") as stream:
            raw = stream.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError("CodeQL return witness exceeds 4 MiB")
        data = json.loads(raw)
        if data.get("version") != "2.1.0":
            raise ValueError("CodeQL return witness must be SARIF 2.1.0")
        for run in data["runs"]:
            if any(not item.get("executionSuccessful") for item in run.get("invocations", [])):
                raise ValueError("CodeQL return witness reports an unsuccessful execution")
            for result in run.get("results", []):
                if result.get("ruleId") != rule_id:
                    continue
                for flow in result.get("codeFlows", []):
                    for thread in flow.get("threadFlows", []):
                        steps = []
                        for step in thread.get("locations", []):
                            if "index" in step:
                                step = {**run["threadFlowLocations"][step["index"]], **step}
                            location = step.get("location", {}).get("physicalLocation", {})
                            uri = location.get("artifactLocation", {}).get("uri")
                            region = location.get("region", {})
                            point = (self._locate(unquote(uri), region["startLine"], region.get("startColumn", 1))
                                     if uri and "startLine" in region else None)
                            steps.append(point)
                        if len(steps) < 2 or steps[0] is None or steps[-1] is None:
                            continue
                        yield steps

    def _locate(self, name: str, line: int, column: int) -> dict | None:
        try:
            name = normalise_repository_path(name)
        except ValueError:
            return None
        if name not in self.methods or line < 1 or column < 1:
            return None
        if name not in self.syntax:
            path = (self.repo / name).resolve()
            if not path.is_relative_to(self.repo) or not path.is_file():
                return None
            raw = path.read_bytes()
            self.syntax[name] = self.parser.parse(raw), raw.decode("utf-8").splitlines()
        tree, lines = self.syntax[name]
        if tree.root_node.has_error or line > len(lines):
            return None
        utf16 = lines[line - 1].encode("utf-16-le")
        offset = (column - 1) * 2
        if offset > len(utf16):
            return None
        try:
            byte_col = len(utf16[:offset].decode("utf-16-le").encode("utf-8"))
        except UnicodeDecodeError:
            return None
        point = (line - 1, byte_col)
        node = tree.root_node.named_descendant_for_point_range(point, point)
        while node and node.type not in {"method_declaration", "constructor_declaration"}:
            node = node.parent
        if node is None:
            return None
        symbol = node.child_by_field_name("name")
        if symbol is None:
            return None
        matching = [entity for entity in self.methods[name] if entity.simple_name == symbol.text.decode()
                    and entity.start_line <= line <= entity.end_line
                    and entity.end_line == node.end_point.row + 1]
        if len(matching) != 1:
            return None
        self.declarations[matching[0].entity_id] = node
        return {"entity_id": matching[0].entity_id, "symbol": matching[0].simple_name,
                "file": name, "line": line, "column": column}

    def call_site(self, entity):
        """Bind the indexed call name to its Java AST and CodeQL call start."""
        file, line = entity.repository_relative_path, entity.start_line
        col = entity.provenance.get("start_column")
        if col is None:
            return None
        if file not in self.syntax:
            self._locate(file, line, 1)
        if file not in self.syntax:
            return None
        tree, lines = self.syntax[file]
        if not 1 <= line <= len(lines):
            return None
        point = (line - 1, len(lines[line - 1][:col - 1].encode("utf-8")))
        node = tree.root_node.named_descendant_for_point_range(point, point)
        while node is not None:
            if node.type in {"method_invocation", "object_creation_expression", "explicit_constructor_invocation"}:
                name = node.child_by_field_name("name") or node.child_by_field_name("type")
                if name is not None and name.start_point <= point < name.end_point:
                    row, byte_col = node.start_point
                    prefix = lines[row].encode("utf-8")[:byte_col].decode("utf-8")
                    return (file, row + 1, len(prefix.encode("utf-16-le")) // 2 + 1), node
            node = node.parent
        return None

    @staticmethod
    def _javadoc(declaration):
        previous = declaration.prev_named_sibling
        if previous is not None and previous.type == "block_comment" and previous.text.startswith(b"/**"):
            return previous
        return None

    def output_contract(self, entity_id: str) -> dict | None:
        entity = self.entities.get(entity_id)
        node = self.declarations.get(entity_id)
        if (entity is None or node is None or not entity.provenance.get("public")
            or not self.return_sites[entity_id]):
            return None
        own_doc = self._javadoc(node)
        if own_doc is None:
            return None
        owner = node.parent.parent
        class_doc = self._javadoc(owner)
        comments = [(own_doc, "method")]
        if class_doc is not None and self.DOCUMENTED_RESULT.search(own_doc.text.decode()):
            comments.append((class_doc, "enclosing_type"))
        for comment, scope in comments:
            lines = comment.text.decode().splitlines()
            match = self.OUTPUT_CONTEXT.search("\n".join(lines))
            if match is None:
                continue
            offset = "\n".join(lines)[:match.start()].count("\n")
            return {
                "scope": scope, "entity_id": entity_id,
                "start_line": comment.start_point.row + max(0, offset - 2) + 1,
                "end_line": comment.start_point.row + min(len(lines) - 1, offset + 2) + 1,
            }
        return None

    def script_dispatch(self, entity_id: str) -> dict | None:
        node = self.declarations.get(entity_id)
        return audit_script_dispatch(node) if node is not None else None

    def character_input_witness(self, entry: str, seed: str, line: int) -> dict | None:
        paths = [steps for steps in self.character_witnesses.get((seed, line), ())
                 if steps[0]["entity_id"] == entry]
        if not paths:
            return None
        steps = min(paths, key=len)
        parameter = steps[0]
        declaration = self.declarations[entry]
        formal_parameters = declaration.child_by_field_name("parameters")
        if formal_parameters is None:
            return None
        line = self.syntax[parameter["file"]][1][parameter["line"] - 1]
        offset = (parameter["column"] - 1) * 2
        column = len(line.encode("utf-16-le")[:offset].decode("utf-16-le").encode("utf-8"))
        point = (parameter["line"] - 1, column)
        for index, formal in enumerate(child for child in formal_parameters.named_children
                                       if child.type in {"formal_parameter", "spread_parameter"}):
            if formal.start_point <= point < formal.end_point:
                return {
                    "kind": "public_parameter_to_character_read",
                    "parameter": {**parameter, "index": index},
                    "character_read": steps[-1], "path_steps": len(steps),
                }
        return None

    def shared_field_return(self, entry: str, seed: str, read_line: int, return_line: int) -> dict | None:
        public = self.entities[entry]
        audited = self.entities[seed]
        key = (public.repository_relative_path, return_line, audited.repository_relative_path, read_line)
        matching = [row for row in self.shared_fields.get(key, ())
                    if public.start_line <= row["entry_line"] <= public.end_line]
        return matching[0] if len(matching) == 1 else None

    def output_state_windows(self, producer: str, processor: str, fallback_line: int) -> dict | None:
        """Find source windows that initialize and check the state used by a conditional return."""
        returned = self.declarations.get(producer)
        method = self.declarations.get(processor)
        if returned is None or method is None:
            return None

        def walk(node):
            yield node
            for child in node.named_children:
                yield from walk(child)

        field = None
        for node in walk(returned):
            if node.type != "ternary_expression" or not node.start_point.row + 1 <= fallback_line <= node.end_point.row + 1:
                continue
            condition = node.child_by_field_name("condition")
            if condition is None or condition.type != "binary_expression":
                continue
            left = condition.child_by_field_name("left")
            right = condition.child_by_field_name("right")
            if left is None or right is None:
                continue
            if left.type == "null_literal":
                left, right = right, left
            if right.type == "null_literal" and left.type in {"identifier", "field_access"}:
                field = left.text.decode().rsplit(".", 1)[-1]
                break
        body = method.child_by_field_name("body")
        if field is None or body is None:
            return None
        initialize = []
        checks = []
        for statement in body.named_children:
            if statement.type == "expression_statement":
                for item in statement.named_children:
                    if item.type != "assignment_expression":
                        continue
                    left = item.child_by_field_name("left")
                    right = item.child_by_field_name("right")
                    if (left is not None and right is not None and right.type == "null_literal"
                        and left.text.decode().rsplit(".", 1)[-1] == field):
                        initialize.append(item.start_point.row + 1)
            if statement.type == "if_statement":
                condition = statement.child_by_field_name("condition")
                if condition is not None and any(
                    item.type == "identifier" and item.text.decode() == field for item in walk(condition)
                ):
                    checks.append((condition.start_point.row + 1, condition.end_point.row + 1))
        if len(initialize) != 1 or not checks:
            return None
        return {"field": field, "initialize_line": initialize[0], "final_check": checks[-1]}

    def quoted_branch_windows(self, processor: str, seed: str, before: int) -> list[dict]:
        """Find the quoted-token branch and its statically resolved helpers."""
        method = self.declarations.get(processor)
        if method is None:
            return []
        edges = [edge for edge in self.by_entity[processor] if edge["kind"] == "CODEQL_CALL"
                 and edge["from"]["entity_id"] == processor]
        dispatches = [edge["from"]["line"] for edge in edges if edge["to"]["entity_id"] == seed]
        if not dispatches:
            return []
        pending = [method.child_by_field_name("body")]
        windows = []
        while pending:
            node = pending.pop()
            if node is None or node.start_point.row + 1 >= before:
                continue
            pending.extend(reversed(node.named_children))
            if node.type != "switch_block_statement_group":
                continue
            start, end = node.start_point.row + 1, node.end_point.row + 1
            if end - start >= 40 or not any(start <= line <= end for line in dispatches):
                continue
            labels = list(node.named_children)
            sibling = node.prev_named_sibling
            while sibling is not None and sibling.type == "switch_block_statement_group":
                if any(child.type not in {"switch_label", "line_comment", "block_comment"}
                       for child in sibling.named_children):
                    break
                labels.extend(sibling.named_children)
                start = sibling.start_point.row + 1
                sibling = sibling.prev_named_sibling
            if end - start >= 40 or not any(label.type == "switch_label" and any(
                child.type == "character_literal" and child.text == b"""'"'"""
                for child in label.named_children
            ) for label in labels):
                continue
            windows.append({"role": "quoted_token_branch", "entity_id": processor,
                            "start_line": start, "end_line": end})
            for edge in edges:
                target = edge["to"]["entity_id"]
                if target == seed or not start <= edge["from"]["line"] <= end:
                    continue
                helper = self.entities[target]
                if helper.end_line - helper.start_line >= 40:
                    return []
                windows.append({"role": "quoted_token_helper", "entity_id": target,
                                "start_line": helper.start_line, "end_line": helper.end_line})
            break
        return windows

    def implementation_window(self, entity_id: str) -> tuple[int, int] | None:
        """Locate source comments inside the selected method that describe the output context."""
        node = self.declarations.get(entity_id)
        if node is None or (body := node.child_by_field_name("body")) is None:
            return None
        entity = self.entities[entity_id]
        lines = self.syntax[entity.repository_relative_path][1]
        for index in range(body.start_point.row, body.end_point.row):
            line = lines[index].strip()
            if line.startswith(("//", "/*", "*")) and self.OUTPUT_CONTEXT.search(line):
                return max(entity.start_line, index - 1), min(entity.end_line, index + 15)
        return None

    def _return_witness(self, seed: str, entry: str, point: dict) -> dict | None:
        paths = self.return_witnesses.get((entry, point["line"], point["column"]), ())
        if not paths:
            return None
        steps = min(paths, key=lambda path: (path[0]["entity_id"] != entry, len(path)))
        mapped = [step for step in steps if step is not None]
        shown = mapped if len(mapped) <= 7 else [*mapped[:3], *mapped[-4:]]
        return {
            "kind": "representative_taint_witness",
            "passes_selected_method": any(step["entity_id"] == seed for step in mapped),
            "unmapped_steps": len(steps) - len(mapped), "omitted_mapped_steps": len(mapped) - len(shown),
            "steps": [[step["file"], step["line"], step["symbol"]] for step in shown],
        }

    def library_boundary(self, seed: str) -> dict | None:
        """Find the nearest documented public return on a bounded incoming call walk."""
        pending = deque([(seed, [])])
        seen = {seed}
        while pending:
            entity_id, chain = pending.popleft()
            contract = self.output_contract(entity_id)
            if contract is not None:
                sites = sorted(self.return_sites[entity_id], key=lambda p: (p["line"], p["column"]))
                point = sites[0]
                producer = next((edge["to"] for edge in self.by_entity[entity_id]
                                 if edge["kind"] == "CODEQL_CALL"
                                 and edge["from"]["entity_id"] == entity_id
                                 and (edge["from"]["line"], edge["from"]["column"]) == (point["line"], point["column"])), None)
                return {"entry_entity_id": entity_id, "contract": contract, "call_sites": chain,
                        "return_site": point, "return_producer": producer,
                        "implementation_window": self.implementation_window(seed),
                        "return_witness": self._return_witness(seed, entity_id, point)}
            if len(chain) >= 3:
                continue
            for edge in self.callers.get(entity_id, ()):
                caller = edge["from"]["entity_id"]
                if caller in seen or len(seen) >= 64 or "/test/" in "/" + self.entities[caller].repository_relative_path:
                    continue
                seen.add(caller)
                pending.append((caller, [edge, *chain]))
        return None

    def context(self, entity_ids: list[str], *, direction: str = "both",
                kind: str | None = None, offset: int = 0, limit: int = 20) -> list[dict]:
        if direction not in {"both", "forward", "backward"} or kind not in self.KINDS | {None}:
            raise ValueError("Unknown graph direction or relation kind.")
        if type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 20:
            raise ValueError("Use a nonnegative offset and a limit between one and twenty.")
        rows = {}
        for requested_id in entity_ids[:8]:
            entity_id = requested_id
            if requested_id not in self.by_entity and requested_id in self.entities:
                requested = self.entities[requested_id]
                owners = [entity for entity in self.methods.get(requested.repository_relative_path, ())
                          if requested.enclosing_callable
                          and f"{entity.qualified_name}{(entity.signature or '')[len(entity.simple_name):]}" == requested.enclosing_callable
                          and entity.start_line <= requested.start_line <= requested.end_line <= entity.end_line]
                if len(owners) == 1:
                    entity_id = owners[0].entity_id
            ranked = sorted(self.by_entity.get(entity_id, ()),
                            key=lambda r: (r["kind"] != "CODEQL_DIRECT_CALL", r["kind"] != "CODEQL_CALL"))
            for item in ranked:
                if item.get("background_only"):
                    continue
                if kind is not None and item["kind"] != kind:
                    continue
                if direction == "forward" and item["from"]["entity_id"] != entity_id:
                    continue
                if direction == "backward" and item["to"]["entity_id"] != entity_id:
                    continue
                left, right = item["from"], item["to"]
                key = (item["kind"], left["file"], left["line"], left["column"],
                       right["file"], right["line"], right["column"])
                rows.setdefault(key, item)
        return list(rows.values())[offset:offset + limit]

    def summary(self) -> dict:
        return {"sha256": self.sha256, "rows": self.rows, "mapped": self.mapped, "unmapped": self.skipped}
