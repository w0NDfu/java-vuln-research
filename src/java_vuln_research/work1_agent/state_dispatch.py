"""AST field cross references and receiver-scoped callback navigation.

Hits are retrieval leads, never assertions about object identity or lifecycle.
"""
from __future__ import annotations

import re
from collections import defaultdict
from functools import lru_cache


EXTERNAL_ANNOTATION = re.compile(r"(?:Mapping|Bind|Bound|Inject|Servlet|Param|^Web|^Path)", re.I)
HANDLER = re.compile(r"^(?:do[A-Z]\w*|service|handle|execute|process\w*)$")
CONTEXT_TYPE = re.compile(r"Request|HttpExchange|Context|Input|Message|Form|Config", re.I)


def walk(node):
    stack = [node]
    while stack:
        item = stack.pop()
        yield item
        stack.extend(reversed(item.named_children))


def callable_nodes(node):
    for child in walk(node):
        parent = child.parent
        while parent is not None and parent.type not in {"method_declaration", "constructor_declaration"}:
            parent = parent.parent
        if child == node or parent == node:
            yield child


class StateDispatchIndex:
    def __init__(self, retrieval):
        self.retrieval = retrieval
        self.graph = retrieval.graph
        self.types = {e.qualified_name: e for e in retrieval.entities.values() if e.kind.value == "TYPE"}
        self.methods = {e.entity_id: e for e in retrieval.entities.values()
                        if e.kind.value in {"METHOD", "CONSTRUCTOR"}}
        self.fields = {e.entity_id: e for e in retrieval.entities.values() if e.kind.value == "FIELD"}
        self.fields_by_name = defaultdict(list)
        for field in self.fields.values():
            self.fields_by_name[field.simple_name].append(field)
        self.by_type = defaultdict(list)
        self.references = defaultdict(set)
        self.annotations = defaultdict(set)
        self.accesses = defaultdict(list)
        self.field_uses = defaultdict(set)
        self.parents = defaultdict(set)
        self.interfaces = defaultdict(set)
        self.source_scores = {}
        self.assignments = defaultdict(list)
        self.diagnostics = []
        for owner, method in self.methods.items():
            self.by_type[method.enclosing_type].append(owner)
            for field in self.fields.values():
                if field.enclosing_type == method.enclosing_type:
                    self.references[owner].update(self.resolve_type(field.type_text or "", method))
        for name, entity in self.types.items():
            text = entity.provenance.get("structural_relations") or ""
            pieces = re.split(r"\b(extends|implements)\b", text)
            relations = {}
            for index in range(1, len(pieces) - 1, 2):
                relations[pieces[index]] = re.findall(r"[\w.]+", pieces[index + 1])
            for token in relations.get("extends", ()):
                for candidate in self.resolve_type(token, entity):
                    if candidate != name:
                        target = self.interfaces if entity.provenance.get("declaration_kind") == "INTERFACE" else self.parents
                        target[name].add(candidate)
            for token in relations.get("implements", ()):
                self.interfaces[name].update(self.resolve_type(token, entity))
        self._build()

    def resolve_type(self, name, anchor):
        name = name.split("<", 1)[0].strip()
        if name in self.types:
            return {name}
        matches = {key for key, entity in self.types.items() if key.rsplit(".", 1)[-1] == name
                   and (self.retrieval.same_module(anchor.entity_id, entity.entity_id)
                        or self.retrieval.same_package(anchor.entity_id, entity.entity_id))}
        return matches

    @lru_cache(maxsize=None)
    def family(self, name):
        result, todo = {name}, [name]
        while todo:
            current = todo.pop()
            related = set(self.parents.get(current, ()))
            enclosing = self.types[current].enclosing_type if current in self.types else None
            if enclosing:
                related.add(enclosing)
            related.update(child for child, parents in self.parents.items() if current in parents)
            related.update(child for child in self.types if child.startswith(current + "."))
            for child in related - result:
                result.add(child)
                todo.append(child)
        return result

    @lru_cache(maxsize=None)
    def visible_field_types(self, name, lexical=True):
        result, todo = [], [name]
        while todo:
            current = todo.pop(0)
            if current in result:
                continue
            result.append(current)
            todo.extend(sorted(self.parents.get(current, ())))
        if lexical and name in self.types and self.types[name].enclosing_type:
            result.extend(item for item in self.visible_field_types(self.types[name].enclosing_type)
                          if item not in result)
        return tuple(result)

    def _build(self):
        if self.graph is None:
            return
        for file, entities in self.retrieval.by_file.items():
            methods = [e for e in entities if e.entity_id in self.methods]
            if not methods:
                continue
            if file not in self.graph.syntax:
                self.graph._locate(file, methods[0].start_line, 1)
            if file not in self.graph.syntax:
                continue
            tree = self.graph.syntax[file][0]
            if tree.root_node.has_error:
                self.diagnostics.append({"file": file, "status": "AST_PARSE_ERROR"})
                continue
            for node in walk(tree.root_node):
                if node.type not in {"method_declaration", "constructor_declaration"}:
                    continue
                name_node = node.child_by_field_name("name")
                matches = [m for m in methods if name_node is not None and m.simple_name == name_node.text.decode()
                           and m.start_line <= node.start_point.row + 1 and m.end_line == node.end_point.row + 1]
                # Anonymous callback bodies not represented by the lexical index
                # are retrieved through their smallest indexed enclosing callable.
                if not matches:
                    matches = sorted((m for m in methods if m.start_line <= node.start_point.row + 1
                                      and node.end_point.row + 1 <= m.end_line),
                                     key=lambda m: (m.end_line - m.start_line, m.entity_id))[:1]
                if len(matches) != 1:
                    continue
                method = matches[0]
                children = list(callable_nodes(node))
                receiver_types = defaultdict(set)
                for entity in self.retrieval.by_callable[self.retrieval._scope_from_method(method)]:
                    if entity.kind.value == "PARAMETER":
                        receiver_types[entity.simple_name].update(self.resolve_type(entity.type_text or "", method))
                for child in children:
                    if child.type == "variable_declarator" and child.child_by_field_name("name") is not None:
                        declaration = child.parent
                        kind = declaration.child_by_field_name("type") if declaration is not None else None
                        if kind is not None:
                            receiver_types[child.child_by_field_name("name").text.decode()].update(
                                self.resolve_type(kind.text.decode(), method))
                for field in self.fields.values():
                    if field.enclosing_type in self.visible_field_types(method.enclosing_type):
                        receiver_types[field.simple_name].update(self.resolve_type(field.type_text or "", method))
                self.assignments[method.entity_id].extend(child for child in children if child.type in {
                    "assignment_expression", "variable_declarator", "return_statement"})
                shadowed = {n.child_by_field_name("name").text.decode() for n in children
                            if n.type in {"formal_parameter", "spread_parameter", "variable_declarator"}
                            and n.child_by_field_name("name") is not None}
                for child in children:
                    if child.type in {"annotation", "marker_annotation"}:
                        a = child.child_by_field_name("name")
                        if a is not None:
                            self.annotations[method.entity_id].add(a.text.decode().rsplit(".", 1)[-1])
                    if child.type in {"type_identifier", "scoped_type_identifier"}:
                        self.references[method.entity_id].update(self.resolve_type(child.text.decode(), method))
                    if child.type != "identifier":
                        continue
                    name = child.text.decode()
                    parent = child.parent
                    explicit = parent is not None and parent.type == "field_access" and parent.child_by_field_name("field") == child
                    field_scope = self.visible_field_types(method.enclosing_type)
                    if explicit:
                        receiver = parent.child_by_field_name("object")
                        receiver_text = receiver.text.decode() if receiver is not None else ""
                        if receiver_text == "this":
                            field_scope = self.visible_field_types(method.enclosing_type, False)
                        elif receiver_text == "super":
                            field_scope = tuple(item for base in sorted(self.parents[method.enclosing_type])
                                                for item in self.visible_field_types(base, False))
                        elif receiver_text.endswith(".this"):
                            declared = self.resolve_type(receiver_text[:-5], method)
                            field_scope = tuple(item for name in sorted(declared) for item in self.visible_field_types(name, False))
                        else:
                            declared = receiver_types.get(receiver_text.removeprefix("this."), set())
                            declared = declared or self.resolve_type(receiver_text, method)
                            if len(declared) != 1:
                                continue
                            field_scope = self.visible_field_types(next(iter(declared)), False)
                    elif name in shadowed:
                        continue
                    elif parent is not None and parent.type in {
                            "method_invocation", "variable_declarator", "formal_parameter"} and parent.child_by_field_name("name") == child:
                        continue
                    candidates = [field for field in self.fields_by_name.get(name, ())
                                  if field.enclosing_type in field_scope]
                    if not candidates:
                        continue
                    candidates.sort(key=lambda field: (field_scope.index(field.enclosing_type), field.entity_id))
                    field = candidates[0]
                    expression = parent if explicit else child
                    outer = expression.parent
                    write = outer is not None and (
                        outer.type == "assignment_expression" and outer.child_by_field_name("left") == expression
                        or outer.type == "update_expression")
                    access = "WRITE" if write else "READ"
                    line = child.start_point.row + 1
                    site = {"method_id": method.entity_id, "file": file, "line": line,
                            "field_id": field.entity_id, "field": name, "access": access,
                            "declaring_type": field.enclosing_type,
                            "callback": name_node.text.decode() if name_node is not None else None}
                    if site not in self.accesses[field.entity_id]:
                        self.accesses[field.entity_id].append(site)
                    self.field_uses[method.entity_id].add(field.entity_id)
                params = [e for e in entities if e.kind.value == "PARAMETER" and self.retrieval.owner(e) == method.entity_id]
                binding = any(EXTERNAL_ANNOTATION.search(a) for a in self.annotations[method.entity_id])
                visible = method.provenance.get("public") or method.provenance.get("protected")
                handler = HANDLER.match(method.simple_name) and any(CONTEXT_TYPE.search(e.type_text or "") for e in params)
                score = (8 if binding and (visible or method.kind.value == "CONSTRUCTOR") else 0) + (6 if handler else 0)
                if score:
                    self.source_scores[method.entity_id] = score

    def query(self, symbol, enclosing_type, direction="both", active_owners=()):
        if direction not in {"forward", "backward", "both"}:
            raise ValueError("Bridge direction must be forward, backward or both.")
        if enclosing_type not in self.types:
            raise ValueError("Select an indexed enclosing_type.")
        active = [self.methods[owner] for owner in active_owners if owner in self.methods]
        if not active:
            active = [self.methods[owner] for owner in self.by_type.get(enclosing_type, ())]
        local_types = self.family(enclosing_type)
        references = set().union(*(self.references[m.entity_id] for m in active)) if active else set()
        state = set().union(*(self.field_uses[m.entity_id] for m in active)) if active else set()
        scoped = local_types | references
        for name, entity in self.types.items():
            if not self.interfaces[name].intersection(references):
                continue
            methods = self.by_type.get(name, ())
            relevant = any(self.field_uses[m] & state or any(EXTERNAL_ANNOTATION.search(a)
                            for a in self.annotations[m]) for m in methods)
            if relevant and any(self.retrieval.same_module(m.entity_id, entity.entity_id)
                                or self.retrieval.same_package(m.entity_id, entity.entity_id) for m in active):
                scoped.add(name)
        hits = []
        for field_id, field in self.fields.items():
            if field.simple_name != symbol or field.enclosing_type not in local_types:
                continue
            wanted = {"READ"} if direction == "forward" else {"WRITE"} if direction == "backward" else {"READ", "WRITE"}
            hits.extend({**site, "kind": "FIELD_STATE"} for site in self.accesses[field_id] if site["access"] in wanted)
        for name in sorted(scoped):
            for owner in self.by_type.get(name, ()):
                method = self.methods[owner]
                if method.simple_name == symbol:
                    hits.append({"method_id": owner, "file": method.repository_relative_path,
                                 "line": method.start_line, "kind": "SCOPED_DISPATCH", "enclosing_type": name})
        unique = {tuple(sorted(hit.items())): hit for hit in hits if hit["method_id"] in self.retrieval.production_entities}
        ranked = sorted(unique.values(), key=lambda hit: (hit["kind"] != "FIELD_STATE", hit["file"], hit["line"], hit["method_id"]))
        return {"symbol": symbol, "enclosing_type": enclosing_type, "direction": direction,
                "matches": ranked[:48], "total_matches": len(ranked), "omitted_matches": max(0, len(ranked) - 48),
                "scope_types": sorted(scoped), "proof_status": "NAVIGATION_ONLY"}
