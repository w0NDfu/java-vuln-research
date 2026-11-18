"""Bounded source navigation and generic security knowledge retrieval."""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict, deque
from pathlib import Path

from .graph_rag import BACKGROUND_FANOUT, CodeQLGraphIndex
from .repository.entity import ProgramEntity, normalise_repository_path


KNOWLEDGE = {
    "CWE-22": (
        ("filesystem-boundary", "canonical normalize resolve startsWith archive path file",
         "Check path normalization, containment at a directory boundary, absolute path handling and the file operation. A string prefix alone may match a sibling directory."),
    ),
    "CWE-78": (
        ("command-boundary", "exec ProcessBuilder command shell argument",
         "Track the exact argument position. Shell interpretation, executable selection and ordinary argument passing have different effects. Determine whether the attacker controls command syntax."),
    ),
    "CWE-79": (
        ("output-context", "response print html script render template escape sanitize",
         "Identify the browser output context. HTML text, attributes, URLs and JavaScript require different encoding. Check how the encoder output reaches the response."),
    ),
    "CWE-94": (
        ("evaluation-boundary", "eval expression script compile template engine reflection",
         "Determine which value is interpreted as code or an expression. Distinguish expression source from data bound to a fixed expression. Check parser restrictions and reachable execution."),
    ),
}


GENERAL_KNOWLEDGE = (
    ("external-caller", "library public callback interface handler framework",
     "Record assumptions about external callers. Missing callers in a library do not settle attacker control."),
    ("guard-dominance", "guard sanitize validate filter allowlist branch check",
     "Read the implementation and all relevant branches. Check that the guard dominates the effect for the same value."),
)

SOURCE_TERMS = re.compile(
    r"^(?:get(?:query|parameter|header|cookie|request|input|body|pathinfo|env)|"
    r"read(?:line|object|utf|input)|receive|accept|nextline|main|do(?:get|post|put|delete)|handle|onmessage)", re.I)
SINK_TERMS = {
    "CWE-22": re.compile(r"^(?:open|newinputstream|newoutputstream|readall|readstring|"
                         r"file(?:input|output)?stream|randomaccessfile|file|resolve|createfile|copy|move|delete|extract)", re.I),
    "CWE-78": re.compile(r"^(?:exec(?:ute)?|processbuilder|start|spawn|command|launch)", re.I),
    "CWE-79": re.compile(r"^(?:write|print|println|append|send|render|respond|redirect|output)", re.I),
    "CWE-94": re.compile(r"^(?:eval(?:uate)?|execute|compile|defineclass|loadclass|"
                         r"forname|invoke|parseexpression|interpret|render)", re.I),
}


def test_source(path: str) -> bool:
    parts = path.casefold().split("/")
    name = parts[-1].removesuffix(".java")
    return (bool({"test", "tests", "testing", "testfixtures", "buildsrc", "build-logic"} & set(parts))
            or name.endswith(("test", "tests"))
            or any(marker in part for part in parts for marker in ("testcase", "mock", "harness")))


def constant_expression(node):
    kind = node.type
    if kind.endswith("_literal") or kind in {"true", "false", "class_literal"}:
        return True
    if kind in {"parenthesized_expression", "array_initializer"}:
        return all(constant_expression(child) for child in node.named_children if not child.is_extra)
    if kind == "cast_expression":
        value = node.child_by_field_name("value")
        return value is not None and constant_expression(value)
    if kind == "array_creation_expression":
        value = node.child_by_field_name("value")
        return value is not None and constant_expression(value)
    if kind == "binary_expression":
        operator = node.child_by_field_name("operator")
        return operator is not None and operator.type == "+" and all(
            constant_expression(child) for child in node.named_children if not child.is_extra)
    return False


def sensitive_slots(entity, cwe, arity, target=None):
    name = entity.simple_name.casefold()
    if cwe == "CWE-78" and name == "exec" and target == "java.lang.Runtime":
        return (0,)
    if cwe == "CWE-79" and name in {"write", "append", "print", "println"}:
        return (0,)
    if cwe == "CWE-94" and name in {"eval", "evaluate", "compile", "forname", "loadclass", "parseexpression"}:
        return (0,)
    if cwe == "CWE-22" and name in {"copy", "move", "file", "resolve"}:
        return tuple(range(min(2, arity)))
    return tuple(range(arity))


class BranchNavigation:
    """Repository-wide endpoint inventory and directed shortest-path hints."""

    def __init__(self, retrieval, cwe):
        self.cwe = cwe
        self.entities = retrieval.entities
        self.owner = retrieval.owner
        self.eligible = retrieval.production_entities
        sources, sinks = [], []
        self.excluded_sink_ids = set()
        for entity in self.entities.values():
            name, kind = entity.simple_name, entity.kind.value
            if kind == "CALL" and SINK_TERMS[cwe].match(name):
                if (entity.entity_id in self.eligible and retrieval.controllable_sink(entity, cwe)
                        and (retrieval.semantic_index is None or retrieval.sink_score(entity, cwe) > 0)):
                    sinks.append(entity)
                else:
                    self.excluded_sink_ids.add(entity.entity_id)
            if entity.entity_id not in self.eligible:
                continue
            if ((kind in {"CALL", "METHOD"} and SOURCE_TERMS.match(name))
                    or (kind == "PARAMETER" and retrieval.entities[retrieval.owner(entity)].provenance.get("public"))):
                sources.append(entity)
        if retrieval.semantic_index is not None:
            sources.extend(retrieval.entities[identity] for identity in retrieval.semantic_index.source_scores
                           if identity in self.eligible)
        for role, selected in (("source", sources), ("sink", sinks)):
            selected.extend(retrieval.entities[identity] for identity in retrieval.inferred_anchors[cwe][role]
                            if identity in self.eligible)
            selected[:] = list({entity.entity_id: entity for entity in selected}.values())
            selected.sort(key=lambda entity: (-retrieval.endpoint_score(entity, cwe, role), self.priority(entity)))
        self.sources = sorted(sources, key=self.priority)
        self.sinks = sorted(sinks, key=self.priority)
        if retrieval.semantic_index is not None:
            self.sources.sort(key=lambda entity: -retrieval.endpoint_score(entity, cwe, "source"))
            self.sinks.sort(key=lambda entity: -retrieval.endpoint_score(entity, cwe, "sink"))
        self.retrieval = retrieval
        self.source_ids = {entity.entity_id for entity in self.sources}
        self.sink_ids = {entity.entity_id for entity in self.sinks}
        self.source_owners = {self.owner(entity) for entity in self.sources}
        self.source_parameter_owners = {self.owner(entity) for entity in self.sources if entity.kind.value == "PARAMETER"}
        self.sink_owners = {self.owner(entity) for entity in self.sinks}
        graph = retrieval.graph
        self.forward = {left: {right: kinds for right, kinds in neighbors.items() if right in self.eligible}
                        for left, neighbors in (graph.navigation.items() if graph else ()) if left in self.eligible}
        self.reverse = defaultdict(dict)
        self.dispatch_by_target = defaultdict(set)
        self.dispatch_sites = {site: targets & self.eligible for site, targets in (graph.dispatch_sites.items() if graph else ())
                               if len(graph.dispatch_fanout[site]) <= BACKGROUND_FANOUT}
        for left, neighbors in self.forward.items():
            for right, kinds in neighbors.items():
                self.reverse[right][left] = kinds
        for site, targets in self.dispatch_sites.items():
            for target in targets:
                self.dispatch_by_target[target].add(site)
        self.distance = self._distance(self.reverse, self.sinks)
        self.from_source = self._distance(self.forward, self.sources)
        self.value_prefixes = []

    @staticmethod
    def priority(entity):
        return (test_source(entity.repository_relative_path), entity.kind.value != "CALL",
                entity.repository_relative_path, entity.start_line, entity.entity_id)

    def _distance(self, neighbors, seeds):
        frontier = deque(dict.fromkeys(self.owner(item) for item in seeds))
        distances = dict.fromkeys(frontier, 0)
        while frontier:
            owner = frontier.popleft()
            for other in neighbors.get(owner, ()):
                if other not in distances:
                    distances[other] = distances[owner] + 1
                    frontier.append(other)
        return distances

    def endpoint_record(self, entity):
        return {"entity_id": entity.entity_id, "method_id": self.owner(entity), "name": entity.simple_name,
                "file": entity.repository_relative_path, "line": entity.start_line,
                **({"enclosing_type": entity.enclosing_type} if self.retrieval.semantic_index else {})}

    def source_ref(self, ref):
        return (ref.entity_id in self.source_ids
                or ref.role.value == "PARAMETER" and ref.entity_id in self.source_parameter_owners)

    def meeting(self, left, right):
        if left == right:
            return "intra_method_hop"
        relation = self.forward.get(left, {}).get(right, ())
        if "CODEQL_FIELD_STATE" in relation:
            return "field_state_bridge"
        if ("CODEQL_VIRTUAL_DISPATCH" in relation
                or self.dispatch_by_target.get(left, set()) & self.dispatch_by_target.get(right, set())):
            return "cha_poly_bridge"
        if self.entities[left].enclosing_type == self.entities[right].enclosing_type:
            return "shared_class_hop"
        return None

    def meeting_neighbors(self, owner):
        targets = set(self.forward.get(owner, ()))
        for site in self.dispatch_by_target.get(owner, ()):
            targets.update(self.dispatch_sites[site])
        return sorted(targets - {owner})

    def context(self):
        sources = sorted(self.sources, key=lambda entity: (
            test_source(entity.repository_relative_path),
            -self.retrieval.endpoint_score(entity, self.cwe, "source"),
            self.distance.get(self.owner(entity), float("inf")), self.priority(entity)))
        sinks = sorted(self.sinks, key=lambda entity: (
            test_source(entity.repository_relative_path),
            -self.retrieval.endpoint_score(entity, self.cwe, "sink"),
            self.from_source.get(self.owner(entity), float("inf")), self.priority(entity)))
        backward = []
        for sink in sinks[:3]:
            owner = self.owner(sink)
            for caller, kinds in sorted(self.reverse.get(owner, {}).items())[:3]:
                backward.append({"methods": [caller, owner], "relations": [sorted(kinds)]})
                for parent, earlier in sorted(self.reverse.get(caller, {}).items())[:1]:
                    if parent != owner:
                        backward.append({"methods": [parent, caller, owner],
                                         "relations": [sorted(earlier), sorted(kinds)]})
        return {"source_count": len(sources), "sink_count": len(sinks),
                "sources": [{**self.endpoint_record(entity),
                             "distance_to_sink": self.distance.get(self.owner(entity))} for entity in sources[:5]],
                "sinks": [self.endpoint_record(entity) for entity in sinks[:5]],
                "backward_slices": backward[:8], "forward_prefixes": self.value_prefixes}


def retrieve_knowledge(cwe: str, queries: list[str]) -> list[dict[str, str]]:
    terms = set(re.findall(r"\w+", " ".join(queries).lower()))
    cards = sorted((*KNOWLEDGE[cwe], *GENERAL_KNOWLEDGE), key=lambda card: (-len(terms.intersection(card[1].lower().split())), card not in KNOWLEDGE[cwe], card[0]))
    return [{"id": name, "cwe": cwe, "guidance": text} for name, _, text in cards[:2]]


class StructuralRetrieval:
    def __init__(self, entities: list[ProgramEntity], static_report: Path | None,
                 graph: CodeQLGraphIndex | None = None) -> None:
        self.graph = graph
        self.semantic_index = None
        self.inferred_anchors = defaultdict(lambda: {"source": set(), "sink": set()})
        self.entities = {entity.entity_id: entity for entity in entities}
        self.by_file = defaultdict(list)
        self.by_callable = defaultdict(list)
        self.by_name = defaultdict(list)
        self.fields_by_type = defaultdict(list)
        self.methods_by_type = defaultdict(list)
        self.callable_ids = {}
        self.navigation = {}
        self.call_sites = {}
        for entity in entities:
            self.by_file[entity.repository_relative_path].append(entity)
            if entity.kind.value in {"METHOD", "CONSTRUCTOR", "CALL"}:
                self.by_name[entity.simple_name].append(entity)
            if entity.enclosing_callable:
                self.by_callable[self._scope(entity)].append(entity)
            if entity.kind.value == "FIELD":
                self.fields_by_type[entity.enclosing_type].append(entity)
            if entity.kind.value in {"METHOD", "CONSTRUCTOR"}:
                self.methods_by_type[entity.enclosing_type].append(entity)
                identity = entity.qualified_name + (entity.signature or "")[len(entity.simple_name):]
                self.callable_ids[entity.repository_relative_path, identity] = entity.entity_id
        self.packages = {entity.repository_relative_path: entity.qualified_name for entity in entities
                         if entity.kind.value == "PACKAGE"}
        production_files = {file for file in self.by_file if not test_source(file)
                            and not test_source(self.packages.get(file, "").replace(".", "/"))}
        self.production_entities = {entity.entity_id for entity in entities
                                    if not production_files or entity.repository_relative_path in production_files}
        self.static_sha256 = None
        self.static_locations: dict[str, int] = {}
        self.static_flow_hints: list[dict] = []
        if static_report is not None:
            self._load_static(static_report)

    def owner(self, entity):
        return self.callable_ids.get((entity.repository_relative_path, entity.enclosing_callable), entity.entity_id)

    def same_package(self, left, right):
        first = self.entities[left].repository_relative_path
        second = self.entities[right].repository_relative_path
        return self.packages.get(first, "") == self.packages.get(second, "")

    def same_module(self, left, right):
        files = (self.entities[entity_id].repository_relative_path for entity_id in (left, right))
        modules = [("/" + file).partition("/src/") for file in files]
        return all(sep for _, sep, _ in modules) and modules[0][0] == modules[1][0]

    def edge_windows(self, sites):
        """Group nearby sites, then pad around each group without clipping it."""
        by_owner = defaultdict(list)
        for rank, (owner, first, last) in enumerate(sites):
            by_owner[owner].append((first, last, rank))
        result = []
        for owner, positions in by_owner.items():
            entity = self.entities[owner]
            merged = []
            for first, last, rank in sorted(positions):
                if merged and max(last, merged[-1][1]) - merged[-1][0] < 40:
                    a, b, index = merged[-1]
                    merged[-1] = (a, max(b, last), min(index, rank))
                else:
                    merged.append((first, last, rank))
            for first, last, rank in merged:
                start = max(entity.start_line, first - 15, last - 39)
                end = min(entity.end_line, start + 39, max(last, first + 24))
                result.append((rank, owner, start, end))
        return [(owner, start, end) for _, owner, start, end in sorted(result)]

    @staticmethod
    def _scope_from_method(entity):
        identity = entity.qualified_name + (entity.signature or "")[len(entity.simple_name):]
        return entity.repository_relative_path, entity.enclosing_type, identity

    def branch_navigation(self, cwe):
        if cwe not in self.navigation:
            self.navigation[cwe] = BranchNavigation(self, cwe)
        return self.navigation[cwe]

    def enable_semantic_priors(self, index):
        self.semantic_index = index
        self.navigation.clear()

    def add_inferred_anchors(self, cwe, sources, sinks):
        for role, rows in (("source", sources), ("sink", sinks)):
            if not isinstance(rows, list) or len(rows) > 8:
                raise ValueError("At most eight inferred anchors per endpoint role.")
            for row in rows:
                identity = row.get("entity_id") if isinstance(row, dict) else row
                if identity not in self.production_entities:
                    raise ValueError("Inferred anchor must identify a production AST entity.")
                entity = self.entities[identity]
                if entity.kind.value not in {"CALL", "PARAMETER", "METHOD", "CONSTRUCTOR"}:
                    raise ValueError("Inferred anchor must be a callable, parameter or call.")
                if role == "sink" and entity.kind.value == "CALL" and not self.controllable_sink(entity, cwe):
                    continue
                self.inferred_anchors[cwe][role].add(identity)
        self.navigation.pop(cwe, None)

    def endpoint_score(self, entity, cwe, role):
        if self.semantic_index is None:
            return 0
        if test_source(entity.repository_relative_path):
            return -100
        score = 5 if entity.entity_id in self.inferred_anchors[cwe][role] else 0
        if role == "source":
            return score + self.semantic_index.source_scores.get(self.owner(entity), 0)
        return score + (self.sink_score(entity, cwe) if entity.kind.value == "CALL" else 0)

    def sink_score(self, entity, cwe):
        name = entity.simple_name.casefold()
        if entity.provenance.get("invocation_kind") == "CONSTRUCTOR_CALL" and name not in {
                "processbuilder", "file", "fileinputstream", "fileoutputstream", "randomaccessfile"}:
            return 0
        if cwe == "CWE-78" and name in {"starttimer", "stoptimer", "starttiming", "executions"}:
            return 0
        matched = self.graph.call_site(entity) if self.graph else None
        target = self.graph.call_targets.get(matched[0], "") if matched else ""
        if target and any(word in target for word in ("java.lang.Runtime", "java.lang.ProcessBuilder", "java.nio.file.",
                                                       "java.io.File", "ScriptEngine", "ExpressionParser")):
            return 10
        if name in {"exec", "processbuilder", "eval", "evaluate", "newinputstream", "newoutputstream", "readallbytes", "write", "print", "println"}:
            return 6
        return 1

    def controllable_sink(self, entity, cwe):
        if entity.entity_id not in self.call_sites:
            self.call_sites[entity.entity_id] = self.graph.call_site(entity) if self.graph else None
        matched = self.call_sites[entity.entity_id]
        arity = entity.provenance.get("argument_count")
        constant = set()
        target = None
        if matched:
            site, node = matched
            target = self.graph.call_targets.get(site)
            if target is None and entity.simple_name == "exec":
                receiver = node.child_by_field_name("object")
                if receiver is not None and receiver.type == "method_invocation":
                    receiver_name = receiver.child_by_field_name("name")
                    qualifier = receiver.child_by_field_name("object")
                    if (receiver_name is not None and receiver_name.text == b"getRuntime" and qualifier is not None
                            and qualifier.text.split(b".")[-1] == b"Runtime"):
                        target = "java.lang.Runtime"
            constant = set(self.graph.constant_arguments.get(site, ()))
            arguments = node.child_by_field_name("arguments")
            if arguments is not None:
                children = [child for child in arguments.named_children if not child.is_extra]
                arity = len(children)
                constant.update(index for index, child in enumerate(children) if constant_expression(child))
        name = entity.simple_name.casefold()
        if name == "start" and cwe == "CWE-78" and target and target != "java.lang.ProcessBuilder":
            return False
        if arity is None:
            return True
        if arity == 0:
            # The receiver can carry the effective input to these operations.
            if (cwe, name) not in {("CWE-78", "start"), ("CWE-22", "delete"), ("CWE-22", "open")}:
                return self.graph is not None and entity.entity_id in self.graph.receiver_value_calls
            if matched:
                receiver = node.child_by_field_name("object")
                if receiver is not None and receiver.type == "object_creation_expression":
                    receiver_type = receiver.child_by_field_name("type")
                    receiver_args = receiver.child_by_field_name("arguments")
                    if (receiver_type is not None and receiver_type.text.decode().split(".")[-1] in {"ProcessBuilder", "File"}
                            and receiver_args is not None):
                        return any(not constant_expression(arg) for arg in receiver_args.named_children if not arg.is_extra)
            return True
        return any(index not in constant for index in sensitive_slots(entity, cwe, arity, target))

    def inventory(self, cwe: str) -> list[dict]:
        terms = set(" ".join(card[1] for card in KNOWLEDGE[cwe]).lower().split())
        methods = [entity for entity in self.entities.values()
                   if entity.kind.value in {"METHOD", "CONSTRUCTOR", "TYPE"}
                   and "/test/" not in "/" + entity.repository_relative_path]
        def priority(entity):
            name = entity.simple_name.lower()
            matched = sum(term in name for term in terms)
            structural = self.semantic_index.source_scores.get(entity.entity_id, 0) if self.semantic_index else 0
            return (-structural, -matched, entity.kind.value == "TYPE",
                    entity.repository_relative_path, entity.start_line, entity.entity_id)

        counts: dict[str, int] = defaultdict(int)
        result = []
        for entity in sorted(methods, key=priority):
            path = entity.repository_relative_path
            if counts[path] >= 12:
                continue
            counts[path] += 1
            result.append({"entity_id": entity.entity_id, "kind": entity.kind.value,
                           "name": entity.simple_name, "file": path,
                           "line": entity.start_line,
                           **({"annotations": sorted(self.semantic_index.annotations.get(entity.entity_id, ())),
                               "enclosing_type": entity.enclosing_type,
                               "source_prior": self.semantic_index.source_scores.get(entity.entity_id, 0),
                               "referenced_types": sorted(self.semantic_index.references.get(entity.entity_id, ()))[:6]}
                              if self.semantic_index else {})})
            if len(result) >= 36:
                break
        return result

    @staticmethod
    def _scope(entity: ProgramEntity) -> tuple:
        return entity.repository_relative_path, entity.enclosing_type, entity.enclosing_callable

    def _load_static(self, path: Path) -> None:
        with path.open("rb") as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("CodeQL report exceeds the 8 MiB input limit")
        payload = json.loads(raw)
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise ValueError("expected a canonical CodeQL report")
        self.static_sha256 = hashlib.sha256(raw).hexdigest()
        for alert_index, alert in enumerate(payload["vulnerabilities"]):
            if not isinstance(alert, dict) or str(alert.get("source_scanner", "")).lower() != "codeql":
                raise ValueError("static report contains a record with a non-CodeQL origin")
            affected_files = alert.get("affected_files", [])
            if not isinstance(affected_files, list):
                raise ValueError("invalid CodeQL affected_files")
            for affected in affected_files:
                if (not isinstance(affected, dict) or not isinstance(affected.get("file_path"), str)
                        or not isinstance(affected.get("line_numbers"), list)):
                    raise ValueError("invalid CodeQL source location")
                relative = normalise_repository_path(affected["file_path"])
                for line in affected["line_numbers"]:
                    if type(line) is not int or line < 1:
                        raise ValueError("invalid CodeQL location")
                    candidates = [e for e in self.by_file.get(relative, ())
                                  if e.kind.value in {"METHOD", "CONSTRUCTOR", "CALL"}
                                  and e.start_line <= line <= e.end_line]
                    if candidates:
                        entity = min(candidates, key=lambda e: (e.end_line - e.start_line, e.entity_id))
                        self.static_locations.setdefault(entity.entity_id, line)
            flows = alert.get("tainted_data_flow") or []
            if not isinstance(flows, list):
                raise ValueError("invalid CodeQL tainted_data_flow")
            for flow_index, flow in enumerate(flows):
                if not isinstance(flow, list):
                    raise ValueError("invalid CodeQL path")
                nodes = []
                for index, point in enumerate(flow):
                    if not isinstance(point, dict):
                        raise ValueError("invalid CodeQL path point")
                    relative = normalise_repository_path(point["file_path"])
                    line = point["line_number"]
                    if type(line) is not int or line < 1:
                        raise ValueError("invalid CodeQL path line")
                    methods = [entity for entity in self.by_file.get(relative, ())
                               if entity.kind.value in {"METHOD", "CONSTRUCTOR"}
                               and entity.start_line <= line <= entity.end_line]
                    if not methods:
                        continue
                    entity = min(methods, key=lambda item: item.end_line - item.start_line)
                    nodes.append({"entity_id": entity.entity_id, "line": line, "index": index})
                    self.static_locations[entity.entity_id] = min(
                        self.static_locations.get(entity.entity_id, line), line)
                if len(nodes) >= 2:
                    selected = nodes if len(nodes) <= 32 else nodes[:16] + nodes[-16:]
                    self.static_flow_hints.append({
                        "path_id": f"codeql-path-{alert_index}-{flow_index}",
                        "report_sha256": self.static_sha256, "nodes": selected,
                        "omitted_nodes": len(flow) - len(selected), "navigation_only": True,
                    })

    def neighbors(self, entity_id: str) -> list[ProgramEntity]:
        entity = self.entities[entity_id]
        cross_file = [
            item for item in self.by_name[entity.simple_name]
            if item.repository_relative_path != entity.repository_relative_path
            and (item.kind.value == "CALL") != (entity.kind.value == "CALL")
        ][:2]
        local = [
            item for item in self.by_callable[self._scope(entity)]
            if item.entity_id != entity_id and item.kind.value in {"CALL", "METHOD", "CONSTRUCTOR"}
        ] if entity.enclosing_callable else []
        anchored = {}
        if self.graph is not None:
            for relation in self.graph.context([entity_id]):
                for side in ("from", "to"):
                    other = relation[side]["entity_id"]
                    if other != entity_id:
                        anchored.setdefault(other, self.entities[other])
        for item in cross_file + local:
            anchored.setdefault(item.entity_id, item)
        return list(anchored.values())[:3]
