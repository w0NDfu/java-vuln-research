"""Attribute annotated method hops using offline evidence from a frozen run."""

import csv
from collections import defaultdict
from itertools import groupby, pairwise, takewhile
from pathlib import Path

from ..work1_agent.graph_rag import CodeQLGraphIndex
from ..work1_agent.proposal.model import canonical_json
from ..work1_agent.repository.entity import normalise_repository_path
from ..work1_agent.repository.indexer import build_repository_index
from ..work1_agent.value_paths import ValuePaths


class HopDiagnostics:
    def __init__(self, source, outcome, trace, candidates, reviews, cwe):
        entities = build_repository_index(source).entities
        graph_file = Path(outcome["static"]["graph"])
        values_file = Path(outcome["values"]["path"])
        self.graph = CodeQLGraphIndex(source, entities, graph_file)
        values = ValuePaths(self.graph, values_file)
        self.callables = {(method.repository_relative_path,
                           f"{method.qualified_name}{(method.signature or '')[len(method.simple_name):]}"):
                          method.entity_id for methods in self.graph.methods.values() for method in methods}
        self.windows = defaultdict(set)
        self.paths = {}
        self.omitted = {}
        self.reviews = defaultdict(set)
        self.proposed = set()
        self.selected_paths = set()
        pending = {}
        for event in trace:
            if event.get("node", "").split(":")[-1] != cwe:
                continue
            if event["event"] == "action_result":
                result = event["result"]
                evidence = result.get("evidence", {})
                if "lines" in result and evidence.get("source_kind") == "SOURCE_SNIPPET":
                    self.windows[evidence["repository_relative_path"]].add(
                        (evidence["start_line"], evidence["end_line"]))
                action = event["action"]
                if action.get("action") == "submit_bridge" and action.get("path_id"):
                    self.proposed.add(("static", action["path_id"]))
                    self.selected_paths.add(action["path_id"])
                if action.get("action") == "propose_assumed_bridge" and "from_anchor" in action and "to_anchor" in action:
                    self.proposed.add(("assumed", canonical_json([action["from_anchor"], action["to_anchor"]])))
                if action.get("action") == "submit_witness_path":
                    self.proposed.add(("witness", canonical_json(action.get("steps"))))
            elif event["event"] == "model_input" and event.get("role") == "reasoning":
                pending[event["node"]] = event["context"].get("value_paths", [])
            elif event["event"] == "model_response" and event.get("role") == "reasoning":
                # Input is traced before provider admission. A reserve or budget
                # stop can leave a context that the reasoner never processed.
                for path in pending.pop(event["node"], []):
                    self.paths[path["id"]] = self.method_sequence(path["ports"])
            elif event["event"] == "value_paths_prompt_truncated":
                for path in event["paths"]:
                    self.omitted[path["id"]] = self.method_sequence(path["ports"])
            elif event["event"] == "protection_review":
                self.reviews[event["value_path_id"]].add(event["verdict"])
        for review in reviews:
            if review["cwe"] == cwe:
                self.reviews[review["candidate_path_id"]].add(review["verdict"])
        for candidate in candidates:
            if candidate["cwe"] == cwe:
                key = candidate["candidate_path_id"]
                self.paths[key] = self.method_sequence(candidate["ordered_nodes"])
                self.selected_paths.add(key)

        self.exports = defaultdict(set)
        with graph_file.open(encoding="utf-8-sig", newline="") as stream:
            rows = csv.reader(stream)
            next(rows)
            for row in rows:
                kind, lf, ll, lc, rf, rl, rc = row[:7]
                if kind in {"CODEQL_CALL", "CODEQL_DIRECT_CALL", "CODEQL_LOCAL_FLOW",
                            "CODEQL_VIRTUAL_DISPATCH", "CODEQL_FIELD_STATE"}:
                    self.record_export(kind, (lf, ll, lc), (rf, rl, rc))
        # A raw row may name both methods even if the more precise value port or
        # witness failed to map. Keep both observations for offline attribution.
        with values_file.open(encoding="utf-8-sig", newline="") as stream:
            rows = csv.reader(stream)
            next(rows)
            for row in rows:
                left, right = row[:3], row[7:10]
                if self.owner(*left) == self.owner(*right):
                    continue
                a, b = values.port(tuple(row[:7])), values.port(tuple(row[7:14]))
                first, last = map(int, row[15:17])
                file = normalise_repository_path(row[14])
                kind = row[17] if len(row) >= 19 else "static"
                end_file = normalise_repository_path(row[18]) if len(row) >= 19 else file
                witnesses = [(file, min(first, last), max(first, last))] if kind == "static" and file == end_file else [
                    (file, first, first), (end_file, last, last)]
                witnesses = list(dict.fromkeys(witnesses))
                mapped = bool(a and b and any(
                    edge["to"] == b[0] and kind == edge["kind"] and witnesses == [
                        (point["file"], point["start"], point["end"]) for point in edge["witnesses"]]
                    for edge in values.outgoing.get(a[0], ())))
                self.record_export("VALUE_BRIDGE", left, right, mapped=mapped, witnesses=witnesses)

    def owner(self, file, line, column=None):
        file, line = normalise_repository_path(file), int(line)
        if column is not None:
            point = self.graph._locate(file, line, int(column))
            if point:
                return point["entity_id"]
        methods = [method.entity_id for method in self.graph.methods.get(file, ())
                   if method.start_line <= line <= method.end_line]
        return methods[0] if len(methods) == 1 else None

    def method_sequence(self, nodes):
        def method(node):
            file = node.get("file") or node.get("repository_relative_path")
            line = node.get("line") or node.get("start_line")
            entity = self.graph.entities.get(node.get("entity_id"))
            if entity and entity.kind.value in {"METHOD", "CONSTRUCTOR"}:
                return entity.entity_id
            if entity and (owner := self.callables.get((file, entity.enclosing_callable))):
                return owner
            return self.owner(file, line) if file and line else None

        return tuple(key for key, _ in groupby(map(method, nodes)))

    def record_export(self, kind, left, right, *, mapped=None, witnesses=()):
        a, b = self.owner(*left), self.owner(*right)
        if a is not None and b is not None and a != b:
            locations = [(normalise_repository_path(file), int(line), int(line))
                         for file, line, _ in (left, right)]
            for file, first, last in witnesses:
                if last - first < 40:
                    locations.append((file, first, last))
                else:
                    locations.extend(((file, first, first), (file, last, last)))
            self.exports[a, b].add((kind, tuple(locations), mapped))

    def read_window(self, file, first, last):
        return any(start <= first <= last <= end for start, end in self.windows.get(file, ()))

    def hop(self, pair):
        matching = {key for key, seq in self.paths.items() if pair in pairwise(seq)}
        verdicts = set().union(*(self.reviews[key] for key in matching))
        exports = self.exports.get(pair, set())
        recalled = [row for row in exports if all(self.read_window(*location) for location in row[1])]
        reason = None
        if matching:
            status = "VERIFIED" if "SUPPORTED" in verdicts else "SPLICED_UNVERIFIED"
            if not verdicts:
                reason = "REVIEW_NOT_RECORDED" if matching & self.selected_paths else "NOT_SELECTED"
        elif not exports:
            status = "STATIC_MISSING"
        elif not recalled:
            status = "EXPORTED_NOT_RECALLED"
        else:
            status = "RECALLED_NOT_SPLICED"
            value_mapping = {mapped for _, _, mapped in recalled if mapped is not None}
            if any(pair in pairwise(seq) for seq in self.omitted.values()):
                reason = "PROMPT_RANKING_TRUNCATED"
            elif value_mapping == {False}:
                reason = "AST_MAPPING_FAILED"
            elif not value_mapping:
                reason = "NO_RECALLED_VALUE_BRIDGE"
            else:
                reason = "SELECTION_STAGE_UNOBSERVED"
        return {"status": status, "reason": reason, "static_kinds": sorted({row[0] for row in exports}),
                "static_edges": len(exports), "recalled_edges": len(recalled),
                "path_ids": sorted(matching), "review_verdicts": sorted(verdicts)}

    def describe(self, method_id):
        entity = self.graph.entities[method_id]
        return {"file": entity.repository_relative_path, "method": entity.qualified_name,
                "signature": entity.signature, "start_line": entity.start_line, "end_line": entity.end_line}

    def patch_methods(self, fixes):
        rows = []
        ids = set()
        for file, class_name, name in sorted({(row["file"], row["class"], row["method"]) for row in fixes}):
            file = normalise_repository_path(file)
            options = [entity for entity in self.graph.methods.get(file, ())
                       if entity.simple_name == name and entity.enclosing_type.split(".")[-1] == class_name]
            if len(options) != 1:
                rows.append({"file": file, "class": class_name, "method": name, "recalled": None,
                             "status": "AMBIGUOUS_METHOD" if options else "METHOD_NOT_RESOLVED"})
                continue
            method = options[0]
            ids.add(method.entity_id)
            read = any(start <= method.end_line and end >= method.start_line
                       for start, end in self.windows.get(file, ()))
            rows.append({**self.describe(method.entity_id), "recalled": read})
        # The patch set is unordered. Report only observed links within it.
        links = [{"from": self.describe(a), "to": self.describe(b), **self.hop((a, b))}
                 for a, b in sorted(self.exports) if a in ids and b in ids]
        return rows, links

    def chain(self, annotation):
        owners = [self.owner(node["file"], node["line"], node.get("column")) for node in annotation["methods"]]
        if len(owners) < 2 or None in owners or any(a == b for a, b in pairwise(owners)):
            raise ValueError("Each annotated hop needs two distinct methods resolved in the frozen source.")

        def endpoint(role, owner):
            point = annotation.get(role)
            if point is None:
                return None
            file, line = normalise_repository_path(point["file"]), point["line"]
            if self.owner(file, line, point.get("column")) != owner:
                raise ValueError(f"The annotated {role} must lie in the corresponding endpoint method.")
            return self.read_window(file, line, line)

        longest = 0
        for path in self.paths.values():
            for i, left in enumerate(owners):
                for j, right in enumerate(path):
                    if left != right:
                        continue
                    connected = sum(1 for _ in takewhile(
                        lambda pair: pair[0] == pair[1], zip(owners[i + 1:], path[j + 1:])))
                    longest = max(longest, connected)
        return {"source_recalled": endpoint("source", owners[0]), "sink_recalled": endpoint("sink", owners[-1]),
                "max_connected_hops": longest,
                "hops": [{"from": self.describe(a), "to": self.describe(b), **self.hop((a, b))}
                         for a, b in pairwise(owners)]}

    def diagnose(self, fixes, annotations):
        patches, links = self.patch_methods(fixes)
        chains = [self.chain(annotation) for annotation in annotations]

        def recall(field):
            measured = [row[field] for row in chains if row[field] is not None]
            return any(measured) if measured else None

        return {"source_recalled": recall("source_recalled"), "sink_recalled": recall("sink_recalled"),
                "bridge_proposed_count": len(self.proposed),
                "max_connected_hops": max((row["max_connected_hops"] for row in chains), default=None),
                "annotation_status": "ORDERED_CHAINS" if chains else "PATCH_METHODS_ONLY" if patches else "NO_LABELS",
                "patch_methods": patches, "observed_patch_links": links, "chains": chains}
