"""Source-bound CodeQL value ports and deterministic, bounded path assembly."""
from collections import defaultdict
import csv
from dataclasses import dataclass
import hashlib
import io
from functools import lru_cache
from heapq import heappop, heappush
from itertools import count

from .graph_rag import BACKGROUND_FANOUT
from .proposal.evidence import EvidenceRef, EvidenceSourceKind, EvidenceStrength
from .proposal.model import EntityRole, EntityRoleRef, stable_digest
from .proposal.roles import validate_role
from .repository.entity import normalise_repository_path


@dataclass(frozen=True, slots=True)
class StrictLink:
    origin: str
    target: str
    kind: str
    sites: tuple[tuple[str, int, int], ...]


class ValuePaths:
    def __init__(self, graph, path=None):
        self.graph = graph
        self.calls = defaultdict(list)
        self.parameters = {}
        for entity in graph.entities.values():
            if entity.kind.value == "CALL":
                self.calls[entity.repository_relative_path, entity.start_line,
                           entity.provenance["start_column"]].append(entity)
            elif entity.kind.value == "PARAMETER":
                self.parameters[entity.repository_relative_path, entity.enclosing_callable,
                                entity.provenance.get("parameter_index")] = entity
        self.outgoing = defaultdict(list)
        self.incoming = defaultdict(list)
        self.by_owner = defaultdict(list)
        self.by_owner_pair = defaultdict(list)
        self.port_owners = {}
        self.strict_links = (defaultdict(list), defaultdict(list))
        self.strict_sites = defaultdict(list)
        self.spines = {}
        self.strict_components = {}
        for origin, relations in graph.direct_edges.items():
            for relation in relations:
                target = relation["to"]["entity_id"]
                self.add_strict_link(origin, target, "CODEQL_DIRECT_CALL", tuple(
                    (point["entity_id"], point["line"], point["line"]) for point in (relation["from"], relation["to"])))
        self.unmapped = 0
        self.rows = 0
        self.duplicates = 0
        self.sha256 = None
        if path is None:
            return
        seen = set()
        with path.open("rb") as stream:
            raw = stream.read(16 * 1024 * 1024 + 1)
        if len(raw) > 16 * 1024 * 1024:
            raise ValueError("CodeQL value export exceeds 16 MiB")
        self.sha256 = hashlib.sha256(raw).hexdigest()
        records = csv.reader(io.StringIO(raw.decode("utf-8-sig")))
        width = len(next(records, ()))
        if width not in {17, 19, 20}:
            raise ValueError("Expected 17, 19 or 20 ValueBridges columns")
        groups = defaultdict(set)
        mapped_edges = []
        for row in records:
            self.rows += 1
            if len(row) != width:
                raise ValueError("Invalid CodeQL value record")
            kind = row[17] if width >= 19 else "static"
            if kind not in {"static", "cha_poly_bridge", "field_state_bridge", "container_state_bridge",
                            "closure_object_bridge", "builder_receiver_bridge", "array_varargs_bridge"}:
                raise ValueError("Unexpected CodeQL value transfer kind")
            file = normalise_repository_path(row[14])
            end_file = normalise_repository_path(row[18]) if width >= 19 else file
            first, last = map(int, row[15:17])
            group = row[19] if width == 20 else ""
            dispatch_site = None
            if kind == "cha_poly_bridge":
                call, implementation = (row[:3], row[7:10]) if row[5] == "ARGUMENT" else (row[7:10], row[:3])
                dispatch_site = (normalise_repository_path(call[0]), int(call[1]), int(call[2]))
                group = group or dispatch_site
                groups[kind, group].add(tuple(implementation))
            source, target = self.port(tuple(row[:7])), self.port(tuple(row[7:14]))
            if not source or not target or source[0] == target[0]:
                self.unmapped += 1
                continue
            if kind in {"field_state_bridge", "container_state_bridge", "closure_object_bridge",
                        "builder_receiver_bridge", "array_varargs_bridge"}:
                group = group or (file, first)
                groups[kind, group].add((source[1], target[1]))
            ranges = [(file, min(first, last), max(first, last))] if kind == "static" and file == end_file else [
                (file, first, first), (end_file, last, last)]
            witnesses = [self.witness(*item) for item in dict.fromkeys(ranges)]
            if any(witness is None for witness in witnesses):
                self.unmapped += 1
                continue
            identity = (source[0], target[0], kind, group, tuple(tuple(w.values()) for w in witnesses))
            if identity in seen:
                self.duplicates += 1
                continue
            seen.add(identity)
            edge = {"from": source[0], "to": target[0], "owners": (source[1], target[1]),
                    "witness": witnesses[0], "witnesses": witnesses, "kind": kind,
                    "guards": tuple(dict.fromkeys([*source[2], *target[2]]))}
            self.outgoing[source[0]].append(edge)
            self.incoming[target[0]].append(edge)
            self.by_owner[source[1]].append(source[0])
            self.by_owner[target[1]].append(target[0])
            self.by_owner_pair[edge["owners"]].append(edge)
            self.port_owners.update({source[0]: source[1], target[0]: target[1]})
            mapped_edges.append((edge, group, dispatch_site))
        for edge, group, dispatch_site in mapped_edges:
            kind = edge["kind"]
            degree = len(groups.get((kind, group), ()))
            if dispatch_site is not None:
                degree = max(degree, len(graph.dispatch_fanout.get(dispatch_site, ())))
            if kind == "field_state_bridge":
                degree = max(degree, len(graph.field_pairs.get(group, ())))
            edge["fanout"] = degree
            edge["background_only"] = degree > BACKGROUND_FANOUT
            if (not edge["background_only"] and edge["to"].role == EntityRole.RECEIVER
                    and graph.entities[edge["to"].entity_id].kind.value == "CALL"):
                graph.receiver_value_calls.add(edge["to"].entity_id)
            source_owner, target_owner = edge["owners"]
            if kind == "static":
                self.join_strict(edge["from"], edge["to"])
                self.add_strict_link(source_owner, target_owner, "VALUE_BRIDGE", self.edge_requirements(edge))
            if source_owner != target_owner and not edge["background_only"]:
                graph.navigation[source_owner].setdefault(target_owner, set()).add(
                    "CODEQL_VALUE" if kind == "static" else kind)

    def add_strict_link(self, origin, target, kind, sites):
        link = StrictLink(origin, target, kind, sites)
        for owner in dict.fromkeys((origin, target, *(site[0] for site in sites))):
            self.strict_sites[owner].append(link)
        if origin != target:
            self.strict_links[0][origin].append(link)
            self.strict_links[1][target].append(link)

    def static_spines(self, navigation, cwe):
        if cwe in self.spines:
            return self.spines[cwe]
        found = {}

        def record(methods, sites, kinds, grounded_ports):
            sites = list(dict.fromkeys(sites))
            identity = stable_digest("static-spine", {"methods": methods, "sites": sites, "kinds": kinds})
            found.setdefault(identity, {"id": identity, "methods": methods, "sites": sites,
                                        "edge_kinds": kinds, "typed_source_to_sink": grounded_ports})

        typed = self.paths(navigation.source_owners, navigation, strict_only=True)
        for chain in typed:
            if not navigation.source_ref(chain[0]["from"]) or chain[-1]["to"].entity_id not in navigation.sink_ids:
                continue
            owners = [chain[0]["owners"][0], *(edge["owners"][1] for edge in chain)]
            methods = [owner for index, owner in enumerate(owners) if index == 0 or owner != owners[index - 1]]
            record(methods, [site for edge in chain for site in self.edge_requirements(edge)],
                   ["VALUE_BRIDGE"] * len(chain), True)
            if len(found) >= 60:
                break

        def dijkstra(side, roots):
            distance = dict.fromkeys(sorted(roots & navigation.eligible), 0)
            parents = {}
            queue = [(0, root) for root in distance]
            while queue:
                cost, owner = heappop(queue)
                if cost != distance[owner]:
                    continue
                for link in self.strict_links[side].get(owner, ()):
                    other = link.target if side == 0 else link.origin
                    new = cost + (1 if link.kind == "VALUE_BRIDGE" else 3)
                    if other in navigation.eligible and new < distance.get(other, float("inf")):
                        distance[other] = new
                        parents[other] = owner, link
                        heappush(queue, (new, other))
            return distance, parents

        def legs(owner, parents):
            chain = []
            while owner in parents:
                owner, link = parents[owner]
                chain.append(link)
            return chain

        if navigation.source_owners and navigation.sink_owners:
            forward, prev = dijkstra(0, navigation.source_owners)
            backward, after = dijkstra(1, navigation.sink_owners)
            for meet in sorted(forward.keys() & backward.keys(), key=lambda node: (forward[node] + backward[node], node)):
                links = [*reversed(legs(meet, prev)), *legs(meet, after)]
                if not links:
                    continue
                methods = [links[0].origin, *(link.target for link in links)]
                if len(set(methods)) != len(methods):
                    continue
                record(methods, [site for link in links for site in link.sites],
                       [link.kind for link in links], False)
                if len(found) >= 80:
                    break
        if len({(row["methods"][0], row["methods"][-1]) for row in found.values()}) < 5:
            for chain in sorted(self.paths(self.by_owner, navigation, exploratory=True, strict_only=True),
                                key=lambda path: -len(path)):
                owners = [chain[0]["owners"][0], *(edge["owners"][1] for edge in chain)]
                methods = [owner for index, owner in enumerate(owners) if index == 0 or owner != owners[index - 1]]
                record(methods, [site for edge in chain for site in self.edge_requirements(edge)],
                       ["VALUE_BRIDGE"] * len(chain), False)
                if len(found) >= 120:
                    break
        ranked = sorted(found.values(), key=lambda row: (
            not (row["typed_source_to_sink"] and len(row["methods"]) >= 3),
            len(row["methods"]) == 1, not row["typed_source_to_sink"],
            -sum(kind == "VALUE_BRIDGE" for kind in row["edge_kinds"]), -len(row["methods"]), row["id"]))
        selected, endpoints = {}, set()
        for row in ranked:
            pair = row["methods"][0], row["methods"][-1]
            if pair in endpoints:
                continue
            selected[row["id"]] = row
            endpoints.add(pair)
            if len(selected) == 5:
                break
        self.spines[cwe] = selected
        return selected

    def relay_sites(self, anchors, eligible):
        """Unique directed relay or shared parent, retaining callsite witnesses."""
        forward, backward = (defaultdict(set), defaultdict(set))
        links = defaultdict(list)
        for owner, edges in self.strict_links[0].items():
            if owner not in eligible:
                continue
            for edge in edges:
                if edge.target in eligible:
                    forward[owner].add(edge.target)
                    backward[edge.target].add(owner)
                    links[owner, edge.target].append(edge)
        proposals = {}
        for left in anchors:
            for right in anchors:
                if left == right or right in forward[left]:
                    continue
                common = forward[left] & backward[right] - {left, right}
                parent = backward[left] & backward[right] - {left, right}
                for kind, nodes in (("directed_relay", common), ("shared_parent", parent)):
                    if len(nodes) != 1:
                        continue
                    middle = next(iter(nodes))
                    pairs = ((left, middle), (middle, right)) if kind == "directed_relay" else (
                        (middle, left), (middle, right))
                    sites = tuple(dict.fromkeys(site for pair in pairs for link in links[pair] for site in link.sites
                                                if site[0] == middle))
                    if sites:
                        proposals.setdefault((middle, kind, min(left, right), max(left, right)), sites)
        return list(proposals.items())

    def strict_root(self, ref):
        components = self.strict_components
        while ref in components and components[ref] != ref:
            parent = components[ref]
            components[ref] = components[parent]
            ref = parent
        return ref

    def join_strict(self, left, right):
        self.strict_components.setdefault(left, left)
        self.strict_components.setdefault(right, right)
        self.strict_components[self.strict_root(left)] = self.strict_root(right)

    def witness(self, file, first, last):
        point = self.graph._locate(file, first, 1) if first > 0 else None
        owners = [owner for owner in self.graph.methods.get(file, ())
                  if owner.start_line <= first <= last <= owner.end_line
                  and (point is None or owner.entity_id == point["entity_id"])]
        if len(owners) != 1:
            return None
        return {"file": file, "start": first, "end": last, "owner": owners[0].entity_id}

    @lru_cache(maxsize=32768)
    def port(self, row):
        raw_file, line, column, end_line, end_column, role_name, index = row
        file = normalise_repository_path(raw_file)
        line, column, end_line, end_column, index = map(int, (line, column, end_line, end_column, index))
        point = self.graph._locate(file, line, column)
        if point is None:
            return None
        owner = point["entity_id"]
        role = EntityRole.RECEIVER if role_name == "CALL_RECEIVER" else EntityRole(role_name)
        entity_id = owner
        call_port = role_name == "CALL_RECEIVER" or role in {EntityRole.CALL_RESULT, EntityRole.ARGUMENT}
        if call_port:
            tree, lines = self.graph.syntax[file]
            if not 1 <= end_line <= len(lines) or end_column < 1:
                return None
            try:
                def byte_column(row_number, utf16_column):
                    encoded = lines[row_number - 1].encode("utf-16-le")
                    return len(encoded[:utf16_column * 2].decode("utf-16-le").encode("utf-8"))
                start = (line - 1, byte_column(line, column - 1))
                end = (end_line - 1, byte_column(end_line, end_column))
            except UnicodeDecodeError:
                return None
            ast = tree.root_node.named_descendant_for_point_range(start, end)
            while ast and (ast.start_point != start or ast.end_point != end or
                           ast.type not in {"method_invocation", "object_creation_expression", "explicit_constructor_invocation"}):
                ast = ast.parent
            if ast is None:
                return None
            name = ast.child_by_field_name("name") or ast.child_by_field_name("type")
            if name is None:
                return None
            if name.type == "generic_type":
                name = name.named_children[0]
            if name.type == "scoped_type_identifier":
                name = name.named_children[-1]
            name_line, name_col = name.start_point
            char_col = len(lines[name_line].encode("utf-8")[:name_col].decode("utf-8")) + 1
            matching = [item for item in self.calls[file, name_line + 1, char_col]
                        if item.simple_name == name.text.decode("utf-8")]
            if len(matching) != 1:
                return None
            entity_id = matching[0].entity_id
        ref = EntityRoleRef(entity_id, role, index if index >= 0 else None)
        if not validate_role(ref, self.graph.entities)[0]:
            return None
        guards = []
        if call_port:
            child = ast
            for parent in self._parents(ast):
                condition = parent.child_by_field_name("condition")
                if parent.type in {"if_statement", "while_statement", "do_statement",
                                    "for_statement", "ternary_expression", "switch_expression"} and condition:
                    consequence = parent.child_by_field_name("consequence")
                    alternative = parent.child_by_field_name("alternative")
                    branch = "then" if child == consequence else "else" if child == alternative else "nested"
                    guards.append((owner, condition.start_point.row + 1, condition.end_point.row + 1, branch))
                child = parent
        return ref, owner, tuple(guards)

    @staticmethod
    def _parents(node):
        while node.parent is not None and node.parent.type not in {"method_declaration", "constructor_declaration"}:
            node = node.parent
            yield node

    def priority(self, chain, navigation):
        from .dag_retrieval import test_source

        start, end = chain[0]["from"], chain[-1]["to"]
        distance = navigation.distance.get(chain[-1]["owners"][1], 1000)
        crossings = sum(edge["kind"] == "static" and edge["owners"][0] != edge["owners"][1] for edge in chain)
        relaxed = sum(edge["kind"] != "static" for edge in chain)
        class_only = sum(edge["kind"] == "shared_class_hop" for edge in chain)
        strength = 4 * navigation.source_ref(start) + 3 * min(crossings, 6) - 2 * relaxed - 4 * class_only
        return (test_source(self.graph.entities[end.entity_id].repository_relative_path),
                relaxed, sum(edge.get("fanout", 0) for edge in chain),
                end.entity_id not in navigation.sink_ids, distance, -strength, len(chain))

    def paths(self, owners, navigation, *, exploratory=False, case=None, strict_only=False):
        """Grow both value frontiers. A structural meeting remains a pending hypothesis."""
        forward_roles = {EntityRole.PARAMETER, EntityRole.CALL_RESULT}
        backward_roles = {EntityRole.ARGUMENT, EntityRole.RETURN, EntityRole.RECEIVER}
        local = dict.fromkeys(ref for owner in owners for ref in self.by_owner.get(owner, ()))
        starts = {ref for ref in self.outgoing if ref.role in forward_roles
                  and ref.entity_id in navigation.eligible
                  and (ref in local or navigation.source_ref(ref))}
        ends = {ref for ref in self.incoming if ref.role in backward_roles
                and ref.entity_id in navigation.eligible and ref.entity_id not in navigation.excluded_sink_ids
                and (ref.entity_id in navigation.sink_ids or exploratory and ref in local)}
        if not starts:
            return []
        queues = ([], [])
        serial = count()
        distances = navigation.distance, navigation.from_source
        explored = ({}, {})
        candidates = {}

        def save(chain):
            if not chain or len(chain) > 12:
                return
            nodes = [chain[0]["from"], *(edge["to"] for edge in chain)]
            if len(set(nodes)) != len(nodes):
                return
            identity = tuple((edge["from"], edge["to"], edge["kind"],
                              tuple(tuple(w.values()) for w in edge["witnesses"])) for edge in chain)
            candidates.setdefault(identity, chain)

        def push(side, ref, chain, seen):
            owner = self.port_owners[ref]
            priority = distances[side].get(owner, 1000)
            seed = chain[0]["from"] if chain and side == 0 else ref
            weak = sum(edge["kind"] != "static" for edge in chain)
            heappush(queues[side], (weak, sum(edge.get("fanout", 0) for edge in chain),
                                    priority, not navigation.source_ref(seed) if side == 0 else False,
                                    len(chain), next(serial), ref, chain, seen))

        for side, roots in enumerate((starts, ends)):
            for ref in sorted(roots, key=lambda item: (item.entity_id, item.role.value, item.index or 0)):
                push(side, ref, (), frozenset({ref}))
        # Bound expansions, while preserving every distinct path discovered under that budget.
        for step in range(1200):
            side = step % 2
            queue = queues[side] or queues[1 - side]
            if not queue:
                break
            if queue is not queues[side]:
                side = 1 - side
            _, _, _, _, _, _, ref, chain, seen = heappop(queue)
            paths = explored[side].setdefault(ref, [])
            if len(paths) >= 4:
                continue
            paths.append(chain)
            for other in explored[1 - side].get(ref, ()):
                save(chain + other if side == 0 else other + chain)
            if len(chain) >= 9:
                continue
            edges = self.outgoing.get(ref, ()) if side == 0 else self.incoming.get(ref, ())
            for edge in edges:
                other = edge["to"] if side == 0 else edge["from"]
                if other in seen or other.entity_id not in navigation.eligible or edge["background_only"]:
                    continue
                if edge["kind"] != "static":
                    if strict_only:
                        continue
                    left, right = edge["from"], edge["to"]
                    if (self.strict_root(left) == self.strict_root(right)
                            or left not in self.strict_components and left not in starts
                            or right not in self.strict_components and right not in ends):
                        continue
                push(side, other, (*chain, edge) if side == 0 else (edge, *chain), seen | {other})
        prefixes = [chains[0] for ref, chains in explored[0].items()
                    if chains[0] and ref.entity_id not in navigation.sink_ids]
        navigation.value_prefixes = [{
            "ports": self.describe(chain[-4:], self.graph.entities)["ports"],
            "method_id": chain[-1]["owners"][1],
            "distance_to_sink": navigation.distance.get(chain[-1]["owners"][1]),
        } for chain in sorted(prefixes, key=lambda path: self.priority(path, navigation))[:5]]
        if case is not None and not strict_only:
            for chain in self.structural_meetings(case, navigation, explored):
                save(chain)
        return sorted(candidates.values(), key=lambda chain: self.priority(chain, navigation))

    def structural_meetings(self, case, navigation, explored):
        def read_ports(frontier):
            for ref, paths in frontier.items():
                entity = case.entities[ref.entity_id]
                owner = self.port_owners[ref]
                if self.proof(case, (owner, entity.start_line, entity.start_line)):
                    yield ref, owner, paths[0]

        suffixes = defaultdict(list)
        for ref, owner, suffix in read_ports(explored[1]):
            suffixes[case.entities[owner].enclosing_type].append((ref, owner, suffix))
        by_owner = defaultdict(list)
        for group in suffixes.values():
            for item in group:
                by_owner[item[1]].append(item)
        for left, left_owner, prefix in read_ports(explored[0]):
            group = suffixes[case.entities[left_owner].enclosing_type]
            extra = [item for owner in navigation.meeting_neighbors(left_owner)
                     for item in by_owner.get(owner, ()) if item not in group]
            for right, right_owner, suffix in [*group[:20], *extra[:20]]:
                if left == right or any(edge["to"] == right for edge in self.outgoing.get(left, ())):
                    continue
                kind = navigation.meeting(left_owner, right_owner)
                if not kind:
                    continue
                witnesses = []
                for ref, owner in ((left, left_owner), (right, right_owner)):
                    entity = case.entities[ref.entity_id]
                    witnesses.append({"file": entity.repository_relative_path, "start": entity.start_line,
                                      "end": entity.start_line, "owner": owner})
                edge = {"from": left, "to": right, "owners": (left_owner, right_owner),
                        "kind": kind, "witness": witnesses[0], "witnesses": witnesses, "guards": (),
                        "navigation_only": True}
                if self.evidence_for(case, (edge,)):
                    yield (*prefix, edge, *suffix)

    @staticmethod
    def describe(chain, entities):
        def port(ref):
            entity = entities[ref.entity_id]
            return {"entity_id": entity.entity_id, "name": entity.simple_name,
                    "file": entity.repository_relative_path, "line": entity.start_line, "role": ref.role.value,
                    **({"index": ref.index} if ref.index is not None else {})}

        identity = stable_digest("value-path", {"edges": [
            [edge["from"].to_dict(), edge["to"].to_dict(), edge["witness"],
             *([edge["kind"], edge["witnesses"]] if edge["kind"] != "static" else [])] for edge in chain
        ]})
        guards = dict.fromkeys(guard for edge in chain for guard in edge["guards"])
        return {"id": identity, "ports": [port(chain[0]["from"]), *(port(edge["to"]) for edge in chain)],
                "witnesses": [edge["witness"] for edge in chain],
                "bridge_kinds": [edge["kind"] for edge in chain],
                "guards": [{"owner": owner, "start": start, "end": end, "branch": branch}
                           for owner, start, end, branch in guards]}

    def transfer(self, case, edge, refs):
        source, target = edge["from"], edge["to"]
        anchors = list(dict.fromkeys((source.entity_id, target.entity_id)))
        if edge.get("navigation_only"):
            return {"proposal_type": "WRAPPER_FLOW", "subject": source.to_dict(),
                    "source": source.to_dict(), "target": target.to_dict(),
                    "scope": {"kind": "CALLABLE", "entity_ids": anchors}, "evidence_refs": refs,
                    "reason": "Source-witnessed structural meeting. Check actual value identity and reachability."}
        relation = {"kind": "CODEQL_DATAFLOW", "from": source.to_dict(), "to": target.to_dict(),
                    "witness": edge["witness"], "csv_sha256": self.sha256,
                    "transfer_kind": edge["kind"], "witnesses": edge["witnesses"],
                    "guards": edge["guards"]}
        artifact = stable_digest("codeql-value", relation)
        proof = EvidenceRef.create(
            source_kind=EvidenceSourceKind.CODEQL_DATAFLOW, entity_ids=anchors,
            confidence=EvidenceStrength.SUPPORTING, artifact_ref=artifact,
            provenance={"producer": "ValueBridges.ql", "csv_sha256": self.sha256},
        )
        case.evidence[proof.evidence_id] = proof
        case.tool_results[artifact] = relation
        return {"proposal_type": "WRAPPER_FLOW", "subject": source.to_dict(),
                "source": source.to_dict(), "target": target.to_dict(),
                "scope": {"kind": "CALLABLE", "entity_ids": anchors},
                "evidence_refs": [*refs, proof.evidence_id],
                "reason": "Role-preserving CodeQL may-taint witness; inspect feasibility and protection."}

    def edge_requirements(self, edge):
        required = []
        for ref, owner in zip((edge["from"], edge["to"]), edge["owners"]):
            entity = self.graph.entities[ref.entity_id]
            if ref.role != EntityRole.RETURN:
                required.append((owner, entity.start_line, entity.end_line if entity.kind.value == "CALL"
                                 else entity.start_line))
            if ref.role == EntityRole.PARAMETER and entity.kind.value in {"METHOD", "CONSTRUCTOR"}:
                identity = entity.qualified_name + (entity.signature or "")[len(entity.simple_name):]
                parameter = self.parameters.get((entity.repository_relative_path, identity, ref.index))
                if parameter is not None:
                    required.append((owner, parameter.start_line, parameter.end_line))
        for witness in edge["witnesses"]:
            if witness["end"] - witness["start"] < 40:
                required.append((witness["owner"], witness["start"], witness["end"]))
            else:
                required.extend((witness["owner"], line, line) for line in (witness["start"], witness["end"]))
        required.extend((owner, first, last) for owner, first, last, _ in edge["guards"])
        return tuple(dict.fromkeys((owner, start, min(start + 39, last))
                                  for owner, first, last in required for start in range(first, last + 1, 40)))

    def obligations(self, case, chain):
        return [self.edge_requirements(edge) for edge in chain]

    @staticmethod
    def proof(case, requirement):
        owner, start, end = requirement
        file = case.entities[owner].repository_relative_path
        return next((item for item in case.evidence.values()
                     if item.source_kind == EvidenceSourceKind.SOURCE_SNIPPET
                     and item.repository_relative_path == file
                     and item.start_line <= start <= end <= item.end_line), None)

    def evidence_for(self, case, chain):
        refs = []
        for required in self.obligations(case, chain):
            proofs = [self.proof(case, item) for item in required]
            if any(proof is None for proof in proofs):
                return None
            refs.append(list(dict.fromkeys(proof.evidence_id for proof in proofs)))
        return refs

    def summary(self):
        return {"rows": self.rows, "unmapped": self.unmapped, "duplicates": self.duplicates,
                "edges": self.rows - self.unmapped - self.duplicates, "sha256": self.sha256,
                "background_only": sum(edge["background_only"] for group in self.outgoing.values() for edge in group)}
