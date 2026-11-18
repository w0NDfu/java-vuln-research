"""Source-witness path admission. Structural relations are pending review."""

import hashlib
from itertools import pairwise

from .hybrid_graph.model import EvidenceNode, HybridCandidatePath, HybridEdge, NodeKind
from .proposal.evidence import EvidenceSourceKind
from .proposal.model import EntityRole, stable_digest
from .repository.entity import normalise_repository_path
from .repository.indexer import _is_identifier, _mask_non_code, _tokens


STEP_ROLES = {"SOURCE", "PROPAGATION", "SANITIZER_CHECK", "SINK"}
EFFECT_CATEGORIES = {
    "CWE-22": {"FILESYSTEM"},
    "CWE-78": {"PROCESS_EXECUTION"},
    "CWE-79": {"REDIRECT_OR_RESPONSE", "TEMPLATE_OR_EXPRESSION"},
    "CWE-94": {"DYNAMIC_CODE", "TEMPLATE_OR_EXPRESSION"},
}


class EvidenceChain:
    def __init__(self, case, retrieval, value_paths, general_evp=False):
        self.case = case
        self.retrieval = retrieval
        self.value_paths = value_paths
        self.checked = {}
        self.files = {}
        self.general_evp = general_evp

    def step(self, draft):
        file = normalise_repository_path(draft["file_path"])
        start, end = draft["line_start"], draft["line_end"]
        expression, symbol, role = draft["tracked_variable_or_expr"], draft["method_symbol"], draft["step_role"]
        if (type(start) is not int or type(end) is not int or not 1 <= start <= end <= start + 39
                or not isinstance(expression, str) or not 1 <= len(expression.strip()) <= 200
                or not isinstance(symbol, str) or role not in STEP_ROLES):
            raise ValueError("Each step needs a callable, exact source range, tracked expression and step role.")
        methods = [entity for entity in self.retrieval.by_file.get(file, ())
                   if entity.kind.value in {"METHOD", "CONSTRUCTOR"} and entity.start_line <= start <= end <= entity.end_line
                   and symbol in {entity.entity_id, entity.simple_name, entity.signature, entity.qualified_name,
                                  entity.qualified_name + (entity.signature or "")[len(entity.simple_name):]}]
        if len(methods) != 1:
            raise ValueError("The step must resolve to one indexed callable enclosing the cited lines.")
        method = methods[0]
        matching = [proof for proof in self.case.evidence.values()
                    if proof.source_kind == EvidenceSourceKind.SOURCE_SNIPPET
                    and proof.repository_relative_path == file and proof.start_line <= start <= end <= proof.end_line
                    and (not draft.get("evidence_id") or draft["evidence_id"] == proof.evidence_id)]
        if not matching:
            raise ValueError("Read the exact step location before adding it to a path.")
        proof = min(matching, key=lambda item: (item.end_line - item.start_line, item.evidence_id))
        if proof.evidence_id not in self.checked:
            # Recompute the digest for the existing read. This cannot add evidence.
            if file not in self.files:
                root = self.case.tools.index.repository_root.resolve()
                path = (root / file).resolve()
                if not path.is_relative_to(root):
                    raise ValueError("The source witness escapes the indexed repository.")
                source = path.read_text(encoding="utf-8")
                self.files[file] = source.splitlines(), _mask_non_code(source).splitlines()
            lines, masked = self.files[file]
            raw = "\n".join(lines[proof.start_line - 1:proof.end_line])
            if hashlib.sha256(raw.encode()).hexdigest() != proof.content_hash:
                raise ValueError("The cited source window changed after retrieval.")
            self.checked[proof.evidence_id] = masked
        masked = self.checked[proof.evidence_id]
        code = tuple(token.text for token in _tokens("\n".join(masked[start - 1:end])))
        members = self.retrieval.by_callable[self.retrieval._scope_from_method(method)]
        calls = [call for call in members if call.kind.value == "CALL"
                 and start <= call.start_line <= end and call.simple_name in code]
        lexed = _tokens(_mask_non_code(expression))
        needle = tuple(token.text for token in lexed)
        match = {}
        if not needle or not any(code[i:i + len(needle)] == needle for i in range(len(code))):
            invoked = {left.text for left, right in pairwise(lexed)
                       if _is_identifier(left) and right.text == "("}
            identifiers = {token.text for token in lexed if _is_identifier(token)
                           and token.text not in {"this", "super", "new", "return", "null", "true", "false",
                                                  "boolean", "byte", "short", "int", "long", "float", "double", "char"}}
            variable_names = {name for name in identifiers if not name[0].isupper()}
            anchors = (invoked & {call.simple_name for call in calls} if invoked else
                       (variable_names or identifiers) & set(code))
            if len(needle) < 2 or not anchors:
                raise ValueError(f"Tracked expression is absent from {file}:{start}-{end}. "
                                 "Cite an actual identifier or call in the read window.")
            match = {"matched_identifiers": sorted(anchors)}
        if role == "SOURCE" and not calls and not any(
            item.kind.value == "PARAMETER" and item.simple_name in needle for item in members
        ):
            raise ValueError("A source step needs an input call or indexed parameter witness.")
        if role == "SINK" and not calls:
            raise ValueError("A sink step needs a call or constructor in the cited source.")
        return {"file_path": file, "line_start": start, "line_end": end, "method_symbol": method.qualified_name,
                "method_id": method.entity_id, "tracked_variable_or_expr": expression, "step_role": role,
                "evidence_id": proof.evidence_id, "content_hash": proof.content_hash, **match}, calls, code

    def relation(self, left, right):
        before, before_calls, before_code = left
        after, after_calls, after_code = right
        a, b = before["method_id"], after["method_id"]
        if a == b:
            return "intra_method_hop"
        for edge in self.value_paths.by_owner_pair.get((a, b), ()):
            locations = [(self.case.entities[edge[side].entity_id].repository_relative_path,
                          self.case.entities[edge[side].entity_id].start_line) for side in ("from", "to")]
            locations.extend((witness["file"], witness["start"]) for witness in edge["witnesses"])
            if all(any(step["file_path"] == file and step["line_start"] <= line <= step["line_end"]
                       for file, line in locations) for step in (before, after)):
                return "static_value_hop" if edge["kind"] == "static" else edge["kind"]
        graph = self.retrieval.graph
        if graph is not None:
            for relation in graph.by_entity.get(a, ()):
                one, two = relation["from"], relation["to"]
                if relation["kind"] in graph.NAVIGATION_KINDS and one["entity_id"] == a and two["entity_id"] == b:
                    if relation["kind"] == "CODEQL_FIELD_STATE":
                        if not (before["line_start"] <= one["line"] <= before["line_end"]
                                and after["line_start"] <= two["line"] <= after["line_end"]):
                            continue
                        return "field_state_bridge"
                    if before["line_start"] <= one["line"] <= before["line_end"]:
                        return "cha_poly_bridge" if relation["kind"] == "CODEQL_VIRTUAL_DISPATCH" else "call_argument_hop"
        first, second = (self.case.entities[item] for item in (a, b))
        for calls, method, kind in ((before_calls, second, "symbol_call_hop"),
                                    (after_calls, first, "symbol_return_hop")):
            if self.general_evp:
                # A matching method name/arity is not receiver resolution. EVP
                # uses scoped retrieval or an explicit pending semantic bridge.
                continue
            members = self.retrieval.by_callable[self.retrieval._scope_from_method(method)]
            arity = sum(item.kind.value == "PARAMETER" for item in members)
            if any(call.simple_name == method.simple_name and call.provenance.get("argument_count") == arity for call in calls):
                return kind
        if first.enclosing_type == second.enclosing_type:
            fields = self.retrieval.fields_by_type.get(first.enclosing_type, ())
            if any(field.simple_name in before_code and field.simple_name in after_code for field in fields):
                return "field_state_bridge"
        raise ValueError("Adjacent steps need a witnessed call, field or same-callable relation.")

    def validate(self, drafts, *, complete, semantic_bridges=None, general_evp=False):
        self.general_evp = general_evp
        limit = 24 if general_evp else 12
        if not isinstance(drafts, list) or not 1 <= len(drafts) <= limit or not all(isinstance(draft, dict) for draft in drafts):
            raise ValueError(f"Provide one to {limit} source witness steps.")
        bridges = semantic_bridges or []
        if (not isinstance(bridges, list) or len(bridges) > 2 or bridges and not general_evp
                or not all(isinstance(row, dict) for row in bridges)):
            raise ValueError("At most two explicit semantic bridges are permitted in EVP mode.")
        checked = [self.step(draft) for draft in drafts]
        steps = [item[0] for item in checked]
        keys = [stable_digest("wstep", {key: val for key, val in step.items()
                                         if key not in {"content_hash", "evidence_id"}}) for step in steps]
        if len(set(keys)) != len(keys):
            raise ValueError("A path cannot repeat the same witness step.")
        roles = [step["step_role"] for step in steps]
        if ("SOURCE" in roles[1:] or "SINK" in roles[:-1]
                or complete and (len(steps) < 2 or roles[0] != "SOURCE" or roles[-1] != "SINK")):
            raise ValueError("A complete path starts at SOURCE, ends at SINK and has neither role in the middle.")
        hops = {}
        used = set()
        for i, (left, right) in enumerate(pairwise(checked)):
            soft = None
            for index, row in enumerate(bridges):
                matches = []
                for side, item in (("from", left), ("to", right)):
                    step = item[0]
                    method = self.case.entities[step["method_id"]]
                    matches.append(row.get(side + "_callable") in {
                        method.entity_id, method.simple_name, method.qualified_name, method.signature}
                        and row.get(side + "_line", step["line_start"]) == step["line_start"])
                if all(matches):
                    if soft is not None or index in used:
                        raise ValueError("Semantic bridge must identify exactly one adjacent step pair.")
                    if (row.get("bridge_type") not in {"DI_WIRING", "FRAMEWORK_CALLBACK", "FIELD_LIFECYCLE", "INTERFACE_DISPATCH"}
                            or any(not isinstance(row.get(field), str) or not 8 <= len(row[field].strip()) <= 1200
                                   for field in ("rationale", "testable_condition"))):
                        raise ValueError("Each semantic bridge needs a type, rationale and testable_condition.")
                    soft = {**row, "from_callable": left[0]["method_id"], "to_callable": right[0]["method_id"]}
                    used.add(index)
            kind = "SEMANTIC_BRIDGE" if soft else self.relation(left, right)
            hop = stable_digest("whop", {"from": keys[i], "to": keys[i + 1], "kind": kind,
                                         **({"semantic_bridge": soft} if soft else {})})
            hops[hop] = {"kind": kind, "from_step": steps[i], "to_step": steps[i + 1],
                         **({"semantic_bridge": soft} if soft else {}),
                         "code_witness": {side: {"evidence_id": step["evidence_id"], "line": step["line_start"]}
                                          for side, step in (("from", steps[i]), ("to", steps[i + 1]))}}
        if len(used) != len(bridges):
            raise ValueError("Semantic bridges must match adjacent, source-backed path steps.")
        return steps, keys, hops


def candidate_from_steps(steps, keys, hops, input_category, effect_category):
    project_id = "repository"
    nodes = [EvidenceNode.security_anchor(project_id=project_id, node_kind=NodeKind.SECURITY_INPUT_ROOT,
                                          proposal_id=keys[0], provenance={"category": input_category})]
    for key, step in zip(keys, steps):
        nodes.append(EvidenceNode(node_id=key, project_id=project_id, node_kind=NodeKind.PROGRAM_VALUE,
                                  entity_id=step["method_id"], role=EntityRole.ENTITY,
                                  repository_relative_path=step["file_path"], start_line=step["line_start"],
                                  end_line=step["line_end"], provenance={"witness_step": step}))
    nodes.append(EvidenceNode.security_anchor(project_id=project_id, node_kind=NodeKind.SECURITY_EFFECT_ROOT,
                                              proposal_id=keys[-1], provenance={"category": effect_category}))
    relations = [("EXTERNAL_INPUT", [steps[0]["evidence_id"]], {})]
    relations.extend(("WRAPPER_FLOW", [row["from_step"]["evidence_id"], row["to_step"]["evidence_id"]],
                      {"witness_hop_id": key, "transfer_kind": row["kind"]}) for key, row in hops.items())
    relations.append(("SECURITY_EFFECT", [steps[-1]["evidence_id"]], {}))
    edges = [HybridEdge.create(project_id=project_id, source_node_id=left.node_id, target_node_id=right.node_id,
                               relation_kind=kind, support_class="ADMISSIBLE_SEMANTIC_PROPOSAL",
                               evidence_refs=refs, provenance=provenance)
             for (left, right), (kind, refs, provenance) in zip(pairwise(nodes), relations)]
    return HybridCandidatePath.create(project_id=project_id, nodes=nodes, edges=edges,
                                      provenance={"producer": "source_witness_steps"})
