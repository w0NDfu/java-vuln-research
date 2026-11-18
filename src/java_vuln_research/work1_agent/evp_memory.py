"""Durable, source-bound propagation segments and deterministic partial chains.

The ledger name is a protocol name, not a vulnerability verdict. A grounded
segment stays pending independent review until its exact witnesses are confirmed.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict

from .evidence_chain import EvidenceChain
from .proposal.model import stable_digest


PROPAGATION_KINDS = {"DIRECT_CALL", "FIELD_STATE", "COLLECTION_STATE", "RETURN_FLOW",
                     "CALLBACK_DISPATCH", "FRAMEWORK_ENTRY"}


class DataflowFactLedger:
    def __init__(self):
        self.facts = {}
        self.steps = {}
        self.rejections = []

    @staticmethod
    def vertex(step):
        return (step["method_id"], step["file_path"], step["line_start"],
                step["tracked_variable_or_expr"])

    def add(self, checker, draft):
        kind = draft.get("propagation_kind")
        if kind not in PROPAGATION_KINDS:
            raise ValueError("Unknown propagation_kind in verified_subpaths.")
        checked = []
        for side in ("from", "to"):
            expression = draft.get(side + "_symbol", draft.get("tainted_symbol"))
            checked.append(checker.step({"file_path": draft[side + "_file"],
                "line_start": draft[side + "_line"], "line_end": draft.get(side + "_end_line", draft[side + "_line"]),
                "method_symbol": draft[side + "_callable"], "tracked_variable_or_expr": expression,
                "step_role": draft.get(side + "_role", "PROPAGATION"),
                **({"evidence_id": draft[side + "_evidence_id"]} if draft.get(side + "_evidence_id") else {})}))
        relation = checker.relation(*checked)
        a, b = (item[0] for item in checked)
        return self.add_checked(a, b, kind, relation, draft.get("confidence", 0.5),
                                draft.get("evidence_snippet_hash"))

    def add_checked(self, a, b, kind, relation, confidence=0.5, expected_hash=None):
        digest = hashlib.sha256((a["content_hash"] + b["content_hash"]).encode()).hexdigest()
        if expected_hash is not None and expected_hash != digest:
            raise ValueError("Dataflow fact evidence_snippet_hash mismatch.")
        if type(confidence) not in (int, float) or not 0 <= confidence <= 1:
            raise ValueError("Fact confidence must be between zero and one.")
        left, right = self.vertex(a), self.vertex(b)
        if left == right:
            return None
        identity = stable_digest("evp-edge", {"from": left, "to": right, "kind": kind})
        if identity in self.facts:
            return identity
        adjacency = defaultdict(set)
        for key, (origin, target) in self.steps.items():
            adjacency[self.vertex(origin)].add(self.vertex(target))
        todo, seen = [right], set()
        while todo:
            vertex = todo.pop()
            if vertex == left:
                raise ValueError("Fact would introduce a cycle in the segment DAG.")
            if vertex not in seen:
                seen.add(vertex)
                todo.extend(adjacency[vertex])
        if len(self.facts) >= 128:
            raise ValueError("The branch fact ledger is full (128 segments).")
        row = {"edge_id": identity, "tainted_symbol": a["tracked_variable_or_expr"],
               "propagation_kind": kind, "relation": relation, "evidence_snippet_hash": digest,
               "confidence": min(float(confidence), 0.8),
               "status": "STATIC_MAY_FLOW" if relation == "static_value_hop" else "SOURCE_GROUNDED_PENDING_REVIEW",
               "evidence_refs": list(dict.fromkeys([a["evidence_id"], b["evidence_id"]]))}
        for side, step in (("from", a), ("to", b)):
            row.update({side + "_callable": step["method_id"], side + "_file": step["file_path"],
                        side + "_line": step["line_start"], side + "_end_line": step["line_end"],
                        side + "_symbol": step["tracked_variable_or_expr"], side + "_role": step["step_role"],
                        side + "_evidence_id": step["evidence_id"]})
        self.facts[identity], self.steps[identity] = row, (a, b)
        return identity

    def remember_hops(self, hops):
        added = []
        for row in hops.values():
            if row["kind"] == "SEMANTIC_BRIDGE":
                continue
            kind = ("FIELD_STATE" if "field" in row["kind"] else
                    "RETURN_FLOW" if "return" in row["kind"] else "DIRECT_CALL")
            try:
                identity = self.add_checked(row["from_step"], row["to_step"], kind, row["kind"])
            except ValueError as exc:
                self.rejections.append(str(exc))
                continue
            if identity:
                added.append(identity)
        return added

    def context(self):
        outgoing, incoming = defaultdict(list), set()
        for identity, (a, b) in self.steps.items():
            if self.facts[identity]["status"] == "VERIFIER_REFUTED":
                continue
            outgoing[self.vertex(a)].append(identity)
            incoming.add(self.vertex(b))
        chains = []
        roots = sorted(set(outgoing) - incoming)
        queue = [(root, []) for root in roots]
        expanded = 0
        while queue and len(chains) < 16 and expanded < 512:
            expanded += 1
            vertex, prefix = queue.pop(0)
            for identity in sorted(outgoing.get(vertex, ())):
                chain = [*prefix, identity]
                a, b = self.steps[identity]
                end = self.vertex(b)
                if outgoing.get(end) and len(chain) < 24:
                    if len(queue) < 256:
                        queue.append((end, chain))
                else:
                    first = self.steps[chain[0]][0]
                    chains.append({"edge_ids": chain, "source_prefix": first["step_role"] == "SOURCE",
                                   "sink_suffix": b["step_role"] == "SINK",
                                   "start_step": first, "end_step": b})
        return {"verified_subpaths": list(self.facts.values()), "connected_partial_chains": chains,
                "meaning": "Source-bound propagation claims; only independent Verification establishes semantic validity."}

    def confirm(self, hop):
        if hop.get("kind") == "SEMANTIC_BRIDGE":
            kind = "FIELD_STATE" if hop["semantic_bridge"]["bridge_type"] == "FIELD_LIFECYCLE" else "CALLBACK_DISPATCH"
            self.add_checked(hop["from_step"], hop["to_step"], kind, "SEMANTIC_BRIDGE")
        for identity, pair in self.steps.items():
            if tuple(self.vertex(step) for step in pair) == tuple(
                    self.vertex(hop[side]) for side in ("from_step", "to_step")):
                self.facts[identity]["status"] = "VERIFIER_CONFIRMED"
                self.facts[identity]["confidence"] = 1.0

    def refute(self, hop):
        for identity, pair in self.steps.items():
            if tuple(self.vertex(step) for step in pair) == tuple(
                    self.vertex(hop[side]) for side in ("from_step", "to_step")):
                self.facts[identity]["status"] = "VERIFIER_REFUTED"
                self.facts[identity]["confidence"] = 0.0
