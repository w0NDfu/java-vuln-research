"""Maintain reviewable source-audit state without promoting incomplete leads."""
from __future__ import annotations

from .proposal.evidence import EvidenceSourceKind
from .proposal.model import stable_digest


def _source_ref(case, evidence_id):
    proof = case.evidence.get(evidence_id)
    return proof if proof is not None and proof.source_kind == EvidenceSourceKind.SOURCE_SNIPPET else None


def audit_note(case, action):
    anchor = action.get("anchor_entity_id")
    refs = action.get("evidence_refs")
    hypothesis = action.get("hypothesis")
    question = action.get("next_question")
    if not isinstance(anchor, str) or anchor not in case.entities:
        raise ValueError("Use a known entity ID as the audit anchor.")
    if not isinstance(refs, list) or not 1 <= len(refs) <= 4 or not all(isinstance(ref, str) for ref in refs):
        raise ValueError("Cite one to four source evidence IDs.")
    proofs = [_source_ref(case, ref) for ref in refs]
    if any(proof is None for proof in proofs) or not any(anchor in proof.entity_ids for proof in proofs):
        raise ValueError("Use this case's source evidence, including an excerpt for the anchor.")
    if not isinstance(hypothesis, str) or not 10 <= len(hypothesis.strip()) <= 600:
        raise ValueError("Describe a concrete source-grounded hypothesis in 10 to 600 characters.")
    if not isinstance(question, str) or not 10 <= len(question.strip()) <= 240:
        raise ValueError("Describe the outstanding evidence question in 10 to 240 characters.")
    value = {
        "anchor_entity_id": anchor, "hypothesis": hypothesis.strip(), "next_question": question.strip(),
        "evidence_refs": list(dict.fromkeys(refs)),
    }
    return {"case_id": stable_digest("audit-case", {"anchor_entity_id": anchor}), **value}


def contract_path_proposals(obligation, boundary, reason):
    """Map a source-backed conditional finding onto ordinary graph proposals."""
    details = obligation["obligation"]
    entry = boundary["entry"]["entity_id"]
    seed = obligation["note"]["anchor_entity_id"]
    parameter = details["entry_to_character_read"]["parameter"]
    public_input = {"entity_id": entry, "role": "PARAMETER", "index": parameter["index"]}
    audit_point = {"entity_id": seed, "role": "METHOD"}
    public_output = {"entity_id": entry, "role": "RETURN"}
    doc_ref = boundary["contract_evidence_id"]
    entry_ref = details["public_return_evidence_id"]
    loop_ref = obligation["local_gap_proof_refs"][0]
    input_refs = obligation["note"]["evidence_refs"]
    return_refs = list(dict.fromkeys([
        loop_ref, entry_ref, details["fallback_evidence_id"], *details["state_evidence_ids"],
        *(item["evidence_id"] for item in details["return_branch_evidence"]),
    ]))

    def proposal(kind, subject, refs, *, source=None, target=None, category=None):
        anchors = dict.fromkeys(ref["entity_id"] for ref in (subject, source, target) if ref is not None)
        return {"proposal_type": kind, "subject": subject, "source": source, "target": target,
                "scope": {"kind": "CALLABLE", "entity_ids": list(anchors)},
                "evidence_refs": refs, "reason": reason, "semantic_category": category}

    return [
        proposal("EXTERNAL_INPUT", public_input, [entry_ref], category="OTHER"),
        proposal("LIBRARY_FLOW", audit_point, input_refs, source=public_input, target=audit_point),
        proposal("LIBRARY_FLOW", audit_point, return_refs, source=audit_point, target=public_output),
        proposal("SECURITY_EFFECT", public_output, [doc_ref, entry_ref], category="LIBRARY_OUTPUT_CONTRACT"),
    ]


def source_read_coverage(case, entity_id, start, end):
    return next((proof for proof in case.evidence.values()
                 if proof.source_kind == EvidenceSourceKind.SOURCE_SNIPPET and entity_id in proof.entity_ids
                 and proof.start_line <= start <= end <= proof.end_line), None)


def incomplete_path(case, actions, turn, gap_check):
    """Retain only gate-checked, source-anchored fragments for an unresolved review."""
    before = dict(case.admitted)
    fragments = []
    feedback = []
    try:
        for index, draft in enumerate(actions):
            action = {"action": "propose", "proposal": draft}
            gap = gap_check(case, action)
            if gap is not None:
                feedback.append({"proposal_index": index, "status": "NEEDS_MORE_EVIDENCE",
                                 "missing_evidence": [gap]})
                continue
            try:
                status, result = case.propose(action, turn)
            except (KeyError, TypeError, ValueError) as error:
                feedback.append({"proposal_index": index, "error": str(error)[:200]})
                continue
            if status not in ("ADMISSIBLE", "DUPLICATE"):
                feedback.append({"proposal_index": index, "status": status, "gate": result["gate"],
                                 "repair_context": result.get("repair_context", {})})
                continue
            proposal = result["proposal"]
            anchors = [proposal[key]["entity_id"] for key in ("subject", "source", "target")
                       if proposal.get(key)]
            proofs = [proof for ref in proposal["evidence_refs"] if (proof := _source_ref(case, ref)) is not None]
            anchor = next((entity for entity in anchors if any(entity in proof.entity_ids for proof in proofs)), None)
            if anchor is not None:
                proofs.sort(key=lambda proof: anchor not in proof.entity_ids)
                fragments.append((index, proposal, anchor, [proof.evidence_id for proof in proofs]))
    finally:
        case.admitted.clear()
        case.admitted.update(before)

    endpoints = {"EXTERNAL_INPUT", "SECURITY_EFFECT"}
    components = {proposal["proposal_type"] if proposal["proposal_type"] in endpoints else "TRANSFER"
                  for _, proposal, _, _ in fragments}
    missing = [part for part in ("EXTERNAL_INPUT", "TRANSFER", "SECURITY_EFFECT") if part not in components]
    result = {"missing_components": missing, "grounded_proposal_indices": [index for index, *_ in fragments],
              "proposal_feedback": feedback,
              "guidance": "Supply the missing evidence or record an unresolved case."}
    if fragments:
        _, proposal, anchor, refs = fragments[0]
        all_refs = list(dict.fromkeys([*refs, *(ref for _, _, _, fragment_refs in fragments for ref in fragment_refs)]))
        hypothesis = proposal["reason"].strip()[:300].rstrip()
        if len(hypothesis) < 10:
            hypothesis = f"Source excerpt supports investigation of {proposal['proposal_type']}."
        question = "What source evidence establishes the missing path components: " + ", ".join(missing) + "?"
        result["audit_case"] = audit_note(case, {
            "anchor_entity_id": anchor, "hypothesis": hypothesis,
            "next_question": question, "evidence_refs": all_refs[:4],
        })
    return "INCOMPLETE_PATH", result


def submit_path(case, actions, turn, gap_check):
    """Commit one connected path through the existing gate or retain the prior state."""
    if not isinstance(actions, list) or len(actions) > 8 or not all(isinstance(item, dict) for item in actions):
        raise ValueError("Provide a proposals list of at most eight proposal objects.")
    if len(actions) < 3:
        return incomplete_path(case, actions, turn, gap_check)
    kinds = [item.get("proposal_type") for item in actions]
    if (kinds[0] != "EXTERNAL_INPUT" or kinds[-1] != "SECURITY_EFFECT"
        or any(kind in ("EXTERNAL_INPUT", "SECURITY_EFFECT") for kind in kinds[1:-1])):
        raise ValueError("Use one external input, one or more transfers and one final security effect.")

    before = dict(case.admitted)
    accepted = False
    verdicts = []
    try:
        for index, draft in enumerate(actions):
            action = {"action": "propose", "proposal": draft}
            gap = gap_check(case, action)
            if gap is not None:
                return "NEEDS_MORE_EVIDENCE", {"proposal_index": index, "missing_evidence": [gap]}
            status, result = case.propose(action, turn)
            gate = result["gate"]
            verdicts.append({"proposal_id": gate["proposal_id"], "status": status})
            if status not in ("ADMISSIBLE", "DUPLICATE"):
                return status, {"proposal_index": index, "gate": gate,
                                "repair_context": result.get("repair_context", {})}
        ids = {item["proposal_id"] for item in verdicts}
        paths = [path.candidate_path_id for path in case.paths().hybrid_paths if ids <= set(path.proposal_ids)]
        if not paths:
            return "DISCONNECTED_PATH", {"missing_evidence": [
                "Adjacent steps must share the same indexed entity, role and parameter or argument index.",
            ], "proposals": verdicts}
        accepted = True
        return "PATH_SUBMITTED", {"candidate_path_ids": paths, "proposals": verdicts}
    finally:
        if not accepted:
            case.admitted.clear()
            case.admitted.update(before)
