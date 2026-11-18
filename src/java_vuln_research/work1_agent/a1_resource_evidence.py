"""Opt-in mixed evidence interface over the frozen FastTrack A1 runner."""
from __future__ import annotations

import hashlib

from .benchmark import digest
from .dag_harness import AgentTeam
from .harness import SUPPORTED_CWES
from .resource_references import ResourceReferences, local_path, resource_identity


REASONING_ADDENDUM = (
    " Java steps use {evidence_id,method_id,line,end_line?,expression,role}. A non-Java resource step instead "
    "uses {evidence_id,resource_id,line,end_line?,expression,role}, with the actual resource_id from "
    "the supplied source window and no method_id. If end_line is present, the expression must be "
    "an exact contiguous substring across the indicated lines, preserving line breaks. "
    "Cite only visible source windows. Resolved resource references identify declarations and files, "
    "not value propagation. Preserve unresolved connections as uncertainties. The existing candidate "
    "conditions, uncertainty and verdict rules apply to both location types. "
    "R2 position-selection mode: a step may omit expression only when it explicitly supplies evidence_id, "
    "method_id or resource_id, line, end_line, and role. The program extracts the exact delivered text "
    "before calling the unchanged validator. Optional start_anchor/end_anchor are exact unique literal "
    "substrings in the first/last selected lines for partial-line boundaries, including minified code. "
    "Never select outside the supplied window. An expression supplied explicitly remains subject to "
    "the original exact-text checks; it is never silently repaired. "
    "You may also request {action:read_file_range,file,start_line,end_line} using the safe repository file reader, "
    "with at most160 lines. Java file-level evidence has a file identity, not a method_id, and cannot be used "
    "as a candidate step; select/read each exact method separately for method evidence."
)
VERIFICATION_ADDENDUM = (
    " Source evidence may identify a Java method or a non-Java resource. Review the actual supplied "
    "source and cite only its evidence IDs. The same verdict rules apply to both location types."
)


def prompts(original):
    return {**original, 'reasoning': original['reasoning'] + REASONING_ADDENDUM,
            'verification': original['verification'] + VERIFICATION_ADDENDUM}


def candidate_step(step, proof, methods):
    """Validate both identity and exact text from the previously presented window."""
    resource = 'resource_id' in proof
    identity_key = 'resource_id' if resource else 'method_id'
    other_key = 'method_id' if resource else 'resource_id'
    if (other_key in step or step.get(identity_key) != proof[identity_key]
            or step.get('evidence_id') != proof['evidence_id']):
        raise ValueError('Candidate step identity must match the visible source window.')
    first = step.get('line')
    last = step.get('end_line', first)
    expression, role = step.get('expression'), step.get('role')
    if (type(first) is not int or type(last) is not int
            or not proof['start_line'] <= first <= last <= proof['end_line']
            or role not in {'SOURCE','PROPAGATION','GUARD','SINK'}
            or not isinstance(expression,str) or not 0 < len(expression) <= 500 or not expression.strip()):
        raise ValueError('Invalid candidate expression, role or source range.')
    if resource:
        if proof['resource_id'] != resource_identity(proof['file'], proof['file_sha256']):
            raise ValueError('Resource identity does not bind the file.')
    else:
        method = methods.get(proof['method_id'])
        if (method is None or proof['method_id'] == 'entity-unknown' or
                method.repository_relative_path != proof['file'] or
                not method.start_line <= first <= last <= method.end_line):
            raise ValueError('Java step must stay inside its indexed method.')
    if expression.count('\n') != last-first or expression.startswith('\n') or expression.endswith('\n'):
        raise ValueError('Expression must touch both ends of the cited range.')
    visible = {}
    for line in proof['source'].splitlines():
        number, sep, raw = line.partition(' | ')
        if not sep or not number.strip().isdigit() or int(number) in visible:
            raise ValueError('Malformed source window.')
        visible[int(number)] = raw
    if list(visible) != list(range(proof['start_line'], proof['end_line']+1)):
        raise ValueError('Source window is missing exact visible lines.')
    if expression not in '\n'.join(visible[n] for n in range(first,last+1)):
        raise ValueError('Expression must match the visible source exactly.')
    node = {'repository_relative_path': proof['file'], 'start_line': first, 'end_line': last,
            'location_kind': 'RESOURCE' if resource else 'JAVA_METHOD', 'role': role,
            'expression': expression, 'evidence_id': proof['evidence_id'],
            'content_sha256': proof['content_sha256']}
    if resource:
        node.update(resource_id=proof['resource_id'], file_sha256=proof['file_sha256'])
    else:
        node['entity_id'] = proof['method_id']
    return node


def extract_selected_step(step,proof,methods):
    """Build only an explicitly selected, already delivered range's exact text."""
    if 'expression' in step:return dict(step)
    first,last=step.get('line'),step.get('end_line')
    if type(first)is not int or type(last)is not int or not proof['start_line']<=first<=last<=proof['end_line']:
        raise ValueError('Exact line and end_line must be supplied and remain inside the delivered evidence window; obtain and select a new window explicitly.')
    identity='resource_id' if 'resource_id' in proof else 'method_id'
    if step.get('evidence_id')!=proof['evidence_id'] or step.get(identity)!=proof[identity]:raise ValueError('Selected evidence identity does not match the delivered window')
    text={}
    for row in proof['source'].split('\n'):
        number,sep,raw=row.partition(' | ')
        if not sep or not number.strip().isdigit() or int(number) in text:raise ValueError('Malformed delivered source record')
        text[int(number)]=raw
    if list(text)!=list(range(proof['start_line'],proof['end_line']+1)):raise ValueError('Delivered source record is not contiguous')
    selected=[text[n] for n in range(first,last+1)]
    if 'start_anchor' in step or 'end_anchor' in step:
        left,right=step.get('start_anchor'),step.get('end_anchor')
        if not isinstance(left,str) or not left or not isinstance(right,str) or not right:raise ValueError('Both exact position anchors must be supplied')
        if selected[0].count(left)!=1 or selected[-1].count(right)!=1:raise ValueError('Position anchors must each occur exactly once in the chosen endpoint line')
        start=selected[0].index(left);end=selected[-1].index(right)+len(right)
        if first==last:
            if start>=end:raise ValueError('Selected anchors have reversed positions')
            selected=[selected[0][start:end]]
        else:selected=[selected[0][start:],*selected[1:-1],selected[-1][:end]]
    built={**step,'expression':'\n'.join(selected)}
    candidate_step(built,proof,methods)
    return built


def install(runner, *, automatic, physical_requests=None, candidate_windows=None):
    """Install identical schema, visibility and admission in both experiment arms."""
    references = ResourceReferences(runner.tools.index.repository_root, runner.ast.parser) if automatic else None
    original_team = runner.team
    original_ask, original_review = runner.ask, runner.review
    resource_archive, exposed = {}, {}
    def restore_exposure(proofs):
        for proof in proofs:
            identity=proof['evidence_id']
            if identity in exposed and exposed[identity]!=proof:raise ValueError('Restored exposure content conflict')
            exposed[identity]=proof
            if 'resource_id' in proof:resource_archive[identity]=proof
    runner.restore_evidence_exposure=restore_exposure
    active_ids = set()
    delivered = set()
    runner.resource_exposure = dict(roots={}, delivered={}, repeated_sends=0,
                                    unconfirmed_sends=0, integrity_reads=0, reads={})
    root = runner.tools.index.repository_root.resolve()

    def observe(policy):
        def send(context):
            proofs = {p['evidence_id']: p for p in context.get('source_evidence', [])}
            for identity, proof in proofs.items():
                if identity in exposed and exposed[identity] != proof:
                    raise ValueError('Previously exposed source window changed.')
            prior_ids = {p['evidence_id'] for p in context.get('evidence_catalog', [])}
            before = physical_requests() if physical_requests is not None else None
            resource_proofs = [p for p in proofs.values() if 'resource_id' in p]
            try:
                turn = policy(context)
            except Exception:
                if resource_proofs and physical_requests is not None and physical_requests()>before:
                    runner.resource_exposure['unconfirmed_sends'] += len(resource_proofs)
                    runner.event('resource_delivery_unconfirmed',role=context['role'],
                                 evidence_ids=[p['evidence_id'] for p in resource_proofs])
                raise
            if resource_proofs and (physical_requests is None or physical_requests()>before):
                new, repeated = [], []
                for proof in resource_proofs:
                    identity = proof['evidence_id']
                    if identity in delivered:
                        repeated.append(identity)
                    else:
                        new.append(identity)
                        delivered.add(identity)
                        runner.resource_exposure['delivered'][identity] = {
                            k:v for k,v in proof.items() if k!='source'}
                runner.resource_exposure['repeated_sends'] += len(repeated)
                runner.event('resource_delivery',role=context['role'],focus=context.get('focus'),
                             newly_delivered=new,repeated=repeated,
                             physical_request=physical_requests() if physical_requests else None)
            exposed.update(proofs)
            active_ids.clear()
            active_ids.update(proofs.keys() | (prior_ids & exposed.keys()))
            return turn
        return send

    def ask(role, context):
        active_ids.clear()
        if role == 'reasoning':
            supplied = context['source_evidence']
            java = [p for p in supplied if 'method_id' in p]
            remaining = max(0, runner.tool_limit-runner.tool_calls)
            packet = (references.build(java,methods=runner.methods,window_limit=remaining,exposed=delivered)
                      if references and remaining else
                      {'source_evidence':[],'relations':[],'previous_evidence':[],
                       'read_counts':{},'window_reads':[],'window_cache_hits':[],'truncations':[]})
            if references and not remaining:
                packet['relations'].append({'kind':'PROJECT_REFERENCE','status':'UNKNOWN',
                                            'reason':'Shared source-read budget exhausted.'})
            for proof in packet['source_evidence']:
                resource_archive[proof['evidence_id']] = proof
            runner.tool_calls += len(packet['window_reads'])
            if references:
                report = runner.resource_exposure
                focus = context['focus']
                root = report['roots'].setdefault(focus['method_id'],{'focus':focus,'packages':[]})
                entry = {'java_roots':[{k:p[k] for k in ('evidence_id','method_id','file','start_line','end_line')}
                                       for p in java],
                         'offered':[p['evidence_id'] for p in packet['source_evidence']],
                         'window_reads':packet['window_reads'],'window_cache_hits':packet['window_cache_hits'],
                         'relations':packet['relations'],'truncations':packet['truncations'],
                         'read_counts':packet['read_counts']}
                root['packages'].append(entry)
                for key,value in packet['read_counts'].items():
                    report['reads'][key] = report['reads'].get(key,0)+value
                runner.event('resource_evidence_package',focus=focus,**entry)
            catalog = [p for p in context['evidence_catalog'] if p['evidence_id'] in exposed or
                       any(p['evidence_id']==v['evidence_id'] for v in java)]
            catalog.extend({k:p[k] for k in ('evidence_id','resource_id','file','start_line','end_line')}
                           for p in packet['previous_evidence'])
            context = {**context, 'source_evidence': list({p['evidence_id']:p for p in [*supplied, *packet['source_evidence']]}.values()),
                       'resource_references': packet['relations'],
                       'evidence_catalog':catalog}
        answer = original_ask(role,context)
        if role == 'verification':
            reviews = []
            for review in answer.get('reviews', []):
                refs = review.get('evidence_refs', []) if isinstance(review,dict) else None
                if isinstance(refs,list) and all(isinstance(r,str) and r in active_ids for r in refs):
                    reviews.append(review)
                else:
                    runner.event('review_protocol_error',reason='Review cited evidence outside its visible input.')
            answer = {**answer,'reviews':reviews}
        return answer

    def candidate(draft):
        cwe = draft.get('cwe')
        if cwe not in SUPPORTED_CWES:
            raise ValueError('Unsupported CWE.')
        for key in ('title','input_reason','effect_reason','guard_analysis'):
            value = draft.get(key)
            if not isinstance(value,str) or not 8 <= len(value.strip()) <= 2400:
                raise ValueError(key + ' needs a concrete source-based explanation.')
        for key in ('conditions','uncertainties'):
            value = draft.get(key)
            if (not isinstance(value,list) or len(value)>8 or
                    any(not isinstance(v,str) or not 0<len(v)<=1200 for v in value)):
                raise ValueError(key + ' must be a bounded list of strings.')
        if not draft['conditions']:
            raise ValueError('State at least one input/use condition.')
        steps = draft.get('steps')
        if (not isinstance(steps,list) or not 2<=len(steps)<=12 or
                any(not isinstance(s,dict) for s in steps) or
                steps[0].get('role')!='SOURCE' or steps[-1].get('role')!='SINK'):
            raise ValueError('Use 2–12 ordered source steps starting SOURCE and ending SINK.')
        nodes = []
        visible = candidate_windows() if candidate_windows is not None else {
            identity: exposed[identity] for identity in active_ids
        }
        resource_lines = {}
        for step in steps:
            identity = step.get('evidence_id')
            if not isinstance(identity,str) or identity not in visible:
                raise ValueError('Step must cite evidence visible to Reasoning.')
            proof = visible[identity]
            node = candidate_step(step,proof,runner.methods)
            file = node['repository_relative_path']
            if 'resource_id' in node and file not in resource_lines:
                path = local_path(root,file)
                raw = path.read_bytes() if path else b''
                if path:
                    runner.resource_exposure['integrity_reads'] += 1
                if hashlib.sha256(raw).hexdigest() != proof['file_sha256']:
                    raise RuntimeError('Frozen resource changed before candidate admission.')
                resource_lines[file] = raw.decode('utf-8').splitlines()
            lines = resource_lines[file] if 'resource_id' in node else runner.sources[file]
            original = '\n'.join(lines[node['start_line']-1:node['end_line']])
            if node['expression'] not in original:
                raise ValueError('Expression must also match the frozen source.')
            nodes.append(node)
        if len({(n['repository_relative_path'],n['start_line'],n['end_line'],n['expression'])
                for n in nodes}) != len(nodes):
            raise ValueError('Duplicate source step.')
        endpoints = [(n['repository_relative_path'], n.get('entity_id', n.get('resource_id')), n['start_line'])
                     for n in (nodes[0],nodes[-1])]
        identity = 'bcand-' + digest([cwe,endpoints])[:24]
        if identity in runner.candidates:
            return identity
        total_cap, cwe_cap = runner.limits.max_candidates, runner.limits.per_cwe
        if ((total_cap is not None and len(runner.candidates)>=total_cap) or
                (cwe_cap is not None and sum(c['cwe']==cwe for c in runner.candidates.values())>=cwe_cap)):
            runner.event('candidate_cap',cwe=cwe)
            return None
        result = {'candidate_path_id':identity,'cwe':cwe,'status':'UNCONFIRMED',
                  **{k:draft[k] for k in ('title','input_reason','effect_reason','guard_analysis',
                                          'conditions','uncertainties')},
                  'ordered_nodes':nodes,'evidence_refs':sorted({n['evidence_id'] for n in nodes}),
                  'path_semantics':'SOURCE_GROUNDED_HYPOTHESIS_NOT_INDEPENDENT_TAINT_PROOF'}
        runner.candidates[identity] = result
        runner.event('candidate_submitted',candidate=result)
        return identity

    def review():
        java = runner.evidence
        runner.evidence = {**java, **{k:v for k,v in resource_archive.items() if k in exposed}}
        try:
            return original_review()
        finally:
            runner.evidence = java

    runner.candidate = candidate
    if candidate_windows is None:
        runner.team = AgentTeam(*(observe(getattr(original_team, role))
                                  for role in ('discovery','reasoning','verification')))
        runner.ask, runner.review = ask, review
    return resource_archive
