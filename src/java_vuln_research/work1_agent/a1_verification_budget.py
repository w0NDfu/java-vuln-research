"""Actual pending Verification reservations; future estimates are not held funds."""
import json,time
from collections import defaultdict,deque
from .experiment_policy import request_reserve
from .benchmark import source_safe

def original_context(candidates,evidence):
    refs={r for c in candidates for r in c['evidence_refs']}
    return {'role':'verification','task':'benchmark_verification','benchmark_first':True,
            'candidates':candidates,'source_evidence':[{**evidence[r],'source':source_safe(evidence[r]['source'])} for r in sorted(refs)]}

def physical_account(path):
    pending=defaultdict(deque);reported=0;count=0;unknown=[]
    for raw in path.read_bytes().splitlines() if path.exists() else []:
        r=json.loads(raw);key=r.get('request_key')
        if r.get('event')=='request_started':pending[key].append(r['reserved_tokens']);count+=1
        elif r.get('event')=='response' and pending[key]:
            held=pending[key].popleft();n=r.get('usage',{}).get('total_tokens')
            if type(n)is int and n>=0:reported+=n
            else:unknown.append(held)
    unsettled=sum(sum(v) for v in pending.values())+sum(unknown)
    return {'physical_requests':count,'reported_tokens':reported,'unsettled_reserved_tokens':unsettled,
            'unsettled_requests':sum(len(v) for v in pending.values())+len(unknown)}

def reservation(runner,archive,context,verification_policy,lookup=None,candidates=None,reviews=None):
    evidence={**runner.evidence,**archive};candidates=runner.candidates if candidates is None else candidates;reviews=runner.reviews if reviews is None else reviews
    pending=[c for k,c in candidates.items() if k not in reviews];batches=[]
    for first in range(0,len(pending),4):
        batch=pending[first:first+4];ctx=original_context(batch,evidence);estimate,method=request_reserve(ctx,verification_policy)
        cached=lookup(ctx,verification_policy) if lookup else None
        known=cached.get('usage',{}).get('total_tokens') if cached else None
        reusable=cached is not None and type(known)is int
        body_bytes=len(json.dumps(ctx,ensure_ascii=False).encode())
        batches.append({'candidate_ids':[c['candidate_path_id'] for c in batch],'context':ctx,'estimate_method':method,
                        'logical_request_reserve':1,'logical_token_reserve':known if reusable else estimate,
                        'physical_request_reserve':0 if reusable else 1,'physical_token_reserve':0 if reusable else estimate,
                        'seconds_reserve':0 if reusable else 240+body_bytes/800*0.012,'cache_origin':cached.get('origin') if reusable else None})
    future=request_reserve(context,verification_policy)[0] if context else None
    return {'actual_pending_candidates':len(pending),'actual_batches':batches,
            'held_requests':sum(b['physical_request_reserve'] for b in batches),
            'held_tokens':sum(b['physical_token_reserve'] for b in batches),
            'held_logical_requests':len(batches),'held_logical_tokens':sum(b['logical_token_reserve'] for b in batches),
            'held_seconds':sum(b['seconds_reserve'] for b in batches),
            'future_request_estimate_not_held':future,'candidate_total_cap':None,'candidate_per_cwe_cap':None,
            'correction_rule':'One original protocol correction only when remaining unheld capacity permits; other candidates retain their primary Verification opportunity.'}

class BudgetAdmission:
    def __init__(self,runner,archive,journal,verification_policy,lookup=None,clock=time.time):
        self.r=runner;self.archive=archive;self.journal=journal;self.policy=verification_policy;self.lookup=lookup;self.clock=clock;self.engine=None
    def available(self):
        physical=physical_account(self.journal.path)
        return {**physical,'physical_available_requests':self.journal.max_requests-physical['physical_requests'],
                'physical_available_tokens':self.journal.max_tokens-physical['reported_tokens']-physical['unsettled_reserved_tokens'],
                'logical_reported_tokens':self.r.usage.get('total_tokens',0),'logical_available_tokens':self.journal.max_tokens-self.r.usage.get('total_tokens',0),
                'logical_available_requests':self.journal.max_requests-self.r.model_calls,
                'available_seconds':self.journal.max_seconds-(self.clock()-self.journal.created_at)}
    def plan(self,candidates=None,reviews=None):
        if candidates is None and self.engine is not None and self.engine.in_review:candidates=self.engine.review_all
        return reservation(self.r,self.archive,{},self.policy,self.lookup,candidates,reviews)
    def fits(self,plan):
        a=self.available()
        return (plan['held_requests']<=a['physical_available_requests'] and plan['held_tokens']<=a['physical_available_tokens']
                and plan['held_logical_requests']<=a['logical_available_requests'] and plan['held_logical_tokens']<=a['logical_available_tokens']
                and plan['held_seconds']<=a['available_seconds'])
    def can_accept(self,candidates,reviews):return self.fits(self.plan(candidates,reviews))
    def admit(self,context,policy):
        from .experiment_policy import VerificationReserve
        all_candidates=(self.engine.review_all if self.engine is not None and self.engine.in_review else self.r.candidates)
        other=all_candidates
        if context['role']=='verification':
            current={c['candidate_path_id'] for c in context['candidates']};other={k:c for k,c in all_candidates.items() if k not in current}
        held=self.plan(other,self.r.reviews);estimate,method=request_reserve(context,policy);a=self.available()
        checks={'physical_requests':a['physical_available_requests']>=held['held_requests']+1,
                'physical_tokens':a['physical_available_tokens']>=held['held_tokens']+estimate,
                'logical_requests':a['logical_available_requests']>=held['held_logical_requests']+1,
                'logical_tokens':a['logical_available_tokens']>=held['held_logical_tokens']+estimate,
                'seconds':a['available_seconds']>=held['held_seconds']+240}
        self.r.event('verification_budget_reservation',account=a,actual_pending_reservation=held,current_request_estimate=estimate,estimate_method=method,admission_checks=checks)
        if not all(checks.values()):raise VerificationReserve('Actual candidate Verification reservations or request budget exhausted: '+str([k for k,v in checks.items() if not v]))
