"""One shared ceiling; R2 protection is a declining, releasable window."""
from .a1_verification_budget import BudgetAdmission
from .experiment_policy import VerificationReserve

class ReservedBudget(BudgetAdmission):
    def __init__(self,*a,r2_requests=28,r2_tools=128,r2_seconds=1200,**kw):
        super().__init__(*a,**kw)
        self.r2_requests=r2_requests;self.r2_tools=r2_tools;self.r2_seconds=r2_seconds
        self.actor='explorer';self.investigator_tools=0;self.total_tools=self.r.tool_limit;self.peer=None
        if self.journal.max_requests<r2_requests or self.total_tools<r2_tools or self.journal.max_seconds<r2_seconds:raise ValueError('Total allocation cannot preserve R2 window')
    def protection(self):
        state=self.engine.book.state if self.engine else {}
        p=state.setdefault('r2_protection',{'logical_discovery_reasoning':0,'dispatches':0,'ended':False,'end_reason':None})
        if not p['ended'] and (p['logical_discovery_reasoning']>=self.r2_requests or p['dispatches']>=28):p.update(ended=True,end_reason='ORIGINAL_LOGICAL_OR_DISPATCH_WINDOW_OBTAINED')
        return p
    def advance(self,*,logical=0,dispatches=0,no_explorer_work=False):
        p=self.protection();p['logical_discovery_reasoning']+=logical;p['dispatches']+=dispatches
        if no_explorer_work and not p['ended']:p.update(ended=True,end_reason='ORIGINAL_QUEUE_HAS_NO_RUNNABLE_WORK')
        self.protection()
        if self.engine:self.engine.book.event('r2_protection_progress',**p)
    def reserved_r2(self):
        p=self.protection();return 0 if p['ended'] else max(0,self.r2_requests-p['logical_discovery_reasoning'])
    def reserved_seconds(self):
        p=self.protection();progress=max(p['logical_discovery_reasoning']/self.r2_requests,p['dispatches']/28)
        return 0 if p['ended'] else self.r2_seconds*max(0,1-progress)
    def reassessment_reserve(self,exclude=None):
        if not self.peer:return 0
        return sum(bool(v.get('reassessment_pending')) and not v.get('transport_quarantine') and v['hypothesis_id']!=exclude for v in self.peer.state['issues'].values())
    def reserved_tools(self):
        return 0 if self.protection()['ended'] else max(0,self.r2_tools-(self.r.tool_calls-self.investigator_tools))
    def investigator_tool_available(self,hid=None):
        used=self.r.tool_calls-self.investigator_tools;extra=getattr(self.r,'evidence_service_non_reads',lambda:0)()
        protected=self.reserved_tools()
        return self.r.tool_calls+extra+protected<self.total_tools and self.can_investigate(hid)
    def can_investigate(self,hid=None):
        a=self.available();held=self.plan();rr=self.reassessment_reserve(hid)
        return a['physical_available_requests']>=self.reserved_r2()+held['held_requests']+rr+1 and a['available_seconds']>=self.reserved_seconds()+held['held_seconds']+(rr+1)*240
    def can_explore(self):
        a=self.available();held=self.plan();rr=self.reassessment_reserve()
        return a['physical_available_requests']>=held['held_requests']+rr+1 and a['available_seconds']>=held['held_seconds']+(rr+1)*240
    def admit(self,context,policy):
        hid=context.get('hypothesis',{}).get('hypothesis_id')
        if context['role']=='investigator' and not self.can_investigate(hid):raise VerificationReserve('INVESTIGATOR_PAUSED: R2, actual Verification and acquired-material reassessment reserves')
        if context['role'] in {'discovery','reasoning'} and not self.can_explore():raise VerificationReserve('Acquired-material reassessment or actual Verification reserve')
        return super().admit(context,policy)
    def can_accept(self,candidates,reviews):
        plan=self.plan(candidates,reviews);a=self.available();rr=self.reassessment_reserve(getattr(self,'current_hypothesis_id',None))
        protected=self.reserved_r2() if self.actor=='investigator' else 0;seconds=self.reserved_seconds() if self.actor=='investigator' else 0
        return self.fits(plan) and a['physical_available_requests']>=protected+plan['held_requests']+rr and a['available_seconds']>=seconds+plan['held_seconds']+rr*240
    def report(self):
        return {'total':{'requests':self.journal.max_requests,'tools':self.total_tools,'seconds':self.journal.max_seconds},'R2_window':dict(self.protection()),'R2_reserved':{'requests':self.reserved_r2(),'tools':self.reserved_tools(),'seconds':self.reserved_seconds()},'acquired_material_reassessment_requests':self.reassessment_reserve(),'actual_pending_verification':self.plan(),'available':self.available(),'investigator_tools':self.investigator_tools,'token_soft_limit':None,'currency_cost':'UNKNOWN'}
