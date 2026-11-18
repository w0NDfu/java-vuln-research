"""Optional safe-boundary callback inside the original single run lifecycle."""
from .a1_verification_budget import physical_account

class CooperativeScheduler:
    def __init__(self,peer):self.peer=peer;self.r=peer.r;self.budget=peer.e.budget
    @staticmethod
    def explorer_has_work(engine):
        # Inspection must never call book.next(), which mutates scheduling.
        return any(t['status']=='QUEUED' for t in engine.book.state['tasks'].values())
    def snapshot(self,engine):
        return {'physical':physical_account(self.budget.journal.path),'available':self.budget.available(),'R2_protection':dict(self.budget.protection()),'tool_operations':self.r.tool_calls+getattr(self.r,'evidence_service_non_reads',lambda:0)(),'pending_verification':sorted(set(self.r.candidates)-set(self.r.reviews)),'reassessment_hypothesis_ids':[k for k,v in self.peer.state['issues'].items() if v.get('reassessment_pending')],'Explorer_runnable':self.explorer_has_work(engine),'Investigator_runnable':self.peer.has_work()}
    def stop(self,engine,trigger):
        engine.actual_stop_trigger=trigger
        engine.book.state['cooperative_actual_stop']={'actual_stop_trigger':trigger,'snapshot':self.snapshot(engine)}
        engine.book.event('cooperative_stop',**engine.book.state['cooperative_actual_stop'])
    def __call__(self,engine):
        self.peer.initialize_scopes()
        engine.book.event('cooperative_loop_started',ratio=[2,1],max_active_scopes=self.peer.max_scopes)
        while not self.r.stop:
            account=physical_account(self.budget.journal.path);available=self.budget.available()
            if account.get('active_unsettled_requests',account['unsettled_requests']):self.stop(engine,'UNSETTLED_REQUEST');break
            if available['available_seconds']<=0:self.stop(engine,'WALL_TIME_LIMIT');break
            if self.r.tool_calls+getattr(self.r,'evidence_service_non_reads',lambda:0)()>=self.budget.total_tools:self.stop(engine,'GLOBAL_TOOL_LIMIT');break
            engine.verify_pending()
            if set(self.r.candidates)-set(self.r.reviews):self.stop(engine,'PENDING_VERIFICATION_RESERVE');break
            self.peer.publish_relevant_material();progress=False
            for _ in range(2):
                if self.r.stop or not self.explorer_has_work(engine):break
                if not self.budget.can_explore():break
                task=engine.book.next()
                if task is None:raise ValueError('Queued work not selectable by original dispatcher')
                old_role=self.peer.role;old_actor=self.budget.actor;self.peer.role=self.budget.actor='explorer'
                try:
                    engine.dispatch(task);self.budget.advance(dispatches=1);progress=True
                except Exception:
                    engine.book.pause_task(task['task_id'],'TOOL_OR_STATE_FAILURE',{'reason':'Original complete dispatch raised; batch must stop'})
                    self.stop(engine,'TOOL_OR_STATE_ERROR');raise
                finally:self.peer.role=old_role;self.budget.actor=old_actor
                if self.r.stop=='REQUEST_QUARANTINED':
                    # Original core already paused this task; this typed transport
                    # outcome cannot mark a decision or cancel independent work.
                    engine.book.event('transport_task_isolated',task_id=task['task_id'])
                    self.r.stop=None
                self.peer.publish_relevant_material();engine.verify_pending()
                if self.peer.state.get('reliability_error'):break
            self.budget.advance(no_explorer_work=not self.explorer_has_work(engine))
            if self.r.stop:break
            if set(self.r.candidates)-set(self.r.reviews):self.stop(engine,'PENDING_VERIFICATION_RESERVE');break
            if self.peer.has_work():progress=self.peer.step() or progress
            engine.verify_pending();self.peer.publish_relevant_material()
            if self.peer.state.get('reliability_error'):self.stop(engine,self.peer.state['reliability_error']['trigger']);break
            if not progress:
                a=self.budget.available()
                if a['physical_available_requests']<=0:trigger='GLOBAL_REQUEST_LIMIT'
                elif a['available_seconds']<240:trigger='WALL_TIME_LIMIT'
                elif self.budget.plan()['held_requests']:trigger='PENDING_VERIFICATION_RESERVE'
                elif self.explorer_has_work(engine) or self.peer.has_work():trigger='NO_ADMISSIBLE_WORK'
                else:trigger='UNRESOLVED_WITHOUT_EXECUTABLE_GAP' if any(v['status']=='PAUSED' for v in self.peer.state['issues'].values()) else 'NO_ADMISSIBLE_WORK'
                self.stop(engine,trigger);break
        if not getattr(engine,'actual_stop_trigger',None):
            stop=str(self.r.stop or self.r.last_error or '')
            trigger='GLOBAL_REQUEST_LIMIT' if self.budget.available()['physical_available_requests']<=0 else 'WALL_TIME_LIMIT' if self.budget.available()['available_seconds']<240 else 'MODEL_OR_PROTOCOL_ERROR' if 'PROTOCOL' in stop or 'MODEL' in stop else 'PENDING_VERIFICATION_RESERVE' if 'VERIFICATION' in stop else 'NO_ADMISSIBLE_WORK'
            self.stop(engine,trigger)
