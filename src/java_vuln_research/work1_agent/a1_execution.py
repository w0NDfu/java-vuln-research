"""Serial A1 task/question persistence and fair scheduling, not a new agent."""
from __future__ import annotations
from pathlib import Path
import copy,hashlib,json,os
from dataclasses import asdict
from .benchmark import digest,source_safe
from .harness import SUPPORTED_CWES

def canonical(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def atomic(path,value):
    temp=path.with_suffix(path.suffix+'.tmp');temp.write_text(canonical(value)+'\n',encoding='utf-8');temp.replace(path)

class ExecutionState:
    def __init__(self,root,binding):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.binding=binding
        self.blobs=self.root/'records';self.blobs.mkdir(exist_ok=True)
        self.state={'binding':binding,'seq':0,'previous_hash':'','cursor':0,'tasks':{},'questions':{},'events':[]}
        if (self.root/'events.jsonl').exists():
            prev='';refs=[]
            for line in (self.root/'events.jsonl').read_bytes().splitlines():
                e=json.loads(line);h=e['event_sha256'];raw={k:v for k,v in e.items() if k!='event_sha256'}
                if e['previous_hash']!=prev or hashlib.sha256(canonical(raw).encode()).hexdigest()!=h:raise ValueError('Execution journal chain mismatch')
                saved=self.get(e['state_snapshot']);self.state={**saved,'seq':e['sequence'],'previous_hash':h,'events':[*refs,self.record(e)]};refs=self.state['events'];prev=h
            self.verify();self.save()
        elif (self.root/'checkpoint.json').exists():self.state=json.loads((self.root/'checkpoint.json').read_bytes());self.verify()
        if self.state['binding']!=binding:raise ValueError('Execution checkpoint input binding mismatch')
    def record(self,value):
        raw=canonical(value).encode();h=hashlib.sha256(raw).hexdigest();path=self.blobs/(h+'.json')
        if not path.exists():path.write_bytes(raw)
        elif path.read_bytes()!=raw:raise ValueError('Immutable record collision')
        return {'sha256':h,'path':'records/'+h+'.json'}
    def get(self,ref):
        p=self.root/ref['path'];raw=p.read_bytes()
        if hashlib.sha256(raw).hexdigest()!=ref['sha256']:raise ValueError('Immutable execution record changed')
        return json.loads(raw)
    def event(self,kind,**value):
        seq=self.state['seq']+1
        snapshot=self.record({k:v for k,v in self.state.items() if k not in {'seq','previous_hash','events'}})
        e={'binding':self.binding,'sequence':seq,'event_id':'evt-'+digest([self.binding,seq])[:24],'state_snapshot':snapshot,
           'previous_hash':self.state['previous_hash'],'kind':kind,'data':value}
        h=hashlib.sha256(canonical(e).encode()).hexdigest();e['event_sha256']=h
        with (self.root/'events.jsonl').open('a',encoding='utf-8') as f:f.write(canonical(e)+'\n');f.flush();os.fsync(f.fileno())
        self.state['seq']=seq;self.state['previous_hash']=h;self.state['events'].append(self.record(e));self.save()
        return e['event_id']
    def save(self):atomic(self.root/'checkpoint.json',self.state)
    def verify(self):
        prev='';events=[]
        for ref in self.state['events']:
            e=self.get(ref);h=e.pop('event_sha256')
            if e['previous_hash']!=prev or hashlib.sha256(canonical(e).encode()).hexdigest()!=h:raise ValueError('Execution event chain changed')
            prev=h;events.append(e)
        if len(events)!=self.state['seq'] or prev!=self.state['previous_hash']:raise ValueError('Checkpoint event position mismatch')
        for t in self.state['tasks'].values():
            for ref in t['origins']:self.get(ref)
        for q in self.state['questions'].values():
            for ref in q['origin_records']+q['actions']+q['tool_returns']:self.get(ref)
            for ref in q['evidence'].values():self.get(ref)
    def register(self,lead,origin,kind='INVESTIGATE',question_id=None):
        if not isinstance(lead,dict) or not isinstance(lead.get('method_id'),str) or lead.get('cwe') not in SUPPORTED_CWES:raise ValueError('Invalid investigation task identity')
        identity='task-'+digest([self.binding,lead['method_id'],lead['cwe'],kind,question_id,lead.get('hypothesis_id')])[:24]
        tasks=self.state['tasks'];ref=self.record({'lead':lead,'origin':origin})
        if identity not in tasks:
            tasks[identity]={'task_id':identity,'method_id':lead['method_id'],'cwe':lead['cwe'],'kind':kind,'question_id':question_id,
                'lead':copy.deepcopy(lead),'origins':[ref],'status':'QUEUED','version':1,'dispatches':0,'stages':[], 'pause':None}
            self.event('task_registered',task_id=identity,origin=ref);self.event('queue_admitted',task_id=identity)
        else:
            tasks[identity]['origins'].append(ref);self.event('proposal_preserved',task_id=identity,origin=ref,status=tasks[identity]['status'])
        return identity
    def ready(self,identity,trigger):
        t=self.state['tasks'][identity]
        if t['status']!='SCHEDULED':t['status']='QUEUED'
        t['version']+=1;t['pause']=None;self.event('task_reassessment_ready',task_id=identity,trigger=trigger,version=t['version'])
    def next(self):
        lanes=[(c,k) for c in SUPPORTED_CWES for k in ('REASSESS','INVESTIGATE')]
        for offset in range(len(lanes)):
            i=(self.state['cursor']+offset)%len(lanes);c,k=lanes[i]
            found=next((t for t in self.state['tasks'].values() if t['status']=='QUEUED' and (t['cwe'],t['kind'])==(c,k)),None)
            if found:
                self.state['cursor']=(i+1)%len(lanes);found['status']='SCHEDULED';found['dispatches']+=1
                self.event('task_scheduled',task_id=found['task_id'],lane=[c,k],next_cursor=self.state['cursor']);return found
        return None
    def stage(self,identity,stage,**data):
        if not identity:return
        t=self.state['tasks'][identity];ref=self.record(data);t['stages'].append({'stage':stage,'record':ref})
        self.event(stage,task_id=identity,record=ref)
    def pause_task(self,identity,reason,witness):
        t=self.state['tasks'][identity];t['status']='PAUSED';t['pause']={'reason':reason,'witness':self.record(witness)}
        self.event('task_paused',task_id=identity,**t['pause'])
    def question(self,task,text,actions,context,origin,provided_id=None,conditions=None):
        if provided_id is not None and not isinstance(provided_id,str):raise ValueError('Question identity must be a string')
        qid=provided_id or 'cq-'+digest([self.binding,task['method_id'],task['cwe'],text])[:24]
        qs=self.state['questions'];ref=self.record({'original_question':text,'actions':actions,'model_origin':origin,'task_id':task['task_id']})
        if qid in qs and (qs[qid]['original_question']!=text or qs[qid]['focus_id']!=task['method_id']):
            old=qid;qid='cq-'+digest([qid,task['method_id'],task['cwe'],text])[:24]
            self.event('question_identity_conflict_preserved',model_question_id=old,fork_id=qid,new_origin=ref)
        if qid not in qs:
            qs[qid]={'question_id':qid,'original_question':text,'focus_id':task['method_id'],'cwe':task['cwe'],'origin_task_id':task['task_id'],
                     'origin_records':[],'actions':[],'tool_returns':[],'evidence':{},'unresolved_conditions':conditions or [],'conditions_status':'EXPLICIT' if conditions else 'NOT_EXPLICITLY_STATED',
                     'last_valid_decision':None,'observations':[],'status':'OPEN','evidence_version':0,'last_judged_version':-1,'pause':None}
        q=qs[qid]
        q['origin_records'].append(ref)
        for a in actions:
            ar=self.record(a)
            if ar not in q['actions']:q['actions'].append(ar)
        for p in context.get('source_evidence',[]):q['evidence'].setdefault(p['evidence_id'],self.record(p))
        self.event('critical_question_registered',question_id=qid,origin=ref,action_records=q['actions'])
        if actions:
            tid=self.register({'method_id':q['focus_id'],'cwe':q['cwe'],'reason':q['original_question']},{'question_id':qid,'model_origin':origin},'REASSESS',qid)
            unfinished=[a for a in actions if not any(self.get(r)['action']==a for r in q['tool_returns'])]
            if unfinished and self.state['tasks'][tid]['status'] in {'PAUSED','DECIDED'}:self.ready(tid,{'unexecuted_explicit_actions':unfinished,'question_id':qid})
        return q
    def tool(self,task,action,result):
        for q in self.state['questions'].values():
            if q['focus_id']!=task['method_id'] or action not in [self.get(r) for r in q['actions']]:continue
            receipt=self.record({'action':action,'return':result,'task_id':task['task_id']});q['tool_returns'].append(receipt)
            self.event('critical_action_executed',question_id=q['question_id'],receipt=receipt)
            if isinstance(result,dict) and result.get('evidence_id') and result.get('source'):
                ref=self.record(result);old=q['evidence'].get(result['evidence_id'])
                if old and old!=ref:raise ValueError('Evidence ID changed content')
                if old is None:
                    q['evidence'][result['evidence_id']]=ref;q['evidence_version']+=1;q['status']='REASSESSMENT_READY';q['pause']=None
                    tid=self.register({'method_id':q['focus_id'],'cwe':q['cwe'],'reason':q['original_question']},{'question_id':q['question_id'],'tool_return':receipt},'REASSESS',q['question_id'])
                    self.ready(tid,{'question_id':q['question_id'],'new_evidence':ref})
    def judge(self,qid,update,visible,origin):
        q=self.state['questions'].get(qid)
        if not q:return
        refs=update.get('evidence_refs',[]);status=update.get('status')
        valid=(isinstance(refs,list) and bool(refs) and all(isinstance(x,str) and x in visible for x in refs)
               and isinstance(update.get('answer'),str) and bool(update['answer'].strip()) and status in {'ANSWERED','REFUTED','UNRESOLVED'})
        ref=self.record({'raw':update,'origin':origin,'references_valid':valid});q['observations'].append(ref)
        if valid:
            q['last_valid_decision']=ref;q['last_judged_version']=q['evidence_version'];q['status']='MODEL_'+status
            if status in {'ANSWERED','REFUTED'}:q['pause']=None
            if isinstance(update.get('unresolved_conditions'),list):q['unresolved_conditions']=update['unresolved_conditions'];q['conditions_status']='EXPLICIT'
        self.event('critical_question_decision',question_id=qid,record=ref,accepted_as_explicit_judgment=valid)
    def pause_question(self,qid,reason,witness):
        q=self.state['questions'][qid]
        if q['status'] in {'MODEL_ANSWERED','MODEL_REFUTED'}:return
        q['status']='PAUSED';q['pause']={'reason':reason,'witness':self.record(witness)};self.event('critical_question_paused',question_id=qid,**q['pause'])

class ExecutionController:
    def __init__(self,runner,archive,binding,critical=False,budget=None):
        self.r=runner;self.archive=archive;self.book=ExecutionState(runner.output/'execution',binding)
        self.critical=critical;self.budget=budget;self.current=None;self.context={};self.origin={};self.role=None
        if binding.startswith('TEST_ONLY'):atomic(runner.output/'TEST_ONLY.json',{'test_only':True,'eligible_for_detection_metric':False,'real_model_requests':0})
        self.core=runner.targeted_original_core['original_core_object'].__get__(runner,type(runner))
        self.old_ask,self.old_request,self.old_event,self.old_candidate,self.old_review=runner.ask,runner.request,runner.event,runner.candidate,runner.review
        self.in_review=False;self.deferred=self.book.state.setdefault('candidate_deferrals',[])
        if budget is not None:budget.engine=self
        runner.enqueue=self.enqueue;runner.ask=self.ask;runner.request=self.request;runner.event=self.event;runner.run=self.run;runner.review=self.verify_pending;runner.candidate=self.candidate
        self.restore_completed_state()
    def restore_completed_state(self):
        pending={};exposed={};logical_calls=0;usage={};r=self.r
        tools=0
        for ref in list(self.book.state['events']):
            event=self.book.get(ref);kind=event['kind'];data=event['data']
            if kind=='model_input_global':pending[data['role']]=self.book.get(data['context'])
            elif kind=='model_logical_response_global':
                logical_calls+=1
                for k,v in data['usage'].items():
                    if type(v)is int:usage[k]=usage.get(k,0)+v
                for p in pending.pop(data['role'],{}).get('source_evidence',[]):exposed[p['evidence_id']]=p
            elif kind=='candidate_accepted':
                value=self.book.get(data['record']);c=value['candidate'];r.candidates[c['candidate_path_id']]=c
            elif kind=='verification_decisions_saved':r.reviews.update(self.book.get(data['reviews']))
            elif kind=='tool_budget_snapshot':tools=max(tools,data['tool_calls'])
        for task in self.book.state['tasks'].values():
            for stage in task['stages']:
                if stage['stage']=='source_read':
                    p=self.book.get(stage['record'])['proof']
                    if 'method_id' in p:r.evidence[p['evidence_id']]=p
        if self.book.state['events']:r.activate_reads()
        for p in exposed.values():
            if 'method_id' in p:r.evidence[p['evidence_id']]=p
            else:self.archive[p['evidence_id']]=p
        r.restore_evidence_exposure(exposed.values());r.model_calls=logical_calls;r.usage.clear();r.usage.update(usage);r.tool_calls=tools
        r.explored.update((t['method_id'],t['cwe']) for t in self.book.state['tasks'].values() if t['dispatches'])
        for t in self.book.state['tasks'].values():
            if t['status']=='SCHEDULED':self.book.pause_task(t['task_id'],'PROCESS_INTERRUPTED_REQUIRES_EXPLICIT_RESUME',{'last_known_stages':t['stages'],'no_automatic_reexecution':True})
        self.sync_queue()
    def enqueue(self,lead,front=False):
        if not isinstance(lead,dict) or not isinstance(lead.get('method_id'),str) or lead['method_id'] not in self.r.methods:raise ValueError('Task requires exact existing method ID')
        tid=self.book.register(lead,{'model_origin':self.origin,'evidence_ids':[p['evidence_id'] for p in self.context.get('source_evidence',[])],'requested_front':front})
        self.sync_queue();return tid
    def sync_queue(self):
        self.r.queue=[t['lead'] for t in self.book.state['tasks'].values() if t['status']=='QUEUED'];self.r.queued={(t['method_id'],t['cwe']) for t in self.book.state['tasks'].values()}
    def event(self,name,**data):
        self.old_event(name,**data)
        tid=self.current['task_id'] if self.current else None
        if name=='source_read':self.book.stage(tid,'source_read',proof=data)
        if name=='model_input':self.book.stage(tid,'reasoning_request_prepared' if data['role']=='reasoning' else 'model_request_prepared',**data)
        if name=='model_response':self.book.stage(tid,'actual_logical_model_response',**data)
        if name=='candidate_submitted':self.book.stage(tid,'candidate_accepted',**data)
        if name=='model_input':self.book.event('model_input_global',role=data['role'],context=self.book.record(data['context']))
        if name=='model_response':self.book.event('model_logical_response_global',role=data['role'],usage=data['usage'],content=self.book.record(data['content']),logical_origin=self.book.record(getattr(getattr(self.r.team,data['role']),'last_receipt',{'kind':'TEST_ONLY_OR_LEGACY_FIXTURE_NO_PHYSICAL_RECEIPT'})))
        if name in {'source_read','targeted_tool_result','retrieval_failed','resource_evidence_package'}:self.book.event('tool_budget_snapshot',tool_calls=self.r.tool_calls)
    def request(self,action):
        result=self.old_request(action)
        if self.current:self.book.tool(self.current,action,result)
        return result
    def ask(self,role,context):
        if role=='reasoning' and not self.in_review:self.verify_pending()
        if self.r.stop:return {}
        self.context=context;self.role=role
        if role=='reasoning' and self.current:
            q=[q for q in self.book.state['questions'].values() if q['focus_id']==self.current['method_id'] and q['status'] not in {'MODEL_ANSWERED','MODEL_REFUTED'}]
            proofs={p['evidence_id']:p for p in context['source_evidence']}
            for question in q:
                for eid,ref in question['evidence'].items():proofs.setdefault(eid,self.book.get(ref))
            context={**context,'source_evidence':list(proofs.values()),'investigation_task':{k:self.current[k] for k in ['task_id','method_id','cwe','kind','question_id','version']},
                     'critical_evidence_closure':{'questions':[{**{k:x[k] for k in ['question_id','original_question','status','unresolved_conditions','evidence_version']},'question':x['original_question'],
                         'last_valid_decision':self.book.get(x['last_valid_decision']) if x['last_valid_decision'] else None,
                         'executed_actions':[self.book.get(ref) for ref in x['tool_returns']]} for x in q]}}
            self.context=context
        value=self.old_ask(role,context)
        self.origin={'role':role,'request_context':self.book.record(context),'response':self.book.record(value)}
        if role=='reasoning' and self.current:
            self.book.stage(self.current['task_id'],'subsequent_decision',raw_response=value,model_origin=self.origin)
            self.current['last_response']=self.book.record(value)
            actions=value.get('requests',[])[:4]
            if self.critical:
                entries=value.get('critical_questions',[])
                if not isinstance(entries,list):entries=[]
                for entry in entries[:2]:
                    if not isinstance(entry,dict) or not isinstance(entry.get('question'),str):continue
                    inds=entry.get('request_indices',[])
                    if not isinstance(inds,list) or any(type(i)is not int or not 0<=i<len(actions) for i in inds):continue
                    try:self.book.question(self.current,entry['question'],[actions[i] for i in inds],context,self.origin,entry.get('question_id'),entry.get('unresolved_conditions'))
                    except ValueError as e:self.book.event('question_protocol_error',raw=entry,error=str(e))
                updates=value.get('question_updates',[])
                if isinstance(updates,list):
                    for update in updates:
                        if isinstance(update,dict):self.book.judge(update.get('question_id'),update,{p['evidence_id'] for p in context['source_evidence']},self.origin)
        return value
    def candidate(self,draft):
        if self.budget is None:return self.old_candidate(draft)
        # Same original validator, buffered until actual verification reservation
        # fits. Resource deferral is not a semantic rejection or a lost draft.
        saved=self.r.candidates;events=[];event=self.r.event
        self.r.candidates=copy.deepcopy(saved);self.r.event=lambda name,**data:events.append((name,data))
        try:
            identity=self.old_candidate(draft);planned=self.r.candidates
        finally:self.r.candidates=saved;self.r.event=event
        if identity in saved:return identity
        if not self.budget.can_accept(planned,self.r.reviews):
            ref=self.book.record({'valid_original_A1_draft':draft,'validated_candidate':planned.get(identity),'reason':'INSUFFICIENT_ACTUAL_VERIFICATION_RESERVATION'})
            self.deferred.append(ref);self.book.event('valid_candidate_resource_deferred',record=ref)
            return None
        self.r.candidates=planned
        for name,data in events:self.r.event(name,**data)
        return identity
    def verify_pending(self):
        if self.in_review:return
        pending=[k for k in self.r.candidates if k not in self.r.reviews]
        if not pending:return
        self.in_review=True;saved=self.r.candidates;self.review_all=saved;stop=self.r.stop;incomplete=[]
        try:
            for i in range(0,len(pending),4):
                batch=pending[i:i+4];self.r.candidates={k:saved[k] for k in batch};self.r.stop=None
                self.old_review()
                self.book.event('verification_decisions_saved',candidate_ids=batch,reviews=self.book.record({k:self.r.reviews[k] for k in batch if k in self.r.reviews}))
                missing=[k for k in batch if k not in self.r.reviews]
                if missing:incomplete.extend(missing);self.book.event('verification_incomplete',candidate_ids=missing,stop=self.r.stop)
        finally:self.r.candidates=saved;self.r.stop=stop or ('VERIFICATION_INCOMPLETE' if incomplete else None);self.in_review=False
    def dispatch(self,task):
        self.current=task;self.r.explored.add((task['method_id'],task['cwe']))
        model_calls_before=self.r.model_calls
        if task['question_id']:
            q=self.book.state['questions'][task['question_id']]
            for ref in q['actions'][:2]:
                action=self.book.get(ref)
                if any(self.book.get(t)['action']==action for t in q['tool_returns']):continue
                try:self.r.request(action)
                except (ValueError,KeyError,TypeError,AttributeError) as e:self.book.event('critical_tool_failure',question_id=q['question_id'],action=ref,error=str(e))
        self.core(task['lead'])
        unresolved=[q for q in self.book.state['questions'].values() if q['focus_id']==task['method_id'] and q['status'] not in {'MODEL_ANSWERED','MODEL_REFUTED'}]
        if self.r.stop or self.r.model_calls==model_calls_before:
            self.book.pause_task(task['task_id'],self.r.stop or 'NO_LOGICAL_REASONING_RESPONSE',{'model_calls_before':model_calls_before,'model_calls_after':self.r.model_calls,'tool_calls':self.r.tool_calls})
        elif unresolved:
            self.book.pause_task(task['task_id'],'BOUNDED_ORIGINAL_LOOP_ENDED_WITH_OPEN_QUESTIONS',{'question_ids':[q['question_id'] for q in unresolved],'model_calls':self.r.model_calls,'tool_calls':self.r.tool_calls})
        elif task.get('last_response') and self.book.get(task['last_response']).get('requests'):
            self.book.pause_task(task['task_id'],'MODEL_REQUESTS_REMAIN_AFTER_BOUNDED_TURN',{'last_model_response':task['last_response'],'tool_calls':self.r.tool_calls})
        else:
            task['status']='DECIDED';self.book.event('task_decided',task_id=task['task_id'])
        self.current=None;self.sync_queue()
    def run(self):
        inventory,ranked,all_rows=self.r.inventory()
        atomic(self.r.output/'discovery-inventory.json',{'total_methods':len(all_rows),'visible_methods':len(inventory),'methods':inventory})
        base=__import__(self.core.__func__.__module__,fromlist=['KNOWLEDGE'])
        if self.book.state.get('discovery_completed'):
            value=self.book.get(self.book.state['discovery_completed'])
            self.origin=self.book.state.get('discovery_origin',{'role':'discovery','origin_status':'LEGACY_CHECKPOINT_ORIGIN_NOT_RECONSTRUCTABLE'})
        else:
            value=self.r.ask('discovery',{'supported_cwes':list(SUPPORTED_CWES),'inventory':inventory,'guidance':{c:[v[2] for v in base.KNOWLEDGE[c]] for c in SUPPORTED_CWES}})
            if not self.r.stop:
                self.book.state['discovery_completed']=self.book.record(value);self.book.state['discovery_origin']=self.origin;self.book.event('discovery_completed',response=self.book.state['discovery_completed'])
        proposed=value.get('leads',[])[:12]
        for lead in proposed:
            try:self.enqueue(lead)
            except (ValueError,AttributeError) as e:self.book.event('proposal_rejected',raw=lead,error=str(e))
        discovery_origin=self.origin;self.origin={'role':'static_fallback','source':'ORIGINAL_STABLE_STATIC_BOUNDARY_RECALL'}
        for rank in range(min(4,len(all_rows))):
            for cwe in SUPPORTED_CWES:
                if ranked[cwe]:self.enqueue({'method_id':ranked[cwe][rank],'cwe':cwe,'reason':'Original static/boundary recall fallback.'})
        self.origin=discovery_origin
        dispatched=sum(t['dispatches'] for t in self.book.state['tasks'].values())
        cooperative=getattr(self,'cooperative_scheduler',None)
        if cooperative is not None:
            cooperative(self)
            dispatched=sum(t['dispatches'] for t in self.book.state['tasks'].values())
        while cooperative is None and not self.r.stop and dispatched<self.r.limits.max_focus:
            if self.r.request_headroom()<1 or self.r.tool_calls>=self.r.tool_limit-3:break
            task=self.book.next()
            if task is None:break
            dispatched+=1
            try:self.dispatch(task)
            except (ValueError,KeyError,TypeError) as e:
                self.book.pause_task(task['task_id'],'TOOL_OR_STATE_FAILURE',{'error':str(e)});self.r.last_error='TOOL_OR_STATE_ERROR';break
        self.verify_pending()
        reason=self.r.stop or self.r.last_error or getattr(self,'actual_stop_trigger',None) or ('TASK_LIMIT' if any(t['status']=='QUEUED' for t in self.book.state['tasks'].values()) else 'GRAPH_COMPLETE')
        for q in self.book.state['questions'].values():
            pending=[r for r in q['actions'] if not any(self.book.get(t)['action']==self.book.get(r) for t in q['tool_returns'])]
            pause_reason=reason if reason!='GRAPH_COMPLETE' else ('UNEXECUTED_ACTION_REQUIRES_NEW_DISPATCH' if pending else 'NO_NEW_EXECUTABLE_ACTION_WITH_AVAILABLE_TOOLS')
            if q['status'] not in {'MODEL_ANSWERED','MODEL_REFUTED'}:self.book.pause_question(q['question_id'],pause_reason,{'dispatches':dispatched,'max_dispatches':self.r.limits.max_focus,'remaining_requests':self.r.request_headroom(),'tool_calls':self.r.tool_calls,'unexecuted_action_records':pending,'tool_returns':q['tool_returns']})
        for c in self.r.candidates.values():c['filter_verdict']=self.r.reviews.get(c['candidate_path_id'],{}).get('verdict','NOT_REVIEWED')
        artifacts={'candidates':list(self.r.candidates.values()),'reviews':list(self.r.reviews.values()),'benchmark-candidates':[c for c in self.r.candidates.values() if c['filter_verdict']!='REJECTED'],'source-evidence':list(self.r.evidence.values())}
        for name,values in artifacts.items():(self.r.output/(name+'.jsonl')).write_text(''.join(canonical(v)+'\n' for v in values),encoding='utf-8')
        summary={'stage':'A1_SERIAL_EXECUTION_CHAIN','test_only':self.book.binding.startswith('TEST_ONLY'),'limits':asdict(self.r.limits),'stop_reason':reason,'model_calls':self.r.model_calls,'tool_calls':self.r.tool_calls,'reported_usage':dict(self.r.usage),'candidate_paths':len(self.r.candidates),'benchmark_candidates':len(artifacts['benchmark-candidates']),'unreviewed':len(set(self.r.candidates)-set(self.r.reviews)),'resource_deferred_valid_drafts':self.deferred,'task_states':{status:sum(t['status']==status for t in self.book.state['tasks'].values()) for status in ['QUEUED','SCHEDULED','PAUSED','DECIDED']},'queued_unexplored':sum(t['status']=='QUEUED' for t in self.book.state['tasks'].values()),'protocol_failed_nodes':[self.r.last_error] if self.r.last_error else []}
        atomic(self.r.output/'run.json',summary);self.book.save();self.r.trace.close();return summary
