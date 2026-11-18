"""Source-selected review tasks using the existing A1 loop and tools only."""
from collections import defaultdict
import copy,re,hashlib
from pathlib import Path
from dataclasses import replace
from .benchmark import digest,source_safe
from .targeted_a1 import _web_surfaces
from .source_window import validate_method_read
from .a1_resource_evidence import extract_selected_step
from .resource_references import local_path,resource_identity

TRAVERSE={'getFirstChild','getLastChild','getNextSibling','getPreviousSibling','getChildNodes','getElementsByTagName'}
MUTATE={'removeChild','replaceChild','appendChild','insertBefore','setNodeValue','setTextContent'}
KINDS=('WEB_SURFACE','DOM_TRANSFORM','ENCODING_USE')
QUESTIONS={
 'WEB_SURFACE':['Trace actual request binding and field reads/writes in the supplied business entry group.','Trace persistence calls, the same record identity, query/list responses, templates/scripts and actual output contexts.','Check guards and their scope at every concrete boundary; request missing implementations. Same-named fields or shared columns do not prove propagation.'],
 'DOM_TRANSFORM':['Determine which child nodes are visited and which data is filtered or scanned.','Trace replacement, aggregation, deletion, later processing and final serialization.','Distinguish local protection from guarantees for the complete transformation/output; investigate source-bound gaps that can change the judgment.'],
 'ENCODING_USE':['Check actual caller edges, argument values and caller-provided encoding context.','Trace returned values through intermediate transformations to actual HTML, JavaScript, template or other consumers.','Match versioned contracts to those concrete uses and guards. A local encoder contract does not establish an application vulnerability. Require source-supported invocation/use for an application claim; preserve the missing caller/consumer boundary when unavailable.']}

def catalog(runner,dependencies):
    runner.activate_reads();plans=[]
    def describe(identity):
        m=runner.methods[identity]
        return {'method_id':identity,'file':m.repository_relative_path,'start_line':m.start_line,'end_line':m.end_line,'name':m.qualified_name,'signature':m.signature}
    def add(kind,identities,facts):
        identities=sorted(set(identities),key=lambda i:(runner.methods[i].repository_relative_path,runner.methods[i].start_line,i))
        if not identities:return
        identity='mechanism-'+digest([kind,[describe(i) for i in identities],facts])[:24]
        plans.append({'mechanism_id':identity,'kind':kind,'method_ids':identities,'source_boundaries':[describe(i) for i in identities],
                      'navigation_facts':facts,'questions':QUESTIONS[kind],
                      'selection':'SOURCE_BEHAVIOR_AND_EXISTING_INDEX_ONLY_STABLE_FILE_LINE_ORDER','proof_status':'NAVIGATION_NOT_ESTABLISHED_FLOW'})
    surfaces,_=_web_surfaces(runner);groups=defaultdict(list)
    for surface in surfaces:groups[surface['file']].append(surface)
    files=sorted(groups)
    # A bounded group of business classes is reviewed as one task. No model
    # proposal is required to admit a source-visible business surface.
    for file in files:
        rows=sorted(groups[file],key=lambda row:(runner.methods[row['method_id']].start_line,row['method_id']))
        for first in range(0,len(rows),3):
            batch=rows[first:first+3]
            add('WEB_SURFACE',[row['method_id'] for row in batch],batch)
    dom=defaultdict(list);enc=defaultdict(list);dom_calls=defaultdict(list)
    classes={d['class'] for d in dependencies}
    for identity,m in sorted(runner.methods.items(),key=lambda item:(item[1].repository_relative_path,item[1].start_line,item[0])):
        if identity not in runner.ast_ids:continue
        calls=runner.ast.calls.get(runner.ast_ids[identity],[]);names={call['name'].split('.')[-1] for call in calls}
        text='\n'.join(runner.sources[m.repository_relative_path])
        if 'org.w3c.dom' in text and names&(TRAVERSE|MUTATE):
            dom[m.repository_relative_path].append(identity);dom_calls[m.repository_relative_path].extend(c for c in calls if c['name'] in TRAVERSE|MUTATE)
        imports=set(re.findall(r'\bimport\s+([\w.]+)\s*;',text))
        aliases={cls.rsplit('.',1)[-1] for cls in imports&classes}
        matched=[c for c in calls if c.get('receiver') in aliases]
        if matched:enc[m.repository_relative_path].append((identity,matched))
    for file,identities in sorted(dom.items()):
        names={c['name'] for c in dom_calls[file]}
        if names&TRAVERSE and names&MUTATE:
            for identity in identities:
                m=runner.methods[identity]
                add('DOM_TRANSFORM',[identity],{'file':file,'actual_AST_calls':[c for c in dom_calls[file] if m.start_line<=c['line']<=m.end_line],
                     'parent_problem':'Preserve the DOM traversal/filter/replace/delete/output question across these exact method boundaries; other CSS or policy-loading questions do not close this problem.',
                     'receiver_resolution':'DOM imports/call sites select scope; actual source decides receiver and behavior'})
    for file,entries in sorted(enc.items()):
        for identity,calls in entries:
            add('ENCODING_USE',[identity],{'file':file,'version_bound_classes':sorted(classes),'actual_AST_calls':[{'method_id':identity,'calls':calls}]})
    return sorted(plans,key=lambda p:(KINDS.index(p['kind']),p['source_boundaries'][0]['file'],p['source_boundaries'][0]['start_line'],p['mechanism_id']))

def install(engine,dependencies=()):
    r=engine.r;book=engine.book
    inventory,dispatch,ask,next_task,event,question,judge=r.inventory,engine.dispatch,r.ask,book.next,r.event,book.question,book.judge
    active={'plan':None,'actual_context':None,'last_read_error':None,'feedback':[],'actions':[]};plans={};prepared={};resources=defaultdict(dict);delivered={}
    original_request,original_read,original_candidate,original_run,original_enqueue=r.request,r.read,r.candidate,r.run,r.enqueue
    def bind_task(task):
        plan=current_plan(task);m=r.methods.get(task['method_id'])
        task.setdefault('problem_id',task.get('followup_of',task['task_id']))
        task.setdefault('question',task['lead'].get('reason','Source-bound investigation'))
        task.setdefault('source_origins',list(task['origins']))
        task.setdefault('required_source_ranges',plan['source_boundaries'] if plan else ([{'method_id':task['method_id'],'file':m.repository_relative_path,'start_line':m.start_line,'end_line':m.end_line}] if m else []))
        return task
    def current_plan(task):
        if not task:return None
        identity=task.get('mechanism_id') or task['lead'].get('hypothesis_id')
        if task.get('question_id'):identity=book.state['questions'][task['question_id']].get('mechanism_id',identity)
        return plans.get(identity)
    def register():
        if 'mechanism_catalog' in book.state:
            values=book.get(book.state['mechanism_catalog'])
        else:
            values=catalog(r,dependencies);book.state['mechanism_catalog']=book.record(values)
            book.event('mechanism_catalog_created',catalog=book.state['mechanism_catalog'])
        plans.update({p['mechanism_id']:p for p in values})
        for plan in values:
            tid=book.register({'method_id':plan['method_ids'][0],'cwe':'CWE-79','hypothesis_id':plan['mechanism_id'],
                'reason':'Source-bound '+plan['kind']+' behavior review; anchor is navigation, all provided group boundaries are in scope.'},
                {'role':'source_mechanism_registration','catalog':book.state['mechanism_catalog'],'mechanism_id':plan['mechanism_id']},'MECHANISM')
            book.state['tasks'][tid]['mechanism_id']=plan['mechanism_id']
            bind_task(book.state['tasks'][tid])
        book.event('mechanism_tasks_admitted',mechanism_ids=list(plans));engine.sync_queue()
    def inventory_hook():
        result=inventory();register();return result
    def choose():
        # Source-file rotation prevents a large controller from monopolizing
        # coverage. Two mechanism turns alternate with one original lane turn.
        phase=book.state.get('r2_lane_phase',0);cursor=book.state.get('mechanism_kind_cursor',0)
        candidates=[t for t in book.state['tasks'].values() if t['kind']=='MECHANISM' and t['status']=='QUEUED']
        if candidates and phase<2:
            fresh=[t for t in candidates if not t.get('followup_of')]
            pool=fresh or candidates;found=None
            for offset in range(len(KINDS)):
                index=(cursor+offset)%len(KINDS)
                typed=[t for t in pool if current_plan(t) and current_plan(t)['kind']==KINDS[index]]
                if not typed:continue
                files=sorted({current_plan(t)['source_boundaries'][0]['file'] for t in typed})
                last=book.state.setdefault('r2_last_file',{}).get(KINDS[index])
                ordered=[f for f in files if last is None or f>last]+[f for f in files if last is not None and f<=last]
                file=ordered[0];found=next(t for t in typed if current_plan(t)['source_boundaries'][0]['file']==file)
                book.state['r2_last_file'][KINDS[index]]=file;break
            if found:
                found['status']='SCHEDULED';found['dispatches']+=1;book.state['r2_lane_phase']=phase+1;book.state['mechanism_kind_cursor']=(index+1)%len(KINDS)
                book.event('task_scheduled',task_id=found['task_id'],lane=['MECHANISM',KINDS[index]],source_file=file);return found
        found=next_task();book.state['r2_lane_phase']=0
        if found:return found
        if candidates:return choose()
        return None
    def execute(action,task,outputs):
        try:
            value=r.request(action);outputs.append({'action':action,'result':value})
            failed=isinstance(value,dict) and (value.get('read_succeeded') is False or value.get('status') in {'not_found','invalid_window','invalid_identity','invalid_request'})
            book.stage(task['task_id'],'mechanism_tool_gap' if failed else 'mechanism_tool_action',action=action,result=value)
            return value
        except (ValueError,KeyError,TypeError,AttributeError) as error:
            value={'action':action,'error':str(error)};outputs.append(value);book.stage(task['task_id'],'mechanism_tool_gap',**value);return None
    def prepare(plan,task):
        if plan['mechanism_id'] in prepared:return prepared[plan['mechanism_id']]
        result={'source_evidence':{},'tool_results':[],'unread_boundaries':[],'caller_edges':[]}
        identities=list(plan['method_ids'])
        if plan['kind']=='ENCODING_USE':
            graph=r.retrieval.graph
            for identity in list(identities):
                value=execute({'action':'follow_graph','entity_id':identity},task,result['tool_results'])
                # Only existing, resolved incoming CodeQL edges admit caller
                # bodies automatically. Literal search hits remain unresolved.
                for edge in graph.by_entity.get(identity,[]) if graph else []:
                    if edge['kind'] not in {'CODEQL_CALL','CODEQL_DIRECT_CALL','CODEQL_VIRTUAL_DISPATCH'} or edge['to']['entity_id']!=identity:continue
                    caller=edge['from']['entity_id']
                    if caller not in r.methods:continue
                    identities.append(caller);result['caller_edges'].append(edge)
                m=r.methods[identity]
                execute({'action':'search_code','query':m.simple_name+'('},task,result['tool_results'])
        for identity in dict.fromkeys(identities):
            m=r.methods[identity]
            for first in range(m.start_line,m.end_line+1,160):
                last=min(m.end_line,first+159)
                if r.tool_calls>=r.tool_limit-3:
                    result['unread_boundaries'].append({'method_id':identity,'start_line':first,'end_line':last,'reason':'ACTUAL_TOOL_BUDGET'});continue
                value=execute({'action':'inspect_entity','entity_id':identity,'start_line':first,'end_line':last},task,result['tool_results'])
                if isinstance(value,dict) and value.get('source') and value.get('evidence_id'):result['source_evidence'][value['evidence_id']]=value
                else:result['unread_boundaries'].append({'method_id':identity,'start_line':first,'end_line':last,'reason':'SOURCE_READ_NOT_RECONSTRUCTED','tool_result':value})
        prepared[plan['mechanism_id']]=result;book.stage(task['task_id'],'mechanism_prepared',mechanism_id=plan['mechanism_id'],preparation=book.record(result));return result
    def request_hook(action):
        if r.tool_calls>=r.tool_limit:return {'status':'budget_not_admitted','read_succeeded':False,'error':'Actual tool limit','requested':action}
        refusal=validate_method_read(action,r)
        if refusal is not None:
            if not refusal.get('candidates'):
                scope=(active['actual_context'] or {}).get('related_methods',[])
                refusal['scope_candidates']=[{k:v for k,v in row.items() if k in {'method_id','name','file','start_line','end_line','signature'}} for row in scope]
            r.tool_calls+=1;r.event('source_read_refused',request=action,result=refusal);return refusal
        if action.get('action')=='read_file_range':
            file=action.get('file');path=local_path(r.tools.index.repository_root,file) if isinstance(file,str) else None
            first,last=action.get('start_line'),action.get('end_line')
            if path is None or type(first)is not int or type(last)is not int or not 1<=first<=last or last-first+1>160:
                value={'status':'invalid_window','read_succeeded':False,'error':'File read requires an exact repository-relative file and an explicit1..160-line range','requested':action};r.event('source_read_refused',request=action,result=value);return value
            try:count=len(path.read_text(encoding='utf-8').splitlines())
            except (OSError,UnicodeError) as error:return {'status':'file_read_failed','read_succeeded':False,'error':str(error),'requested':action}
            if last>count:return {'status':'invalid_window','read_succeeded':False,'error':'Requested range exceeds the actual file','file_lines':count,'requested':action}
            if r.tool_calls>=r.tool_limit:return {'status':'budget_not_admitted','read_succeeded':False,'error':'Actual tool limit'}
            r.tool_calls+=1
            try:raw=r.tools.read_file_range(file,first,last,max_lines=160)
            except (ValueError,OSError,UnicodeError) as error:return {'status':'file_read_failed','read_succeeded':False,'error':str(error),'requested':action}
            h=hashlib.sha256(path.read_bytes()).hexdigest();identity=resource_identity(file,h)
            value={'file':file,'file_sha256':h,'start_line':first,'end_line':raw['end_line'],'source':source_safe(raw['text']),'content_sha256':digest(raw['lines'])}
            if path.suffix.lower()=='.java':
                value.update(file_id='file-'+digest([file,h])[:24],evidence_id='fsrc-'+digest([file,h,first,raw['end_line']])[:24],candidate_step_eligible=False)
                value['method_declarations']=[r.ast.describe(m) for m in r.ast.by_file.get(file,[]) if m.start_line<=raw['end_line'] and first<=m.end_line]
            else:
                count=len(path.read_text().splitlines());value.update(resource_id=identity,unknown_ranges=([[1,first-1]] if first>1 else [])+([[raw['end_line']+1,count]] if raw['end_line']<count else []))
                value['evidence_id']='rsrc-'+digest([identity,first,raw['end_line'],value['content_sha256']])[:24]
                prior=engine.archive.get(value['evidence_id'])
                if prior is not None:value=prior
                else:engine.archive[value['evidence_id']]=value
            r.event('file_source_read',request=action,proof=value)
            if engine.current:book.tool(engine.current,action,value)
            return value
        try:return original_request(action)
        except (ValueError,KeyError,TypeError,AttributeError) as error:
            value={'status':'tool_failed','read_succeeded':False,'requested':action,'error':str(error)};r.event('tool_request_failed',request=action,result=value);return value
    def read_hook(identity,start=None,end=None):
        action={'action':'inspect_entity','entity_id':identity}
        if start is not None:action['start_line']=start
        if end is not None:action['end_line']=end
        error=validate_method_read(action,r)
        if error:
            active['last_read_error']=error;r.event('source_read_refused',request=action,result=error)
            raise ValueError('SOURCE_IDENTITY_OR_RANGE_SELECTION_REQUIRED')
        try:return original_read(identity,start,end)
        except ValueError:
            if r.tool_calls<r.tool_limit:raise
            active['last_read_error']={'status':'budget_not_admitted','read_succeeded':False,'error':'Actual tool-read limit'}
            raise
    def candidate_hook(draft):
        if not isinstance(draft,dict) or not isinstance(draft.get('steps'),list):return original_candidate(draft)
        context=active['actual_context'] or {};visible={p['evidence_id']:p for p in context.get('source_evidence',[])}
        for row in context.get('evidence_catalog',[]):
            if row.get('evidence_id') in delivered:visible.setdefault(row['evidence_id'],delivered[row['evidence_id']])
        built=copy.deepcopy(draft);changed=False
        for index,step in enumerate(built['steps']):
            if not isinstance(step,dict) or 'expression' in step:continue
            if not isinstance(step.get('evidence_id'),str) or step['evidence_id'] not in visible:raise ValueError('Position selector must name a delivered source evidence_id in the actual visible scope')
            built['steps'][index]=extract_selected_step(step,visible[step['evidence_id']],r.methods);changed=True
        if changed:book.stage(engine.current['task_id'] if engine.current else None,'candidate_evidence_constructed',raw=book.record(draft),constructed=book.record(built))
        return original_candidate(built)
    def continuation(task):
        if not active['actions'] and not active['feedback']:return
        result=active['actions'];scope=current_plan(task);problem=task.get('problem_id',task['task_id'])
        signature=digest([problem,result,active['feedback']])[:24]
        tid=book.register({**task['lead'],'hypothesis_id':'r2-followup-'+signature,'reason':task['question']},
              {'role':'R2_ACTUAL_TOOLS_AND_DECISION_CONTINUATION','parent_task':task['task_id'],'problem_id':problem,'actions':book.record(result)},'MECHANISM' if scope else 'REASSESS')
        next_=book.state['tasks'][tid];next_['followup_of']=task['task_id'];next_['problem_id']=problem;next_['question']=task['question'];next_['tool_delivery']=book.record(result);next_['candidate_feedback']=list(active['feedback'])
        if scope:next_['mechanism_id']=scope['mechanism_id']
        bind_task(next_);task['next_task_id']=tid;book.event('r2_continuation_admitted',task_id=tid,parent_task=task['task_id'],problem_id=problem)
    def dispatch_hook(task):
        bind_task(task);plan=current_plan(task);active['plan']=plan;active['actions']=[];active['feedback']=[];active['last_read_error']=None
        if plan:
            engine.current=task;prepare(plan,task);book.event('mechanism_dispatched',task_id=task['task_id'],mechanism_id=plan['mechanism_id'])
        limits=r.limits;r.limits=replace(limits,calls_per_focus=0)
        headroom=r.request_headroom
        r.request_headroom=lambda:headroom()+int(r.limits.light_review and not(set(r.candidates)-set(r.reviews)))
        try:
            answer=dispatch(task);continuation(task)
            observed=any(s['stage']=='actual_logical_model_response' and book.get(s['record']).get('role')=='reasoning' for s in task['stages'])
            task['execution_outcome']='EXECUTED' if observed else ('BUDGET_NOT_ADMITTED' if r.stop else 'SOURCE_READ_WITHOUT_REASONING')
            return answer
        except ValueError:
            if not active['last_read_error']:raise
            task['execution_outcome']=('EVIDENCE_NOT_FOUND' if active['last_read_error']['status']=='not_found' else 'BUDGET_NOT_ADMITTED' if active['last_read_error']['status']=='budget_not_admitted' else 'IDENTITY_OR_RANGE_SELECTION_REQUIRED')
            book.pause_task(task['task_id'],task['execution_outcome'],active['last_read_error'])
        finally:active['plan']=None;r.limits=limits;r.request_headroom=headroom;engine.current=None
    def ask_hook(role,context):
        plan=active['plan']
        current=engine.current or {}
        if role=='reasoning':
            context={**context,'critical_question_protocol':{'optional_critical_questions':'When an actual source-bound gap can change the judgment, use critical_questions with question, request_indices, evidence_refs (exact supplied source IDs), and nonempty unresolved_conditions. Preserve the provided question_id for updates; UNKNOWN is not refutation. Original candidates and tools remain independent of question acceptance.'},
              'r2_read_and_position_protocol':{'reads':'inspect_entity requires an exact method_id/resource_id and a range wholly in that method. Invalid windows return actual candidates; choose explicitly. Cross-method context uses separate IDs. read_file_range(file,start_line,end_line) uses the existing safe file reader; Java file evidence is not a method/candidate identity.',
               'candidate_steps':'Select delivered evidence_id, exact method_id/resource_id, line,end_line,role. Omit expression for program extraction. Optional exact unique start_anchor/end_anchor select partial endpoint lines; all original checks still apply.',
               'current_problem':current.get('question'),'required_source_ranges':current.get('required_source_ranges',[])}}
            if current.get('tool_delivery'):
                receipts=book.get(current['tool_delivery']);proofs={p['evidence_id']:p for p in context['source_evidence']};files=[]
                for receipt in receipts:
                    value=receipt.get('result',{})
                    if isinstance(value,dict) and value.get('source') and value.get('evidence_id'):
                        if value.get('candidate_step_eligible') is False:files.append(value)
                        else:proofs[value['evidence_id']]=value
                context={**context,'source_evidence':list(proofs.values()),'file_evidence':files,'retrieval_results':[ *context.get('retrieval_results',[]),*receipts],'feedback':[*context.get('feedback',[]),*current.get('candidate_feedback',[])]}
        if role=='reasoning' and plan:
            preparation=prepared[plan['mechanism_id']];proofs={p['evidence_id']:p for p in context['source_evidence']}
            proofs.update(preparation['source_evidence']);proofs.update(resources[plan['mechanism_id']])
            context={**context,'source_evidence':[{**p,'source':source_safe(p['source'])} for p in proofs.values()],
                'mechanism_review':{'mechanism_id':plan['mechanism_id'],'kind':plan['kind'],'questions':plan['questions'],
                 'navigation_facts':plan['navigation_facts'],'source_boundaries':plan['source_boundaries'],
                 'caller_edges':preparation['caller_edges'],'investigation_tool_results':preparation['tool_results'],
                 'unread_boundaries':preparation['unread_boundaries'],
                 'instructions':'The Java focus is only a navigation anchor. Review the provided behavior group using actual source; source relationships must be checked, not inferred from names. Original A1 candidates can be submitted immediately; unresolved conditions remain explicit. Use original tools for the next concrete boundary.',
                 'critical_question_protocol':{'critical_questions':[{'question':'precise source-bound question','request_indices':['indexes in requests'],
                    'evidence_refs':['actual supplied evidence IDs anchoring this question'],'unresolved_conditions':['specific condition to answer']}],
                    'question_updates':'Same original A1 question_updates schema; answer or pause based on actual returned evidence.'}}}
        value=ask(role,context)
        if role=='reasoning' and engine.current:
            for action in value.get('requests',[])[:4]:
                outputs=[];execute(action,engine.current,outputs);active['actions'].extend(outputs)
            # Raw response and its actions remain immutable. Original A1 does
            # not defer a second copy of actions already actually executed.
            value={**value,'requests':[]}
            engine.current['last_response']=book.record(value)
            book.stage(engine.current['task_id'],'r2_requested_actions_executed',tool_results=book.record(active['actions']),control_response=engine.current['last_response'])
        return value
    def event_hook(name,**data):
        if name in {'file_source_read','source_read_refused','tool_request_failed'}:book.event('tool_budget_snapshot',tool_calls=r.tool_calls)
        if name=='model_response' and data['role']=='reasoning' and active['actual_context']:
            for proof in active['actual_context'].get('source_evidence',[]):delivered[proof['evidence_id']]=proof
        if name=='candidate_rejected_protocol':active['feedback'].append({'candidate_error':data.get('reason'),'raw_draft':data.get('draft')})
        if name=='model_input' and data['role']=='reasoning':
            active['actual_context']=data['context'];plan=active['plan']
            if plan:
                for proof in data['context'].get('source_evidence',[]):
                    if proof.get('resource_id'):resources[plan['mechanism_id']][proof['evidence_id']]=proof
                book.stage(engine.current['task_id'],'mechanism_actual_request',mechanism_id=plan['mechanism_id'],
                    evidence_ids=[p['evidence_id'] for p in data['context']['source_evidence']],context=book.record(data['context']))
        return event(name,**data)
    def question_hook(task,text,actions,context,origin,provided_id=None,conditions=None):
        plan=active['plan']
        answer=book.get(origin['response']);entry=next((v for v in answer.get('critical_questions',[]) if isinstance(v,dict) and v.get('question')==text and v.get('question_id')==provided_id),{})
        refs=entry.get('evidence_refs');actual=active['actual_context'] or context;proofs={p['evidence_id']:p for p in actual['source_evidence']}
        if not isinstance(refs,list) or not refs or any(not isinstance(v,str) or v not in proofs for v in refs):raise ValueError('Mechanism question requires exact supplied source evidence_refs; raw entry preserved')
        if not isinstance(conditions,list) or not conditions or any(not isinstance(c,str) or not c.strip() for c in conditions):raise ValueError('Mechanism question requires explicit unresolved_conditions')
        q=question(task,text,actions,{**actual,'source_evidence':[proofs[v] for v in refs]},origin,provided_id,conditions)
        if plan:q['mechanism_id']=plan['mechanism_id']
        q['anchor_evidence_refs']=refs;q['source_ranges']=[{k:p[k] for k in ('evidence_id','file','start_line','end_line')} for p in [proofs[v] for v in refs]]
        book.event('mechanism_question_anchored',question_id=q['question_id'],mechanism_id=plan['mechanism_id'] if plan else None,source_ranges=q['source_ranges']);return q
    def judge_hook(qid,update,visible,origin):
        actual=active['actual_context'];proofs={p['evidence_id']:p for p in actual.get('source_evidence',[])} if actual else {}
        if actual:
            visible=set(proofs);q=book.state['questions'].get(qid);refs=update.get('evidence_refs',[])
            if q and isinstance(refs,list) and refs and all(isinstance(v,str) and v in proofs for v in refs):
                added=[]
                for identity in refs:
                    if identity not in q['evidence']:q['evidence'][identity]=book.record(proofs[identity]);added.append(identity)
                if added:
                    q['evidence_version']+=1;book.event('question_model_selected_visible_evidence',question_id=qid,evidence_ids=added,actual_request=book.record(actual))
        return judge(qid,update,visible,origin)
    def run_hook():
        result=original_run()
        for task in book.state['tasks'].values():
            if not task['dispatches']:
                task['execution_outcome']='BUDGET_NOT_ADMITTED';task['not_executed_reason']=result['stop_reason'];bind_task(task)
            elif task['status']=='PAUSED':task.setdefault('execution_outcome','EXPLICIT_PAUSE')
        book.event('r2_task_execution_classified',stop_reason=result['stop_reason']);result['execution_outcomes']=dict(__import__('collections').Counter(t.get('execution_outcome','EXECUTED') for t in book.state['tasks'].values()))
        from .a1_execution import atomic
        atomic(r.output/'run.json',result);return result
    r.inventory=inventory_hook;book.next=choose;engine.dispatch=dispatch_hook;r.ask=ask_hook;r.event=event_hook;book.question=question_hook;book.judge=judge_hook
    r.request=request_hook;r.read=read_hook;r.candidate=candidate_hook;r.run=run_hook
    engine.critical=True
    engine.mechanism_plans=plans;engine.mechanism_prepared=prepared
    return engine
