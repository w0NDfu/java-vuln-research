"""Production entry for the single frozen R2+HECV direct-improvement batch."""
from pathlib import Path
from dataclasses import replace
import argparse,copy,hashlib,inspect,json,os,signal,traceback
from .fasttrack import baseline,build_runner
from .dag_harness import AgentTeam
from .a1_resource_evidence import install as mixed_install
from .targeted_a1 import Switches,install as targeted_install,prompts
from .a1_contract_context import install as contract_install
from .a1_execution import ExecutionController,atomic
from .mechanism_coverage import install as mechanism_install
from .a1_history import HistoryIndex,HistoryFirst,IdentityJournal,legacy_key,hashed
from .a1_verification_budget import BudgetAdmission,physical_account
from .run_harness import OpenLuxChatPolicy,OPENLUX_ENDPOINT
from .experiment_policy import request_reserve
from .harness import ModelTurn,PolicyError
from .r2_hecv import PeerController,INVESTIGATOR_PROMPT,BRIDGE_PROMPT
from .r2_hecv_budget import ReservedBudget
from .r2_hecv_coordination import CooperativeScheduler

def active_scopes(args):
    legacy=getattr(args,'max_scopes',None)
    return legacy if legacy is not None else getattr(args,'max_active_scopes',4)
from .r2_hecv_recovery import ResponseRecovery,require_complete_protocol
from context_serialization import pack,unpack,canonical,component_estimates

SWITCHES=Switches(web_surface_enhancement=True,critical_evidence_closure=True,cross_cwe_reasoning=True)
def published(core):
 p=prompts(baseline(core).PROMPTS,SWITCHES);p['investigator']=INVESTIGATOR_PROMPT+BRIDGE_PROMPT;return p

class DirectPolicy(OpenLuxChatPolicy):
    def __init__(self,token,prompt,model,source_id,history,holder,core):
        super().__init__(OPENLUX_ENDPOINT,model,token,system_prompt=prompt,max_output_tokens=8192,json_mode=True)
        self.source_id=source_id;self.history=history;self.holder=holder;self.core=Path(core);self.audit=None
    def forms(self,context):
        original=super().request_body(context);packed,stats=pack(context)
        body=copy.deepcopy(original)
        if self.history.lookup(legacy_key(context,self),original,self.source_id) is None:body['messages'][1]['content']=json.dumps(packed,ensure_ascii=False)
        assert canonical(unpack(json.loads(body['messages'][1]['content'])))==canonical(context)
        return body,stats
    def request_body(self,c):return self.forms(c)[0]
    def request_token_material(self,c):return json.dumps(self.request_body(c),ensure_ascii=False,sort_keys=True)
    def record_wire_request(self,raw):
        actual=json.loads(raw);semantic=unpack(json.loads(actual['messages'][1]['content']))
        assert canonical(semantic)==canonical(self.context)
        (self.audit/'actual-wire-request.json').write_bytes(raw)
        atomic(self.audit/'actual-wire-receipt.json',{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'roundtrip_equal':True,'authorization_headers_recorded':False})
    def response_turn(self,raw):
        (self.audit/'actual-provider-response.json').write_bytes(raw)
        if len(raw)>512*1024:raise PolicyError('Explicit raw response bound exceeded; original saved')
        try:
            p=json.loads(raw);c=p['choices'][0]['message']['content'];u=p.get('usage') or {}
            if not isinstance(c,str) or len(c.encode())>128*1024 or not isinstance(u,dict) or p.get('model')!=self.model:raise ValueError('Envelope/content/model mismatch')
        except (ValueError,TypeError,KeyError,IndexError) as error:raise PolicyError('Invalid provider response: '+str(error))
        turn=ModelTurn(c,u,{'finish_reason':p['choices'][0].get('finish_reason'),'returned_model':p.get('model'),'reported_cost':p.get('cost')})
        # Invoked by the unchanged transport only after SDK success; no guessed
        # repair of raw content. This receipt covers a crash before __call__ returns.
        atomic(self.audit/'successful-provider-envelope.json',{'raw_sha256':hashlib.sha256(raw).hexdigest(),'body_sha256':hashed(self.request_body(self.context)),'model':self.model,'http_status':200,'content':turn.content,'usage':dict(turn.usage),'metadata':dict(turn.metadata)})
        return turn
    def __call__(self,context):
        if os.environ.get('FASTTRACK_AUTHORIZED_LIVE')!='1':raise PolicyError('Direct live run not authorized in environment')
        self.context=context
        if context['role']=='reasoning':
            stack=[{'file':x.filename,'line':x.lineno,'function':x.function} for x in inspect.stack() if Path(x.filename).resolve()==self.core.resolve()]
            if not any(x['function']=='explore' for x in stack):raise PolicyError('Explorer must execute original frozen A1 explore')
            atomic(self.audit/'original-core-stack.json',{'sha256':hashlib.sha256(self.core.read_bytes()).hexdigest(),'stack':stack})
        turn=super().__call__(context)
        recovery=self.holder['recovery'];body=self.request_body(context);key=recovery.store.key(body)
        recovery.store.event(key,'HTTP_RESPONSE_RECEIVED',audit=str(self.audit))
        recovery.store.put(body,context,turn,{'mode':'ACTUAL_HTTP_RESPONSE','audit':str(self.audit),'body_sha256':hashed(body)})
        return turn

class DirectHistory(HistoryFirst):
    def __init__(self,*a,holder,**kw):super().__init__(*a,**kw);self.holder=holder
    def __call__(self,context):
        parent=self.logical_path.parent/'request-audit';parent.mkdir(exist_ok=True)
        folder=parent/(f'{len(list(parent.iterdir()))+1:03d}-'+context['role']);folder.mkdir();p=self.policy;p.audit=folder
        body,stats=p.forms(context);atomic(folder/'request-body.json',body);atomic(folder/'semantic-context.json',context)
        estimate,method=request_reserve(context,p)
        receipt={'role':context['role'],'legacy_request_key':legacy_key(context,p),'body_sha256':hashed(body),'semantic_sha256':hashed(context),'context_estimates':component_estimates(context),'wire_estimates':component_estimates(json.loads(body['messages'][1]['content']),stats['table_category_owners']),'serialization':stats,'future_estimated_tokens_not_actual_usage':estimate,'estimate_method':method,'provider_usage_status':'NOT_SENT_OR_UNSETTLED'}
        atomic(folder/'receipt.json',receipt)
        if self.journal.path.exists():
            prior=[json.loads(row) for row in self.journal.path.read_bytes().splitlines()]
            if any(row.get('legacy_request_key')==legacy_key(context,p) and row.get('body_sha256')!=hashed(body) for row in prior):raise PolicyError('CURRENT_FULL_IDENTITY_MISMATCH; no guessed reuse or resend')
        if self.preview(context) is None and self.index.db.execute('SELECT 1 FROM records WHERE key=? AND source_id=? LIMIT 1',(legacy_key(context,p),self.source_identity)).fetchone():raise PolicyError('Known successful historical key has a different complete wire identity; no guessed reuse or resend')
        recovery=self.holder['recovery'];saved=recovery.store.get(body)
        if saved and saved['witness'].get('mode')=='ACTUAL_HTTP_RESPONSE':recovery.reconcile_usage(saved,p)
        try:turn=super().__call__(context)
        except Exception as error:atomic(folder/'failure.json',{'type':type(error).__name__,'message':str(error)});raise
        (folder/'assistant-content.txt').write_text(turn.content,encoding='utf-8')
        reused=bool(turn.metadata.get('history_reused'))
        receipt.update(provider_usage_status='HISTORICAL_ORIGINAL_NOT_NEW_COST' if reused else 'PROVIDER_REPORTED',provider_usage=dict(turn.usage),metadata=dict(turn.metadata),new_physical_requests=0 if reused else 1)
        atomic(folder/'receipt.json',receipt)
        witness={'receipt':str(folder/'receipt.json'),'receipt_sha256':hashlib.sha256((folder/'receipt.json').read_bytes()).hexdigest(),'body_file':str(folder/'request-body.json'),'body_file_sha256':hashlib.sha256((folder/'request-body.json').read_bytes()).hexdigest(),'mode':'EXACT_HISTORICAL_SUCCESS' if reused else 'ACTUAL_HTTP_RESPONSE','new_wire_transmission':not reused}
        saved=recovery.store.get(body)
        if saved is None:
            recovery.store.put(body,context,turn,witness);saved=recovery.store.get(body)
        key=recovery.store.key(body);recovery.store.event(key,'USAGE_SETTLED',historical_or_current_reuse=reused)
        recovery.coordinate(saved)
        # Protocol failure is distinct from coordination failure. No invented JSON.
        require_complete_protocol(turn)
        recovery.store.event(key,'RESPONSE_RETURNED')
        return turn

def build(args,team,investigator,journal,history,policies,holder):
    core=Path(args.core);base=baseline(core);out=Path(args.output)
    construction=out
    if (out/'trace.jsonl').exists() and getattr(args,'resume',False):
        import uuid
        construction=out/'resume-segments'/uuid.uuid4().hex;construction.mkdir(parents=True,exist_ok=False)
    # Actual sealed R2 run.json: outer calls=2, focus=28. The unchanged R2
    # mechanism dispatcher applies its own single-turn + persisted continuation.
    r=build_runner(Path(args.repository),construction,team,r12_implementation=core,strategy='A1',static_report=Path(args.static_report),static_graph=Path(args.static_graph),limits=replace(base.BenchmarkLimits(),max_candidates=None,per_cwe=None,max_focus=28,calls_per_focus=base.BenchmarkLimits().calls_per_focus),tool_limit=args.max_tools,request_headroom=lambda:args.max_requests-journal.requests,token_headroom=lambda:journal.max_tokens-journal.tokens)
    r.output=out
    r.physical_tool_limit=args.max_tools
    # Retain the full original R2 resource middleware, including its review
    # evidence bridge. Callback-only installation intentionally omits these.
    from . import a1_resource_evidence as resource_adapter
    original_factory=resource_adapter.ResourceReferences
    references=original_factory(r.tools.index.repository_root,r.ast.parser)
    # Constructor injection exposes the original cache for checkpoint restore;
    # the original parser, selection, package bounds and build logic stay intact.
    try:
        resource_adapter.ResourceReferences=lambda root,parser:references
        archive=mixed_install(r,automatic=True,physical_requests=lambda:journal.requests)
    finally:resource_adapter.ResourceReferences=original_factory
    original_resource_build=references.build
    def cached_resource_build(java_proofs,**options):
        peer=holder.get('peer');exposed=set(options.pop('exposed',()))
        if peer:
            for entry in peer.service.state['proofs'].values():
                proof=entry['proof']
                if entry['evidence_type']=='RESOURCE' and proof.get('file_sha256'):
                    references.windows.setdefault((proof['file'],proof['file_sha256'],proof['start_line'],proof['end_line']),proof)
                    if entry['delivered_to'].get('explorer'):exposed.add(proof['evidence_id'])
        return original_resource_build(java_proofs,exposed=exposed,**options)
    references.build=cached_resource_build;r.resource_reference_cache=references
    pipeline_restore=r.restore_evidence_exposure
    mixed_install(r,automatic=False,physical_requests=lambda:journal.requests,candidate_windows=lambda:holder['peer'].service.visible(holder['budget'].actor))
    validator_restore=r.restore_evidence_exposure
    def restore(proofs):
        values=list(proofs);pipeline_restore(values);validator_restore(values)
    r.restore_evidence_exposure=restore
    contract_install(r,json.loads(Path(args.dependency_catalog).read_bytes()))
    targeted_install(r,SWITCHES,archive,chain_managed=True)
    admission=ReservedBudget(r,archive,journal,policies['verification'],lambda c,p:team.verification.preview(c,p));holder['budget']=admission
    engine=ExecutionController(r,archive,args.binding,critical=True,budget=admission)
    mechanism_install(engine,json.loads(Path(args.dependency_catalog).read_bytes()))
    if getattr(args,'source_cache',None):r.source_cache=json.loads(Path(args.source_cache).read_bytes())
    peer=PeerController(engine,investigator,source_id=args.source_identity,max_scopes=active_scopes(args));holder['peer']=peer
    holder['recovery']=ResponseRecovery(out,args.source_identity,journal,peer)
    engine.cooperative_scheduler=CooperativeScheduler(peer)
    return r,engine,archive,peer

def run(args):
    out=Path(args.output);core=Path(args.core);token=os.environ.get('WORK1_AGENT_API_KEY')
    if not token:raise ValueError('Authorized credential missing')
    binding={'source_identity':args.source_identity,'binding':args.binding,'model':args.model,'core_sha256':hashlib.sha256(core.read_bytes()).hexdigest(),'static_report_sha256':hashlib.sha256(Path(args.static_report).read_bytes()).hexdigest(),'static_graph_sha256':hashlib.sha256(Path(args.static_graph).read_bytes()).hexdigest(),'dependency_catalog_sha256':hashlib.sha256(Path(args.dependency_catalog).read_bytes()).hexdigest(),'prompts':published(core),'max_requests':args.max_requests,'max_tools':args.max_tools,'max_seconds':args.max_seconds,'max_active_scopes':active_scopes(args),'dispatch_ratio':[2,1],'material_signature_version':'MATERIAL_V1','code_manifest_sha256':getattr(args,'code_manifest_sha256',None)}
    binding['source_cache_sha256']=hashlib.sha256(Path(args.source_cache).read_bytes()).hexdigest() if getattr(args,'source_cache',None) else None
    binding['closed_loop_modules']={name:hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest() for name in ['r2_hecv.py','r2_hecv_run.py','r2_hecv_services.py','r2_hecv_budget.py','r2_hecv_coordination.py','a1_execution.py','a1_history.py','a1_verification_budget.py','r2_hecv_recovery.py','request_outcomes.py']}
    if getattr(args,'resume',False):
        if not out.is_dir() or not (out/'RUN_INPUT_BINDING.json').is_file() or json.loads((out/'RUN_INPUT_BINDING.json').read_bytes())!=binding:raise ValueError('RECOVERY_BLOCKED: run input/configuration binding mismatch')
    else:
        out.mkdir(exist_ok=False);atomic(out/'RUN_INPUT_BINDING.json',binding)
    history=HistoryIndex(args.history,read_only=True);journal=IdentityJournal(out/'requests.jsonl',source_identity=args.source_identity,max_requests=args.max_requests,max_tokens=2**60,max_seconds=args.max_seconds,binding=args.binding);journal.token_limit_disabled=True
    pp=published(core);atomic(out/'published-prompts.json',pp);holder={};policies={};wrapped={}
    for role in ['discovery','reasoning','verification','investigator']:
        p=DirectPolicy(token,pp[role],args.model,args.source_identity,history,holder,core);policies[role]=p
        wrapped[role]=DirectHistory(history,p,journal.wrap(p),out/'logical-work.jsonl',args.source_identity,guard=lambda c,p:holder['budget'].admit(c,p),journal=journal,holder=holder)
    team=AgentTeam(*(wrapped[k] for k in ['discovery','reasoning','verification']))
    r,e,archive,peer=build(args,team,wrapped['investigator'],journal,history,policies,holder)
    atomic(out/'declared-budget.json',{'physical_requests':args.max_requests,'tool_operations':args.max_tools,'seconds':args.max_seconds,'token_soft_cap':None,'max_output_tokens':8192,'model':args.model,'analysis_agents':['R2_ENHANCED_EXPLORER','HECV_INVESTIGATOR'],'unchanged_stage_functions':['original Discovery','original Verification'],'additional_agent':False,'max_active_scopes':active_scopes(args),'legacy_max_scopes_input':getattr(args,'max_scopes',None),'dispatch_ratio':[2,1],'r2_window_is_not_total_cap':True})
    def deadline(*_):raise TimeoutError('Declared physical wall-time limit')
    import time,math
    remaining=args.max_seconds-(time.time()-journal.created_at)
    signal.signal(signal.SIGALRM,deadline);signal.alarm(max(1,math.ceil(remaining)));error=None;summary=None
    try:
        if remaining<=0:raise TimeoutError('Original physical wall-time exhausted; restart does not reset its clock')
        recovered=holder['recovery'].recover(policies)
        if any(v['status']=='RECOVERY_BLOCKED' for v in recovered):raise PolicyError('RECOVERY_BLOCKED: incomplete successful-request identity')
        peer.recover_candidates()
        summary=r.run()
    except Exception as exc:
        error={'type':type(exc).__name__,'message':str(exc)};(out/'error-traceback.txt').write_text(traceback.format_exc())
    finally:signal.alarm(0)
    # No hidden retry or second run. Save even a partial/error run and all queues.
    peer.finalize();atomic(out/'BUDGET_RESERVATION_REPORT.json',holder['budget'].report());holder['recovery'].recover(policies);atomic(out/'resource-evidence.json',list(archive.values()));e.book.save()
    for name,values in {'candidates':list(r.candidates.values()),'reviews':list(r.reviews.values()),'benchmark-candidates':[c for k,c in r.candidates.items() if r.reviews.get(k,{}).get('verdict')!='REJECTED'],'source-evidence':list(r.evidence.values())}.items():
        (out/(name+'.jsonl')).write_text(''.join(json.dumps(v,ensure_ascii=False,sort_keys=True)+'\n' for v in values))
    r.trace.close();account=physical_account(out/'requests.jsonl');rr=[json.loads(x) for x in (out/'requests.jsonl').read_bytes().splitlines()] if (out/'requests.jsonl').exists() else []
    usage={k:sum(x.get('usage',{}).get(k,0) for x in rr if x['event']=='response') for k in ['prompt_tokens','completion_tokens','total_tokens']}
    unresolved={k:t for k,t in e.book.state['tasks'].items() if t['status'] in {'QUEUED','PAUSED','SCHEDULED'}}
    atomic(out/'unfinished-tasks.json',{'Explorer':unresolved,'Investigator':{k:v for k,v in peer.state['issues'].items() if v['status'] in {'NEW','NEEDS_EVIDENCE','NEEDS_REASSESSMENT'} or v['status'].startswith('PAUSE')}})
    unreviewed=sorted(set(r.candidates)-set(r.reviews));stop=r.stop or r.last_error or (summary or {}).get('stop_reason')
    actual=getattr(e,'actual_stop_trigger',None) or ('WALL_TIME_LIMIT' if error and error['type']=='TimeoutError' else 'TOOL_OR_STATE_ERROR' if error else 'UNSETTLED_REQUEST' if account['unsettled_requests'] else 'MODEL_OR_PROTOCOL_ERROR' if peer.state.get('reliability_error') else stop)
    if account.get('active_unsettled_requests',account['unsettled_requests']):actual='UNSETTLED_REQUEST'
    fault=actual in {'MODEL_OR_PROTOCOL_ERROR','TOOL_OR_STATE_ERROR','UNSETTLED_REQUEST'}
    quarantined=bool(account.get('quarantined_requests') or account.get('historical_quarantined_requests'))
    closed=(not error or error['type']=='TimeoutError') and not fault and not account.get('active_unsettled_requests',account['unsettled_requests']) and not unreviewed
    result={'status':'CLOSED_BOUNDED_PARTIAL' if closed and (unresolved or quarantined) else 'CLOSED' if closed else 'INCOMPLETE_ERROR_OR_UNSETTLED','error':error,'summary':summary,'physical_account':account,'new_provider_usage':usage,'currency_cost':'UNKNOWN','stop_reason':stop,'candidates':len(r.candidates),'reviews':len(r.reviews),'unreviewed_candidates':unreviewed,'unfinished_Explorer_tasks':len(unresolved),'strict_semantic_confirmation':0,'partial_is_not_complete_negative':True,'historical_candidate_injection':False,'R3_as_base':False}
    result.update(execution_status='FAULT' if fault or error and error['type']!='TimeoutError' else 'UNSETTLED' if account.get('active_unsettled_requests',account['unsettled_requests']) else 'NORMAL_BOUNDED_END',coverage_status='TRANSPORT_QUARANTINED_PARTIAL' if quarantined and not fault and not error else 'SYSTEM_FAULT_INTERRUPTED' if fault or error and error['type']!='TimeoutError' else 'BUDGET_TRUNCATED' if actual in {'GLOBAL_REQUEST_LIMIT','GLOBAL_TOOL_LIMIT','WALL_TIME_LIMIT','PENDING_VERIFICATION_RESERVE'} or e.cooperative_scheduler.explorer_has_work(e) or peer.has_work() else 'UNRESOLVED_WITHOUT_EXECUTABLE_GAP' if unresolved else 'RUNNABLE_WORK_EXHAUSTED',actual_stop_trigger=actual,actual_stop_snapshot=e.book.state.get('cooperative_actual_stop',{}).get('snapshot'),Investigator_reliability_error=peer.state.get('reliability_error'))
    atomic(out/'RUN_RESULT.json',result)
    files=[p for p in out.rglob('*') if p.is_file() and p.name!='SHA256SUMS'];(out/'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.relative_to(out).as_posix()+'\n' for p in sorted(files)))
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser()
    for name in ['repository','output','core','source-identity','history','binding','static-report','static-graph','dependency-catalog']:p.add_argument('--'+name,required=True)
    p.add_argument('--source-cache');p.add_argument('--resume',action='store_true');scope=p.add_mutually_exclusive_group();scope.add_argument('--max-active-scopes',type=int,default=4);scope.add_argument('--max-scopes',type=int,default=None,help='Deprecated alias: active root window, not project lifetime scope cap');p.add_argument('--code-manifest-sha256')
    p.add_argument('--model',default='gpt-6.1-sol');p.add_argument('--max-requests',type=int,default=128);p.add_argument('--max-tools',type=int,default=1024);p.add_argument('--max-seconds',type=int,default=7200)
    print(json.dumps(run(p.parse_args()),ensure_ascii=False),flush=True)
