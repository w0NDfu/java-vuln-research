"""One frozen, three-case A1 development experiment; no label imports."""
from pathlib import Path
import hashlib,json,sys,time,os,zipfile,re,signal,inspect,xml.etree.ElementTree as ET
from java_vuln_research.work1_agent.fasttrack import build_runner,baseline
from java_vuln_research.work1_agent.dag_harness import AgentTeam
from java_vuln_research.work1_agent.a1_resource_evidence import install as mixed_install
from java_vuln_research.work1_agent.targeted_a1 import Switches,install as targeted_install,prompts
from java_vuln_research.work1_agent.a1_contract_context import install as contract_install
from java_vuln_research.work1_agent.a1_verification_budget import BudgetAdmission
from java_vuln_research.work1_agent.a1_execution import ExecutionController
from java_vuln_research.work1_agent.a1_history import HistoryIndex,HistoryFirst,IdentityJournal
from java_vuln_research.work1_agent.run_harness import OpenLuxChatPolicy,OPENLUX_ENDPOINT
from java_vuln_research.work1_agent.experiment_policy import RequestJournal,request_reserve,VerificationReserve

R=Path(__file__).resolve().parent;W=R.parent;LAB=R.parents[1]
ORDER=['sample_31','sample_74','sample_26'];MODEL='gpt-6-luna'
SWITCHES={'sample_31':Switches(web_surface_enhancement=True),'sample_74':Switches(critical_evidence_closure=True),'sample_26':Switches(cross_cwe_reasoning=True)}
BASE=R/'runtime/frozen-r12-benchmark.py'
def read(p):return json.loads(Path(p).read_bytes())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def write(p,v):Path(p).write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def rows(p):return [json.loads(s) for s in p.read_bytes().splitlines()] if p.exists() else []
def seal(folder,name='SHA256SUMS',files=None):
    files=files or [p for p in folder.rglob('*') if p.is_file() and p.name!=name and '__pycache__' not in p.parts]
    dest=folder/name
    with dest.open('x') as f:
        f.write(''.join(f'{sha(p)}  {p.relative_to(folder).as_posix()}\n' for p in sorted(files)))
def verify(folder,name='SHA256SUMS'):
    for line in (folder/name).read_text().splitlines():
        h,p=line.split('  ',1);assert sha(folder/p)==h,p
def source_hash(root):
    h=hashlib.sha256()
    for p in sorted(p for p in root.rglob('*') if p.is_file()):
        assert p.resolve().is_relative_to(root.resolve());h.update(p.relative_to(root).as_posix().encode()+b'\0');h.update(p.read_bytes())
    return h.hexdigest()
def catalog(entry):
    # The single available local dependency document is offered generically for
    # an exact imported class/call, never because of a target method identity.
    root=Path(entry['source_root']);poms=list(root.rglob('pom.xml'))
    dependency=False
    for p in poms:
        tree=ET.fromstring(p.read_bytes())
        for dep in tree.iter():
            if dep.tag.rsplit('}',1)[-1]!='dependency':continue
            values={x.tag.rsplit('}',1)[-1]:(x.text or '').strip() for x in dep}
            if (values.get('groupId'),values.get('artifactId'),values.get('version'))==('org.owasp.encoder','encoder','1.1.1'):dependency=True
    if not dependency:return []
    jar=W/'a1-evidence-driven-20261110.xbWYWZ/contracts/encoder-1.1.1-sources.jar'
    binary=jar.parent/'encoder-1.1.1.jar'
    # Resolve the existing Maven cache deterministically during preflight only.
    if not binary.exists():
        choices=[p for p in LAB.rglob('encoder-1.1.1.jar') if not p.name.endswith('-sources.jar')]
        hashes={sha(p) for p in choices};assert len(hashes)==1 and choices,'Ambiguous dependency binary'
        binary=sorted(choices)[0]
    with zipfile.ZipFile(binary) as z:
        props=z.read('META-INF/maven/org.owasp.encoder/encoder/pom.properties').decode()
        assert 'version=1.1.1' in props.splitlines()
    # Existing cache receipts, no network fetch.
    for p in [jar,binary]:
        receipt=Path(str(p)+'.sha1');assert receipt.exists()
        assert hashlib.sha1(p.read_bytes()).hexdigest()==receipt.read_text().strip().split()[0]
    return [{'coordinate':'org.owasp.encoder:encoder:1.1.1','class':'org.owasp.encoder.Encode',
             'sources_jar':str(jar),'sources_sha256':sha(jar),'binary':str(binary),'binary_sha256':sha(binary),
             'binding':'CURRENT_PROJECT_POM_AND_BINARY_MAVEN_PROPERTIES_AND_EXISTING_SHA1_RECEIPTS'}]

def prepare():
    original=W/'fasttrack-a1-12-20261110/run-01/experiment'
    for line in (original/'code.sha256').read_text().splitlines():
        h,rel=line.split('  ',1);assert sha(original/rel)==h
    manifest=read(W/'hecv-local-relations-v2-thmsu6d4/codeql-evidence-manifest.json')
    inputs={k:manifest['projects'][k] for k in ORDER};checks=[];catalogs={}
    for key,e in inputs.items():
        root=Path(e['source_root']);assert source_hash(root)==e['source_tree_sha256']
        assert e['database_finalised'] and (Path(e['database'])/'db-java').is_dir()
        table=e['database_table_fingerprint'];table_root=Path(table['directory']);dh=hashlib.sha256()
        for p in sorted(p for p in table_root.rglob('*') if p.is_file()):
            dh.update(p.relative_to(table_root).as_posix().encode()+b'\0'+bytes.fromhex(sha(p)))
        assert dh.hexdigest()==table['tree_sha256'],(key,'database tables')
        for field in ['database_metadata','database_source_zip','graph_csv','native_execution_receipt','native_report','native_sarif','query_execution_receipt']:
            rec=e[field];assert sha(rec['file'])==rec['sha256'],(key,field)
        for q in e['native_queries']:assert sha(q['file'])==q['sha256']
        catalogs[key]=catalog(e)
        checks.append({'sample':key,'source':e['source_tree_sha256'],'database_finalised':True,'existing_queries_verified':len(e['native_queries']),'new_queries':0,'dependency_contract_entries':len(catalogs[key])})
    write(R/'inputs.json',{'projects':inputs,'dependency_catalog':catalogs})
    write(R/'preflight-inputs.json',checks)
    write(R/'tool-schema.json',{'actions':{
        'inspect_entity':{'entity_id':'exact provided Java method ID or provided resource_id','start_line':'optional integer','end_line':'optional integer','max_lines':160,'resource_byte_limit':9000,'ambiguous_identity':'refuse, never guess'},
        'search_symbols':{'query':'bounded literal string,1..160 chars'},
        'search_code':{'query':'bounded literal string,1..160 chars'},
        'follow_graph':{'entity_id':'existing entity ID'},
        'read_file_range':{'file':'exact repository-relative path','start_line':'explicit integer','end_line':'explicit integer,at most160 lines','Java_file_evidence':'not a method identity or candidate step'}},
        'critical_questions':'B-only declared in actual Reasoning prompt; indexes refer to original requests; valid original candidates survive invalid question entries',
        'candidate_schema':'Original A1 fields plus existing mixed Java/resource exact-location adapter; no relaxed references; total/per-CWE caps null',
        'verification_schema':'Original reviews with candidate_path_id, verdict, reason, evidence_refs; unchanged'})
    write(R/'frozen-prompts.json',{k:prompts(baseline(BASE).PROMPTS,SWITCHES[k]) for k in ORDER})
    write(R/'frozen-rules.json',{'sample_order':ORDER,'model':MODEL,'max_requests':28,'max_tokens':300000,'max_seconds':1200,'max_tools':128,'completion_tokens':4096,'sdk_retries':0,
          'protocol_corrections':'Original A1 max one feedback correction per malformed response, shared ledger',
          'candidate_cap':None,'per_cwe':None,'focuses':12,'calls_per_focus':2,'original_inventory_size':360,
          'switches':{k:vars(SWITCHES[k]) for k in ORDER},
          'verification_reserve':'Actual pending candidates only, original batches of4, one guaranteed primary opportunity; cached responses have zero new physical reserve. Future estimates and optional correction are separate. Original semantic validator precedes transactional resource admission; valid budget-deferred drafts are preserved. Pending reviews run before further reasoning.',
          'critical_question_tasks':'persisted, evidence revisions independently re-assessed in fair serial lanes','critical_actions_per_dispatch':2,
          'reuse_discovery':'REQUIRED_EXACT_SEALED_BODY_KEY_SCHEMA_SOURCE_MATCH','serial_scheduler_repaired':True,'original_reasoning_explore_candidate_and_review_unchanged':True,
          'shared_existing_support':['exact safe source-window intersection','existing mixed resource evidence/admission and bounded source reads','existing method/interface/version documentation retrieval','existing paced SDK transport'],
          'interpretation':'Three known development cases, single targeted switch per case; no generalization or universal single-factor causal claim.',
          'stop_after_three':True,'no_reruns':True,'no_new_queries':True,'no_new_agents':True})
    print('INPUTS_VERIFIED_NO_MODEL',flush=True)

def freeze():
    assert not (R/'detection').exists()
    assert read(R/'regression.json')['passed']
    assert read(R/'regression.json')['physical_model_requests']==0
    assert read(R/'final-integrity.json')['passed']
    files=[p for p in (R/'runtime').rglob('*') if p.is_file() and '__pycache__' not in p.parts and '.pytest_cache' not in p.parts]
    files += [R/x for x in ['experiment.py','execute-once.sh','evaluate.py','acceptance.py','finalize.py','score_closed_pair.py','inputs.json','preflight-inputs.json','tool-schema.json','regression.json','unit-tests-final.log','frozen-prompts.json','frozen-rules.json','minimal-change.patch','BASELINE.json','final-integrity.json','history/history.sqlite','history/history-inventory.json']]
    seal(R,'snapshot.sha256',files);verify(R,'snapshot.sha256')
    write(R/'freeze-receipt.json',{'status':'UNIFIED_FROZEN_WAITING_AUTHORIZATION','snapshot_sha256':sha(R/'snapshot.sha256'),'exact_base_snapshot_sha256':read(R/'BASELINE.json')['exact_base_snapshot_sha256'],'physical_requests':0,'new_detection_runs':0,'new_codeql_queries':0,'next_live_run_authorized':False,'required_live_gate':'New user authorization, then FASTTRACK_AUTHORIZED_LIVE=1; no automatic launch','offline_acceptance':read(R/'regression.json')['acceptance_directory']})

class Policy(OpenLuxChatPolicy):
    def __init__(self,key,prompt,folder):
        super().__init__(OPENLUX_ENDPOINT,MODEL,key,system_prompt=prompt,max_output_tokens=4096,json_mode=True)
        self.folder=folder
        self.n=max([int(p.name.split('-')[-1].split('.')[0]) for p in (folder/'messages').glob('*.request.json')]+[0])
    def __call__(self,context):
        if os.environ.get('FASTTRACK_AUTHORIZED_LIVE')!='1':
            from java_vuln_research.work1_agent.harness import PolicyError
            raise PolicyError('LIVE_TRANSPORT_NOT_AUTHORIZED: offline repair only')
        self.n+=1;d=self.folder/'messages';d.mkdir(exist_ok=True)
        write(d/f'{context["role"]}-{self.n:03d}.request.json',self.request_body(context))
        if context['role']=='reasoning':
            stack=[{'file':f.filename,'function':f.function,'line':f.lineno} for f in inspect.stack() if Path(f.filename).resolve()==BASE.resolve()]
            assert any(f['function']=='explore' for f in stack),'Actual Reasoning must run inside original A1 explore'
            write(d/f'reasoning-{self.n:03d}.original-core-stack.json',{'original_core_sha256':sha(BASE),'stack':stack,'unused_reasoning':False})
        turn=super().__call__(context)
        (d/f'{context["role"]}-{self.n:03d}.raw.txt').write_text(turn.content,encoding='utf-8')
        write(d/f'{context["role"]}-{self.n:03d}.metadata.json',{'usage':turn.usage,'metadata':turn.metadata})
        return turn

def accounting(folder):
    rr=rows(folder/'requests.jsonl');responses=[x for x in rr if x['event']=='response'];starts=[x for x in rr if x['event']=='request_started']
    logical=rows(folder/'logical-work.jsonl');reused=[r for r in logical if r['event']=='logical_response_reused']
    return {'requests':len(starts),'responses':len(responses),'tokens':sum(x['usage'].get('total_tokens',0) for x in responses),'unsettled':len(starts)-len(responses),
            'by_role':{r:{'requests':sum(x['role']==r for x in starts),'tokens':sum(x['usage'].get('total_tokens',0) for x in responses if x['role']==r)} for r in ['discovery','reasoning','verification']},
            'logical_responses':len(logical),'reused_responses':len(reused),'reused_logical_tokens':sum(r.get('logical_usage',{}).get('total_tokens',0) for r in reused),'reuse_new_physical_cost':0,
            'currency_cost':None,'returned_models':sorted({x.get('metadata',{}).get('returned_model','UNKNOWN') for x in responses})}

def detect():
    if os.environ.get('FASTTRACK_AUTHORIZED_LIVE')!='1':raise RuntimeError('LIVE_RUN_NOT_AUTHORIZED: this repair task permits offline checks only')
    verify(R,'snapshot.sha256');(R/'detection').mkdir(exist_ok=False)
    from dotenv import dotenv_values
    key=os.environ.get('WORK1_AGENT_API_KEY') or dotenv_values(LAB/'vEcho/.env').get('OPENLUX_API_KEY')
    assert key,'Authorized credential unavailable'
    inputs=read(R/'inputs.json');pp=read(R/'frozen-prompts.json');summary=[]
    write(R/'batch-status.json',{'status':'RUNNING','order':ORDER})
    for case in ORDER:
        verify(R,'snapshot.sha256');entry=inputs['projects'][case];root=Path(entry['source_root']);assert source_hash(root)==entry['source_tree_sha256']
        out=R/'detection'/case;out.mkdir();start=time.monotonic();journal=IdentityJournal(out/'requests.jsonl',source_identity=entry['source_tree_sha256'],max_requests=28,max_tokens=2**60,max_seconds=1200,binding=f'{sha(R/"snapshot.sha256")}:{case}:{MODEL}')
        journal.token_limit_disabled=True
        verification_policy=Policy(key,pp[case]['verification'],out)
        history=HistoryIndex(R/'history/history.sqlite',read_only=True)
        budget_ref=[None]
        def role_policy(role,prompt):
            p=verification_policy if role=='verification' else Policy(key,prompt,out);send=journal.wrap(p)
            return HistoryFirst(history,p,send,out/'logical-work.jsonl',entry['source_tree_sha256'],guard=lambda ctx,policy:budget_ref[0].admit(ctx,policy),journal=journal)
        team=AgentTeam(**{role:role_policy(role,p) for role,p in pp[case].items()})
        base=baseline(BASE)
        runner=build_runner(root,out,team,r12_implementation=BASE,strategy='A1',static_report=Path(entry['native_report']['file']),static_graph=Path(entry['graph_csv']['file']),limits=base.BenchmarkLimits(max_candidates=None,per_cwe=None,max_focus=28),request_headroom=lambda:28-journal.requests,token_headroom=lambda:journal.max_tokens-journal.tokens)
        archive=mixed_install(runner,automatic=True,physical_requests=lambda:journal.requests)
        contract_install(runner,inputs['dependency_catalog'][case])
        questions=targeted_install(runner,SWITCHES[case],archive,chain_managed=True)
        lookup=lambda ctx,p:team.verification.preview(ctx,p)
        budget_ref[0]=BudgetAdmission(runner,archive,journal,verification_policy,lookup)
        engine=ExecutionController(runner,archive,f'{sha(R/"snapshot.sha256")}:{case}',critical=SWITCHES[case].critical_evidence_closure,budget=budget_ref[0])
        runner.request_headroom=lambda:28-journal.requests
        core=runner.targeted_original_core
        original_class=next(c for c in type(runner).__mro__ if c.__name__=='BenchmarkRun' and Path(inspect.getsourcefile(c)).resolve()==BASE.resolve())
        assert core['original_core_object'] is original_class.explore
        assert sha(core['core_explore_file'])=='f4bb22a4457742b99ae08ade40c079165ecc75aed8fb0cb483d1a529b7890034'
        write(out/'runtime-call-chain.json',{'core_file':core['core_explore_file'],'core_sha256':sha(BASE),'original_core_unchanged':True,'original_Reasoning_loop':True,'actual_model_policy':'HistoryFirst then shared RequestJournal/OpenLux; exact history wins before physical send','unused_reasoning':False,'switches':vars(SWITCHES[case]),'candidate_total_cap':None,'candidate_per_cwe_cap':None})
        error=None
        try:result=runner.run()
        except Exception as exc:error={'type':type(exc).__name__,'detail':str(exc)};result=None
        finally:runner.trace.close()
        intact=source_hash(root)==entry['source_tree_sha256'];verify(R,'snapshot.sha256')
        candidates=list(runner.candidates.values());reviews=list(runner.reviews.values());missing=sorted(set(runner.candidates)-set(runner.reviews))
        status='COMPLETE' if result and intact and not missing and not result['protocol_failed_nodes'] and not result.get('resource_deferred_valid_drafts') and result['stop_reason'] in {'GRAPH_COMPLETE','BENCHMARK_BUDGET_COMPLETE','VERIFICATION_RESERVE'} else 'PARTIAL'
        if error or not intact:status='FAILED'
        write(out/'resource-evidence.json',list(archive.values()));write(out/'resource-exposure.json',runner.resource_exposure)
        item={'sample':case,'status':status,'stop_reason':result['stop_reason'] if result else error,'error':error,'inputs_unchanged':intact,'candidates':len(candidates),'reviews':len(reviews),'unreviewed':missing,'ledger':accounting(out),'elapsed_seconds':round(time.monotonic()-start,3),'switches':vars(SWITCHES[case])}
        write(out/'finished.json',item);seal(out);verify(out);summary.append(item)
        write(R/'batch-status.json',{'status':'RUNNING','completed':summary,'order':ORDER})
        print(json.dumps(item),flush=True)
        if error or not intact or runner.last_error=='TOOL_OR_STATE_ERROR':
            write(R/'batch-status.json',{'status':'HALTED_SHARED_FAILURE','completed':summary,'not_started':ORDER[len(summary):]});return
    write(R/'batch-status.json',{'status':'DETECTION_CLOSED','completed':summary,'not_started':[]})
    seal(R/'detection');print('THREE_CASES_SEALED_STOP_MODEL_REQUESTS',flush=True)

if __name__=='__main__':globals()[sys.argv[1]]()
