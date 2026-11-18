"""TEST ONLY synthetic production wiring; no network, labels or detection score."""
import copy,json,socket
from pathlib import Path
from types import SimpleNamespace
import pytest
from java_vuln_research.work1_agent.r2_hecv_run import build,DirectHistory,DirectPolicy,published
from java_vuln_research.work1_agent.r2_hecv_services import normalize_retrieval_request,ServiceError,EvidenceService,ResponseStore
from java_vuln_research.work1_agent.r2_hecv_recovery import ResponseRecovery,require_complete_protocol
from java_vuln_research.work1_agent.a1_history import IdentityJournal,HistoryIndex,legacy_key,hashed
from java_vuln_research.work1_agent.dag_harness import AgentTeam
from java_vuln_research.work1_agent.harness import ModelTurn,PolicyError
from java_vuln_research.work1_agent.fasttrack import baseline

ROOT=Path(__file__).resolve().parents[2]

@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setattr(socket.socket,'connect',lambda *a,**k:pytest.fail('No network permitted in deterministic acceptance'))

@pytest.fixture
def env(tmp_path):
    repo=tmp_path/'source';repo.mkdir();out=tmp_path/'out';out.mkdir()
    (repo/'F.java').write_text('class F {\n public String write(String input) {\n String value = input;\n System.out.print(value);\n return value;\n }\n public String other(String text) { return text; }\n}\n')
    (repo/'view.js').write_text('let value = data.name;\nelement.innerHTML = value;\n')
    static=tmp_path/'static.json';static.write_text('{"vulnerabilities":[]}')
    graph=tmp_path/'graph.csv';graph.write_text('kind,left_path,left_line,left_col,right_path,right_line,right_col,detail\n')
    dep=tmp_path/'dep.json';dep.write_text('[]')
    args=SimpleNamespace(repository=str(repo),output=str(out),core=str(ROOT/'frozen-r12-benchmark.py'),static_report=str(static),static_graph=str(graph),dependency_catalog=str(dep),max_requests=64,max_tools=256,max_seconds=7200,source_identity='TEST_ONLY_TREE',binding='TEST_ONLY_82532',max_scopes=2)
    journal=IdentityJournal(out/'requests.jsonl',source_identity=args.source_identity,max_requests=64,max_tokens=2**60,max_seconds=7200,binding=args.binding);journal.token_limit_disabled=True
    history=HistoryIndex(tmp_path/'history.sqlite')
    holder={};policies={};wrapped={}
    for role,prompt in published(args.core).items():
        p=DirectPolicy('TEST_ONLY',prompt,'gpt-6.1-sol',args.source_identity,history,holder,args.core);policies[role]=p
        wrapped[role]=DirectHistory(history,p,journal.wrap(p),out/'logical-work.jsonl',args.source_identity,journal=journal,holder=holder,guard=lambda c,p:holder['budget'].admit(c,p))
    team=AgentTeam(*(wrapped[k] for k in ['discovery','reasoning','verification']))
    r,e,a,peer=build(args,team,wrapped['investigator'],journal,history,policies,holder)
    yield SimpleNamespace(**locals())
    r.trace.close()

def proof(env):
    env.r.inventory();env.r.activate_reads()
    m=next(m for m in env.r.methods.values() if m.simple_name=='write')
    return env.r.request({'action':'inspect_entity','entity_id':m.entity_id,'start_line':m.start_line,'end_line':m.end_line})

def draft(p,cwe='CWE-79'):
    return {'cwe':cwe,'title':'Synthetic wiring candidate only','input_reason':'Parameter is the synthetic source for this test.','effect_reason':'Output operation is the synthetic sink in this test.','guard_analysis':'No guard is declared in the synthetic method.','conditions':['TEST ONLY: not a detected vulnerability.'],'uncertainties':['No impact claim is made.'],'steps':[{'evidence_id':p['evidence_id'],'method_id':p['method_id'],'line':3,'end_line':3,'role':'SOURCE'},{'evidence_id':p['evidence_id'],'method_id':p['method_id'],'line':4,'end_line':4,'role':'SINK'}]}

def deliver(env,p,role='explorer'):
    assert not env.peer.service.deliver(role,{'source_evidence':[p]},{'mode':'TEST_ONLY_HTTP'})

def test_actual_r2_outer_and_original_modules(env):
    assert env.r.limits.calls_per_focus==2 and env.r.limits.max_focus==28
    assert env.r.limits.max_candidates is None and env.r.limits.per_cwe is None
    assert baseline(env.args.core).BenchmarkLimits().calls_per_focus==2
    assert env.e.core.__func__.__module__==baseline(env.args.core).__name__

def test_original_file_then_method_reuses_raw_reader_without_upgrading_file_proof(env,monkeypatch):
    env.r.inventory();env.r.activate_reads()
    m=next(m for m in env.r.methods.values() if m.simple_name=='write')
    service=env.peer.service;physical=service.original_range_reader;calls=[]
    def counted(*a,**k):calls.append((a,k));return physical(*a,**k)
    monkeypatch.setattr(service,'original_range_reader',counted)
    file_proof=env.r.request({'action':'read_file_range','file':'F.java','start_line':m.start_line,'end_line':m.end_line})
    method_proof=env.r.request({'action':'inspect_entity','entity_id':m.entity_id,'start_line':m.start_line,'end_line':m.end_line})
    assert len(calls)==1 and file_proof['evidence_id']!=method_proof['evidence_id']
    assert not service.state['proofs'][file_proof['evidence_id']]['candidate_step_eligible']
    assert service.state['proofs'][method_proof['evidence_id']]['candidate_step_eligible']
    assert method_proof['method_id']==m.entity_id and method_proof['source']==file_proof['source']
    assert not service.visible('explorer') and not service.visible('investigator')

def test_raw_reader_cache_survives_service_restore_and_returns_exact_original_result(env,monkeypatch):
    p=proof(env);service=env.peer.service
    expected=next(iter(service.state['raw_source_windows'].values()))['result']
    restored=EvidenceService(env.r,env.a,env.e.book,env.args.source_identity)
    monkeypatch.setattr(restored,'original_range_reader',lambda *a,**k:pytest.fail('Completed physical source read repeated'))
    actual=env.r.tools.read_file_range(p['file'],p['start_line'],p['end_line'],max_lines=160)
    assert actual==expected
    actual['text']='mutated caller copy'
    assert env.r.tools.read_file_range(p['file'],p['start_line'],p['end_line'],max_lines=160)==expected

def test_legacy_source_window_without_original_raw_result_is_blocked_not_reconstructed(env,monkeypatch):
    p=proof(env);service=env.peer.service;service.state['raw_source_windows'].clear();service.save()
    monkeypatch.setattr(service,'original_range_reader',lambda *a,**k:pytest.fail('Legacy completed read retried'))
    with pytest.raises(ServiceError,match='RECOVERY_BLOCKED: legacy window'):
        env.r.tools.read_file_range(p['file'],p['start_line'],p['end_line'],max_lines=160)

@pytest.mark.parametrize('failure',['IN_FLIGHT','HASH_MISMATCH'])
def test_unproven_or_corrupt_raw_reader_result_is_blocked_without_retry(env,monkeypatch,failure):
    p=proof(env);service=env.peer.service;entry=next(iter(service.state['raw_source_windows'].values()))
    if failure=='IN_FLIGHT':entry.update(status='IN_FLIGHT',result=None)
    else:entry['result']['text']='invalid cached content'
    service.save();monkeypatch.setattr(service,'original_range_reader',lambda *a,**k:pytest.fail('Unproven physical read retried'))
    with pytest.raises(ServiceError,match='RECOVERY_BLOCKED'):
        env.r.tools.read_file_range(p['file'],p['start_line'],p['end_line'],max_lines=160)

@pytest.mark.parametrize('raw',[{'tool':'inspect_entity','arguments':{'entity_id':'m'}},{'action':'inspect_entity','entity_id':'m'}])
def test_normalize_aliases(raw):
    assert normalize_retrieval_request(raw,requester='investigator')['arguments']=={'entity_id':'m'}

@pytest.mark.parametrize('raw',[{}, {'action':'shell','query':'x'}, {'action':'read_file_range','file':'../x','start_line':1,'end_line':2},{'action':'read_file_range','file':'patches/x.java','start_line':1,'end_line':2},{'action':'inspect_entity','entity_id':'m','start_line':1}, {'tool':'inspect_entity','action':'search_code','query':'x'},{'action':'read_file_range','file':'F.java','start_line':1,'end_line':200}])
def test_invalid_retrieval_is_explicit(raw):
    with pytest.raises(ServiceError):normalize_retrieval_request(raw,requester='investigator')

def test_shared_read_distinct_delivery_and_version(env):
    p=proof(env);mid=p['method_id'];calls=env.r.tool_calls
    result=env.peer.service.execute({'tool':'inspect_entity','arguments':{'entity_id':mid,'start_line':p['start_line'],'end_line':p['end_line']}},actor='investigator',hypotheses=['different-question'],execute=env.peer.original_request)
    assert result['evidence_id']==p['evidence_id'] and result['requester']=='investigator' and env.r.tool_calls==calls
    assert env.peer.service.visible('investigator')=={}
    deliver(env,p);assert p['evidence_id'] in env.peer.service.visible('explorer') and not env.peer.service.visible('investigator')
    deliver(env,p,'investigator');env.peer.service.use('investigator',[p['evidence_id']],'used_in_reasoning',{'test_only':True})
    assert len(env.peer.service.state['proofs'][p['evidence_id']]['used_in_reasoning'])==1
    with pytest.raises(ServiceError,match='version'):EvidenceService(env.r,env.a,env.e.book,'OTHER_TREE')

def test_delivery_file_level_receipt_not_dictionary(env):
    env.r.inventory();env.r.activate_reads()
    p=env.r.request({'action':'read_file_range','file':'F.java','start_line':1,'end_line':2})
    eid=p['evidence_id'];env.peer.service.state['proofs'].pop(eid);env.peer.service.save()
    assert eid not in env.r.evidence and eid not in env.a
    assert env.peer.validate_delivery('reasoning',{'source_evidence':[p]},{'mode':'TEST_ONLY_HTTP'})==[]
    assert not env.peer.service.state['proofs'][eid]['candidate_step_eligible']

@pytest.mark.parametrize('cwe',['CWE-22','CWE-78','CWE-79','CWE-94'])
def test_independent_candidate_original_validator_and_provenance(env,cwe):
    p=proof(env);deliver(env,p,'investigator')
    cid=env.peer.submit(draft(p,cwe),'investigator',{'hypothesis_id':'independent-not-explorer'})
    assert cid in env.r.candidates and env.peer.state['candidate_provenance'][cid]['roles']==['investigator']
    deliver(env,p)
    assert env.r.candidate(draft(p,cwe))==cid
    assert set(env.peer.state['candidate_provenance'][cid]['roles'])=={'investigator','explorer'}
    variant=draft(p,cwe);variant['steps'][0].update(line=2,end_line=2)
    assert env.peer.submit(variant,'investigator',{'hypothesis_id':'other-path'})==cid or len(env.r.candidates)>1

def test_unseen_source_rejected_durably(env):
    p=proof(env)
    with pytest.raises(ServiceError,match='delivered'):env.peer.submit(draft(p),'investigator',{'hypothesis_id':'h'})
    assert env.peer.state['candidate_attempts'][-1]['status']=='REJECTED' and not env.r.candidates

def fake_success(env,context,value):
    p=env.policies[context['role']];body=p.request_body(context);key=env.journal.identity(context,p)
    env.journal.append({'event':'request_started','request_key':key,'role':context['role'],'reserved_tokens':100,'body_sha256':hashed(body)})
    env.journal.requests+=1;env.journal.tokens+=100
    turn=ModelTurn(json.dumps(value),{'prompt_tokens':13,'completion_tokens':7,'total_tokens':20},{'finish_reason':'stop','http_status':200})
    env.holder['recovery'].store.put(body,context,turn,{'mode':'ACTUAL_HTTP_RESPONSE','test_only':True})
    return p,turn

def test_settled_success_survives_observer_failure_no_resend(env,monkeypatch):
    p=proof(env);ctx={'role':'reasoning','source_evidence':[p]};policy,turn=fake_success(env,ctx,{'candidates':[draft(p)]})
    monkeypatch.setattr(env.peer,'observe',lambda *a:(_ for _ in ()).throw(ValueError('TEST_ONLY_OBSERVER_FAILURE')))
    received=env.wrapped['reasoning'](ctx)
    assert received.content==turn.content and len(env.journal.responses)==1 and env.journal.requests==1
    cid=env.r.candidate(json.loads(received.content)['candidates'][0]);assert cid in env.r.candidates
    assert any(s['state']=='COORDINATION_FAILED' for s in env.holder['recovery'].store.audit()[0]['states'])
    monkeypatch.undo();result=env.holder['recovery'].recover(env.policies)
    assert result[0]['new_physical_requests']==0 and env.journal.requests==1

@pytest.mark.parametrize('cut',['HTTP_SUCCESS','RESPONSE_PERSISTED','EVIDENCE_DELIVERED','INVESTIGATOR_DECIDED','CANDIDATE_SUBMITTED'])
def test_five_recovery_cutpoints(env,cut):
    p=proof(env);ctx={'role':'investigator','source_evidence':[p]};policy,turn=fake_success(env,ctx,{'action':'PAUSE','reason':'TEST ONLY','evidence_ids':[p['evidence_id']]})
    rec=env.holder['recovery'];v=rec.store.get(policy.request_body(ctx))
    if cut in {'EVIDENCE_DELIVERED','INVESTIGATOR_DECIDED','CANDIDATE_SUBMITTED'}:rec.reconcile_usage(v,policy);rec.coordinate(v)
    if cut in {'INVESTIGATOR_DECIDED','CANDIDATE_SUBMITTED'}:env.peer.state['decisions']['fixed']={'response':json.loads(turn.content)};env.peer.save()
    if cut=='CANDIDATE_SUBMITTED':env.peer.submit(draft(p),'investigator',{'hypothesis_id':'fixed'})
    journal=IdentityJournal(env.journal.path,source_identity=env.args.source_identity,max_requests=64,max_tokens=2**60,max_seconds=7200,binding=env.args.binding)
    recovery=ResponseRecovery(env.out,env.args.source_identity,journal,env.peer)
    assert recovery.recover(env.policies)[0]['status']=='RECOVERED_OR_ALREADY_SETTLED'
    assert journal.requests==1 and len(journal.responses)==1
    assert env.wrapped['investigator'](ctx).content==turn.content and env.journal.requests==1

@pytest.mark.parametrize('content,finish',[('', 'length'), ('{}','stop'), ('{"action":', 'length')])
def test_empty_truncation_not_valid_decision(content,finish):
    with pytest.raises(PolicyError):require_complete_protocol(ModelTurn(content,{'total_tokens':20},{'finish_reason':finish}))

def test_reserved_r2_and_verification(env):
    budget=env.holder['budget'];assert budget.reserved_r2()==28
    env.journal.max_requests=28
    with pytest.raises(Exception,match='protected R2'):budget.admit({'role':'investigator'},env.policies['investigator'])
    assert budget.reserved_r2()==28

def test_scope_scheduler_independent_of_explorer(env):
    assert env.r.model_calls==0
    scopes=env.peer.initialize_scopes();assert scopes and env.r.model_calls==0
    assert all(s['related_facts']['evidence_level']=='STATIC_NAVIGATION_NOT_VALUE_PROPAGATION' for s in scopes)

def test_independent_scope_model_gap_and_candidate_closes_through_original_review(env):
    """No Explorer model lead: the actual Peer scheduler drives all I operations."""
    calls=[]
    def investigator(ctx):
        calls.append(copy.deepcopy(ctx));env.peer.validate_delivery('investigator',ctx,{'mode':'TEST_ONLY_HTTP','turn':len(calls)})
        p=ctx['source_evidence'][0];scope=ctx['scope']['scope_id']
        if len(calls)==1:
            value={'hypothesis':{'scope_id':scope,'mechanism':'Synthetic output handling ambiguity','question':'Does the separate helper change the shown output value?','support_if':'The source shows an unprotected output boundary.','counter_if':'The helper applies the relevant protection.','unknowns':['Helper behavior.']},'action':'CONTINUE','reason':'Need a concrete helper window','evidence_ids':[p['evidence_id']],'evidence_gaps':[{'question':'What does the separate helper return?','missing_evidence':'The helper implementation','evidence_ids':[p['evidence_id']],'requests':[{'tool':'read_file_range','arguments':{'file':'F.java','start_line':7,'end_line':7}}]}]}
        else:value={'action':'PROMOTE','reason':'Synthetic original-adapter wiring only','evidence_ids':[p['evidence_id']],'candidates':[draft(p)],'unknowns':['TEST ONLY: no impact claim.']}
        return ModelTurn(json.dumps(value),{'total_tokens':1},{'finish_reason':'stop','test_only':True})
    env.peer.policy=investigator;env.peer.max_scopes=1
    env.peer.run_independent()
    assert len(calls)==2 and not env.r.stop and env.r.model_calls==0
    assert env.r.candidates and all(p['roles']==['investigator'] for p in env.peer.state['candidate_provenance'].values())
    def verification(ctx):
        return ModelTurn(json.dumps({'reviews':[{'candidate_path_id':c['candidate_path_id'],'verdict':'RETAIN_UNCONFIRMED','reason':'TEST ONLY: original review wiring','evidence_refs':c['evidence_refs']} for c in ctx['candidates']]}),{'total_tokens':1},{'test_only':True})
    env.wrapped['verification'].physical_send=verification;env.e.verify_pending()
    assert set(env.r.reviews)==set(env.r.candidates) and all(not v['strict_verification'] for v in env.r.reviews.values())

def test_r2_reference_behavior_matches_repaired_explorer(env,tmp_path):
    """Compare actual unmodified R2 dispatch/tool continuation with the sidecar."""
    from dataclasses import replace
    from java_vuln_research.work1_agent.fasttrack import build_runner
    from java_vuln_research.work1_agent.a1_resource_evidence import install as mixed
    from java_vuln_research.work1_agent.targeted_a1 import install as targeted
    from java_vuln_research.work1_agent.a1_contract_context import install as contract
    from java_vuln_research.work1_agent.a1_execution import ExecutionController
    from java_vuln_research.work1_agent.mechanism_coverage import install as mechanism
    from java_vuln_research.work1_agent.a1_verification_budget import BudgetAdmission
    from java_vuln_research.work1_agent.r2_hecv_run import SWITCHES
    reference=tmp_path/'reference';reference.mkdir();seen=[[],[]]
    def model(index,runner):
        def call(ctx):
            seen[index].append(copy.deepcopy(ctx));witness={'mode':'TEST_ONLY_HTTP','n':len(seen[index])}
            if index==1:env.peer.validate_delivery(ctx['role'],ctx,witness);env.peer.observe(ctx['role'],ctx,ModelTurn('{"disposition":"continue"}',{},{}),witness)
            if ctx['role']=='discovery':value={'leads':[]}
            elif ctx['role']=='verification':value={'reviews':[]}
            else:
                reasoning=sum(x['role']=='reasoning' for x in seen[index])
                value={'disposition':'TEST ONLY source question','requests':[{'action':'read_file_range','file':'F.java','start_line':7,'end_line':7}]} if reasoning==1 else {'disposition':'TEST ONLY bounded answer'}
            return ModelTurn(json.dumps(value),{'total_tokens':1},{'test_only':True})
        return call
    original=build_runner(Path(env.args.repository),reference,None,r12_implementation=Path(env.args.core),strategy='A1',static_report=Path(env.args.static_report),static_graph=Path(env.args.static_graph),limits=replace(baseline(env.args.core).BenchmarkLimits(),max_candidates=None,per_cwe=None,max_focus=28),tool_limit=128)
    original.team=AgentTeam(*(model(0,original) for _ in range(3)))
    archive=mixed(original,automatic=True);contract(original,[]);targeted(original,SWITCHES,archive,chain_managed=True)
    original_engine=ExecutionController(original,archive,'TEST_ONLY_82532',critical=True);mechanism(original_engine,[])
    env.r.team=AgentTeam(*(model(1,env.r) for _ in range(3)))
    # Both run the unchanged R2 dispatcher. Disable candidate work in this trace;
    # original candidate+Verification are exercised independently above.
    before=original.run();after=env.r.run()
    def projection(rows):
        return [{'role':v['role'],'focus':v.get('focus'),'source_evidence':v.get('source_evidence'),'supported_cwes':v.get('supported_cwes'),'retrieval_results':v.get('retrieval_results')} for v in rows]
    assert projection(seen[0])==projection(seen[1])
    assert before['model_calls']==after['model_calls'] and before['tool_calls']==after['tool_calls'] and before['stop_reason']==after['stop_reason']
    assert any(t.get('followup_of') for t in env.e.book.state['tasks'].values())
    assert any(any(p.get('start_line')==7 for p in c.get('source_evidence',[])) for c in seen[1][2:])

def test_original_a1_three_inner_turns_are_not_confused_with_r2(env):
    # Inspecting the unchanged original implementation distinguishes its loop
    # default from R2's dispatcher. The preceding test executes R2 continuations.
    import inspect
    assert 'range(self.limits.calls_per_focus + 1)' in inspect.getsource(env.e.core)
    assert env.r.limits.calls_per_focus==2

def restart(env):
    env.r.trace.flush();env.r.trace.close();before=(env.out/'trace.jsonl').read_bytes();env.args.resume=True
    r,e,a,peer=build(env.args,env.team,env.wrapped['investigator'],env.journal,env.history,env.policies,env.holder)
    assert (env.out/'trace.jsonl').read_bytes()==before
    return r,e,peer

def test_original_candidate_and_evidence_survive_real_controller_restart(env):
    p=proof(env);deliver(env,p,'investigator');origin={'hypothesis_id':'durable'}
    cid=env.peer.submit(draft(p),'investigator',origin);count=env.r.tool_calls
    r,e,peer=restart(env)
    try:
        peer.recover_candidates();assert cid in r.candidates
        assert peer.submit(draft(p),'investigator',origin)==cid
        assert r.read(p['method_id'],p['start_line'],p['end_line'])==p and r.tool_calls==count
        assert len(r.candidates)==1 and env.journal.requests==0
    finally:r.trace.close()

def test_pending_investigator_response_restarts_with_exact_http_identity(env):
    class Crash(BaseException):pass
    def interrupted(ctx):
        fake_success(env,ctx,{'action':'RETAIN','reason':'TEST ONLY: pending response recovery','evidence_ids':[ctx['source_evidence'][0]['evidence_id']]})
        env.wrapped['investigator'](ctx)
        raise Crash()
    env.peer.policy=interrupted;env.peer.max_scopes=1
    with pytest.raises(Crash):env.peer.run_independent()
    assert env.journal.requests==1
    r,e,peer=restart(env)
    try:
        peer.run_independent()
        assert env.journal.requests==1 and len(peer.state['decisions'])==1
        assert all(i['status']=='DECIDED' for i in peer.state['issues'].values())
    finally:r.trace.close()

def test_cross_resource_exact_multiline_and_distinct_paths(env):
    p=proof(env);q=env.r.request({'tool':'read_file_range','file':'view.js','start_line':1,'end_line':2});deliver(env,p,'investigator');deliver(env,q,'investigator')
    d=draft(p);d['steps'][0].update(line=2,end_line=3);d['steps'][1]={'evidence_id':q['evidence_id'],'resource_id':q['resource_id'],'line':2,'end_line':2,'role':'SINK'}
    cid=env.peer.submit(d,'investigator',{'hypothesis_id':'multiline-resource'})
    assert '\n' in env.r.candidates[cid]['ordered_nodes'][0]['expression']
    d2=copy.deepcopy(d);d2['steps'][0]['end_line']=2;d2['steps'].insert(1,{'evidence_id':p['evidence_id'],'method_id':p['method_id'],'line':3,'end_line':3,'role':'PROPAGATION'})
    assert env.peer.submit(d2,'investigator',{'hypothesis_id':'separate-path'})==cid
    assert len(env.peer.state['candidate_provenance'][cid]['exact_paths'])==2

def issue(hid,scope,eid):
    return {'hypothesis_id':hid,'scope_id':scope,'status':'PAUSED','supporting':[eid],'counter':[eid],'unknowns':['Unknown actual caller.'],'children':[],'dependencies':['initial-dependency'],'history':[]}

def test_split_preserves_evidence_counter_unknowns_and_children_are_executed(env):
    seen=[];env.peer.max_scopes=1
    def investigate(ctx):
        seen.append(ctx);env.peer.validate_delivery('investigator',ctx,{'mode':'TEST_ONLY_HTTP'});eid=ctx['source_evidence'][0]['evidence_id'];sid=ctx['scope']['scope_id']
        if len(seen)==1:
            children=[{'scope_id':sid,'question':question,'mechanism':mechanism,'support_if':'Exact shown source supports this boundary.','counter_if':'A matching guard covers this use.','unknowns':['Actual consumer unknown.']} for question,mechanism in [('Is the return value independently consumed?','Returned-value protection'),('Is the direct output independently protected?','Direct-output protection')]]
            value={'action':'SPLIT','reason':'Two different source-visible consumer questions','evidence_ids':[eid],'counterevidence_ids':[eid],'unknowns':['Caller still unknown.'],'children':children}
        else:value={'action':'RETAIN','reason':'TEST ONLY child analysis completed','evidence_ids':[eid]}
        return ModelTurn(json.dumps(value),{}, {'finish_reason':'stop','test_only':True})
    env.peer.policy=investigate;env.peer.run_independent()
    assert len(seen)==3 and len(env.peer.state['issues'])==3
    parent=next(i for i in env.peer.state['issues'].values() if i.get('children'))
    for hid in parent['children']:
        child=env.peer.state['issues'][hid];assert child['counter']==parent['counter'] and 'Caller still unknown.' in child['unknowns'] and parent['hypothesis_id'] in child['dependencies'] and child['status']=='DECIDED'

@pytest.mark.parametrize('difference',[None,'consumer','relation','gap'])
def test_merge_requires_same_source_expression_consumer_relation_and_gap(env,difference):
    p=proof(env);deliver(env,p,'investigator');eid=p['evidence_id'];a=issue('a','scope',eid);b=issue('b','scope',eid)
    a['mechanism_identity']={'evidence_id':eid,'line':3,'expression':'String value = input;'}
    a['relation_identity']={'consumer_evidence_id':eid,'line':4,'expression':'System.out.print(value);','kind':'VALUE_TO_CONSUMER','missing_evidence':'Actual input trust'}
    b.update(mechanism_identity=copy.deepcopy(a['mechanism_identity']),relation_identity=copy.deepcopy(a['relation_identity']))
    if difference=='consumer':b['relation_identity']['line']=5
    if difference=='relation':b['relation_identity']['kind']='CALLER_GUARD'
    if difference=='gap':b['relation_identity']['missing_evidence']='Another distinct required input'
    b['unknowns']=['A different deployment unknown.'];env.peer.state['issues']={'a':a,'b':b}
    value={'action':'MERGE','merge_into':'b','reason':'Same exact source-grounded mechanism and relation'}
    if difference:
        with pytest.raises(ServiceError,match='exact mechanism'):env.peer.structural(a,value,[eid],{'b':b})
        assert a['status']=='PAUSED'
    else:
        env.peer.structural(a,value,[eid],{'b':b});assert a['status']=='MERGED' and set(b['unknowns'])=={'A different deployment unknown.','Unknown actual caller.'} and b['history'][0]['merged_original']['hypothesis_id']=='a'

def test_pending_verification_and_tool_allowance_are_reserved_before_investigator(env):
    p=proof(env);deliver(env,p,'investigator');cid=env.peer.submit(draft(p),'investigator',{'hypothesis_id':'reserve'})
    budget=env.holder['budget'];assert budget.plan()['held_requests']==1
    env.journal.max_requests=29
    with pytest.raises(Exception,match='protected R2'):budget.admit({'role':'investigator'},env.policies['investigator'])
    assert cid in env.r.candidates and budget.reserved_r2()==28
    env.r.tool_limit=128;assert not budget.investigator_tool_available()

def test_unsettled_tool_is_recovery_blocked_without_physical_retry(env):
    from java_vuln_research.work1_agent.benchmark import digest
    p=proof(env);a={'entity_id':p['method_id']};signature=digest([env.args.source_identity,'inspect_entity',a])
    env.peer.service.state['requests'][signature]={'dependencies':['first'],'result':None,'status':'IN_FLIGHT'};env.peer.service.save()
    with pytest.raises(ServiceError,match='RECOVERY_BLOCKED'):env.peer.service.execute({'action':'inspect_entity',**a},actor='investigator',execute=lambda a:pytest.fail('No unproven retry'))

def test_production_run_and_explicit_resume_make_no_duplicate_sdk_calls(env,monkeypatch):
    from java_vuln_research.work1_agent.r2_hecv_run import run
    from java_vuln_research.work1_agent.run_harness import OpenLuxChatPolicy
    sdk=[]
    def mock_sdk(self,ctx):
        sdk.append(ctx['role']);self.record_wire_request(json.dumps(self.request_body(ctx),ensure_ascii=False).encode())
        if ctx['role']=='investigator':value={'action':'PROMOTE','reason':'TEST ONLY independent candidate wiring','evidence_ids':[ctx['source_evidence'][0]['evidence_id']],'candidates':[draft(ctx['source_evidence'][0])]}
        elif ctx['role']=='discovery':value={'leads':[]}
        elif ctx['role']=='verification':value={'reviews':[{'candidate_path_id':c['candidate_path_id'],'verdict':'RETAIN_UNCONFIRMED','reason':'TEST ONLY original Verification entry','evidence_refs':c['evidence_refs']} for c in ctx['candidates']]}
        else:value={'disposition':'TEST ONLY no further evidence gap'}
        raw=json.dumps({'model':self.model,'choices':[{'message':{'content':json.dumps(value)},'finish_reason':'stop'}],'usage':{'prompt_tokens':1,'completion_tokens':1,'total_tokens':2}}).encode()
        turn=self.response_turn(raw);return ModelTurn(turn.content,turn.usage,{**turn.metadata,'http_status':200,'test_only':True})
    monkeypatch.setattr(OpenLuxChatPolicy,'__call__',mock_sdk);monkeypatch.setenv('WORK1_AGENT_API_KEY','TEST_ONLY');monkeypatch.setenv('FASTTRACK_AUTHORIZED_LIVE','1')
    args=copy.deepcopy(env.args);args.output=str(env.tmp_path/'full-cli');args.history=str(env.tmp_path/'history.sqlite');args.model='gpt-6.1-sol';args.max_scopes=1
    result=run(args);assert not result['error'] and result['candidates']==1 and result['reviews']==1
    assert 'investigator' in sdk and 'reasoning' in sdk and 'verification' in sdk
    calls=len(sdk);original=(Path(args.output)/'trace.jsonl').read_bytes();args.resume=True
    resumed=run(args)
    assert not resumed['error'] and len(sdk)==calls and resumed['candidates']==1 and resumed['reviews']==1
    assert (Path(args.output)/'trace.jsonl').read_bytes()==original

@pytest.mark.parametrize('conditions',['A concrete protection condition.',['One protection condition.','Another independent condition.']])
def test_hypothesis_conditions_preserve_scalar_or_list_without_rewriting(conditions):
    from java_vuln_research.work1_agent.hecv_protocol import _hypothesis_seed
    h={'scope_id':'s','question':'What does the actual guard protect?','mechanism':'Source-visible guard scope','support_if':copy.deepcopy(conditions),'counter_if':copy.deepcopy(conditions),'unknowns':['Actual consumer unknown.']};saved=copy.deepcopy(h)
    value=_hypothesis_seed(h,'s');assert h==saved and value['support_if']==conditions and value['counter_if']==conditions

@pytest.mark.parametrize('conditions',[None,[],['x']*9,{'condition':'Not an allowed type'},['']])
def test_malformed_conditions_remain_rejected(conditions):
    from java_vuln_research.work1_agent.hecv_protocol import _hypothesis_seed
    h={'scope_id':'s','question':'What does the guard protect?','mechanism':'Guard coverage question','support_if':conditions,'counter_if':'Explicit refutation condition.','unknowns':[]}
    with pytest.raises(ValueError):_hypothesis_seed(h,'s')

def test_independent_candidate_survives_unrelated_hypothesis_metadata_error(env):
    env.peer.max_scopes=1
    def policy(ctx):
        env.peer.validate_delivery('investigator',ctx,{'mode':'TEST_ONLY_HTTP'});p=ctx['source_evidence'][0]
        h={'scope_id':ctx['scope']['scope_id'],'question':'Is this direct output guarded?','mechanism':'Local output boundary','support_if':['Input reaches the shown output.'],'counter_if':{'invalid':'typed metadata'},'unknowns':[]}
        return ModelTurn(json.dumps({'hypothesis':h,'action':'PROMOTE','reason':'TEST ONLY valid independent candidate','evidence_ids':[p['evidence_id']],'candidates':[draft(p)]}),{}, {'finish_reason':'stop','test_only':True})
    env.peer.policy=policy;env.peer.run_independent()
    assert len(env.r.candidates)==1 and env.peer.state['candidate_attempts'][0]['status']=='ACCEPTED_OR_ORIGINAL_ENDPOINT_COALESCED'
    assert all(i['status']=='PAUSED' and i.get('error') for i in env.peer.state['issues'].values())

def test_original_resource_middleware_bridges_cross_resource_candidate_to_real_review(env):
    p=proof(env);resource=env.r.request({'tool':'read_file_range','file':'view.js','start_line':1,'end_line':2});deliver(env,p,'investigator');deliver(env,resource,'investigator')
    d=draft(p);d['steps'][1]={'evidence_id':resource['evidence_id'],'resource_id':resource['resource_id'],'line':2,'end_line':2,'role':'SINK'}
    cid=env.peer.submit(d,'investigator',{'hypothesis_id':'resource-review-regression'});seen=[]
    def review(ctx):
        seen.append(ctx)
        return ModelTurn(json.dumps({'reviews':[{'candidate_path_id':cid,'verdict':'RETAIN_UNCONFIRMED','reason':'TEST ONLY cross-resource original Verification','evidence_refs':[p['evidence_id'],resource['evidence_id']]}]}),{'total_tokens':1},{'finish_reason':'stop','test_only':True})
    env.wrapped['verification'].physical_send=review;env.e.verify_pending()
    assert cid in env.r.reviews and len(seen)==1
    assert {v['evidence_id'] for v in seen[0]['source_evidence']}=={p['evidence_id'],resource['evidence_id']}
    assert env.r.reviews[cid]['verdict']=='RETAIN_UNCONFIRMED' and not env.r.reviews[cid]['strict_verification']

def test_settled_explorer_draft_not_consumed_before_interrupt_is_recovered_once(env):
    p=proof(env);ctx={'role':'reasoning','source_evidence':[p]};policy,turn=fake_success(env,ctx,{'candidates':[draft(p)]})
    saved=env.holder['recovery'].store.get(policy.request_body(ctx));env.holder['recovery'].reconcile_usage(saved,policy);env.holder['recovery'].coordinate(saved)
    assert not env.r.candidates
    env.peer.recover_candidates();assert len(env.r.candidates)==1 and env.journal.requests==1
    count=len(env.peer.state['candidate_attempts']);env.peer.recover_candidates()
    assert len(env.peer.state['candidate_attempts'])==count and len(env.r.candidates)==1 and env.journal.requests==1

def test_condition_lists_reach_independent_decision_and_candidate(env):
    env.peer.max_scopes=1
    def policy(ctx):
        env.peer.validate_delivery('investigator',ctx,{'mode':'TEST_ONLY_HTTP'});p=ctx['source_evidence'][0]
        h={'scope_id':ctx['scope']['scope_id'],'question':'Does the shown output have a matching guard?','mechanism':'Explicit output boundary','support_if':['The source reaches the output.'],'counter_if':['A context-correct guard protects this value.'],'unknowns':['Actual caller unknown.']}
        return ModelTurn(json.dumps({'hypothesis':h,'action':'PROMOTE','reason':'TEST ONLY list-condition integration','evidence_ids':[p['evidence_id']],'candidates':[draft(p)]}),{}, {'finish_reason':'stop','test_only':True})
    env.peer.policy=policy;env.peer.run_independent()
    assert len(env.r.candidates)==1
    hypothesis=next(iter(env.peer.state['issues'].values()))
    assert hypothesis['status']=='DECIDED' and hypothesis['support_if']==['The source reaches the output.'] and not hypothesis.get('error')

def gap_value(ctx,requests,action='CONTINUE'):
    return {'action':action,'reason':'TEST ONLY concrete evidence gap','evidence_ids':[ctx['source_evidence'][0]['evidence_id']],'evidence_gaps':[{'question':'What does the actual helper source contain?','missing_evidence':'The helper implementation or its indexed location','evidence_ids':[ctx['source_evidence'][0]['evidence_id']],'requests':requests}]}

def test_search_navigation_is_delivered_before_followup_source_selection(env):
    calls=[];env.peer.max_scopes=1
    def policy(ctx):
        calls.append(copy.deepcopy(ctx));assert not env.peer.validate_delivery('investigator',ctx,{'mode':'TEST_ONLY_HTTP','turn':len(calls)})
        if len(calls)==1:value=gap_value(ctx,[{'action':'search_symbols','query':'other'}])
        elif len(calls)==2:
            hits=ctx['retrieval_results'][0]['original_result']['hits'];assert hits
            eid=hits[0]['entity']['entity_id'];assert eid in env.r.methods
            value=gap_value(ctx,[{'tool':'inspect_entity','arguments':{'entity_id':eid}}])
        else:
            assert any('return text' in p['source'] for p in ctx['source_evidence'])
            value={'action':'RETAIN','reason':'TEST ONLY source followed from actual search facts','evidence_ids':[p['evidence_id'] for p in ctx['source_evidence']]}
        return ModelTurn(json.dumps(value),{}, {'finish_reason':'stop','test_only':True})
    env.peer.policy=policy;env.peer.run_independent()
    assert len(calls)==3 and next(iter(env.peer.state['issues'].values()))['status']=='DECIDED'
    records=env.peer.service.state['requests'];search=next(v for v in records.values() if v.get('result',{}).get('normalized_action',{}).get('action')=='search_symbols')
    assert search['delivered_to']['investigator']

def test_invalid_tool_gets_one_bounded_model_correction_without_implicit_translation(env):
    calls=[];env.peer.max_scopes=1
    def policy(ctx):
        calls.append(copy.deepcopy(ctx));env.peer.validate_delivery('investigator',ctx,{'mode':'TEST_ONLY_HTTP'})
        if len(calls)==1:value=gap_value(ctx,[{'action':'retrieve_source','arguments':{'file':'F.java','scope':'helper'}}])
        elif len(calls)==2:
            assert ctx['task']=='retrieval_protocol_correction' and ctx['protocol_feedback']['unexecuted_gaps'][0]['requests'][0]['action']=='retrieve_source'
            value=gap_value(ctx,[{'action':'read_file_range','file':'F.java','start_line':7,'end_line':7}])
        else:value={'action':'RETAIN','reason':'TEST ONLY corrected request returned real source','evidence_ids':[p['evidence_id'] for p in ctx['source_evidence']]}
        return ModelTurn(json.dumps(value),{}, {'finish_reason':'stop','test_only':True})
    env.peer.policy=policy;env.peer.run_independent();issue=next(iter(env.peer.state['issues'].values()))
    assert len(calls)==3 and issue['status']=='DECIDED' and not issue.get('error') and len(issue['protocol_rejections'])==1
    before=env.r.tool_calls;env.peer.run_independent();assert len(calls)==3 and env.r.tool_calls==before
    assert all(v.get('result',{}).get('normalized_action',{}).get('action')!='retrieve_source' for v in env.peer.service.state['requests'].values())

def test_unchanged_invalid_tool_does_not_loop_or_become_valid_decision(env):
    calls=[];env.peer.max_scopes=1
    def policy(ctx):
        calls.append(ctx);env.peer.validate_delivery('investigator',ctx,{'mode':'TEST_ONLY_HTTP'})
        return ModelTurn(json.dumps(gap_value(ctx,[{'action':'retrieve_source','arguments':{'file':'F.java'}}])),{}, {'finish_reason':'stop','test_only':True})
    env.peer.policy=policy;env.peer.run_independent();issue=next(iter(env.peer.state['issues'].values()))
    assert len(calls)==2 and issue['status']=='PAUSED' and issue['pause_reason']=='BOUNDED_PROTOCOL_REPAIR_EXHAUSTED'
    before=env.r.tool_calls;env.peer.run_independent();assert len(calls)==2 and env.r.tool_calls==before

def test_existing_resource_window_is_reused_without_reader_or_file_text_access(env,monkeypatch):
    resource=env.r.request({'action':'read_file_range','file':'view.js','start_line':1,'end_line':2});before=env.r.tool_calls
    env.peer.service.state['requests'].clear();env.peer.service.save()
    original=Path.read_text
    def guarded(path,*a,**k):
        if path==Path(env.args.repository)/'view.js':pytest.fail('Completed source window must not be read again')
        return original(path,*a,**k)
    monkeypatch.setattr(Path,'read_text',guarded)
    result=env.peer.service.execute({'tool':'read_file_range','file':'view.js','start_line':1,'end_line':2},actor='investigator',execute=lambda a:pytest.fail('No repeated source reader'))
    assert result['evidence_id']==resource['evidence_id'] and result['reuse_origin']=='PROVEN_ORIGINAL_ACQUIRED_WINDOW' and env.r.tool_calls==before

def test_original_automatic_resource_windows_restore_from_acquired_cache(env,tmp_path):
    source=tmp_path/'websource';(source/'src/main/java/demo').mkdir(parents=True);(source/'src/main/resources/templates').mkdir(parents=True)
    (source/'src/main/java/demo/Page.java').write_text('package demo;\nimport org.springframework.stereotype.Controller;\nimport org.springframework.web.bind.annotation.GetMapping;\n@Controller\nclass Page {\n @GetMapping("/view")\n public String page() { return "view"; }\n}\n')
    (source/'src/main/resources/templates/view.html').write_text('<div>hello</div>\n')
    args=copy.deepcopy(env.args);args.repository=str(source);args.output=str(tmp_path/'webout');args.source_identity='TEST_ONLY_WEB_CACHE';Path(args.output).mkdir()
    holder={};r,e,a,peer=build(args,env.team,env.wrapped['investigator'],env.journal,env.history,env.policies,holder)
    try:
        r.inventory();r.activate_reads();m=next(m for m in r.methods.values() if m.simple_name=='page');p=r.read(m.entity_id)
        refs=r.resource_reference_cache;packet=refs.build([p],methods=r.methods);assert packet['source_evidence']
        for q in packet['source_evidence']:peer.service.acquire(q,{'kind':'ORIGINAL_R2_RESOURCE_WINDOW_TEST'},'explorer')
        peer.service.deliver('explorer',{'source_evidence':packet['source_evidence']},{'mode':'TEST_ONLY_HTTP'})
        before=refs.stats['window_reads'];refs.windows.clear();again=refs.build([p],methods=r.methods)
        assert refs.stats['window_reads']==before and not again['window_reads'] and again['previous_evidence']
    finally:r.trace.close()

def test_non_source_queries_cannot_bypass_physical_tool_cap(env):
    proof(env);env.r.physical_tool_limit=env.r.tool_calls
    with pytest.raises(ServiceError,match='Physical tool-operation'):
        env.peer.service.execute({'action':'search_symbols','query':'other'},actor='investigator',execute=lambda a:pytest.fail('No over-budget query'))

def test_investigator_query_operations_preserve_r2_tool_reservation(env):
    proof(env);env.peer.service.state['non_read_operations']=128
    assert not env.e.budget.investigator_tool_available()
