"""UNIT TEST ONLY: real transport ledger/recovery services, synthetic peers."""
import json,copy,socket
from types import SimpleNamespace
from pathlib import Path
import pytest
from java_vuln_research.work1_agent.r2_hecv_run import DirectHistory,DirectPolicy
from java_vuln_research.work1_agent.r2_hecv_services import EvidenceService,ResponseStore,ServiceError,ScopeScheduler
from java_vuln_research.work1_agent.r2_hecv_recovery import ResponseRecovery
from java_vuln_research.work1_agent.a1_history import IdentityJournal,HistoryIndex,hashed
from java_vuln_research.work1_agent.harness import ModelTurn,PolicyError
from java_vuln_research.work1_agent.benchmark import digest
from java_vuln_research.work1_agent.repository.reader import read_file_range as bounded_read

@pytest.fixture
def boundary(tmp_path,monkeypatch):
    monkeypatch.setattr(socket.socket,'connect',lambda *a,**k:pytest.fail('No network'))
    out=tmp_path/'out';out.mkdir();repo=tmp_path/'source';repo.mkdir()
    (repo/'F.java').write_text('class F {\n String write(String input) { return input; }\n}\n')
    method=SimpleNamespace(entity_id='m',repository_relative_path='F.java',start_line=2,end_line=2)
    r=SimpleNamespace(output=out,tools=SimpleNamespace(index=SimpleNamespace(repository_root=repo),read_file_range=lambda file,first,last,**options:bounded_read(repo,file,first,last,**options)),retrieval=SimpleNamespace(entities={'m':method}),evidence={},methods={'m':method})
    service=EvidenceService(r,{},None,'TEST_ONLY_SOURCE')
    proof={'evidence_id':'bsrc-test','method_id':'m','file':'F.java','start_line':2,'end_line':2,'source':'2 |  String write(String input) { return input; }','content_sha256':digest([' String write(String input) { return input; }'])}
    r.evidence[proof['evidence_id']]=proof
    seen=[]
    def observe(*args):seen.append(args)
    peer=SimpleNamespace(validate_delivery=lambda role,ctx,w:service.deliver('explorer' if role=='reasoning' else role,ctx,w),observe=observe)
    journal=IdentityJournal(out/'requests.jsonl',source_identity='TEST_ONLY_SOURCE',max_requests=64,max_tokens=2**60,max_seconds=7200,binding='TEST_ONLY_82532')
    history=HistoryIndex(tmp_path/'history.sqlite');holder={}
    p=DirectPolicy('TEST_ONLY','TEST ONLY','gpt-6.1-sol','TEST_ONLY_SOURCE',history,holder,Path(__file__))
    recovery=ResponseRecovery(out,'TEST_ONLY_SOURCE',journal,peer);holder['recovery']=recovery;holder['peer']=peer
    wrapped=DirectHistory(history,p,journal.wrap(p),out/'logical-work.jsonl','TEST_ONLY_SOURCE',journal=journal,holder=holder)
    ctx={'role':'reasoning','source_evidence':[proof]};body=p.request_body(ctx);key=journal.identity(ctx,p)
    journal.append({'event':'request_started','request_key':key,'role':'reasoning','reserved_tokens':100,'body_sha256':hashed(body)})
    journal.requests=1;journal.tokens=100
    turn=ModelTurn('{"disposition":"TEST ONLY"}',{'prompt_tokens':13,'completion_tokens':7,'total_tokens':20},{'finish_reason':'stop','http_status':200})
    yield SimpleNamespace(**locals())

def test_real_directhistory_returns_success_despite_coordination_failure(boundary):
    b=boundary;b.recovery.store.put(b.body,b.ctx,b.turn,{'mode':'ACTUAL_HTTP_RESPONSE','test_only':True})
    b.peer.observe=lambda *a:(_ for _ in ()).throw(ValueError('TEST_ONLY_COORDINATION_FAILURE'))
    result=b.wrapped(b.ctx)
    assert result.content==b.turn.content and len(b.journal.responses)==1 and b.journal.requests==1 and b.journal.tokens==20
    assert b.proof['evidence_id'] in b.service.visible('explorer')
    states=b.recovery.store.audit()[0]['states'];assert any(v['state']=='COORDINATION_FAILED' for v in states) and any(v['state']=='RESPONSE_RETURNED' for v in states)
    b.peer.observe=lambda *a:b.seen.append(a)
    assert b.recovery.recover({'reasoning':b.p})[0]['status']=='RECOVERED_OR_ALREADY_SETTLED'
    assert b.wrapped(b.ctx).content==result.content and b.journal.requests==1

def test_validation_failure_and_coordination_failure_are_separate(boundary):
    b=boundary;b.recovery.store.put(b.body,b.ctx,b.turn,{'mode':'ACTUAL_HTTP_RESPONSE'})
    b.peer.validate_delivery=lambda *a:(_ for _ in ()).throw(ValueError('TEST_ONLY_DELIVERY_FAILURE'))
    assert b.wrapped(b.ctx).content==b.turn.content and b.seen
    states=b.recovery.store.audit()[0]['states'];assert any(v['state']=='DELIVERY_FAILED' for v in states) and any(v['state']=='COORDINATED' for v in states)

@pytest.mark.parametrize('cut',['HTTP_SUCCESS','RESPONSE_PERSISTED','EVIDENCE_DELIVERED','INVESTIGATOR_DECIDED','CANDIDATE_SUBMITTED'])
def test_ledger_recovery_cutpoints_no_resend(boundary,cut):
    b=boundary
    if cut=='HTTP_SUCCESS':
        folder=b.out/'request-audit/001-reasoning';folder.mkdir(parents=True)
        for name,value in [('request-body.json',b.body),('semantic-context.json',b.ctx)]: (folder/name).write_text(json.dumps(value))
        b.p.audit=folder;b.p.context=b.ctx
        raw=json.dumps({'model':b.p.model,'choices':[{'message':{'content':b.turn.content},'finish_reason':'stop'}],'usage':b.turn.usage}).encode()
        b.p.response_turn(raw) # Original transport's success callback, TEST ONLY raw envelope.
    else:
        b.recovery.store.put(b.body,b.ctx,b.turn,{'mode':'ACTUAL_HTTP_RESPONSE'})
        if cut!='RESPONSE_PERSISTED':
            v=b.recovery.store.get(b.body);b.recovery.reconcile_usage(v,b.p);b.recovery.coordinate(v)
        # Decision/candidate crash markers here test transport idempotence only;
        # full original-candidate production recovery is tested in the AST suite.
        if cut in {'INVESTIGATOR_DECIDED','CANDIDATE_SUBMITTED'}:b.recovery.store.event(b.recovery.store.key(b.body),cut,test_only=True)
    journal=IdentityJournal(b.journal.path,source_identity='TEST_ONLY_SOURCE',max_requests=64,max_tokens=2**60,max_seconds=7200,binding='TEST_ONLY_82532')
    rec=ResponseRecovery(b.out,'TEST_ONLY_SOURCE',journal,b.peer)
    assert rec.recover({'reasoning':b.p})[0]['status']=='RECOVERED_OR_ALREADY_SETTLED'
    assert journal.requests==1 and len(journal.responses)==1 and journal.tokens==20
    assert rec.recover({'reasoning':b.p})[0]['usage_reconciled'] is False

def test_raw_without_success_receipt_blocks_recovery(boundary):
    b=boundary;folder=b.out/'request-audit/001-reasoning';folder.mkdir(parents=True)
    (folder/'request-body.json').write_text(json.dumps(b.body));(folder/'actual-provider-response.json').write_text('{}')
    assert b.recovery.recover({'reasoning':b.p})[0]['status']=='RECOVERY_BLOCKED' and not b.journal.responses

def test_failed_proof_does_not_promote_read_to_delivery(boundary):
    b=boundary;p=copy.deepcopy(b.proof);p['source']='2 | invented text'
    failures=b.service.deliver('explorer',{'source_evidence':[p]},{'mode':'TEST_ONLY'})
    assert failures and not b.service.visible('explorer') and b.service.state['proofs'][b.proof['evidence_id']]['delivered_to']=={}

def test_file_level_java_registry_no_method_dictionary_required(boundary):
    b=boundary;p={k:v for k,v in b.proof.items() if k!='method_id'};p.update(evidence_id='fsrc-test',candidate_step_eligible=False)
    (b.out/'trace.jsonl').write_text(json.dumps({'event':'file_source_read','proof':p})+'\n')
    assert not b.service.deliver('explorer',{'source_evidence':[p]},{'mode':'TEST_ONLY'})
    assert b.service.state['proofs']['fsrc-test']['evidence_type']=='JAVA_FILE' and not b.service.state['proofs']['fsrc-test']['candidate_step_eligible']

def test_normalized_request_shared_across_hypotheses_and_agents(boundary):
    b=boundary;reads=[]
    def execute(a):reads.append(a);return b.proof
    a=b.service.execute({'action':'inspect_entity','entity_id':'m'},actor='explorer',hypotheses=['q1'],execute=execute)
    c=b.service.execute({'tool':'inspect_entity','arguments':{'entity_id':'m'}},actor='investigator',hypotheses=['q2'],execute=execute)
    assert len(reads)==1 and a['evidence_id']==c['evidence_id'] and c['requester']=='investigator' and c['reused']
    assert b.service.state['requests'][a['request_id']]['dependencies']==['q1','q2']
    assert not b.service.visible('investigator')

def test_real_read_failure_is_not_empty_success(boundary):
    b=boundary
    result=b.service.execute({'action':'inspect_entity','entity_id':'m'},actor='investigator',execute=lambda a:(_ for _ in ()).throw(OSError('TEST_ONLY_READ_FAILURE')))
    assert result['error']=='TEST_ONLY_READ_FAILURE' and not result['complete'] and result['actual_source_content'] is None

def test_outside_bounds_and_source_version_rejected(boundary):
    b=boundary
    b.service.read_range('F.java',1,3,max_lines=160)
    refused=b.service.execute({'action':'read_file_range','file':'F.java','start_line':1,'end_line':5},actor='investigator',execute=lambda a:pytest.fail('Must reject before physical read'))
    assert refused['validation_refusal'] and refused['original_result']['file_lines']==3 and not refused['complete'] and not refused['candidate_step_eligible']
    with pytest.raises(ServiceError,match='version'):EvidenceService(b.r,{},None,'OTHER_SOURCE')

def test_truncated_tool_response_explicit(boundary):
    b=boundary
    result=b.service.execute({'action':'inspect_entity','entity_id':'m','start_line':2,'end_line':3},actor='investigator',execute=lambda a:b.proof)
    assert result['truncated'] and not result['complete'] and result['evidence_id']==b.proof['evidence_id']
