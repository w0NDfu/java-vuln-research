"""Minimal TEST ONLY checks for the 82533 production boundaries; no network."""
import copy,json
from pathlib import Path
import pytest
from test_r2_hecv_82532 import env,offline,proof,deliver
from java_vuln_research.work1_agent.r2_hecv_services import ScopeScheduler
from java_vuln_research.work1_agent.harness import ModelTurn
from java_vuln_research.work1_agent.run_harness import OpenLuxChatPolicy

def response(ctx,**extra):
    return {'action':'PAUSE','reason':'TEST ONLY: current boundary is understood; external conditions remain UNKNOWN.','evidence_ids':[p['evidence_id'] for p in ctx['source_evidence']],**extra}

def scope_catalogue(env):
    p=proof(env);mid=p['method_id'];out=[]
    for channel,kinds in [('R2_MECHANISM_CATALOGUE',['MECH_A','MECH_B']),('STATIC_BOUNDARY_FALLBACK',['CWE-22','CWE-78','CWE-79','CWE-94'])]:
        for kind in kinds:
            for n in range(2):out.append({'scope_id':channel+kind+str(n),'source_channel':channel,'scope_kind':kind,'method_id':mid,'question_seed':'TEST ONLY concrete boundary question','source_tree_sha256':env.args.source_identity,'entry_evidence':[],'related_facts':{},'status':'QUEUED'})
    env.peer.state['scope_catalogue']=out;env.peer.state['scope_rotation']={'channel_cursor':0,'kind_cursors':{},'issue_cursor':0,'next_work':'NEW','active_scope_ids':[]};env.peer.save();return out

def test_scope_channels_kinds_release_and_restart(env):
    catalogue=scope_catalogue(env);rotation={};chosen=[]
    for _ in range(6):
        s=ScopeScheduler.select(catalogue,rotation,set(chosen));chosen.append(s['scope_id'])
    assert {s['scope_kind'] for s in catalogue if s['scope_id'] in chosen}>={'MECH_A','MECH_B','CWE-22','CWE-78','CWE-79'}
    assert ScopeScheduler.select(catalogue,json.loads(json.dumps(rotation)),set(chosen))==ScopeScheduler.select(catalogue,copy.deepcopy(rotation),set(chosen))
    contexts=[]
    def policy(ctx):
        contexts.append(ctx);env.peer.validate_delivery('investigator',ctx,{'mode':'TEST_ONLY'});return ModelTurn(json.dumps(response(ctx)),{}, {'finish_reason':'stop'})
    env.peer.policy=policy
    for _ in range(6):assert env.peer.step()
    assert len(contexts)==6 and len(env.peer.state['scopes'])==6
    assert len(env.peer.state['scope_rotation']['active_scope_ids'])<=env.peer.max_scopes
    assert len(env.peer.state['scope_catalogue'])>len(env.peer.state['scopes'])
    channels=[v['scope']['source_channel'] for v in contexts]
    assert channels[:4]==['R2_MECHANISM_CATALOGUE','STATIC_BOUNDARY_FALLBACK']*2

def test_one_decision_per_step_and_returned_navigation_is_consumed_later(env):
    scope_catalogue(env);calls=[]
    def policy(ctx):
        calls.append(copy.deepcopy(ctx));env.peer.validate_delivery('investigator',ctx,{'mode':'TEST_ONLY'})
        gaps=[] if len(calls)>1 else [{'question':'Does this symbol exist?','missing_evidence':'Actual search result','evidence_ids':[ctx['source_evidence'][0]['evidence_id']],'requests':[{'action':'search_symbols','query':'NoSuchSyntheticBoundary'}]}]
        return ModelTurn(json.dumps(response(ctx,evidence_gaps=gaps)),{}, {'finish_reason':'stop'})
    env.peer.policy=policy;assert env.peer.step();assert len(calls)==1
    issue=next(iter(env.peer.state['issues'].values()));assert issue['reassessment_pending']
    scope=env.peer.state['scopes'][0];assert env.peer.investigate(scope,issue['hypothesis_id']);assert len(calls)==2
    assert any(v['normalized_action']['action']=='search_symbols' and v['original_result'] is not None for v in calls[-1]['retrieval_results'])
    assert not env.peer.investigate(scope,issue['hypothesis_id']) and len(calls)==2
    assert not issue['reassessment_pending']

def test_explicit_material_dependencies_flow_both_ways_without_broadcast(env):
    p=proof(env);deliver(env,p);scope_catalogue(env)
    scope,a=env.peer.select_work();b=copy.deepcopy(a);b['hypothesis_id']='unrelated';b['dependency_ids']=[];env.peer.state['issues']['unrelated']=b
    method=next(m for m in env.r.methods.values() if m.simple_name=='other')
    raw={'action':'inspect_entity','entity_id':method.entity_id,'start_line':method.start_line,'end_line':method.end_line}
    env.peer.register_dependency(a,raw)
    env.r.request(raw);env.peer.publish_relevant_material()
    assert a['reassessment_pending'] and not b['reassessment_pending']
    text='TEST ONLY same concrete source gap'
    raw={'action':'read_file_range','file':'view.js','start_line':1,'end_line':2}
    answer={'critical_questions':[{'question':text,'question_id':None,'evidence_refs':[p['evidence_id']]}]}
    lead={'method_id':p['method_id'],'cwe':'CWE-79','reason':text};tid=env.e.enqueue(lead);task=env.e.book.state['tasks'][tid]
    origin={'response':env.e.book.record(answer)}
    q=env.e.book.question(task,text,[raw],{'source_evidence':[p]},origin,conditions=['Need exact callee source.'])
    follow=next(t for t in env.e.book.state['tasks'].values() if t['question_id']==q['question_id']);env.e.book.pause_task(follow['task_id'],'WAITING_FOR_EXPLICIT_GAP',{})
    env.peer.investigator_read(raw,text,a['hypothesis_id'])
    env.peer.publish_relevant_material()
    assert q['tool_returns'] and follow['status']=='QUEUED'
    assert env.e.book.state['tasks'][tid]['dispatches']==0
    assert any(json.loads(v)['event']=='EXPLORER_DEPENDENCY_SATISFIED' for v in (env.peer.root/'coordination.jsonl').read_text().splitlines())

def install_sdk(monkeypatch,calls):
    def sdk(self,ctx):
        calls.append(ctx['role']);self.record_wire_request(json.dumps(self.request_body(ctx),ensure_ascii=False).encode())
        value=response(ctx) if ctx['role']=='investigator' else {'leads':[]} if ctx['role']=='discovery' else {'reviews':[{'candidate_path_id':c['candidate_path_id'],'verdict':'RETAIN_UNCONFIRMED','reason':'TEST ONLY original review','evidence_refs':c['evidence_refs']} for c in ctx['candidates']]} if ctx['role']=='verification' else {'disposition':'TEST ONLY no further executable gap'}
        raw=json.dumps({'model':self.model,'choices':[{'message':{'content':json.dumps(value)},'finish_reason':'stop'}],'usage':{'prompt_tokens':1,'completion_tokens':1,'total_tokens':2}}).encode()
        turn=self.response_turn(raw);return ModelTurn(turn.content,turn.usage,{**turn.metadata,'http_status':200,'test_only':True})
    monkeypatch.setattr(OpenLuxChatPolicy,'__call__',sdk);monkeypatch.setenv('FASTTRACK_AUTHORIZED_LIVE','1');monkeypatch.setenv('WORK1_AGENT_API_KEY','TEST_ONLY')

def test_real_production_dispatch_chain_continues_after_28_without_second_discovery(env,monkeypatch):
    calls=[];install_sdk(monkeypatch,calls);p=proof(env)
    for n in range(31):env.r.enqueue({'method_id':p['method_id'],'cwe':'CWE-79','hypothesis_id':'TEST_ONLY_'+str(n),'reason':'Synthetic distinct queued investigation'})
    assert env.r.limits.max_focus==28
    # Pure inspection must not claim work, change a cursor or append an event.
    before=copy.deepcopy(env.e.book.state);assert env.e.cooperative_scheduler.explorer_has_work(env.e);assert env.e.book.state==before
    result=env.r.run();dispatches=sum(t['dispatches'] for t in env.e.book.state['tasks'].values())
    assert dispatches>28 and calls.count('discovery')==1
    assert calls.index('reasoning')<calls.index('investigator')
    assert not env.r.last_error and not env.peer.state.get('reliability_error')
    assert env.holder['budget'].protection()['ended'] and env.holder['budget'].reserved_r2()==0 and env.holder['budget'].reserved_seconds()==0
    assert result['stop_reason']!='TASK_LIMIT'
    for folder in (env.out/'request-audit').glob('*-reasoning'):assert (folder/'original-core-stack.json').exists()

def test_logical_history_progress_releases_protection_and_real_verify_is_reserved(env):
    budget=env.holder['budget'];calls=env.journal.requests
    for _ in range(28):budget.advance(logical=1)
    assert env.journal.requests==calls and budget.reserved_r2()==0 and budget.reserved_seconds()==0
    p=proof(env);deliver(env,p,'investigator')
    from test_r2_hecv_82532 import draft
    env.peer.submit(draft(p),'investigator',{'hypothesis_id':'test-reserve'})
    env.journal.max_requests=1
    assert budget.plan()['held_requests']==1 and not budget.can_investigate() and not budget.can_explore()

def test_failed_single_step_restores_roles_and_is_not_a_valid_decision(env):
    scope_catalogue(env)
    def broken(ctx):return ModelTurn('',{}, {'finish_reason':'length'})
    env.peer.policy=broken;assert not env.peer.step()
    assert env.peer.role=='explorer' and env.holder['budget'].actor=='explorer'
    assert not env.peer.state['decisions'] and env.peer.state['reliability_error']['trigger']=='MODEL_OR_PROTOCOL_ERROR'
    assert all(v['status']!='DECIDED' for v in env.peer.state['issues'].values())

def test_optional_execution_hook_disabled_preserves_r2_reference_trace(env,tmp_path):
    from test_r2_hecv_82532 import test_r2_reference_behavior_matches_repaired_explorer
    env.e.cooperative_scheduler=None
    test_r2_reference_behavior_matches_repaired_explorer(env,tmp_path)
