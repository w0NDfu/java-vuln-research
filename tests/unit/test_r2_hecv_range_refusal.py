"""TEST ONLY: actual safe-reader bounds, refusal persistence and later input."""
import copy,json
from pathlib import Path
import pytest
from test_r2_hecv_82532 import env,offline,proof
from test_r2_hecv_82533 import scope_catalogue,response
from java_vuln_research.work1_agent.harness import ModelTurn
from java_vuln_research.work1_agent.r2_hecv_services import ServiceError
from context_serialization import unpack

def warm_file(env,lines=138):
    (env.repo/'window.txt').write_text(''.join('synthetic source line '+str(n)+'\n' for n in range(1,lines+1)))
    return env.r.request({'action':'read_file_range','file':'window.txt','start_line':1,'end_line':lines})

def test_proven_eof_refusal_is_saved_reused_and_never_exposes_source(env,monkeypatch):
    p=warm_file(env);service=env.peer.service;before=env.r.tool_calls
    original=Path.read_text
    def guarded(path,*a,**k):
        if path==env.repo/'window.txt':pytest.fail('Known EOF metadata must use the original reader receipt')
        return original(path,*a,**k)
    monkeypatch.setattr(Path,'read_text',guarded)
    action={'action':'read_file_range','file':'window.txt','start_line':1,'end_line':160}
    r=service.execute(action,actor='investigator',hypotheses=['h1'],execute=lambda a:pytest.fail('Out-of-range source reader must not run'))
    assert r['validation_refusal'] and r['original_result']['status']=='invalid_window' and r['original_result']['file_lines']==138
    assert r['original_result']['bounds_provenance'] and not r['complete'] and r['actual_source_content'] is None and not r['candidate_step_eligible']
    assert service.state['requests'][r['request_id']]['status']=='SETTLED' and service.state['requests'][r['request_id']]['outcome']=='REFUSED'
    r2=service.execute(action,actor='explorer',hypotheses=['q2'],execute=lambda a:pytest.fail('Completed refusal must not execute again'))
    assert r2['reused'] and r2['request_id']==r['request_id'] and env.r.tool_calls==before
    assert set(service.state['requests'][r['request_id']]['dependencies'])=={'h1','q2'}
    assert not service.deliver('investigator',{'retrieval_results':[r],'source_evidence':[]},{'mode':'TEST_ONLY_REFUSAL_INPUT'})
    assert p['evidence_id'] not in service.visible('investigator')
    corrected=service.execute({**action,'end_line':138},actor='investigator',execute=lambda a:pytest.fail('Completed valid source window must be reused'))
    assert corrected['evidence_id']==p['evidence_id'] and env.r.tool_calls==before

def test_refusal_reaches_next_problem_input_and_explicit_correction_is_rejudged(env):
    p=warm_file(env);scope_catalogue(env);calls=[]
    def policy(ctx):
        # Build the real production HTTP body, without sending it; prove the
        # refused result survives shared-source serialization.
        body=env.policies['investigator'].request_body(ctx);wire=unpack(json.loads(body['messages'][1]['content']));calls.append(copy.deepcopy(wire))
        env.peer.validate_delivery('investigator',ctx,{'mode':'TEST_ONLY_BODY','n':len(calls)})
        end=160 if len(calls)==1 else 138
        gaps=[] if len(calls)==3 else [{'question':'What does the requested current file contain?','missing_evidence':'One explicit source range','evidence_ids':[],'requests':[{'action':'read_file_range','arguments':{'file':'window.txt','start_line':1,'end_line':end}}]}]
        return ModelTurn(json.dumps(response(ctx,evidence_gaps=gaps)),{}, {'finish_reason':'stop'})
    env.peer.policy=policy;assert env.peer.step() and len(calls)==1
    issue=next(iter(env.peer.state['issues'].values()));scope=env.peer.state['scopes'][0]
    assert issue['reassessment_pending'] and not env.peer.state.get('reliability_error')
    assert env.peer.investigate(scope,issue['hypothesis_id']) and len(calls)==2
    refusal=next(v for v in calls[1]['retrieval_results'] if v.get('validation_refusal'))
    assert refusal['original_result']['file_lines']==138 and refusal['actual_source_content'] is None
    assert p['evidence_id'] not in {v['evidence_id'] for v in calls[1]['source_evidence']}
    assert env.peer.investigate(scope,issue['hypothesis_id']) and len(calls)==3
    assert p['evidence_id'] in {v['evidence_id'] for v in calls[2]['source_evidence']}
    assert not issue['reassessment_pending'] and not env.peer.state.get('reliability_error')
    assert not env.peer.investigate(scope,issue['hypothesis_id']) and len(calls)==3

def test_unknown_bounds_use_the_original_refusal_and_explorer_keeps_its_metadata(env):
    result=env.r.request({'action':'read_file_range','file':'view.js','start_line':1,'end_line':160})
    assert result['status']=='invalid_window' and result['file_lines']==2 and not result['read_succeeded']
    settled=[v for v in env.peer.service.state['requests'].values() if v.get('result',{}).get('validation_refusal')]
    assert len(settled)==1 and settled[0]['status']=='SETTLED'

@pytest.mark.parametrize('action',[{'action':'read_file_range','file':'absent.txt','start_line':1,'end_line':2},{'action':'inspect_entity','entity_id':'missing-neutral-identity'}])
def test_missing_path_or_identity_is_material_feedback_without_physical_source_read(env,action):
    before=env.r.tool_calls
    value=env.peer.service.execute(action,actor='investigator',execute=lambda a:pytest.fail('Known invalid source selection must not execute'))
    assert value['validation_refusal'] and value['error'] and not value['complete'] and value['evidence_id'] is None
    assert env.r.tool_calls==before

def test_corrupt_eof_receipt_stays_recovery_blocked_not_a_normal_refusal(env):
    warm_file(env);service=env.peer.service
    row=next(v for v in service.state['raw_source_windows'].values() if v['arguments']['file']=='window.txt');row['result']['total_file_lines']=160
    with pytest.raises(ServiceError,match='RECOVERY_BLOCKED'):
        service.execute({'action':'read_file_range','file':'window.txt','start_line':1,'end_line':160},actor='investigator',execute=lambda a:pytest.fail('Corrupt receipt must not cause a fresh read'))
