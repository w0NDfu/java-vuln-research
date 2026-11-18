"""TEST ONLY: production transport/accounting/resume; synthetic SDK, no network."""
import copy
import json
from types import SimpleNamespace
import pytest
from test_r2_hecv_82532 import env, offline, proof
from test_r2_hecv_82533 import scope_catalogue, response, install_sdk
from java_vuln_research.work1_agent.a1_history import IdentityJournal, HistoryIndex
from java_vuln_research.work1_agent.a1_verification_budget import physical_account
from java_vuln_research.work1_agent.harness import PolicyError
from java_vuln_research.work1_agent.request_outcomes import RequestQuarantined
from java_vuln_research.work1_agent.run_harness import OpenLuxChatPolicy


def error(status=None):
    return PolicyError('OpenLux request failed ' + json.dumps({
        'http_status': status, 'request_id': 'TEST_ONLY_PROVIDER_ID' if status else None,
        'cause_type': 'HTTPStatusError' if status else 'ReadTimeout',
        'error_type': 'APIStatusError' if status else 'APITimeoutError',
        'max_retries': 0, 'elapsed_seconds': 0.01,
    }))


def broken_sdk(monkeypatch, status=None):
    calls = []
    def fail(self, context):
        calls.append(copy.deepcopy(context))
        self.record_wire_request(json.dumps(self.request_body(context)).encode())
        raise error(status)
    monkeypatch.setattr(OpenLuxChatPolicy, '__call__', fail)
    monkeypatch.setenv('FASTTRACK_AUTHORIZED_LIVE', '1')
    return calls


@pytest.mark.parametrize('status,outcome', [(None, 'UNKNOWN_QUARANTINED'), (429, 'FAILED_HTTP'), (500, 'FAILED_HTTP')])
def test_real_policy_failure_separate_from_answer_and_billing(env, monkeypatch, status, outcome):
    calls = broken_sdk(monkeypatch, status)
    ctx = {'role': 'investigator', 'source_evidence': []}
    for _ in range(2):
        with pytest.raises(RequestQuarantined): env.wrapped['investigator'](ctx)
    rows = [json.loads(v) for v in env.journal.path.read_text().splitlines()]
    assert len(calls) == 1 and len(rows) == 2
    assert rows[0]['event'] == 'request_started' and rows[1]['event'] == 'request_outcome'
    assert rows[1]['outcome'] == outcome and rows[1]['usage_status'] == 'UNKNOWN'
    assert rows[1]['currency_cost'] == 'UNKNOWN' and not env.journal.responses
    account = physical_account(env.journal.path)
    assert account['physical_requests'] == 1 and account['unsettled_requests'] == 1
    assert account['active_unsettled_requests'] == 0 and account['reported_tokens'] == 0
    assert account['quarantined_requests'] == 1 and account['failed_request_usage_unknown'] == 1
    assert not list((env.out/'request-audit').glob('*/assistant-content.txt'))
    assert not list((env.out/'response-store').glob('*.json'))
    before = env.journal.path.read_bytes()
    env.holder['recovery'].recover(env.policies)
    assert env.journal.path.read_bytes() == before  # repeated reconciliation is idempotent
    restored = IdentityJournal(env.journal.path, source_identity=env.args.source_identity,
        binding=env.args.binding, max_requests=64, max_tokens=2**60, max_seconds=7200)
    assert restored.created_at == env.journal.created_at and restored.requests == 1
    with pytest.raises(RequestQuarantined): restored.wrap(env.policies['investigator'])(ctx)
    assert len(calls) == 1


def test_abandoned_start_isolated_after_recovery_without_response(env):
    p = env.policies['investigator'];ctx = {'role': 'investigator'};key = env.journal.identity(ctx,p)
    env.journal.append({'event':'request_started','request_key':key,'reserved_tokens':123})
    env.journal.requests=1;env.journal.tokens=123
    env.holder['recovery'].recover(env.policies)
    a=physical_account(env.journal.path)
    assert a['quarantined_requests']==1 and a['active_unsettled_requests']==0
    assert a['unsettled_reserved_tokens']==123 and not env.journal.responses
    before=env.journal.path.read_bytes();env.holder['recovery'].recover(env.policies)
    assert env.journal.path.read_bytes()==before


@pytest.mark.parametrize('details', [
    {'outcome':'FAILED_HTTP'},
    {'outcome':'UNKNOWN_QUARANTINED','content':'invented answer'},
    {'outcome':'UNKNOWN_QUARANTINED','usage_status':'KNOWN','currency_cost':0,'automatic_retry_allowed':False},
])
def test_failure_receipt_cannot_invent_success_or_zero_usage(env, details):
    with pytest.raises(PolicyError): env.journal.failure('missing',details)
    assert not env.journal.path.exists()


def test_historical_unknown_isolated_without_a_new_physical_start(env, monkeypatch):
    from java_vuln_research.work1_agent.a1_history import legacy_key
    calls=broken_sdk(monkeypatch)
    ctx={'role':'investigator','task':'TEST_ONLY unknown historical attempt'}
    key=legacy_key(ctx,env.policies['investigator'])
    env.history.db.execute('INSERT INTO unknown VALUES(?,?,?)',(key,'UNSETTLED_HISTORICAL_OUTCOME_NO_RESEND','TEST_ONLY_OLD_LEDGER:121'))
    env.history.db.commit()
    for _ in range(2):
        with pytest.raises(RequestQuarantined):env.wrapped['investigator'](ctx)
    assert not calls and env.journal.requests==0 and not env.journal.responses
    a=physical_account(env.journal.path)
    assert a['physical_requests']==0 and a['historical_quarantined_requests']==1
    assert a['unsettled_requests']==0  # historical cost is not charged to this new run
    assert len(env.journal.path.read_text().splitlines())==1


def test_programming_error_is_not_hidden_as_an_operational_quarantine(env, monkeypatch):
    monkeypatch.setenv('FASTTRACK_AUTHORIZED_LIVE','1')
    monkeypatch.setattr(OpenLuxChatPolicy,'__call__',lambda *a:(_ for _ in ()).throw(ValueError('TEST_ONLY_BUG')))
    with pytest.raises(ValueError,match='TEST_ONLY_BUG'):env.wrapped['investigator']({'role':'investigator'})
    assert physical_account(env.journal.path)['active_unsettled_requests']==1


def test_quarantined_issue_not_decided_or_retried_and_other_issues_continue(env, monkeypatch):
    scope_catalogue(env);calls=broken_sdk(monkeypatch)
    assert not env.peer.step()
    issue=next(iter(env.peer.state['issues'].values()))
    assert issue['status']=='PAUSED' and issue['pending_context_json'] and issue['transport_quarantine']
    assert not env.peer.issue_runnable(issue) and not env.peer.state['decisions']
    assert not env.peer.state.get('reliability_error')
    assert env.holder['budget'].reassessment_reserve()==0
    assert not env.peer.step() and len(calls)==2  # a second independent scope, not the first request
    assert calls[0]['scope']['scope_id']!=calls[1]['scope']['scope_id']


def test_exact_success_arriving_after_quarantine_recovers_once_and_rejudges(env, monkeypatch):
    scope_catalogue(env);calls=broken_sdk(monkeypatch)
    assert not env.peer.step();issue=next(iter(env.peer.state['issues'].values()))
    ctx=json.loads(issue['pending_context_json']);policy=env.policies['investigator']
    folder=next((env.out/'request-audit').glob('*-investigator'))
    policy.audit=folder;policy.context=ctx
    raw=json.dumps({'model':policy.model,'choices':[{'message':{'content':json.dumps(response(ctx))},'finish_reason':'stop'}],
        'usage':{'prompt_tokens':12,'completion_tokens':3,'total_tokens':15}}).encode()
    policy.response_turn(raw)  # synthetic durable success; no network or fabricated repair
    env.holder['recovery'].recover(env.policies)
    assert env.peer.issue_runnable(issue)
    scope=next(v for v in env.peer.state['scopes'] if v['scope_id']==issue['scope_id'])
    assert env.peer.investigate(scope,issue['hypothesis_id'])
    assert not issue.get('transport_quarantine') and not issue.get('pending_context_json')
    assert len(calls)==1 and env.journal.requests==1 and len(env.peer.state['decisions'])==1
    a=physical_account(env.journal.path)
    assert a['reported_tokens']==15 and a['unsettled_requests']==0 and a['quarantined_requests']==0
    before=env.journal.path.read_bytes();env.holder['recovery'].recover(env.policies)
    assert env.journal.path.read_bytes()==before


@pytest.mark.parametrize('failed_role',['reasoning','investigator'])
def test_production_dispatch_isolates_failure_without_repeating_or_stopping_other_work(env, monkeypatch, failed_role):
    scope_catalogue(env)  # Multiple independent questions are required for this continuation check.
    calls=[];install_sdk(monkeypatch,calls);sdk=OpenLuxChatPolicy.__call__;failed=[]
    def once(self,ctx):
        if ctx['role']==failed_role and not failed:
            failed.append(copy.deepcopy(ctx));calls.append(failed_role)
            self.record_wire_request(json.dumps(self.request_body(ctx)).encode())
            raise error()
        return sdk(self,ctx)
    monkeypatch.setattr(OpenLuxChatPolicy,'__call__',once)
    result=env.r.run()
    assert failed and calls.count(failed_role)>1
    assert not env.peer.state.get('reliability_error') and env.r.stop!='REQUEST_QUARANTINED'
    a=physical_account(env.journal.path)
    assert a['quarantined_requests']==1 and a['active_unsettled_requests']==0
    assert len([v for v in (env.out/'request-audit').glob('*/actual-wire-request.json')])==a['physical_requests']
    if failed_role=='reasoning':
        paused=[v for v in env.e.book.state['tasks'].values() if v.get('pause_reason')=='REQUEST_QUARANTINED']
        # Persisted stage, task pause event and zero response together are the proof.
        assert any('REQUEST_QUARANTINED' in json.dumps(v) and v['status']=='PAUSED' for v in env.e.book.state['tasks'].values())
    assert calls.count('discovery')==1


def test_fresh_service_uses_verified_raw_cache_without_acquiring_or_delivering_old_proofs(env, monkeypatch):
    from java_vuln_research.work1_agent.r2_hecv_services import EvidenceService, ServiceError
    proof(env);service=env.peer.service
    windows=copy.deepcopy(service.state['raw_source_windows'])
    env.r.source_cache={'source_tree_sha256':env.args.source_identity,'raw_source_windows':windows}
    service.state['proofs'].clear();service.state['raw_source_windows'].clear();service.save()
    monkeypatch.setattr(env.r,'_hecv_original_range_reader',lambda *a,**k:pytest.fail('Completed raw source read repeated'))
    restored=EvidenceService(env.r,{},None,env.args.source_identity)
    row=next(iter(windows.values()));args=row['arguments']
    assert restored.read_range(args['file'],args['start_line'],args['end_line'],**args['options'])==row['result']
    assert restored.state['proofs']=={} and not restored.visible('explorer') and not restored.visible('investigator')
    env.r.source_cache['source_tree_sha256']='DIFFERENT_TREE'
    with pytest.raises(ServiceError,match='source-version'):EvidenceService(env.r,{},None,env.args.source_identity)


def test_raw_cache_seed_does_not_accept_unsettled_or_modified_reader_result(env):
    from java_vuln_research.work1_agent.r2_hecv_services import EvidenceService, ServiceError
    proof(env);windows=copy.deepcopy(env.peer.service.state['raw_source_windows'])
    next(iter(windows.values()))['result']['text']='TEST_ONLY_CORRUPTION'
    env.r.source_cache={'source_tree_sha256':env.args.source_identity,'raw_source_windows':windows}
    with pytest.raises(ServiceError,match='Unverified'):EvidenceService(env.r,{},None,env.args.source_identity)


def test_production_run_and_resume_report_quarantine_as_partial_not_success_or_complete_negative(env, monkeypatch):
    from pathlib import Path
    from java_vuln_research.work1_agent.r2_hecv_run import run
    calls=[];install_sdk(monkeypatch,calls);sdk=OpenLuxChatPolicy.__call__;failed=[]
    def once(self,ctx):
        if ctx['role']=='investigator' and not failed:
            failed.append(ctx);calls.append('investigator')
            self.record_wire_request(json.dumps(self.request_body(ctx)).encode())
            raise error()
        return sdk(self,ctx)
    monkeypatch.setattr(OpenLuxChatPolicy,'__call__',once)
    args=copy.deepcopy(env.args);args.output=str(env.tmp_path/'full-failure-cli')
    args.history=str(env.tmp_path/'history.sqlite');args.model='gpt-6.1-sol';args.max_scopes=1
    result=run(args)
    assert result['error'] is None and result['execution_status']=='NORMAL_BOUNDED_END'
    assert result['status']=='CLOSED_BOUNDED_PARTIAL' and result['coverage_status']=='TRANSPORT_QUARANTINED_PARTIAL'
    assert result['physical_account']['unsettled_requests']==1 and result['physical_account']['active_unsettled_requests']==0
    state=json.loads((Path(args.output)/'hecv/state.json').read_bytes())
    assert any(v.get('transport_quarantine') for v in state['issues'].values())
    before=len(calls);physical=result['physical_account']['physical_requests'];args.resume=True
    resumed=run(args)
    assert resumed['error'] is None and len(calls)==before
    assert resumed['physical_account']['physical_requests']==physical
    assert resumed['coverage_status']=='TRANSPORT_QUARANTINED_PARTIAL'
