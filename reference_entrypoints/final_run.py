"""One authorized batch; frozen A1 plus lossless wire serialization/receipts."""
from pathlib import Path
import ast,copy,difflib,hashlib,json,os,runpy,sys,time
import experiment as e
from context_serialization import pack,unpack,canonical,sha as object_sha,component_estimates,token_count
from java_vuln_research.work1_agent.a1_history import HistoryIndex,HistoryFirst,legacy_key
from java_vuln_research.work1_agent.experiment_policy import request_reserve
from java_vuln_research.work1_agent.harness import PolicyError

e.W=Path('/home/dcj/java_vuln_work1/vecho-reproduction/agentic-path-builder-20261109')
e.LAB=Path('/home/dcj/java_vuln_work1/vecho-reproduction')
BASE_ROOT=e.W/'fasttrack-a1-chain-repair-1lpYyBqA'
EXPECTED='5b18fef9fe36afc0b69524e5c0c453c48e0bd0333f368025fa4991892f1436dc'
ORIGINAL_POLICY=e.Policy
HISTORY=HistoryIndex(e.R/'history/history.sqlite',read_only=True)
INPUTS=e.read(e.R/'inputs.json')

class Policy(ORIGINAL_POLICY):
    def source_id(self):
        return INPUTS['projects'][self.case]['source_tree_sha256']
    def original_body(self,context):return e.OpenLuxChatPolicy.request_body(self,context)
    def forms(self,context):
        original=self.original_body(context);packed,stats=pack(context)
        exact=HISTORY.lookup(legacy_key(context,self),original,self.source_id())
        compact=copy.deepcopy(original);compact['messages'][1]['content']=json.dumps(packed,ensure_ascii=False)
        selected=original if exact is not None else compact
        stats.update({'wire_format':'ORIGINAL_EXACT_HISTORY_REUSE' if exact is not None else 'LOSSLESS_METADATA_REFERENCES',
                      'semantic_roundtrip_equal':canonical(unpack(json.loads(selected['messages'][1]['content'])))==canonical(context),
                      'historical_exact_success_available':exact is not None,
                      'effective_removed_utf8_bytes':0 if exact is not None else stats['removed_duplicate_utf8_bytes']})
        return original,selected,stats
    def request_body(self,context):return self.forms(context)[1]
    def request_token_material(self,context):
        body=self.request_body(context)
        return json.dumps({'context':json.loads(body['messages'][1]['content']),'system':self.system_prompt},ensure_ascii=False,sort_keys=True)
    def record_wire_request(self,raw):
        self.audit.mkdir(parents=True,exist_ok=True);(self.audit/'actual-wire-request.json').write_bytes(raw)
        e.write(self.audit/'actual-wire-request.sha256.json',{'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'scope':'Exact HTTP request body bytes, no authorization headers'})
    def response_turn(self,raw):
        (self.audit/'actual-provider-response.json').write_bytes(raw)
        return super().response_turn(raw)

class ObservedHistoryFirst(HistoryFirst):
    def __init__(self,*args,**kw):
        super().__init__(*args,**kw);self.policy.case=self.logical_path.parent.name
    def __call__(self,context):
        parent=self.logical_path.parent/'request-audit';parent.mkdir(exist_ok=True)
        folder=parent/(f'{len(list(parent.iterdir()))+1:03d}-'+context['role']);folder.mkdir()
        p=self.policy;p.audit=folder
        original,body,stats=p.forms(context);material=json.loads(body['messages'][1]['content'])
        e.write(folder/'semantic-context.json',context);e.write(folder/'original-unfactored-request.json',original);e.write(folder/'request-body.json',body)
        reserve,method=request_reserve(context,p)
        report={'role':context['role'],'legacy_request_key':legacy_key(context,p),'complete_request_canonical_sha256':object_sha(body),
                'original_semantic_context_sha256':object_sha(context),'serialized_context_sha256':object_sha(material),'deduplication':stats,
                'estimated_before':component_estimates(context),'estimated_after':component_estimates(material,stats['table_category_owners']),
                'provider_usage':None,'provider_usage_status':'NOT_SENT_OR_NOT_SETTLED','reserved_tokens':reserve,'reserve_method':method,
                'cached_tokens_rule':'Cached prompt tokens are a subset of provider prompt/total usage; never added again.'}
        e.write(folder/'receipt.json',report)
        try:turn=super().__call__(context)
        except Exception as error:
            report.update(error_type=type(error).__name__,error=str(error),new_physical_requests=None)
            e.write(folder/'receipt.json',report);raise
        usage=dict(turn.usage);reused=bool(turn.metadata.get('history_reused'))
        (folder/'assistant-content.txt').write_text(turn.content,encoding='utf-8')
        e.write(folder/'response-metadata.json',dict(turn.metadata))
        report.update(provider_usage=usage,provider_usage_status='ORIGINAL_HISTORICAL_USAGE' if reused else 'REPORTED_BY_PROVIDER',
                      new_physical_requests=0 if reused else 1,new_reported_tokens=0 if reused else usage.get('total_tokens'),
                      reserve_minus_reported_tokens=reserve-usage['total_tokens'] if type(usage.get('total_tokens')) is int else None,
                      original_physical_receipt=turn.metadata.get('original_physical_receipt'))
        if (folder/'actual-wire-request.sha256.json').exists():report['actual_wire_request']=e.read(folder/'actual-wire-request.sha256.json')
        e.write(folder/'receipt.json',report);return turn

def install():
    e.Policy=Policy;e.HistoryFirst=ObservedHistoryFirst

def preflight():
    assert e.sha(BASE_ROOT/'snapshot.sha256')==EXPECTED;e.verify(BASE_ROOT,'snapshot.sha256')
    assert e.sha(e.BASE)=='f4bb22a4457742b99ae08ade40c079165ecc75aed8fb0cb483d1a529b7890034'
    assert not (e.R/'detection').exists()
    # Existing input/source/CodeQL receipts only. No query/model execution.
    e.prepare()
    assert (e.R/'frozen-prompts.json').read_bytes()==(BASE_ROOT/'frozen-prompts.json').read_bytes()
    out=e.R/'preflight-context';out.mkdir(exist_ok=False);checks=[]
    class Capture(Policy):
        def __call__(self,context):
            original,wire,stats=self.forms(context)
            e.write(self.folder/'discovery-original.json',original);e.write(self.folder/'discovery-wire.json',wire)
            e.write(self.folder/'semantic-compare.json',stats)
            checks.append({'sample':self.case,'role':'discovery','original_request_sha256':object_sha(original),'wire_request_sha256':object_sha(wire),
                           'deduplication':stats,'components_before':component_estimates(context),'components_if_factored':component_estimates(pack(context)[0],stats['table_category_owners']),
                           'inventory_count':len(context['inventory']),'web_relation_count':len(context.get('web_surface_inventory',[])),
                           'context_keys':list(context),'history_reuse_available':stats['historical_exact_success_available'],'real_model_requests':0})
            error=PolicyError('PREFLIGHT_CAPTURE_ONLY_NO_MODEL');error.stop_reason='PREFLIGHT_CAPTURE_ONLY';raise error
    for key in e.ORDER:
        entry=INPUTS['projects'][key];folder=out/key;folder.mkdir()
        pp=e.read(e.R/'frozen-prompts.json')[key];policy=Capture('OFFLINE-NOT-A-CREDENTIAL',pp['discovery'],folder);policy.case=key
        team=e.AgentTeam(discovery=policy,reasoning=policy,verification=policy);base=e.baseline(e.BASE)
        runner=e.build_runner(Path(entry['source_root']),folder,team,r12_implementation=e.BASE,strategy='A1',static_report=Path(entry['native_report']['file']),static_graph=Path(entry['graph_csv']['file']),limits=base.BenchmarkLimits(max_candidates=None,per_cwe=None))
        archive=e.mixed_install(runner,automatic=True);e.contract_install(runner,INPUTS['dependency_catalog'][key]);e.targeted_install(runner,e.SWITCHES[key],archive,chain_managed=True)
        engine=e.ExecutionController(runner,archive,'TEST_ONLY:PREFLIGHT:'+key,critical=e.SWITCHES[key].critical_evidence_closure)
        inventory,ranked,all_rows=runner.inventory();original=__import__(engine.core.__func__.__module__,fromlist=['KNOWLEDGE'])
        runner.ask('discovery',{'supported_cwes':['CWE-22','CWE-78','CWE-79','CWE-94'],'inventory':inventory,'guidance':{c:[v[2] for v in original.KNOWLEDGE[c]] for c in ['CWE-22','CWE-78','CWE-79','CWE-94']}})
        assert runner.model_calls==0;runner.trace.close()
    # Exact repeated metadata, arrays/order, distinct same-name records, full
    # source text and uncertainties are compared via the same serializer.
    record={'id':'TEST_ONLY_SHARED','coordinates':[1,2],'description':'navigation '*80}
    synthetic={'inventory':[record,record,{**record,'id':'TEST_ONLY_DIFFERENT_SOURCE'}],'source_evidence':[{'source':'FULL SOURCE\n'*40}], 'uncertainties':['UNKNOWN must remain']}
    packed,proof=pack(synthetic);assert packed!=synthetic and unpack(packed)==synthetic
    assert packed['source_evidence']==synthetic['source_evidence'] and packed['uncertainties']==synthetic['uncertainties']
    e.write(e.R/'context-preflight.json',{'passed':True,'model_requests':0,'actual_discovery_previews':checks,'synthetic_roundtrip':proof,
         'prompts_byte_identical':True,'candidate_and_verification_semantics_changed':False,'no_source_truncation':True,'order_semantics_preserved':True})
    print(json.dumps([{'sample':v['sample'],'inventory':v['inventory_count'],'web_relations':v['web_relation_count'],'potential_removed_bytes':v['deduplication']['removed_duplicate_utf8_bytes'],'exact_history':v['history_reuse_available']} for v in checks]),flush=True)

def freeze():
    assert e.read(e.R/'context-preflight.json')['passed'];assert not (e.R/'detection').exists()
    expected_changes={'context_serialization.py','final_run.py','evaluate_final.py','runtime/src/java_vuln_research/work1_agent/experiment_policy.py','runtime/src/java_vuln_research/work1_agent/run_harness.py'}
    paths={p.relative_to(e.R).as_posix() for p in (e.R/'runtime').rglob('*') if p.is_file() and '__pycache__' not in p.parts and '.pytest_cache' not in p.parts}
    paths.update(['experiment.py','context_serialization.py','final_run.py','evaluate_final.py'])
    changed=[];patch=[]
    for rel in sorted(paths):
        before=BASE_ROOT/rel;after=e.R/rel
        if before.exists() and before.read_bytes()==after.read_bytes():continue
        changed.append(rel);patch.extend(difflib.unified_diff(before.read_text().splitlines(True) if before.exists() else [],after.read_text().splitlines(True),fromfile='a/'+rel if before.exists() else '/dev/null',tofile='b/'+rel))
    assert set(changed)==expected_changes,changed
    (e.R/'serialization-only.patch').write_text(''.join(patch))
    e.write(e.R/'RUN_BASELINE.json',{'base_runtime_snapshot_sha256':EXPECTED,'original_core_sha256':e.sha(e.BASE),'changed_files':changed,
        'run_root':str(e.R),'shared_readonly_data_root':str(e.LAB),'prompt_sha256_unchanged':e.sha(e.R/'frozen-prompts.json'),
        'modifications':'Lossless metadata serialization, actual wire/provider receipts, input estimate uses serialized material; no candidate, task, scheduler, prompt, Reasoning or Verification changes. Evaluator also scores sealed fully verified outputs stopped at the declared task limit, preserving PARTIAL task status and remaining tasks; original IRIS formulas and path adapter unchanged.'})
    files=[e.R/rel for rel in paths]+[e.R/n for n in ['inputs.json','preflight-inputs.json','frozen-prompts.json','frozen-rules.json','tool-schema.json','history/history.sqlite','history/history-inventory.json','context-preflight.json','serialization-only.patch','RUN_BASELINE.json','evaluate.py','score_closed_pair.py','BASE.snapshot.sha256','no-model-tests.log']]
    e.seal(e.R,'snapshot.sha256',files);e.verify(e.R,'snapshot.sha256')
    e.write(e.R/'freeze-receipt.json',{'status':'FROZEN_FINAL_RUN_AUTHORIZED','snapshot_sha256':e.sha(e.R/'snapshot.sha256'),'base_snapshot_sha256':EXPECTED,'new_model_requests_before_freeze':0,'configuration':'gpt-6-luna/28 requests/300000 tokens/128 tools/1200 seconds/completion4096/retries0','no_automatic_reruns':True})
    print(json.dumps(e.read(e.R/'freeze-receipt.json')),flush=True)

if __name__=='__main__':
    operation=sys.argv[1]
    if operation=='preflight':preflight()
    elif operation=='freeze':freeze()
    elif operation=='detect':install();e.detect()
    elif operation=='evaluate':runpy.run_path(str(e.R/'evaluate_final.py'),run_name='__main__')
    else:raise ValueError('Unknown operation')
