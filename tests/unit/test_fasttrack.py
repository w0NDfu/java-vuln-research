"""FastTrack compatibility and bounded reuse, with independent Java source."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from java_vuln_research.work1_agent.fasttrack import ExactPrefixReuse, baseline, build_runner
from java_vuln_research.work1_agent.harness import ModelTurn
from java_vuln_research.work1_agent.dag_harness import AgentTeam


@pytest.fixture
def pinned():
    root = Path(__file__).parents[2]
    path = root/'frozen-r12-benchmark.py'
    if not path.exists(): path = root/'.tmp/fasttrack-r12-benchmark.py'
    if not path.exists(): pytest.skip('The lab-only immutable baseline is not installed.')
    return path


def test_baseline_rejects_changed_code(tmp_path):
    f=tmp_path/'modified.py';f.write_text('changed')
    with pytest.raises(ValueError,match='exact frozen'):baseline(f)


def test_a1_preserves_discovery_and_valid_reads_and_repairs_invalid_window(tmp_path,pinned):
    source=tmp_path/'source';source.mkdir()
    (source/'F.java').write_text('class F {\n public String take(String x) { return x; }\n class Inner { void run() {} }\n}\n')
    def unused(_):pytest.fail('No model calls allowed')
    team=AgentTeam(unused,unused,unused)
    output=tmp_path/'new';output.mkdir()
    r=build_runner(source,output,team,r12_implementation=pinned,strategy='A1')
    base=baseline(pinned)
    (tmp_path/'old').mkdir()
    plain=base.BenchmarkRun(r.tools,r.retrieval,team,tmp_path/'old')
    before=list(r.methods)
    selected,_,_=r.inventory();r.activate_reads()
    assert selected == plain.inventory()[0]
    assert [x['method_id'] for x in selected]==before or set(x['method_id'] for x in selected)==set(before)
    m=next(x for x in r.methods.values() if x.simple_name=='take')
    proof=r.request({'action':'inspect_entity','entity_id':m.entity_id})
    assert proof['method_id']==m.entity_id and 'return x' in proof['source']
    assert proof == plain.request({'action':'inspect_entity','entity_id':m.entity_id})
    invalid=r.request({'action':'inspect_entity','entity_id':m.entity_id,'start_line':1,'end_line':999})
    assert invalid['status']=='invalid_window' and invalid['selected_method']['signature']=='take(String)'
    found=r.request({'action':'resolve_method','query':'Inner.run()'})
    assert found['status']=='unique' and found['candidates'][0]['signature']=='run()'
    r.trace.close()
    plain.trace.close()


def test_prefix_cache_charges_logical_budget_and_stops_after_first_changed_input(tmp_path):
    import hashlib
    class Policy:
        system_prompt='same';model='same';endpoint='same';max_output_tokens=4096
        calls=0
        def __call__(self,c):self.calls+=1;return ModelTurn('{}',{'total_tokens':7})
    policy=Policy();context={'role':'reasoning','source':'unchanged'}
    key=hashlib.sha256(json.dumps({'context':context,'system':policy.system_prompt,'model':policy.model,
        'endpoint':policy.endpoint,'output_limit':4096},ensure_ascii=False,sort_keys=True).encode()).hexdigest()
    old=tmp_path/'old.jsonl';old.write_text(json.dumps({'event':'response','request_key':key,'charged_tokens':11,'content':'{}','usage':{'total_tokens':11}})+'\n')
    journal=SimpleNamespace(max_requests=28,requests=0,max_tokens=300000,tokens=0)
    reuse=ExactPrefixReuse(journal,old,tmp_path/'reuse.jsonl');wrapped=reuse.wrap(policy)
    wrapped(context)
    assert policy.calls==0 and reuse.requests==1 and journal.max_requests==27 and journal.max_tokens==299989
    wrapped({'role':'reasoning','source':'changed'})
    wrapped(context)
    assert policy.calls==2 and not reuse.enabled


def test_a2_packing_never_drops_or_reorders_candidates(tmp_path,pinned):
    pytest.importorskip('tiktoken')
    from java_vuln_research.work1_agent.fasttrack import pack_discovery
    source=tmp_path/'source';source.mkdir()
    (source/'F.java').write_text('class F { public void write(String x) { System.out.print(x); } }')
    out=tmp_path/'out';out.mkdir()
    r=build_runner(source,out,None,r12_implementation=pinned,strategy='A2')
    rows,_,_=r.inventory()
    payload,aliases,count=pack_discovery({'inventory':rows},r.full_rows,r.ast,r.ast_ids,'fixed prompt')
    assert [aliases[x[0]] for x in payload['inventory']]==[x['method_id'] for x in r.full_rows]
    assert count<=12000
    r.trace.close()
