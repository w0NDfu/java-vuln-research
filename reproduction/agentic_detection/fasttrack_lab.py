"""Separate zero-model collection, label-side admission, and one fixed FastTrack comparison."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys

BASE=Path('/home/dcj/java_vuln_work1/vecho-reproduction')
PARENT=BASE/'agentic-path-builder-20261109'
OLD=PARENT/'r12-benchmark-first/refinement-02'


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--stage',choices=['prepare','gate','run'],required=True)
    args=parser.parse_args();root=args.root.resolve();code=root/'code'
    if not root.is_relative_to(PARENT/'fasttrack-20261109'):raise ValueError('Independent FastTrack directory required.')
    sys.path[:0]=[str(code/'src'),str(code/'reproduction')]
    from agentic_detection.validate import write,read_jsonl,detect,score,tree_hash,check_database
    from agentic_detection.r12_lab import verify,sha
    from java_vuln_research.work1_agent.fasttrack import baseline,build_runner,pack_discovery
    from java_vuln_research.work1_agent.dag_harness import AgentTeam
    codeql=BASE.parent/'experiment-output/tools/codeql-v2.26.4/codeql/codeql'
    os.umask(0o077)
    for name in ['code.sha256','frozen-diagnostic.sha256']:verify(OLD/name,OLD)
    if args.stage=='prepare':
        if (root/'prepared.json').exists():raise ValueError('Preparation already completed.')
        env=dict(os.environ,PYTHONPATH=':'.join(map(str,[code/'src',code/'reproduction',BASE/'experiments/work1-m7-source-only-20261108/test-deps'])))
        with (root/'engineering.log').open('xb') as f:
            subprocess.run([sys.executable,'-B','-m','pytest','-q','-p','no:cacheprovider','tests/unit'],cwd=code,env=env,stdout=f,stderr=f,check=True)
        files=sorted(f for f in code.rglob('*') if f.is_file() and '__pycache__' not in f.parts)
        (root/'code.sha256').write_text(''.join(sha(f)+'  '+f.relative_to(root).as_posix()+'\n' for f in files))
        base=baseline(code/'frozen-r12-benchmark.py')
        selection=[]
        for row in json.loads((OLD/'private/selection.json').read_text()):
            o=json.loads((OLD/'runs'/row['key']/'outcome.json').read_text());s=o['static']
            assert tree_hash(Path(row['source']))==row['tree_sha256'] and sha(Path(s['graph']))==s['graph_sha256']
            check_database(Path(s['database']),Path(row['source']))
            selection.append({**row,'reuse_static':str(Path(s['graph']).parent)})
            link=root/'baseline-journals'/row['key']/'request-journal.jsonl';link.parent.mkdir(parents=True,exist_ok=True)
            link.symlink_to(OLD/'runs'/row['key']/'request-journal.jsonl')
        for profile in ['A1','A2']:
            exp=root/profile;exp.mkdir();(exp/'code').symlink_to(code,target_is_directory=True)
            write(exp/'private/selection.json',selection)
            write(exp/'detector-config.json',{'benchmark_first':True,'fasttrack':profile})
            for row in selection:
                output=root/'zero'/profile/row['key'];output.mkdir(parents=True)
                def forbidden(_):raise AssertionError('Zero-model collection must not call a policy.')
                r=build_runner(row['source'],output,AgentTeam(forbidden,forbidden,forbidden),
                    r12_implementation=code/'frozen-r12-benchmark.py',strategy=profile,
                    static_report=Path(json.loads((OLD/'runs'/row['key']/'outcome.json').read_text())['native']['report']),
                    static_graph=Path(json.loads((OLD/'runs'/row['key']/'outcome.json').read_text())['static']['graph']))
                selected,_,_=r.inventory()
                context={'supported_cwes':list(base.SUPPORTED_CWES),'inventory':selected,
                         'guidance':{c:[v[2] for v in base.KNOWLEDGE[c]] for c in base.SUPPORTED_CWES}}
                packing=None
                if profile=='A2':
                    payload,aliases,tokens=pack_discovery(context,r.full_rows,r.ast,r.ast_ids,base.PROMPTS['discovery'])
                    packing={'tokens':tokens,'aliases':aliases,'context':payload}
                    write(output/'compact-discovery.json',packing)
                r.trace.close()
        from agentic_detection.scorer_conformance import check
        with (root/'scorer-preflight.log').open('x') as f,contextlib.redirect_stdout(f):
            result=check(BASE,[OLD],PARENT/'r12-benchmark-first/scorer-reference/evaluation_pipeline.py',root/'scorer-preflight')
        assert result['all_equal']
        write(root/'prepared.json',{'provider_requests':0,'code_files':len(files),'scorer_checks':len(result['checks'])})
        return
    if args.stage=='gate':
        # Labels are only read here, in a process separate from collection/detection.
        from vecho_experiment.evaluation import evaluate
        validation={r['key']:r for r in json.loads((OLD/'validation-results.json').read_text())}
        selection={r['key']:r for r in json.loads((OLD/'private/selection.json').read_text())}
        cases=[]
        for key in ['project_1','project_fresh_fixed']:
            targets=validation[key]['metric']['targets'];fixes=[{'file':f,'class':c,'method':m} for f,c,m in targets]
            oldrows=json.loads((OLD/'runs'/key/'attempt-0001/discovery-inventory.json').read_text())['methods']
            for profile in ['A0','A1','A2']:
                rows=oldrows if profile=='A0' else json.loads((root/'zero'/profile/key/'static-candidates.json').read_text())['rows']
                records=[{'fingerprint':str(i),'tainted_data_flow':[[{'file_path':r['file'],'line_number':r['start_line']}]]} for i,r in enumerate(rows)]
                m=evaluate(selection[key]['source'],records,fixes);assert m['status']=='available'
                hit={d['fingerprint']:{tuple(t) for t in d['matched_methods']} for d in m['details']}
                coverage=lambda k:len(set().union(*(hit[str(i)] for i in range(min(k,len(rows))))))
                packing=root/'zero'/profile/key/'compact-discovery.json'
                cases.append({'profile':profile,'key':key,'full':coverage(len(rows)),'at10':coverage(10),'at30':coverage(30),
                    'total':len(targets),'estimated_discovery_tokens':json.loads(packing.read_text())['tokens'] if packing.exists() else None})
        gates={}
        for profile in ['A1','A2']:
            gates[profile]=all(all(next(r for r in cases if r['key']==key and r['profile']==profile)[metric]>=
                                      next(r for r in cases if r['key']==key and r['profile']=='A0')[metric]
                                  for metric in ['at10','at30']) for key in ['project_1','project_fresh_fixed'])
        write(root/'admission.json',{'provider_requests':0,'cases':cases,'profiles_allowed':gates,'engineering_passed':True})
        print(json.dumps({'cases':cases,'profiles_allowed':gates},indent=2));return
    admission=json.loads((root/'admission.json').read_text());verify(root/'code.sha256',root)
    for profile in ['A1','A2']:
        if not admission['profiles_allowed'][profile]:continue
        exp=root/profile
        if (exp/'status.json').exists():raise ValueError('Do not rerun an existing comparison.')
        selection=json.loads((exp/'private/selection.json').read_text())
        for group in ['synthetic','diagnostic']:
            write(root/'status.json',{'profile':profile,'group':group,'status':'RUNNING'})
            for row in selection:
                if row['split']!=group:continue
                outcome=detect(row,BASE,exp,codeql)
                print(json.dumps({'profile':profile,'key':row['key'],'status':outcome['status'],'error':outcome.get('error')}),flush=True)
                if outcome['status']!='complete':
                    write(root/'status.json',{'profile':profile,'status':'EXECUTION_FAILURE','key':row['key']});return
            paths=sorted(f for f in (exp/'runs').rglob('*') if f.is_file() and f.suffix!='.lock')
            seal=exp/('frozen-'+group+'.sha256');seal.write_text(''.join(sha(f)+'  '+f.relative_to(exp).as_posix()+'\n' for f in paths))
            score(selection,exp,BASE);verify(seal,exp)
            controls=[r for r in json.loads((exp/'validation-results.json').read_text()) if r['split']=='synthetic']
            if len(controls)!=2 or not all(r['passed'] for r in controls):
                write(root/'status.json',{'profile':profile,'status':'CONTROLS_NOT_PASSED'});return
        aggregate=json.loads((exp/'benchmark-results.json').read_text())['aggregate']
        write(exp/'status.json',{'status':'COMPLETE','aggregate':aggregate})
        verify(root/'code.sha256',root)
    write(root/'status.json',{'status':'COMPARISON_COMPLETE','automatic_refinement':False,'full_campaign_started':False})


if __name__=='__main__':main()
