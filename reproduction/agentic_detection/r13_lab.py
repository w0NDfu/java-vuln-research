"""R13 layered lab validation; no labels enter detection or native queries."""
import argparse
import contextlib
import json
import os
from pathlib import Path
import subprocess
import sys

BASE = Path('/home/dcj/java_vuln_work1/vecho-reproduction')
PARENT = BASE / 'agentic-path-builder-20261109'
BASELINE = PARENT / 'r12-benchmark-first/refinement-02'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--experiment', type=Path, required=True)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    exp = args.experiment.resolve()
    if not exp.is_relative_to(PARENT / 'r13-native-discovery'):
        raise ValueError('R13 requires an independent run directory.')
    code = exp / 'code'
    sys.path[:0] = [str(code / 'src'), str(code / 'reproduction')]
    from agentic_detection.r12_lab import verify, sha
    from agentic_detection.validate import write, check_database, tree_hash, detect, score
    from agentic_detection.scorer_conformance import check
    from java_vuln_research.work1_agent.repository.tools import RepositoryTools
    from java_vuln_research.work1_agent.repository.java_symbols import JavaSymbols
    from java_vuln_research.work1_agent.native_discovery import map_alerts
    codeql = BASE.parent / 'experiment-output/tools/codeql-v2.26.4/codeql/codeql'
    env = dict(os.environ, PYTHONPATH=':'.join(map(str, [code / 'src', code / 'reproduction',
        BASE / 'experiments/work1-m7-source-only-20261108/test-deps'])), PYTHONDONTWRITEBYTECODE='1')
    os.environ.update({k: env[k] for k in ('PYTHONPATH', 'PYTHONDONTWRITEBYTECODE')})
    if not (exp / 'offline-complete.json').exists():
        history = {n: verify(BASELINE / n, BASELINE) for n in ['code.sha256', 'frozen-synthetic.sha256', 'frozen-diagnostic.sha256']}
        selection = []
        mapping = []
        for row in json.loads((BASELINE / 'private/selection.json').read_text()):
            outcome = json.loads((BASELINE / 'runs' / row['key'] / 'outcome.json').read_text())
            static = outcome['static']
            check_database(Path(static['database']), Path(row['source']))
            assert tree_hash(Path(row['source'])) == row['tree_sha256']
            assert sha(Path(static['graph'])) == static['graph_sha256']
            assert sha(code / 'codeql/work1_agent/RepositorySiteGraph.ql') == static['query_sha256']
            selection.append({**row, 'reuse_static': str(Path(static['graph']).parent)})
            native = json.loads((args.native / row['key'] / 'native-receipt.json').read_text())
            assert native['status'] == 'complete' and native.get('force_rerun') is True and native['source_tree_sha256'] == row['tree_sha256']
            assert sha(Path(native['report'])) == native['report_sha256']
            assert sha(Path(native['sarif'])) == native['sarif_sha256']
            assert native['original_database_before_sha256'] == native['original_database_after_sha256']
            assert all(sha(Path(q['path'])) == q['sha256'] for q in native['queries'])
            write(exp / 'native-inputs' / row['key'] / 'native-receipt.json', native)
            tools = RepositoryTools.open(row['source'])
            symbols = JavaSymbols(tools.index)
            alerts, stats = map_alerts(json.loads(Path(native['report']).read_text()), symbols)
            from java_vuln_research.work1_agent.dag_retrieval import test_source
            stats['production_alerts'] = sum(any(p['mapping'] == 'unique' and not test_source(p['file_path']) for p in a['mapped_locations']) for a in alerts)
            stats['parse_error_files'] = symbols.parse_errors
            mapping.append({'key': row['key'], **stats})
        write(exp / 'private/selection.json', selection)
        write(exp / 'detector-config.json', {'benchmark_first': True, 'native_discovery': True})
        write(exp / 'historical-verification.json', history)
        write(exp / 'native-mapping-preflight.json', mapping)
        write(exp / 'acceptance.json', {'phase': 'DEVELOPMENT_ONLY', 'baseline': str(BASELINE),
            'model': 'gpt-6.1-sol', 'limits': {'requests': 28, 'tokens': 300000, 'tools': 128, 'seconds': 1200},
            'candidates_max': 12, 'per_cwe_max': 4,
            'gate': {'both_controls_passed': True, 'both_diagnostic_targets_detected': True, 'AvgF1_min': 0.5, 'AvgFDR_max': 0.5},
            'automatic_full_120': False})
        files = sorted(p for p in code.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
        (exp / 'code.sha256').write_text(''.join(sha(p) + '  ' + p.relative_to(exp).as_posix() + '\n' for p in files))
        with (exp / 'engineering-final.log').open('xb') as log:
            subprocess.run([sys.executable, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests/unit'],
                           cwd=code, env=env, stdout=log, stderr=log, check=True)
        with (exp / 'scorer-preflight.log').open('x') as log, contextlib.redirect_stdout(log):
            result = check(BASE, [BASELINE], PARENT / 'r12-benchmark-first/scorer-reference/evaluation_pipeline.py', exp / 'scorer-preflight')
        assert result['all_equal']
        verify(exp / 'code.sha256', exp)
        write(exp / 'environment.json', json.loads(subprocess.check_output([str(codeql), 'version', '--format=json'], text=True)))
        write(exp / 'offline-complete.json', {'status': 'PASSED', 'provider_requests': 0, 'native_mapping': mapping,
                                               'scorer_checks': len(result['checks'])})
    if not args.run:
        print((exp / 'offline-complete.json').read_text(), flush=True)
        return
    verify(exp / 'code.sha256', exp)
    selection = json.loads((exp / 'private/selection.json').read_text())
    for group in ['synthetic', 'diagnostic']:
        write(exp / 'status.json', {'status': 'RUNNING', 'group': group})
        for row in selection:
            if row['split'] != group: continue
            result = detect(row, BASE, exp, codeql)
            print(json.dumps({'key': row['key'], 'status': result['status'], 'error': result.get('error')}), flush=True)
            if result['status'] != 'complete':
                write(exp / 'status.json', {'status': 'EXECUTION_FAILURE', 'key': row['key']})
                return
        paths = sorted(p for p in (exp / 'runs').rglob('*') if p.is_file() and p.suffix != '.lock')
        seal = exp / ('frozen-' + group + '.sha256')
        seal.write_text(''.join(sha(p) + '  ' + p.relative_to(exp).as_posix() + '\n' for p in paths))
        score(selection, exp, BASE)
        verify(seal, exp)
        rows = json.loads((exp / 'validation-results.json').read_text())
        controls = [r for r in rows if r['split'] == 'synthetic']
        if len(controls) != 2 or not all(r['passed'] for r in controls):
            write(exp / 'status.json', {'status': 'CONTROLS_NOT_PASSED'})
            return
    metric = json.loads((exp / 'benchmark-results.json').read_text())['aggregate']
    passed = metric['#Detected'] == 2 and metric['AvgF1'] >= .5 and metric['AvgFDR'] <= .5
    verify(exp / 'code.sha256', exp)
    with (exp / 'scorer-final.log').open('x') as log, contextlib.redirect_stdout(log):
        result = check(BASE, [exp], PARENT / 'r12-benchmark-first/scorer-reference/evaluation_pipeline.py', exp / 'scorer-final')
    assert result['all_equal']
    write(exp / 'status.json', {'status': 'DEVELOPMENT_GATE_PASSED' if passed else 'DEVELOPMENT_GATE_NOT_PASSED',
                              'aggregate': metric, 'independent_evaluation_started': False})
    if passed:
        write(exp / 'release-freeze.json', {'code_manifest_sha256': sha(exp / 'code.sha256'),
              'detection_manifest_sha256': sha(exp / 'frozen-diagnostic.sha256'),
              'config_sha256': sha(exp / 'detector-config.json'), 'status': 'ELIGIBLE_FOR_INDEPENDENT_EVALUATION'})


if __name__ == '__main__':
    main()
