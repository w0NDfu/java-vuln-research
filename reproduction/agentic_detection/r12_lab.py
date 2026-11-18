"""Lab-only r12 development supervisor; private selection never enters model workers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


BASE = Path('/home/dcj/java_vuln_work1/vecho-reproduction')
PARENT = BASE / 'agentic-path-builder-20261109'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(manifest, root):
    count = 0
    for line in manifest.read_text().splitlines():
        value, name = line.split(maxsplit=1)
        path = (root / name).resolve()
        if not path.is_relative_to(root.resolve()) or sha(path) != value:
            raise ValueError('Manifest mismatch: ' + name)
        count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--experiment', required=True, type=Path)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    os.umask(0o077)
    exp, old = args.experiment.resolve(), PARENT / 'r11-general-evp/refinement-06'
    if not exp.is_relative_to(PARENT) or exp == old:
        raise ValueError('Use an independent lab run directory.')
    code = exp / 'code'
    sys.path[:0] = [str(code / 'src'), str(code / 'reproduction')]
    from agentic_detection.validate import write, check_database, tree_hash, detect, score
    from agentic_detection.benchmark_track import audit
    codeql = BASE.parent / 'experiment-output/tools/codeql-v2.26.4/codeql/codeql'
    env = dict(os.environ, PYTHONPATH=':'.join(map(str, (code / 'src', code / 'reproduction',
               BASE / 'experiments/work1-m7-source-only-20261108/test-deps'))), PYTHONDONTWRITEBYTECODE='1')
    os.environ.update({k: env[k] for k in ('PYTHONPATH', 'PYTHONDONTWRITEBYTECODE')})
    if not (exp / 'code.sha256').exists():
        checks = {}
        for prior in (PARENT / 'r10-budget-fit', old):
            checks[str(prior)] = {name: verify(prior / name, prior) for name in ('code.sha256', 'frozen-all.sha256')}
        selection = []
        for item in json.loads((old / 'private/selection.json').read_text()):
            outcome = json.loads((old / 'runs' / item['key'] / 'outcome.json').read_text())
            static = outcome['static']
            check_database(Path(static['database']), Path(item['source']))
            if (tree_hash(Path(item['source'])) != item['tree_sha256']
                    or sha(Path(static['graph'])) != static['graph_sha256']
                    or sha(code / 'codeql/work1_agent/RepositorySiteGraph.ql') != static['query_sha256']):
                raise ValueError('Source or static export binding mismatch.')
            selection.append({**item, 'reuse_static': str(Path(static['graph']).parent)})
        write(exp / 'private/selection.json', selection)
        write(exp / 'historical-verification.json', checks)
        write(exp / 'detector-config.json', {'benchmark_first': True})
        # This diagnostic is stored outside the source and is never supplied to any policy.
        write(exp / 'r10-r11-preaudit.json', [audit(BASE, e) for e in (PARENT / 'r10-budget-fit', old)])
        write(exp / 'acceptance.json', {
            'phase': 'DEVELOPMENT_ONLY', 'controls': 'A retained positive; B no retained candidate',
            'development_gate': {'both_diagnostic_targets_detected': True, 'AvgF1_min': 0.5, 'AvgFDR_max': 0.5},
            'candidates_per_project_max': 12, 'per_cwe_max': 4,
            'budget_per_case': {'requests': 28, 'tokens': 300000, 'seconds': 1200, 'tools': 128},
            'next_stage': 'Freeze method after passing; independent unseen repository evaluation before 120-CVE campaign',
            'automatic_full_120_run': False})
        files = sorted(p for p in code.rglob('*') if p.is_file() and '__pycache__' not in p.parts)
        (exp / 'code.sha256').write_text(''.join(f'{sha(p)}  {p.relative_to(exp)}\n' for p in files))
        print('PREPARED', len(files), flush=True)
    if not args.run:
        return
    verify(exp / 'code.sha256', exp)
    with (exp / 'engineering-final.log').open('xb') as log:
        subprocess.run([sys.executable, '-B', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests/unit'],
                       cwd=code, env=env, stdout=log, stderr=subprocess.STDOUT, check=True)
    selection = json.loads((exp / 'private/selection.json').read_text())
    rows = []
    for group in ('synthetic', 'diagnostic'):
        write(exp / 'status.json', {'status': 'RUNNING', 'group': group})
        for item in selection:
            if item['split'] != group:
                continue
            outcome = detect(item, BASE, exp, codeql)
            print(json.dumps({'key': item['key'], 'status': outcome['status'],
                              'stop_reason': outcome.get('summary', {}).get('stop_reason')}), flush=True)
            if outcome['status'] != 'complete':
                write(exp / 'status.json', {'status': 'EXECUTION_FAILURE', 'key': item['key']})
                return
        # Freeze all current model outputs before evaluating any labels.
        paths = sorted(p for p in (exp / 'runs').rglob('*') if p.is_file() and p.suffix != '.lock')
        seal = exp / ('frozen-' + group + '.sha256')
        seal.write_text(''.join(f'{sha(p)}  {p.relative_to(exp)}\n' for p in paths))
        score(selection, exp, BASE)
        verify(seal, exp)
        rows = json.loads((exp / 'validation-results.json').read_text())
        controls = [r for r in rows if r['split'] == 'synthetic']
        if len(controls) != 2 or not all(r['passed'] for r in controls):
            write(exp / 'status.json', {'status': 'CONTROLS_NOT_PASSED'})
            return
    report = json.loads((exp / 'benchmark-results.json').read_text())
    metrics = report['aggregate']
    passed = metrics['#Detected'] == 2 and metrics['AvgF1'] >= 0.5 and metrics['AvgFDR'] <= 0.5
    verify(exp / 'code.sha256', exp)
    write(exp / 'status.json', {'status': 'DEVELOPMENT_GATE_PASSED' if passed else 'DEVELOPMENT_GATE_NOT_PASSED',
                              'aggregate': metrics, 'independent_evaluation_started': False})


if __name__ == '__main__':
    main()
