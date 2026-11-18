"""Run a label-independent, hash-pinned Java security query inventory."""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

from agentic_detection.validate import command, check_database, tree_hash, write

CWES = {'CWE-022', 'CWE-078', 'CWE-079', 'CWE-094'}


def inventory(package):
    rows, seen = [], set()
    for path in sorted(package.rglob('*.ql'), key=lambda p: ('experimental' in p.parts, str(p))):
        if not CWES.intersection(path.parts):
            continue
        text = path.read_text()
        rule = re.search(r'@id\s+(\S+)', text)
        kind = re.search(r'@kind\s+(\S+)', text)
        tags = sorted(set('CWE-' + str(int(x)) for x in re.findall(r'external/cwe/cwe-(\d+)', text)))
        if not rule or not kind or kind[1] not in {'problem', 'path-problem'}:
            continue
        if rule[1] in seen:
            raise ValueError('Duplicate native query rule ID: ' + rule[1])
        seen.add(rule[1])
        import hashlib
        rows.append({'path': str(path), 'rule_id': rule[1], 'kind': kind[1], 'cwes': tags,
                     'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                     'experimental': 'experimental' in path.parts})
    if not rows or not all(any('CWE-' + str(int(c[4:])) in r['cwes'] for r in rows) for c in CWES):
        raise ValueError('Installed native queries do not cover all four CWE families.')
    return rows


def run_native(item, static, output, codeql, queries, package):
    """Only write an independent database copy; never reuse failed/null receipts."""
    import hashlib
    output.mkdir(parents=True, exist_ok=False)
    receipt = output / 'native-receipt.json'
    result = {'status': 'not_executed', 'source_tree_sha256': item['tree_sha256'],
              'original_database': static['database'], 'query_pack': str(package), 'queries': queries,
              'force_rerun': True}
    write(receipt, result)
    started = time.monotonic()
    original = Path(static['database'])
    before = tree_hash(original)
    try:
        check_database(original, Path(item['source']))
        if tree_hash(Path(item['source'])) != item['tree_sha256']:
            raise ValueError('Native source snapshot binding mismatch.')
        database = output / 'database'
        shutil.copytree(original, database)
        check_database(database, Path(item['source']))
        raw = output / 'native.sarif'
        command([str(codeql), 'database', 'analyze', str(database),
                 *[q['path'] for q in queries], '--rerun', '--format=sarifv2.1.0', f'--output={raw}',
                 '--threads=2', '--ram=4096'], output / 'native.log', timeout=2400)
        from java_vuln_research.work1_agent.native_discovery import canonical_sarif
        payload = canonical_sarif(json.loads(raw.read_text()), item['source'])
        report = output / 'native.canonical.json'
        write(report, payload)
        result.update(status='complete', alerts=len(payload['vulnerabilities']),
                      result_state='success_with_alerts' if payload['vulnerabilities'] else 'success_zero_alerts',
                      report=str(report), report_sha256=hashlib.sha256(report.read_bytes()).hexdigest(),
                      sarif=str(raw), sarif_sha256=hashlib.sha256(raw.read_bytes()).hexdigest(),
                      database=str(database))
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        result.update(status='failed', result_state='execution_failed', error=str(error), error_type=type(error).__name__)
    finally:
        after = tree_hash(original)
        result.update(original_database_before_sha256=before, original_database_after_sha256=after,
                      elapsed_seconds=round(time.monotonic() - started, 3))
        if before != after:
            result.update(status='failed', error='Historical database changed during native execution.')
        write(receipt, result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--codeql', type=Path, required=True)
    args = parser.parse_args()
    from agentic_detection.r12_lab import verify
    for name in ('code.sha256', 'frozen-synthetic.sha256', 'frozen-diagnostic.sha256'):
        verify(args.baseline / name, args.baseline)
    args.output.mkdir(parents=True, exist_ok=False)
    packs = json.loads(subprocess.check_output([str(args.codeql), 'resolve', 'qlpacks', '--format=json'], text=True))
    package = Path(packs['codeql/java-queries'][0])
    queries = inventory(package)
    write(args.output / 'query-inventory.json', queries)
    results = []
    for item in json.loads((args.baseline / 'private/selection.json').read_text()):
        static = json.loads((args.baseline / 'runs' / item['key'] / 'outcome.json').read_text())['static']
        result = run_native(item, static, args.output / item['key'], args.codeql, queries, package)
        results.append({'key': item['key'], **result})
        print(json.dumps({'key': item['key'], 'status': result['status'], 'alerts': result.get('alerts'), 'error': result.get('error')}), flush=True)
        write(args.output / 'native-preparation.json', results)
    raise SystemExit(0 if all(x['status'] == 'complete' for x in results) else 2)


if __name__ == '__main__':
    main()
