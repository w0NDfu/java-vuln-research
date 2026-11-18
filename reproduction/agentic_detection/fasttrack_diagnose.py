"""Offline-only inspection of already frozen discovery; never imported by detection."""
import argparse
import json
from pathlib import Path


def unique_methods(rows):
    seen, out = set(), []
    for row in rows:
        if row['method_id'] not in seen:
            out.append(row); seen.add(row['method_id'])
    return out


def initial_queue(inventory, leads, cwes):
    rows = {r['method_id']: r for r in inventory}
    ranked = {c: sorted(rows, key=lambda i: (-rows[i]['scores'][c], rows[i]['file'], rows[i]['start_line'])) for c in cwes}
    queue, seen = [], set()
    def add(row):
        key = row.get('method_id'), row.get('cwe')
        if key[0] in rows and key[1] in cwes and key not in seen:
            seen.add(key); queue.append(row)
    for lead in leads[:12]: add(lead)
    model = queue[:]; queue = []
    for c in cwes:
        found = next((r for r in model if r['cwe'] == c), None)
        if found: queue.append(found); model.remove(found)
        elif ranked[c]: add({'method_id': ranked[c][0], 'cwe': c})
    queue.extend(model)
    for rank in range(min(4, len(rows))):
        for c in cwes: add({'method_id': ranked[c][rank], 'cwe': c})
    return unique_methods(queue)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--parent', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    from agentic_detection.r12_lab import verify
    from agentic_detection.validate import read_jsonl, write
    from vecho_experiment.evaluation import evaluate
    cwes = ['CWE-22', 'CWE-78', 'CWE-79', 'CWE-94']
    results = []
    for name in ['r12-benchmark-first', 'r13-native-discovery']:
        exp = args.parent / name / 'refinement-02'
        for n in ['code.sha256', 'frozen-diagnostic.sha256']:
            verify(exp / n, exp)
        selection = {r['key']: r for r in json.loads((exp / 'private/selection.json').read_text())}
        validation = {r['key']: r for r in json.loads((exp / 'validation-results.json').read_text())}
        for key in ['project_1', 'project_fresh_fixed']:
            out = exp / 'runs' / key / 'attempt-0001'
            trace = read_jsonl(out / 'trace.jsonl')
            inventory = json.loads((out / 'discovery-inventory.json').read_text())
            rows = inventory['methods']
            context = next(x['context'] for x in trace if x['event'] == 'model_input' and x['role'] == 'discovery')
            proposals = json.loads(next(x['content'] for x in trace if x['event'] == 'model_response' and x['role'] == 'discovery'))['leads']
            queue = (next(x['leads'] for x in trace if x['event'] == 'multi_source_discovery')
                     if name.startswith('r13') else initial_queue(rows, proposals, cwes))
            queue = unique_methods(queue)
            targets = validation[key]['metric']['targets']
            fixes = [{'file': f, 'class': cls, 'method': m} for f, cls, m in targets]
            records = [{'fingerprint': r['method_id'], 'tainted_data_flow': [[{'file_path': r['file'], 'line_number': r['start_line']}]]} for r in rows]
            metric = evaluate(selection[key]['source'], records, fixes)
            assert metric['status'] == 'available'
            hits = {d['fingerprint']: {tuple(t) for t in d['matched_methods']} for d in metric['details']}
            def coverage(items):
                matched = set().union(*(hits.get(r['method_id'], set()) for r in items)) if items else set()
                return {'recalled': len(matched), 'total': len(targets), 'methods': sorted(matched)}
            response = next(x for x in trace if x['event'] == 'model_response' and x['role'] == 'discovery')
            ranks = []
            for target in targets:
                ranks.append({'target': target,
                    'static_rank': next((i + 1 for i, r in enumerate(rows) if tuple(target) in hits[r['method_id']]), None),
                    'initial_queue_rank': next((i + 1 for i, r in enumerate(queue) if tuple(target) in hits.get(r['method_id'], set())), None)})
            results.append({'configuration': name, 'key': key, 'inventory_total': inventory['total_methods'],
                'inventory_visible': len(rows), 'all': coverage(rows), 'top10': coverage(rows[:10]), 'top30': coverage(rows[:30]),
                'initial_queue10': coverage(queue[:10]), 'initial_queue30': coverage(queue[:30]),
                'actual_read': validation[key]['target_code_recall'], 'target_ranks': ranks,
                'discovery_input_tokens': response['usage']['prompt_tokens']})
    write(args.output, {'scope': 'OFFLINE_LABEL_DIAGNOSTIC_ONLY', 'provider_requests': 0, 'cases': results})
    print(json.dumps(results, indent=2))


if __name__ == '__main__': main()
