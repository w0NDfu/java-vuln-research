"""Offline differential check against an unmodified, hash-pinned IRIS evaluator."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

from agentic_detection.benchmark_track import predictions
from agentic_detection.validate import frozen_output, read_jsonl, write
from vecho_experiment.evaluation import evaluate, labels


REFERENCE_SHA256 = '9556b699be88e0c33201f53291dc584d5a93994fa15bfb5704eee44bfee86404'


def declaration_ranges(root):
    """Independent declaration table adapter; never read fixed-source line ranges."""
    from tree_sitter import Language, Parser
    import tree_sitter_java
    parser = Parser(Language(tree_sitter_java.language()))
    classes, methods = [], []
    for file in sorted(Path(root).rglob('*.java')):
        relative = file.relative_to(root).as_posix()
        tree = parser.parse(file.read_bytes())
        pending = [tree.root_node]
        while pending:
            node = pending.pop()
            pending.extend(reversed(node.named_children))
            name = node.child_by_field_name('name')
            if name is None:
                continue
            row = {'file': relative, 'name': name.text.decode(),
                   'start_line': node.start_point.row + 1, 'end_line': node.end_point.row + 1}
            if node.type in {'class_declaration', 'interface_declaration', 'enum_declaration', 'record_declaration', 'annotation_type_declaration'}:
                classes.append(row)
            elif node.type in {'method_declaration', 'constructor_declaration', 'compact_constructor_declaration'}:
                methods.append(row)
    return classes, methods


def to_sarif(candidates):
    results = []
    for candidate in candidates:
        locations = []
        for node in candidate['ordered_nodes']:
            if not node.get('repository_relative_path') or not node.get('start_line'):
                continue
            description = node.get('expression') or node.get('provenance', {}).get('witness_step', {}).get('tracked_variable_or_expr', '')
            locations.append({'location': {'physicalLocation': {
                'artifactLocation': {'uri': node['repository_relative_path']},
                'region': {'startLine': node['start_line']}}, 'message': {'text': description}}})
        if locations:
            results.append({'codeFlows': [{'threadFlows': [{'locations': locations}]}]})
    return {'version': '2.1.0', 'runs': [{'results': results}]}


def check(base, experiments, reference, output):
    import pandas as pd
    if hashlib.sha256(reference.read_bytes()).hexdigest() != REFERENCE_SHA256:
        raise ValueError('Original IRIS evaluator differs from the audited reference.')
    spec = importlib.util.spec_from_file_location('original_iris_evaluation', reference)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for exp in experiments:
        for item in json.loads((exp / 'private/selection.json').read_text()):
            job = exp / 'runs' / item['key']
            if not (job / 'outcome.json').exists() or json.loads((job / 'outcome.json').read_text())['status'] != 'complete':
                continue
            frozen, _ = frozen_output(item, job)
            candidates = read_jsonl(frozen / 'candidates.jsonl')
            reviews = read_jsonl(frozen / 'reviews.jsonl')
            supported = {r['candidate_path_id'] for r in reviews if r['verdict'] == 'SUPPORTED'}
            subsets = {'submitted': candidates, 'strict': [c for c in candidates if c['candidate_path_id'] in supported]}
            if (frozen / 'benchmark-candidates.jsonl').exists():
                subsets['retained'] = read_jsonl(frozen / 'benchmark-candidates.jsonl')
            if item['split'] == 'synthetic':
                fixes = [{'file': 'Endpoint.java', 'class': 'Endpoint', 'method': 'handle'}]
            else:
                fixes, _ = labels(base / 'dataset', item['project'])
            classes, methods = declaration_ranges(Path(item['source']))
            directory = output / (exp.parent.name + '-' + exp.name) / item['key']
            directory.mkdir(parents=True)
            columns = ['file', 'name', 'start_line', 'end_line']
            class_file, method_file = directory / 'classes.csv', directory / 'methods.csv'
            pd.DataFrame(classes, columns=columns).to_csv(class_file, index=False)
            pd.DataFrame(methods, columns=columns).to_csv(method_file, index=False)
            pipeline = module.EvaluationPipeline(pd.DataFrame(fixes), str(class_file), str(method_file), item['source'])
            for subset, values in subsets.items():
                sarif = directory / (subset + '.sarif')
                write(sarif, to_sarif(values))
                actual = pipeline.evaluate_sarif_result(str(sarif))
                compatible = evaluate(item['source'], predictions(values), fixes)
                observed = [actual['num_paths'], actual['num_tp_paths_method'], int(actual['recall_method'])]
                ours = [compatible['paths'], compatible['tp_paths'], compatible['recall']]
                rows.append({'experiment': str(exp), 'key': item['key'], 'subset': subset,
                             'original': observed, 'compatible': ours, 'equal': observed == ours})
    result = {'reference_sha256': REFERENCE_SHA256,
              'reference_url': 'https://github.com/iris-sast/iris/blob/v2/src/modules/evaluation_pipeline.py',
              'location_table_provider': 'Independent tree-sitter declarations; not original CodeQL extraction',
              'comparison': ['paths', 'tp_paths_method', 'recall_method'],
              'all_equal': bool(rows) and all(r['equal'] for r in rows), 'checks': rows,
              'limitations': 'Finite frozen-output conformance, not equivalence for every Java program or original vEcho executable.'}
    write(output / 'conformance.json', result)
    print(json.dumps(result, indent=2))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--experiment', type=Path, action='append', required=True)
    parser.add_argument('--reference', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.base, args.experiment, args.reference, args.output)
    raise SystemExit(0 if result['all_equal'] else 2)


if __name__ == '__main__':
    main()
