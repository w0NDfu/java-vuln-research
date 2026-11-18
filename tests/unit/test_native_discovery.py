"""R13 independent Java fixtures, native mapping and bounded retrieval tests."""
import json
import shutil
from pathlib import Path

import pytest

from java_vuln_research.work1_agent.repository.tools import RepositoryTools
from java_vuln_research.work1_agent.repository.java_symbols import JavaSymbols
from java_vuln_research.work1_agent.native_discovery import canonical_sarif, map_alerts, method_signals, merge_leads
from java_vuln_research.work1_agent.benchmark import run_benchmark
from java_vuln_research.work1_agent.dag_harness import AgentTeam
from java_vuln_research.work1_agent.harness import ModelTurn


@pytest.fixture
def symbols(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    shutil.copyfile(Path(__file__).parents[1] / 'fixtures/r13_native/R13Symbols.java', source / 'R13Symbols.java')
    return JavaSymbols(RepositoryTools.open(source).index)


def test_nested_local_anonymous_overloads_and_inheritance(symbols):
    assert len(symbols.resolve('Container.Worker.select')) == 2
    selected = symbols.resolve('Container$Worker.select(String)')
    assert len(selected) == 1 and selected[0].signature == 'select(String)'
    inherited = symbols.resolve('Worker.inherited(java.lang.String)')
    assert len(inherited) == 1 and inherited[0].enclosing_type == 'symbols.Parent'
    assert not symbols.resolve('Worker.hidden(String)')
    assert len(symbols.resolve('select')) == 3
    run = symbols.resolve('run')
    assert len(run) == 1 and '$anon@' in run[0].enclosing_type
    assert '$local@' in symbols.resolve('carry')[0].enclosing_type
    assert not symbols.resolve('Worker.select(boolean)')


def test_same_line_declarations_remain_ambiguous_without_column(symbols):
    first = symbols.resolve('first')[0]
    assert len(symbols.at('R13Symbols.java', first.start_line)) == 2
    assert [m.simple_name for m in symbols.at('R13Symbols.java', first.start_line, 8)] == ['first']


def sarif_fixture(file='R13Symbols.java', line=15):
    return {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'CodeQL', 'rules': [
        {'id': 'java/example', 'properties': {'tags': ['security', 'external/cwe/cwe-079']}}]}},
        'results': [{'ruleId': 'java/example', 'message': {'text': 'Real diagnostic message'},
          'locations': [{'physicalLocation': {'artifactLocation': {'uri': file}, 'region': {'startLine': line, 'startColumn': 21}}}],
          'codeFlows': [{'threadFlows': [{'locations': [{'location': {'physicalLocation': {'artifactLocation': {'uri': file}, 'region': {'startLine': line, 'startColumn': 21}}}}]}]}]}]}]}


def test_sarif_preserves_metadata_locations_and_paths_and_maps_anonymous(symbols):
    payload = canonical_sarif(sarif_fixture(), symbols.index.repository_root)
    alert = payload['vulnerabilities'][0]
    assert alert['rule_id'] == 'java/example' and alert['cwes'] == ['CWE-79']
    assert alert['description'] == 'Real diagnostic message'
    assert alert['locations'][0]['column'] == 21 and len(alert['tainted_data_flow']) == 1
    mapped, summary = map_alerts(payload, symbols)
    assert summary['mapping_rate'] == 1
    assert all('$anon@' in symbols.methods[p['method_ids'][0]].enclosing_type for p in mapped[0]['mapped_locations'])


@pytest.mark.parametrize('bad', ['../R13Symbols.java', '/unrelated/R13Symbols.java', 'file://remote/R13Symbols.java'])
def test_sarif_does_not_guess_paths_by_basename(symbols, bad):
    with pytest.raises(ValueError): canonical_sarif(sarif_fixture(bad), symbols.index.repository_root)


def test_native_success_zero_and_execution_failed_are_distinct(symbols):
    payload = sarif_fixture()
    payload['runs'][0]['results'] = []
    assert canonical_sarif(payload, symbols.index.repository_root) == {'vulnerabilities': [], 'native_status': 'complete'}
    payload['runs'][0]['invocations'] = [{'executionSuccessful': False}]
    with pytest.raises(ValueError, match='execution failed'): canonical_sarif(payload, symbols.index.repository_root)


def test_multi_source_merge_prioritizes_native_and_deduplicates_method(symbols):
    payload = canonical_sarif(sarif_fixture(), symbols.index.repository_root)
    alerts, _ = map_alerts(payload, symbols)
    rows = {m.entity_id: {**symbols.describe(m), **method_signals(m, symbols, alerts)} for m in symbols.methods.values()}
    native = symbols.resolve('run')[0]
    proposal = {'method_id': native.entity_id, 'cwe': 'CWE-79', 'reason': 'Inspect actual printed argument'}
    leads = merge_leads(rows, [proposal, proposal], ['CWE-22', 'CWE-78', 'CWE-79', 'CWE-94'])
    assert leads[0]['method_id'] == native.entity_id
    assert len({r['method_id'] for r in leads}) == len(leads)
    single = merge_leads(rows, [proposal], ['CWE-22', 'CWE-78', 'CWE-79', 'CWE-94'])
    assert leads[0]['score'] == single[0]['score']
    assert {'CODEQL_NATIVE', 'AGENT_DISCOVERY', 'AST_DANGEROUS_CALL'} <= set(leads[0]['origins'])
    # A suggestive method name does not turn an identity function into an injection sink.
    assert not any(method_signals(symbols.resolve('inherited')[0], symbols, [])['dangerous_calls'].values())


def test_invalid_read_returns_exact_candidates_and_succeeds_when_explicitly_selected(tmp_path, symbols):
    contexts = []
    def policy(context):
        contexts.append(context)
        if context['role'] == 'discovery': return ModelTurn('{"leads":[]}')
        requests = []
        if not context['retrieval_results']:
            requests = [{'action': 'inspect_entity', 'entity_id': 'Container.Worker.select'}]
        else:
            result = context['retrieval_results'][0]['result']
            if result.get('status') == 'ambiguous':
                assert len(result['candidates']) == 2
                c = result['candidates'][0]
                assert all(k in c for k in ['file', 'type', 'signature', 'start_line', 'end_line'])
                requests = [{'action': 'inspect_entity', 'entity_id': c['method_id'], 'start_line': 1, 'end_line': 999}]
            elif result.get('status') == 'invalid_window':
                requests = [{'action': 'inspect_entity', 'entity_id': result['selected_method']['method_id']}]
        return ModelTurn(json.dumps({'candidates': [], 'requests': requests, 'leads': [], 'disposition': 'Fixture retrieval'}))
    result = run_benchmark(symbols.index.repository_root, tmp_path / 'run', AgentTeam(policy, policy, policy))
    assert result['read_failures'] > 0
    assert not result['protocol_failed_nodes']


def test_query_inventory_requires_all_cwes_and_pins_metadata(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / 'reproduction'))
    from agentic_detection.native_queries import inventory
    for number in [22, 78, 79, 94]:
        folder = tmp_path / f'CWE-{number:03}'
        folder.mkdir()
        (folder / 'Test.ql').write_text(f'/** @id java/test-{number}\n * @kind path-problem\n * @tags security external/cwe/cwe-{number:03}\n */')
    queries = inventory(tmp_path)
    assert len(queries) == 4 and all(len(q['sha256']) == 64 for q in queries)


@pytest.mark.parametrize('failed', [False, True])
def test_native_execution_receipt_preserves_zero_vs_failure_and_original_database(tmp_path, monkeypatch, failed):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / 'reproduction'))
    from agentic_detection import native_queries
    database = tmp_path / 'historical-db'
    database.mkdir()
    (database / 'immutable').write_text('original database')
    source = tmp_path / 'source'
    source.mkdir()
    monkeypatch.setattr(native_queries, 'check_database', lambda *a: None)
    def execute(args, log, **kwargs):
        if failed: raise RuntimeError('CodeQL process exited 2')
        raw = Path(next(x.removeprefix('--output=') for x in args if x.startswith('--output=')))
        raw.write_text(json.dumps({'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 'CodeQL'}}, 'results': []}]}))
    monkeypatch.setattr(native_queries, 'command', execute)
    result = native_queries.run_native({'source': str(source), 'tree_sha256': native_queries.tree_hash(source)},
        {'database': str(database)}, tmp_path / 'new-run', Path('unused-codeql'), [], tmp_path)
    assert result['original_database_before_sha256'] == result['original_database_after_sha256']
    assert (database / 'immutable').read_text() == 'original database'
    if failed:
        assert result['status'] == 'failed' and result['result_state'] == 'execution_failed'
        assert 'alerts' not in result and 'exited 2' in result['error']
    else:
        assert result['status'] == 'complete' and result['result_state'] == 'success_zero_alerts' and result['alerts'] == 0


def test_short_type_suffix_is_not_silently_matched(symbols):
    assert not symbols.resolve('ker.select(String)')


def test_duplicate_type_names_in_distinct_packages_return_explicit_choices(tmp_path):
    (tmp_path / 'One.java').write_text('package one; class Same { void handle(String x) {} }')
    (tmp_path / 'Two.java').write_text('package two; class Same { void handle(String x) {} }')
    symbols = JavaSymbols(RepositoryTools.open(tmp_path).index)
    assert len(symbols.resolve('Same.handle(String)')) == 2
    assert len(symbols.resolve('one.Same.handle(String)')) == 1
