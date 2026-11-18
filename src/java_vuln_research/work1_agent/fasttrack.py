"""One bounded FastTrack comparison over a pinned r12 implementation."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

from .benchmark import BenchmarkRun as SafeRun
from .dag_retrieval import StructuralRetrieval, test_source
from .graph_rag import CodeQLGraphIndex
from .native_discovery import SINKS
from .repository.tools import RepositoryTools
from .repository.java_symbols import JavaSymbols
from .harness import ModelTurn
from .experiment_policy import BudgetExceeded

R12_SHA256 = 'f4bb22a4457742b99ae08ade40c079165ecc75aed8fb0cb483d1a529b7890034'


def baseline(path):
    path = Path(path)
    if hashlib.sha256(path.read_bytes()).hexdigest() != R12_SHA256:
        raise ValueError('FastTrack requires the exact frozen r12 refinement-02 implementation.')
    name = 'java_vuln_research.work1_agent._fasttrack_frozen_r12'
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def pack_discovery(context, rows, symbols, ast_ids, system):
    import tiktoken
    encoding = tiktoken.get_encoding('o200k_base')
    files, types = [], []
    aliases, packed, details, sink_hints = {}, [], {}, {}
    for i, row in enumerate(rows):
        alias = 'm' + str(i)
        aliases[alias] = row['method_id']
        file = row['file']
        typ = row['name'].rsplit('.', 1)[0]
        if file not in files: files.append(file)
        if typ not in types: types.append(typ)
        packed.append([alias, files.index(file), types.index(typ), row['name'].rsplit('.', 1)[-1],
                       row['start_line'], [row['scores'][c] for c in ['CWE-22', 'CWE-78', 'CWE-79', 'CWE-94']]])
        calls = symbols.calls.get(ast_ids.get(row['method_id']), [])
        dangerous = [dict(cwe=cwe, **c) for c in calls for cwe, names in SINKS.items() if c['name'].split('.')[-1] in names]
        if dangerous:
            sink_hints[alias] = [[c['name'],c['dynamic_arguments']] for c in sorted(dangerous,key=lambda c:(-c['dynamic_arguments'],c['line']))[:2]]
        details[alias] = {'signature': row['signature'], 'end': row['end_line'], 'calls': row['calls'][:12],
                          'sink_arguments': dangerous[:3]}
    payload = {k:v for k,v in context.items() if k != 'inventory'}
    payload.update(inventory=packed, files=files, types=types,
        inventory_schema=['method_id', 'file_index', 'type_index', 'method', 'line', 'scores_22_78_79_94'],
        selection='Keep r12 retrieval priors. Prefer real dangerous calls and dynamic arguments; investigate all four CWEs. Return listed method_id aliases. Source is fetched on demand.',
        sink_hints=sink_hints,sink_hint_schema=['actual_call','dynamic_argument_count'],details={})
    def tokens():
        return len(encoding.encode(json.dumps({'role':'discovery','task':'benchmark_discovery',**payload}, ensure_ascii=False), disallowed_special=())) + len(encoding.encode(system, disallowed_special=())) + 16
    count = tokens()
    # Enrich a small repository with useful signatures/argument facts; never pad or drop methods.
    for alias, detail in details.items():
        if count >= 9000: break
        payload['details'][alias] = detail
        count = tokens()
        if count > 12000:
            del payload['details'][alias]; count = tokens(); break
    if count > 12000:
        raise ValueError('Compact Discovery exceeds 12k estimated tokens without dropping candidates.')
    return payload, aliases, count


def runner_type(base):
    class FastRun(base.BenchmarkRun):
        def setup(self, strategy, symbols):
            self.strategy, self.ast = strategy, symbols
            self.read_failures = 0
            self.ast_ids = {}
            self.legacy_for_ast = {}
            for i, m in self.methods.items():
                matches = [a for a in symbols.by_file[m.repository_relative_path]
                           if a.simple_name == m.simple_name and a.start_line == m.start_line and a.end_line == m.end_line]
                if len(matches) == 1:
                    self.ast_ids[i] = matches[0].entity_id
                    self.legacy_for_ast[matches[0].entity_id] = i
            self.supplement = {i:m for i,m in symbols.methods.items() if i not in self.legacy_for_ast
                               and not test_source(m.repository_relative_path)}
            for i in self.supplement: self.ast_ids[i] = i
            self.full_rows = None

        def inventory(self):
            selected, ranked, rows = super().inventory()
            extra = []
            for m in self.supplement.values():
                calls = sorted({c['name'] for c in self.ast.calls[m.entity_id]})
                extra.append({'method_id':m.entity_id,'name':m.qualified_name,'signature':m.signature,
                              'file':m.repository_relative_path,'start_line':m.start_line,'end_line':m.end_line,
                              'calls':calls[:24], 'scores':{c:0 for c in ['CWE-22','CWE-78','CWE-79','CWE-94']},'codeql_alert':False})
            self.full_rows = [*selected, *[r for i,r in rows.items() if i not in {x['method_id'] for x in selected}],
                              *sorted(extra,key=lambda r:(r['file'],r['start_line'],r['name']))]
            (self.output/'static-candidates.json').write_text(json.dumps({'strategy':self.strategy,'rows':self.full_rows},indent=2)+'\n')
            return selected, ranked, rows

        def activate_reads(self):
            for i,m in self.supplement.items():
                self.methods[i] = m
                self.retrieval.entities[i] = m
                self.sources.setdefault(m.repository_relative_path,(self.tools.index.repository_root/m.repository_relative_path).read_text().splitlines())

        def ask(self, role, context):
            aliases = {}
            if role == 'discovery':
                self.activate_reads()
                if self.strategy == 'A2':
                    context, aliases, count = pack_discovery(context,self.full_rows,self.ast,self.ast_ids,base.PROMPTS['discovery'])
                    (self.output/'discovery-packing.json').write_text(json.dumps({'estimated_input_tokens':count,'aliases':aliases},indent=2)+'\n')
            elif role == 'reasoning' and self.strategy == 'A2':
                i = context['focus']['method_id']
                calls = self.ast.calls.get(self.ast_ids.get(i),[])
                sinks = [dict(cwe=cwe,**c) for c in calls for cwe,names in SINKS.items() if c['name'].split('.')[-1] in names]
                context = {**context,'sink_first':{'calls':sinks[:4],
                    'instruction':'Start at actual sink arguments; inspect incoming callers, parameter binding and external input. A dangerous call alone is not a vulnerability. Scan all four CWE families.'}}
            value = super().ask(role,context)
            if aliases:
                for lead in value.get('leads',[]): lead['method_id'] = aliases.get(lead.get('method_id'),lead.get('method_id'))
            return value

        def request(self, action):
            # Preserve successful r12 tool results. Only failed/missing resolutions use the AST view.
            if action.get('action') != 'resolve_method':
                try:
                    result = super().request(action)
                    if action.get('action') != 'search_symbols' or result.get('hits'): return result
                except (ValueError,KeyError,TypeError):
                    pass
            self.symbols = self.ast
            saved = dict(self.methods)
            self.methods.update({i:m for i,m in self.ast.methods.items() if not test_source(m.repository_relative_path)})
            adapted = dict(action)
            i = action.get('entity_id')
            if i in self.ast_ids: adapted['entity_id'] = self.ast_ids[i]
            try:
                return SafeRun.request(self,adapted)
            finally:
                self.symbols = None
                # AST declarations remain available for an explicit subsequent read.
                self.methods.update(saved)

        def read(self, method_id, start=None, end=None):
            if self.strategy == 'A2' and start is None and end is None:
                m = self.methods.get(method_id)
                calls = self.ast.calls.get(self.ast_ids.get(method_id,method_id),[])
                sinks = [c for c in calls if any(c['name'].split('.')[-1] in names for names in SINKS.values())]
                if m and sinks:
                    chosen = sorted(sinks,key=lambda c:(-c['dynamic_arguments'],c['line']))[0]
                    start = max(m.start_line,chosen['line']-30)
                    end = min(m.end_line,start+119)
            return super().read(method_id,start,end)

        def neighbors(self, method_id):
            rows = super().neighbors(method_id)
            if self.strategy == 'A2' and self.retrieval.graph:
                incoming = {e['from']['entity_id'] for e in self.retrieval.graph.by_entity.get(method_id,[])
                            if e['to']['entity_id'] == method_id}
                rows.sort(key=lambda r:r['method_id'] not in incoming)
            return rows
    return FastRun


def build_runner(repository, output, team, *, r12_implementation, strategy, static_report=None, static_graph=None,
                 limits=None, tool_limit=128, request_headroom=None, token_headroom=None):
    if strategy not in {'A1','A2'}: raise ValueError('Choose A1 or A2.')
    base = baseline(r12_implementation)
    tools = RepositoryTools.open(repository)
    symbols = JavaSymbols(RepositoryTools.open(repository).index)
    graph = CodeQLGraphIndex(Path(repository),tools.index.entities,static_graph)
    retrieval = StructuralRetrieval(tools.index.entities,static_report,graph)
    runner = runner_type(base)(tools,retrieval,team,Path(output),limits=limits or base.BenchmarkLimits(),
                              tool_limit=tool_limit,request_headroom=request_headroom,token_headroom=token_headroom)
    runner.setup(strategy,symbols)
    return runner


def run_fasttrack(repository, output, team, **kwargs):
    output = Path(output)
    if output.resolve().is_relative_to(Path(repository).resolve()): raise ValueError('Output must be outside source.')
    output.mkdir(parents=True,exist_ok=False)
    runner = build_runner(repository,output,team,**kwargs)
    try:
        result = runner.run()
        result.update(fasttrack=runner.strategy,read_failures=runner.read_failures)
        (output/'run.json').write_text(json.dumps(result,indent=2)+'\n')
        return result
    finally: runner.trace.close()


class ExactPrefixReuse:
    """Reuse only an unchanged request prefix; cached work still consumes the logical budget."""
    def __init__(self, journal, source, log):
        self.journal,self.log = journal,Path(log)
        self.rows = [json.loads(x) for x in Path(source).read_text().splitlines() if json.loads(x)['event']=='response']
        self.cursor,self.enabled,self.requests,self.tokens = 0,True,0,0

    def wrap(self, policy):
        def call(context):
            encoded = json.dumps({'context':context,'system':policy.system_prompt,'model':policy.model,
                'endpoint':policy.endpoint,'output_limit':policy.max_output_tokens},ensure_ascii=False,sort_keys=True).encode()
            key = hashlib.sha256(encoded).hexdigest()
            if self.enabled and self.cursor < len(self.rows) and self.rows[self.cursor]['request_key'] == key:
                row = self.rows[self.cursor]
                charged = row['charged_tokens']
                if self.journal.max_requests-self.journal.requests < 1 or self.journal.tokens+charged > self.journal.max_tokens:
                    raise BudgetExceeded('Logical budget including exact-prefix reuse exhausted.')
                self.requests += 1; self.tokens += charged; self.cursor += 1
                self.journal.max_requests -= 1; self.journal.max_tokens -= charged
                with self.log.open('a') as stream:
                    stream.write(json.dumps({'event':'exact_prefix_reuse','request_key':key,'logical_tokens':charged,'prefix_position':self.cursor})+'\n')
                return ModelTurn(row['content'],row['usage'],row.get('metadata',{}))
            self.enabled = False
            return policy(context)
        for key in ['system_prompt','model','endpoint','max_output_tokens']:
            setattr(call,key,getattr(policy,key))
        return call
