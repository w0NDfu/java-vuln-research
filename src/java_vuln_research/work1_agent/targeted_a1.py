"""Three independent, bounded amendments around the original A1 methods."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path,PurePosixPath
import hashlib,json,re,inspect
from .resource_references import (children,descendants,text,string_literal,ViewScripts,
                                  local_path,resource_identity)
from .source_window import clip_exact_window
from .benchmark import digest,source_safe

@dataclass(frozen=True)
class Switches:
    web_surface_enhancement: bool=False
    critical_evidence_closure: bool=False
    cross_cwe_reasoning: bool=False

WEB_PROMPT = (' Also inspect web_surface_inventory: these are source-located navigation facts for '
 'business routes, request-bound objects, persistence interfaces, list responses, views and scripts. '
 'The original inventory retains its order; supplemental business entry methods were previously outside '
 'the 360-row view. Select diverse concrete business-data-to-browser investigations as warranted by '
 'these relations, alongside the original surfaces. No entry is a forced choice or known vulnerability. '
 'Static references do not prove same-record propagation, input control or runtime rendering.')
CLOSURE_PROMPT = (' Preserve the current hypothesis while closing decision-changing evidence gaps. '
 'When requesting missing implementation that could change your safety judgment, add '
 'critical_questions:[{question:string,request_indices:[zero-based indexes in requests]}], at most two. '
 'Use the original tool request schemas and exact identities. On receiving critical_evidence_closure, '
 'reassess the listed questions using delivered source; report '
 'question_updates:[{question_id,status:ANSWERED or REFUTED or UNRESOLVED,answer:string,evidence_refs:[IDs]}]. '
 'ANSWERED/REFUTED require actual supplied source references; UNKNOWN is not refutation. '
 'Keep questions compact. Do not chase unrelated completeness or require all runtime conditions proved. '
 'Submit a candidate immediately when the original conditional A1 standard is met; evidence questions '
 'must not delay an otherwise admissible candidate. A bounded continuation may deliver critical reads.')
CROSS_PROMPT = (' On EVERY round reconsider all supported CWE-22/78/79/94 using the actual source '
 'and safety context. The historical focus hint is only navigation, not a required classification or '
 'a prerequisite task. Do not spend the response merely proving the hint absent. If another CWE has '
 'a grounded conditional candidate, submit it NOW using the original candidate schema and exact '
 'evidence, even while other tool requests or the hinted question remain pending. Distinguish local '
 'safety conditions from deployment assumptions; preserve unconfirmed conditions in uncertainties. '
 'A library parameter may be conditional input under original A1 rules; no caller is not by itself '
 'a rule forbidding a grounded library-boundary candidate. A name alone, unsupported contract, or '
 'generic library sink alone is not sufficient. Do not force any particular CWE or any candidate.')

def prompts(original,switches):
    from .a1_resource_evidence import prompts as mixed
    p=mixed(original)
    p['reasoning']+=' Investigation leads become independent serial tasks, including a different supported CWE while the present task remains unresolved. Use the existing leads schema with exact method_id/cwe/reason; optional evidence_refs identify your actual supplied sources. For critical questions retain the provided question_id when updating that same original question; new questions must not overwrite older ones. Unresolved conditions and a missing caller are not refutations. Task/question provenance is supplied separately from vulnerability proof.'
    p['reasoning']+=' The existing inspect_entity action also accepts an actually supplied resource_id as entity_id, with explicit start_line/end_line. Resource reads remain bounded to160 lines and9000 bytes; any excluded source remains unknown. Never invent a resource or Java identity.'
    if switches.web_surface_enhancement:p['discovery']+=WEB_PROMPT
    if switches.critical_evidence_closure:p['reasoning']+=CLOSURE_PROMPT
    if switches.cross_cwe_reasoning:p['reasoning']+=CROSS_PROMPT
    return p

def _web_surfaces(runner):
    root=runner.tools.index.repository_root;surfaces=[];extra_types=set()
    by_span={(m.repository_relative_path,m.start_line,m.end_line):m for m in runner.methods.values()}
    for file in sorted({m.repository_relative_path for m in runner.ast.methods.values()}):
        if '/src/main/java/' not in '/'+file:continue
        raw=(root/file).read_bytes();tree=runner.ast.parser.parse(raw)
        if tree.root_node.has_error:continue
        imports={x.rsplit('.',1)[-1]:x for x in re.findall(r'\bimport\s+([\w.]+)\s*;',raw.decode())}
        pkg=re.search(r'\bpackage\s+([\w.]+)\s*;',raw.decode());package=pkg[1] if pkg else ''
        def qualify(t):return imports.get(t,t if '.' in t else (package+'.'+t if package else t))
        for owner in descendants(tree.root_node):
            if owner.type!='class_declaration':continue
            mods=text(next(iter(children(owner,{'modifiers'})),None))
            controller=(imports.get('Controller')=='org.springframework.stereotype.Controller' and '@Controller' in mods or imports.get('RestController')=='org.springframework.web.bind.annotation.RestController' and '@RestController' in mods)
            if not controller:continue
            body=owner.child_by_field_name('body');fields=[];views=[]
            for field in children(body,{'field_declaration'}):
                typ=text(field.child_by_field_name('type'))
                if not re.fullmatch(r'[\w.]+',typ):continue
                for dec in children(field,{'variable_declarator'}):fields.append({'name':text(dec.child_by_field_name('name')),'type':qualify(typ),'line':field.start_point.row+1})
            methods=children(body,{'method_declaration'})
            before,_=('/'+file).rsplit('/src/main/java/',1);base=(before.lstrip('/')+'/' if before else '')+'src/main/resources'
            for node in methods:
                for ret in descendants(node,stop={'class_body','lambda_expression'}):
                    if ret.type!='return_statement':continue
                    literals=children(ret,{'string_literal'})
                    if len(literals)!=1:continue
                    literal=string_literal(literals[0])
                    if not literal or not re.fullmatch(r'[\w.-]+(?:/[\w.-]+)*',literal):continue
                    choices=[f'{base}/templates/{literal}{s}' for s in ('','.ftl','.html','.jsp')]
                    found=[f for f in choices if local_path(root,f)]
                    if len(found)!=1:continue
                    v={'file':found[0],'origin_file':file,'return_line':ret.start_point.row+1,'scripts':[],'scope':'STATIC_FILE_REFERENCE_ONLY'}
                    parser=ViewScripts();parser.feed((root/found[0]).read_text())
                    for first,last,src in parser.references:
                        if not src:continue
                        src=src.removeprefix('${request.contextPath}').removeprefix('${pageContext.request.contextPath}')
                        if not re.fullmatch(r'/?[\w.-]+(?:/[\w.-]+)*',src):continue
                        choices=([f'{base}/{d}/{src[1:]}' for d in ('static','public','META-INF/resources')]+[f'{base}/{src[1:]}']) if src.startswith('/') else [str(PurePosixPath(found[0]).parent/src)]
                        matches=[s for s in dict.fromkeys(choices) if local_path(root,s)]
                        v['scripts'].append({'src':src,'template_lines':[first,last],'resolved_file':matches[0] if len(matches)==1 else None,'binding':'FILE_REFERENCE_NOT_VALUE_FLOW'})
                    views.append(v)
            for node in methods:
                ann=text(next(iter(children(node,{'modifiers'})),None))
                if not re.search(r'@(?:[\w.]+\.)?(?:Request|Get|Post|Put|Delete|Patch)Mapping\b',ann):continue
                m=by_span.get((file,node.start_point.row+1,node.end_point.row+1))
                if m is None:continue
                params=[]
                for param in children(node.child_by_field_name('parameters'),{'formal_parameter','spread_parameter'}):
                    typ=text(param.child_by_field_name('type'));q=qualify(typ);matches=[t for t in runner.ast.types.values() if t.qualified_name==q]
                    row={'name':text(param.child_by_field_name('name')),'type':typ,'line':param.start_point.row+1,'annotations':text(next(iter(children(param,{'modifiers'})),None)),'binding':'SOURCE_DECLARED_PARAMETER_FRAMEWORK_BINDING_UNCONFIRMED'}
                    if len(matches)==1:row['dto_type']=q;row['dto_file']=matches[0].repository_relative_path;extra_types.add(q)
                    params.append(row)
                calls=runner.ast.calls.get(runner.ast_ids.get(m.entity_id,m.entity_id),[])
                persistence=[{'receiver':c['receiver'],'method':c['name'],'line':c['line'],'declared_type':f['type']} for c in calls for f in fields if c['receiver'] in {f['name'],'this.'+f['name']}]
                mapper_files=[]
                for f in fields:
                    for xml in sorted((root/base).rglob('*.xml')) if (root/base).exists() else []:
                        if xml.stat().st_size>524288:continue
                        content=xml.read_text()
                        if re.search(r'<mapper\b[^>]*\bnamespace=[\'"]'+re.escape(f['type'])+r'[\'"]',content):mapper_files.append(xml.relative_to(root).as_posix())
                surfaces.append({'method_id':m.entity_id,'file':file,'lines':[m.start_line,m.end_line],'route_annotations':ann[:800], 'parameters':params,'declared_persistence_calls':persistence,'mapper_files':sorted(set(mapper_files)),'class_views':views,'scope':'NAVIGATION_RELATIONS_NOT_PROVEN_PROPAGATION'})
    return surfaces,extra_types

def install(runner,switches,archive,chain_managed=False):
    old_inventory,old_ask,old_request,old_explore=runner.inventory,runner.ask,runner.request,runner.explore
    questions={};pending_proofs={};proof_owners={};pending_results=[];current_focus=[None];last_answer=[{}]
    runtime_proof={'core_explore_module':old_explore.__func__.__module__,'core_explore_file':inspect.getsourcefile(old_explore.__func__),'original_core_object':old_explore.__func__}
    def persist():
        (runner.output/'critical-questions.json').write_text(json.dumps(list(questions.values()),ensure_ascii=False,indent=2)+'\n')
    def inventory():
        original,ranked,rows=old_inventory()
        if not switches.web_surface_enhancement:return original,ranked,rows
        runner.activate_reads();surfaces,types=_web_surfaces(runner)
        mids={s['method_id'] for s in surfaces}
        mids.update(m.entity_id for m in runner.methods.values() if m.enclosing_type in types)
        full={r['method_id']:r for r in runner.full_rows};ids={r['method_id'] for r in original}
        added=[full[i] for i in mids if i in full and i not in ids]
        added.sort(key=lambda r:(r['file'],r['start_line'],r['name'],r['method_id']))
        selected=[*original,*added]
        audit={'original_visible_count':len(original),'expanded_visible_count':len(selected),'original_order_unchanged':selected[:len(original)]==original,'added_ids':[r['method_id'] for r in added],'surfaces':surfaces,'selection':'ORIGINAL_ORDER_THEN_STABLE_SOURCE_ORDER_NO_CWE_OR_TARGET_SORT'}
        (runner.output/'discovery-web-surface.json').write_text(json.dumps(audit,ensure_ascii=False,indent=2)+'\n')
        runner.web_surfaces=surfaces;runner.event('discovery_web_expansion',**{k:v for k,v in audit.items() if k!='surfaces'})
        return selected,ranked,rows
    def request(action):
        original=dict(action)
        # Existing resource IDs bind an exact file, never a guessed Java method.
        rid=action.get('entity_id')
        if action.get('action')=='inspect_entity' and isinstance(rid,str) and rid.startswith('resource-'):
            matches=[p for p in archive.values() if p.get('resource_id')==rid]
            files={(p['file'],p['file_sha256']) for p in matches}
            if len(files)!=1:raise ValueError('Unknown or ambiguous resource identity.')
            file,h=next(iter(files));path=local_path(runner.tools.index.repository_root,file)
            if not path or hashlib.sha256(path.read_bytes()).hexdigest()!=h:raise ValueError('Resource identity no longer matches source.')
            lines=path.read_text().splitlines();first=action.get('start_line',1);last=action.get('end_line',min(first+119,len(lines)))
            if type(first)is not int or type(last)is not int or not 1<=first<=last<=len(lines) or last-first+1>160:raise ValueError('Invalid explicit resource range.')
            if runner.tool_calls>=runner.tool_limit:raise ValueError('Tool budget exhausted.')
            end=first-1;size=0
            for i in range(first,last+1):
                size+=len(lines[i-1].encode())+12
                if size>9000:break
                end=i
            if end<first:raise ValueError('One resource line exceeds the existing byte window.')
            runner.tool_calls+=1
            actual=runner.tools.read_file_range(file,first,end,max_lines=160)
            proof={'resource_id':rid,'file':file,'file_sha256':h,'start_line':first,'end_line':actual['end_line'],'source':source_safe(actual['text']),'content_sha256':digest(actual['lines']),
                   'unknown_ranges':([[1,first-1]] if first>1 else [])+([[end+1,len(lines)]] if end<len(lines) else [])}
            proof['evidence_id']='rsrc-'+digest([rid,first,end,proof['content_sha256']])[:24]
            if proof['evidence_id'] in archive:
                assert archive[proof['evidence_id']]==proof,'Conflicting representation of immutable resource evidence'
                proof=archive[proof['evidence_id']]
            archive[proof['evidence_id']]=proof;pending_proofs[proof['evidence_id']]=proof;proof_owners[proof['evidence_id']]=current_focus[0];result=proof
        else:
            adjustment=clip_exact_window(action,runner.ast,runner.ast_ids)
            if adjustment:action=adjustment['action'];runner.event('source_window_clipped',audit=adjustment)
            result=old_request(action)
        runner.event('targeted_tool_result',original_request=original,executed_request=action,result=result)
        for q in questions.values():
            if q['focus_id']==current_focus[0] and any(a==original for a in q['actions']):
                q['tool_returns'].append({'request':original,'result':result})
                if isinstance(result,dict) and result.get('evidence_id'):
                    pending_proofs[result['evidence_id']]=result;q['delivered_evidence_ids'].append(result['evidence_id']);q['status']='EVIDENCE_ACQUIRED_REASSESSMENT_PENDING'
        persist();return result
    def ask(role,context):
        if role=='discovery' and switches.web_surface_enhancement:context={**context,'web_surface_inventory':getattr(runner,'web_surfaces',[])}
        if role=='reasoning':
            focus=context['focus'];current_focus[0]=focus['method_id']
            if switches.critical_evidence_closure and not chain_managed:
                qs=[q for q in questions.values() if q['focus_id']==current_focus[0] and q['status'] not in {'MODEL_ANSWERED','MODEL_REFUTED'}]
                chosen={p['evidence_id']:p for p in context.get('source_evidence',[])}
                chosen.update({k:v for k,v in pending_proofs.items() if any(k in q['delivered_evidence_ids'] for q in qs)})
                context={**context,'source_evidence':list(chosen.values()),'critical_evidence_closure':{'original_hypothesis':focus['reason'],'questions':[{k:q[k] for k in ['question_id','question','status','delivered_evidence_ids']} for q in qs],'continuation_tool_results':list(pending_results)}}
            # Resource reads are shared compatibility support, not a semantic hypothesis.
            resources=[p for k,p in pending_proofs.items() if 'resource_id' in p and proof_owners.get(k)==current_focus[0]]
            if resources:context={**context,'source_evidence':list({p['evidence_id']:p for p in [*context['source_evidence'],*resources]}.values())}
            if switches.cross_cwe_reasoning:
                context={**context,'focus':{k:v for k,v in focus.items() if k!='cwe'},'cross_cwe_review':{'historical_hint':focus.get('cwe'),'supported_cwes':['CWE-22','CWE-78','CWE-79','CWE-94'],'candidate_before_hint_completion':True}}
                runner.event('cross_cwe_context',original_focus=focus,delivered_focus=context['focus'])
        answer=old_ask(role,context)
        if role=='reasoning':
            runner.event('original_reasoning_result',core_file=runtime_proof['core_explore_file'],candidate_cwes=[c.get('cwe') for c in answer.get('candidates',[]) if isinstance(c,dict)])
            if switches.critical_evidence_closure and not chain_managed:
                actions=answer.get('requests',[])[:4];priority=[]
                if actions and not answer.get('critical_questions'):
                    runner.event('critical_question_protocol_gap',raw_disposition=answer.get('disposition'),original_requests=actions,reason='No structured decision-changing question supplied; semantic question not invented.')
                declared=answer.get('critical_questions',[])
                if not isinstance(declared,list):
                    runner.event('critical_question_protocol_error',field='critical_questions',raw=declared,reason='Must be a list; valid candidates and tool requests preserved.')
                    declared=[]
                for x in declared[:2]:
                    if not isinstance(x,dict) or not isinstance(x.get('question'),str) or not x['question'].strip():continue
                    inds=x.get('request_indices',[])
                    if not isinstance(inds,list) or any(type(i)is not int or not 0<=i<len(actions) for i in inds):continue
                    qid='cq-'+digest([current_focus[0],x['question']])[:20]
                    q=questions.setdefault(qid,{'question_id':qid,'focus_id':current_focus[0],'question':x['question'],'status':'UNRESOLVED','actions':[],'tool_returns':[],'delivered_evidence_ids':[],'model_updates':[]})
                    q['actions']=[actions[i] for i in inds];priority.extend(inds)
                updates=answer.get('question_updates',[])
                if not isinstance(updates,list):
                    runner.event('critical_question_protocol_error',field='question_updates',raw=updates,reason='Must be a list; no semantic updates inferred.')
                    updates=[]
                for update in updates[:4]:
                    if not isinstance(update,dict):continue
                    q=questions.get(update.get('question_id'));refs=update.get('evidence_refs',[])
                    if not q:continue
                    valid= isinstance(refs,list) and bool(refs) and all(isinstance(i,str) and i in {p['evidence_id'] for p in context.get('source_evidence',[])} for i in refs)
                    q['model_updates'].append({'raw':update,'references_valid':valid})
                    if update.get('status') in {'ANSWERED','REFUTED'} and valid and isinstance(update.get('answer'),str) and update['answer'].strip():q['status']='MODEL_'+update['status']
                order=list(dict.fromkeys([*priority,*range(len(actions))]));answer={**answer,'requests':[actions[i] for i in order]}
                last_answer[0]=answer;persist()
        return answer
    def explore(lead):
        runner.event('original_core_explore_enter',file=runtime_proof['core_explore_file'],lead=lead,continuation=False)
        old_explore(lead)
        if not switches.critical_evidence_closure or runner.stop:return
        # Only one bounded continuation; it invokes the exact original loop.
        qs=[q for q in questions.values() if q['focus_id']==lead['method_id'] and q['status'] not in {'MODEL_ANSWERED','MODEL_REFUTED'}]
        actions=[]
        for q in qs:
            for a in q['actions']:
                if a not in actions and not any(t['request']==a and isinstance(t['result'],dict) and t['result'].get('evidence_id') for t in q['tool_returns']):actions.append(a)
        fresh=False
        for action in actions[:2]:
            if runner.tool_calls>=runner.tool_limit-3:break
            try:
                before=set(runner.evidence)|set(archive);result=request(action);pending_results.append({'request':action,'result':result})
                after=set(runner.evidence)|set(archive);fresh|=bool(after-before) or bool(result.get('hits') or result.get('candidates') or result.get('neighbors'))
            except (ValueError,KeyError,TypeError) as error:runner.event('critical_read_failed',request=action,error=str(error))
        if fresh and not runner.stop and runner.request_headroom()>1:
            runner.event('original_core_explore_enter',file=runtime_proof['core_explore_file'],lead=lead,continuation=True)
            old_explore(lead)
        for q in qs:
            if q['status'] not in {'MODEL_ANSWERED','MODEL_REFUTED'}:q['status']='UNRESOLVED_BOUNDED_FOCUS_END'
        persist()
    runner.inventory,runner.ask,runner.request=inventory,ask,request
    if switches.critical_evidence_closure and not chain_managed:runner.explore=explore
    runner.targeted_original_core=runtime_proof
    return questions
