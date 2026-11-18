from __future__ import annotations
import hashlib,re,zipfile
from pathlib import Path

def doc_before(lines,first):
    prefix='\n'.join(lines[:first-1]);a=prefix.rfind('/**');b=prefix.rfind('*/')
    if a<0 or b<a:return None
    tail=prefix[b+2:]
    if any(s.strip() and not s.strip().startswith('@') for s in tail.splitlines()):return None
    return prefix[:a].count('\n')+1,prefix[:b+2].count('\n')+1


def install(runner,dependency_catalog=()):
    old_ask=runner.ask
    root=runner.tools.index.repository_root
    def documentation(proofs):
        result=[];seen=set();used=0
        def add(file,lines,a,b,artifact,origin):
            nonlocal used
            key=(file,a,b,artifact)
            if key in seen:return
            text='\n'.join(f'{i} | {lines[i-1]}' for i in range(a,b+1))
            if len(result)>=12 or used+len(text.encode())>16000:return
            seen.add(key);used+=len(text.encode())
            result.append({'file':file,'start_line':a,'end_line':b,'source':text,'artifact_sha256':artifact,'origin':origin,'candidate_step_eligible':False})
        for proof in proofs:
            m=runner.methods.get(proof.get('method_id'))
            if m is None:continue
            path=root/m.repository_relative_path;lines=path.read_text(encoding='utf-8').splitlines();bounds=doc_before(lines,m.start_line)
            if bounds:add(m.repository_relative_path,lines,*bounds,hashlib.sha256(path.read_bytes()).hexdigest(),'CURRENT_METHOD_JAVADOC')
            # Exact same method signature on declared interface types; no same-name joins.
            header='\n'.join(lines[:m.start_line]);match=re.search(r'\bclass\s+\w+[^\{]*?\bimplements\s+([^\{]+)\{',header)
            names=set(re.findall(r'\b[\w.]+\b',match[1])) if match else set()
            imports=dict((x.rsplit('.',1)[-1],x) for x in re.findall(r'\bimport\s+([\w.]+)\s*;',header))
            package=re.search(r'\bpackage\s+([\w.]+)\s*;',header)
            for name in names:
                qualified=imports.get(name,name if '.' in name else ((package[1]+'.') if package else '')+name)
                matches=[x for x in runner.ast.methods.values() if x.qualified_name==qualified+'.'+m.simple_name and x.signature==m.signature]
                if len(matches)!=1:continue
                decl=matches[0];p=root/decl.repository_relative_path;ls=p.read_text(encoding='utf-8').splitlines();bound=doc_before(ls,decl.start_line)
                if bound:add(decl.repository_relative_path,ls,bound[0],decl.end_line,hashlib.sha256(p.read_bytes()).hexdigest(),'EXACT_IMPLEMENTED_INTERFACE_SIGNATURE')
            for entry in dependency_catalog:
                # Catalog is already source/POM/version/hash checked during preflight.
                cls=entry['class'];simple=cls.rsplit('.',1)[-1]
                if imports.get(simple)!=cls:continue
                calls=set(re.findall(r'\b'+re.escape(simple)+r'\.([A-Za-z_$][\w$]*)\s*\(',proof['source']))
                if not calls:continue
                if hashlib.sha256(Path(entry['sources_jar']).read_bytes()).hexdigest()!=entry['sources_sha256']:
                    raise RuntimeError('Frozen dependency documentation changed.')
                ast_calls=runner.ast.calls.get(runner.ast_ids.get(m.entity_id,m.entity_id),[])
                with zipfile.ZipFile(entry['sources_jar']) as z:
                    ls=z.read(cls.replace('.','/')+'.java').decode('utf-8').splitlines()
                for call in sorted(calls):
                    arities={len(x['arguments']) for x in ast_calls if x['name'].split('.')[-1]==call and proof['start_line']<=x['line']<=proof['end_line']}
                    if len(arities)!=1:continue
                    arity=next(iter(arities));declarations=[]
                    for i,l in enumerate(ls,1):
                        match=re.search(r'\b(?:public|protected)\s+static\s+[\w<>\[\]]+\s+'+re.escape(call)+r'\s*\(([^)]*)\)',l)
                        if match and (len(match[1].split(',')) if match[1].strip() else 0)==arity:declarations.append(i)
                    if len(declarations)!=1:continue
                    bound=doc_before(ls,declarations[0])
                    if bound:add('dependency/'+entry['coordinate']+'/'+cls.replace('.','/')+'.java',ls,bound[0],declarations[0],entry['sources_sha256'],'VERSION_MATCHED_LOCAL_DEPENDENCY_JAVADOC')
        return result

    def ask(role,context):
        if role=="reasoning":
            docs=documentation(context.get("source_evidence",[]))
            runner.event("contract_evidence",focus=context["focus"],documents=docs)
            context={**context,"contract_evidence":docs}
        return old_ask(role,context)
    runner.ask=ask
