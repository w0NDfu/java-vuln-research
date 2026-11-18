"""Intersect only an explicitly identified callable's requested source window."""


def clip_exact_window(request, symbols, aliases):
    if (request.get('action') != 'inspect_entity'
            or set(request) != {'action', 'entity_id', 'start_line', 'end_line'}):
        return None
    identity = request.get('entity_id')
    if not isinstance(identity, str):
        return None
    method = symbols.methods.get(aliases.get(identity, identity))
    first, last = request['start_line'], request['end_line']
    if method is None or type(first) is not int or type(last) is not int or first > last:
        return None
    # R2 rejects mismatched windows at the production request entrance.
    # Silently intersecting an ID with a different question loses context.
    return None


def validate_method_read(request,runner):
    """Return a structured refusal or None; never choose an alternative ID."""
    if not isinstance(request,dict):return {'status':'invalid_request','error':'Read action must be an object','candidates':[],'read_succeeded':False}
    if request.get('action')!='inspect_entity':return None
    identity=request.get('entity_id')
    if not isinstance(identity,str):return {'status':'invalid_identity','error':'entity_id must be an exact supplied string','candidates':[],'read_succeeded':False}
    if identity.startswith('resource-'):return None
    method=runner.methods.get(identity) or runner.ast.methods.get(identity)
    def describe(m):
        return {'method_id':m.entity_id,'file':m.repository_relative_path,'start_line':m.start_line,'end_line':m.end_line,'name':m.qualified_name,'signature':m.signature}
    if method is None:
        entity=runner.ast.types.get(identity) or runner.retrieval.entities.get(identity)
        if entity is not None:
            file=entity.repository_relative_path
            return {'status':'non_method_identity','error':'Selected identity is not a method. Choose a declaration or use file-level reading explicitly.',
                    'identity_kind':entity.kind.value,'file':file,'candidates':[describe(m) for m in runner.ast.by_file.get(file,[])],
                    'file_range_option':{'action':'read_file_range','file':file,'start_line':entity.start_line,'end_line':min(entity.end_line,entity.start_line+159)},'automatic_selection':False,'read_succeeded':False}
        candidates=[]
        for row in getattr(runner,'full_rows',[]) or []:
            if row['method_id'] in runner.methods:
                m=runner.methods[row['method_id']]
                if request.get('file')==m.repository_relative_path:candidates.append(describe(m))
        return {'status':'not_found','error':'Unknown method ID; its file cannot be inferred from line numbers. Select an exact supplied method_id/file.',
                'candidates':candidates,'requested':request,'read_succeeded':False,'automatic_selection':False}
    decl=runner.ast.methods.get(runner.ast_ids.get(identity,identity))
    if decl is None:
        exact=[m for m in runner.ast.by_file.get(method.repository_relative_path,[]) if m.start_line==method.start_line and m.end_line==method.end_line]
        decl=exact[0] if len(exact)==1 else None
    first=request.get('start_line',method.start_line)
    last=request.get('end_line',min(method.end_line,first+159)) if type(first)is int else None
    candidates=[m for m in runner.ast.by_file.get(method.repository_relative_path,[]) if type(first)is int and type(last)is int and m.start_line<=last and first<=m.end_line]
    valid=(decl is not None and type(first)is int and type(last)is int and decl.start_line<=first<=last<=decl.end_line and last-first+1<=160
           and request.get('file',method.repository_relative_path)==method.repository_relative_path)
    if valid:return None
    return {'status':'invalid_window','error':'Range must belong to the selected declaration and contain at most160 lines. Cross-method context needs separate exact method IDs or a file read.',
            'requested':request,'selected_method':describe(method),'confirmed_declaration':describe(decl) if decl else None,
            'candidates':[describe(m) for m in candidates],
            'file_range_option':{'action':'read_file_range','file':method.repository_relative_path,'start_line':first,'end_line':last},
            'automatic_selection':False,'read_succeeded':False}
