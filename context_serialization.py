"""Reversible exact metadata references and explicitly estimated token attribution."""
import collections,hashlib,json
from java_vuln_research.work1_agent.experiment_policy import _token_encoding

def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'))
def sha(value):return hashlib.sha256(canonical(value).encode()).hexdigest()
PROTECTED={'conditions','uncertainties'}
KINDS=['inventory','relations_navigation','source','codeql','historical_observations','contract_material','other_and_framing']
def category(path):
    keys=[str(k).lower() for k in path]
    if any('contract' in k or 'documentation' in k for k in keys):return 'contract_material'
    if any(k in {'source_evidence','source','source_window'} for k in keys):return 'source'
    if any(k in {'recent_observations','existing_candidates','feedback','critical_evidence_closure'} for k in keys):return 'historical_observations'
    if any('codeql' in k or 'native_alert' in k or 'native_finding' in k for k in keys):return 'codeql'
    if any(k in {'web_surface_inventory','class_views','related_methods','resource_references','retrieval_results','guidance','callers','callees','navigation_facts','source_boundaries','caller_edges','investigation_tool_results'} for k in keys):return 'relations_navigation'
    if 'inventory' in keys:return 'inventory'
    return 'other_and_framing'

def pack(context):
    if '_shared_metadata' in context or '_metadata_serialization' in context:raise ValueError('Reserved serialization key conflict')
    counts=collections.Counter();objects={}
    def scan(v,path=()):
        if any(k in PROTECTED for k in path):return
        if isinstance(v,dict):
            raw=canonical(v)
            if path and len(raw.encode())>=256:
                counts[raw]+=1;objects[raw]=v
            for k,x in v.items():scan(x,(*path,k))
        elif isinstance(v,list):
            for i,x in enumerate(v):scan(x,(*path,i))
    scan(context);selected={raw for raw,n in counts.items() if n>1};table={};owners={};replaced=[0]
    def encode(v,path=(),root=False):
        if any(k in PROTECTED for k in path):return v
        if isinstance(v,dict):
            raw=canonical(v)
            if not root and raw in selected:
                identity='metadata-'+hashlib.sha256(raw.encode()).hexdigest()[:24]
                if identity not in table:
                    table[identity]=None;owners[identity]=category(path)
                    table[identity]={k:encode(x,(*path,k)) for k,x in v.items()}
                replaced[0]+=1
                return {'$metadata_ref':identity}
            return {k:encode(x,(*path,k)) for k,x in v.items()}
        if isinstance(v,list):return [encode(x,(*path,i)) for i,x in enumerate(v)]
        return v
    encoded=encode(context,root=True)
    if table:
        encoded={**encoded,'_shared_metadata':table,'_metadata_serialization':{'version':'exact-metadata-references-v1','reference_key':'$metadata_ref','table_key':'_shared_metadata','ordering':'Original arrays retain every ordered occurrence; references resolve to exact complete objects.'}}
    if len(canonical(encoded).encode())>=len(canonical(context).encode()):encoded=context;table={};owners={};replaced[0]=0
    assert canonical(unpack(encoded))==canonical(context),'Lossless semantic roundtrip failed'
    return encoded,{'semantic_sha256':sha(context),'roundtrip_sha256':sha(unpack(encoded)),'all_ordered_occurrences_preserved':True,'unique_records_preserved':True,
                    'shared_records':len(table),'references':replaced[0],'table_category_owners':owners,
                    'original_utf8_bytes':len(canonical(context).encode()),'serialized_utf8_bytes':len(canonical(encoded).encode()),
                    'removed_duplicate_utf8_bytes':len(canonical(context).encode())-len(canonical(encoded).encode()),
                    'protected_fields':sorted(PROTECTED),'minimum_factored_record_bytes':256}

def unpack(context):
    table=context.get('_shared_metadata',{})
    def decode(v,visiting=()):
        if isinstance(v,dict):
            if set(v)=={'$metadata_ref'}:
                identity=v['$metadata_ref']
                if identity in visiting or identity not in table:raise ValueError('Invalid/cyclic metadata reference')
                value=decode(table[identity],(*visiting,identity))
                if identity!='metadata-'+sha(value)[:24]:raise ValueError('Metadata identity/content mismatch')
                return value
            return {k:decode(x,visiting) for k,x in v.items()}
        if isinstance(v,list):return [decode(x,visiting) for x in v]
        return v
    return decode({k:v for k,v in context.items() if k not in {'_shared_metadata','_metadata_serialization'}})

def token_count(value):
    text=value if isinstance(value,str) else canonical(value);encoding=_token_encoding()
    return len(encoding.encode(text,disallowed_special=())) if encoding is not None else len(text.encode())

def component_estimates(context,owners=None):
    parts={k:[] for k in KINDS};owners=owners or {}
    def walk(v,path=(),forced=None):
        if isinstance(v,dict):
            for k,x in v.items():
                if k=='_shared_metadata':
                    for identity,record in x.items():walk(record,(*path,k,identity),owners.get(identity,'other_and_framing'))
                else:walk(x,(*path,k),forced)
        elif isinstance(v,list):
            for i,x in enumerate(v):walk(x,(*path,i),forced)
        else:parts[forced or category(path)].append({'path':list(path),'value':v})
    walk(context)
    return {'basis':'ESTIMATE_ONLY_o200k_base' if _token_encoding() is not None else 'ESTIMATE_ONLY_utf8_byte_upper_bound',
            'provider_per_component_usage_available':False,'components':{k:token_count(values) if values else 0 for k,values in parts.items()},
            'method':'Disjoint semantic leaf/path buckets, separately tokenized; diagnostic estimates include attribution-path framing and must not be summed with provider usage.',
            'whole_context_estimated_tokens':token_count(context)}
