"""Small deterministic services around R2, no new parser or detection pipeline."""
from pathlib import Path,PurePosixPath
import copy,hashlib,json,os,re
from collections import defaultdict,deque
from .a1_execution import atomic,canonical
from .benchmark import digest,source_safe
from .resource_references import local_path

class ServiceError(ValueError):pass

RETRIEVAL_SCHEMAS={'inspect_entity':({'entity_id'},{'start_line','end_line'}),'read_file_range':({'file','start_line','end_line'},set()),'search_symbols':({'query'},set()),'search_code':({'query'},set()),'follow_graph':({'entity_id'},set()),'resolve_method':({'query'},set())}

def retrieval_protocol():
    return {'version':'R2_RETRIEVAL_V1','syntax':'Use action or tool, with flat parameters or nested arguments. No additional parameters.','operations':{name:{'required':sorted(required),'optional':sorted(optional)} for name,(required,optional) in RETRIEVAL_SCHEMAS.items()},'range':'Integers, both start_line and end_line when either is given; 1..160 lines inside the actual file/method.','identities':'inspect_entity/follow_graph require an actual entity_id from supplied facts; method_id is the value, not the parameter name.','paths':'Repository-relative current source/resources only; no labels, patches, external paths or commands.'}

def append(path,row):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('a',encoding='utf-8') as f:f.write(canonical(row)+'\n');f.flush();os.fsync(f.fileno())

def normalize_retrieval_request(raw,*,requester,purpose='',hypothesis_ids=()):
    if requester not in {'explorer','investigator'} or not isinstance(raw,dict):raise ServiceError('Invalid requester or request')
    action=raw.get('action',raw.get('tool'))
    if raw.get('action') and raw.get('tool') and raw['action']!=raw['tool']:raise ServiceError('Conflicting tool/action')
    schemas=RETRIEVAL_SCHEMAS
    if action not in schemas:raise ServiceError('Unsupported retrieval operation')
    arguments=raw.get('arguments')
    if arguments is None:arguments={k:v for k,v in raw.items() if k not in {'action','tool','purpose','hypothesis_ids','requester'}}
    elif not isinstance(arguments,dict) or any(k not in {'action','tool','arguments','purpose','hypothesis_ids','requester'} for k in raw):raise ServiceError('Ambiguous retrieval arguments')
    required,optional=schemas[action]
    if not required<=set(arguments) or not set(arguments)<=required|optional:raise ServiceError('Missing or unsupported retrieval parameters')
    for key in ['query','entity_id','file']:
        if key in arguments and (not isinstance(arguments[key],str) or not arguments[key].strip()):raise ServiceError('Empty retrieval identity/query')
    if 'query' in arguments and len(arguments['query'])>160:raise ServiceError('Query exceeds original bound')
    if any(k in arguments for k in ['start_line','end_line']):
        if not all(type(arguments.get(k))is int for k in ['start_line','end_line']) or not 1<=arguments['start_line']<=arguments['end_line'] or arguments['end_line']-arguments['start_line']+1>160:raise ServiceError('Explicit range must be within original160-line bound')
    if 'file' in arguments:
        path=PurePosixPath(arguments['file'])
        if path.is_absolute() or '\\' in arguments['file'] or ':' in arguments['file'] or '..' in path.parts or any(p.lower() in {'.git','.env','ground_truth','ground-truth','labels','patches'} for p in path.parts) or path.suffix.lower() in {'.patch','.diff'}:raise ServiceError('Unsafe repository-relative path')
    ids=raw.get('hypothesis_ids',list(hypothesis_ids))
    if not isinstance(ids,(list,tuple)) or any(not isinstance(v,str) for v in ids):raise ServiceError('Invalid hypothesis identities')
    return {'action':action,'arguments':copy.deepcopy(arguments),'purpose':raw.get('purpose',purpose),'hypothesis_ids':list(dict.fromkeys(ids)),'requester':requester}

class SourceRangeTools:
    """Forward original tools unchanged except the persistent raw range cache."""
    def __init__(self,original,read_range):self.original=original;self.read_file_range=read_range
    def __getattr__(self,name):return getattr(self.original,name)

class EvidenceService:
    def __init__(self,runner,archive,book,source_id):
        self.r=runner;self.archive=archive;self.book=book;self.source_id=source_id;self.path=runner.output/'hecv/evidence.json'
        self.state=json.loads(self.path.read_bytes()) if self.path.exists() else {'source_tree_sha256':source_id,'proofs':{},'requests':{}}
        if self.state['source_tree_sha256']!=source_id:raise ServiceError('Evidence source-version mismatch')
        if 'non_read_operations' not in self.state:
            self.state['non_read_operations']=sum(v.get('result',{}).get('normalized_action',{}).get('action') in {'search_symbols','search_code','follow_graph','resolve_method'} for v in self.state['requests'].values() if v.get('result'))
        self.state.setdefault('raw_source_windows',{})
        seed=getattr(runner,'source_cache',None)
        if seed:
            if seed.get('source_tree_sha256')!=source_id:raise ServiceError('Read cache source-version mismatch')
            for key,value in seed['raw_source_windows'].items():
                if value.get('status')!='SETTLED' or value.get('result') is None or digest(value['result'])!=value.get('result_sha256'):raise ServiceError('Unverified source cache seed')
                if digest([source_id,value['arguments']])!=key:raise ServiceError('Source cache request identity mismatch')
                current=self.state['raw_source_windows'].get(key)
                if current and current.get('result_sha256')!=value['result_sha256']:raise ServiceError('Conflicting source cache results')
                self.state['raw_source_windows'].setdefault(key,copy.deepcopy(value))

        self.original_range_reader=getattr(runner,'_hecv_original_range_reader',runner.tools.read_file_range)
        runner._hecv_original_range_reader=self.original_range_reader
        original_tools=getattr(runner,'_hecv_original_tools',runner.tools)
        runner._hecv_original_tools=original_tools
        runner.tools=SourceRangeTools(original_tools,self.read_range)
        if not self.path.exists():self.save()
    def save(self):self.path.parent.mkdir(parents=True,exist_ok=True);atomic(self.path,self.state)
    def read_range(self,file,start,end,**options):
        # Cache the original bounded reader response, independently of the
        # caller's file/method evidence identity. Original r.read still checks
        # the method and constructs its own eligible proof; file proofs remain
        # ineligible and availability/delivery are not changed here.
        arguments={'file':file,'start_line':start,'end_line':end,'options':{'max_lines':250,'max_bytes':65536,**options}}
        identity=digest([self.source_id,arguments]);cache=self.state['raw_source_windows']
        if identity in cache:
            row=cache[identity]
            if row['status']!='SETTLED' or row.get('result') is None:raise ServiceError('RECOVERY_BLOCKED: original source reader result is not settled')
            if digest(row['result'])!=row['result_sha256']:raise ServiceError('RECOVERY_BLOCKED: original source reader result hash mismatch')
            append(self.path.parent/'source-reader.jsonl',{'event':'RAW_SOURCE_WINDOW_REUSED','request_id':identity,'source_tree_sha256':self.source_id,'arguments':arguments,'result_sha256':row['result_sha256'],'physical_read':False})
            return copy.deepcopy(row['result'])
        # A legacy proof is not a complete original low-level reader response.
        # Never reconstruct/upgrade it or reread the same completed window.
        if any(p['repository_relative_path']==file and p['start_line']==start and p['end_line']==end for p in self.state['proofs'].values()):
            raise ServiceError('RECOVERY_BLOCKED: legacy window has no original raw reader response')
        cache[identity]={'status':'IN_FLIGHT','arguments':arguments,'result':None};self.save()
        try:result=self.original_range_reader(file,start,end,**options)
        except Exception as error:
            cache[identity].update(status='FAILED',error_type=type(error).__name__,error=str(error));self.save();raise
        cache[identity].update(status='SETTLED',result=copy.deepcopy(result),result_sha256=digest(result));self.save()
        append(self.path.parent/'source-reader.jsonl',{'event':'RAW_SOURCE_WINDOW_READ','request_id':identity,'source_tree_sha256':self.source_id,'arguments':arguments,'result_sha256':digest(result),'physical_read':True})
        return result
    def acquire(self,proof,origin,actor):
        if not isinstance(proof,dict) or not proof.get('evidence_id') or not proof.get('source'):raise ServiceError('Not an acquired source window')
        p={**proof,'source':source_safe(proof['source'])};eid=p['evidence_id'];old=self.state['proofs'].get(eid)
        if old:
            if old['proof']!=p:raise ServiceError('Immutable evidence identity collision')
            return old
        path=local_path(self.r.tools.index.repository_root,p.get('file',''))
        if path is None:raise ServiceError('Source window outside authorized repository')
        numbered=[]
        for row in p['source'].splitlines():
            n,sep,_=row.partition(' | ')
            if not sep or not n.strip().isdigit():raise ServiceError('Malformed original source window')
            numbered.append(int(n))
        if numbered!=list(range(p['start_line'],p['end_line']+1)):raise ServiceError('Missing source lines')
        kind='JAVA_METHOD' if 'method_id' in p else 'RESOURCE' if 'resource_id' in p else 'JAVA_FILE'
        entry={'evidence_id':eid,'source_tree_sha256':self.source_id,'repository_relative_path':p['file'],'start_line':p['start_line'],'end_line':p['end_line'],'content_sha256':p['content_sha256'],'source_text_sha256':hashlib.sha256(p['source'].encode()).hexdigest(),'evidence_type':kind,'resource_identity':p.get('resource_id',p.get('file_id')),'method_identity':p.get('method_id'),'acquisition_record':copy.deepcopy(origin),'acquired_by':actor,'available_to':['explorer','investigator'],'delivered_to':{},'used_in_reasoning':[],'used_in_candidate':[],'candidate_step_eligible':bool(kind!='JAVA_FILE' and p.get('candidate_step_eligible',True)),'proof':p}
        self.state['proofs'][eid]=entry;self.save();return entry
    def existing_acquisition(self,proof):
        eid=proof['evidence_id']
        if eid in self.state['proofs']:return self.state['proofs'][eid]
        known=self.r.evidence.get(eid,self.archive.get(eid))
        if known is not None:return self.acquire(known,{'kind':'ORIGINAL_R2_READ_DICTIONARY'},'explorer')
        # Original file-level reads intentionally do not enter method/resource dictionaries.
        trace=self.r.output/'trace.jsonl'
        if trace.exists():
            for line in trace.read_bytes().splitlines():
                e=json.loads(line);p=e.get('proof',{})
                if e.get('event')=='file_source_read' and p.get('evidence_id')==eid:return self.acquire(p,{'kind':'ORIGINAL_R2_FILE_READ_EVENT','trace':str(trace),'event_sha256':digest(e)},'explorer')
        raise ServiceError('No original read receipt for delivered source')
    def deliver(self,role,context,witness):
        failures=[]
        if role not in {'explorer','investigator'}:return failures
        for proof in context.get('source_evidence',[]):
            try:
                entry=self.existing_acquisition(proof)
                if entry['proof']!={**proof,'source':source_safe(proof['source'])}:raise ServiceError('Wire/source acquisition mismatch')
                records=entry['delivered_to'].setdefault(role,[])
                if witness not in records:records.append(copy.deepcopy(witness))
            except (ServiceError,KeyError,TypeError) as error:failures.append({'evidence_id':proof.get('evidence_id'),'error':str(error)})
        for result in context.get('retrieval_results',[]):
            if not isinstance(result,dict) or not result.get('request_id'):continue
            entry=self.state['requests'].get(result['request_id'])
            if not entry or entry.get('result') is None or digest(entry['result'].get('original_result'))!=digest(result.get('original_result')):
                failures.append({'request_id':result['request_id'],'error':'No matching settled original tool result'});continue
            delivery=entry.setdefault('delivered_to',{}).setdefault(role,[])
            if witness not in delivery:delivery.append(copy.deepcopy(witness))
        self.save();return failures
    def visible(self,role):return {k:v['proof'] for k,v in self.state['proofs'].items() if role in v['delivered_to']}
    def use(self,role,ids,kind,origin):
        if kind not in {'used_in_reasoning','used_in_candidate'}:raise ServiceError('Unknown evidence usage')
        for eid in ids:
            p=self.state['proofs'].get(eid)
            if p is None or role not in p['delivered_to']:raise ServiceError('Evidence not delivered to submitting Agent')
        for eid in ids:
            row={'role':role,'origin':copy.deepcopy(origin)}
            if row not in self.state['proofs'][eid][kind]:self.state['proofs'][eid][kind].append(row)
        self.save()
    def execute(self,raw,*,actor='investigator',purpose='',hypotheses=(),execute=None):
        normalized=normalize_retrieval_request(raw,requester=actor,purpose=purpose,hypothesis_ids=hypotheses)
        a=normalized['arguments'];action=normalized['action']
        signature=digest([self.source_id,action,a]);requests=self.state['requests']
        if signature in requests:
            row=requests[signature];row['dependencies']=list(dict.fromkeys([*row['dependencies'],*normalized['hypothesis_ids']]));self.save()
            if row.get('result') is not None:
                cached=copy.deepcopy(row['result']);cached.update(requester=actor,normalized_action=normalized,reused=True);return cached
            # An interrupted action without a provable return is never guessed
            # completed or silently reissued, even when it was only a search.
            raise ServiceError('RECOVERY_BLOCKED: original tool return not durably settled')
        old={'action':action,**a};result=None;error=None;refusal=None
        # A well-formed but unsatisfied source request is material feedback,
        # not an exception in the reasoning protocol. Cache lookup precedes
        # validation so a completed refusal is not re-executed on restoration.
        if 'file' in a:
            p=local_path(self.r.tools.index.repository_root,a['file'])
            if p is None or not p.is_file():refusal={'status':'not_found','read_succeeded':False,'validation_refusal':True,'error':'Requested repository file is missing or outside the authorized root','requested':old,'actual_read_performed':False}
        known_entities=set(self.r.methods)|set(getattr(self.r.retrieval,'entities',{}))
        if action in {'inspect_entity','follow_graph'} and a['entity_id'] not in known_entities and not any(v['proof'].get('resource_id')==a['entity_id'] for v in self.state['proofs'].values()) and not any(p.get('resource_id')==a['entity_id'] for p in self.archive.values()):
            refusal={'status':'invalid_identity','read_succeeded':False,'validation_refusal':True,'error':'Unknown exact source identity; select an identity from actual navigation results','requested':old,'actual_read_performed':False}
        # Automatic R2 resource acquisition and explicit requests may name the
        # same exact window. Reuse its proven original result without a new read.
        reusable=None
        if action=='inspect_entity' and a['entity_id'] in self.r.methods:
            method=self.r.methods[a['entity_id']];first=a.get('start_line',method.start_line);last=a.get('end_line',min(method.end_line,first+159))
            reusable=next((v for v in self.state['proofs'].values() if v['evidence_type']=='JAVA_METHOD' and v['method_identity']==a['entity_id'] and v['start_line']==first and v['end_line']==last),None)
        if action=='read_file_range':
            reusable=next((v for v in self.state['proofs'].values() if v['evidence_type'] in {'RESOURCE','JAVA_FILE'} and v['repository_relative_path']==a['file'] and v['start_line']==a['start_line'] and v['end_line']==a['end_line']),None)
            if refusal is None and reusable is None:
                bounds=[]
                for key,row in self.state['raw_source_windows'].items():
                    raw_result=row.get('result')
                    if row['status']!='SETTLED' or not isinstance(raw_result,dict) or raw_result.get('repository_relative_path')!=a['file']:continue
                    if digest(raw_result)!=row['result_sha256']:raise ServiceError('RECOVERY_BLOCKED: original source reader result hash mismatch')
                    bounds.append({'raw_reader_request_id':key,'result_sha256':row['result_sha256'],'total_file_lines':raw_result['total_file_lines']})
                counts={b['total_file_lines'] for b in bounds}
                if len(counts)>1:raise ServiceError('RECOVERY_BLOCKED: conflicting original source file bounds')
                if counts and a['end_line']>next(iter(counts)):
                    refusal={'status':'invalid_window','read_succeeded':False,'validation_refusal':True,'error':'Requested end_line exceeds the proven file length; select a valid explicit window','requested':old,'file_lines':next(iter(counts)),'bounds_provenance':bounds,'available_evidence':[{'evidence_id':eid,'file':v['repository_relative_path'],'start_line':v['start_line'],'end_line':v['end_line'],'delivery_status':'AVAILABLE_NOT_DELIVERED_BY_THIS_REFUSAL'} for eid,v in self.state['proofs'].items() if v['repository_relative_path']==a['file']],'actual_read_performed':False}
                # Without an original bounds receipt, the unchanged safe R2
                # tool validates the range and supplies its actual refusal.
                # Do not read the file again here or guess/truncate the range.
        requests[signature]={'dependencies':normalized['hypothesis_ids'],'result':None,'status':'IN_FLIGHT','normalized_action':normalized};self.save()
        if not refusal and not reusable and getattr(self.r,'tool_calls',0)+self.state['non_read_operations']>=getattr(self.r,'physical_tool_limit',getattr(self.r,'tool_limit',1024)):
            requests.pop(signature);self.save();raise ServiceError('Physical tool-operation safety limit')
        if not refusal and action in {'search_symbols','search_code','follow_graph','resolve_method'}:
            self.state['non_read_operations']+=1;self.save()
        try:
            if refusal:result=refusal;error=refusal['error']
            else:result=copy.deepcopy(reusable['proof']) if reusable else (execute or self.r.request)(old)
        except (ValueError,KeyError,TypeError,OSError) as exc:error=str(exc)
        success=isinstance(result,dict) and bool(result.get('source')) and bool(result.get('evidence_id'))
        if success:self.acquire(result,{'kind':'NORMALIZED_R2_TOOL','request_id':signature,'original_action':old},actor)
        elif action in {'inspect_entity','read_file_range'}:error=error or (result.get('error','Original reader returned no source') if isinstance(result,dict) else 'Original reader returned no source')
        actual_end=result.get('end_line') if isinstance(result,dict) else None
        truncated=bool(success and a.get('end_line') is not None and actual_end<a['end_line'])
        out={'request_id':signature,'requester':actor,'normalized_action':normalized,'source_tree_sha256':self.source_id,'file':result.get('file') if isinstance(result,dict) else a.get('file'),'start_line':result.get('start_line') if isinstance(result,dict) else a.get('start_line'),'end_line':actual_end,'evidence_id':result.get('evidence_id') if isinstance(result,dict) else None,'content_sha256':result.get('content_sha256') if isinstance(result,dict) else None,'actual_source_content':result.get('source') if success else None,'complete':bool(success and not truncated) if action in {'inspect_entity','read_file_range'} else error is None,'truncated':truncated,'error':error,'candidate_step_eligible':bool(success and self.state['proofs'][result['evidence_id']]['candidate_step_eligible']),'original_result':result}
        refused=bool(refusal or isinstance(result,dict) and result.get('status') in {'invalid_window','invalid_identity','not_found','invalid_request'})
        if refused:out.update(validation_refusal=True,actual_read_performed=False)
        if reusable:out.update(reused=True,reuse_origin='PROVEN_ORIGINAL_ACQUIRED_WINDOW',original_acquisition_record=reusable['acquisition_record'])
        requests[signature]={'dependencies':normalized['hypothesis_ids'],'result':out,'status':'SETTLED','outcome':'REFUSED' if refused else 'RETURNED'};self.state['tool_calls']=getattr(self.r,'tool_calls',0);self.save()
        if refused and self.book is not None:self.book.event('retrieval_refusal_saved',request_id=signature,requester=actor,normalized_action=normalized,result_sha256=digest(out),original_status=result.get('status'),actual_source_read=False)
        return copy.deepcopy(out)

class ScopeScheduler:
    def __init__(self,r,source_id,max_scopes,mechanism_plans=None):
        self.r=r;self.source_id=source_id;self.max_scopes=max_scopes;self.plans=mechanism_plans if mechanism_plans is not None else {}
    def scopes(self):
        if not getattr(self.r,'full_rows',None):self.r.inventory()
        self.r.activate_reads();result={}
        covered=set()
        for plan in self.plans.values():
            mid=plan['method_ids'][0];covered.update(plan['method_ids']);key=digest([self.source_id,plan['kind'],plan['source_boundaries']])
            result[key]={'scope_id':'scope-'+key[:24],'source_channel':'R2_MECHANISM_CATALOGUE','source_tree_sha256':self.source_id,'scope_kind':plan['kind'],'entry_evidence':[dict(b,evidence_level='INDEXED_NOT_READ') for b in plan['source_boundaries']],'method_id':mid,'related_facts':{'indexed_calls':plan['navigation_facts'],'original_boundary_scores':{},'CodeQL_alert':False,'evidence_level':'STATIC_NAVIGATION_NOT_VALUE_PROPAGATION'},'question_seed':' '.join(plan['questions']),'priority_basis':'Existing deterministic R2 source-boundary catalog; no Explorer model lead or historical candidate','unknowns':['Read source to establish processing, guards and actual consumers.'],'status':'QUEUED'}
        for row in self.r.full_rows:
            mid=row['method_id'];scores=row.get('scores',{});calls=row.get('calls',[])
            if mid in covered:continue
            kinds=[c for c,v in scores.items() if v>0]
            if not kinds and not row.get('codeql_alert'):continue
            key=digest([self.source_id,mid,'SECURITY_BOUNDARY'])
            kind=max(sorted(scores),key=lambda c:scores[c]) if kinds else 'CODEQL_BOUNDARY'
            result.setdefault(key,{'scope_id':'scope-'+key[:24],'source_tree_sha256':self.source_id,'scope_kind':kind,'entry_evidence':[],'method_id':mid,'related_facts':{'indexed_calls':calls,'original_boundary_scores':scores,'CodeQL_alert':row.get('codeql_alert',False),'evidence_level':'STATIC_NAVIGATION_NOT_VALUE_PROPAGATION'},'question_seed':'Which concrete input, processing boundary, guard and final use merit an independent source-grounded security hypothesis?','priority_basis':'Original deterministic security-boundary scores and source-located facts; no model discovery/labels','unknowns':['Actual input trust, propagation and consumer must be checked in source.'],'status':'QUEUED'})
        groups=defaultdict(deque)
        for scope in sorted(result.values(),key=lambda x:(-sum(x['related_facts']['original_boundary_scores'].values()),self.r.methods[x['method_id']].repository_relative_path,self.r.methods[x['method_id']].start_line,x['scope_id'])):groups[scope['scope_kind']].append(scope)
        # A complete catalogue is not a model task queue. Admission happens
        # lazily in PeerController; max_scopes is now an active-root window.
        return [dict(scope,source_channel=scope.get('source_channel','STATIC_BOUNDARY_FALLBACK')) for kind in sorted(groups) for scope in groups[kind]]

    @staticmethod
    def select(catalogue,rotation,selected):
        channels=['R2_MECHANISM_CATALOGUE','STATIC_BOUNDARY_FALLBACK']
        for offset in range(len(channels)):
            ci=(rotation.get('channel_cursor',0)+offset)%len(channels);channel=channels[ci]
            kinds=sorted({s['scope_kind'] for s in catalogue if s['source_channel']==channel})
            if not kinds:continue
            cursors=rotation.setdefault('kind_cursors',{});cursor=cursors.get(channel,0)
            for delta in range(len(kinds)):
                ki=(cursor+delta)%len(kinds);kind=kinds[ki]
                scope=next((s for s in catalogue if s['source_channel']==channel and s['scope_kind']==kind and s['scope_id'] not in selected),None)
                if scope:
                    rotation['channel_cursor']=(ci+1)%len(channels);cursors[channel]=(ki+1)%len(kinds)
                    return scope
        return None

class ResponseStore:
    def __init__(self,root,source_id):self.root=Path(root)/'response-store';self.root.mkdir(exist_ok=True);self.source_id=source_id
    def key(self,body):return digest([self.source_id,body])
    def event(self,key,state,**v):append(self.root/'events.jsonl',{'response_id':key,'state':state,**v})
    def get(self,body):
        p=self.root/(self.key(body)+'.json')
        if not p.exists():return None
        v=json.loads(p.read_bytes())
        if v['source_tree_sha256']!=self.source_id or v['body']!=body:raise ServiceError('Response identity mismatch')
        if digest([v['body'],v['content'],v['usage'],v['metadata']])!=v['response_sha256']:raise ServiceError('Persisted response changed')
        # Canonical snapshots sort dictionary keys; the HTTP message string is
        # the authoritative order-preserving input for exact request replay.
        from context_serialization import unpack
        context=unpack(json.loads(v['body']['messages'][1]['content']))
        if digest(context)!=digest(v['context']):raise ServiceError('Persisted semantic input mismatch')
        v['context']=context
        return v
    def put(self,body,context,turn,witness):
        key=self.key(body);value={'source_tree_sha256':self.source_id,'body':copy.deepcopy(body),'context':copy.deepcopy(context),'content':turn.content,'usage':dict(turn.usage),'metadata':dict(turn.metadata),'witness':copy.deepcopy(witness),'response_sha256':digest([body,turn.content,dict(turn.usage),dict(turn.metadata)])}
        old=self.get(body)
        if old and digest(old)!=digest(value):raise ServiceError('Immutable response collision')
        atomic(self.root/(key+'.json'),value);self.event(key,'RESPONSE_PERSISTED');return key
    def audit(self):
        result=[]
        events=[json.loads(x) for x in (self.root/'events.jsonl').read_bytes().splitlines()] if (self.root/'events.jsonl').exists() else []
        for p in sorted(self.root.glob('*.json')):
            v=json.loads(p.read_bytes());self.get(v['body']);states=[e for e in events if e['response_id']==p.stem]
            result.append({'response_id':p.stem,'states':states,'coordination_recovery_needed':not any(e['state']=='COORDINATED' for e in states),'response_return_recorded':any(e['state']=='RESPONSE_RETURNED' for e in states)})
        return result
