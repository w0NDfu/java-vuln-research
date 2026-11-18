"""Read-only historical identity catalog and separate logical reuse receipts."""
from pathlib import Path
from collections import defaultdict,Counter,deque
import hashlib,json,os,sqlite3,time,tarfile
from .harness import ModelTurn,PolicyError
from .experiment_policy import RequestJournal,request_reserve,BudgetExceeded

ENDPOINT='https://api.openlux.ai/v1/chat/completions'
def canon(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)
def hashed(v):return hashlib.sha256(canon(v).encode()).hexdigest()
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def schema(body):
    return {'tools':body.get('tools',[]),'tool_choice':body.get('tool_choice'),
            'response_format':body.get('response_format'),
            'published_system':[m for m in body.get('messages',[]) if m.get('role') in {'system','developer'}]}
def legacy_key(context,policy):
    return hashlib.sha256(json.dumps({'context':context,'system':policy.system_prompt,'model':policy.model,
        'endpoint':policy.endpoint,'output_limit':policy.max_output_tokens},ensure_ascii=False,sort_keys=True).encode()).hexdigest()
def body_key(body,endpoint=ENDPOINT):
    systems=[m['content'] for m in body.get('messages',[]) if m.get('role')=='system']
    users=[m['content'] for m in body.get('messages',[]) if m.get('role')=='user']
    if len(systems)!=1 or len(users)!=1:raise ValueError('Unsupported archived message structure')
    context=json.loads(users[0]);limit=body.get('max_completion_tokens',body.get('max_tokens'))
    if '_shared_metadata' in context:
        from context_serialization import unpack
        context=unpack(context)
    return hashlib.sha256(json.dumps({'context':context,'system':systems[0],'model':body['model'],
        'endpoint':endpoint,'output_limit':limit},ensure_ascii=False,sort_keys=True).encode()).hexdigest()

class HistoryIndex:
    def __init__(self,path,read_only=False):
        self.path=Path(path);self.db=sqlite3.connect('file:'+self.path.as_posix()+'?mode=ro',uri=True) if read_only else sqlite3.connect(self.path)
        if not read_only:
            self.db.execute('CREATE TABLE IF NOT EXISTS records (key TEXT, body_hash TEXT, schema_hash TEXT, source_id TEXT, created REAL, payload TEXT)')
            self.db.execute('CREATE INDEX IF NOT EXISTS request_identity ON records(key,body_hash,schema_hash,source_id)')
            self.db.execute('CREATE TABLE IF NOT EXISTS unknown (key TEXT, reason TEXT, origin TEXT)')
    def source_identity(self,path,lab):
        case=next((p.name for p in [path.parent,*path.parents] if p.name.startswith(('sample_','pool_','case_'))),None)
        for parent in [path.parent,*path.parents]:
            if not parent.is_relative_to(lab):break
            for name in ('inputs.json','codeql-evidence-manifest.json'):
                f=parent/name
                if not f.exists():continue
                try:
                    value=json.loads(f.read_bytes());projects=value.get('projects',{})
                    if case in projects and projects[case].get('source_tree_sha256'):return projects[case]['source_tree_sha256']
                except (ValueError,AttributeError):pass
        return None
    def build(self,lab,output,exclude=()):
        lab=Path(lab).resolve();output=Path(output);output.mkdir(parents=True,exist_ok=True)
        exclude=[Path(p).resolve() for p in exclude];files=[];archives=[];pruned=[]
        for directory,dirs,names in os.walk(lab):
            root=Path(directory)
            kept=[]
            for name in dirs:
                p=root/name
                if name in {'.git','.venv','node_modules','db-java','toolchains','m2-cache'} or any(p.resolve().is_relative_to(x) for x in exclude):pruned.append(str(p))
                else:kept.append(name)
            dirs[:]=kept
            for name in names:
                p=root/name
                if name.endswith('.jsonl') and any(s in name.lower() for s in ('request','journal','ledger')):files.append(p)
                elif name.endswith('.request.json') or ('/messages/' in p.as_posix() and name.endswith('.json')):files.append(p)
                elif name.endswith('.sha256') or 'SHA256SUMS' in name:files.append(p)
                elif name.endswith(('.tar','.tar.gz','.tgz')):archives.append(p)
        manifests=[p for p in files if p.name.endswith('.sha256') or 'SHA256SUMS' in p.name]
        sealed=defaultdict(list)
        for p in manifests:
            try:lines=p.read_text(encoding='utf-8').splitlines()
            except (OSError,UnicodeError):continue
            manifest_hash=sha(p)
            for line in lines:
                if '  ' not in line:continue
                h,name=line.split('  ',1)
                if len(h)!=64 or any(c not in '0123456789abcdef' for c in h):continue
                f=(p.parent/name).resolve()
                if f.is_relative_to(lab):sealed[str(f)].append({'expected_sha256':h,'manifest':str(p),'manifest_sha256':manifest_hash})
        hash_cache={}
        def seal(p):
            name=str(p.resolve())
            if name not in hash_cache:hash_cache[name]=sha(p)
            return next((v for v in sealed.get(name,[]) if v['expected_sha256']==hash_cache[name]),None)
        bodies=defaultdict(list);body_stats=Counter()
        for p in files:
            if not (p.name.endswith('.request.json') or '/messages/' in p.as_posix()):continue
            try:
                body=json.loads(p.read_bytes())
                if not isinstance(body,dict) or 'messages' not in body or 'model' not in body:continue
                key=body_key(body);proof=seal(p);sid=self.source_identity(p,lab)
                if proof and sid:bodies[key].append({'body':body,'body_hash':hashed(body),'schema_hash':hashed(schema(body)),'file':str(p),'sha256':sha(p),'seal':proof,'source_id':sid})
                else:body_stats['UNSEALED_OR_SOURCE_BINDING_UNKNOWN']+=1
            except (ValueError,TypeError,KeyError,OSError,UnicodeError):body_stats['UNSUPPORTED_BODY_FORMAT']+=1
        counts=Counter();inventory=[];direct_hashes={}
        self.db.execute('DELETE FROM records');self.db.execute('DELETE FROM unknown')
        for p in files:
            if not p.name.endswith('.jsonl'):continue
            item={'ledger':str(p),'sha256':sha(p),'classification':None,'rows':0,'responses':0};direct_hashes[item['sha256']]=str(p)
            test=any(s in p.as_posix().lower() for s in ['/regression','/pytest','/test-','/test_','/offline','/contract-replay'])
            try:rr=[json.loads(l) for l in p.read_bytes().splitlines() if l.strip()]
            except (ValueError,OSError):item['classification']='INVALID_JSONL';inventory.append(item);counts['INVALID_JSONL']+=1;continue
            item['rows']=len(rr);starts=defaultdict(deque);proof=seal(p);source=self.source_identity(p,lab)
            for line,row in enumerate(rr,1):
                if not isinstance(row,dict):continue
                if row.get('event')=='request_started':starts[row.get('request_key')].append((line,row));continue
                if row.get('event')!='response' or not row.get('request_key'):continue
                item['responses']+=1;physical_key=row['request_key'];key=row.get('legacy_request_key',physical_key);reason=None
                start=starts[physical_key].popleft() if starts[physical_key] else None
                source=row.get('source_identity') or source
                if test or row.get('metadata',{}).get('test_only'):reason='TEST_ONLY_NOT_A_PHYSICAL_HISTORY_SOURCE'
                elif not proof:reason='LEDGER_NOT_VERIFIABLY_SEALED'
                elif start is None:reason='ORIGINAL_PHYSICAL_START_NOT_RECONSTRUCTABLE'
                elif not isinstance(row.get('content'),str) or type(row.get('usage',{}).get('total_tokens'))is not int:reason='UNSETTLED_OR_MISSING_SUCCESS_CONTENT'
                elif row.get('metadata',{}).get('http_status',200)!=200:reason='NON_SUCCESS_HTTP_STATUS'
                options=[v for v in bodies.get(key,[]) if v['source_id']==source and source]
                if options:
                    # Prefer bodies inside the same run/case directory. A
                    # different full body with the legacy key remains ambiguous.
                    local=[v for v in options if Path(v['file']).is_relative_to(p.parent)]
                    if local:options=local
                if not reason and not options:reason='FULL_BODY_OR_SOURCE_ID_NOT_RECONSTRUCTABLE'
                if not reason and len({v['body_hash'] for v in options})!=1:reason='AMBIGUOUS_FULL_BODY_FOR_LEGACY_KEY'
                if reason:
                    if reason!='TEST_ONLY_NOT_A_PHYSICAL_HISTORY_SOURCE':self.db.execute('INSERT INTO unknown VALUES(?,?,?)',(key,reason,str(p)+':'+str(line)))
                    counts[reason]+=1;continue
                body=sorted(options,key=lambda v:v['file'])[0]
                origin={'ledger':str(p),'ledger_sha256':item['sha256'],'response_line':line,'physical_start_line':start[0],'ledger_seal':proof,
                        'request_body':body['file'],'request_body_sha256':body['sha256'],'request_body_seal':body['seal']}
                payload={'legacy_key':key,'body':body['body'],'effective_schema':schema(body['body']),'source_identity':source,'content':row['content'],'usage':row['usage'],'metadata':row.get('metadata',{}),'origin':origin}
                self.db.execute('INSERT INTO records VALUES(?,?,?,?,?,?)',(key,body['body_hash'],body['schema_hash'],source,float(row.get('created_at',0)),canon(payload)));counts['REUSABLE_SUCCESS_RECEIPT']+=1
            item['classification']='REQUEST_JOURNAL' if item['responses'] else 'NON_REQUEST_OR_UNSUPPORTED_LEDGER_SCHEMA';inventory.append(item)
        archive_inventory=[]
        for path in archives:
            item={'archive':str(path),'ledger_members':[]}
            try:
                with tarfile.open(path,'r:*') as tar:
                    for member in tar:
                        if not member.isfile() or not member.name.endswith('.jsonl') or not any(s in Path(member.name).name.lower() for s in ('request','journal','ledger')):continue
                        raw=tar.extractfile(member).read();h=hashlib.sha256(raw).hexdigest();mirror=direct_hashes.get(h)
                        rec={'member':member.name,'sha256':h,'identical_directory_ledger':mirror}
                        if not mirror:
                            try:
                                rr=[json.loads(l) for l in raw.splitlines() if l.strip()]
                                for line,row in enumerate(rr,1):
                                    if isinstance(row,dict) and row.get('event')=='response' and row.get('request_key'):
                                        self.db.execute('INSERT INTO unknown VALUES(?,?,?)',(row['request_key'],'ARCHIVE_ONLY_FULL_IDENTITY_NOT_RECONSTRUCTABLE',str(path)+'::'+member.name+':'+str(line)))
                                rec['classification']='ARCHIVE_ONLY_IDENTITIES_AUDITED_FAIL_CLOSED'
                            except ValueError:rec['classification']='INVALID_ARCHIVED_JSONL'
                        else:rec['classification']='EXACT_MIRROR_ALREADY_AUDITED'
                        item['ledger_members'].append(rec)
            except (OSError,tarfile.TarError) as e:item['error']=type(e).__name__
            archive_inventory.append(item)
        self.db.commit()
        report={'directory_ledgers':inventory,'archives':archive_inventory,'pruned_non_run_data_roots':pruned,'counts':dict(counts),'body_reconstruction_failures':dict(body_stats),
                'scope':'All directory model-ledger filename families and tar artifacts under the authorized lab workspace; .git, environments, dependency caches and CodeQL data tables excluded, not model-run directories.',
                'unknown_identity_rule':'Never reuse or physically resend a same-key unknown historical success. Fail closed until identity is reconstructable.',
                'model_requests':0}
        (output/'history-inventory.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');return report
    def lookup(self,key,body,source_identity,effective_schema=None):
        sh=hashed(schema(body) if effective_schema is None else effective_schema)
        candidates=self.db.execute('SELECT payload FROM records WHERE key=? AND body_hash=? AND schema_hash=? AND source_id=? ORDER BY created,payload',(key,hashed(body),sh,source_identity)).fetchall()
        if not candidates:return None
        value=json.loads(candidates[0][0]);origin=value['origin']
        if sha(origin['ledger'])!=origin['ledger_sha256'] or sha(origin['request_body'])!=origin['request_body_sha256']:raise PolicyError('Historical immutable request/response changed; physical send blocked.')
        return value
    def unresolved(self,key):return self.db.execute('SELECT reason,origin FROM unknown WHERE key=? LIMIT 1',(key,)).fetchone()

class IdentityJournal(RequestJournal):
    """Current physical ledger uses the full body/schema/source identity too."""
    def __init__(self,*args,source_identity,**kwargs):
        super().__init__(*args,**kwargs);self.source_identity=source_identity
    def identity(self,context,policy):
        body=policy.request_body(context);effective=getattr(policy,'tool_schema',None) or schema(body)
        return hashed({'legacy_key':legacy_key(context,policy),'body':body,'effective_schema':effective,'source_identity':self.source_identity,'endpoint':policy.endpoint})
    def preview(self,context,policy):
        key=self.identity(context,policy);r=self.responses.get(key)
        if not r:return None
        return {'content':r['content'],'usage':r['usage'],'metadata':r.get('metadata',{}),
                'origin':{'current_physical_ledger':str(self.path),'request_key':key,'response_record_sha256':hashed(r)}}
    def wrap(self,policy,**_):
        def send(context):
            key=self.identity(context,policy);cached=self.preview(context,policy)
            if cached:return ModelTurn(cached['content'],cached['usage'],cached['metadata'])
            existing=[]
            if self.path.exists():existing=[json.loads(l) for l in self.path.read_bytes().splitlines()]
            if any(r.get('event')=='request_started' and r.get('request_key')==key for r in existing):raise PolicyError('PREVIOUS_PHYSICAL_OUTCOME_UNSETTLED; no automatic physical resend')
            reserve,method=request_reserve(context,policy)
            if self.requests>=self.max_requests or self.tokens+reserve>self.max_tokens or time.time()-self.created_at>=self.max_seconds:raise BudgetExceeded('Current physical budget exhausted')
            body=policy.request_body(context);common={'request_key':key,'legacy_request_key':legacy_key(context,policy),'role':context['role'],'model':policy.model,'source_identity':self.source_identity,'body_sha256':hashed(body),'schema_sha256':hashed(getattr(policy,'tool_schema',None) or schema(body))}
            self.append({'event':'request_started',**common,'reserved_tokens':reserve,'reserve_method':method})
            self.requests+=1;self.tokens+=reserve
            if hasattr(policy,'deadline'):policy.deadline=time.monotonic()+max(0,self.max_seconds-(time.time()-self.created_at))
            turn=policy(context);n=turn.usage.get('total_tokens');charged=n if type(n)is int and n>=0 else reserve
            row={'event':'response',**common,'reserved_tokens':reserve,'charged_tokens':charged,'content':turn.content,'usage':dict(turn.usage),'metadata':dict(turn.metadata)}
            self.append(row);self.tokens+=charged-reserve;self.responses[key]={'binding':self.binding,'created_at':self.created_at,**row};return turn
        return send

class HistoryFirst:
    def __init__(self,index,policy,physical_send,logical_path,source_identity,guard=None,test_only=False,journal=None):
        self.index=index;self.policy=policy;self.physical_send=physical_send;self.logical_path=Path(logical_path);self.source_identity=source_identity;self.guard=guard;self.test_only=test_only;self.journal=journal
        for name in ['system_prompt','model','endpoint','max_output_tokens']:setattr(self,name,getattr(policy,name))
    def preview(self,context,policy=None):
        p=policy or self.policy;body=p.request_body(context)
        found=self.index.lookup(legacy_key(context,p),body,self.source_identity,getattr(p,'tool_schema',None))
        return found or (self.journal.preview(context,p) if self.journal is not None else None)
    def append(self,row):
        self.logical_path.parent.mkdir(parents=True,exist_ok=True)
        self.last_receipt={'test_only':self.test_only,**row}
        with self.logical_path.open('a',encoding='utf-8') as f:f.write(canon(self.last_receipt)+'\n');f.flush();os.fsync(f.fileno())
    def __call__(self,context):
        key=legacy_key(context,self.policy);body=self.policy.request_body(context);cached=self.preview(context)
        if cached:
            self.append({'event':'logical_response_reused','request_key':key,'body_sha256':hashed(body),'source_identity':self.source_identity,'original_physical_receipt':cached['origin'],'logical_usage':cached['usage'],'new_physical_requests':0,'new_reported_tokens':0,'new_currency_cost':0})
            return ModelTurn(cached['content'],cached['usage'],{**cached['metadata'],'history_reused':True,'original_physical_receipt':cached['origin'],'new_physical_requests':0})
        unknown=self.index.unresolved(key)
        if unknown:raise PolicyError('HISTORICAL_IDENTITY_NOT_RECONSTRUCTABLE: '+unknown[0]+'; no physical resend allowed.')
        if self.guard:self.guard(context,self.policy)
        turn=self.physical_send(context)
        receipt=self.journal.preview(context,self.policy) if self.journal is not None else None
        self.append({'event':'new_logical_response','request_key':key,'body_sha256':hashed(body),'source_identity':self.source_identity,'logical_usage':dict(turn.usage),'new_physical_requests':1,'origin':'CURRENT_PHYSICAL_JOURNAL','current_physical_receipt':receipt['origin'] if receipt else None})
        return turn
