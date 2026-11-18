"""Durable transport boundary. Coordination is a recoverable observer, not a gate."""
import copy,json,hashlib
from .harness import ModelTurn,PolicyError
from .a1_execution import atomic
from .r2_hecv_services import ResponseStore,ServiceError

class ResponseRecovery:
    def __init__(self,root,source_id,journal,peer):
        self.root=root;self.store=ResponseStore(root,source_id);self.journal=journal;self.peer=peer

    def reconcile_usage(self,value,policy):
        """Only an exact successful response plus an existing start can settle usage."""
        ctx=value['context'];key=self.journal.identity(ctx,policy)
        if policy.request_body(ctx)!=value['body']:raise ServiceError('Recovery wire identity mismatch')
        if key in self.journal.responses:return False
        rows=[json.loads(x) for x in self.journal.path.read_bytes().splitlines()] if self.journal.path.exists() else []
        starts=[x for x in rows if x.get('event')=='request_started' and x.get('request_key')==key]
        if len(starts)!=1:raise ServiceError('RECOVERY_BLOCKED: unique physical start missing')
        if value['witness'].get('mode')!='ACTUAL_HTTP_RESPONSE':raise ServiceError('RECOVERY_BLOCKED: actual success receipt missing')
        start=starts[0];n=value['usage'].get('total_tokens');held=start['reserved_tokens']
        charged=n if type(n)is int and n>=0 else held
        row={k:v for k,v in start.items() if k not in {'event','binding','created_at'}}
        row.update(event='response',charged_tokens=charged,content=value['content'],usage=value['usage'],metadata=value['metadata'],recovery='EXACT_PERSISTED_SUCCESS_NO_RESEND')
        self.journal.append(row);self.journal.responses[key]=row;self.journal.tokens+=charged-held
        self.store.event(self.store.key(value['body']),'USAGE_SETTLED',recovered=True)
        return True

    def coordinate(self,value,*,recovery=False):
        key=self.store.key(value['body']);role=value['context']['role'];turn=ModelTurn(value['content'],value['usage'],value['metadata'])
        # Delivery validation and mechanism observation fail independently.
        try:
            failures=self.peer.validate_delivery(role,value['context'],value['witness'])
            self.store.event(key,'DELIVERY_FAILED' if failures else 'EVIDENCE_DELIVERED',failures=failures,recovery=recovery)
        except Exception as exc:
            self.store.event(key,'DELIVERY_FAILED',error=type(exc).__name__+': '+str(exc),recovery=recovery)
        try:
            self.peer.observe(role,value['context'],turn,value['witness'])
            self.store.event(key,'COORDINATED',recovery=recovery)
        except Exception as exc:
            self.store.event(key,'COORDINATION_FAILED',error=type(exc).__name__+': '+str(exc),recovery=recovery)
        return turn

    def recover(self,policies):
        result=[]
        for folder in sorted((self.root/'request-audit').glob('*')):
            if not folder.is_dir() or not (folder/'request-body.json').exists():continue
            body=json.loads((folder/'request-body.json').read_bytes())
            if self.store.get(body):continue
            receipt=folder/'successful-provider-envelope.json'
            if not receipt.exists():
                if (folder/'actual-provider-response.json').exists():result.append({'audit':str(folder),'status':'RECOVERY_BLOCKED','reason':'Raw response exists without a durable success receipt; never guess success or resend','new_physical_requests':0})
                continue
            try:
                v=json.loads(receipt.read_bytes());raw=(folder/'actual-provider-response.json').read_bytes()
                from context_serialization import unpack
                context=unpack(json.loads(body['messages'][1]['content']));policy=policies[context['role']]
                if json.loads((folder/'semantic-context.json').read_bytes())!=context:raise ServiceError('Raw semantic receipt mismatch')
                from .a1_history import hashed
                if hashlib.sha256(raw).hexdigest()!=v['raw_sha256'] or hashed(body)!=v['body_sha256'] or body!=policy.request_body(context) or v['http_status']!=200 or v['model']!=policy.model:raise ServiceError('Raw success binding mismatch')
                payload=json.loads(raw)
                if payload['choices'][0]['message']['content']!=v['content'] or payload.get('usage',{})!=v['usage']:raise ServiceError('Raw success content mismatch')
                self.store.put(body,context,ModelTurn(v['content'],v['usage'],v['metadata']),{'mode':'ACTUAL_HTTP_RESPONSE','audit':str(folder),'success_receipt_sha256':hashlib.sha256(receipt.read_bytes()).hexdigest()})
            except Exception as exc:result.append({'audit':str(folder),'status':'RECOVERY_BLOCKED','reason':str(exc),'new_physical_requests':0})
        for entry in self.store.audit():
            key=entry['response_id'];saved=json.loads((self.store.root/(key+'.json')).read_bytes());value=self.store.get(saved['body'])
            row={'response_id':key,'new_physical_requests':0}
            try:
                if value['witness'].get('mode')=='ACTUAL_HTTP_RESPONSE':row['usage_reconciled']=self.reconcile_usage(value,policies[value['context']['role']])
                states=entry['states']
                if not any(e['state']=='COORDINATED' for e in states) or (any(e['state']=='DELIVERY_FAILED' for e in states) and not any(e['state']=='EVIDENCE_DELIVERED' for e in states)):
                    self.coordinate(value,recovery=True)
                row['status']='RECOVERED_OR_ALREADY_SETTLED'
            except Exception as exc:row.update(status='RECOVERY_BLOCKED',reason=type(exc).__name__+': '+str(exc))
            result.append(row)
        atomic(self.root/'RESPONSE_DELIVERY_RECOVERY_AUDIT.json',{'model_requests':0,'records':result,'events':self.store.audit()})
        return result

def require_complete_protocol(turn):
    """Keep the provider bytes; never complete truncated JSON or invent a decision."""
    if turn.metadata.get('finish_reason')=='length':raise PolicyError('TRUNCATED_RESPONSE: saved and accounted; not a decision')
    try:value=json.loads(turn.content)
    except (ValueError,TypeError):return None # Original A1 owns its bounded protocol correction.
    if not isinstance(value,dict) or not value:raise PolicyError('EMPTY_OR_INVALID_RESPONSE: saved and accounted; not a decision')
    return value
