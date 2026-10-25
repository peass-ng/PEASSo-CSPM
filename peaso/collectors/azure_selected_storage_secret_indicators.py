"""Unregistered exact-version Blob/File source reads; no listing, keys or writes.

Fixed ARM/account identity precedes OAuth named object reads. Archives are parsed
in memory using the existing regular-file-only bounded parser, never extracted.
"""
from peaso.secret_evidence import scan_with_source, target_source

import base64
from copy import deepcopy
from datetime import datetime, timezone
from email.utils import format_datetime
import http.client
import json
import re
import time
from types import FunctionType
from uuid import uuid4
from urllib.parse import quote
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint, redact_matches
from .aws_package_content_indicators import scan_zip, scan_tar, PartialArchive

KIND='azure_storage_selected_source'
CHECK='azure.review.storage.selected_source_secret_indicators'
OPTION='selected_azure_storage_sources'
MARKER='SelectedStorageSourceSecretIndicators'
SCHEMA='azure-selected-storage-source-v1'
ARM='https://management.azure.com'
STORAGE='https://storage.azure.com'
ARM_VERSION='2025-06-01'
SUB_VERSION='2022-12-01'
DATA_VERSION='2023-11-03'
MAX_TARGETS=4
MAX_CALLS=24
MAX_ARM=524288
MAX_OBJECT=4*1024*1024
MAX_TOTAL=12*1024*1024
MAX_MEMBER=1024*1024
MAX_EXPANDED=8*1024*1024
MAX_TOTAL_EXPANDED=16*1024*1024
MAX_MEMBERS=128
MAX_TOTAL_MEMBERS=256
MAX_SECONDS=120
MAX_LEAKS=128
MAX_LOCATIONS=512
MAX_REDACTION_BYTES=8*1024*1024
MAX_REDACTION_VALUES=256
MAX_REDACTION_VALUE_BYTES=65536
MAX_REDACTION_TOTAL=262144
GUID=r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
SCOPE=re.compile('/subscriptions/'+GUID+r'\Z',re.I)
ACCOUNT=re.compile(r'(/subscriptions/'+GUID+r')/resourceGroups/([A-Za-z0-9_()-][A-Za-z0-9_.()-]{0,88}[A-Za-z0-9_()-]|[A-Za-z0-9_()-])/providers/Microsoft\.Storage/storageAccounts/([a-z0-9]{3,24})\Z',re.I)
VERSION=re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,7})?Z\Z')

class Incomplete(ValueError):
    """Stable code only; never native errors, URLs, names, content or credentials."""


def enabled(options):
    return options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'),list) and KIND in options['_content_secret_scan_kinds']


def parse(target):
    if not isinstance(target,dict) or target.get('service') not in ('blob','file'):raise Incomplete('invalid_selection')
    service=target['service'];container='container' if service=='blob' else 'share'
    if set(target)-{'service','resource_id',container,'object','version','format'} or not {'service','resource_id',container,'object','format'}<=set(target):raise Incomplete('invalid_selection')
    rid=target['resource_id'];m=ACCOUNT.fullmatch(rid) if isinstance(rid,str) and len(rid)<=512 else None
    name=target[container];path=target['object'];version=target.get('version')
    if (not m or '/.' in rid or not isinstance(name,str) or not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])',name) or '--' in name
            or not isinstance(path,str) or not 1<=len(path.encode('utf-8'))<=1024
            or not re.fullmatch(r'[A-Za-z0-9_./@+ =()-]+',path) or any(p in ('','.','..') or p.endswith(('.', ' ')) for p in path.split('/'))
            or len(path.split('/'))>32 or 'version' in target and (not isinstance(version,str) or not VERSION.fullmatch(version))
            or target['format'] not in ('text','zip','tar','tar.gz')):raise Incomplete('invalid_selection')
    if service=='file' and any(len(part)>255 for part in path.split('/')):raise Incomplete('invalid_selection')
    try:
        if version is not None:datetime.fromisoformat(version.replace('Z','+00:00'))
    except ValueError:raise Incomplete('invalid_selection') from None
    return service,m[1],rid,m[3].lower(),name,path,version,target['format']


def selected_targets(options,scopes):
    """Credential-free validator; omitted version means coherent current read."""
    if not isinstance(options,dict) or ('content_secret_scans' in options and type(options['content_secret_scans']) is not bool):raise Incomplete('invalid_selection')
    if OPTION not in options and not enabled(options):return []
    targets=options.get(OPTION)
    if (not isinstance(scopes,list) or not 1<=len(scopes)<=8 or any(not isinstance(s,str) or not SCOPE.fullmatch(s) for s in scopes)
            or len({s.casefold() for s in scopes})!=len(scopes) or not isinstance(targets,list) or not 1<=len(targets)<=MAX_TARGETS):raise Incomplete('invalid_selection')
    seen=set()
    for target in targets:
        service,scope,rid,account,name,path,version,form=parse(target)
        key=(rid.casefold(),service,name,path.casefold() if service=='file' else path,version)
        if scope.casefold() not in {s.casefold() for s in scopes} or key in seen:raise Incomplete('invalid_selection')
        seen.add(key)
    return deepcopy(targets)


def identity(target):
    native=deepcopy(target);native['resource_id']=native['resource_id'].casefold()
    if native['service']=='file':native['object']=native['object'].casefold()
    return KIND+':'+_fingerprint(json.dumps(native,sort_keys=True,separators=(',',':')))


def data_route(target):
    service,_,_,account,name,path,version,_=parse(target)
    query='?'+('versionid' if service=='blob' else 'sharesnapshot')+'='+quote(version,safe='') if version is not None else ''
    return account+'.'+service+'.core.windows.net','/'+name+'/'+quote(path,safe='/')+query


def remaining(reader,state):
    reader.check_cancelled();left=state['deadline']-time.monotonic()
    if left<=0:raise Incomplete('source_deadline')
    return min(left,10)


def _pairs(pairs):
    value={}
    for k,v in pairs:
        if k in value:raise Incomplete('duplicate_native_field')
        value[k]=v
    return value


def _json(raw):
    return json.loads(raw.decode('utf-8',errors='strict'),object_pairs_hook=_pairs,parse_constant=lambda _:(_ for _ in ()).throw(Incomplete('nonfinite_native_field')))


def _token(transport,audience,state):
    token=transport.token(audience)
    if not isinstance(token,str) or not 16<=len(token)<=16384 or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',token):raise Incomplete('token_unavailable')
    encoded=token.split('.')[1];claims=_json(base64.urlsafe_b64decode(encoded+'='*((-len(encoded))%4)))
    expected={audience,audience+'/'}|({'https://management.core.windows.net/'} if audience==ARM else set())
    tenant=claims.get('tid');principal=claims.get('oid');now=time.time()
    if (claims.get('aud') not in expected or not isinstance(tenant,str) or not re.fullmatch(GUID,tenant,re.I)
            or not isinstance(principal,str) or not re.fullmatch(GUID,principal,re.I) or type(claims.get('exp')) not in (int,float) or not now+5<claims['exp']<now+172800
            or 'nbf' in claims and (type(claims['nbf']) not in (int,float) or not claims['nbf']<=now)
            or any(isinstance(t,str) and t.casefold()!=tenant.casefold() for t in (getattr(transport,'tenant',None),getattr(transport,'verified_tenant',None)))):raise Incomplete('token_binding')
    binding={'tenant':tenant.lower(),'principal':'storage-source-principal:'+_fingerprint(tenant.lower()+'\n'+principal.lower())}
    if state.get('authority') not in (None,binding):raise Incomplete('token_identity_changed')
    state['authority']=binding
    return token


def _read(reader,transport,state,receipts,target,operation,host,path,method,cap,*,expected=None):
    remaining(reader,state)
    if state['calls']>=MAX_CALLS:raise Incomplete('source_call_limit')
    state['calls']+=1
    ident=identity(target);service=parse(target)[0];scope=parse(target)[1]
    receipt={'id':'storage-source-read:'+uuid4().hex,'identity':ident,'scope':scope,'capture':state['capture'],
             'operation':operation,'method':method,'origin':'arm' if host=='management.azure.com' else service,
             'request':'storage-source-request:'+_fingerprint(method+'\n'+host+'\n'+path),'status':'unavailable','http_status':None,'bytes':0,
             'tenant':None,'principal':None,'bound':False,'native_request':None,'version':SUB_VERSION if operation=='subscription' else ARM_VERSION if operation=='account' else DATA_VERSION}
    receipts.append(receipt);connection=response=None
    try:
        audience=ARM if host=='management.azure.com' else STORAGE
        token=_token(transport,audience,state);receipt.update(**state['authority'])
        headers={'Authorization':'Bearer '+token,'Accept-Encoding':'identity','Accept':'application/json' if audience==ARM else '*/*'}
        if audience==STORAGE:
            headers.update({'x-ms-version':DATA_VERSION,'x-ms-date':format_datetime(datetime.now(timezone.utc),usegmt=True)})
            if service=='file':headers['x-ms-file-request-intent']='backup'
            if service=='blob' and expected is not None:headers['If-Match']=expected['etag']
        connection=http.client.HTTPSConnection(host,timeout=remaining(reader,state));connection.set_debuglevel(0)
        connection.request(method,path,body=None,headers=headers);del token
        response=connection.getresponse();receipt['http_status']=response.status
        if type(response.status) is not int or response.status!=200:raise Incomplete('native_read_unavailable')
        if response.getheader('Content-Encoding') not in (None,'','identity') or response.getheader('Content-Range') is not None or response.getheader('Transfer-Encoding') is not None:raise Incomplete('unsupported_wire_response')
        length=response.getheader('Content-Length')
        if not isinstance(length,str) or not re.fullmatch(r'[0-9]{1,10}',length):raise Incomplete('length_unavailable')
        size=int(length)
        if not 1<=size<=cap:raise Incomplete('response_bound')
        request_id=response.getheader('x-ms-request-id')
        if not isinstance(request_id,str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}',request_id):raise Incomplete('request_provenance')
        receipt['native_request']='storage-source-response:'+_fingerprint(request_id)
        if audience==STORAGE:
            if response.getheader('x-ms-version')!=DATA_VERSION:raise Incomplete('data_api_version')
            observed=_properties(response,target,size)
            if expected is not None and observed!=expected:raise Incomplete('object_version_changed')
            if method=='HEAD':receipt.update(status='collected',bound=True);return observed
        elif (response.getheader('Content-Type') or '').split(';')[0].strip().lower()!='application/json':raise Incomplete('arm_response_type')
        raw=bytearray()
        while True:
            remaining(reader,state);chunk=response.read(min(16384,cap+1-len(raw)))
            if not isinstance(chunk,bytes):raise Incomplete('malformed_stream')
            if not chunk:break
            raw.extend(chunk);state['bytes']+=len(chunk);receipt['bytes']=len(raw)
            if len(raw)>cap or state['bytes']>MAX_TOTAL:raise Incomplete('transfer_bound')
        if len(raw)!=size:raise Incomplete('truncated_native_response')
        remaining(reader,state);receipt.update(status='collected',bound=audience==STORAGE)
        return _json(bytes(raw)) if audience==ARM else bytes(raw)
    finally:
        if response is not None:response.close()
        if connection is not None:connection.close()


def _properties(response,target,size):
    service,_,_,_,_,_,version,_=parse(target)
    etag=response.getheader('ETag')
    if not isinstance(etag,str) or not re.fullmatch(r'"[A-Za-z0-9-]{1,128}"',etag):raise Incomplete('etag_unavailable')
    copy=response.getheader('x-ms-copy-status')
    if copy not in (None,'success'):raise Incomplete('copy_incomplete')
    if service=='blob':
        native_version=response.getheader('x-ms-version-id')
        if (response.getheader('x-ms-blob-type')!='BlockBlob' or version is not None and native_version!=version
                or native_version is not None and (not isinstance(native_version,str) or not VERSION.fullmatch(native_version))):raise Incomplete('blob_version_binding')
        file_id=None
    else:
        file_id=response.getheader('x-ms-file-file-id')
        if response.getheader('x-ms-type')!='File' or not isinstance(file_id,str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}',file_id):raise Incomplete('file_identity_binding')
        if response.getheader('x-ms-file-file-type') not in (None,'Regular'):raise Incomplete('unsupported_file_type')
    return {'etag':etag,'bytes':size,'file_id':file_id,'version':native_version if service=='blob' else version}


def _bound_subscription(data,scope,state):
    if (not isinstance(data,dict) or set(data)&{'error','nextLink','partial','_coverage'} or str(data.get('id','')).casefold()!=scope.casefold()
            or str(data.get('subscriptionId','')).casefold()!=scope.rsplit('/',1)[1].casefold() or data.get('state')!='Enabled'
            or str(data.get('tenantId','')).casefold()!=state['authority']['tenant']):raise Incomplete('subscription_identity')


def _bound_account(data,target):
    service,scope,rid,account,*_=parse(target)
    if (not isinstance(data,dict) or set(data)&{'error','nextLink','partial','_coverage'} or str(data.get('id','')).casefold()!=rid.casefold()
            or str(data.get('name','')).casefold()!=account or str(data.get('type','')).casefold()!='microsoft.storage/storageaccounts'):raise Incomplete('account_identity')
    props=data.get('properties')
    if (not isinstance(props,dict) or props.get('provisioningState')!='Succeeded' or not isinstance(props.get('primaryEndpoints'),dict)
            or props['primaryEndpoints'].get(service)!='https://'+account+'.'+service+'.core.windows.net/'):raise Incomplete('account_primary_endpoint')


def text(raw):
    if not isinstance(raw,bytes) or not raw or len(raw)>MAX_MEMBER:raise Incomplete('text_bound')
    decoded=raw.decode('utf-8',errors='strict')
    if not decoded.strip() or any(ord(c)<32 and c not in '\t\r\n' or ord(c)==127 for c in decoded):raise Incomplete('binary_or_empty_content')
    if raw.startswith((b'PK',b'\x1f\x8b',b'7z\xbc\xaf',b'Rar!')) or raw[257:262]==b'ustar':raise Incomplete('nested_archive')


class Deadline:
    def __init__(self,reader,state):self.reader,self.state=reader,state
    def check_deadline(self):remaining(self.reader,self.state)


def _scan(reader,state,target,marker,payload,member_path=None):
    text(payload);remaining(reader,state)
    path=identity(target)+'.file-'+str(len(marker['parts'])+1)
    def remember(values):
        current=reader.storage_source_secret_redactions
        if reader.storage_source_secret_overflow:return
        if (len(values)>MAX_REDACTION_VALUES or any(len(v.encode())>MAX_REDACTION_VALUE_BYTES for v in values)):
            reader.storage_source_secret_overflow=True;current.clear();return
        current.update(values)
        if len(current)>MAX_REDACTION_VALUES or sum(len(v.encode()) for v in current)>MAX_REDACTION_TOTAL:
            reader.storage_source_secret_overflow=True;current.clear()
    result=scan_with_source(scan_content, payload,path,timeout=min(30,remaining(reader,state)),_redact_values=remember, source=target_source(target, resource_id=identity(target), path=member_path or target['object']))
    leaks=merge_leaks(result['leaks'])
    # Native file paths never leave parsing; rendered scanner line numbers are
    # not needed to identify the explicitly selected versioned source object.
    for leak in leaks:leak['locations']=[{'path':path}]
    marker['parts'].append({'path':path,'bytes':len(payload),'complete':result['complete'],'engines':deepcopy(result['engines']),'leaks':deepcopy(leaks)})
    marker['leaks']=merge_leaks(marker['leaks']+leaks)
    if len(marker['leaks'])>MAX_LEAKS or sum(len(l['locations']) for l in marker['leaks'])>MAX_LOCATIONS:raise Incomplete('finding_bound')
    remaining(reader,state)
    if not result['complete']:raise Incomplete('detector_incomplete')
    return []


def _inspect(reader,state,target,marker,raw):
    form=parse(target)[-1]
    if form=='text':_scan(reader,state,target,marker,raw);marker.update(expanded_bytes=len(raw),members=1);return
    cap=min(MAX_EXPANDED,MAX_TOTAL_EXPANDED-state['expanded']);members=min(MAX_MEMBERS,MAX_TOTAL_MEMBERS-state['members'])
    if cap<=0 or members<=0:raise Incomplete('archive_total_bound')
    facade=Deadline(reader,state)
    def inspect_member(payload,name,requests):
        requests.check_deadline()
        if name.lower().endswith(('.zip','.tar','.tgz','.tar.gz','.gz','.bz2','.xz','.7z','.rar','.exe','.dll','.so','.pyc','.pdf','.png','.jpg','.wasm')):raise Incomplete('unsupported_archive_member')
        return _scan(reader,state,target,marker,bytes(payload),member_path=name)
    parser=scan_zip if form=='zip' else scan_tar
    namespace=dict(parser.__globals__,_scan=inspect_member,EXPANDED_LIMIT=min(cap,max(1024,len(raw)*100)) if form=='tar.gz' else cap,
                   MEMBER_LIMIT=members,ZIP_LIMIT=MAX_OBJECT,LAYER_LIMIT=MAX_OBJECT)
    bounded=FunctionType(parser.__code__,namespace,parser.__name__,parser.__defaults__,parser.__closure__)
    charged_bytes,charged_members=cap,members
    try:
        if form=='zip':_,expanded,count=bounded(raw,facade)
        else:_,expanded,count=bounded(raw,'application/vnd.oci.image.layer.v1.tar'+('+gzip' if form=='tar.gz' else ''),facade)
        charged_bytes,charged_members=expanded,count
        if not marker['parts']:raise Incomplete('empty_archive')
        marker.update(expanded_bytes=expanded,members=count)
    finally:state['expanded']+=charged_bytes;state['members']+=charged_members


def _one(reader,transport,state,target,receipts):
    service,scope,rid,account,name,path,version,form=parse(target);ident=identity(target);start=len(receipts)
    marker={'schema':SCHEMA,'identity':ident,'scope':scope,'capture':state['capture'],'service':service,'format':form,'selection_mode':'current' if version is None else 'versioned',
            'tenant':None,'principal':None,'native_complete':False,'complete':False,'reason':'incomplete','verification':'not_attempted',
            'object_bytes':0,'expanded_bytes':0,'members':0,'parts':[],'leaks':[],'source_requests':[],'version_locator':None,'etag_locator':None,'file_locator':None}
    try:
        subscription=reader.call(_read,reader,transport,state,receipts,target,'subscription','management.azure.com',scope+'?api-version='+SUB_VERSION,'GET',MAX_ARM)
        _bound_subscription(subscription,scope,state);receipts[-1]['bound']=True;del subscription
        native=reader.call(_read,reader,transport,state,receipts,target,'account','management.azure.com',rid+'?api-version='+ARM_VERSION,'GET',MAX_ARM)
        _bound_account(native,target);receipts[-1]['bound']=True;del native
        host,route=data_route(target)
        before=reader.call(_read,reader,transport,state,receipts,target,'properties_before',host,route,'HEAD',MAX_OBJECT)
        raw=reader.call(_read,reader,transport,state,receipts,target,'content',host,route,'GET',MAX_OBJECT,expected=before)
        after=reader.call(_read,reader,transport,state,receipts,target,'properties_after',host,route,'HEAD',MAX_OBJECT)
        if before!=after:raise Incomplete('source_version_changed')
        marker.update(**state['authority'],native_complete=True,object_bytes=len(raw),
            version_locator='storage-source-version:'+_fingerprint(json.dumps(before,sort_keys=True)),etag_locator='storage-source-etag:'+_fingerprint(before['etag']),
            file_locator=None if service=='blob' else 'storage-source-file:'+_fingerprint(before['file_id']))
        _inspect(reader,state,target,marker,raw);del raw
        marker.update(complete=True,reason='complete')
    except Exception:
        marker['reason']='incomplete'
        if len(marker['leaks'])>MAX_LEAKS or sum(len(l['locations']) for l in marker['leaks'])>MAX_LOCATIONS:
            marker['leaks']=[];marker['parts']=[]
    marker['source_requests']=[r['id'] for r in receipts[start:]]
    return {'id':ident,MARKER:marker,'_provenance':{'scope':scope,'capture':state['capture'],'source_requests':list(marker['source_requests'])}}


def collect(reader,transport,scopes,wanted,options):
    """Root integration hook: serial scoped native jobs on the real scheduler."""
    if KIND not in wanted:return
    targets=selected_targets(options,scopes);capture='storage-source-capture:'+uuid4().hex
    reader.storage_source_secret_redactions=set();reader.storage_source_secret_overflow=False
    reader.storage_source_secret_metadata={KIND+'_authorized':enabled(options),KIND+'_selection':{s:[identity(t) for t in targets if parse(t)[1].casefold()==s.casefold()] for s in scopes},
        KIND+'_targets':{identity(t):{'service':t['service'],'format':t['format'],'selection_mode':'versioned' if 'version' in t else 'current'} for t in targets},
        KIND+'_capture':capture,KIND+'_receipts':[],KIND+'_redaction_complete':True}
    if not enabled(options):return
    state={'capture':capture,'deadline':time.monotonic()+MAX_SECONDS,'bytes':0,'calls':0,'expanded':0,'members':0,'authority':None}
    receipts=reader.storage_source_secret_metadata[KIND+'_receipts']
    for scope in scopes:
        names=[t for t in targets if parse(t)[1].casefold()==scope.casefold()]
        if names:
            def fetch(names=names):yield [_one(reader,transport,state,t,receipts) for t in names]
            reader.run([(KIND,scope,'Microsoft.Storage',fetch)])


def final_snapshot(reader,snapshot):
    """Root finalization hook: scrub mixed projections; no match set survives."""
    values=getattr(reader,'storage_source_secret_redactions',set())
    try:
        if not values and not getattr(reader,'storage_source_secret_overflow',False):return snapshot
        from peaso.snapshot import seal
        try:
            if getattr(reader,'storage_source_secret_overflow',False):raise Incomplete('redaction_bound')
            class BatchLimit(Exception):
                pass
            def measure(value, depth):
                stack=[(value,depth)];nodes=total=0
                while stack:
                    member,level=stack.pop();nodes+=1
                    if level>32:raise Incomplete('redaction_bound')
                    if nodes>65536:raise BatchLimit()
                    if isinstance(member,str):
                        if len(member)>MAX_REDACTION_BYTES:raise Incomplete('redaction_bound')
                        size=len(member.encode())
                        if size>MAX_REDACTION_BYTES:raise Incomplete('redaction_bound')
                        total+=size
                    elif isinstance(member,dict):
                        if len(member)>65536:raise Incomplete('redaction_bound')
                        stack.extend((child,level+1) for pair in member.items() for child in pair)
                    elif isinstance(member,list):
                        if len(member)>65536:raise Incomplete('redaction_bound')
                        stack.extend((child,level+1) for child in member)
                    if total>MAX_REDACTION_BYTES:raise BatchLimit()
            def scrub(original, depth=0):
                try:
                    measure(original,depth)
                except BatchLimit:
                    # Native evidence can itself contain complete inventories.
                    # Split containers, never strings or uninspected fields.
                    if isinstance(original,dict):
                        output,changed={},[]
                        for key,member in original.items():
                            safe_key,safe_member=scrub(key,depth+1),scrub(member,depth+1)
                            output[safe_key]=safe_member
                            if key!='_coverage' and (safe_key!=key or safe_member!=member):changed.append(safe_key)
                        if changed:
                            coverage=output.get('_coverage',{})
                            coverage=dict(coverage) if isinstance(coverage,dict) else {}
                            for key in changed:coverage[key]={'status':'unknown','reason':'detected_secret_redacted'}
                            output['_coverage']=coverage
                        return output
                    if isinstance(original,list):
                        if len(original)==1:return [scrub(original[0],depth+1)]
                        middle=len(original)//2
                        return scrub(original[:middle],depth)+scrub(original[middle:],depth)
                    raise Incomplete('redaction_bound')
                return redact_matches(original,values)
            safe=scrub(snapshot)
            reader.collections[:]=deepcopy(safe['collections'])
            reader.storage_source_secret_metadata=redact_matches(reader.storage_source_secret_metadata,values)
            return seal(safe)
        except Exception:
            # Withhold all potentially matched mixed-inventory aliases rather
            # than export unread text after bounded redaction cannot finish.
            safe=deepcopy(snapshot);safe['metadata']={KIND+'_redaction_complete':False}
            safe['collections']=[{'type':KIND,'scope':s,'service':'Microsoft.Storage','status':'unknown','items':[],
                                  'error':{'code':'source_redaction_incomplete'}} for s in snapshot['scopes'] if SCOPE.fullmatch(s)]
            reader.collections[:]=deepcopy(safe['collections']);reader.storage_source_secret_metadata={KIND+'_redaction_complete':False}
            return seal(safe)
    finally:values.clear()
