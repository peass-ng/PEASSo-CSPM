"""Pure consumer of exact selected immutable ACR image inspection evidence."""
from copy import deepcopy
import json
import re
from peaso.secret_scanning import merge_leaks,KINGFISHER_VERSION,TRUFFLEHOG_VERSION
from peaso import oci_index_20261021 as oci_index
from peaso.collectors.azure_acr_image_stream_inspection_20261021 import consistent_descriptors,complete_blob_receipts
from peaso.collectors.azure_acr_image_secret_indicators import (
    KIND,CHECK,MARKER,SCHEMA,_SCOPE,MODES,MAX_IMAGES,MAX_LAYERS,MAX_MANIFEST,
    MAX_CONFIG,MAX_LAYER,MAX_IMAGE,MAX_EXPANDED,MAX_MEMBERS,MAX_CALLS,MAX_LEAKS,MAX_LOCATIONS,MAX_PARTS,
    DIGEST,TAR_TYPES,CONFIG_TYPES,_descriptor)

DECLARATIONS=[{'id':CHECK,'provider':'azure','category':'hardening','kind':KIND,
    'finding_type':'secrets','severity':'high','requirements':[],'dependencies':[KIND],
    'title':'Selected immutable ACR images have no detected secrets',
    'remediation':'Remove exposed credential literals from image build inputs and layers, rebuild the image, and rotate confirmed exposed credentials.',
    'evidence_sentences':['A likely secret was detected in a selected immutable ACR image.',
        'The value is hidden; offline detection did not validate the credential.']}]


def evaluate(item,index):
    try:
        ctx=index['context'];scope=ctx['scope'];meta=ctx['metadata']
        if (ctx['provider']!='azure' or not isinstance(scope,str) or not _SCOPE.fullmatch(scope)
                or meta[KIND+'_authorized'] is not True or meta['context_binding']!='scan_local'):
            raise ValueError('authorization')
        own=[c for c in index['collections'][KIND] if c.get('scope')==scope]
        if len(own)!=1 or own[0].get('status') not in ('collected','partial'):raise ValueError('collection')
        own=own[0];selected=meta[KIND+'_selection'][scope]
        if (not isinstance(selected,list) or not 1<=len(selected)<=MAX_IMAGES or len(set(selected))!=len(selected)
                or any(not isinstance(s,str) or not re.fullmatch(KIND+':[0-9a-f]{64}',s) for s in selected)
                or not isinstance(own.get('items'),list) or len(own['items'])!=len(selected)
                or {i.get('id') for i in own['items']}!=set(selected) or sum(i==item for i in own['items'])!=1):
            raise ValueError('selection')
        for row in (own,item):
            if any(not isinstance(meta[k],str) or not meta[k] or row['_provenance'][k]!=meta[k]
                   for k in ('credential_context_id','customer_context_id')):raise ValueError('capture')
        ident=item['id'];m=item[MARKER]
        if 'graph' in m:
            return _evaluate_index(item,own,index,scope,meta,ident,m)
        if m.get('complete') is False and m.get('leaks'):
            return _partial_positive(item,index,scope,meta,ident,m)
        if own.get('status')!='collected':raise ValueError('leaf collection')
        if (set(m)!={'schema','kind','identity','scope','complete','verification','descriptors','layers_scanned','parts','leaks','source_requests','mode','auth_audience','expanded_bytes','members','regular_files','manifest_digest'}
                or m['schema']!=SCHEMA or m['kind']!=KIND or m['identity']!=ident or m['scope']!=scope
                or m['auth_audience'] not in ('arm','acr') or m['complete'] is not True or m['verification']!='not_attempted' or m['mode'] not in MODES
                or m['manifest_digest']!=meta[KIND+'_digests'][ident]
                or not isinstance(m['manifest_digest'],str) or not DIGEST.fullmatch(m['manifest_digest'])
                or item['_provenance']['scope']!=scope):raise ValueError('marker')
        desc=m['descriptors']
        if not isinstance(desc,list) or not 2<=len(desc)<=MAX_LAYERS+1:raise ValueError('descriptors')
        if _descriptor(desc[0],CONFIG_TYPES,MAX_CONFIG)!=desc[0]:raise ValueError('config')
        if any(_descriptor(d,TAR_TYPES,MAX_LAYER)!=d for d in desc[1:]):raise ValueError('layers')
        if not consistent_descriptors(desc) or sum(d['size'] for d in desc)>MAX_IMAGE:raise ValueError('descriptor bound')
        if m['layers_scanned']!=[d['digest'] for d in desc[1:]]:raise ValueError('layers incomplete')
        if (type(m['expanded_bytes']) is not int or not 1<=m['expanded_bytes']<=MAX_EXPANDED
                or type(m['members']) is not int or not 1<=m['members']<=MAX_MEMBERS
                or type(m['regular_files']) is not int or not 1<=m['regular_files']<=m['members']):raise ValueError('expanded')
        refs=m['source_requests'];ledger=meta[KIND+'_receipts']
        if (not isinstance(refs,list) or not 6<=len(refs)<=3+1+2*len(desc)
                or len(set(refs))!=len(refs) or not isinstance(ledger,list) or len(ledger)>MAX_CALLS
                or item['_provenance']['source_requests']!=refs):raise ValueError('receipts')
        receipts=[]
        for ref in refs:
            rows=[r for r in ledger if r.get('id')==ref]
            if not isinstance(ref,str) or not re.fullmatch(r'acr-read-[1-9][0-9]*',ref) or len(rows)!=1:raise ValueError('receipt identity')
            r=rows[0]
            if (set(r)!={'id','identity','scope','method','operation','endpoint','status','http_status','bytes','digest','verified','bound'}
                    or r['identity']!=ident or r['scope']!=scope or r['verified'] is not True or r['bound'] is not True
                    or type(r['http_status']) is not int or type(r['bytes']) is not int or not 0<=r['bytes']<=MAX_LAYER):raise ValueError('receipt binding')
            receipts.append(r)
        for r,operation,method,endpoint in zip(receipts[:3],('registry_identity','oauth_exchange','oauth_pull'),('GET','POST','POST'),('arm','registry','registry')):
            if (r['operation']!=operation or r['method']!=method or r['endpoint']!=endpoint or r['status']!='collected'
                    or r['http_status']!=200 or r['digest'] is not None or not 1<=r['bytes']<=(MAX_CONFIG if operation=='registry_identity' else 32768)):
                raise ValueError('native auth provenance')
        manifest=receipts[3]
        if (manifest['operation']!='manifest' or manifest['endpoint']!='registry' or manifest['method']!='GET'
                or manifest['status']!='collected' or manifest['http_status']!=200 or manifest['digest']!=m['manifest_digest']
                or not 1<=manifest['bytes']<=MAX_MANIFEST):raise ValueError('manifest provenance')
        cursor=4
        for d in desc:
            r=receipts[cursor];cursor+=1
            if r['method']!='GET' or r['operation']!='blob' or r['endpoint']!='registry' or r['digest']!=d['digest']:raise ValueError('blob provenance')
            if r['status']=='redirect':
                if r['http_status']!=307 or r['bytes']!=0:raise ValueError('redirect')
                r=receipts[cursor];cursor+=1
                if (r['operation']!='blob_data' or r['endpoint'] not in
                        ('native_dedicated_data','native_pinned_shared_data')
                        or r['method']!='GET' or r['digest']!=d['digest']):
                    raise ValueError('native data provenance')
            if r['status']!='collected' or r['http_status']!=200 or r['bytes']!=d['size']:raise ValueError('blob completeness')
        if cursor!=len(receipts):raise ValueError('extra requests')
        if not complete_blob_receipts(receipts,[desc]):raise ValueError('blob occurrence receipts')
        parts=m['parts'];versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION}
        if not isinstance(parts,list) or not m['regular_files']+2<=len(parts)<=MAX_PARTS or parts[0].get('part')!='manifest' or parts[1].get('part')!='config':raise ValueError('parts')
        names=[];member_parts={}
        for pos,p in enumerate(parts):
            if (set(p)!={'part','bytes','complete','engines'} or type(p['bytes']) is not int or not 0<=p['bytes']<=MAX_LAYER
                    or p['complete'] is not True or not isinstance(p['part'],str)):raise ValueError('part')
            if pos>=2:
                match=re.fullmatch(r'layer-([1-9][0-9]*)\.member-([1-9][0-9]*)\.(?:name|chunk-[1-9][0-9]*)',p['part'])
                if not match or int(match[1])>len(desc)-1 or int(match[2])>m['members']:raise ValueError('member')
                member_parts.setdefault((int(match[1]),int(match[2])),[]).append(p['part'].split('.')[-1])
            es=p['engines']
            if (not isinstance(es,list) or len(es)!=2 or {e.get('engine') for e in es}!=set(versions)
                    or any(set(e)!={'engine','version','status'} or e.get('version')!=versions.get(e.get('engine')) or e.get('status')!='complete' for e in es)):
                raise ValueError('engines')
            names.append(p['part'])
        if len(names)!=len(set(names)) or parts[0]['bytes']!=manifest['bytes'] or parts[1]['bytes']!=desc[0]['size']:raise ValueError('part binding')
        # Every regular file, including an empty file, produces its name and
        # at least chunk-1. A retained filename alone cannot prove its contents
        # were inspected. Preserve the producer's consecutive chunk order.
        if (len(member_parts)!=m['regular_files']
                or {member for layer,member in member_parts}!=set(range(1,m['regular_files']+1))
                or any(parts!=['name']+['chunk-'+str(n) for n in range(1,len(parts))]
                    or len(parts)<2 for parts in member_parts.values())):
            raise ValueError('incomplete file parts')
        leaks=m['leaks']
        if (not isinstance(leaks,list) or merge_leaks(leaks)!=leaks or len(leaks)>MAX_LEAKS
                or sum(len(l['locations']) for l in leaks)>MAX_LOCATIONS
                or any(loc['path'] not in {ident+'.'+n for n in names} for l in leaks for loc in l['locations'])):raise ValueError('leaks')
        observed=('A likely secret was detected in a selected immutable ACR image. The value is hidden; offline detection did not validate the credential.' if leaks else
            'Both offline detectors completed without detecting a supported secret in the selected immutable ACR image. Coverage is limited to the observed manifest, config and supported layer files.')
        return ('FAIL' if leaks else 'PASS'),{'secret_leaks':deepcopy(leaks),'credential_validation':'not_attempted','complete':True,
            'coverage':'selected_observed_image_content_only','parts':deepcopy(parts),'source_requests':list(refs),'observed':observed}
    except (KeyError,TypeError,ValueError,AttributeError,OverflowError,IndexError):
        return 'UNKNOWN',{'observed':'The selected ACR image was disabled, unsupported, incomplete or unbound. Secret absence could not be assessed.'}


def _evaluate_index(item,collection,index,scope,meta,ident,m):
    """Validate the parent and each verified child before accepting a clean result."""
    try:
        expected={'schema','kind','identity','scope','complete','verification','descriptors',
            'layers_scanned','parts','leaks','source_requests','mode','auth_audience',
            'expanded_bytes','members','regular_files','manifest_digest','graph','child_inspections'}
        if m.get('complete') is False:expected.add('inspected_digests')
        if 'scan_partial' in m:expected.update(('scan_partial','skipped_files'))
        graph=m['graph'];children=graph['children'];inspections=m['child_inspections']
        if (set(m)!=expected or m['schema']!=SCHEMA or m['kind']!=KIND
                or m['identity']!=ident or m['scope']!=scope or m['manifest_digest']!=meta[KIND+'_digests'][ident]
                or m['verification']!='not_attempted' or m['auth_audience'] not in ('arm','acr')
                or m['mode'] not in MODES or m['descriptors']!=[]
                or type(graph) is not dict or set(graph)!={'parent_digest','media_type','children','complete'}
                or graph['parent_digest']!=m['manifest_digest']
                or graph['media_type'] not in oci_index.INDEX_TYPES or type(graph['complete']) is not bool
                or type(children) is not list or len(children)>oci_index.MAX_CHILDREN
                or m['complete'] is True and not children
                or ('scan_partial' in m and (m['scan_partial'] is not True
                    or type(m['skipped_files']) is not int or not 1<=m['skipped_files']<=MAX_MEMBERS
                    or m['complete'] is not False))
                or type(inspections) is not list or len(inspections)>len(children)
                or item['_provenance']['scope']!=scope
                or item['_provenance']['source_requests']!=m['source_requests']):
            raise ValueError('index identity')
        complete=(m['complete'] is True and graph['complete'] is True and
            collection['status']=='collected' and len(inspections)==len(children))
        if m['complete'] is True and not complete:raise ValueError('incomplete graph')
        refs=m['source_requests'];ledger=meta[KIND+'_receipts']
        if (type(refs) is not list or len(refs)<4 or len(refs)>MAX_CALLS or len(set(refs))!=len(refs)
                or type(ledger) is not list or len(ledger)>MAX_CALLS):raise ValueError('index receipts')
        rows=[]
        for ref in refs:
            found=[r for r in ledger if r.get('id')==ref]
            if (len(found)!=1 or found[0].get('identity')!=ident or found[0].get('scope')!=scope
                    or found[0].get('status') in ('collected','redirect')
                    and (found[0].get('bound') is not True or found[0].get('verified') is not True)):
                raise ValueError('foreign receipt')
            rows.append(found[0])
        if complete and any(r.get('status') not in ('collected','redirect') for r in rows):
            raise ValueError('incomplete native read')
        if [r.get('operation') for r in rows[:4]]!=['registry_identity','oauth_exchange','oauth_pull','manifest']:
            raise ValueError('index native prefix')
        if (rows[3].get('digest')!=graph['parent_digest'] or rows[3].get('status')!='collected'
                or rows[3].get('http_status')!=200 or not 1<=rows[3].get('bytes',0)<=MAX_MANIFEST):
            raise ValueError('parent manifest')
        descriptor_groups=[]
        for child,record in zip(children,inspections):
            if (type(child) is not dict or set(child)!={'digest','size','mediaType','platform','config_digest'}
                    or child['mediaType'] not in oci_index.LEAF_TYPES
                    or type(child['size']) is not int or not 0<child['size']<=MAX_MANIFEST
                    or not DIGEST.fullmatch(child['digest']) or not DIGEST.fullmatch(child['config_digest'])
                    or oci_index._platform(child['platform'])!=child['platform']
                    or type(record) is not dict or set(record)!={'digest','descriptors','layers_scanned','parts','expanded_bytes','members','regular_files','scan_partial','skipped_files'}
                    or record['digest']!=child['digest']
                    or type(record['scan_partial']) is not bool
                    or type(record['skipped_files']) is not int or record['skipped_files']<0
                    or record['scan_partial']!=(record['skipped_files']>0)):
                raise ValueError('index child')
            desc=record['descriptors']
            descriptor_groups.append(desc)
            if (type(desc) is not list or not 2<=len(desc)<=MAX_LAYERS+1
                    or _descriptor(desc[0],CONFIG_TYPES,MAX_CONFIG)!=desc[0]
                    or desc[0]['digest']!=child['config_digest']
                    or any(_descriptor(d,TAR_TYPES,MAX_LAYER)!=d for d in desc[1:])
                    or not consistent_descriptors(desc)
                    or record['layers_scanned']!=[d['digest'] for d in desc[1:]]
                    or type(record['regular_files']) is not int or record['regular_files']<1
                    or type(record['expanded_bytes']) is not int or not 1<=record['expanded_bytes']<=MAX_EXPANDED):
                raise ValueError('child content')
            if not any(r.get('operation')=='manifest' and r.get('digest')==child['digest']
                    and r.get('bytes')==child['size'] and r.get('status')=='collected'
                    and r.get('http_status')==200 for r in rows):raise ValueError('child manifest receipt')
            for descriptor in desc:
                if not any(r.get('digest')==descriptor['digest'] and r.get('bytes')==descriptor['size']
                        and r.get('status')=='collected' and r.get('http_status')==200 for r in rows):
                    raise ValueError('child blob receipt')
        if not complete_blob_receipts(rows,descriptor_groups):raise ValueError('child blob occurrence receipts')
        if complete:
            if (sum(r.get('operation')=='registry_identity' for r in rows)<2
                    or sum(r.get('operation')=='manifest' and r.get('digest')==graph['parent_digest']
                        for r in rows)<2):raise ValueError('after read binding')
        parts=m['parts'];versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION}
        if (type(parts) is not list or not 1<=len(parts)<=MAX_PARTS or parts[0].get('part')!='index'
                or any(type(p) is not dict or set(p)!={'part','bytes','complete','engines'}
                    or p['complete'] is not True or type(p['part']) is not str
                    or type(p['bytes']) is not int or not 0<=p['bytes']<=MAX_LAYER
                    or type(p['engines']) is not list or len(p['engines'])!=2
                    or {e.get('engine') for e in p['engines']}!=set(versions)
                    or any(e.get('status')!='complete' or e.get('version')!=versions.get(e.get('engine'))
                        for e in p['engines']) for p in parts)):
            raise ValueError('index parts')
        names=[p['part'] for p in parts]
        if len(set(names))!=len(names) or parts[0]['bytes']!=rows[3]['bytes']:
            raise ValueError('part identity')
        witnessed={'index'}
        for child,record in zip(children,inspections):
            prefix='child-'+child['digest'][7:]
            if (type(record['parts']) is not list or len(record['parts'])<2
                    or record['parts'][:2]!=[prefix+'.manifest',prefix+'.config']
                    or any(part not in names or not part.startswith(prefix+'.') for part in record['parts'])):
                raise ValueError('child part binding')
            if complete:
                member_parts={}
                for part in record['parts'][2:]:
                    match=re.fullmatch(re.escape(prefix)+r'\.layer-([1-9][0-9]*)\.member-([1-9][0-9]*)\.(name|chunk-[1-9][0-9]*)',part)
                    if not match or int(match[1])>len(record['descriptors'])-1:
                        raise ValueError('child member identity')
                    member_parts.setdefault((int(match[1]),int(match[2])),[]).append(match[3])
                if (len(member_parts)!=record['regular_files']
                        or {member for layer,member in member_parts}!=set(range(1,record['regular_files']+1))
                        or any(parts!=['name']+['chunk-'+str(n) for n in range(1,len(parts))]
                            or len(parts)<2 for parts in member_parts.values())):
                    raise ValueError('incomplete child file parts')
            witnessed.update(record['parts'])
        if ('scan_partial' in m and (m['skipped_files']<sum(c['skipped_files'] for c in inspections)
                or graph['complete'] is True and m['skipped_files']!=sum(c['skipped_files'] for c in inspections))
                or complete and any(c['scan_partial'] for c in inspections)):
            raise ValueError('child scan coverage')
        if complete and set(names)!=witnessed:raise ValueError('unbound part')
        leaks=m['leaks']
        if (type(leaks) is not list or merge_leaks(leaks)!=leaks or len(leaks)>MAX_LEAKS
                or sum(len(v['locations']) for v in leaks)>MAX_LOCATIONS
                or any(loc.get('path') not in {ident+'.'+name for name in witnessed}
                    for leak in leaks for loc in leak['locations'])):raise ValueError('index leaks')
        if leaks:
            return 'FAIL',{'secret_leaks':deepcopy(leaks),'complete':complete,
                'coverage':'selected_index_positive' if not complete else 'selected_index_complete',
                'source_requests':list(refs),'observed':
                'Verified content of the selected ACR image index contains a likely secret. '
                'Its value is hidden.'}
        if complete:
            return 'PASS',{'secret_leaks':[],'complete':True,'coverage':'selected_index_complete',
                'source_requests':list(refs),'observed':
                'The selected ACR image index has no detected secret in its fully inspected supported children. '
                'Its parent digest and registry identity remained bound during the read.'}
    except (KeyError,TypeError,ValueError,AttributeError,IndexError):
        pass
    return 'UNKNOWN',{'observed':
        'The selected ACR image index is missing complete child content or a bound registry read. '
        'Secret exposure in that child remains unclear.'}


def _partial_positive(item,index,scope,meta,ident,m):
    """Admit a verified positive prefix without treating incomplete layers as clean."""
    try:
        expected={'schema','kind','identity','scope','complete','verification','descriptors',
            'layers_scanned','parts','leaks','source_requests','mode','auth_audience',
            'expanded_bytes','members','regular_files','manifest_digest','inspected_digests'}
        if 'scan_partial' in m:
            expected.update(('scan_partial','skipped_files'))
        if (set(m)!=expected or m['schema']!=SCHEMA or m['kind']!=KIND or m['identity']!=ident
                or m['scope']!=scope or m['verification']!='not_attempted'
                or 'scan_partial' in m and (m['scan_partial'] is not True
                    or type(m['skipped_files']) is not int or not 1<=m['skipped_files']<=MAX_MEMBERS)
                or m['manifest_digest']!=meta[KIND+'_digests'][ident]
                or m['auth_audience'] not in ('arm','acr') or m['mode'] not in MODES
                or item['_provenance']['scope']!=scope):raise ValueError('partial marker')
        desc=m['descriptors'];inspected=m['inspected_digests']
        if (not isinstance(desc,list) or not 2<=len(desc)<=MAX_LAYERS+1
                or _descriptor(desc[0],CONFIG_TYPES,MAX_CONFIG)!=desc[0]
                or any(_descriptor(d,TAR_TYPES,MAX_LAYER)!=d for d in desc[1:])
                or sum(d['size'] for d in desc)>MAX_IMAGE
                or not consistent_descriptors(desc)
                or not isinstance(inspected,list) or len(inspected)<2
                or inspected[:2]!=[m['manifest_digest'],desc[0]['digest']]
                or inspected[2:]!=[d['digest'] for d in desc[1:1+len(inspected)-2]]
                or m['layers_scanned']!=inspected[2:]):raise ValueError('partial descriptors')
        refs=m['source_requests'];ledger=meta[KIND+'_receipts']
        if (not isinstance(refs,list) or not isinstance(ledger,list) or len(ledger)>MAX_CALLS
                or len(set(refs))!=len(refs) or len(refs)<5
                or item['_provenance']['source_requests']!=refs):raise ValueError('partial receipts')
        rows=[]
        for ref in refs:
            found=[r for r in ledger if r.get('id')==ref]
            if len(found)!=1 or found[0].get('identity')!=ident or found[0].get('scope')!=scope:
                raise ValueError('partial receipt identity')
            rows.append(found[0])
        if [r.get('operation') for r in rows[:4]]!=['registry_identity','oauth_exchange','oauth_pull','manifest']:
            raise ValueError('partial auth receipts')
        for r,operation,method,endpoint in zip(rows[:3],
                ('registry_identity','oauth_exchange','oauth_pull'),
                ('GET','POST','POST'),('arm','registry','registry')):
            if (set(r)!={'id','identity','scope','method','operation','endpoint','status','http_status',
                    'bytes','digest','verified','bound'} or r['operation']!=operation
                    or r['method']!=method or r['endpoint']!=endpoint or r['status']!='collected'
                    or r['http_status']!=200 or r['verified'] is not True or r['bound'] is not True
                    or r['digest'] is not None or type(r['bytes']) is not int or not 1<=r['bytes']<=MAX_CONFIG):
                raise ValueError('partial auth binding')
        manifest=rows[3]
        if (manifest.get('operation')!='manifest' or manifest.get('method')!='GET'
                or manifest.get('endpoint')!='registry' or manifest.get('status')!='collected'
                or manifest.get('http_status')!=200 or manifest.get('verified') is not True
                or manifest.get('bound') is not True or manifest.get('digest')!=m['manifest_digest']
                or type(manifest.get('bytes')) is not int or not 1<=manifest['bytes']<=MAX_MANIFEST):
            raise ValueError('partial manifest binding')
        cursor=4
        for d in desc[:len(inspected)-1]:
            if cursor>=len(rows):raise ValueError('partial blob receipt')
            r=rows[cursor];cursor+=1
            if r.get('status')=='redirect':
                if r.get('operation')!='blob' or cursor>=len(rows):raise ValueError('partial redirect')
                r=rows[cursor];cursor+=1
            if (r.get('status')!='collected' or r.get('verified') is not True
                    or r.get('bound') is not True or r.get('digest')!=d['digest']
                    or r.get('bytes')!=d['size'] or r.get('http_status')!=200):
                raise ValueError('partial blob binding')
        parts=m['parts'];leaks=m['leaks']
        if (not isinstance(parts,list) or not 1<=len(parts)<=MAX_PARTS or not isinstance(leaks,list)
                or not leaks or merge_leaks(leaks)!=leaks or len(leaks)>MAX_LEAKS
                or sum(len(l['locations']) for l in leaks)>MAX_LOCATIONS
                or any(p.get('complete') is not True for p in parts)):
            raise ValueError('partial witness')
        versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION}
        for part in parts:
            es=part.get('engines')
            if (set(part)!={'part','bytes','complete','engines'} or type(part.get('bytes')) is not int
                    or not 0<=part['bytes']<=MAX_LAYER or not isinstance(es,list) or len(es)!=2
                    or {e.get('engine') for e in es}!=set(versions)
                    or any(set(e)!={'engine','version','status'} or e['version']!=versions[e['engine']]
                           or e['status']!='complete' for e in es)):
                raise ValueError('partial part binding')
        paths={ident+'.'+p['part'] for p in parts if isinstance(p,dict) and isinstance(p.get('part'),str)}
        if any(loc.get('path') not in paths for leak in leaks for loc in leak['locations']):
            raise ValueError('partial location')
        for part in parts:
            name=part['part']
            match=re.fullmatch(r'layer-([1-9][0-9]*)\.member-([1-9][0-9]*)\.(?:name|chunk-[1-9][0-9]*)',name)
            if name not in ('manifest','config') and (match is None or int(match[1])>len(inspected)-2):
                raise ValueError('unverified partial layer')
        return 'FAIL',{'secret_leaks':deepcopy(leaks),'credential_validation':'not_attempted',
            'complete':False,'coverage':'verified_image_prefix_only','parts':deepcopy(parts),
            'source_requests':list(refs),'observed':
            'A likely secret was detected in the verified content of a selected immutable ACR image. The value is hidden; later image content was incomplete.'}
    except (KeyError,TypeError,ValueError,AttributeError,OverflowError,IndexError):
        return 'UNKNOWN',{'observed':'The selected ACR image content was incomplete or unbound, so its secret exposure is unclear.'}


def install():
    from pathlib import Path
    from . import CHECKS,register
    from .fixtures import CASES
    if any(c.id==CHECK for c in CHECKS):return
    d=DECLARATIONS[0]
    register(CHECK,'azure','hardening',KIND,d['title'],'high','security_configuration',d['remediation'],dependencies=[KIND])(evaluate)
    CASES[CHECK]=json.loads(Path(__file__).with_name('azure_acr_image_secret_review_20261020_fixtures.json').read_text()).get(CHECK,{})
