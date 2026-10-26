"""Explicit selected immutable ACR vulnerability reads and offline Trivy input.

Requires the accepted streaming ACR Reader at installation. No tag discovery,
challenge negotiation, registry credential export, cloud writes, Docker daemon,
or secret-store read is introduced here. The DB is pre-provisioned and read only.
"""
from copy import deepcopy
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import time

from peaso import container_image_archive_20261020 as archive
from peaso import oci_index_20261021 as oci_index
from peaso import image_findings
from peaso import trivy_container_runner_20261020 as trivy
from peaso.trivy_database_20261021 import diagnostic_phase
from . import azure_acr_image_secret_indicators as acr
from . import azure_acr_image_stream_inspection_20261021 as stream

ENABLE = 'image_vulnerability_scans'
OPTION = 'selected_azure_acr_image_vulnerabilities'
KIND = 'acr_selected_image_vulnerabilities'
CHECK = 'azure.review.acr.selected_image_high_critical_vulnerabilities'
MARKER = 'AcrSelectedImageVulnerabilities'
SCHEMA = 'azure-acr-native-image-vulnerabilities-20261021-v1'
MAX_SECONDS = 600
MAX_TOTAL = acr.MAX_IMAGES * archive.MAX_COMPRESSED
DEFAULT_DB_CACHE = '/tmp/peaso/trivy/current'


def selected_targets(options, scopes):
    """Credential-free exact selector; distinct from content secret scanning."""
    if type(options) is not dict or ENABLE in options and type(options[ENABLE]) is not bool:
        raise ValueError('invalid_acr_vulnerability_selection')
    if OPTION not in options and options.get(ENABLE) is not True:
        return []
    try:
        return acr.selected_targets({acr.OPTION:options.get(OPTION)},scopes)
    except Exception:
        raise ValueError('invalid_acr_vulnerability_selection') from None


def enabled(options):
    return (options.get(ENABLE) is True
        and type(options.get('_image_vulnerability_scan_kinds')) is list
        and KIND in options['_image_vulnerability_scan_kinds'])


def identity(target):
    return KIND + ':' + hashlib.sha256(
        repr((target['registry_id'].casefold(),target['repository'],target['digest'])).encode()).hexdigest()


def selection_metadata(options, scopes):
    targets=selected_targets(options,scopes)
    return {KIND+'_authorized':enabled(options), KIND+'_selection':{
        scope:[identity(t) for t in targets if acr._REGISTRY.fullmatch(t['registry_id'])[1].casefold()==scope.casefold()]
        for scope in scopes},KIND+'_digests':{identity(t):t['digest'] for t in targets},KIND+'_receipts':[]}


def _require(ok, reason='native_image_unavailable'):
    if not ok:raise ValueError(reason)


def _file_hash(path, descriptor, check):
    _require(isinstance(path,Path) and path.is_absolute())
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as source:
        before=os.fstat(source.fileno())
        _require(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid()
            and before.st_mode & 0o077==0 and before.st_size==descriptor['size'])
        digest=hashlib.sha256();size=0
        while True:
            check();part=source.read(1024*1024)
            if not part:break
            size+=len(part);_require(size<=descriptor['size']);digest.update(part)
        after=os.fstat(source.fileno())
        _require(size==descriptor['size'] and
            (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)
            and 'sha256:'+digest.hexdigest()==descriptor['digest'])
        return digest.hexdigest()


def _descriptors(raw):
    doc=archive.decode(raw)
    _require(type(doc) is dict and not set(doc)-{'schemaVersion','mediaType','config','layers','annotations'}
        and type(doc.get('schemaVersion')) is int and doc['schemaVersion']==2
        and doc.get('mediaType') in (archive.OCI,archive.DOCKER))
    config=archive.descriptor(doc['config'],archive.CONFIGS,archive.MAX_CONFIG)
    layers=doc.get('layers')
    _require(type(layers) is list and 1<=len(layers)<=archive.MAX_LAYERS)
    layers=[archive.descriptor(d,archive.LAYERS,archive.MAX_LAYER) for d in layers]
    # Repeated immutable layers are valid and must retain their manifest order.
    _require(stream.consistent_descriptors([config]+layers)
        and sum(d['size'] for d in [config]+layers)<=archive.MAX_COMPRESSED)
    return doc,config,layers


def _rootfs(raw, layers):
    doc=archive.decode(raw)
    diffs=doc.get('rootfs',{}).get('diff_ids') if type(doc) is dict else None
    _require(type(doc) is dict and doc.get('os')=='linux'
        and doc.get('architecture') in ('amd64','arm64')
        and type(doc.get('rootfs')) is dict and doc['rootfs'].get('type')=='layers'
        and type(diffs) is list and len(diffs)==len(layers)
        and all(type(d) is str and archive.DIGEST.fullmatch(d) for d in diffs))
    return diffs


def _observation(scope,target,image,scan):
    return {'provider':'azure','scope':scope,'asset_id':target['registry_id']
        +'/repositories/'+target['repository']+'@'+target['digest'],
        'asset_kind':'acr_image','scan':{'image':deepcopy(image),'status':scan['status'],
            'complete':scan['complete'],'scan_complete':scan['scan_complete'],
            'coverage_status':scan['coverage_status'],
            'database':{'fresh':scan.get('database',{}).get('fresh') is True},
            'findings':deepcopy(scan['findings'])}}


def _unknown(reason='image_vulnerability_coverage_incomplete'):
    return {'status':'UNKNOWN','complete':False,'scan_complete':False,
        'coverage_status':'UNKNOWN','database':{'fresh':False},'findings':[],
        'reason':reason}


def _scan_index(reader, token, parent_raw, marker, target, scope, *, db_cache,
        cli, runner, scratch_parent):
    """Scan every supported child of a digest-bound parent, retaining typed positives."""
    parent=target['digest'];document=archive.decode(parent_raw)
    marker['graph']={'parent_digest':parent,'media_type':document['mediaType'],
                     'children':[],'complete':False}
    marker['child_vulnerability_scans']=[]
    marker['scratch_removed']=True
    def fetch(digest,size,media_type):
        return reader.blob('manifests',digest,archive.MAX_MANIFEST,token,size)
    for child in oci_index.children(parent_raw,parent,fetch,check=reader.check):
        digest=child['digest'];manifest=child['raw']
        _,config_desc,layers=_descriptors(manifest)
        if config_desc['size']+sum(d['size'] for d in layers)>archive.MAX_COMPRESSED:
            raise ValueError('compressed_child_bound')
        raw=reader.blob('blobs',config_desc['digest'],archive.MAX_CONFIG,token,config_desc['size'])
        config=archive.decode(raw);diffs=_rootfs(raw,layers)
        platform=child['platform']
        if (config.get('os')!=platform['os'] or config.get('architecture')!=platform['architecture']
                or 'variant' in platform and config.get('variant')!=platform['variant']):
            raise ValueError('child_platform_config_mismatch')
        image=archive.identity({'provider':'azure','scope':scope,
            'immutable_reference':reader.host+'/'+target['repository']+'@'+digest,
            'manifest_digest':digest,'config_digest':config_desc['digest']})
        marker['graph']['children'].append({'digest':digest,'size':child['size'],
            'mediaType':child['mediaType'],'platform':platform,'config_digest':config_desc['digest'],
            'descriptors':deepcopy([config_desc]+layers),'rootfs_diff_ids':list(diffs)})
        with tempfile.TemporaryDirectory(prefix='peaso-azure-acr-index-',dir=scratch_parent) as directory:
            root=Path(directory);root.chmod(0o700)
            from .azure_acr_layer_overlap_20261026 import download_and_validate
            paths=download_and_validate(reader,token,layers,root,image,manifest,raw)
            fingerprints=tuple(_file_hash(path,desc,reader.check) for path,desc in zip(paths,layers))
            def verify():
                fresh=reader.authenticate()
                if reader.blob('manifests',parent,archive.MAX_MANIFEST,fresh)!=parent_raw:
                    raise ValueError('parent_manifest_changed')
                if reader.blob('manifests',digest,archive.MAX_MANIFEST,fresh,child['size'])!=manifest:
                    raise ValueError('child_manifest_changed')
                if reader.blob('blobs',config_desc['digest'],archive.MAX_CONFIG,fresh,config_desc['size'])!=raw:
                    raise ValueError('child_config_changed')
                if fingerprints!=tuple(_file_hash(path,desc,reader.check) for path,desc in zip(paths,layers)):
                    raise ValueError('child_layer_changed')
                return dict(image)
            verify()
            report=(runner or trivy.scan_image)(image,manifest,raw,paths,
                native_verifier=verify,enabled=True,db_cache=db_cache,cli=cli,
                # Pinned Trivy reads an --input tar only in docker-save layout;
                # an OCI layout tar fails ("index.json: not a directory").
                archive_format='docker',
                timeout=min(trivy.MAX_SECONDS,max(1,int(reader.state['deadline']-time.monotonic()))),
                cancel=reader.check,scratch_parent=scratch_parent)
            verify()
        _require(type(report) is dict and report.get('image')==image
            and report.get('status') in ('PASS','FAIL','UNKNOWN')
            and type(report.get('findings')) is list)
        full=(report.get('complete') is True and report.get('scan_complete') is True
            and report.get('coverage_status')=='COMPLETE'
            and type(report.get('database')) is dict and report['database'].get('fresh') is True)
        if full:
            scan=deepcopy(report)
        elif report['status']=='FAIL' and report['findings']:
            proof=report.get('archive')
            _require(type(proof) is dict and proof.get('manifest_digest')==digest
                and proof.get('config_digest')==config_desc['digest']
                and proof.get('format') in ('oci','docker')
                and type(proof.get('expanded_bytes')) is int
                and 0<proof['expanded_bytes']<=archive.MAX_EXPANDED
                and type(proof.get('members')) is int and 0<proof['members']<=archive.MAX_MEMBERS)
            scan={'image':image,'status':'FAIL','complete':False,'scan_complete':False,
                'coverage_status':'UNKNOWN','database':{'fresh':report['database'].get('fresh') is True},
                'findings':deepcopy(report['findings']),'archive':deepcopy(proof)}
        else:
            scan={**_unknown(), 'image':image}
        observed=_observation(scope,target,image,scan)
        built=image_findings.build_report([observed],selected=True)
        _require(built['invalid_observations']==built['invalid_vulnerabilities']==0)
        if scan['status']=='FAIL':_require(bool(built['rows']))
        if scan['status']=='PASS':_require(built['complete'] is True and not built['rows'])
        marker['child_vulnerability_scans'].append(scan)
        if scan['status']=='FAIL':marker['status']='FAIL'
    marker['graph']['complete']=True
    fresh=reader.authenticate()
    if reader.blob('manifests',parent,archive.MAX_MANIFEST,fresh)!=parent_raw:
        raise ValueError('parent_manifest_changed')
    scans=marker['child_vulnerability_scans']
    full=bool(scans) and all(s['status'] in ('PASS','FAIL') and s.get('complete') is True
        and s.get('scan_complete') is True and s.get('coverage_status')=='COMPLETE'
        and s.get('database',{}).get('fresh') is True for s in scans)
    marker['complete']=full
    marker['status']='FAIL' if any(s['status']=='FAIL' for s in scans) else 'PASS' if full else 'UNKNOWN'
    marker['reason']=None if full else 'selected_image_vulnerability_coverage_incomplete'


def _scan_target(outer, transport, receipts, scope, target, state, *, db_cache,
        cli, runner, scratch_parent):
    row={'id':identity(target),MARKER:{'schema':SCHEMA,'selection':deepcopy(target),
        'status':'UNKNOWN','complete':False,'reason':'native_image_unavailable',
        'image':None,'descriptors':[],'rootfs_diff_ids':[],
        'observation':None,'source_requests':[],'archive':None,'scratch_removed':False},
        '_provenance':{'scope':scope,'source_requests':[]}}
    marker=row[MARKER];start=len(receipts)
    scratch=None
    try:
        reader=acr.Reader(outer,transport,receipts,scope,target,state)
        stream.enable_pinned_shared_data(reader)
        # Persisted CVE receipts must survive collector/evaluator process boundaries.
        # This identity contains resource selectors, never a credential value.
        reader.ident = row['id']
        token=reader.authenticate()
        manifest=reader.blob('manifests',target['digest'],archive.MAX_MANIFEST,token)
        document=archive.decode(manifest)
        if type(document) is dict and document.get('mediaType') in oci_index.INDEX_TYPES:
            _scan_index(reader,token,manifest,marker,target,scope,db_cache=db_cache,
                cli=cli,runner=runner,scratch_parent=scratch_parent)
            return row
        _,config_desc,layers=_descriptors(manifest)
        config=reader.blob('blobs',config_desc['digest'],archive.MAX_CONFIG,token,config_desc['size'])
        diffs=_rootfs(config,layers)
        image=archive.identity({'provider':'azure','scope':scope,
            'immutable_reference':reader.host+'/'+target['repository']+'@'+target['digest'],
            'manifest_digest':target['digest'],'config_digest':config_desc['digest']})
        marker.update(image=image,descriptors=deepcopy([config_desc]+layers),rootfs_diff_ids=list(diffs))
        scratch=tempfile.TemporaryDirectory(prefix='peaso-azure-acr-vuln-',dir=scratch_parent)
        root=Path(scratch.name);root.chmod(0o700)
        from .azure_acr_layer_overlap_20261026 import download_and_validate
        paths=download_and_validate(reader,token,layers,root,image,manifest,config)
        fingerprints=tuple(_file_hash(path,desc,reader.check) for path,desc in zip(paths,layers))
        def verify():
            # Every call obtains a fresh native ARM registry identity and an exact
            # immutable manifest/config observation. Local files are rehashed.
            fresh=reader.authenticate()
            again=reader.blob('manifests',target['digest'],archive.MAX_MANIFEST,fresh)
            _require(again==manifest)
            _,new_config,new_layers=_descriptors(again)
            _require(new_config==config_desc and new_layers==layers)
            new_raw=reader.blob('blobs',config_desc['digest'],archive.MAX_CONFIG,fresh,config_desc['size'])
            _require(new_raw==config and _rootfs(new_raw,layers)==diffs)
            _require(fingerprints==tuple(_file_hash(path,desc,reader.check)
                for path,desc in zip(paths,layers)))
            return dict(image)
        verify()
        raw=(runner or trivy.scan_image)(image,manifest,config,paths,
            native_verifier=verify,enabled=True,db_cache=db_cache,
            cli=cli,archive_format='docker',timeout=min(trivy.MAX_SECONDS,
                max(1,int(state['deadline']-time.monotonic()))),
            cancel=reader.check,scratch_parent=scratch_parent)
        verify()
        _require(type(raw) is dict and raw.get('image')==image and
            raw.get('status') in ('PASS','FAIL','UNKNOWN') and
            type(raw.get('findings')) is list)
        # Full coverage is required for PASS. A verified, typed positive can
        # survive incomplete scanner/DB coverage without asserting clean scope.
        full=(raw.get('complete') is True and raw.get('scan_complete') is True
            and raw.get('coverage_status')=='COMPLETE'
            and type(raw.get('database')) is dict and raw['database'].get('fresh') is True)
        if full:
            scan=deepcopy(raw)
        elif raw['status']=='FAIL' and raw['findings']:
            proof=raw.get('archive')
            _require(type(raw.get('complete')) is bool
                and type(raw.get('scan_complete')) is bool
                and raw.get('coverage_status') in ('COMPLETE','UNKNOWN')
                and type(raw.get('database')) is dict
                and type(raw['database'].get('fresh')) is bool
                and type(proof) is dict and proof.get('format')=='docker'
                and proof.get('manifest_digest')==target['digest']
                and proof.get('config_digest')==config_desc['digest']
                and type(proof.get('expanded_bytes')) is int
                and 0<proof['expanded_bytes']<=archive.MAX_EXPANDED
                and type(proof.get('members')) is int
                and 0<proof['members']<=archive.MAX_MEMBERS)
            scan={'status':'FAIL','complete':False,'scan_complete':False,
                'coverage_status':'UNKNOWN',
                'database':{'fresh':type(raw.get('database')) is dict
                    and raw['database'].get('fresh') is True},
                'findings':deepcopy(raw['findings']),
                'reason':'scanner_or_database_incomplete'}
        else:
            scan=_unknown('scanner_or_database_incomplete')
        _require(scan['status'] in ('PASS','FAIL') if scan['complete'] else scan['status'] in ('FAIL','UNKNOWN'))
        observed=_observation(scope,target,image,scan)
        report=image_findings.build_report([observed],selected=True)
        _require(report['invalid_observations']==report['invalid_vulnerabilities']==0)
        if scan['status']=='FAIL':
            _require(bool(report['rows']))
        if scan['status']=='PASS':
            _require(report['complete'] is True and not report['rows'])
        marker.update(status=scan['status'],complete=report['complete'],
            reason=None if report['complete'] else scan['reason'],
            observation=observed,archive=deepcopy(raw.get('archive')))
    except Exception as exc:
        if (type(exc).__name__=='AzureReadError'
                and getattr(exc,'code',None) in ('collection_cancelled','deadline_exceeded')):
            raise
        pass
    finally:
        if scratch is not None:
            try:scratch.cleanup();marker['scratch_removed']=True
            except Exception:
                marker.update(status='UNKNOWN',complete=False,reason='scratch_cleanup_failed')
        marker['source_requests']=[r['id'] for r in receipts[start:]]
        row['_provenance']['source_requests']=list(marker['source_requests'])
    return row


def _unavailable_row(scope,target,reason):
    marker={'schema':SCHEMA,'selection':deepcopy(target),'status':'UNKNOWN','complete':False,
        'reason':reason,'image':None,'descriptors':[],'rootfs_diff_ids':[],
        'observation':None,'source_requests':[],'archive':None,'scratch_removed':True}
    return {'id':identity(target),MARKER:marker,
            '_provenance':{'scope':scope,'source_requests':[]}}


def _append_receipts(result,row,local):
    """Number a target's private receipts as one contiguous serial block."""
    offset=len(result['receipts']);mapping={}
    for number,receipt in enumerate(local,offset+1):
        new='acr-read-'+str(number)
        mapping[receipt['id']]=new
        receipt['id']=new
    result['receipts'].extend(local)
    marker=row[MARKER]
    marker['source_requests']=[mapping.get(rid,rid) for rid in marker['source_requests']]
    row['_provenance']['source_requests']=list(marker['source_requests'])


def collect_native(outer,transport,scopes,options,*,db_cache=DEFAULT_DB_CACHE,
        cli=trivy.DEFAULT_CLI,runner=None,scratch_parent=None,
        database_check=None, database_diagnostics=None):
    """No credential or network access before an explicit named-check selection."""
    targets=selected_targets(options,scopes)
    result={'schema':SCHEMA,'authorized':enabled(options),'status':'UNKNOWN',
        'complete':False,'rows':[],'receipts':[],'observations':[],
        'reason':'disabled'}
    if not result['authorized']:
        return result
    _require(bool(targets),'exact_acr_vulnerability_selection_required')
    checker=database_check or trivy.database_state
    try:
        with diagnostic_phase('offline_validation', database_diagnostics):
            state=checker(db_cache)
            _require(type(state) is dict and state.get('fresh') is True,
                     'fresh_offline_database_required')
    except Exception:
        result['reason']='offline_database_unavailable'
        for scope in scopes:
            result['rows'].extend(_unavailable_row(scope,target,result['reason']) for target in targets
                if acr._REGISTRY.fullmatch(target['registry_id'])[1].casefold()==scope.casefold())
        result['observations']=[None for _ in result['rows']]
        return result
    limit={'deadline':time.monotonic()+MAX_SECONDS,'bytes':0,'calls':0}
    jobs=[(scope,target) for scope in scopes for target in targets
          if acr._REGISTRY.fullmatch(target['registry_id'])[1].casefold()==scope.casefold()]
    from .azure_acr_image_parallel_20261026 import scan_targets
    for row,local in scan_targets(jobs,lambda scope,target,receipts:_scan_target(
            outer,transport,receipts,scope,target,limit,db_cache=db_cache,cli=cli,
            runner=runner,scratch_parent=scratch_parent)):
        _append_receipts(result,row,local)
        result['rows'].append(row)
    observations=[]
    for row in result['rows']:
        marker=row[MARKER];graph=marker.get('graph')
        if type(graph) is dict:
            target=marker['selection'];scans=marker.get('child_vulnerability_scans',[])
            for scan in scans:
                observations.append(_observation(row['_provenance']['scope'],target,scan['image'],scan)
                    if scan.get('status') in ('PASS','FAIL') else None)
            if graph.get('complete') is not True or len(scans)!=len(graph.get('children',[])):
                observations.append(None)
        else:
            observations.append(deepcopy(marker['observation']) if marker['complete'] is True
                or marker['status']=='FAIL' else None)
    result['observations']=observations
    result['complete']=bool(result['rows']) and all(r[MARKER]['complete'] for r in result['rows'])
    result['status']='FAIL' if any(r[MARKER]['status']=='FAIL' for r in result['rows']) else 'PASS' if result['complete'] else 'UNKNOWN'
    result['reason']=None if result['complete'] else 'selected_image_vulnerability_coverage_incomplete'
    return result


def collect(reader,transport,scopes,wanted,options,*,cli=trivy.DEFAULT_CLI):
    """Narrow Azure collector hook, entered only for the named selected check."""
    if KIND not in wanted:return
    metadata=selection_metadata(options,scopes)
    reader.acr_image_vulnerability_metadata=metadata
    if not enabled(options):return
    from . import selected_image_trivy_database_20261021 as database
    diagnostics={}
    metadata['image_database_diagnostics']=diagnostics
    with ExitStack() as lease_stack:
        db_cache=database.acquire(lease_stack,enabled=True,cancel=reader.check_cancelled,
            diagnostics=diagnostics)
        result=collect_native(reader,transport,scopes,options,db_cache=db_cache,cli=cli,
            database_check=(lambda _: {'fresh':False}) if db_cache is None else None,
            database_diagnostics=diagnostics)
    metadata[KIND+'_receipts']=result['receipts']
    metadata['image_vulnerability_scan']={'selected':True,
        'observations':deepcopy(result['observations'])}
    for scope in scopes:
        rows=[row for row in result['rows'] if row['_provenance']['scope']==scope]
        if not rows:continue
        def fetch(rows=rows):yield rows
        reader.run([(KIND,scope,'Microsoft.ContainerRegistry',fetch)])
