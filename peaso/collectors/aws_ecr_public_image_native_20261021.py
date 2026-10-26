"""Selected ECR Public digest inspection with native alias/account binding."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
import tempfile
import time

from peaso import container_image_archive_20261020 as archive
from peaso import oci_index_20261021 as oci_index
from peaso.aws_ecr_public_selection_20261021 import KIND, selected_targets
from peaso.secret_scanning import merge_leaks

SCHEMA = 'aws-selected-ecr-public-image-v1'
HOST = 'public.ecr.aws'
MAX_SECONDS = 600
MAX_NATIVE_CALLS = 3 * (oci_index.MAX_CHILDREN + 2)
MAX_SCAN = 64 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
WINDOW = 1024 * 1024
OVERLAP = 4096


class Incomplete(ValueError):
    """A stable local reason; raw provider responses never enter evidence."""


def identity(target):
    return 'ecr-public-image:' + hashlib.sha256(json.dumps(target, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _one(value, field):
    if type(value) is not dict or type(value.get(field)) is not list or len(value[field]) != 1 or value.get('nextToken'):
        raise Incomplete('native_binding_unavailable')
    row = value[field][0]
    if type(row) is not dict:
        raise Incomplete('native_binding_unavailable')
    return row


class NativeReader:
    """Six fixed SDK read calls in us-east-1, never custom endpoints or discovery."""
    def __init__(self, requests, session, account):
        from botocore.config import Config
        self.requests, self.account, self.calls = requests, account, []
        config = Config(connect_timeout=3, read_timeout=5,
            retries={'total_max_attempts': 1, 'mode': 'standard'},
            ignore_configured_endpoint_urls=True, use_fips_endpoint=False, use_dualstack_endpoint=False)
        self.client = session.client('ecr-public', region_name='us-east-1', config=config)

    def _call(self, operation, **arguments):
        self.requests.check_deadline()
        if len(self.calls) >= MAX_NATIVE_CALLS:
            raise Incomplete('native_call_bound')
        receipt = {'operation': 'ecr-public:' + operation, 'status': 'unavailable'}
        self.calls.append(receipt)
        with self.requests._lock:
            if self.requests.max_calls is not None and self.requests.calls >= self.requests.max_calls:
                raise Incomplete('native_call_bound')
            self.requests.calls += 1
        try:
            response = getattr(self.client, operation)(**arguments)
            self.requests.check_deadline()
            if type(response) is not dict or response.get('ResponseMetadata', {}).get('HTTPStatusCode') != 200:
                raise Incomplete('native_read_unavailable')
            receipt['status'] = 'collected'
            return response
        except Exception as exc:
            if getattr(exc, 'code', None) in ('collection_cancelled', 'intentional_scan_deadline', 'deadline_exceeded'):
                raise
            raise Incomplete('native_read_unavailable') from None

    def bind(self, target):
        account, alias, repo, digest = (target['scope'].split('/')[0], target['registry_alias'],
                                      target['repository_name'], target['image_digest'])
        registry = _one(self._call('describe_registries'), 'registries')
        expected_registry = f'arn:aws:ecr-public::{account}:registry/{account}'
        aliases = registry.get('aliases')
        if (registry.get('registryId') != account or account != self.account
                or registry.get('registryArn') != expected_registry
                or type(aliases) is not list or not 1 <= len(aliases) <= 16
                or len([a for a in aliases if type(a) is dict and a.get('name') == alias and a.get('status') == 'ACTIVE']) != 1):
            raise Incomplete('foreign_registry_alias')
        active = {a['name'] for a in aliases if type(a) is dict and a.get('status') == 'ACTIVE' and type(a.get('name')) is str}
        repository = _one(self._call('describe_repositories', registryId=account, repositoryNames=[repo]), 'repositories')
        uri = repository.get('repositoryUri')
        expected_repo_arn = f'arn:aws:ecr-public::{account}:repository/{repo}'
        if (repository.get('registryId') != account or repository.get('repositoryName') != repo
                or repository.get('repositoryArn') != expected_repo_arn or type(uri) is not str
                or not any(uri == f'{HOST}/{name}/{repo}' for name in active)):
            raise Incomplete('foreign_repository')
        detail = _one(self._call('describe_images', registryId=account, repositoryName=repo,
                                 imageIds=[{'imageDigest': digest}]), 'imageDetails')
        media = detail.get('imageManifestMediaType')
        size = detail.get('imageSizeInBytes')
        if (detail.get('registryId') != account or detail.get('repositoryName') != repo
                or detail.get('imageDigest') != digest or media not in oci_index.ALL_MANIFEST_TYPES
                or type(size) is not int or not 0 < size <= archive.MAX_COMPRESSED):
            raise Incomplete('foreign_or_unsupported_image')
        return {'account':account, 'registry_alias':alias, 'repository_name':repo,
                'image_digest':digest, 'registry_arn':expected_registry,
                'repository_arn':expected_repo_arn, 'manifest_media_type':media,
                'image_size':size}

    def close(self):
        try:
            self.client.close()
            return True
        except Exception:
            return False


def inspect(target, native, *, registry_factory=None, scanner=None, cancel=lambda:None,
            secret_enabled=True, trivy_enabled=False, trivy_runner=None, trivy_db=None,
            trivy_cli=None, redact_values=None):
    """Inspect an exact ECR Public digest and every bounded image-index child."""
    from .k8s_selected_registry_image_20261021 import RegistryReader, _scan
    registry_factory = registry_factory or RegistryReader
    scanner = scanner or _scan
    ident, digest = identity(target), target['image_digest']
    marker = {'schema':SCHEMA, 'identity':ident, 'selection':deepcopy(target),
              'native_before':None, 'native_after':None, 'native_stable':False,
              'secret_complete':False, 'vulnerability':None, 'leaks':[], 'parts':[],
              'registry_receipts':[], 'native_receipts':native.calls, 'reason':'unavailable',
              'graph':{'parent_digest':digest,'media_type':None,'children':[], 'complete':False},
              'child_vulnerability_scans':[]}
    leaks, parts, reader, before = [], marker['parts'], None, None
    is_index, vulnerability_results = False, []
    secret_gaps = set()
    deadline = time.monotonic() + MAX_SECONDS
    def check():
        cancel(); native.requests.check_deadline()
        if time.monotonic() >= deadline:
            raise Incomplete('image_deadline')
    def scan(raw, path, source):
        try:
            if redact_values is None:
                scanner(raw, path, source, check, leaks, parts)
            else:
                scanner(raw, path, source, check, leaks, parts, redact_values=redact_values)
        except ValueError as exc:
            if str(exc) != 'detectors_incomplete':
                raise
            secret_gaps.add('detectors_incomplete')
    try:
        before = native.bind(target)
        marker['native_before'] = before
        reader = registry_factory(HOST, target['registry_alias'] + '/' + target['repository_name'], check,
                                  authorization=None)
        parent_raw = reader.get('manifests', digest, archive.MAX_MANIFEST)
        parent_doc = archive.decode(parent_raw)
        if type(parent_doc) is not dict or parent_doc.get('mediaType') != before['manifest_media_type']:
            raise Incomplete('parent_manifest_media_mismatch')
        marker['graph']['media_type'] = parent_doc['mediaType']
        is_index = parent_doc['mediaType'] in oci_index.INDEX_TYPES
        source = {'resource_id':ident,'scope':target['scope'],'image_digest':digest}
        if is_index and secret_enabled:
            scan(parent_raw, ident+'.index', {**source,'location_kind':'image_index'})
        def fetch_child(child_digest, size, media_type):
            return reader.get('manifests', child_digest, archive.MAX_MANIFEST, size=size)
        for child in oci_index.children(parent_raw, digest, fetch_child, check=check):
            child_digest, manifest = child['digest'], child['raw']
            decoded = archive.decode(manifest)
            conf = archive.descriptor(decoded.get('config'), archive.CONFIGS, archive.MAX_CONFIG)
            descriptions = decoded.get('layers')
            if type(descriptions) is not list or not 1 <= len(descriptions) <= archive.MAX_LAYERS:
                raise Incomplete('layer_descriptors_unavailable')
            descriptions = [archive.descriptor(d, archive.LAYERS, archive.MAX_LAYER) for d in descriptions]
            if conf['size'] + sum(d['size'] for d in descriptions) > archive.MAX_COMPRESSED:
                raise Incomplete('compressed_image_bound')
            config = reader.get('blobs', conf['digest'], archive.MAX_CONFIG, size=conf['size'])
            if is_index:
                child_config = archive.decode(config)
                platform = child['platform']
                if (type(child_config) is not dict or child_config.get('os') != platform['os']
                        or child_config.get('architecture') != platform['architecture']
                        or 'variant' in platform and child_config.get('variant') != platform['variant']):
                    raise Incomplete('child_platform_config_mismatch')
            image = {'provider':'aws','scope':target['scope'],
                     'immutable_reference':f'{HOST}/{target["registry_alias"]}/{target["repository_name"]}@{child_digest}',
                     'manifest_digest':child_digest,'config_digest':conf['digest']}
            archive.identity(image)
            prefix = ident + ('.child-' + child_digest[7:23] if is_index else '')
            marker['graph']['children'].append({'digest':child_digest,'size':child['size'],
                'mediaType':child['mediaType'],'platform':child['platform'],'config_digest':conf['digest']})
            with tempfile.TemporaryDirectory(prefix='peaso-ecr-public-') as directory:
                layers = [reader.get('blobs', desc['digest'], archive.MAX_LAYER,
                                     size=desc['size'], destination=Path(directory)/f'layer-{i}')
                          for i, desc in enumerate(descriptions)]
                if secret_enabled:
                    scanned = [0]
                    scan(manifest, prefix+'.manifest', {**source,'source':child_digest,'location_kind':'manifest'})
                    scan(config, prefix+'.config', {**source,'source':child_digest,'location_kind':'configuration'})
                    config_strings, stack, nodes, size = [], [archive.decode(config)], 0, 0
                    while stack:
                        check(); value=stack.pop(); nodes += 1
                        if nodes > 20000:
                            raise Incomplete('config_json_bound')
                        if type(value) is str:
                            raw=value.encode('utf-8'); size += len(raw)+1
                            if size > archive.MAX_CONFIG*2:
                                raise Incomplete('config_json_bound')
                            config_strings.append(raw)
                        elif type(value) is dict:
                            stack.extend(reversed(list(value.keys())))
                            stack.extend(reversed(list(value.values())))
                        elif type(value) is list:
                            stack.extend(reversed(value))
                    if config_strings:
                        scan(b'\n'.join(config_strings),prefix+'.config-strings',
                             {**source,'source':child_digest,'location_kind':'configuration'})
                    def visit(name, stream, length, layer):
                        if length > MAX_FILE or scanned[0] + length > MAX_SCAN:
                            raise Incomplete('file_scan_bound')
                        path = prefix+f'.layer-{layer+1}.file-{len(parts)+1}'
                        origin = {**source,'source':child_digest,'layer':descriptions[layer]['digest'],'path':name}
                        scan(name.encode(), path+'.name', origin)
                        offset, overlap = 0, b''
                        while offset < length:
                            chunk = stream.read(min(WINDOW,length-offset))
                            if type(chunk) is not bytes or not chunk:
                                raise Incomplete('file_truncated')
                            if offset == 0 and (chunk.startswith((b'PK\x03\x04',b'\x1f\x8b',b'BZh',b'7z\xbc\xaf')) or chunk[257:262] == b'ustar'):
                                secret_gaps.add('nested_archive_uninspected')
                                return
                            offset += len(chunk); scanned[0] += len(chunk)
                            scan(overlap+chunk,path+f'.chunk-{offset}',origin)
                            try: text = chunk.decode('utf-8')
                            except UnicodeError:
                                secret_gaps.add('binary_file_uninspected')
                                return
                            if any(ord(c)<32 and c not in '\t\r\n' or ord(c)==127 for c in text):
                                secret_gaps.add('binary_file_uninspected')
                                return
                            overlap=(overlap+chunk)[-OVERLAP:]
                    archive.visit_files(image,manifest,config,layers,lambda *_:None,check,partial_callback=visit,stage=trivy_enabled)
                else:
                    archive.validate(image,manifest,config,layers,check,stage=trivy_enabled)
                if trivy_enabled:
                    if trivy_runner is None:
                        from peaso import trivy_container_runner_20261020 as trivy
                        trivy_runner, default_cli = trivy.scan_image, trivy.DEFAULT_CLI
                    else:
                        default_cli = '/usr/local/bin/trivy'
                    def verify():
                        if native.bind(target) != before:
                            raise Incomplete('native_image_changed')
                        return image
                    # Pinned Trivy reads an --input tar only in docker-save layout; an
                    # OCI layout tar fails ("index.json: not a directory") and stays UNKNOWN.
                    report = trivy_runner(image,manifest,config,layers,
                        native_verifier=verify,enabled=True,db_cache=trivy_db,cli=trivy_cli or default_cli,
                        cancel=check,archive_format='docker')
                    if type(report) is not dict or type(report.get('findings')) is not list:
                        raise Incomplete('vulnerability_result_unavailable')
                    vulnerability_results.append(report)
                    marker['child_vulnerability_scans'].append(deepcopy(report))
        marker['graph']['complete'] = True
        if trivy_enabled:
            if not is_index:
                marker['vulnerability'] = vulnerability_results[0]
        after = native.bind(target)
        marker['native_after'] = after
        if after != before:
            raise Incomplete('native_image_changed')
        marker['native_stable'] = True
        marker['secret_complete'] = bool(secret_enabled and not secret_gaps and marker['graph']['complete'] and parts and
                                         all(p['complete'] for p in parts))
        marker['reason'] = sorted(secret_gaps)[0] if secret_gaps else 'complete'
    except Exception as exc:
        if getattr(exc, 'code', None) in ('collection_cancelled', 'intentional_scan_deadline', 'deadline_exceeded'):
            raise
        marker['reason'] = str(exc) if type(exc) is Incomplete else 'image_inspection_unavailable'
    finally:
        if is_index and trivy_enabled and vulnerability_results:
            findings = [deepcopy(f) for value in vulnerability_results for f in value.get('findings',[])]
            finding_overflow = len(findings) > 10000
            if finding_overflow:
                findings = findings[:10000]
                marker['reason'] = 'finding_bound'
            fully_scanned = (marker['graph']['complete'] is True and
                not finding_overflow and
                len(vulnerability_results) == len(marker['graph']['children']) and
                all(v.get('complete') is True and v.get('scan_complete') is True and
                    v.get('coverage_status') == 'COMPLETE' and
                    v.get('database',{}).get('fresh') is True for v in vulnerability_results))
            marker['vulnerability'] = {'status':'FAIL' if findings else 'PASS' if fully_scanned else 'UNKNOWN',
                'findings':findings,'complete':fully_scanned,'scan_complete':fully_scanned,
                'coverage_status':'COMPLETE' if fully_scanned else 'UNKNOWN',
                'database':{'fresh':fully_scanned},
                'children':[{'digest':c['digest'],'status':v.get('status'),'complete':v.get('complete') is True}
                    for c,v in zip(marker['graph']['children'],vulnerability_results)]}
        merged = merge_leaks(leaks)
        bounded, locations = [], 0
        for leak in merged:
            if len(bounded) >= 256 or locations >= 2000:
                break
            row = deepcopy(leak)
            row['locations'] = row['locations'][:2000-locations]
            if row['locations']:
                bounded.append(row);locations += len(row['locations'])
        marker['leaks'] = merge_leaks(bounded)
        if len(merged) != len(bounded) or sum(len(v['locations']) for v in merged) > locations:
            marker['reason'] = 'finding_bound'
            marker['secret_complete'] = False
        if reader is not None:
            marker['registry_receipts'] = list(reader.receipts)
    return marker


def collect_scope(requests,session,account_identity,region,targets,*,secret_enabled,vuln_enabled,trivy_db=None):
    from .aws import ReadResult
    from . import aws_selected_configuration_secret_indicators as redaction
    selected = [t for t in targets if t['scope'] == account_identity['Account']+'/'+region]
    if not selected:
        return ReadResult([], 'empty')
    rows=[]
    for target in selected:
        native = None
        marker = None
        try:
            native = NativeReader(requests,session,account_identity['Account'])
            marker = inspect(target,native,cancel=requests.check_deadline,
                secret_enabled=secret_enabled,trivy_enabled=vuln_enabled,
                trivy_db=trivy_db,
                redact_values=lambda values:redaction.remember_matches(requests,values))
        except Exception as exc:
            if getattr(exc, 'code', None) in ('collection_cancelled', 'intentional_scan_deadline', 'deadline_exceeded'):
                raise
            marker = {'schema':SCHEMA,'identity':identity(target),
                      'selection':deepcopy(target),'native_before':None,'native_after':None,
                      'native_stable':False,'secret_complete':False,'vulnerability':None,
                      'leaks':[],'parts':[],'registry_receipts':[],
                      'native_receipts':native.calls if native else [],'reason':'native_unavailable'}
        finally:
            if native is not None and not native.close() and marker is not None:
                marker['native_stable']=False;marker['secret_complete']=False;marker['reason']='native_cleanup_unavailable'
        rows.append({'id':identity(target),'ECRPublicImageContent':deepcopy(marker)})
    complete=all(r['ECRPublicImageContent']['native_stable'] and
                 (not secret_enabled or r['ECRPublicImageContent']['secret_complete']) and
                 (not vuln_enabled or (r['ECRPublicImageContent']['vulnerability'] or {}).get('complete') is True)
                 for r in rows)
    return ReadResult(rows,'collected' if complete else 'partial',
                      None if complete else {'code':'selected_ecr_public_image_incomplete'})
