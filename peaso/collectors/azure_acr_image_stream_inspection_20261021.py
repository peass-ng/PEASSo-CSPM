"""Bounded private inspection of an exact ACR leaf or finite OCI index."""
from copy import deepcopy
from collections import Counter
import hashlib
import http.client
import ipaddress
import os
from pathlib import Path
import re
import shutil
import socket
import tempfile
import time
from types import MethodType
from urllib.parse import urlsplit

from peaso import container_image_archive_20261020 as archive
from peaso import oci_index_20261021 as oci_index
from peaso.secret_evidence import alias_path, scan_with_source, source_context
from peaso.secret_scanning import merge_leaks, scan_content
from peaso.secret_scanning_batch import prepared_content_batch, MAX_BATCH_ITEMS, MAX_BATCH_BYTES
from . import azure_acr_image_secret_indicators as native

WINDOW = 1024 * 1024
OVERLAP = 4096
MAX_FILE_SCAN = 64 * 1024 * 1024
MAX_IMAGE_SCAN = 512 * 1024 * 1024
ABORT_CODES = frozenset(('collection_cancelled', 'intentional_scan_deadline',
    'deadline_exceeded', 'scanner_deadline'))


def consistent_descriptors(descriptors):
    """A reused digest must keep the same size and media type."""
    seen = {}
    for descriptor in descriptors:
        digest = descriptor['digest']
        identity = (descriptor['size'], descriptor['mediaType'])
        if digest in seen and seen[digest] != identity:
            return False
        seen[digest] = identity
    return True


def complete_blob_receipts(rows, descriptor_groups):
    """Require a verified blob read for every manifest reference."""
    needed = Counter((d['digest'], d['size']) for group in descriptor_groups for d in group)
    observed = Counter((r.get('digest'), r.get('bytes')) for r in rows
        if r.get('operation') in ('blob', 'blob_data') and r.get('status') == 'collected'
        and r.get('http_status') == 200 and r.get('verified') is True and r.get('bound') is True)
    return all(observed[key] >= count for key, count in needed.items())


def _shared_location(location):
    """Bind one registry-issued redirect to one Azure Storage account host."""
    parsed = urlsplit(location) if isinstance(location, str) else None
    host = parsed.hostname if parsed is not None else None
    path = parsed.path if parsed is not None else ''
    if (not isinstance(location, str) or not 1 <= len(location) <= 8192
            or any(ord(char) <= 32 or ord(char) > 126 or char == '\\' for char in location)
            or host is None or not re.fullmatch(r'[a-z0-9]{3,24}\.blob\.core\.windows\.net', host)
            or parsed.scheme != 'https' or parsed.netloc != host or parsed.port is not None
            or parsed.username is not None or parsed.password is not None or parsed.fragment
            or not parsed.query or not re.fullmatch(r'/[A-Za-z0-9_./%~+@=-]{1,2048}', path)
            or path.startswith('//') or path.endswith('/')
            or any(part in ('.','..') for part in path[1:].split('/'))
            or re.search(r'%(?![0-9A-Fa-f]{2})|%2[fF]|%5[cC]|%2[eE]|%00', path)):
        raise native.Incomplete('unsupported_data_location')
    # Azure's signed storage path may contain an interior empty segment. Its
    # exact spelling is retained for the SAS signature and never persisted.
    return host, path+'?'+parsed.query


class _PublicPinnedHTTPSConnection(http.client.HTTPSConnection):
    """Resolve once, reject nonpublic answers, and retain the host for TLS SNI."""

    def connect(self):
        infos = socket.getaddrinfo(self.host, 443, type=socket.SOCK_STREAM)
        if (not infos or any(not ipaddress.ip_address(info[4][0]).is_global for info in infos)):
            raise native.Incomplete('nonpublic_data_address')
        last_error = None
        for family, socktype, protocol, _, address in infos:
            raw = socket.socket(family, socktype, protocol)
            try:
                raw.settimeout(self.timeout)
                raw.connect(address)
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                return
            except OSError as exc:
                last_error = exc
                raw.close()
        raise native.Incomplete('data_connection_unavailable') from last_error


def _pinned_request(self, host, route, operation, cap, *, body=None,
                    authorization=None, digest=None, size=None, redirect=False,
                    destination=None, shared_host=None):
    """Read a digest-bound blob with at most one credential-free redirect."""
    if self.state['calls'] >= native.MAX_CALLS:
        raise native.Incomplete('image_call_limit')
    if shared_host is not None and (host != shared_host or operation != 'blob_data'
            or body is not None or authorization is not None or redirect
            or digest is None or size is None):
        raise native.Incomplete('shared_data_binding')
    self.check(); self.state['calls'] += 1
    endpoint = ('arm' if host == native.ARM else 'registry' if host == self.host else
                'native_pinned_shared_data' if shared_host is not None else 'native_dedicated_data')
    receipt = {'id':'acr-read-'+str(len(self.receipts)+1), 'identity':self.ident,
        'scope':self.scope, 'method':'POST' if body is not None else 'GET',
        'operation':operation, 'endpoint':endpoint, 'status':'unavailable',
        'http_status':0, 'bytes':0, 'digest':digest, 'verified':False, 'bound':False}
    self.receipts.append(receipt)
    connection = response = None
    try:
        connection = _PublicPinnedHTTPSConnection(host, timeout=self.timeout())
        connection.set_debuglevel(0)
        headers = {'Accept-Encoding':'identity',
            'Accept':', '.join((native.OCI,native.DOCKER,native.oci_index.OCI_INDEX,
                native.oci_index.DOCKER_LIST)) if operation == 'manifest' else 'application/octet-stream'}
        if body is not None:
            headers.update({'Content-Type':'application/x-www-form-urlencoded',
                            'Content-Length':str(len(body))})
        if authorization is not None:headers['Authorization'] = 'Bearer '+authorization
        connection.request(receipt['method'], route, body=body, headers=headers)
        response = connection.getresponse(); receipt['http_status'] = response.status
        if response.status == 307 and redirect and shared_host is None:
            location = response.getheader('Location')
            if response.getheader('WWW-Authenticate') is not None:
                raise native.Incomplete('auth_challenge')
            try:
                rh, rr = native._location(location, self.data_hosts)
                pinned = None
            except native.Incomplete:
                if self.data_hosts:
                    raise native.Incomplete('unsupported_data_location')
                rh, rr = _shared_location(location)
                pinned = rh
            receipt.update(status='redirect', verified=True, bound=True)
            # The signed query remains only in this call. No registry bearer,
            # cookies, identity headers, or URL reach receipts or logs.
            return self.get(rh, rr, 'blob_data', cap, digest=digest, size=size,
                            destination=destination, shared_host=pinned)
        if (type(response.status) is not int or response.status != 200
                or response.getheader('WWW-Authenticate') is not None
                or response.getheader('Location') is not None):
            raise native.Incomplete('native_unavailable')
        if response.getheader('Content-Encoding') not in (None, '', 'identity'):
            raise native.Incomplete('encoded_response')
        length = response.getheader('Content-Length'); expected = None
        if length is not None:
            if not isinstance(length, str) or not re.fullmatch(r'[0-9]{1,10}', length):
                raise native.Incomplete('stream_length')
            expected = int(length)
            if expected > cap or size is not None and expected != size:
                raise native.Incomplete('stream_length')
        header_digest = response.getheader('Docker-Content-Digest')
        if header_digest is not None and (digest is None or header_digest != digest):
            raise native.Incomplete('digest_header')
        output = None; created = False; raw = bytearray(); count = 0
        checksum = hashlib.sha256()
        try:
            if destination is not None:
                if (not isinstance(destination, Path) or not destination.is_absolute()
                        or size is None or shutil.disk_usage(destination.parent).free < size + 256*1024*1024):
                    raise native.Incomplete('scratch_disk_bound')
                fd = os.open(destination, os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0), 0o600)
                created = True; output = os.fdopen(fd, 'wb')
            while True:
                timeout = self.timeout()
                if getattr(connection, 'sock', None) is not None:
                    connection.sock.settimeout(timeout)
                block = response.read(min(16384, cap+1-count))
                if not isinstance(block, bytes):raise native.Incomplete('stream_type')
                count += len(block); self.state['bytes'] += len(block); receipt['bytes'] += len(block)
                if self.state['bytes'] > native.MAX_TOTAL or count > cap or size is not None and count > size:
                    raise native.Incomplete('stream_bound')
                if not block:break
                checksum.update(block)
                if output is None:raw.extend(block)
                else:
                    if shutil.disk_usage(destination.parent).free < len(block)+256*1024*1024:
                        raise native.Incomplete('scratch_disk_bound')
                    output.write(block)
            self.check()
            if (not count or expected is not None and count != expected
                    or size is not None and count != size
                    or digest is not None and 'sha256:'+checksum.hexdigest() != digest):
                raise native.Incomplete('digest_or_truncation')
            if output is not None:output.close(); output = None
        except BaseException:
            if output is not None:output.close()
            if created:destination.unlink(missing_ok=True)
            raise
        receipt.update(status='collected', verified=True, bound=digest is not None)
        return destination if destination is not None else bytes(raw)
    except Exception as exc:
        if (type(exc).__name__ == 'AzureReadError'
                and getattr(exc, 'code', None) in ('collection_cancelled','deadline_exceeded')):
            raise
        raise native.Incomplete('native_image_read_unavailable') from None
    finally:
        if response is not None:response.close()
        if connection is not None:connection.close()


def enable_pinned_shared_data(reader):
    """Install the current transport on this selected image reader only."""
    if type(reader) is not native.Reader:
        raise native.Incomplete('reader_binding')
    reader.request = MethodType(_pinned_request, reader)


def _abort_code(exc):
    code = getattr(exc, 'code', None)
    if code is None and isinstance(exc, native.Incomplete) and exc.args:
        code = exc.args[0]
    return type(code) is str and code in ABORT_CODES


def inspect_image(reader):
    enable_pinned_shared_data(reader)
    parent = reader.target['digest']
    marker = {'schema':native.SCHEMA,'kind':native.KIND,'identity':reader.ident,
        'scope':reader.scope,'complete':False,'verification':'not_attempted',
        'manifest_digest':parent,'descriptors':[], 'layers_scanned':[],
        'parts':[],'leaks':[],'source_requests':[], 'mode':None,
        'auth_audience':None,'expanded_bytes':0,'members':0,'regular_files':0}
    start=len(reader.receipts)
    leaks=[];verified=[];scanned=0;scan_partial=False;skipped_files=0
    index_mode=False
    try:
        token=reader.authenticate()
        marker['mode'],marker['auth_audience']=reader.mode,reader.auth_audience
        parent_raw=reader.blob('manifests',parent,native.MAX_MANIFEST,token)
        parent_doc=archive.decode(parent_raw)
        index_mode=type(parent_doc) is dict and parent_doc.get('mediaType') in oci_index.INDEX_TYPES
        if index_mode:
            marker['graph']={'parent_digest':parent,'media_type':parent_doc['mediaType'],
                             'children':[],'complete':False}
            marker['child_inspections']=[]
        def scan(payload,path,layer,*,native_document=None,original_path=None,child_digest=None):
            reader.check()
            remaining=reader.state['deadline']-time.monotonic()
            if remaining<1:raise native.Incomplete('scanner_deadline')
            from .azure_selected_secret_integration_20261020 import remember
            with source_context(resource_id=reader.ident,scope=reader.scope,image_digest=parent,
                    child_digest=child_digest,layer=layer,path=original_path or path,
                    location_kind='configuration' if native_document is not None else 'file',
                    native=native_document):
                if original_path is not None:alias_path(path,original_path)
                outcome=scan_with_source(scan_content,payload,path,source={},timeout=min(30,remaining),
                    _redact_values=lambda values:remember(reader.reader,'acr_image_secret_redactions',values))
            leaks.extend(outcome['leaks'])
            if len(leaks)>native.MAX_LEAKS or sum(len(l['locations']) for l in leaks)>native.MAX_LOCATIONS:
                raise native.Incomplete('leak_bound')
            if len(marker['parts'])>=native.MAX_PARTS:raise native.Incomplete('part_bound')
            marker['parts'].append({'part':path.removeprefix(reader.ident+'.'),
                'bytes':len(payload),'complete':outcome['complete'],'engines':outcome['engines']})
            if outcome['complete'] is not True:raise native.Incomplete('scanners_incomplete')
        if index_mode:
            scan(parent_raw,reader.ident+'.index',parent,native_document=parent_doc)
        def fetch(child_digest,size,media_type):
            # The Reader constructs the route from the selected repository and
            # exact child digest; no descriptor URL or second origin is accepted.
            return reader.blob('manifests',child_digest,native.MAX_MANIFEST,token,size)
        for child in oci_index.children(parent_raw,parent,fetch,check=reader.check):
            digest=child['digest'];manifest_raw=child['raw']
            manifest=archive.decode(manifest_raw)
            if (type(manifest) is not dict or set(manifest)-{'schemaVersion','mediaType','config','layers','annotations'}
                    or type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion']!=2
                    or manifest.get('mediaType') not in oci_index.LEAF_TYPES):
                raise native.Incomplete('unsupported_leaf_manifest')
            config=native._descriptor(manifest['config'],native.CONFIG_TYPES,native.MAX_CONFIG)
            layers=manifest.get('layers')
            if type(layers) is not list or not 1<=len(layers)<=native.MAX_LAYERS:
                raise native.Incomplete('layers_unavailable')
            layers=[native._descriptor(d,native.TAR_TYPES,native.MAX_LAYER) for d in layers]
            # A manifest may reference the same immutable layer more than once.
            # Keep every occurrence in order and charge each against the bound.
            if (not consistent_descriptors([config]+layers)
                    or sum(d['size'] for d in [config]+layers)>native.MAX_IMAGE):
                raise native.Incomplete('compressed_image_bound')
            prefix=reader.ident+('.child-'+digest[7:] if index_mode else '')
            record={'digest':digest,'descriptors':deepcopy([config]+layers),
                'layers_scanned':[],'parts':[],'expanded_bytes':0,'members':0,'regular_files':0,
                'scan_partial':False,'skipped_files':0}
            if index_mode:
                marker['graph']['children'].append({'digest':digest,'size':child['size'],
                    'mediaType':child['mediaType'],'platform':child['platform'],
                    'config_digest':config['digest']})
            else:
                marker['descriptors']=deepcopy(record['descriptors'])
            raw=reader.blob('blobs',config['digest'],native.MAX_CONFIG,token,config['size'])
            decoded=archive.decode(raw)
            if (type(decoded) is not dict or set(decoded)&{'error','nextLink','partial','_partial','_coverage','resultTruncated'}
                    or decoded.get('os')!='linux' or decoded.get('architecture') not in ('amd64','arm64')
                    or type(decoded.get('rootfs')) is not dict or decoded['rootfs'].get('type')!='layers'
                    or type(decoded['rootfs'].get('diff_ids')) is not list
                    or len(decoded['rootfs']['diff_ids'])!=len(layers)
                    or any(type(d) is not str or not native.DIGEST.fullmatch(d)
                           for d in decoded['rootfs']['diff_ids'])):
                raise native.Incomplete('unsupported_rootfs')
            if index_mode and (decoded['os']!=child['platform']['os']
                    or decoded['architecture']!=child['platform']['architecture']
                    or 'variant' in child['platform'] and decoded.get('variant')!=child['platform']['variant']):
                raise native.Incomplete('child_platform_config_mismatch')
            image_identity={'provider':'azure','scope':reader.scope,
                'immutable_reference':reader.host+'/'+reader.target['repository']+'@'+digest,
                'manifest_digest':digest,'config_digest':config['digest']}
            archive.identity(image_identity)
            if not index_mode:verified=[parent,config['digest']]
            before_parts=len(marker['parts'])
            scan(manifest_raw,prefix+'.manifest',digest,native_document=manifest,child_digest=digest)
            with source_context(resource_id=reader.ident,scope=reader.scope,
                    image_digest=parent,child_digest=digest,layer=config['digest']):
                config_outcome=native._scan_json(raw,decoded,prefix+'.config',reader)
            leaks.extend(config_outcome['leaks'])
            marker['parts'].append({'part':(prefix+'.config').removeprefix(reader.ident+'.'),
                'bytes':len(raw),'complete':True,'engines':config_outcome['engines']})
            marker['expanded_bytes']+=len(raw);record['expanded_bytes']=len(raw)
            nodes={};path_budget=[0];budget=[len(raw)]
            pending=[];pending_bytes=0;pending_charge=0
            def partial_file(file):
                nonlocal scan_partial,skipped_files
                if file['failed']:return
                complete_parts=[p for p in marker['parts'][file['parts']:]
                    if p.get('complete') is True]
                marker['parts'][file['parts']:]=complete_parts
                completed_paths={reader.ident+'.'+p['part'] for p in complete_parts}
                kept=[]
                for leak in leaks[file['leaks']:]:
                    locations=[loc for loc in leak.get('locations',())
                        if loc.get('path') in completed_paths]
                    if locations:kept.append({**leak,'locations':locations})
                leaks[file['leaks']:]=kept
                file['failed']=True
                scan_partial=True;record['scan_partial']=True
                skipped_files+=1;record['skipped_files']+=1
            def flush():
                nonlocal pending,pending_bytes,pending_charge,scanned
                if not pending:return
                reader.check()
                remaining=reader.state['deadline']-time.monotonic()
                if remaining<1:raise native.Incomplete('scanner_deadline')
                entries,pending=pending,[]
                pending_bytes=pending_charge=0
                with prepared_content_batch([(payload,path) for payload,path,_,_,_,_ in entries],
                        timeout=min(30,remaining)):
                    for payload,path,layer,options,file,charge in entries:
                        if file['failed']:continue
                        if file['parts'] is None:
                            file['parts']=len(marker['parts']);file['leaks']=len(leaks)
                        scanned+=charge
                        try:scan(payload,path,layer,**options)
                        except Exception as exc:
                            if isinstance(exc,native.Incomplete) and str(exc)=='scanners_incomplete':
                                partial_file(file)
                            else:
                                # Reading ahead must not advance public counters
                                # beyond the file the serial scanner would stop on.
                                marker['regular_files']=file['global_number']
                                record['regular_files']=file['number']
                                raise
            def queue(payload,path,layer,file,*,charge=0,**options):
                nonlocal pending_bytes,pending_charge
                reader.check()
                if file['failed']:return
                if pending and (len(pending)>=MAX_BATCH_ITEMS
                        or pending_bytes+len(payload)>MAX_BATCH_BYTES):
                    flush()
                if file['failed']:return
                pending.append((payload,path,layer,options,file,charge))
                pending_bytes+=len(payload);pending_charge+=charge
            with tempfile.TemporaryDirectory(prefix='peaso-azure-acr-') as directory:
                root=Path(directory)
                for number,(layer,diff) in enumerate(zip(layers,decoded['rootfs']['diff_ids'])):
                    reader.check();blob=root/('blob-'+str(number))
                    reader.blob('blobs',layer['digest'],native.MAX_LAYER,token,layer['size'],destination=blob)
                    expanded=root/('expanded-'+str(number)+'.tar')
                    with expanded.open('xb') as output:
                        size=archive._expand(blob,layer,diff,output,budget,reader.check)
                    blob.unlink()
                    count=archive._tar_members(expanded,nodes,marker['members'],reader.check,number,path_budget)
                    marker['expanded_bytes']+=size;record['expanded_bytes']+=size
                    marker['members']=count;record['members']=count
                    budget[0]+=size;verified.append(layer['digest'])
                    marker['layers_scanned'].append(layer['digest']);record['layers_scanned'].append(layer['digest'])
                    for name,node in sorted(nodes.items()):
                        if node[0] not in ('file','hardlink') or node[1][3]!=number:continue
                        marker['regular_files']+=1;record['regular_files']+=1
                        base=prefix+'.layer-'+str(number+1)+'.member-'+str(record['regular_files'])
                        file={'parts':None,'leaks':None,'failed':False,
                              'number':record['regular_files'],'global_number':marker['regular_files']}
                        try:
                            queue(name.encode('utf-8'),base+'.name',layer['digest'],file,original_path=name,child_digest=digest)
                            def observe(original,stream,length,layer_index):
                                if length>MAX_FILE_SCAN or scanned+pending_charge+length>MAX_IMAGE_SCAN:
                                    flush()
                                    if file['failed']:return
                                    if length>MAX_FILE_SCAN or scanned+length>MAX_IMAGE_SCAN:
                                        raise native.Incomplete('file_scan_bound')
                                offset=0;overlap=b'';chunk_no=0
                                while offset<length:
                                    reader.check();chunk=stream.read(min(WINDOW,length-offset))
                                    if type(chunk) is not bytes or not chunk:raise native.Incomplete('file_truncation')
                                    if offset==0 and (chunk.startswith((b'PK\x03\x04',b'\x1f\x8b',b'BZh',b'\xfd7zXZ',
                                            b'7z\xbc\xaf',b'Rar!',b'\x28\xb5\x2f\xfd')) or chunk[257:262]==b'ustar'):
                                        raise native.Incomplete('nested_archive_uninspected')
                                    if any((value<32 and value not in (9,10,13)) or value==127 for value in chunk):
                                        raise native.Incomplete('binary_file_uninspected')
                                    chunk_no+=1;offset+=len(chunk)
                                    queue(overlap+chunk,base+'.chunk-'+str(chunk_no),layer['digest'],file,
                                         charge=len(chunk),original_path=original,child_digest=digest)
                                    if file['failed']:return
                                    overlap=(overlap+chunk)[-OVERLAP:]
                                if length==0:queue(b'',base+'.chunk-1',layer['digest'],file,original_path=original,child_digest=digest)
                            archive._visit_node(name,node,observe,reader.check)
                        except Exception as exc:
                            if _abort_code(exc):raise
                            # A later binary/archive error must not discard
                            # earlier complete chunks queued for this file.
                            flush()
                            if file['failed']:continue
                            if not isinstance(exc,native.Incomplete) or str(exc) not in (
                                    'nested_archive_uninspected','binary_file_uninspected','scanners_incomplete'):
                                raise
                            partial_file(file)
                    flush()
            if not record['regular_files']:raise native.Incomplete('no_layer_files')
            record['parts']=[p['part'] for p in marker['parts'][before_parts:]]
            if index_mode:marker['child_inspections'].append(record)
        if index_mode:
            marker['graph']['complete']=True
            # Rebind ARM registry identity, tenant and parent bytes after every
            # child. Child bytes are immutable SHA-256 verified by the Reader.
            after=reader.authenticate()
            again=reader.blob('manifests',parent,native.MAX_MANIFEST,after)
            if again!=parent_raw:raise native.Incomplete('parent_manifest_changed')
        elif not marker['regular_files']:
            raise native.Incomplete('no_layer_files')
        marker['leaks']=merge_leaks(leaks);marker['complete']=not scan_partial
        if scan_partial:
            marker['scan_partial']=True;marker['skipped_files']=skipped_files
    except Exception as exc:
        if _abort_code(exc):
            raise
        marker['complete']=False
        marker['parts']=[part for part in marker['parts'] if part.get('complete') is True]
        if index_mode:
            marker['graph']['complete']=False
            # Only complete children can substantiate an incomplete positive.
            witnessed={reader.ident+'.'+name for c in marker['child_inspections'] for name in c['parts']}
            if marker['parts'] and marker['parts'][0].get('part')=='index':witnessed.add(reader.ident+'.index')
        else:
            witnessed={reader.ident+'.'+part['part'] for part in marker['parts']}
        retained=[]
        for leak in leaks:
            locations=[loc for loc in leak.get('locations',[]) if loc.get('path') in witnessed]
            if locations:retained.append({**leak,'locations':locations})
        if retained:
            try:marker['leaks']=merge_leaks(retained)
            except (TypeError,ValueError,KeyError,AttributeError):marker['leaks']=[]
    marker['source_requests']=[r['id'] for r in reader.receipts[start:]]
    if not marker['complete']:marker['inspected_digests']=verified
    return {'id':reader.ident,native.MARKER:marker,
        '_provenance':{'scope':reader.scope,'source_requests':list(marker['source_requests'])}}
