"""Explicit standalone immutable GCP registry images: native reads and offline Trivy.

No workload deployment claim. Registry project/repository/image metadata is read
before and after the bounded content download. The scanner receives no cloud
credentials. Disabled or invalid selections create no session and make no calls.
"""
from copy import deepcopy
import hashlib
import json
import re
import time
import tempfile
from pathlib import Path
from urllib.parse import quote
from . import gcp_cloudrun_v2_job_declared_images_20261020 as metadata
from . import gcp_image_secret_indicators as native
from .gcp_registry_image_uri import parse
from .gcp_job_trivy_stream_20261021 import CaptureReader, Reader, _read_image, sha256, MAX_IMAGE, MAX_LAYER
from .gcp_image_stream_inspection_20261021 import _interrupt
from peaso import container_image_archive_20261020 as archive
from peaso import oci_index_20261021 as oci_index
from peaso import trivy_container_runner_20261020 as trivy

SCHEMA = 'gcp-selected-registry-image-vulnerabilities-v1'
MAX_METADATA_CALLS = 24
MAX_METADATA_BODY = metadata.MAX_METADATA_BODY
MAX_METADATA_BYTES = MAX_METADATA_CALLS * MAX_METADATA_BODY
_shape = metadata._shape
_require = archive.require

class MetadataReader:
    """No transport cache: every revalidation is a new bounded HTTP GET."""
    def __init__(self, transport, session, end, scope):
        self.transport, self.session, self.end, self.scope = transport, session, end, scope
        self.calls, self.bytes, self.records, self.captures = 0, 0, [], []

    def check(self):
        self.transport.check_cancelled()
        _require(time.monotonic() < self.end, 'proposal_deadline')

    def get(self, url, fields):
        self.check()
        _require(self.calls < MAX_METADATA_CALLS, 'metadata_call_bound')
        receipt = {'method': 'GET', 'url': url, 'scope': self.scope,
                   'query': {'fields': fields}, 'operation': 'artifactregistry_selected_image_metadata_get',
                   'status': 'unavailable', 'http_attempts': 0}
        response, body = None, None
        try:
            with self.transport.lock:
                self.transport.check_cancelled()
                _require(self.transport.max_calls is None or self.transport.calls < self.transport.max_calls,
                         'native_call_budget')
                self.transport.calls += 1
            self.calls += 1
            authorization = self.transport.credentials.headers().get('Authorization')
            _require(type(authorization) is str and re.fullmatch(r'Bearer [A-Za-z0-9._~+/-]+=*', authorization),
                     'native_access_token_unavailable')
            if hasattr(self.session, 'cookies'):
                self.session.cookies.clear()
            receipt['http_attempts'] = 1
            response = self.session.request('GET', url, params={'fields': fields},
                headers={'Authorization': authorization, 'Accept': 'application/json',
                         'Accept-Encoding': 'identity'}, stream=True, allow_redirects=False,
                timeout=min(10, self.transport.timeout, max(.001, self.end - time.monotonic())))
            receipt['http_status'] = response.status_code
            # requests includes params in response.url; compare the exact prepared URL.
            import requests
            expected = requests.Request('GET', url, params={'fields': fields}).prepare().url
            _require(response.status_code == 200 and response.url == expected and not response.history
                     and response.headers.get('Content-Encoding', 'identity') == 'identity'
                     and response.headers.get('WWW-Authenticate') is None, 'metadata_http_unavailable')
            length = response.headers.get('Content-Length')
            _require(length is None or length.isdecimal() and int(length) <= MAX_METADATA_BODY,
                     'metadata_length_bound')
            output = bytearray()
            for chunk in response.iter_content(chunk_size=8192):
                self.check()
                _require(type(chunk) is bytes, 'invalid_metadata_stream')
                self.bytes += len(chunk)
                _require(len(output) + len(chunk) <= MAX_METADATA_BODY and self.bytes <= MAX_METADATA_BYTES,
                         'metadata_byte_bound')
                output.extend(chunk)
            _require(length is None or len(output) == int(length), 'metadata_truncation')
            body = native._json(bytes(output))
            _shape(body, fields)
            receipt.update(status='collected', bytes=len(output),
                           body_sha256=hashlib.sha256(output).hexdigest())
            return body
        finally:
            if response is not None:
                if response.status_code in (401, 403):
                    receipt['status'] = 'denied'
                response.close()
            with self.transport.lock:
                if not hasattr(self.transport, 'evidence'):
                    self.transport.evidence = []
                receipt['id'] = 'request-' + str(len(self.transport.evidence) + 1)
                self.transport.evidence.append(receipt)
                self.records.append(deepcopy(receipt))
                if receipt['status'] == 'collected':
                    self.captures.append({'source_request': receipt['id'], 'body': deepcopy(body)})


def normalize_selection(selectors, scope):
    archive.require(type(scope) is str and re.fullmatch(r'projects/[a-z][a-z0-9-]{4,61}[a-z0-9]', scope),
                    'exact_project_required')
    refs = native.normalize_selected(selectors, scope)
    return [uri.removeprefix('https://') for uri in refs]


def requests_for(reference, scope):
    _, repository, _, image_id = parse(reference)
    archive.require(repository.startswith(scope + '/'), 'foreign_project')
    return [
        ('https://cloudresourcemanager.googleapis.com/v3/' + scope, metadata.PROJECT_FIELDS),
        ('https://artifactregistry.googleapis.com/v1/' + repository, metadata.REPO_FIELDS),
        ('https://artifactregistry.googleapis.com/v1/' + repository + '/dockerImages/'
         + quote(image_id, safe=''), metadata.IMAGE_FIELDS),
    ]


def bind(reference, scope, bodies):
    archive.require(type(bodies) is list and len(bodies) == 3, 'native_metadata_required')
    project, repository, image = bodies
    uri, repo, digest, image_id = parse(reference)
    archive.require(project.get('projectId') == scope.split('/')[1]
                    and project.get('state') == 'ACTIVE'
                    and type(project.get('name')) is str
                    and re.fullmatch(r'projects/[0-9]+', project['name']), 'project_identity_mismatch')
    archive.require(repository.get('name') == repo and repository.get('format') == 'DOCKER'
                    and repository.get('mode') in (None, 'STANDARD_REPOSITORY'),
                    'repository_identity_mismatch')
    prefix = repo + '/dockerImages/'
    archive.require(image.get('name') in (prefix + image_id, prefix + quote(image_id, safe=''))
                    and image.get('uri') == reference
                    and image.get('mediaType') in oci_index.ALL_MANIFEST_TYPES,
                    'image_identity_mismatch')
    row = {**image, 'repository': repo, 'digest': digest}
    archive.require(native.bind_image(row, scope, [repository], [project]) == (uri, repo, digest),
                    'native_image_join_mismatch')
    return row


def _fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


class IndexCaptureReader(CaptureReader):
    """Keep the existing authenticated reader while retaining bounded child blobs."""
    def get(self, uri, category, digest, cap, size=None):
        archive.require(category in ('manifests', 'blobs') and type(uri) is str
                        and self._uri in (None, uri), 'single_native_image_required')
        key = category, digest
        if cap <= native.MAX_CONFIG:
            value = self.reader.get(uri, category, digest, cap, size)
            archive.require(type(value) is bytes and archive.sha(value) == digest,
                            'native_read_digest_mismatch')
            count = len(value)
        else:
            archive.require(category == 'blobs' and type(size) is int
                            and 0 < size <= MAX_LAYER and cap <= MAX_LAYER,
                            'bounded_layer_capture_required')
            matches = []
            for (kind, _), raw in self._blobs.items():
                if kind != 'manifests':
                    continue
                document = archive.decode(raw)
                if document.get('mediaType') not in oci_index.LEAF_TYPES:
                    continue
                matches.extend(item for item in document.get('layers', [])
                    if item.get('digest') == digest and item.get('size') == size)
            archive.require(bool(matches), 'child_layer_descriptor_required')
            descriptor = archive.descriptor(matches[0], archive.LAYERS, MAX_LAYER)
            if self._scratch is None:
                self._scratch = tempfile.TemporaryDirectory(prefix='peaso-gcp-trivy-index-')
            path = Path(self._scratch.name) / ('blob-' + str(len(self._reads)))
            value = self.reader.get_layer(uri, descriptor, path)
            count = size
        self._uri = uri
        if key not in self._blobs:
            self._total += count
            archive.require(self._total <= native.MAX_IMAGES * MAX_IMAGE,
                            'retained_index_byte_bound')
            self._blobs[key] = value
        else:
            archive.require(sha256(self._blobs[key], self.check).digest()
                            == sha256(value, self.check).digest(), 'duplicate_digest_changed')
        rid = self.reader.request_ids[-1]
        records = [r for r in self.reader.transport.evidence if r.get('id') == rid]
        archive.require(len(records) == 1 and records[0].get('status') == 'collected'
                        and records[0].get('method') == 'GET'
                        and records[0].get('operation') == 'artifactregistry.registry_content_get'
                        and records[0].get('category') == category
                        and records[0].get('digest') == digest, 'native_read_receipt_mismatch')
        self._reads.append((rid, key))
        return value


def _read_index(reference, scope, before, captured, *, runner, db_cache, cli, timeout,
                scratch_parent):
    """Scan each verified child as it arrives so a later failure keeps prior findings."""
    row = bind(reference, scope, before)
    uri, repo, parent_digest = native.bind_image(row, scope, [before[1]], [before[0]])
    parent_raw = captured.get(uri, 'manifests', parent_digest, native.MAX_MANIFEST)
    parent_doc = archive.decode(parent_raw)
    archive.require(parent_doc.get('mediaType') == row.get('mediaType')
                    and parent_doc['mediaType'] in oci_index.INDEX_TYPES,
                    'selected_index_required')
    graph = {'parent_digest': parent_digest, 'media_type': parent_doc['mediaType'],
             'parent_source_request': captured._reads[-1][0], 'children': [],
             'tail_reads': [], 'complete': False}
    scans = []
    try:
        def fetch(digest, size, _media_type):
            return captured.get(uri, 'manifests', digest, native.MAX_MANIFEST, size)
        for child in oci_index.children(parent_raw, parent_digest, fetch, check=captured.check):
            start = len(captured._reads) - 1
            document = archive.decode(child['raw'])
            config_desc = archive.descriptor(document['config'], archive.CONFIGS, archive.MAX_CONFIG)
            layers = document['layers']
            archive.require(type(layers) is list and 1 <= len(layers) <= archive.MAX_LAYERS,
                            'child_layers_required')
            layers = [archive.descriptor(part, archive.LAYERS, archive.MAX_LAYER) for part in layers]
            archive.require(sum(d['size'] for d in [config_desc] + layers) <= MAX_IMAGE,
                            'child_compressed_bound')
            config = captured.get(uri, 'blobs', config_desc['digest'], archive.MAX_CONFIG,
                                  config_desc['size'])
            decoded = archive.decode(config)
            platform = child['platform']
            archive.require(decoded.get('os') == platform['os']
                            and decoded.get('architecture') == platform['architecture']
                            and ('variant' not in platform or decoded.get('variant') == platform['variant']),
                            'child_config_platform_mismatch')
            from .gcp_layer_overlap_20261026 import read_layers
            prebuilt = read_layers(captured, uri, layers, MAX_LAYER, scope, child['digest'],
                                   config_desc['digest'])
            vars(captured).pop('prebuilt', None)
            payloads = [captured._blobs[('blobs', part['digest'])] for part in layers]
            child_ref = reference.rsplit('@', 1)[0] + '@' + child['digest']
            identity = archive.identity({'provider': 'gcp', 'scope': scope,
                'immutable_reference': child_ref, 'manifest_digest': child['digest'],
                'config_digest': config_desc['digest']})
            keys = [('manifests', child['digest']), ('blobs', config_desc['digest'])] + [
                ('blobs', part['digest']) for part in layers]
            ids = [rid for rid, key in captured._reads[start:] if key in keys]
            archive.require(len(ids) == len(keys) and [key for _, key in captured._reads[start:]] == keys,
                            'child_read_sequence_required')
            def verify_child(identity=identity, child_raw=child['raw'], config=config,
                             payloads=payloads, keys=keys, ids=ids, prebuilt=[prebuilt]):
                captured.check()
                archive.require([key for rid, key in captured._reads if rid in ids] == keys,
                                'child_read_sequence_changed')
                archive.require(all(sha256(captured._blobs[key], captured.check).hexdigest() == key[1][7:]
                                    for key in keys), 'child_retained_bytes_changed')
                archive.validate(identity, child_raw, config, payloads, captured.check, stage=True,
                                 prebuilt=prebuilt.pop() if prebuilt else None)
                return identity
            verify_child()
            outcome = runner(identity, child['raw'], config, payloads,
                native_verifier=verify_child, enabled=True, db_cache=db_cache, cli=cli,
                archive_format='docker', timeout=timeout, cancel=captured.check,
                scratch_parent=scratch_parent)
            archive.require(type(outcome) is dict and outcome.get('image') == identity
                            and outcome.get('status') in ('PASS', 'FAIL', 'UNKNOWN')
                            and type(outcome.get('complete')) is bool
                            and type(outcome.get('findings')) is list
                            and (outcome['status'] == 'FAIL') == bool(outcome['findings']),
                            'child_scan_identity_or_status_mismatch')
            descriptor = {key: child[key] for key in ('digest', 'size', 'mediaType', 'platform')}
            descriptor.update(config=config_desc, layers=layers, source_requests=ids,
                              status=outcome['status'], complete=outcome['complete'],
                              scan_complete=outcome.get('scan_complete') is True,
                              database_fresh=outcome.get('database', {}).get('fresh') is True)
            graph['children'].append(descriptor)
            scans.append((outcome, verify_child))
        graph['complete'] = True
    except Exception as exc:
        if _interrupt(exc):
            raise
        pass
    committed = 1 + sum(len(child['source_requests']) for child in graph['children'])
    graph['tail_reads'] = [{'id': rid, 'category': key[0], 'digest': key[1]}
                           for rid, key in captured._reads[committed:]]
    return graph, scans


def scan_captured(reference, scope, before, after, captured, metadata_reader, *, runner,
                  db_cache=None, cli=trivy.DEFAULT_CLI, timeout=trivy.MAX_SECONDS,
                  scratch_parent=None):
    """No trust verdict cache: reconstruct bindings and rehash owned bytes per call."""
    archive.require(before == after, 'metadata_changed')
    row = bind(reference, scope, before)
    uri, _, digest = native.bind_image(row, scope, [before[1]], [before[0]])
    archive.require(captured._uri == uri, 'captured_image_mismatch')
    records, captures = metadata_reader.records, metadata_reader.captures
    expected = requests_for(reference, scope) * 2
    archive.require(len(records) == len(captures) == 6, 'all_metadata_receipts_required')
    seen = set()
    for record, capture, request, body in zip(records, captures, expected, before + after):
        archive.require(record.get('id') not in seen and type(record.get('id')) is str
                        and capture == {'source_request': record['id'], 'body': body}
                        and record.get('method') == 'GET' and record.get('url') == request[0]
                        and record.get('query') == {'fields': request[1]}
                        and record.get('operation') == 'artifactregistry_selected_image_metadata_get'
                        and record.get('scope') == scope and record.get('status') == 'collected'
                        and record.get('http_status') == 200 and record.get('http_attempts') == 1
                        and type(record.get('bytes')) is int and 0 < record['bytes'] <= MAX_METADATA_BODY
                        and type(record.get('body_sha256')) is str
                        and re.fullmatch(r'[0-9a-f]{64}', record['body_sha256']), 'metadata_receipt_mismatch')
        seen.add(record['id'])
    archive.require(all(records[i]['body_sha256'] == records[i + 3]['body_sha256']
                        and records[i]['bytes'] == records[i + 3]['bytes'] for i in range(3)),
                    'metadata_wire_changed')
    manifest = captured._blobs[('manifests', digest)]
    decoded = archive.decode(manifest)
    config_desc = archive.descriptor(decoded['config'], archive.CONFIGS, archive.MAX_CONFIG)
    layers = decoded['layers']
    archive.require(type(layers) is list and 1 <= len(layers) <= archive.MAX_LAYERS, 'all_layers_required')
    layers = [archive.descriptor(d, archive.LAYERS, archive.MAX_LAYER) for d in layers]
    config = captured._blobs[('blobs', config_desc['digest'])]
    payloads = [captured._blobs[('blobs', d['digest'])] for d in layers]
    expected_reads = [('manifests', digest), ('blobs', config_desc['digest'])] + [('blobs', d['digest']) for d in layers]
    archive.require([key for _, key in captured._reads] == expected_reads, 'image_reads_incomplete')
    ids = [rid for rid, _ in captured._reads]
    archive.require(len(set(ids)) == len(ids) and not set(ids) & seen, 'duplicate_native_receipts')
    identity = archive.identity({'provider': 'gcp', 'scope': scope,
        'immutable_reference': reference, 'manifest_digest': digest, 'config_digest': config_desc['digest']})
    archive.validate(identity, manifest, config, payloads, captured.check, stage=True,
                     prebuilt=vars(captured).pop('prebuilt', None))
    image_ledger = {r.get('id'): r for r in captured.transport.evidence}
    image_records = {rid:deepcopy(image_ledger[rid]) for rid in ids}
    archive.require(all(r.get('scope') == scope and r.get('http_status') == 200
                        and type(r.get('http_attempts')) is int and (
                            r['http_attempts'] == 1 and 'same_origin_blob_redirect' not in r
                            or r['http_attempts'] == 2 and r.get('category') == 'blobs'
                            and r.get('same_origin_blob_redirect') is True)
                        for r in image_records.values()), 'image_native_receipts_required')
    expected_state = _fingerprint([before, after, records, captures, captured._reads])
    byte_state = tuple((key, sha256(value, captured.check).digest()) for key, value in captured._blobs.items())

    def verify():
        captured.check()
        archive.require(_fingerprint([before, after, records, captures, captured._reads]) == expected_state,
                        'metadata_or_sequence_changed')
        archive.require(bind(reference, scope, after) == row, 'native_binding_changed')
        archive.require(tuple((key, sha256(value, captured.check).digest())
                        for key, value in captured._blobs.items()) == byte_state, 'retained_bytes_changed')
        ledger = {r.get('id'): r for r in captured.transport.evidence}
        archive.require(all(ledger.get(r['id']) == r for r in records), 'metadata_ledger_changed')
        archive.require(all(ledger.get(rid) == image_records[rid] for rid in ids), 'image_receipt_changed')
        archive.require(all(ledger.get(rid, {}).get('status') == 'collected'
                        and ledger[rid].get('digest') == key[1]
                        and ledger[rid].get('category') == key[0]
                        and ledger[rid].get('operation') == 'artifactregistry.registry_content_get'
                        and ledger[rid].get('method') == 'GET' for rid, key in captured._reads),
                        'image_ledger_changed')
        return identity

    verify()
    outcome = runner(identity, manifest, config, payloads, native_verifier=verify,
        enabled=True, db_cache=db_cache, cli=cli, archive_format='docker', timeout=timeout,
        cancel=captured.check, scratch_parent=scratch_parent)
    archive.require(type(outcome) is dict and outcome.get('image') == identity, 'scanner_identity_mismatch')
    return {**outcome, 'schema': SCHEMA, 'association_kind': 'selected_registry_digest',
            'runtime_image_proven': False, 'source_requests': sorted(seen) + ids}


def scan_index_captured(reference, scope, before, after, captured, metadata_reader,
                        graph, scans, source_requests):
    """Revalidate immutable parent ownership before retaining any child scan."""
    archive.require(before == after and bind(reference, scope, before) == bind(reference, scope, after),
                    'index_native_metadata_changed')
    records, captures = metadata_reader.records, metadata_reader.captures
    expected = requests_for(reference, scope) * 2
    archive.require(len(records) == len(captures) == 6, 'all_metadata_receipts_required')
    for record, capture, request, body in zip(records, captures, expected, before + after):
        archive.require(capture == {'source_request': record.get('id'), 'body': body}
                        and record.get('method') == 'GET' and record.get('url') == request[0]
                        and record.get('query') == {'fields': request[1]}
                        and record.get('operation') == 'artifactregistry_selected_image_metadata_get'
                        and record.get('scope') == scope and record.get('status') == 'collected'
                        and record.get('http_status') == 200 and record.get('http_attempts') == 1,
                        'index_metadata_receipt_mismatch')
    archive.require(all(records[i]['body_sha256'] == records[i+3]['body_sha256']
                        and records[i]['bytes'] == records[i+3]['bytes'] for i in range(3)),
                    'index_metadata_wire_changed')
    uri, _, parent_digest = native.bind_image(bind(reference, scope, before), scope,
                                              [before[1]], [before[0]])
    archive.require(captured._uri == uri and graph['parent_digest'] == parent_digest
                    and archive.sha(captured._blobs[('manifests', parent_digest)]) == parent_digest,
                    'index_parent_digest_changed')
    ledger = {record.get('id'): record for record in captured.transport.evidence}
    archive.require(len(ledger) == len(captured.transport.evidence), 'duplicate_native_receipt')
    successful = [record for record in captured._reads]
    archive.require(successful and successful[0] ==
                    (graph['parent_source_request'], ('manifests', parent_digest)),
                    'index_parent_read_missing')
    for rid, key in successful:
        receipt = ledger[rid]
        archive.require(receipt.get('status') == 'collected' and receipt.get('http_status') == 200
                        and receipt.get('method') == 'GET'
                        and receipt.get('operation') == 'artifactregistry.registry_content_get'
                        and receipt.get('scope') == scope and receipt.get('category') == key[0]
                        and receipt.get('digest') == key[1], 'index_blob_receipt_mismatch')
    archive.require(len(scans) == len(graph['children']) and scans,
                    'scanned_children_required')
    for _, verify in scans:
        verify()
    findings, seen, fresh = [], set(), True
    scan_complete = graph['complete']
    for (outcome, _), child in zip(scans, graph['children']):
        archive.require(outcome.get('image', {}).get('manifest_digest') == child['digest'],
                        'child_finding_identity_changed')
        fresh = fresh and outcome.get('database', {}).get('fresh') is True
        scan_complete = scan_complete and outcome.get('scan_complete') is True
        for finding in outcome.get('findings', []):
            archive.require(type(finding) is dict and finding.get('image_digest') == child['digest'],
                            'foreign_child_finding')
            key = (child['digest'], finding.get('package'), finding.get('version'),
                   finding.get('vulnerability_id'))
            archive.require(key not in seen and len(findings) < trivy.MAX_FINDINGS,
                            'duplicate_or_excess_child_finding')
            seen.add(key)
            findings.append(deepcopy(finding))
    complete = graph['complete'] and fresh and all(outcome.get('complete') is True for outcome, _ in scans)
    status = 'FAIL' if findings else 'PASS' if complete else 'UNKNOWN'
    return {'schema': SCHEMA, 'association_kind': 'selected_registry_digest',
            'runtime_image_proven': False, 'image': {'provider': 'gcp', 'scope': scope,
                'immutable_reference': reference, 'manifest_digest': parent_digest},
            'graph': deepcopy(graph), 'status': status, 'complete': complete,
            'scan_complete': scan_complete, 'coverage_status': 'COMPLETE' if complete else 'UNKNOWN',
            'database': {'fresh': fresh}, 'findings': findings,
            'source_requests': deepcopy(source_requests)}


def collect_native(transport, *, scope, selectors=None, enabled=False, metadata_session=None,
                   image_session=None, db_cache=None, cli=trivy.DEFAULT_CLI,
                   timeout=trivy.MAX_SECONDS, scratch_parent=None, runner=trivy.scan_image):
    result = {'schema': SCHEMA, 'scope': scope, 'status': 'UNKNOWN', 'complete': False,
              'reason': 'disabled', 'rows': [], 'source_requests': []}
    if enabled is not True:
        return result
    try:
        selected = normalize_selection(selectors, scope)
    except Exception:
        result['reason'] = 'invalid_selection'
        return result
    reader = None
    try:
        metadata_session = metadata_session if metadata_session is not None else metadata._session()
        image_session = image_session if image_session is not None else metadata._session()
        deadline = time.monotonic() + 600
        meta = MetadataReader(transport, metadata_session, deadline, scope)
        reader = IndexCaptureReader(Reader(transport, session=image_session))
        for reference in selected:
            reader.reset()
            meta.records, meta.captures = [], []
            row = {'immutable_reference': reference, 'status': 'UNKNOWN', 'complete': False,
                   'reason': 'native_image_unavailable', 'scan': None, 'source_requests': []}
            result['rows'].append(row)
            start = len(getattr(transport, 'evidence', []))
            try:
                requests = requests_for(reference, scope)
                before = [meta.get(*request) for request in requests]
                image = bind(reference, scope, before)
                indexed = image.get('mediaType') in oci_index.INDEX_TYPES
                if indexed:
                    graph, scans = _read_index(reference, scope, before, reader, runner=runner,
                        db_cache=db_cache, cli=cli, timeout=timeout, scratch_parent=scratch_parent)
                else:
                    _read_image(image, scope, [None, before[0], before[1], before[2]], reader)
                after = [meta.get(*request) for request in requests]
                if indexed:
                    scan = scan_index_captured(reference, scope, before, after, reader, meta,
                        graph, scans, [r['id'] for r in transport.evidence[start:]])
                else:
                    scan = scan_captured(reference, scope, before, after, reader, meta, runner=runner,
                        db_cache=db_cache, cli=cli, timeout=timeout, scratch_parent=scratch_parent)
                archive.require(scan.get('status') in ('PASS', 'FAIL', 'UNKNOWN')
                                and type(scan.get('complete')) is bool, 'scanner_result_malformed')
                row.update(scan=scan, status=scan['status'],
                    complete=scan['complete'] is True and scan['status'] != 'UNKNOWN', reason=scan.get('reason'))
            except Exception as exc:
                if _interrupt(exc):
                    raise
                pass
            finally:
                row['source_requests'] = [r['id'] for r in transport.evidence[start:]]
                reader.reset()
        result['complete'] = bool(result['rows']) and all(r['complete'] for r in result['rows'])
        result['status'] = ('FAIL' if any(r['status'] == 'FAIL' for r in result['rows']) else
                            'PASS' if result['complete'] and all(r['status'] == 'PASS' for r in result['rows']) else 'UNKNOWN')
        result['reason'] = None if result['complete'] else 'selected_image_coverage_incomplete'
    except Exception as exc:
        if _interrupt(exc):
            raise
        result['reason'] = 'native_reader_unavailable'
    finally:
        if reader is not None:
            reader.reset()
        for session in (metadata_session, image_session):
            if session is not None:
                try:
                    session.close()
                except Exception:
                    result['complete'] = False
                    if result['status'] != 'FAIL':
                        result['status'] = 'UNKNOWN'
                    result['reason'] = 'session_cleanup_incomplete'
        result['source_requests'] = deepcopy(getattr(transport, 'evidence', []))
    return result
