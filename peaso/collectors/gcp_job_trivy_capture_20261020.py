"""Draft adapter for bytes already read by the selected GCP Job image collector.

This module is deliberately unregistered. It neither makes registry requests nor
passes native credentials to Trivy. Call only after the collector's before/after
metadata revalidation has succeeded.
"""
from copy import deepcopy
import hashlib
import re

from peaso import container_image_archive_20261020 as archive
from peaso import trivy_container_runner_20261020 as trivy
from peaso.collectors import gcp_cloudrun_v2_job_declared_images_20261020 as job
from peaso.collectors import gcp_image_secret_indicators as native

SCHEMA = 'gcp-job-trivy-captured-image-draft-20261020-v1'


def _unknown(reason):
    return {'schema': SCHEMA, 'status': 'UNKNOWN', 'complete': False,
            'coverage_status': 'UNKNOWN', 'reason': reason, 'findings': []}


class CaptureReader:
    """Observe successful native reads without issuing any of its own."""
    def __init__(self, reader):
        self.reader = reader
        self.reset()

    def __getattr__(self, name):
        return getattr(self.reader, name)

    def reset(self):
        self._uri = None
        self._blobs = {}
        self._reads = []
        self._total = 0

    def get(self, uri, category, digest, cap, size=None):
        raw = self.reader.get(uri, category, digest, cap, size)
        archive.require(type(raw) is bytes and archive.sha(raw) == digest,
                        'native_read_digest_mismatch')
        archive.require(category in ('manifests', 'blobs') and type(uri) is str,
                        'native_read_category_required')
        archive.require(self._uri in (None, uri), 'mixed_image_capture')
        self._uri = uri
        key = category, digest
        if key not in self._blobs:
            self._total += len(raw)
            archive.require(self._total <= archive.MAX_COMPRESSED + archive.MAX_MANIFEST,
                            'retained_image_byte_bound')
            self._blobs[key] = raw
        else:
            archive.require(self._blobs[key] == raw, 'duplicate_digest_changed')
        rid = self.reader.request_ids[-1]
        records = [r for r in self.reader.transport.evidence if r.get('id') == rid]
        archive.require(len(records) == 1 and records[0].get('status') == 'collected'
                        and records[0].get('method') == 'GET'
                        and records[0].get('operation') == 'artifactregistry.registry_content_get'
                        and records[0].get('category') == category
                        and records[0].get('digest') == digest,
                        'native_read_receipt_mismatch')
        self._reads.append((rid, key))
        return raw


def scan_captured(selection, scope, before, after, captured, *, enabled=False,
                  metadata_captures=None, metadata_records=None,
                  db_cache=None, cli=trivy.DEFAULT_CLI, timeout=trivy.MAX_SECONDS,
                  scratch_parent=None, runner=trivy.scan_image):
    """Bind revalidated GCP metadata and retained bytes, then invoke Trivy once.

    The caller owns the native reader and closes its session. No result is a
    runtime image claim; this covers only the Job's desired digest declaration.
    """
    if enabled is not True:
        return _unknown('disabled')
    try:
        captured.check()
        archive.require(type(before) is list and type(after) is list
                        and len(before) == len(after) == 4 and before == after,
                        'metadata_revalidation_required')
        expected = job._requests(selection, scope) * 2
        archive.require(type(metadata_captures) is list and len(metadata_captures) == 8
                        and type(metadata_records) is list,
                        'native_metadata_provenance_required')
        ledger = {r['id']: r for r in metadata_records if type(r) is dict and type(r.get('id')) is str}
        archive.require(len(ledger) == len(metadata_records), 'native_metadata_receipt_duplicate')
        seen = set()
        for capture, (url, fields), body in zip(metadata_captures, expected, before + after):
            archive.require(type(capture) is dict and set(capture) == {'source_request', 'body'}
                            and capture['body'] == body and capture['source_request'] in ledger
                            and capture['source_request'] not in seen,
                            'native_metadata_capture_mismatch')
            seen.add(capture['source_request'])
            record = ledger[capture['source_request']]
            archive.require(record.get('method') == 'GET' and record.get('url') == url
                            and record.get('query') == {'fields': fields}
                            and record.get('operation') == 'cloudrun_v2_job_declared_image_metadata_get'
                            and record.get('status') == 'collected' and record.get('http_status') == 200
                            and record.get('http_attempts') == 1 and record.get('scope') == scope
                            and type(record.get('bytes')) is int
                            and 0 < record['bytes'] <= job.MAX_METADATA_BODY
                            and type(record.get('body_sha256')) is str
                            and re.fullmatch(r'[0-9a-f]{64}', record['body_sha256']),
                            'native_metadata_receipt_mismatch')
        _, first = job._bind(selection, scope, deepcopy(before))
        _, second = job._bind(selection, scope, deepcopy(after))
        archive.require(first == second and
                        captured._uri.removeprefix('https://') == selection['immutable_reference'],
                        'native_image_binding_mismatch')
        uri, _, digest = native.bind_image(first, scope, [before[2]], [before[1]])
        archive.require(uri == captured._uri and digest == selection['digest'],
                        'native_image_binding_mismatch')
        manifest = captured._blobs[('manifests', digest)]
        decoded = archive.decode(manifest)
        config_desc = archive.descriptor(decoded['config'], archive.CONFIGS, archive.MAX_CONFIG)
        layers = decoded['layers']
        archive.require(type(layers) is list and 1 <= len(layers) <= archive.MAX_LAYERS,
                        'all_layers_required')
        layers = [archive.descriptor(d, archive.LAYERS, archive.MAX_LAYER) for d in layers]
        config = captured._blobs[('blobs', config_desc['digest'])]
        payloads = [captured._blobs[('blobs', d['digest'])] for d in layers]
        expected_reads = [('manifests', digest), ('blobs', config_desc['digest'])] + [
            ('blobs', d['digest']) for d in layers]
        archive.require([key for _, key in captured._reads] == expected_reads,
                        'native_read_sequence_incomplete')
        ids = [rid for rid, _ in captured._reads]
        archive.require(len(ids) == len(set(ids)) and not seen.intersection(ids),
                        'native_read_receipt_duplicate')
        identity = archive.identity({'provider': 'gcp', 'scope': scope,
            'immutable_reference': captured._uri.removeprefix('https://'), 'manifest_digest': digest,
            'config_digest': config_desc['digest']})
        archive.validate(identity, manifest, config, payloads, captured.check, stage=True)
        fingerprint = (tuple(ids), tuple((key, hashlib.sha256(raw).digest())
                       for key, raw in captured._blobs.items()))

        def verify():
            captured.check()
            archive.require(before == after and
                            all(c['body'] == body for c, body in zip(metadata_captures, before + after))
                            and all(ledger[c['source_request']].get('status') == 'collected'
                                    for c in metadata_captures), 'metadata_changed')
            _, again = job._bind(selection, scope, deepcopy(after))
            bound_uri, _, bound_digest = native.bind_image(again, scope, [after[2]], [after[1]])
            current = (tuple(rid for rid, _ in captured._reads),
                       tuple((key, hashlib.sha256(raw).digest())
                             for key, raw in captured._blobs.items()))
            archive.require(current == fingerprint and bound_uri == uri and bound_digest == digest,
                            'capture_changed')
            image_ledger = {r.get('id'): r for r in captured.reader.transport.evidence}
            archive.require(all(image_ledger.get(rid, {}).get('status') == 'collected'
                                and image_ledger[rid].get('digest') == key[1]
                                for rid, key in captured._reads), 'image_receipt_changed')
            return identity

        verify()
        outcome = runner(identity, manifest, config, payloads, native_verifier=verify,
                         enabled=True, db_cache=db_cache, cli=cli, archive_format='docker',
                         timeout=timeout, cancel=captured.check,
                         scratch_parent=scratch_parent)
        archive.require(type(outcome) is dict and outcome.get('image') == identity,
                        'scanner_identity_mismatch')
        result = dict(outcome)
        result.update(schema=SCHEMA, association_kind='desired_digest_declaration',
                      runtime_image_proven=False, source_requests=sorted(seen) + ids,
                      image_digest=digest)
        return result
    except Exception:
        return _unknown('native_capture_or_scan_unavailable')
