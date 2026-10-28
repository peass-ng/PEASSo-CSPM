"""Mocked native ACL collection through the signed PCI bucket evaluator."""
from __future__ import annotations

import copy
import json
from urllib.parse import urlsplit

import pytest

from peaso.collectors import collect_live, gcp
from peaso.engine import evaluate_snapshot
from peaso.collectors.gcp_bucket_acl_evidence_native import materialize
from peaso.snapshot import seal
from tests.test_peaso_gcp_storage_acl_native import API, BUCKET, SCOPE
from tests.archived_check_contract import plan_collection
from tests.test_peaso_gcp_api_key_alias_native import (
    CHECK as API_ALIAS_CHECK, SCOPE as API_ALIAS_SCOPE, Transport as APIAliasTransport,
)

CHECK = 'gcp_pci_bucket_157fb0c69361'
KINDS = ['bucket', 'bucket_acl', 'bucket_effective_iam', 'iam_policy', 'object_acl', 'project']


class EmptyACLAPI(API):
    def request(self, method, url, **kwargs):
        data, request_id = super().request(method, url, **kwargs)
        if urlsplit(url).path.endswith(('/acl', '/o')):
            return {'items': []}, request_id
        return data, request_id


class DuplicateACLAPI(API):
    def request(self, method, url, **kwargs):
        data, request_id = super().request(method, url, **kwargs)
        if urlsplit(url).path.endswith('/acl'):
            data['items'].append(copy.deepcopy(data['items'][0]))
        return data, request_id


class DuplicateBucketAPI(API):
    def request(self, method, url, **kwargs):
        data, request_id = super().request(method, url, **kwargs)
        if urlsplit(url).path == '/storage/v1/b':
            data['items'].append(copy.deepcopy(data['items'][0]))
        return data, request_id


def capture(monkeypatch, mode='acl_private', kinds=KINDS, api_class=API):
    api = api_class(mode)
    monkeypatch.setattr(gcp, 'Credentials', lambda *args, **kwargs: None)
    monkeypatch.setattr(gcp, 'Transport', lambda *args, **kwargs: api)
    connector = {'provider': 'gcp', 'scopes': [SCOPE],
                 'options': {'resource_iam': False, 'metrics_scopes': False}}
    snapshot = collect_live(connector, kinds)
    report = evaluate_snapshot(snapshot, checks=[CHECK], include_not_applicable=True)
    findings = [f for f in report['findings'] if f['check_id'] == CHECK]
    assert len(findings) == 1
    collections = {c['type']: c for c in snapshot['collections'] if c['scope'] == SCOPE}
    bucket = collections['bucket']['items'][0]
    return api, snapshot, collections, bucket, findings[0]['status']


def test_public_native_bucket_acl_fails_with_complete_provenance(monkeypatch):
    api, snapshot, collections, bucket, status = capture(monkeypatch, 'acl_public_read')
    assert status == 'FAIL'
    assert bucket['bucketAccessControls']['items'] == [
        {'bucket': BUCKET, 'entity': 'allUsers', 'role': 'READER'}]
    assert bucket['objectAccessControls']['all_objects'] is True
    assert bucket['objectAccessControls']['all_versions'] is True
    assert bucket['objectAccessControls']['projection'] == 'full'
    for kind, key in [('bucket_acl', 'bucketAccessControls'), ('object_acl', 'objectAccessControls')]:
        native = collections[kind]
        proof = native['per_parent_coverage'][BUCKET]
        embedded = bucket[key]
        assert embedded['source_requests'] == proof['source_requests']
        assert embedded['parent_source_requests'] == collections['bucket']['source_requests']
        assert embedded['page_count'] == proof['page_count']
    assert 'private-marker' not in json.dumps(snapshot)
    assert all((kw.get('params') or {}).get('alt') != 'media' for _, _, kw in api.requests)


def test_complete_empty_acl_lists_pass_and_preserve_page_proof(monkeypatch):
    _, _, collections, bucket, status = capture(monkeypatch, 'acl_private', api_class=EmptyACLAPI)
    assert status == 'PASS'
    for kind, key in [('bucket_acl', 'bucketAccessControls'), ('object_acl', 'objectAccessControls')]:
        assert collections[kind]['status'] == 'empty'
        assert bucket[key]['items'] == []
        assert bucket[key]['all_pages'] is True
        assert bucket[key]['page_count'] == 1
    assert bucket['objectAccessControls']['object_count'] == 0


def test_public_object_acl_fails_without_exposing_object_identity(monkeypatch):
    _, snapshot, _, bucket, status = capture(monkeypatch, 'acl_object_owner')
    assert status == 'FAIL'
    assert bucket['objectAccessControls']['items'] == [
        {'bucket': BUCKET, 'entity': 'allUsers', 'role': 'OWNER'}]
    assert 'private-marker' not in json.dumps(snapshot)


def test_public_object_acl_exposure_identifies_hashed_object_version(monkeypatch):
    import peaso.checks  # initialize source admission before the collector transport double
    from peaso.analysis import analyze
    _, snapshot, collections, _, _ = capture(monkeypatch, 'acl_object_owner')
    native = collections['object_acl']['items']
    assert len(native) == 1 and native[0]['objectRef']
    report = analyze(snapshot)
    types = {row['id']: row['type'] for row in report['resources']}
    findings = [row for row in report['findings']
                if row['check_id'] == 'analysis.internet_exposure' and types.get(row['resource_id']) == 'bucket']
    assert len(findings) == 1
    evidence = json.dumps(findings[0]['evidence'])
    assert native[0]['objectRef'] in evidence
    assert native[0]['generation'] in evidence
    assert 'private-marker' not in evidence


def test_private_object_acl_exposure_retains_only_domain_hint(monkeypatch):
    import peaso.checks  # initialize source admission before the collector transport double
    from peaso.analysis import analyze
    _, snapshot, collections, _, _ = capture(monkeypatch, 'acl_private')
    native = collections['object_acl']['items']
    assert len(native) == 1
    assert native[0]['principalKind'] == 'user' and native[0]['principalDomain'] == 'example.com'
    assert 'private-marker' not in json.dumps(snapshot)
    report = analyze(snapshot)
    types = {row['id']: row['type'] for row in report['resources']}
    findings = [row for row in report['findings']
                if row['check_id'] == 'analysis.principal_exposure' and types.get(row['resource_id']) == 'object_acl']
    assert len(findings) == 1 and findings[0]['status'] == 'UNKNOWN'
    assert findings[0]['evidence']['principals'][0]['principal'] == 'domain:example.com'
    assert 'private-marker' not in json.dumps(findings[0]['evidence'])


def test_uniform_bucket_behavior_needs_no_acl_envelopes(monkeypatch):
    api, _, collections, bucket, status = capture(monkeypatch, 'complete', kinds=['bucket'])
    # Local policy absence cannot settle inherited public-read permissions.
    assert status == 'UNKNOWN'
    assert 'bucketAccessControls' not in bucket and 'objectAccessControls' not in bucket
    assert 'bucket_acl' not in collections and 'object_acl' not in collections
    assert not any(urlsplit(url).path.endswith(('/acl', '/o')) for _, url, _ in api.requests)


@pytest.mark.parametrize('mode,api_class,kinds', [
    ('acl_private', API, ['bucket']),
    ('acl_private', API, ['bucket', 'bucket_acl']),
    ('acl_denied', API, KINDS),
    ('object_partial', API, KINDS),
    ('foreign_acl', API, KINDS),
    ('duplicate_object', API, KINDS),
    ('acl_private', DuplicateACLAPI, KINDS),
])
def test_missing_failed_foreign_or_duplicate_acl_never_passes(monkeypatch, mode, api_class, kinds):
    _, _, collections, bucket, status = capture(monkeypatch, mode, kinds, api_class)
    assert status == 'UNKNOWN'
    assert 'bucketAccessControls' not in bucket
    assert 'objectAccessControls' not in bucket
    if mode == 'acl_denied':
        assert collections['bucket_acl']['status'] != 'empty'


def test_ambiguous_parent_coverage_cannot_be_materialized(monkeypatch):
    _, _, collections, _, status = capture(monkeypatch)
    assert status == 'PASS'
    parent = collections['bucket']
    bucket = parent['items'][0]
    bucket.pop('bucketAccessControls')
    bucket.pop('objectAccessControls')
    acl = collections['bucket_acl']
    acl['covered_parent_ids'] = [BUCKET, BUCKET]
    proxy = type('Collector', (), {'collections': {('bucket', SCOPE): parent,
                                               ('bucket_acl', SCOPE): acl,
                                               ('object_acl', SCOPE): collections['object_acl']}})()
    assert materialize(proxy, SCOPE) is False
    assert 'bucketAccessControls' not in bucket and 'objectAccessControls' not in bucket


def test_missing_version_enumeration_proof_cannot_be_materialized(monkeypatch):
    _, _, collections, _, status = capture(monkeypatch)
    assert status == 'PASS'
    bucket = collections['bucket']['items'][0]
    bucket.pop('bucketAccessControls')
    bucket.pop('objectAccessControls')
    collections['object_acl']['per_parent_coverage'][BUCKET]['all_versions'] = False
    proxy = type('Collector', (), {'collections': {('bucket', SCOPE): collections['bucket'],
                                               ('bucket_acl', SCOPE): collections['bucket_acl'],
                                               ('object_acl', SCOPE): collections['object_acl']}})()
    assert materialize(proxy, SCOPE) is False
    assert 'bucketAccessControls' not in bucket and 'objectAccessControls' not in bucket


def test_exact_single_check_plan_collects_acl_evidence_and_fails_public_grant(monkeypatch):
    connector = {'provider': 'gcp', 'scopes': [SCOPE],
                 'options': {'resource_iam': False, 'metrics_scopes': False}}
    kinds = plan_collection({'connector': connector, 'checks': [CHECK]})
    assert kinds == KINDS
    api = API('acl_public_read')
    monkeypatch.setattr(gcp, 'Credentials', lambda *args, **kwargs: None)
    monkeypatch.setattr(gcp, 'Transport', lambda *args, **kwargs: api)
    snapshot = collect_live(connector, kinds)
    report = evaluate_snapshot(snapshot, checks=[CHECK], include_not_applicable=True)
    assert [f['status'] for f in report['findings'] if f['check_id'] == CHECK] == ['FAIL']
    collections = {c['type']: c for c in snapshot['collections'] if c['scope'] == SCOPE}
    bucket = collections['bucket']['items'][0]
    assert bucket['bucketAccessControls']['source_requests'] == \
        collections['bucket_acl']['per_parent_coverage'][BUCKET]['source_requests']
    assert bucket['objectAccessControls']['source_requests'] == \
        collections['object_acl']['per_parent_coverage'][BUCKET]['source_requests']


def test_other_bucket_check_stays_bucket_only():
    connector = {'provider': 'gcp', 'scopes': [SCOPE], 'options': {}}
    assert plan_collection({'connector': connector,
                            'checks': ['gcp_c5_deletion_recoverability']}) == ['bucket']


def test_default_api_alias_plan_avoids_ancestry_and_unrelated_hydration():
    connector = {'provider': 'gcp', 'scopes': [API_ALIAS_SCOPE],
                 'options': {'concurrency': 1}}
    kinds = plan_collection({'connector': connector, 'checks': [API_ALIAS_CHECK]})
    assert kinds == ['api_key', 'service_usage']
    transport = APIAliasTransport()
    collector = gcp.GCPCollector(connector, kinds, transport=transport)
    assert collector.alias_identity_only()
    snapshot = collector.collect()
    report = evaluate_snapshot(snapshot, checks=[API_ALIAS_CHECK])
    assert [f['status'] for f in report['findings']] == ['FAIL']
    assert len(transport.requests) == 3
    assert not any('getAncestry' in url or 'compute.googleapis.com' in url
                   for url in transport.requests)


def test_explicitly_omitted_acl_inventories_remain_unknown(monkeypatch):
    connector = {'provider': 'gcp', 'scopes': [SCOPE],
                 'options': {'resource_iam': False, 'metrics_scopes': False,
                             'inventories': ['bucket']}}
    kinds = plan_collection({'connector': connector, 'checks': [CHECK]})
    assert kinds == ['bucket']
    api = API('acl_private')
    monkeypatch.setattr(gcp, 'Credentials', lambda *args, **kwargs: None)
    monkeypatch.setattr(gcp, 'Transport', lambda *args, **kwargs: api)
    snapshot = collect_live(connector, kinds)
    report = evaluate_snapshot(snapshot, checks=[CHECK], include_not_applicable=True)
    assert [f['status'] for f in report['findings'] if f['check_id'] == CHECK] == ['UNKNOWN']
    bucket = next(c for c in snapshot['collections'] if c['type'] == 'bucket')['items'][0]
    assert 'bucketAccessControls' not in bucket and 'objectAccessControls' not in bucket
    assert not any(urlsplit(url).path.endswith(('/acl', '/o')) for _, url, _ in api.requests)


def test_duplicate_raw_bucket_list_makes_parent_incomplete(monkeypatch):
    api = DuplicateBucketAPI('acl_private')
    monkeypatch.setattr(gcp, 'Credentials', lambda *args, **kwargs: None)
    monkeypatch.setattr(gcp, 'Transport', lambda *args, **kwargs: api)
    connector = {'provider': 'gcp', 'scopes': [SCOPE],
                 'options': {'resource_iam': False, 'metrics_scopes': False}}
    kinds = plan_collection({'connector': connector, 'checks': [CHECK]})
    snapshot = collect_live(connector, kinds)
    parent = next(c for c in snapshot['collections'] if c['type'] == 'bucket' and c['scope'] == SCOPE)
    assert parent['status'] not in ('collected', 'empty')
    assert parent['error']['code'] == 'duplicate_bucket_identity'
    report = evaluate_snapshot(snapshot, checks=[CHECK], include_not_applicable=True)
    statuses = [f['status'] for f in report['findings'] if f['check_id'] == CHECK]
    assert statuses and set(statuses) == {'UNKNOWN'}
    assert all('bucketAccessControls' not in item for item in parent['items'])


@pytest.mark.parametrize('change', [
    'parent_name_denied', 'parent_uniform_denied', 'acl_entity_denied',
    'acl_row_denied', 'empty_with_rows', 'wrong_collection_type',
    'foreign_row_request', 'missing_collection_request',
])
def test_malformed_or_unavailable_native_evidence_cannot_certify_absence(monkeypatch, change):
    _, snapshot, collections, bucket, status = capture(monkeypatch)
    assert status == 'PASS'
    bucket.pop('bucketAccessControls')
    bucket.pop('objectAccessControls')
    acl = collections['bucket_acl']
    row = acl['items'][0]
    if change == 'parent_name_denied':
        bucket.setdefault('_coverage', {})['name'] = {'status': 'denied'}
    elif change == 'parent_uniform_denied':
        bucket.setdefault('_coverage', {})['iamConfiguration'] = {'status': 'denied'}
    elif change == 'acl_entity_denied':
        row.setdefault('_coverage', {})['entity'] = {'status': 'denied'}
    elif change == 'acl_row_denied':
        row['collection_status'] = 'denied'
    elif change == 'empty_with_rows':
        acl['status'] = acl['coverage_status'] = 'empty'
    elif change == 'wrong_collection_type':
        acl['type'] = 'object_acl'
    elif change == 'foreign_row_request':
        row['_provenance']['source_requests'] = ['other-bucket-request']
    elif change == 'missing_collection_request':
        acl['source_requests'] = collections['bucket']['source_requests']
    proxy = type('Collector', (), {'collections': {('bucket', SCOPE): collections['bucket'],
                                               ('bucket_acl', SCOPE): acl,
                                               ('object_acl', SCOPE): collections['object_acl']}})()
    assert materialize(proxy, SCOPE) is False
    assert 'bucketAccessControls' not in bucket and 'objectAccessControls' not in bucket
    if change in ('empty_with_rows', 'wrong_collection_type'):
        # The snapshot schema itself rejects these contradictions before any
        # signed predicate can observe a purported empty inventory.
        with pytest.raises(ValueError):
            evaluate_snapshot(seal(snapshot), checks=[CHECK], include_not_applicable=True)
    else:
        report = evaluate_snapshot(seal(snapshot), checks=[CHECK], include_not_applicable=True)
        statuses = [f['status'] for f in report['findings'] if f['check_id'] == CHECK]
        assert statuses and set(statuses) == {'UNKNOWN'}
