"""Real API response shapes through collector, snapshot and check evaluation."""
import copy
import json

import pytest

from peaso.collectors.gcp import ReadError
from tests.archived_check_contract import evaluate_snapshot
from tests.test_peaso_collectors_gcp import snapshot, collection

ORG = 'organizations/123'
PROJECT = 'projects/p-one'
TOPIC = 'projects/alerts/topics/oncall'
SCC = 'gcp_logging_scc_findings_alert'
BACKUP = 'gcp_c5_backup_remote_location'


def finding():
    return {'name': ORG + '/sources/1/findings/first', 'state': 'ACTIVE', 'severity': 'HIGH',
            'createTime': '2026-10-12T10:00:00Z', 'description': 'private-marker',
            'sourceProperties': {'arbitrary': 'private-marker'}, 'externalUri': 'private-marker'}


def config():
    return {'name': ORG + '/notificationConfigs/oncall', 'pubsubTopic': TOPIC,
            'streamingConfig': {'filter': 'state = "ACTIVE" AND severity = "HIGH"'},
            'description': 'private-marker', 'serviceAccount': 'private-marker'}


def scc_snapshot(mode='complete', **options):
    def resolve(request):
        url = request['url']
        assert request['method'] == 'GET'
        if url == 'https://cloudresourcemanager.googleapis.com/v3/' + ORG:
            return {'name': ORG}
        if mode == 'denied':
            raise ReadError('denied', 'PERMISSION_DENIED', http_status=403)
        if mode == 'disabled':
            error = ReadError('unavailable', 'api_error', reason='SERVICE_DISABLED')
            error.consumer = ORG
            raise error
        if mode == 'empty':
            return {}
        if url.endswith('/findings'):
            value = finding()
            if mode == 'foreign': value['name'] = value['name'].replace(ORG, 'organizations/999')
            if mode == 'badtime': value['createTime'] = 'not-time'
            if mode == 'badstate': value['state'] = 'UNRECOGNIZED'
            if mode == 'unwrapped': return {'listFindingsResults': [value]}
            page = request['params'].get('pageToken')
            if page and mode == 'partial': raise ReadError('denied', 'denied_on_later_page')
            if page and mode == 'conflict': value['severity'] = 'CRITICAL'
            if page and mode == 'pagination': value['name'] += '-second'
            result = {'listFindingsResults': [{'finding': value, 'resource': {'displayName': 'private-marker'}}]}
            if not page and mode in ('partial', 'conflict', 'pagination', 'limit', 'repeat'):
                result['nextPageToken'] = 'next'
            if mode == 'repeat': result['nextPageToken'] = 'next'
            return result
        assert url.endswith('/notificationConfigs')
        value = config()
        if mode == 'wrongroute': value['pubsubTopic'] = 'projects/alerts/topics/other'
        if mode == 'foreignconfig': value['name'] = value['name'].replace(ORG, 'organizations/999')
        if mode == 'arbitraryfilter': value['streamingConfig']['filter'] = 'source_properties.unknown = "x"'
        if mode == 'emptyfilter': value['streamingConfig'] = {}
        if mode == 'precedence': value['streamingConfig']['filter'] = 'state = "INACTIVE" AND severity = "LOW" OR severity = "HIGH"'
        if mode == 'invalidtopic': value['pubsubTopic'] = 'https://arbitrary.invalid'
        return {'notificationConfigs': [value]}
    return snapshot(['organization', 'scc_finding', 'scc_notification_config'], resolve, scopes=[ORG],
        sw55_policy={'scope': ORG, 'status': 'collected', 'approved_on_call_topics': [TOPIC]}, **options)


def verdict(result, cid):
    findings = evaluate_snapshot(result, checks=[cid], include_not_applicable=True)['findings']
    assert len(findings) == 1
    return findings[0]['status']


@pytest.mark.parametrize('mode,expected', [('complete', 'PASS'), ('wrongroute', 'FAIL'),
    ('arbitraryfilter', 'UNKNOWN'), ('empty', 'NOT_APPLICABLE'), ('pagination', 'PASS'),
    ('emptyfilter', 'PASS'), ('precedence', 'FAIL')])
def test_scc_native_findings_routing_and_minimal_payload(mode, expected):
    result, api = scc_snapshot(mode)
    assert verdict(result, SCC) == expected
    assert 'private-marker' not in json.dumps(result)
    assert all(request['method'] == 'GET' for request in api.requests)
    if mode == 'pagination':
        assert len(collection(result, 'scc_finding', ORG)['items']) == 2


@pytest.mark.parametrize('mode', ['denied', 'disabled', 'partial', 'conflict', 'foreign', 'badtime',
    'badstate', 'unwrapped', 'foreignconfig', 'invalidtopic', 'limit', 'repeat'])
def test_scc_incomplete_or_untrusted_inventory_never_passes(mode):
    result, _ = scc_snapshot(mode, **({'max_pages': 1} if mode == 'limit' else {}))
    assert verdict(result, SCC) in ('UNKNOWN', 'DENIED')
    kind = 'scc_notification_config' if mode in ('foreignconfig', 'invalidtopic') else 'scc_finding'
    assert collection(result, kind, ORG)['coverage_status'] not in ('collected', 'empty')


def backup_snapshot(location='us-east1', mode='complete'):
    def resolve(request):
        assert request['method'] == 'GET'
        url = request['url']
        if url.endswith('/instances'):
            return {'items': [{'name': 'db', 'instanceType': 'CLOUD_SQL_INSTANCE', 'region': 'us-central1'}]}
        if url.endswith('/users'):
            return {}
        assert url.endswith('/db/backupRuns')
        page = request['params'].get('pageToken')
        if mode == 'denied' or mode == 'partial' and page:
            raise ReadError('denied', 'PERMISSION_DENIED')
        if mode == 'empty': return {}
        value = {'id': '123', 'instance': 'db', 'type': 'AUTOMATED', 'status': 'SUCCESSFUL',
                 'location': location, 'endTime': '2026-10-12T10:00:00Z', 'description': 'private-marker'}
        if mode == 'foreign': value['instance'] = 'another-db'
        if mode == 'failed': value['status'] = 'FAILED'
        if mode == 'badtime': value['endTime'] = 'not-time'
        return {'items': [value], **({'nextPageToken': 'next'} if mode == 'partial' else {})}
    return snapshot(['sql_instance', 'backup_target'], resolve,
        compliance_policy={'scope': PROJECT, 'status': 'collected', 'sql_scope': ['db'], 'approved_offsite_policy': True})


@pytest.mark.parametrize('location,expected', [('us-east1', 'PASS'), ('us-central1', 'FAIL'),
    ('us', 'UNKNOWN'), ('eu', 'UNKNOWN'), ('', 'UNKNOWN'), (None, 'UNKNOWN')])
def test_cloudsql_backup_region_actual_observation(location, expected):
    result, api = backup_snapshot(location)
    assert verdict(result, BACKUP) == expected
    native = collection(result, 'backup_target')
    assert 'private-marker' not in json.dumps(native)
    assert sum(request['url'].endswith('/backupRuns') for request in api.requests) == 1
    if expected in ('PASS', 'FAIL'):
        assert native['items'][0]['failureRegion'] == location
        assert native['items'][0]['backupRun'].endswith('/backupRuns/123')


@pytest.mark.parametrize('mode', ['denied', 'partial', 'empty', 'failed', 'foreign', 'badtime'])
def test_cloudsql_failed_or_incomplete_backup_evidence_stays_unknown(mode):
    result, _ = backup_snapshot(mode=mode)
    assert verdict(result, BACKUP) in ('UNKNOWN', 'DENIED')


def test_backup_policy_scope_binding_and_explicit_root_precedence():
    import sys
    sw = sys.modules['peaso.checks._bulk_pending_compliance_new_sw53']
    from peaso.checks.facts import Unavailable
    index = {'context': {'provider': 'gcp', 'scope': PROJECT,
                        'metadata': {'compliance_policy': {'scope': 'projects/foreign', 'status': 'collected'}}}}
    with pytest.raises(Unavailable): sw._policy(index)
    index['context']['policy'] = {'approved_offsite_policy': False}
    assert sw._policy(index) == {'approved_offsite_policy': False}


def test_collector_selection_exposes_real_new_native_types():
    from peaso.collectors.gcp import SUPPORTED_TYPES
    assert {'scc_finding', 'scc_notification_config', 'backup_target'} <= SUPPORTED_TYPES
    result, api = snapshot(['scc_finding'], lambda request: pytest.fail('non-native scope must not issue SCC requests'))
    assert not api.requests
    assert collection(result, 'scc_finding')['coverage_status'] == 'unsupported'


def asset_snapshot(mode='complete', approved=None):
    typ = 'compute.googleapis.com/Instance'
    name = '//compute.googleapis.com/' + PROJECT + '/zones/us-central1-a/instances/vm'
    def resolve(request):
        url = request['url']
        if url.endswith('/assets'):
            assert request['params']['contentType'] == 'RESOURCE'
            value = {'name': name, 'assetType': typ, 'updateTime': '2026-10-12T10:00:00Z'}
            return {'assets': [] if mode in ('missing', 'empty') else [value]}
        assert url.endswith('/aggregated/instances')
        if mode == 'denied': raise ReadError('denied', 'PERMISSION_DENIED')
        if mode == 'partial' and request['params'].get('pageToken'): raise ReadError('denied', 'later_page_denial')
        if mode == 'empty': return {}
        link = 'https://www.googleapis.com/compute/v1/' + PROJECT + '/zones/us-central1-a/instances/vm'
        if mode == 'foreign': link = link.replace(PROJECT, 'projects/foreign')
        if mode == 'kind_confusion': link = link.replace('instances/vm', 'disks/vm')
        return {'items': {'zones/us-central1-a': {'instances': [{'name': 'vm', 'selfLink': link}]}},
                **({'nextPageToken': 'next'} if mode == 'partial' else {})}
    return snapshot(['asset', 'asset_service_inventory'], resolve,
        sw51_policy={'scope': PROJECT, 'status': 'collected', 'approved_asset_types': approved or [typ]})


@pytest.mark.parametrize('mode,expected', [('complete', 'PASS'), ('missing', 'FAIL'), ('empty', 'NOT_APPLICABLE'),
    ('denied', 'UNKNOWN'), ('partial', 'UNKNOWN'), ('foreign', 'UNKNOWN'), ('kind_confusion', 'UNKNOWN')])
def test_asset_inventory_independent_service_reads_actual_reconciliation(mode, expected):
    result, api = asset_snapshot(mode)
    assert verdict(result, 'gcp_c5_asset_inventory') == expected
    assert len({request['url'].split('/')[2] for request in api.requests}) == 2
    assert any('compute.googleapis.com/' in request['url'] for request in api.requests)
    assert any('cloudasset.googleapis.com/' in request['url'] for request in api.requests)
    assert all(request['method'] == 'GET' for request in api.requests)


def test_asset_inventory_unsupported_approved_types_cannot_shrink_coverage():
    result, _ = asset_snapshot(approved=['compute.googleapis.com/Instance', 'unknown.googleapis.com/Resource'])
    assert verdict(result, 'gcp_c5_asset_inventory') == 'UNKNOWN'
    assert collection(result, 'asset_service_inventory')['coverage_status'] == 'unsupported'


@pytest.mark.parametrize('asset_type,row,name', [
    ('storage.googleapis.com/Bucket', {'name': 'private-bucket'}, '//storage.googleapis.com/private-bucket'),
    ('sqladmin.googleapis.com/Instance', {'name': 'db', 'project': 'p-one'}, '//cloudsql.googleapis.com/projects/p-one/instances/db'),
    ('run.googleapis.com/Service', {'name': PROJECT + '/locations/us-east1/services/service'},
     '//run.googleapis.com/projects/p-one/locations/us-east1/services/service'),
])
def test_asset_canonical_names_follow_cai_names_not_iam_aliases(asset_type, row, name):
    from peaso.collectors.gcp_native_evidence import _asset_name
    assert _asset_name(row, asset_type, PROJECT) == name


@pytest.mark.parametrize('asset_type,row', [
    ('storage.googleapis.com/Bucket', {'name': 'foreign/path'}),
    ('sqladmin.googleapis.com/Instance', {'name': 'db', 'project': 'foreign'}),
    ('run.googleapis.com/Service', {'name': 'projects/foreign/locations/us-east1/services/service'}),
])
def test_asset_canonical_identity_rejects_foreign_and_ambiguous_names(asset_type, row):
    from peaso.collectors.gcp_native_evidence import _asset_name
    with pytest.raises(ReadError): _asset_name(row, asset_type, PROJECT)


def approval_snapshot(mode='complete', **options):
    approval = PROJECT + '/approvalRequests/customer-consent'
    log = PROJECT + '/logs/cloudaudit.googleapis.com%2Faccess_transparency'
    def resolve(request):
        url = request['url']
        if url.endswith('/accessApprovalSettings'):
            assert request['method'] == 'GET'
            return {'name': PROJECT + '/accessApprovalSettings', 'enrolledServices': [{'cloudProduct': 'bigquery.googleapis.com'}]}
        if url.endswith('/approvalRequests'):
            assert request['method'] == 'GET' and request['params']['filter'] == 'ALL'
            if mode == 'deniedrequest': raise ReadError('denied', 'PERMISSION_DENIED')
            if mode == 'norequests': return {}
            value = {'name': approval, 'requestedResourceName': '//bigquery.googleapis.com/' + PROJECT,
                     'requestTime': '2026-10-12T10:00:00Z', 'requestedExpiration': '2026-10-12T14:00:00Z',
                     'requestedReason': {'detail': 'private-marker'},
                     'approve': {'approveTime': '2026-10-12T11:00:00Z', 'expireTime': '2026-10-12T14:00:00Z',
                                 'signatureInfo': {'signature': 'private-marker'}}}
            if mode == 'expired': value['approve']['expireTime'] = '2026-10-12T11:30:00Z'
            if mode == 'invalidated': value['approve']['invalidateTime'] = '2026-10-12T11:30:00Z'
            if mode == 'lateapproval': value['approve']['approveTime'] = '2026-10-12T13:00:00Z'
            if mode == 'auto': value['approve']['autoApproved'] = True
            if mode == 'policy_auto': value['approve'].update(autoApproved=True, policyApproved=True)
            if mode == 'badflag': value['approve']['autoApproved'] = 'true'
            if mode == 'pending': value.pop('approve')
            if mode == 'foreignrequest': value['name'] = 'projects/foreign/approvalRequests/x'
            return {'approvalRequests': [value]}
        assert url.endswith('/entries:list') and request['method'] == 'POST'
        assert request['body']['resourceNames'] == [PROJECT]
        assert 'access_transparency' in request['body']['filter']
        assert 'timestamp>=' in request['body']['filter'] and 'timestamp<' in request['body']['filter']
        if mode == 'deniedlog' or mode == 'partiallog' and request['body'].get('pageToken'):
            raise ReadError('denied', 'PERMISSION_DENIED')
        if mode == 'empty': return {}
        value = {'insertId': 'one', 'timestamp': '2026-10-12T12:00:00Z', 'logName': log,
                 'jsonPayload': {'@type': 'type.googleapis.com/google.cloud.audit.TransparencyLog',
                     'accesses': [{'resourceName': '//bigquery.googleapis.com/' + PROJECT, 'methodName': 'GoogleInternal.Read'}],
                     'accessApprovals': [approval], 'reason': [{'detail': 'private-marker'}],
                     'location': {'principalOfficeCountry': 'private-marker'}}}
        if mode == 'wrongreference': value['jsonPayload']['accessApprovals'] = [PROJECT + '/approvalRequests/another']
        if mode == 'missingreference': value['jsonPayload'].pop('accessApprovals')
        if mode == 'foreignlog': value['logName'] = log.replace(PROJECT, 'projects/foreign')
        if mode == 'foreignresource': value['jsonPayload']['accesses'][0]['resourceName'] = '//bigquery.googleapis.com/projects/foreign'
        if mode == 'genericresource': value['jsonPayload']['accesses'][0]['resourceName'] = '//googleapis.com/storage/buckets/x/objects/y'
        if mode == 'wrongtype': value['jsonPayload']['@type'] = 'type.googleapis.com/google.cloud.audit.AuditLog'
        if mode == 'outofwindow': value['timestamp'] = '2026-10-13T01:00:00Z'
        if mode == 'multiaccess': value['jsonPayload']['accesses'] *= 2
        return {'entries': [value], **({'nextPageToken': 'next'} if mode == 'partiallog' else {})}
    return snapshot(['access_approval_settings', 'access_approval_request', 'provider_access_event'], resolve,
        sw55_policy={'status': 'collected', 'scope': PROJECT,
            'consent_scopes': [{'serviceName': 'bigquery.googleapis.com', 'resourceName': PROJECT}],
            'log_coverage': {'status': 'collected', 'start': '2026-10-12T00:00:00Z', 'end': '2026-10-13T00:00:00Z'}}, **options)


@pytest.mark.parametrize('mode,expected', [('complete', 'PASS'), ('empty', 'NOT_APPLICABLE'),
    ('expired', 'FAIL'), ('invalidated', 'FAIL'), ('lateapproval', 'FAIL'), ('pending', 'FAIL'),
    ('norequests', 'FAIL'), ('auto', 'UNKNOWN'), ('policy_auto', 'PASS'), ('wrongreference', 'FAIL'),
    ('missingreference', 'FAIL'), ('multiaccess', 'PASS')])
def test_access_approval_real_schema_consent_expiration_and_exact_request_join(mode, expected):
    result, api = approval_snapshot(mode)
    assert verdict(result, 'gcp_c5_access_approval') == expected
    assert 'private-marker' not in json.dumps(result)
    if mode != 'empty':
        event = collection(result, 'provider_access_event')['items'][0]
        assert event['principalIdentityDisclosed'] is False
        assert event['principal'] == 'Google personnel (individual identity not disclosed)'
    assert all(request['method'] == 'GET' or request['url'].endswith('/entries:list') for request in api.requests)


@pytest.mark.parametrize('mode', ['deniedrequest', 'deniedlog', 'partiallog', 'foreignrequest',
    'foreignlog', 'foreignresource', 'genericresource', 'wrongtype', 'outofwindow', 'badflag'])
def test_access_approval_unresolved_native_facts_never_become_pass(mode):
    result, _ = approval_snapshot(mode)
    assert verdict(result, 'gcp_c5_access_approval') in ('UNKNOWN', 'DENIED')


def test_approval_request_numeric_project_alias_requires_crm_binding():
    from peaso.collectors.gcp_native_evidence import _approval_jobs

    class Collector:
        needed = {'access_approval_request'}

        def __init__(self, observed, bound):
            self.observed, self.bound = observed, bound
            self.binding_reads = 0

        def _data_project_binding(self, scope, *, require_alias=False):
            assert scope == PROJECT and require_alias
            self.binding_reads += 1
            return {'project_id': 'p-one', 'project_number': self.bound}

        def pages(self, url, scope, *, key, params, transform):
            assert url == 'https://accessapproval.googleapis.com/v1/' + PROJECT + '/approvalRequests'
            assert key == 'approvalRequests' and params == {'filter': 'ALL'}
            yield [transform({'name': 'projects/' + self.observed + '/approvalRequests/a1',
                              'requestedResourceName': '//bigquery.googleapis.com/projects/p-one/datasets/d1',
                              'requestTime': '2026-10-12T12:00:00Z',
                              'requestedExpiration': '2026-10-13T12:00:00Z'})], 'list'

    good = Collector('1234', '1234')
    rows = [row for page, _ in _approval_jobs(good, PROJECT)[0][3]() for row in page]
    assert rows[0]['name'] == PROJECT + '/approvalRequests/a1'
    assert good.binding_reads == 1
    for observed in ('5678', 'foreign'):
        bad = Collector(observed, '1234')
        with pytest.raises(ReadError, match='approval_request_identity_unresolved'):
            list(_approval_jobs(bad, PROJECT)[0][3]())


def test_provider_logs_are_opt_in_and_missing_approved_window_makes_no_log_request():
    from peaso.collectors.gcp import GCPCollector
    collector = GCPCollector({'scopes': [PROJECT], 'options': {}})
    assert 'provider_access_event' not in collector.wanted
    collector.hydration_pool.shutdown(wait=True)
    result, api = snapshot(['provider_access_event'], lambda request: pytest.fail('must not read unbounded logs'))
    assert not api.requests
    assert collection(result, 'provider_access_event')['coverage_status'] == 'unavailable'


@pytest.mark.parametrize('path', ['sources/-/findings', 'notificationConfigs'])
def test_scc_actual_http_transport_allows_only_read_operations(monkeypatch, path):
    from tests.test_peaso_collectors_gcp import http_transport, Response
    transport, calls = http_transport(monkeypatch, [Response(data={})])
    url = 'https://securitycenter.googleapis.com/v1/' + ORG + '/' + path
    transport.request('GET', url, scope=ORG)
    assert len(calls) == 1 and calls[0]['url'] == url
    with pytest.raises(ReadError, match='cloud_mutation_prohibited'):
        transport.request('POST', url, body={})


@pytest.fixture
def history_clock(monkeypatch):
    # The fixture window must stay inside the 35-day native CAI retention.
    from datetime import datetime, timezone
    from peaso.collectors import gcp

    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 10, 20, tzinfo=timezone.utc).astimezone(tz)

    monkeypatch.setattr(gcp, 'datetime', Clock)


def history_snapshot(mode='complete'):
    start, end = '2026-10-12T00:00:00+00:00', '2026-10-13T00:00:00+00:00'
    name = '//compute.googleapis.com/' + PROJECT + '/zones/us-central1-a/instances/vm'
    log = PROJECT + '/logs/cloudaudit.googleapis.com%2Factivity'
    def resolve(request):
        url = request['url']
        if url == 'https://cloudresourcemanager.googleapis.com/v3/' + PROJECT:
            if mode == 'foreignbinding': return {'name': 'projects/123456789012', 'projectId': 'foreign'}
            return {'name': 'projects/123456789012', 'projectId': 'p-one'}
        if url.endswith('/assets'):
            assert request['method'] == 'GET'
            previous = request['params']['readTime'] == start
            assert previous or request['params']['readTime'] == end
            if previous and mode == 'deniedprevious': raise ReadError('denied', 'PERMISSION_DENIED')
            if previous and mode == 'partialprevious' and request['params'].get('pageToken'):
                raise ReadError('denied', 'LATER_PAGE_DENIED')
            value = {'name': name, 'assetType': 'compute.googleapis.com/Instance',
                     'updateTime': '2026-10-11T00:00:00Z' if previous or mode == 'unchanged' else '2026-10-12T12:00:00Z'}
            if mode == 'foreignasset': value['name'] = name.replace(PROJECT, 'projects/foreign')
            if mode == 'numeric_alias' or mode == 'alias_conflict' and previous:
                value['name'] = name.replace(PROJECT, 'projects/123456789012')
            if mode == 'missingcurrent' and not previous: rows = []
            else: rows = [value]
            result = {'readTime': request['params']['readTime'], 'assets': rows}
            if mode == 'missingreadtime': result.pop('readTime')
            if mode == 'wrongreadtime': result['readTime'] = '2026-10-13T00:00:01Z'
            if mode == 'partialprevious' and previous: result['nextPageToken'] = 'next'
            return result
        assert url.endswith('/entries:list') and request['method'] == 'POST'
        assert request['body']['resourceNames'] == [PROJECT] and 'activity' in request['body']['filter']
        if mode == 'selected': assert 'protoPayload.serviceName="compute.googleapis.com"' in request['body']['filter']
        if mode == 'wildcard': assert 'protoPayload.serviceName' not in request['body']['filter']
        if mode == 'deniedlog': raise ReadError('denied', 'PERMISSION_DENIED')
        if mode == 'missinglog': return {}
        value = {'insertId': 'one', 'timestamp': '2026-10-12T12:00:00Z', 'logName': log,
                 'protoPayload': {'@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                     'serviceName': 'compute.googleapis.com', 'methodName': 'v1.compute.instances.setLabels',
                     'resourceName': PROJECT + '/zones/us-central1-a/instances/vm',
                     'request': {'arbitrary': 'private-marker'}, 'response': {'arbitrary': 'private-marker'}}}
        if mode == 'failure': value['protoPayload']['status'] = {'code': 7, 'message': 'private-marker'}
        if mode == 'pendingoperation': value['operation'] = {'first': True}
        if mode == 'completedoperation': value['operation'] = {'last': True}
        if mode == 'foreignlog': value['logName'] = log.replace(PROJECT, 'projects/foreign')
        if mode == 'wrongtype': value['protoPayload']['@type'] = 'arbitrary'
        if mode == 'wrongwindow': value['timestamp'] = '2026-10-14T00:00:00Z'
        return {'entries': [value]}
    return snapshot(['asset', 'asset_previous', 'asset_audit_log'], resolve,
        sw51_policy={'scope': PROJECT, 'status': 'collected', 'audit_window': {'start': start, 'end': end}},
        **({'asset_types': ['compute.googleapis.com/Instance']} if mode == 'selected' else
           {'asset_types': ['compute.googleapis.com/.*']} if mode == 'wildcard' else {}))


@pytest.mark.parametrize('mode,expected', [('complete', 'PASS'), ('missinglog', 'FAIL'), ('failure', 'FAIL'),
    ('pendingoperation', 'FAIL'), ('completedoperation', 'PASS'), ('unchanged', 'NOT_APPLICABLE'),
    ('missingcurrent', 'PASS'), ('numeric_alias', 'PASS'), ('selected', 'PASS'), ('wildcard', 'PASS')])
@pytest.mark.usefixtures('history_clock')
def test_cai_history_real_asof_timestamps_and_admin_activity_join(mode, expected):
    result, api = history_snapshot(mode)
    assert verdict(result, 'gcp_c5_asset_change_audit') == expected
    assert collection(result, 'asset_previous')['readTime'].startswith('2026-10-12')
    assert collection(result, 'asset')['readTime'].startswith('2026-10-13')
    assert 'private-marker' not in json.dumps(result)
    assert all(request['method'] == 'GET' or request['url'].endswith('/entries:list') for request in api.requests)
    if mode == 'numeric_alias':
        event = collection(result, 'asset_audit_log')['items'][0]
        assert 'projects/123456789012/' in event['protoPayload']['resourceName']
        assert event['sourceResourceName'].startswith('//compute.googleapis.com/' + PROJECT)
        assert len(event['_provenance']['source_requests']) >= 2


@pytest.mark.parametrize('mode', ['deniedprevious', 'partialprevious', 'missingreadtime', 'wrongreadtime',
    'foreignasset', 'deniedlog', 'foreignlog', 'wrongtype', 'wrongwindow', 'foreignbinding', 'alias_conflict'])
@pytest.mark.usefixtures('history_clock')
def test_cai_history_partial_mismatched_or_foreign_evidence_stays_unknown(mode):
    result, _ = history_snapshot(mode)
    assert verdict(result, 'gcp_c5_asset_change_audit') in ('UNKNOWN', 'DENIED')


@pytest.mark.parametrize('window', [{'start': '2026-10-12T00:00:00Z', 'end': '2026-10-11T00:00:00Z'},
    {'start': '2020-01-01T00:00:00Z', 'end': '2020-01-02T00:00:00Z'},
    {'start': '2099-01-01T00:00:00Z', 'end': '2099-01-02T00:00:00Z'},
    {'start': '2026-10-12T00:00:00', 'end': '2026-10-13T00:00:00'}])
def test_cai_history_unbounded_or_unverifiable_windows_issue_no_reads(window):
    result, api = snapshot(['asset_previous', 'asset_audit_log'], lambda request: pytest.fail('invalid window must not reach API'),
        sw51_policy={'scope': PROJECT, 'status': 'collected', 'audit_window': window})
    assert not api.requests
    assert all(c['coverage_status'] not in ('collected', 'empty') for c in result['collections'])
