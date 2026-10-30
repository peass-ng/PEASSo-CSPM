"""GCP wave 2 facts use the native pagination and provenance envelope."""
import json
import pytest

from peaso.collectors.gcp import ReadError
from peaso.collectors.gcp_cloudbuild_projection import project_trigger
from tests.test_peaso_collectors_gcp import collection, snapshot


SCOPE = 'projects/p-one'


@pytest.mark.parametrize('mode,status,count', [
    ('complete', 'collected', 1), ('empty', 'empty', 0),
    ('paginated', 'collected', 2), ('error', 'denied', 0), ('partial', 'partial', 1),
])
def test_worker_pool_inventory(mode, status, count):
    def resolve(request):
        assert request['url'].endswith('/locations/us-central1/workerPools')
        page = request['params'].get('pageToken')
        if mode == 'error' or mode == 'partial' and page:
            raise ReadError('denied', 'fixture_denial')
        if mode == 'empty':
            return {'workerPools': []}
        name = f'{SCOPE}/locations/us-central1/workerPools/' + ('second' if page else 'first')
        return {'workerPools': [{'name': name, 'state': 'RUNNING',
            'privatePoolV1Config': {'networkConfig': {'peeredNetwork': 'networks/private'}}}],
            **({'nextPageToken': 'two'} if not page and mode in ('paginated', 'partial') else {})}
    result, transport = snapshot(['worker_pool'], resolve, worker_pool_locations=['us-central1'])
    env = collection(result, 'worker_pool')
    assert env['coverage_status'] == status and len(env['items']) == count
    assert all(row['_provenance']['scope'] == SCOPE and
               row['_provenance']['representation'] == 'full' for row in env['items'])
    assert len(transport.requests) == (2 if mode in ('paginated', 'partial') else 1)


@pytest.mark.parametrize('mode,status,count', [
    ('complete', 'collected', 1), ('empty', 'empty', 0),
    ('paginated', 'collected', 2), ('error', 'denied', 0), ('partial', 'partial', 1),
])
def test_sql_backup_run_fanout(mode, status, count):
    def resolve(request):
        url = request['url']
        if url.endswith('/instances'):
            return {'items': [{'name': 'db', 'instanceType': 'CLOUD_SQL_INSTANCE'}]}
        if url.endswith('/db/users'):
            return {'items': []}
        assert url.endswith('/db/backupRuns')
        page = request['params'].get('pageToken')
        if mode == 'error' or mode == 'partial' and page:
            raise ReadError('denied', 'fixture_denial')
        if mode == 'empty':
            return {'items': []}
        return {'items': [{'id': '2' if page else '1', 'instance': 'db',
                 'type': 'AUTOMATED', 'status': 'SUCCESSFUL', 'endTime': '2026-10-01T00:00:00Z'}],
                **({'nextPageToken': 'two'} if not page and mode in ('paginated', 'partial') else {})}
    result, transport = snapshot(['sql_backup_run'], resolve)
    env = collection(result, 'sql_backup_run')
    assert env['coverage_status'] == status and len(env['items']) == count
    assert all(row['instanceName'] == 'db' and row['_provenance']['scope'] == SCOPE
               for row in env['items'])
    assert sum(r['url'].endswith('/db/backupRuns') for r in transport.requests) == (
        2 if mode in ('paginated', 'partial') else 1)


@pytest.mark.parametrize('mode,status,count', [
    ('complete', 'collected', 1), ('empty', 'empty', 0),
    ('paginated', 'collected', 2), ('error', 'denied', 0),
    ('partial', 'partial', 1), ('policy_error', 'partial', 1),
])
def test_source_repository_policy_fanout(mode, status, count):
    def resolve(request):
        url = request['url']
        if url.endswith(':getIamPolicy'):
            if mode == 'policy_error':
                raise ReadError('denied', 'fixture_denial')
            return {'bindings': [{'role': 'roles/source.reader', 'members': ['user:reader@example.com']}],
                    'version': 3}
        assert url.endswith('/repos')
        page = request['params'].get('pageToken')
        if mode == 'error' or mode == 'partial' and page:
            raise ReadError('denied', 'fixture_denial')
        if mode == 'empty':
            return {'repos': []}
        return {'repos': [{'name': f'{SCOPE}/repos/' + ('second' if page else 'first')}],
                **({'nextPageToken': 'two'} if not page and mode in ('paginated', 'partial') else {})}
    result, transport = snapshot(['source_repository'], resolve)
    env = collection(result, 'source_repository')
    assert env['coverage_status'] == status and len(env['items']) == count
    if status == 'collected':
        assert all(row['iamPolicy']['bindings'] and row['_provenance']['scope'] == SCOPE
                   for row in env['items'])
    assert sum(r['url'].endswith(':getIamPolicy') for r in transport.requests) == count


def test_bigquery_table_schema_is_full_only_after_successful_detail():
    def resolve(request):
        url = request['url']
        if url.endswith('/datasets'):
            return {'datasets': [{'datasetReference': {'projectId': 'p-one', 'datasetId': 'ds'}, 'id': 'p-one:ds'}]}
        if url.endswith('/datasets/ds'):
            return {'datasetReference': {'projectId': 'p-one', 'datasetId': 'ds'}, 'id': 'p-one:ds'}
        if url.endswith('/tables'):
            return {'tables': [{'tableReference': {'projectId': 'p-one', 'datasetId': 'ds', 'tableId': 't'}}]}
        if url.endswith('/tables/t:getIamPolicy'):
            return {'bindings': []}
        assert url.endswith('/tables/t')
        assert 'schema(fields(name,type,mode,fields,policyTags(names)))' in request['params']['fields']
        return {'tableReference': {'projectId': 'p-one', 'datasetId': 'ds', 'tableId': 't'},
                'schema': {'fields': [{'name': 'customer', 'fields': [{'name': 'email',
                    'policyTags': {'names': ['projects/p-one/locations/us-central1/taxonomies/x/policyTags/y']}}]}]}}
    result, _ = snapshot(['bigquery_table'], resolve)
    env = collection(result, 'bigquery_table')
    assert env['coverage_status'] == 'collected'
    assert env['items'][0]['_provenance']['schema_full'] is True
    assert env['items'][0]['schema']['fields'][0]['fields'][0]['policyTags']['names']


def test_bigquery_table_denied_schema_never_claims_full():
    def resolve(request):
        url = request['url']
        if url.endswith('/datasets'):
            return {'datasets': [{'datasetReference': {'projectId': 'p-one', 'datasetId': 'ds'}, 'id': 'p-one:ds'}]}
        if url.endswith('/datasets/ds'):
            return {'datasetReference': {'projectId': 'p-one', 'datasetId': 'ds'}, 'id': 'p-one:ds'}
        if url.endswith('/tables'):
            return {'tables': [{'tableReference': {'projectId': 'p-one', 'datasetId': 'ds', 'tableId': 't'}}]}
        raise ReadError('denied', 'fixture_denial')
    result, _ = snapshot(['bigquery_table'], resolve)
    row = collection(result, 'bigquery_table')['items'][0]
    assert row['_coverage']['tableDetails']['status'] == 'denied'
    assert row['_provenance'].get('schema_full') is not True


@pytest.mark.parametrize('mode,status,count', [
    ('complete', 'collected', 1), ('empty', 'empty', 0),
    ('paginated', 'collected', 2), ('error', 'unavailable', 0),
    ('partial', 'unavailable', 0),
])
def test_alert_policy_reuses_monitoring_inventory(mode, status, count):
    def resolve(request):
        assert request['url'].endswith('/alertPolicies')
        page = request['params'].get('pageToken')
        if mode == 'error' or mode == 'partial' and page:
            raise ReadError('denied', 'fixture_denial')
        if mode == 'empty':
            return {'alertPolicies': []}
        return {'alertPolicies': [{'name': f'{SCOPE}/alertPolicies/' + ('2' if page else '1'),
            'enabled': True, 'conditions': [], 'notificationChannels': []}],
            **({'nextPageToken': 'two'} if not page and mode in ('paginated', 'partial') else {})}
    result, transport = snapshot(['alert_policy'], resolve)
    env = collection(result, 'alert_policy')
    assert env['coverage_status'] == status and len(env['items']) == count
    assert sum(r['url'].endswith('/alertPolicies') for r in transport.requests) == (
        2 if mode in ('paginated', 'partial') else 1)


@pytest.mark.parametrize('mode,status,count', [
    ('complete', 'collected', 1), ('empty', 'empty', 0),
    ('paginated', 'collected', 2), ('error', 'denied', 0), ('partial', 'partial', 1),
])
def test_access_transparency_uses_bounded_exact_log_stream(mode, status, count):
    log_name = f'{SCOPE}/logs/cloudaudit.googleapis.com%2Faccess_transparency'
    def resolve(request):
        assert request['method'] == 'POST' and request['url'].endswith('/entries:list')
        body = request['body']
        assert body['resourceNames'] == [SCOPE]
        assert f'logName="{log_name}"' in body['filter']
        assert 'timestamp>="' in body['filter'] and 'timestamp<"' in body['filter']
        page = body.get('pageToken')
        if mode == 'error' or mode == 'partial' and page:
            raise ReadError('denied', 'fixture_denial')
        if mode == 'empty':
            return {'entries': []}
        return {'entries': [{'insertId': '2' if page else '1', 'logName': log_name,
                    'timestamp': '2026-10-01T00:00:00Z'}],
                **({'nextPageToken': 'two'} if not page and mode in ('paginated', 'partial') else {})}
    result, transport = snapshot(['access_transparency_entry'], resolve)
    env = collection(result, 'access_transparency_entry')
    assert env['coverage_status'] == status and len(env['items']) == count
    assert all(row['project'] == SCOPE and row['_provenance']['scope'] == SCOPE
               for row in env['items'])
    assert len(transport.requests) == (2 if mode in ('paginated', 'partial') else 1)


@pytest.mark.parametrize('mode,status,count', [
    ('complete', 'collected', 1), ('empty', 'empty', 0),
    ('paginated', 'collected', 2), ('error', 'denied', 0), ('partial', 'partial', 1),
])
def test_os_inventory_full_package_map_and_vm_fanout(mode, status, count):
    def resolve(request):
        url = request['url']
        if url.endswith('/aggregated/instances'):
            page = request['params'].get('pageToken')
            if mode == 'empty':
                return {'items': {}}
            vm = 'vm2' if page else 'vm1'
            vm_id = '456' if page else '123'
            return {'items': {'zones/us-central1-a': {'instances': [
                {'name': vm, 'id': vm_id, 'zone': f'{SCOPE}/zones/us-central1-a'}]}},
                **({'nextPageToken': 'two'} if not page and mode in ('paginated', 'partial') else {})}
        if url.endswith('/getIamPolicy'):
            assert '/compute/v1/' in url and request['params'] == {'optionsRequestedPolicyVersion': 3}
            return {'bindings': []}
        assert '/locations/us-central1-a/instances/' in url and url.endswith('/inventory')
        assert request['params'] == {'view': 'FULL'}
        if mode == 'error' or mode == 'partial' and '/456/' in url:
            raise ReadError('denied', 'fixture_denial')
        return {'name': url.split('/v1/', 1)[1], 'updateTime': '2026-10-12T00:00:00Z',
                'items': {'pkg': {'type': 'INSTALLED_PACKAGE',
                    'installedPackage': {'aptPackage': {'packageName': 'agent', 'version': '1.2'}}}}}
    result, transport = snapshot(['os_inventory'], resolve)
    env = collection(result, 'os_inventory')
    assert env['coverage_status'] == status and len(env['items']) == count
    assert all(row['items']['installedPackages'] == [{'name': 'agent', 'version': '1.2'}]
               and row['_provenance']['scope'] == SCOPE for row in env['items'])
    assert sum('/inventory' in r['url'] for r in transport.requests) == (
        0 if mode == 'empty' else 2 if mode in ('paginated', 'partial') else 1)


@pytest.mark.parametrize('mode,status,count', [
    ('complete', 'collected', 1), ('empty', 'empty', 0),
    ('paginated', 'collected', 2), ('error', 'denied', 0), ('partial', 'partial', 1),
])
def test_security_policies_global_and_regional_coverage(mode, status, count):
    def resolve(request):
        url = request['url']
        assert url.endswith('/securityPolicies')
        page = request['params'].get('pageToken')
        if mode == 'error' and '/global/' in url or mode == 'partial' and '/regions/' in url:
            raise ReadError('denied', 'fixture_denial')
        if mode == 'empty' or '/regions/' in url:
            return {'items': []}
        name = 'second' if page else 'first'
        return {'items': [{'name': name,
            'selfLink': f'https://www.googleapis.com/compute/v1/{SCOPE}/global/securityPolicies/{name}',
            'rules': [{'priority': 2147483647, 'match': {}, 'action': 'allow'}]}],
            **({'nextPageToken': 'two'} if not page and mode == 'paginated' else {})}
    result, transport = snapshot(['security_policy'], resolve, security_policy_regions=['us-central1'])
    env = collection(result, 'security_policy')
    assert env['coverage_status'] == status and len(env['items']) == count
    assert all(row['_provenance']['representation'] == 'full' and row['_provenance']['scope'] == SCOPE
               for row in env['items'])
    assert sum(r['url'].endswith('/securityPolicies') for r in transport.requests) == (
        1 if mode == 'error' else 3 if mode == 'paginated' else 2)


def test_security_policy_region_discovery_exhausts_all_pages():
    def resolve(request):
        url = request['url']
        if url.endswith('/regions'):
            page = request['params'].get('pageToken')
            return {'items': [{'name': 'europe-west1' if page else 'us-central1'}],
                    **({} if page else {'nextPageToken': 'two'})}
        assert url.endswith('/securityPolicies')
        return {'items': []}
    result, transport = snapshot(['security_policy'], resolve)
    assert collection(result, 'security_policy')['coverage_status'] == 'empty'
    assert sum(r['url'].endswith('/regions') for r in transport.requests) == 2
    assert sum(r['url'].endswith('/securityPolicies') for r in transport.requests) == 3


def test_workforce_policy_org_scope_reuses_existing_provider_reads():
    scope = 'organizations/123'
    pool = 'locations/global/workforcePools/p'
    def resolve(request):
        if request['url'].endswith('/workforcePools'):
            assert request['params']['parent'] == scope
            return {'workforcePools': [{'name': pool, 'state': 'ACTIVE'}]}
        assert request['url'].endswith('/providers')
        return {'workforcePoolProviders': [{'name': pool + '/providers/oidc', 'state': 'ACTIVE',
            'oidc': {'issuerUri': 'https://idp.example', 'allowedAudiences': ['aud']},
            'attributeMapping': {'google.subject': 'assertion.sub'}}]}
    policy = {'status': 'collected', 'scope': scope, 'workforce': {
        'mapping_complete': True, 'customer_provider_mapping': [{
            'pool': pool, 'provider': pool + '/providers/oidc', 'issuer': 'https://idp.example',
            'audiences': ['aud'], 'mfa_claim': 'amr', 'mfa_mapping': 'assertion.amr',
            'idp_assurance_verified': True}]}}
    result, transport = snapshot(['workforce_pool', 'workforce_provider'], resolve,
                                 scopes=[scope], compliance_policy=policy)
    assert result['metadata']['compliance_policy'] == policy
    assert collection(result, 'workforce_pool', scope)['coverage_status'] == 'collected'
    assert collection(result, 'workforce_provider', scope)['coverage_status'] == 'collected'
    assert sum(r['url'].endswith('/providers') for r in transport.requests) == 1


def test_sw51_policy_is_project_bound_without_inventing_owner_values():
    approved = {'status': 'collected', 'scope': SCOPE,
                'key_version_schedule': {'key': {'version': {'enabled_expiry': '2030-01-01T00:00:00Z'}}},
                'approved_cache_policy': {'cache_modes': ['CACHE_ALL_STATIC'], 'max_client_ttl': 3600}}
    result, _ = snapshot(['cloud_asset'], lambda _: {'results': []}, sw51_policy=approved)
    assert result['metadata']['sw51_policy'] == approved
    with pytest.raises(ValueError):
        snapshot(['cloud_asset'], lambda _: {'results': []},
                 sw51_policy={**approved, 'scope': 'projects/foreign'})


def test_security_event_route_reuses_complete_monitoring_reads():
    metric = SCOPE + '/metrics/security'
    channel = SCOPE + '/notificationChannels/1'
    def resolve(request):
        url = request['url']
        if url.endswith('/metrics'):
            return {'metrics': [{'name': 'security', 'filter': 'protoPayload.methodName="SetIamPolicy"'}]}
        if url.endswith('/alertPolicies'):
            return {'alertPolicies': [{'name': SCOPE + '/alertPolicies/1', 'enabled': True,
                'conditions': [{'conditionThreshold': {'filter': 'metric.type="logging.googleapis.com/user/security"'}}],
                'notificationChannels': [channel]}]}
        assert url.endswith('/notificationChannels')
        return {'notificationChannels': [{'name': channel, 'enabled': True}]}
    policy = {'status': 'collected', 'scope': SCOPE, 'approved_security_event_metrics': [metric]}
    result, transport = snapshot(['logging_metric', 'monitoring_alert_policy',
                                  'monitoring_notification_channel'], resolve, sw52=policy)
    assert result['metadata']['sw52'] == policy
    assert all(collection(result, kind)['coverage_status'] == 'collected' for kind in (
        'logging_metric', 'monitoring_alert_policy', 'monitoring_notification_channel'))
    assert len(transport.requests) == 3


def test_inline_cloudbuild_step_ids_without_build_code():
    projected = project_trigger({'id': 't', 'build': {'steps': [
        {'id': 'security-test', 'script': 'never-retain', 'args': ['never-retain']}],
        'options': {'logging': 'CLOUD_LOGGING_ONLY'}}})
    assert projected['buildDefinition'] == {'status': 'collected', 'steps': [{'id': 'security-test'}]}
    assert 'never-retain' not in json.dumps(projected)
    assert project_trigger({'id': 't', 'filename': 'cloudbuild.yaml'}).get('buildDefinition') is None
    assert project_trigger({'id': 't', 'build': {'steps': [{'script': 'never-retain'}]}})[
        'buildDefinition']['status'] == 'unavailable'
