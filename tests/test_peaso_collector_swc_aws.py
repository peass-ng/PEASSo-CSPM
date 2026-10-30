"""Provider-owned synthetic AWS metadata; no live calls or credentials."""
import copy
import json
from collections import defaultdict, deque
from datetime import datetime, timezone

import pytest

boto3 = pytest.importorskip('boto3')
from botocore.exceptions import ClientError
from peaso.collectors import aws, aws_facts_swc as facts

ACCOUNT = '123456789012'
REGION = 'us-east-1'


@pytest.fixture
def sdk(monkeypatch):
    session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert', region_name=REGION)
    queues = defaultdict(deque)
    clients = {}
    calls = []

    class Client:
        def __init__(self, service, region):
            self.service, self.region = service, region
            self.model = session.client(service, region_name=region)
        def can_paginate(self, operation):
            return self.model.can_paginate(operation)
        def get_paginator(self, operation):
            return self.model.get_paginator(operation)
        def __getattr__(self, operation):
            def call(**arguments):
                calls.append((self.service, self.region, operation, arguments))
                queue = queues[(self.service, self.region, operation)]
                if not queue:
                    raise ClientError({'Error': {'Code': 'AccessDeniedException'}}, operation)
                response = queue.popleft()
                if isinstance(response, Exception):
                    raise response
                return copy.deepcopy(response)
            return call

    def client(self, selected, service, region):
        key = service, region
        if key not in clients:
            clients[key] = Client(service, region)
        return clients[key]

    def add(service, operation, *responses, region=REGION):
        queues[(service, region, operation)].extend(responses)

    monkeypatch.setattr(aws.Requests, 'client', client)
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'test'))
    return session, aws.Requests({'retry_attempts': 1}), add, calls


def denied():
    return ClientError({'Error': {'Code': 'AccessDeniedException', 'Message': 'secret must never escape'}}, 'Read')


PRIMARY = [
    ('vpc_peering_connection', 'ec2', 'describe_vpc_peering_connections', 'VpcPeeringConnections', 'NextToken', 'NextToken', {'VpcPeeringConnectionId': 'pcx-1'}),
    ('load_balancer_v2', 'elbv2', 'describe_load_balancers', 'LoadBalancers', 'Marker', 'NextMarker', {'LoadBalancerArn': 'lb-1', 'Type': 'network'}),
    ('ecr_public_repository', 'ecr-public', 'describe_repositories', 'repositories', 'nextToken', 'nextToken', {'repositoryArn': 'repo-1', 'repositoryName': 'one'}),
    ('client_vpn_endpoint', 'ec2', 'describe_client_vpn_endpoints', 'ClientVpnEndpoints', 'NextToken', 'NextToken', {'ClientVpnEndpointId': 'cvpn-1'}),
    ('lightsail_bucket', 'lightsail', 'get_buckets', 'buckets', 'pageToken', 'nextPageToken', {'name': 'bucket-1', 'arn': 'bucket-arn'}),
    ('kms_external_key_store', 'kms', 'describe_custom_key_stores', 'CustomKeyStores', 'Marker', 'NextMarker', {'CustomKeyStoreId': 'store-1', 'CustomKeyStoreName': 'one'}),
    ('ami', 'ec2', 'describe_images', 'Images', 'NextToken', 'NextToken', {'ImageId': 'ami-1'}),
]


@pytest.mark.parametrize('kind,service,operation,key,input_token,output_token,row', PRIMARY)
@pytest.mark.parametrize('state', ['complete', 'empty', 'paginated', 'error', 'partial'])
def test_primary_full_pagination_and_failure(sdk, kind, service, operation, key, input_token, output_token, row, state):
    session, requests, add, calls = sdk
    page = {key: [row]}
    if state in {'paginated', 'partial'}:
        page[output_token] = 'next'
        if service == 'kms':
            page['Truncated'] = True
        add(service, operation, page, {key: [row]} if state == 'paginated' else denied())
    else:
        add(service, operation, denied() if state == 'error' else {key: []} if state == 'empty' else page)
    fetch = facts.FETCHERS.get(kind)
    read = fetch(requests, session, REGION, ACCOUNT) if fetch else requests.pages(session, service, REGION, operation, key)
    expected = {'complete': 'collected', 'empty': 'empty', 'paginated': 'collected', 'error': 'denied', 'partial': 'partial'}[state]
    assert read.status == expected
    assert len(read.items) == {'complete': 1, 'empty': 0, 'paginated': 2, 'error': 0, 'partial': 1}[state]
    if state in {'paginated', 'partial'}:
        assert calls[-1][3][input_token] == 'next'
    assert 'secret must never escape' not in json.dumps(read.error)


@pytest.mark.parametrize('state', ['complete', 'empty', 'paginated', 'error', 'partial'])
def test_cognito_nested_inventory(sdk, state):
    session, requests, add, calls = sdk
    add('cognito-idp', 'list_user_pools', {'UserPools': [{'Id': 'us-east-1_pool'}]})
    row = {'ClientId': 'client-1'}
    first = {'UserPoolClients': [row]}
    if state in {'paginated', 'partial'}:
        first['NextToken'] = 'next'
        add('cognito-idp', 'list_user_pool_clients', first, {'UserPoolClients': []} if state == 'paginated' else denied())
    else:
        add('cognito-idp', 'list_user_pool_clients', denied() if state == 'error' else {'UserPoolClients': []} if state == 'empty' else first)
    read = facts._clients(requests, session, REGION, ACCOUNT)
    assert read.status == {'complete': 'collected', 'empty': 'empty', 'paginated': 'collected', 'error': 'denied', 'partial': 'partial'}[state]
    if read.items:
        assert read.items[0]['id'] == 'us-east-1_pool/client-1'


@pytest.mark.parametrize('state', ['complete', 'empty', 'paginated', 'error', 'partial'])
def test_batch_both_statuses_and_no_environment(sdk, state):
    session, requests, add, calls = sdk
    row = {'jobDefinitionArn': 'arn:job', 'status': 'ACTIVE', 'containerProperties': {'environment': [{'name': 'secret', 'value': 'sensitive'}], 'logConfiguration': {'logDriver': 'awslogs', 'options': {'awslogs-group': 'group', 'secret': 'sensitive'}}}}
    if state in {'paginated', 'partial'}:
        add('batch', 'describe_job_definitions', {'jobDefinitions': [row], 'nextToken': 'next'}, {'jobDefinitions': []} if state == 'paginated' else denied(), {'jobDefinitions': []})
    else:
        add('batch', 'describe_job_definitions', denied() if state == 'error' else {'jobDefinitions': []} if state == 'empty' else {'jobDefinitions': [row]}, {'jobDefinitions': []})
    read = facts._batch(requests, session, REGION, ACCOUNT)
    assert read.status == {'complete': 'collected', 'empty': 'empty', 'paginated': 'collected', 'error': 'denied', 'partial': 'partial'}[state]
    assert [x[3]['status'] for x in calls] == (['ACTIVE', 'ACTIVE', 'INACTIVE'] if state in {'paginated', 'partial'} else ['ACTIVE', 'INACTIVE'])
    projected = facts._job(requests, session, REGION, read.items)
    assert 'sensitive' not in json.dumps(projected)


DETAILS = [
    ('codepipeline_pipeline', {'name': 'pipe'}, 'codepipeline', 'get_pipeline', {'pipeline': {'name': 'pipe', 'stages': [{'actions': [{'actionTypeId': {'category': 'Deploy'}, 'configuration': {'Secret': 'sensitive'}}]}]}}, 'Pipeline'),
    ('rest_api_stage', {'clientCertificateId': 'cert', '_provenance': {'source_operation': 'get_stages'}}, 'apigateway', 'get_client_certificate', {'clientCertificateId': 'cert', 'expirationDate': datetime(2030, 1, 1, tzinfo=timezone.utc)}, 'ClientCertificate'),
    ('msk_cluster', {'ClusterArn': 'cluster', 'ClusterType': 'PROVISIONED'}, 'kafka', 'describe_cluster_v2', {'ClusterInfo': {'ClusterArn': 'cluster', 'Provisioned': {'EncryptionInfo': {'EncryptionInTransit': {'InCluster': True}}}}}, 'Detail'),
    ('lambda_function', {'FunctionName': 'fn', 'FunctionArn': 'fn-arn'}, 'lambda', 'get_function_code_signing_config', {'FunctionArn': 'fn-arn'}, 'CodeSigning'),
    ('backup_vault', {'BackupVaultName': 'vault'}, 'backup', 'get_backup_vault_notifications', {'SNSTopicArn': 'topic', 'BackupVaultEvents': ['BACKUP_JOB_FAILED']}, 'Notifications'),
    ('cognito_user_pool_client', {'UserPoolId': 'pool', 'ClientId': 'client'}, 'cognito-idp', 'describe_user_pool_client', {'UserPoolClient': {'ClientId': 'client', 'AccessTokenValidity': 1, 'IdTokenValidity': 1, 'RefreshTokenValidity': 30, 'ClientSecret': 'sensitive'}}, 'ClientDetail'),
    ('route53_zone', {'Id': '/hostedzone/zone', 'Config': {'PrivateZone': False}}, 'route53', 'get_dnssec', {'Status': {'ServeSignature': 'SIGNING'}, 'KeySigningKeys': [{'Status': 'ACTIVE', 'PublicKey': 'unneeded'}]}, 'DNSSEC'),
]


@pytest.mark.parametrize('kind,row,service,operation,response,field', DETAILS)
@pytest.mark.parametrize('error', [False, True])
def test_details_exact_envelopes_and_denied(sdk, kind, row, service, operation, response, field, error):
    session, requests, add, calls = sdk
    add(service, operation, denied() if error else response)
    result = facts.ENRICHERS[kind](requests, session, REGION, [row])[0]
    assert result[field]['collection_status'] == ('denied' if error else 'collected')
    assert 'sensitive' not in json.dumps(aws._safe(result))
    if kind == 'lambda_function' and not error:
        assert result[field]['CodeSigningConfigArn'] == ''
    if kind == 'route53_zone':
        assert result[field]['HostedZoneId'] == row['Id']


@pytest.mark.parametrize('state', ['complete', 'empty', 'paginated', 'error', 'partial'])
@pytest.mark.parametrize('kind,field,service,operation,key,row,child', [
    ('load_balancer_v2', 'Listeners', 'elbv2', 'describe_listeners', 'Listeners', {'LoadBalancerArn': 'lb'}, {'ListenerArn': 'listener', 'Protocol': 'TLS'}),
    ('client_vpn_endpoint', 'AuthorizationRules', 'ec2', 'describe_client_vpn_authorization_rules', 'AuthorizationRules', {'ClientVpnEndpointId': 'vpn'}, {'Status': {'Code': 'active'}, 'AuthorizeAllGroups': False, 'DestinationCidr': '10.0.0.0/8'}),
])
def test_nested_listing(sdk, kind, field, service, operation, key, row, child, state):
    session, requests, add, calls = sdk
    token = 'NextMarker' if service == 'elbv2' else 'NextToken'
    if state in {'paginated', 'partial'}:
        add(service, operation, {key: [child], token: 'next'}, {key: []} if state == 'paginated' else denied())
    else:
        add(service, operation, denied() if state == 'error' else {key: []} if state == 'empty' else {key: [child]})
    result = facts.ENRICHERS[kind](requests, session, REGION, [row])[0][field]
    assert result['collection_status'] == {'complete': 'collected', 'empty': 'empty', 'paginated': 'collected', 'error': 'denied', 'partial': 'partial'}[state]
    if kind == 'load_balancer_v2' and state in {'complete', 'paginated'}:
        assert result['items'][0]['Certificates'] == []
    if kind == 'client_vpn_endpoint' and state == 'complete':
        assert aws._safe(result)['items'][0]['Status']['Code'] == 'active'


def test_shared_cache_alias_scoped_snapshot(sdk):
    session, requests, add, calls = sdk
    add('sts', 'get_caller_identity', {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'id'})
    add('ec2', 'describe_vpc_peering_connections', {'VpcPeeringConnections': [{'VpcPeeringConnectionId': 'pcx', 'Status': {'Code': 'active'}, 'RequesterVpcInfo': {'OwnerId': ACCOUNT}}]})
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'options': {'regions': [REGION], 'service_concurrency': 1}}, ['vpc_peering', 'vpc_peering_connection'])
    selected = [c for c in snapshot['collections'] if c['type'] in {'vpc_peering', 'vpc_peering_connection'}]
    assert len(selected) == 2
    assert all(c['status'] == 'collected' and c['scope'] == ACCOUNT + '/' + REGION for c in selected)
    assert all(c['items'][0]['Status']['Code'] == 'active' for c in selected)
    assert len([c for c in calls if c[2] == 'describe_vpc_peering_connections']) == 1


def test_securityhub_all_audited_regions_and_partial(sdk):
    session, requests, add, calls = sdk
    requests.audited_regions_by_account = {ACCOUNT: [REGION, 'eu-west-1']}
    row = {'HubArn': f'arn:aws:securityhub:{REGION}:{ACCOUNT}:hub/default'}
    add('securityhub', 'get_findings', {'Findings': [], 'NextToken': 'next'}, {'Findings': []})
    add('securityhub', 'get_findings', denied(), region='eu-west-1')
    detail = facts._critical(requests, session, REGION, [row])[0]['CriticalFindings']
    assert detail['collection_status'] == 'denied'
    assert detail['covered_regions'] == [REGION]
    assert calls[0][3]['Filters']['SeverityLabel'][0]['Value'] == 'CRITICAL'


def test_ami_permissions_identity_and_absence(sdk):
    session, requests, add, calls = sdk
    add('ec2', 'describe_image_attribute', {'ImageId': 'ami-1', 'LaunchPermissions': []}, {'ImageId': 'ami-other', 'LaunchPermissions': []}, denied())
    for status in ['empty', 'malformed', 'denied']:
        result = facts._ami(requests, session, REGION, [{'ImageId': 'ami-1'}])[0]
        assert result['LaunchPermissions']['collection_status'] == status
        # Detail cache keys are single-flight; refresh only for separate test reads.
        requests._cache.clear()


def test_lightsail_access_keys_projected_before_cache(sdk):
    session, requests, add, calls = sdk
    add('lightsail', 'get_bucket_access_keys', {'accessKeys': [{'accessKeyId': 'key-id', 'secretAccessKey': 'must-never-be-cached', 'status': 'Active'}]})
    item = facts._lightsail(requests, session, REGION, [{'name': 'bucket', 'arn': 'arn:bucket', 'resourcesReceivingAccess': [{'arn': 'arn:instance'}]}])[0]
    assert item['resourcesReceivingAccess'] == ['arn:instance']
    assert item['AccessKeys']['collection_status'] == 'collected'
    assert item['_coverage']['accessLogConfig']['status'] == 'not_collected'
    assert 'must-never-be-cached' not in json.dumps(item)
    assert 'must-never-be-cached' not in json.dumps([f.result() for f in requests._cache.values()])


def test_certificate_not_found_preserves_join(sdk):
    session, requests, add, calls = sdk
    add('apigateway', 'get_client_certificate', ClientError({'Error': {'Code': 'NotFoundException'}}, 'GetClientCertificate'))
    detail = facts._stage(requests, session, REGION, [{'clientCertificateId': 'cert'}])[0]['ClientCertificate']
    assert detail['collection_status'] == 'empty' and detail['absent'] is True
    assert detail['clientCertificateId'] == 'cert'


def test_actions_readonly_registered_and_code_payload_omitted():
    assert set(facts.SPECS) <= set(aws.AWS_TYPES)
    assert facts.READ_ACTIONS <= aws.READ_ACTIONS
    assert all(op.startswith(('get_', 'list_', 'describe_')) for _, op in facts.READ_ACTIONS)
    assert aws._safe({'Code': {'Location': 'secret'}, 'Status': {'Code': 'active'}}) == {'Status': {'Code': 'active'}}


def test_native_shield_field_normalization_and_health_join(sdk):
    session, requests, add, calls = sdk
    add('shield', 'describe_protection', {'Protection': {'Id': 'p1', 'ApplicationLayerAutomaticResponseConfiguration': {'Status': 'ENABLED', 'Action': {'Block': {}}}}})
    add('route53', 'get_health_check', {'HealthCheck': {'Id': 'h1'}})
    item = facts._shield(requests, session, REGION, [{'Id': 'p1', 'ResourceArn': f'arn:aws:cloudfront::{ACCOUNT}:distribution/d1', 'HealthCheckIds': ['h1']}])[0]
    assert item['Protection']['Id'] == 'p1'
    assert item['Protection']['ApplicationLayerAutomaticResponse']['Status'] == 'ENABLED'
    assert item['Protection']['collection_status'] == 'collected'
    assert item['HealthChecks'] == [{'Id': 'h1', 'HealthCheck': {'Id': 'h1'}, 'collection_status': 'collected'}]


def test_xks_native_connectivity_normalization(sdk):
    session, requests, add, calls = sdk
    item = facts._store(requests, session, REGION, [{'CustomKeyStoreId': 'cks-1', 'CustomKeyStoreName': 'one', 'CustomKeyStoreType': 'EXTERNAL_KEY_STORE', 'XksProxyConfiguration': {'Connectivity': 'PUBLIC_ENDPOINT', 'AccessKeyId': 'omit'}, 'TrustAnchorCertificate': 'omit'}])[0]
    assert item['XksProxyConnectivity'] == 'PUBLIC_ENDPOINT'
    assert 'omit' not in json.dumps(item)


@pytest.mark.parametrize('error', [False, True])
def test_kms_tags_preserve_empty_vs_denied(sdk, error):
    session, requests, add, calls = sdk
    add('kms', 'list_resource_tags', denied() if error else {'Tags': []})
    item = facts._kms_tags(requests, session, REGION, [{'KeyId': 'key'}])[0]
    assert item['_coverage']['Tags']['status'] == ('denied' if error else 'empty')
    assert ('Tags' in item) is (not error)


def test_lambda_signing_configuration(sdk):
    session, requests, add, calls = sdk
    add('lambda', 'get_function_code_signing_config', {'FunctionArn': 'fn-arn', 'CodeSigningConfigArn': 'csc'})
    add('lambda', 'get_code_signing_config', {'CodeSigningConfig': {'CodeSigningConfigArn': 'csc', 'AllowedPublishers': {'SigningProfileVersionArns': ['profile']}, 'CodeSigningPolicies': {'UntrustedArtifactOnDeployment': 'Enforce'}}})
    item = facts._lambda(requests, session, REGION, [{'FunctionName': 'fn'}])[0]
    assert item['CodeSigningConfig']['CodeSigningConfig']['CodeSigningPolicies']['UntrustedArtifactOnDeployment'] == 'Enforce'


def test_role_permissions_and_immutable_versions():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / 'infra/aws'
    current = json.loads((root / 'customer-role.json').read_text())
    current_role = current['Resources']['AuditRole']
    assert current_role['Properties']['AssumeRolePolicyDocument']['Statement'][0]['Principal']['AWS'] == {'Ref': 'CollectorRoleArn'}
    assert 'CollectorRoleArn' in current['Parameters']
    assert current_role['Properties'].pop('ManagedPolicyArns') == [
        'arn:aws:iam::aws:policy/ReadOnlyAccess',
        'arn:aws:iam::aws:policy/SecurityAudit',
        'arn:aws:iam::aws:policy/IAMAccessAnalyzerFullAccess',
    ]
    actions = set()
    gateway_resources = []
    for resource in current['Resources'].values():
        if resource['Type'] != 'AWS::IAM::ManagedPolicy':
            continue
        policy = resource['Properties']['PolicyDocument']
        assert len(json.dumps(policy, separators=(',', ':'))) <= 6144
        for statement in policy['Statement']:
            values = statement['Action'] if isinstance(statement['Action'], list) else [statement['Action']]
            actions.update(values)
            if statement['Action'] == 'apigateway:GET':
                assert isinstance(statement['Resource'], list)
                gateway_resources.extend(statement['Resource'])
    assert {'Fn::Sub': 'arn:${AWS::Partition}:apigateway:*::/clientcertificates/*'} in gateway_resources
    assert {'Fn::Sub': 'arn:${AWS::Partition}:apigateway:*::/restapis/*/deployments/*'} in gateway_resources
    assert '*' not in gateway_resources
    assert {'kms:DescribeCustomKeyStores', 'kafka:DescribeClusterV2', 'ecr-public:DescribeRepositories', 'shield:DescribeProtection'} <= actions


def test_securityhub_complete_multiple_regions(sdk):
    session, requests, add, calls = sdk
    requests.audited_regions_by_account = {ACCOUNT: [REGION, 'eu-west-1']}
    add('securityhub', 'get_findings', {'Findings': []})
    add('securityhub', 'get_findings', {'Findings': [{'Id': 'finding', 'Region': 'eu-west-1', 'Severity': {'Label': 'CRITICAL'}, 'RecordState': 'ACTIVE', 'Workflow': {'Status': 'NEW'}, 'Description': 'unneeded'}]}, region='eu-west-1')
    detail = facts._critical(requests, session, REGION, [{'HubArn': f'arn:aws:securityhub:{REGION}:{ACCOUNT}:hub/default'}])[0]['CriticalFindings']
    assert detail['collection_status'] == 'collected'
    assert detail['covered_regions'] == [REGION, 'eu-west-1']
    assert 'Description' not in detail['items'][0]


def test_shield_failed_detail_and_missing_health_check(sdk):
    session, requests, add, calls = sdk
    add('shield', 'describe_protection', denied())
    add('route53', 'get_health_check', ClientError({'Error': {'Code': 'NoSuchHealthCheck'}}, 'GetHealthCheck'))
    item = facts._shield(requests, session, REGION, [{'Id': 'p', 'ResourceArn': f'arn:aws:cloudfront::{ACCOUNT}:distribution/d', 'HealthCheckIds': ['h']}])[0]
    assert item['Protection']['collection_status'] == 'denied'
    assert item['HealthChecks'][0]['collection_status'] == 'empty'
    assert item['HealthChecks'][0]['Id'] == 'h'
    assert item['HealthChecks'][0]['absent'] is True


def test_notifications_documented_absence(sdk):
    session, requests, add, calls = sdk
    add('backup', 'get_backup_vault_notifications', ClientError({'Error': {'Code': 'ResourceNotFoundException'}}, 'GetBackupVaultNotifications'))
    detail = facts._notifications(requests, session, REGION, [{'BackupVaultName': 'vault'}])[0]['Notifications']
    assert detail['collection_status'] == 'empty' and detail['absent'] is True


def test_organization_retains_management_account(sdk):
    session, requests, add, calls = sdk
    add('organizations', 'describe_organization', {'Organization': {'Id': 'o-org', 'MasterAccountId': ACCOUNT}})
    read = aws._account_configuration(requests, session, REGION, {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/test'})
    assert read.items[0]['Organization'] == {'collection_status': 'collected', 'OrganizationId': 'o-org', 'MasterAccountId': ACCOUNT}


def test_pagination_limit_stays_partial(sdk):
    session, requests, add, calls = sdk
    requests.max_pages = 1
    add('ec2', 'describe_vpc_peering_connections', {'VpcPeeringConnections': [{'VpcPeeringConnectionId': 'pcx'}], 'NextToken': 'next'})
    read = requests.pages(session, 'ec2', REGION, 'describe_vpc_peering_connections', 'VpcPeeringConnections')
    assert read.status == 'partial' and read.error['code'] == 'page_limit'


@pytest.mark.parametrize('response,status', [
    ({'Organization': {'Id': 'o-org'}}, 'malformed'),
    (ClientError({'Error': {'Code': 'AWSOrganizationsNotInUseException'}}, 'DescribeOrganization'), 'empty'),
    (ClientError({'Error': {'Code': 'AccessDeniedException'}}, 'DescribeOrganization'), 'denied'),
])
def test_organization_malformed_absent_denied(sdk, response, status):
    session, requests, add, calls = sdk
    add('organizations', 'describe_organization', response)
    read = aws._account_configuration(requests, session, REGION, {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/test'})
    assert read.items[0]['Organization']['collection_status'] == status


def test_cognito_secret_presence_metadata_before_cache(sdk):
    session, requests, add, calls = sdk
    add('cognito-idp', 'describe_user_pool_client', {'UserPoolClient': {'ClientId': 'client', 'ClientSecret': 'must-never-cache', 'AllowedOAuthScopes': ['openid']}})
    item = facts._client(requests, session, REGION, [{'UserPoolId': 'pool', 'ClientId': 'client'}])[0]
    assert item['ClientDetail']['UserPoolClient']['ClientSecretPresent'] is True
    assert item['ClientDetail']['UserPoolClient']['AllowedOAuthScopes'] == ['openid']
    assert 'must-never-cache' not in json.dumps([f.result() for f in requests._cache.values()])
