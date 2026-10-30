"""Bounded SDK-response -> actual producer -> registered consumer audit probes.

No cloud calls. Stubber validates installed SDK shapes; these probes do not claim
all-service collect() execution, exhaustive policy equivalence or live behavior.
"""
import json
from datetime import datetime, timezone

import pytest
from peaso.engine import _registry
from peaso.collectors import aws, aws_b_services, aws_facts_cb_ca, aws_privesc_facts

KINDS = {'cloudfront_distribution', 'opensearch_domain', 'redshift_cluster',
         'secret', 'cognito_user_pool', 'emr_cluster'}
REGISTRY = {c.id: c for c in _registry() if c.provider == 'aws' and c.kind in KINDS}
ACCOUNT, REGION = '123456789012', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
NOW = datetime(2026, 10, 19, tzinfo=timezone.utc)


@pytest.fixture
def sdk(monkeypatch):
    import boto3
    from botocore.stub import Stubber
    session = boto3.Session(aws_access_key_id='test', aws_secret_access_key='test', region_name=REGION)
    clients, stubs = {}, {}
    def stub(service):
        if service not in clients:
            clients[service] = session.client(service, region_name=REGION)
            stubs[service] = Stubber(clients[service])
            stubs[service].activate()
        return stubs[service]
    monkeypatch.setattr(aws.Requests, 'client', lambda self, selected, service, region: clients[service])
    yield aws.Requests({'retry_attempts': 1}), session, stub
    for value in stubs.values():
        value.assert_no_pending_responses()
        value.deactivate()


def inventory(kind, rows, status='collected'):
    return {'context': {'provider': 'aws', 'scope': SCOPE, 'Account': ACCOUNT, 'created_at': NOW.isoformat()},
            'collections': {kind: [{'type': kind, 'scope': SCOPE, 'account_id': ACCOUNT,
                                   'global': False, 'status': status, 'items': rows}]},
            kind: [{'type': kind, 'scope': SCOPE, 'data': row} for row in rows]}


def cf_config(insecure=False):
    return {'CallerReference': 'review', 'Comment': '', 'Enabled': True,
            'Origins': {'Quantity': 1, 'Items': [{'Id': 'origin', 'DomainName': 'app.example.org',
                'CustomOriginConfig': {'HTTPPort': 80, 'HTTPSPort': 443, 'OriginProtocolPolicy': 'https-only',
                    'OriginSslProtocols': {'Quantity': 1, 'Items': ['TLSv1.2']}}}]},
            'DefaultCacheBehavior': {'TargetOriginId': 'origin', 'ViewerProtocolPolicy': 'https-only',
                                    'TrustedSigners': {'Enabled': False, 'Quantity': 0}},
            'CacheBehaviors': {'Quantity': 1, 'Items': [{'PathPattern': '/legacy/*', 'TargetOriginId': 'origin',
                'ViewerProtocolPolicy': 'allow-all' if insecure else 'redirect-to-https',
                'TrustedSigners': {'Enabled': False, 'Quantity': 0}}]}}


@pytest.mark.parametrize('variant', ['secure', 'insecure', 'missing', 'denied'])
def test_cloudfront_all_behaviors_native_config(sdk, variant):
    requests, session, stub = sdk
    api = stub('cloudfront')
    args = {'Id': 'E123'}
    if variant == 'denied':
        api.add_client_error('get_distribution_config', service_error_code='AccessDenied', expected_params=args)
    else:
        body = {} if variant == 'missing' else {'DistributionConfig': cf_config(variant == 'insecure')}
        api.add_response('get_distribution_config', body, args)
    item = aws_b_services._enricher('cloudfront_distribution')(requests, session, REGION, [{'Id': 'E123'}])[0]
    assert REGISTRY['aws.b.cloudfront.viewer_encryption'].evaluate(item, {})[0] == {
        'secure': 'PASS', 'insecure': 'FAIL', 'missing': 'UNKNOWN', 'denied': 'UNKNOWN'}[variant]


@pytest.mark.parametrize('variant', ['secure', 'insecure', 'missing', 'denied'])
def test_opensearch_https_native_domain(sdk, variant):
    requests, session, stub = sdk
    api = stub('opensearch')
    args = {'DomainName': 'review'}
    if variant == 'denied':
        api.add_client_error('describe_domain', service_error_code='AccessDeniedException', expected_params=args)
    else:
        status = {'DomainId': ACCOUNT+'/review', 'DomainName': 'review',
                  'ARN': f'arn:aws:es:{REGION}:{ACCOUNT}:domain/review',
                  'ClusterConfig': {}}
        if variant != 'missing': status['DomainEndpointOptions'] = {'EnforceHTTPS': variant == 'secure'}
        api.add_response('describe_domain', {'DomainStatus': status}, args)
    item = aws._enrich(requests, session, REGION, 'opensearch_domain', [{'DomainName': 'review'}], account=ACCOUNT, partition='aws')[0]
    assert REGISTRY['aws.cb.opensearch.enforce_https'].evaluate(item, {})[0] == {
        'secure': 'PASS', 'insecure': 'FAIL', 'missing': 'UNKNOWN', 'denied': 'UNKNOWN'}[variant]


@pytest.mark.parametrize('variant', ['secure', 'insecure', 'missing', 'denied'])
def test_redshift_shared_logging_and_parameter_producer(sdk, variant):
    requests, session, stub = sdk
    api = stub('redshift')
    args = {'ClusterIdentifier': 'review'}
    if variant == 'denied':
        api.add_client_error('describe_logging_status', service_error_code='AccessDenied', expected_params=args)
    else:
        api.add_response('describe_logging_status', {} if variant == 'missing' else {'LoggingEnabled': variant == 'secure'}, args)
    api.add_response('describe_cluster_parameters', {'Parameters': [{'ParameterName': 'require_ssl',
        'ParameterValue': 'true' if variant == 'secure' else 'false'}]}, {'ParameterGroupName': 'review'})
    original = {'ClusterIdentifier': 'review', 'ClusterParameterGroups': [{'ParameterGroupName': 'review'}]}
    item = aws_b_services._enricher('redshift_cluster')(requests, session, REGION, [original])[0]
    item = aws_facts_cb_ca._redshift_facts(requests, session, REGION, [item])[0]
    for cid in ('aws.b.redshift.audit_logging', 'aws.cb.redshift.audit_logging'):
        assert REGISTRY[cid].evaluate(item, {})[0] == {
            'secure': 'PASS', 'insecure': 'FAIL', 'missing': 'UNKNOWN', 'denied': 'UNKNOWN'}[variant]
    assert REGISTRY['aws.cb.redshift.require_ssl'].evaluate(item, {})[0] == ('PASS' if variant == 'secure' else 'FAIL')


@pytest.mark.parametrize('variant', ['secure', 'insecure', 'missing', 'denied'])
def test_cognito_native_describe_and_client_projection(sdk, variant):
    requests, session, stub = sdk
    api = stub('cognito-idp')
    pool_id, client_id = 'us-east-1_review', 'reviewclient'
    args = {'UserPoolId': pool_id}
    if variant == 'denied':
        api.add_client_error('describe_user_pool', service_error_code='AccessDeniedException', expected_params=args)
    else:
        pool = {'Id': pool_id}
        if variant != 'missing': pool['MfaConfiguration'] = 'ON' if variant == 'secure' else 'OFF'
        api.add_response('describe_user_pool', {'UserPool': pool}, args)
    api.add_response('describe_risk_configuration', {'RiskConfiguration': {}}, args)
    api.add_response('list_user_pool_clients', {'UserPoolClients': [{'ClientId': client_id, 'UserPoolId': pool_id}]}, {**args, 'MaxResults': 60})
    api.add_response('describe_user_pool_client', {'UserPoolClient': {'ClientId': client_id, 'UserPoolId': pool_id,
        'ClientSecret': 'synthetic-client-secret-value', 'EnableTokenRevocation': variant == 'secure'}}, {**args, 'ClientId': client_id})
    item = aws_b_services._enricher('cognito_user_pool')(requests, session, REGION, [{'Id': pool_id}])[0]
    # Known optional MFA omission follows the source adapter's OFF contract.
    assert REGISTRY['aws.b.cognito.required_mfa'].evaluate(item, {})[0] == {
        'secure': 'PASS', 'insecure': 'FAIL', 'missing': 'FAIL', 'denied': 'UNKNOWN'}[variant]
    client = item['Clients']['items'][0]['Configuration']['UserPoolClient']
    assert 'ClientSecret' not in client and client['ClientSecretPresent'] is True
    assert REGISTRY['aws.c2b.cognito.clients_token_revocation'].evaluate(item, {})[0] == {
        'secure': 'PASS', 'insecure': 'FAIL', 'missing': 'FAIL', 'denied': 'UNKNOWN'}[variant]


@pytest.mark.parametrize('variant', ['secure', 'insecure', 'missing', 'denied', 'foreign'])
def test_secret_native_rotation_identity_and_denial(sdk, variant):
    requests, session, stub = sdk
    api = stub('secretsmanager')
    arn = f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:review-abcdef'
    args = {'SecretId': arn}
    if variant == 'denied':
        api.add_client_error('describe_secret', service_error_code='AccessDeniedException', expected_params=args)
    else:
        body = {'ARN': arn+'foreign' if variant == 'foreign' else arn, 'Name': 'review'}
        if variant != 'missing': body['RotationEnabled'] = variant == 'secure'
        api.add_response('describe_secret', body, args)
    api.add_response('get_resource_policy', {'ARN': arn, 'Name': 'review'}, args)
    item = aws._enrich(requests, session, REGION, 'secret', [{'ARN': arn, 'Name': 'review', 'RotationEnabled': True}], account=ACCOUNT, partition='aws')[0]
    assert REGISTRY['aws.secretsmanager.rotation'].evaluate(item, inventory('secret', [item]))[0] == {
        'secure': 'PASS', 'insecure': 'FAIL', 'missing': 'FAIL', 'denied': 'UNKNOWN', 'foreign': 'UNKNOWN'}[variant]


@pytest.mark.parametrize('variant', ['secure', 'insecure', 'missing', 'denied'])
def test_emr_native_detail_projection_retains_kerberos(sdk, variant):
    requests, session, stub = sdk
    api = stub('emr')
    args = {'ClusterId': 'j-REVIEW'}
    if variant == 'denied':
        api.add_client_error('describe_cluster', service_error_code='AccessDeniedException', expected_params=args)
    else:
        cluster = {'Id': 'j-REVIEW'}
        if variant == 'secure': cluster['KerberosAttributes'] = {'Realm': 'EXAMPLE.ORG', 'KdcAdminPassword': 'never-retain'}
        api.add_response('describe_cluster', {} if variant == 'missing' else {'Cluster': cluster}, args)
    item = aws_privesc_facts._emr_clusters(requests, session, REGION, [{'Id': 'j-REVIEW', 'Status': {'State': 'TERMINATED'}}])[0]
    assert 'never-retain' not in json.dumps(item)
    assert REGISTRY['aws.c2b.emr.cluster_kerberos_enabled'].evaluate(item, {})[0] == {
        'secure': 'PASS', 'insecure': 'FAIL', 'missing': 'UNKNOWN', 'denied': 'UNKNOWN'}[variant]


def test_cloudfront_external_bucket_fact_has_no_native_producer():
    """Regression receipt for a coverage gap, not a safe-PASS assertion."""
    config = cf_config()
    config['Origins']['Items'] = [{'Id': 'origin', 'DomainName': 'partner.s3.amazonaws.com',
                                  'S3OriginConfig': {'OriginAccessIdentity': ''}}]
    item = {'Config': {'collection_status': 'collected', 'DistributionConfig': config}}
    check = REGISTRY['aws.c2b.cloudfront.s3_origin_bucket_exists']
    assert check.evaluate(item, inventory('bucket', [], 'empty'))[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind', ['secret', 'opensearch_domain'])
def test_public_policy_wildcard_principal_arn_is_not_restrictive(sdk, kind):
    requests, session, stub = sdk
    policy = {'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': '*', 'Resource': '*',
                            'Condition': {'StringLike': {'aws:PrincipalArn': '*'}}}]}
    if kind == 'secret':
        arn = f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:review-abcdef'
        api = stub('secretsmanager')
        api.add_response('describe_secret', {'ARN': arn, 'Name': 'review'}, {'SecretId': arn})
        api.add_response('get_resource_policy', {'ARN': arn, 'Name': 'review', 'ResourcePolicy': json.dumps(policy)}, {'SecretId': arn})
        item = aws._enrich(requests, session, REGION, kind, [{'ARN': arn, 'Name': 'review'}], account=ACCOUNT, partition='aws')[0]
        cid = 'aws.cb.secretsmanager.policy_not_public'
    else:
        api = stub('opensearch')
        api.add_response('describe_domain', {'DomainStatus': {'DomainId': ACCOUNT+'/review', 'DomainName': 'review',
            'ARN': f'arn:aws:es:{REGION}:{ACCOUNT}:domain/review', 'ClusterConfig': {},
            'AccessPolicies': json.dumps(policy)}}, {'DomainName': 'review'})
        item = aws._enrich(requests, session, REGION, kind, [{'DomainName': 'review'}], account=ACCOUNT, partition='aws')[0]
        cid = 'aws.cb.opensearch.access_policy_not_public'
    assert REGISTRY[cid].evaluate(item, inventory(kind, [item]))[0] == 'FAIL'


@pytest.mark.parametrize('variant', ['secure', 'insecure', 'missing', 'denied'])
def test_emr_security_configuration_native_join(sdk, variant):
    from peaso.collectors import aws_facts_data_identity
    requests, session, stub = sdk
    api = stub('emr')
    api.add_response('describe_cluster', {'Cluster': {'Id': 'j-REVIEW', 'SecurityConfiguration': 'review'}}, {'ClusterId': 'j-REVIEW'})
    if variant == 'denied':
        api.add_client_error('describe_security_configuration', service_error_code='AccessDeniedException', expected_params={'Name': 'review'})
    else:
        document = {} if variant == 'missing' else {'EncryptionConfiguration': {
            'EnableAtRestEncryption': variant == 'secure', 'EnableInTransitEncryption': variant == 'secure'}}
        document['AuthenticationConfiguration'] = {'KerberosConfiguration': {'Secret': 'never-retain'}}
        api.add_response('describe_security_configuration', {'Name': 'review', 'SecurityConfiguration': json.dumps(document)}, {'Name': 'review'})
    cluster = aws_privesc_facts._emr_clusters(requests, session, REGION, [{'Id': 'j-REVIEW', 'Status': {'State': 'TERMINATED'}}])[0]
    config = aws_facts_data_identity._emr_security_configuration(requests, session, REGION, [{'Name': 'review'}])[0]
    assert 'never-retain' not in json.dumps(config)
    index = inventory('emr_security_configuration', [config])
    for cid in ('aws.c2b.emr.cluster_at_rest_encryption', 'aws.c2b.emr.cluster_in_transit_encryption'):
        assert REGISTRY[cid].evaluate(cluster, index)[0] == {
            'secure': 'PASS', 'insecure': 'FAIL', 'missing': 'FAIL', 'denied': 'UNKNOWN'}[variant]


@pytest.mark.parametrize('operator,key,value,expected', [
    ('StringLike', 'aws:PrincipalArn', '*', 'FAIL'),
    ('StringLike', 'aws:PrincipalArn', '**', 'FAIL'),
    ('ArnLike', 'aws:PrincipalArn', '*', 'FAIL'),
    ('ArnEquals', 'aws:PrincipalArn', '*', 'FAIL'),
    ('StringLike', 'aws:SourceAccount', '*', 'FAIL'),
    ('StringLike', 'aws:PrincipalOrgID', '*', 'FAIL'),
    ('StringLike', 'aws:SourceVpc', '*', 'FAIL'),
    ('StringLike', 'aws:SourceArn', '*', 'FAIL'),
    ('ArnLike', 'aws:PrincipalArn', 'arn:aws:iam::*:role/*', 'FAIL'),
    ('StringLike', 'aws:PrincipalArn', [f'arn:aws:iam::{ACCOUNT}:role/review', '*'], 'FAIL'),
    ('ArnLike', 'aws:PrincipalArn', f'arn:aws:iam::{ACCOUNT}:role/*', 'PASS'),
    ('StringLike', 'aws:SourceArn', 'arn:aws:s3:::named-bucket/*', 'PASS'),
    ('StringEquals', 'aws:SourceAccount', ACCOUNT, 'PASS'),
    ('StringEquals', 'aws:PrincipalOrgID', 'o-example', 'PASS'),
    ('StringEquals', 'aws:SourceVpc', 'vpc-0123456789abcdef0', 'PASS'),
    ('StringEquals', 'aws:PrincipalArn', '*', 'PASS'),  # Literal star cannot match an IAM principal ARN.
    ('StringLike', 'aws:SourceAccount', '1234*', 'UNKNOWN'),
    ('StringLike', 'aws:PrincipalOrgID', 'o-*', 'UNKNOWN'),
    ('StringLike', 'aws:SourceVpc', 'vpc-*', 'UNKNOWN'),
    ('ArnLike', 'aws:PrincipalArn', 'arn:aws:iam::*:role/review', 'UNKNOWN'),
    ('StringLike', 'aws:PrincipalArn', '${aws:PrincipalArn}', 'UNKNOWN'),
])
def test_policy_condition_wildcard_boundary_contract(operator, key, value, expected):
    statement = {'Effect': 'Allow', 'Principal': '*', 'Action': '*', 'Resource': '*',
                 'Condition': {operator: {key: value}}}
    item = {'ARN': f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:review-abcdef',
            'Policy': {'collection_status': 'collected', 'ResourcePolicy': {'Statement': [statement]}}}
    status = REGISTRY['aws.cb.secretsmanager.policy_not_public'].evaluate(item, inventory('secret', [item]))[0]
    assert status == expected
