"""Isolated signed GCP sw51 compliance decisions."""
import copy

import pytest
from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw51 as m

SCOPE = 'projects/p'
B = 'projects/p/global/backendServices/b'
P = 'projects/p/global/securityPolicies/p'
K = 'projects/p/locations/us-central1/keyRings/r/cryptoKeys/k'
A = '//storage.googleapis.com/buckets/b'


@pytest.fixture(scope='module', autouse=True)
def no_registry_leak():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in m.META]


def row(name=None, selfLink=None, **fields):
    result = {'_provenance': {'scope': SCOPE}, **fields}
    if name is not None:
        result['name'] = name
    if selfLink is not None:
        result['selfLink'] = selfLink
    return result


def facts(kind, subject, extras=None, policy=None, *, status='collected', scope=SCOPE):
    groups = {kind: [subject]}
    groups.update(extras or {})
    index = {'context': {'provider': 'gcp', 'scope': SCOPE,
              'created_at': '2026-10-12T00:00:00Z',
              'metadata': {'sw51_policy': {'status': 'collected', 'scope': SCOPE, **(policy or {})}}},
             'collections': {}, }
    for k, rows in groups.items():
        envelope = {'type': k, 'scope': scope, 'status': status, 'items': rows}
        if k == 'asset':
            envelope['readTime'] = '2026-10-12T00:00:00Z'
        if k == 'asset_previous':
            envelope['readTime'] = '2026-10-10T00:00:00Z'
        index['collections'][k] = [envelope]
        index[k] = [{'type': k, 'scope': scope, 'data': r} for r in rows]
    return index


def decision(id, subject, extras=None, policy=None, **kwargs):
    kind = m.META[id]['kind']
    return evaluate_check(id, subject, facts(kind, subject, extras, policy, **kwargs))[0]


def bucket(**fields):
    return row('b', **{'iamPolicy': {'bindings': []},
                       'iamConfiguration': {'uniformBucketLevelAccess': {'enabled': True}},
                       '_representation': 'full', **fields})


def backend(**fields):
    return row(selfLink=B, _representation='full', **fields)


def security(rules=None, **fields):
    return row(selfLink=P, rules=rules if rules is not None else [
        {'priority': 2147483647, 'match': {'versionedExpr': 'SRC_IPS_V1'}, 'action': 'allow'}], **fields)


def acl(name, role='READER', entity='allUsers'):
    return row(name, bucket='b', role=role, entity=entity)


def effective_bucket(access=False, write=False):
    return row('b', resolutionComplete=True, publicAccess=access, publicWrite=write)


def test_bucket_public_access_pass_fail_unknown_and_exclusion():
    id = 'gcp_pci_bucket_7dc6cb8c2e05'
    good = bucket()
    assert decision(id, good, {'bucket_effective_iam': [effective_bucket()]}, {'excludedPublicBuckets': []}) == 'PASS'
    bad = bucket(iamPolicy={'bindings': [{'role': 'roles/storage.objectViewer', 'members': ['allUsers']}]})
    assert decision(id, bad, policy={'excludedPublicBuckets': []}) == 'FAIL'
    assert decision(id, good, policy={'excludedPublicBuckets': ['b']}) == 'NOT_APPLICABLE'
    assert decision(id, good) == 'UNKNOWN'
    no_uniform = bucket(iamConfiguration={'uniformBucketLevelAccess': {'enabled': False}})
    assert decision(id, no_uniform, {'bucket_acl': [acl('b/a')], 'bucket_effective_iam': [effective_bucket()]}, {'excludedPublicBuckets': []}) == 'FAIL'
    assert decision(id, no_uniform, {'bucket_acl': [acl('b/a')]}, {'excludedPublicBuckets': []}) == 'FAIL'
    assert decision(id, good, {'bucket_effective_iam': [effective_bucket(access=True)]}, {'excludedPublicBuckets': []}) == 'FAIL'
    assert decision(id, no_uniform, policy={'excludedPublicBuckets': []}) == 'UNKNOWN'


def test_bucket_public_write_pass_fail_unknown():
    id = 'gcp_pci_bucket_56c6b1b7f813'
    good = bucket()
    assert decision(id, good, {'bucket_effective_iam': [effective_bucket()]}) == 'PASS'
    bad = bucket(iamPolicy={'bindings': [{'role': 'roles/storage.objectCreator', 'members': ['allUsers']}]})
    assert decision(id, bad) == 'FAIL'
    nonuniform = bucket(iamConfiguration={'uniformBucketLevelAccess': {'enabled': False}})
    extras = {'bucket_acl': [acl('b/a', 'READER')], 'object_acl': [acl('b/o', 'WRITER')],
              'bucket_effective_iam': [effective_bucket()]}
    assert decision(id, nonuniform, extras) == 'FAIL'
    assert decision(id, nonuniform, {'bucket_acl': [acl('b/a', 'READER')], 'object_acl': [acl('b/o', 'WRITER')]}) == 'FAIL'
    extras['object_acl'] = [acl('b/o', 'READER')]
    assert decision(id, nonuniform, extras) == 'PASS'
    assert decision(id, good, {'bucket_effective_iam': [effective_bucket(write=True)]}) == 'FAIL'
    assert decision(id, nonuniform) == 'UNKNOWN'


def test_asset_inventory_pass_fail_unknown_not_applicable():
    id = 'gcp_c5_asset_inventory'
    a = row(A, assetType='storage.googleapis.com/Bucket', updateTime='2026-10-11T00:00:00Z')
    service = row(A, assetType=a['assetType'])
    policy = {'approved_asset_types': [a['assetType']]}
    assert decision(id, a, {'asset_service_inventory': [service]}, policy) == 'PASS'
    assert decision(id, a, {'asset_service_inventory': [row('other', assetType=a['assetType'])]}, policy) == 'FAIL'
    assert decision(id, a, {'asset': [], 'asset_service_inventory': [service]}, policy) == 'FAIL'
    assert decision(id, {k: v for k, v in a.items() if k != 'updateTime'}, {'asset_service_inventory': [service]}, policy) == 'FAIL'
    assert decision(id, {**a, 'updateTime': None}, {'asset_service_inventory': [service]}, policy) == 'UNKNOWN'
    assert decision(id, a, policy=policy) == 'UNKNOWN'
    assert decision(id, a, {'asset_service_inventory': [service]}, {'approved_asset_types': ['other']}) == 'NOT_APPLICABLE'


def test_asset_risk_label_pass_fail_unknown_not_applicable():
    id = 'gcp_c5_asset_risk_label'
    policy = {'risk_asset_types': ['storage.googleapis.com/Bucket'], 'required_risk_label': 'risk', 'approved_risk_values': ['high']}
    a = row(A, assetType='storage.googleapis.com/Bucket', resource={'data': {'labels': {'risk': 'high'}}})
    assert decision(id, a, policy=policy) == 'PASS'
    assert decision(id, {**a, 'resource': {'data': {'labels': {}}}}, policy=policy) == 'FAIL'
    assert decision(id, {**a, 'resource': {'data': {}}}, policy=policy) == 'UNKNOWN'
    assert decision(id, a) == 'UNKNOWN'
    assert decision(id, a, policy={**policy, 'risk_asset_types': ['other']}) == 'NOT_APPLICABLE'


def test_asset_change_audit_pass_fail_unknown_not_applicable():
    id = 'gcp_c5_asset_change_audit'
    now = row(A, updateTime='2026-10-11T00:00:00Z')
    prior = row(A, updateTime='2026-10-10T00:00:00Z')
    event = row('event1', logName='projects/p/logs/cloudaudit.googleapis.com%2Factivity',
                operationSucceeded=True, timestamp='2026-10-11T00:01:00Z',
                protoPayload={'resourceName': A, 'methodName': 'storage.buckets.update'})
    policy = {'audit_window': {'start': '2026-10-10T00:00:00Z', 'end': '2026-10-12T00:00:00Z'}}
    assert decision(id, now, {'asset_previous': [prior], 'asset_audit_log': [event]}, policy) == 'PASS'
    assert decision(id, now, {'asset_previous': [prior], 'asset_audit_log': []}, policy) == 'FAIL'
    assert decision(id, now, {'asset': [], 'asset_previous': [prior], 'asset_audit_log': []}, policy) == 'FAIL'
    assert decision(id, now, {'asset_previous': [now], 'asset_audit_log': []}, policy) == 'NOT_APPLICABLE'
    assert decision(id, now, {'asset_previous': [prior]}, policy) == 'UNKNOWN'
    narrow = {'audit_window': {'start': '2026-10-11T00:00:00Z', 'end': '2026-10-12T00:00:00Z'}}
    assert decision(id, now, {'asset_previous': [prior], 'asset_audit_log': []}, narrow) == 'UNKNOWN'


def test_asset_region_pass_fail_unknown_not_applicable():
    id = 'gcp_c5_region'
    a = row(A, assetType='storage.googleapis.com/Bucket')
    policy = {'asset_locations': {A: {'kind': 'bucket', 'resource_name': 'b'}},
              'approved_regions_by_asset': {A: ['us-central1']}, 'location_region_mapping': {}}
    assert decision(id, a, {'bucket': [bucket(location='us-central1')]}, policy) == 'PASS'
    assert decision(id, a, {'bucket': [bucket(location='europe-west1')]}, policy) == 'FAIL'
    assert decision(id, a, policy=policy) == 'UNKNOWN'
    assert decision(id, a, policy={'asset_locations': {}, 'approved_regions_by_asset': {}}) == 'NOT_APPLICABLE'


def test_key_versions_pass_fail_unknown():
    id = 'gcp_c5_key_versions'
    key = row(K)
    version = row(K + '/cryptoKeyVersions/1', state='ENABLED')
    schedule = {'key_version_schedule': {K: {version['name']: {'enabled_expiry': '2026-11-01T00:00:00Z', 'destroy_not_before': '2026-01-01T00:00:00Z'}}}}
    assert decision(id, key, {'kms_key_version': [version]}, schedule) == 'PASS'
    expired = copy.deepcopy(schedule)
    expired['key_version_schedule'][K][version['name']]['enabled_expiry'] = '2026-10-01T00:00:00Z'
    assert decision(id, key, {'kms_key_version': [version]}, expired) == 'FAIL'
    assert decision(id, key, {'kms_key_version': [row(version['name'], state='DESTROYED', destroyTime='2025-01-01T00:00:00Z')]}, schedule) == 'FAIL'
    assert decision(id, key, policy=schedule) == 'UNKNOWN'


def test_effective_kms_users_pass_fail_unknown():
    id = 'gcp_pci_kms_key_a3927a5f3b84'
    key = row(K)
    def use(principals, complete=True):
        return row(K, principals=principals, resolutionComplete=complete)
    assert decision(id, key, {'kms_effective_use': [use(['user:a', 'user:b', 'user:c'])]}) == 'PASS'
    assert decision(id, key, {'kms_effective_use': [use(['user:a', 'user:b', 'user:c', 'user:d'])]}) == 'FAIL'
    assert decision(id, key, {'kms_effective_use': [use(['allUsers'])]}) == 'FAIL'
    assert decision(id, key, {'kms_effective_use': [use(['user:a'], False)]}) == 'UNKNOWN'
    assert decision(id, key) == 'UNKNOWN'


def test_armor_nondefault_pass_fail_unknown_not_applicable():
    id = 'gcp_backend_service_checks_armor_security_policy_contains_f48cc81ccae3'
    good = security([{'priority': 1000, 'match': {'expr': {'expression': 'true'}}, 'action': 'deny(403)'},
                     {'priority': 2147483647, 'match': {}, 'action': 'allow'}])
    b = backend(securityPolicy=P)
    assert decision(id, good, {'backend_service': [b]}) == 'PASS'
    assert decision(id, security(), {'backend_service': [b]}) == 'FAIL'
    assert decision(id, good, {'backend_service': []}) == 'NOT_APPLICABLE'
    assert decision(id, good) == 'UNKNOWN'


def test_admin_waf_pass_fail_unknown_not_applicable():
    id = 'gcp_c5_cloud_armor_waf'
    b = backend(securityPolicy=P)
    policy = {'admin_backend_mapping': {B: {'in_scope': True, 'internet_reachable': True, 'topology_verified': True}},
              'approved_waf_expression': 'evaluatePreconfiguredWaf()', 'approved_waf_action': 'deny(403)'}
    rule = {'priority': 100, 'match': {'expr': {'expression': 'evaluatePreconfiguredWaf()'}}, 'action': 'deny(403)', 'disabled': False}
    p = security([rule, {'priority': 2147483647, 'match': {}, 'action': 'allow'}])
    extras = {'security_policy': [p], 'url_map': [], 'target_https_proxy': [], 'forwarding_rule': []}
    assert decision(id, b, extras, policy) == 'PASS'
    assert decision(id, backend(), extras, policy) == 'FAIL'
    assert decision(id, b, extras, {**policy, 'admin_backend_mapping': {B: {'in_scope': False, 'internet_reachable': True}}}) == 'NOT_APPLICABLE'
    assert decision(id, b, extras) == 'UNKNOWN'


def test_armor_cidr_pass_fail_unknown_not_applicable():
    id = 'gcp_cloud_armor_cidr_deny'
    expr = "!inIpRange(origin.ip, '10.0.0.0/8')"
    policy = {'approved_cidrs': ['10.0.0.0/8'], 'approved_cidr_deny_expression': expr,
              'cidr_expression_review': {'cidrs': ['10.0.0.0/8']}}
    rule = {'priority': 100, 'match': {'expr': {'expression': expr}}, 'action': 'deny(403)', 'disabled': False}
    p = security([rule, {'priority': 2147483647, 'match': {}, 'action': 'allow'}], cidrRulePrecedenceVerified=True)
    b = backend(securityPolicy=P, internetFacing=True)
    assert decision(id, p, {'backend_service': [b]}, policy) == 'PASS'
    assert decision(id, security(cidrRulePrecedenceVerified=True), {'backend_service': [b]}, policy) == 'FAIL'
    assert decision(id, p, {'backend_service': [backend(securityPolicy=P, internetFacing=False)]}, policy) == 'NOT_APPLICABLE'
    assert decision(id, security(), {'backend_service': [b]}, policy) == 'UNKNOWN'


def test_armor_rate_limit_pass_fail_unknown_not_applicable():
    id = 'gcp_cloud_armor_rate_limit'
    policy = {'rate_limit_enforce_on_key': 'IP', 'rate_limit_match_expression': 'true'}
    rule = {'priority': 100, 'match': {'expr': {'expression': 'true'}}, 'action': 'throttle', 'disabled': False,
            'rateLimitOptions': {'rateLimitThreshold': {'count': 2000, 'intervalSec': 300},
                                 'banDurationSec': 60, 'enforceOnKey': 'IP'}}
    p = security([rule, {'priority': 2147483647, 'match': {}, 'action': 'allow'}], rateRulePrecedenceVerified=True)
    b = backend(securityPolicy=P, internetFacing=True)
    assert decision(id, p, {'backend_service': [b]}, policy) == 'PASS'
    assert decision(id, security(rateRulePrecedenceVerified=True), {'backend_service': [b]}, policy) == 'FAIL'
    assert decision(id, p, {'backend_service': [backend(securityPolicy=P, internetFacing=False)]}, policy) == 'NOT_APPLICABLE'
    assert decision(id, security(), {'backend_service': [b]}, policy) == 'UNKNOWN'


def test_cdn_cache_pass_fail_unknown_not_applicable():
    id = 'gcp_cloudcdn_cache_policy'
    b = backend(enableCDN=True, cdnPolicy={'cacheMode': 'USE_ORIGIN_HEADERS', 'clientTtl': 60, 'defaultTtl': 60})
    policy = {'sensitive_backend_services': [B], 'approved_cache_policy': {'cache_modes': ['USE_ORIGIN_HEADERS'], 'max_client_ttl': 60, 'max_default_ttl': 60}}
    assert decision(id, b, policy=policy) == 'PASS'
    assert decision(id, {**b, 'cdnPolicy': {**b['cdnPolicy'], 'clientTtl': 120}}, policy=policy) == 'FAIL'
    assert decision(id, {**b, 'cdnPolicy': {}}, policy=policy) == 'UNKNOWN'
    assert decision(id, b, policy={'sensitive_backend_services': []}) == 'NOT_APPLICABLE'


def test_cdn_viewer_tls_pass_fail_unknown_not_applicable():
    id = 'gcp_pci_backend_service_2ce96d36d0bf'
    b = backend(enableCDN=True)
    extras = {'url_map': [row(selfLink='projects/p/global/urlMaps/u', defaultService=B, _representation='full')],
              'target_https_proxy': [row(selfLink='projects/p/global/targetHttpsProxies/t', urlMap='projects/p/global/urlMaps/u', sslPolicy='projects/p/global/sslPolicies/s')],
              'ssl_policy': [row(selfLink='projects/p/global/sslPolicies/s', minTlsVersion='TLS_1_2')]}
    assert decision(id, b, extras) == 'PASS'
    weak = copy.deepcopy(extras)
    weak['ssl_policy'][0]['minTlsVersion'] = 'TLS_1_0'
    assert decision(id, b, weak) == 'FAIL'
    assert decision(id, b) == 'UNKNOWN'
    assert decision(id, backend(enableCDN=False), extras) == 'NOT_APPLICABLE'


def test_armor_backend_logging_pass_fail_unknown_not_applicable():
    id = 'gcp_pci_backend_service_571fd0bfec67'
    policy = {'required_armor_log_sink': {'required': False}}
    b = backend(securityPolicy=P, logConfig={'enable': True})
    assert decision(id, b, policy=policy) == 'PASS'
    assert decision(id, backend(securityPolicy=P, logConfig={'enable': False}), policy=policy) == 'FAIL'
    assert decision(id, b, policy={'required_armor_log_sink': {'required': True, 'destination': 'storage.googleapis.com/b', 'filter': 'x'}}) == 'UNKNOWN'
    assert decision(id, backend(logConfig={'enable': True}), policy=policy) == 'NOT_APPLICABLE'


@pytest.mark.parametrize('id', list(m.META))
def test_all_ids_reject_incomplete_malformed_foreign_and_missing_fact(id):
    kind = m.META[id]['kind']
    subject = row('b' if kind == 'bucket' else A if kind == 'asset' else K if kind == 'kms_key' else None,
                  selfLink=B if kind == 'backend_service' else P if kind == 'security_policy' else None)
    assert decision(id, subject, status='partial') == 'UNKNOWN'
    assert decision(id, subject, scope='projects/other') == 'UNKNOWN'
    malformed = {**subject, '_provenance': {'scope': 'projects/other'}}
    assert decision(id, malformed) == 'UNKNOWN'
    assert decision(id, subject) == 'UNKNOWN'
