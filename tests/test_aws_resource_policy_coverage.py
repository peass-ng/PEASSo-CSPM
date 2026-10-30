"""Finite AWS policy coverage, SDK contracts and public-grant boundaries."""
import json
from pathlib import Path

import botocore.session
from botocore import xform_name
import jmespath
import pytest

from peaso.collectors import aws
from peaso.collectors import aws_resource_policy_families as families
from peaso.checks.aws_resource_policy_scope import review_document

ACCOUNT = '123456789012'
REGION = 'eu-west-1'
PUBLIC = {'Statement': [{'Effect': 'Allow', 'Principal': '*', 'Action': '*', 'Resource': '*'}]}
SESSION = botocore.session.get_session()


def sample(shape, key='', region=REGION, depth=0):
    if shape is None or depth > 8:
        return None
    if shape.type_name == 'structure':
        return {k: sample(v, k, region, depth + 1) for k, v in shape.members.items()
                if k.lower() not in {'nexttoken', 'nextmarker', 'continuationtoken', 'marker'}}
    if shape.type_name == 'list':
        return [sample(shape.member, key, region, depth + 1)]
    if shape.type_name == 'map':
        return {'fixture': json.dumps(PUBLIC)} if key == 'Policies' else {}
    if shape.type_name in {'integer', 'long', 'float', 'double'}:
        return 1
    if shape.type_name == 'boolean':
        return True
    lower = key.lower()
    if shape.name == '__string' and lower == 'applicationid':
        return f'arn:aws:serverlessrepo:{region}:{ACCOUNT}:applications/fixture'
    if lower.endswith('arn') or lower in {'resource', 'identifier', 'reportgroups'}:
        return f'arn:aws:fixture:{region}:{ACCOUNT}:resource/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
    if lower in {'policy', 'policytext', 'policydocument', 'resourcepolicy', 'delegatedadminresourcepolicy', 'resourcepolicycontent', 'policyinjson', 'accesspolicies', 'assumerolepolicydocument', 's3accesspolicy', 'deliverydestinationpolicy', 'options', 'document', 'content', 'policies', 'managementpolicy', 'configuredaudiencemodelpolicy', 'firewallrulegrouppolicy', 'resolverquerylogconfigpolicy', 'resolverrulepolicy'}:
        return json.dumps(PUBLIC)
    if lower in {'principal', 'principals', 'action', 'actions'}:
        return '*'
    if lower in {'owner', 'domainowner'}:
        return ACCOUNT
    if lower == 'accountids':
        return 'all'
    if lower == 'principalorgids':
        return 'o-1234567890'
    if lower == 'effect':
        return 'Allow'
    return ('fixture' + 'f' * max(0, shape.metadata.get('min', 7) - 7))[:shape.metadata.get('max', 200)]


class Requests:
    def __init__(self):
        self.calls = []

    def operation(self, service, operation):
        model = SESSION.get_service_model(service)
        return model.operation_model({xform_name(n): n for n in model.operation_names}[operation])

    def validate(self, service, region, operation, parameters):
        from botocore.validate import validate_parameters
        shape = self.operation(service, operation).input_shape
        if shape:
            validate_parameters(parameters, shape)
        self.calls.append((service, region, operation, parameters))

    def pages(self, session, service, region, operation, path, **parameters):
        self.validate(service, region, operation, parameters)
        response = sample(self.operation(service, operation).output_shape, region=region)
        items = jmespath.search(path, response)
        assert isinstance(items, list), (service, operation, path, items)
        return aws.ReadResult(items, 'collected' if items else 'empty')

    def detail(self, session, service, region, operation, absent=(), **parameters):
        self.validate(service, region, operation, parameters)
        response = sample(self.operation(service, operation).output_shape, region=region)
        if service == 'signin':
            response['signinResourceBasedPolicy'] = {'version': '2012-10-17', 'statement': [
                {'effect': 'Allow', 'principal': '*', 'action': '*', 'resource': '*'}]}
        return {**response, 'collection_status': 'collected'}


@pytest.mark.parametrize('recipe', families.RECIPES, ids=lambda r: r.id)
def test_every_recipe_uses_real_sdk_shapes_and_bounded_parameters(recipe):
    requests = Requests()
    read = families.collect(requests, SESSION, REGION, ACCOUNT, [recipe])
    assert read.status in {'collected', 'empty'}, (recipe.id, read.error)
    assert requests.calls
    for row in read.items:
        assert set(row) == {'ResourceArn', 'Policy', '_provenance'}
        assert row['_provenance']['owner_account'] == ACCOUNT
        assert row['_provenance']['collection_region'] == REGION
        assert row['_provenance']['families'] == [recipe.id]


@pytest.mark.parametrize('condition,bounded', [
    ({}, False),
    ({'Bool': {'aws:SecureTransport': 'true'}}, False),
    ({'StringEquals': {'aws:RequestedRegion': REGION}}, False),
    ({'StringEqualsIfExists': {'aws:SourceAccount': ACCOUNT}}, False),
    ({'ForAllValues:StringEquals': {'aws:PrincipalOrgID': 'o-1234567890'}}, False),
    ({'StringNotEquals': {'aws:PrincipalAccount': '999999999999'}}, False),
    ({'StringLike': {'aws:SourceArn': 'arn:aws:sns:*:*:topic'}}, False),
    ({'ArnLike': {'aws:PrincipalArn': f'arn:aws:iam::{ACCOUNT}:role/*'}}, True),
    ({'StringEquals': {'aws:SourceAccount': [ACCOUNT, '*']}}, False),
    ({'StringEquals': {'aws:SourceAccount': ACCOUNT}}, True),
    ({'StringEquals': {'aws:PrincipalOrgID': 'o-approved'}}, False),
    ({'StringEquals': {'aws:PrincipalOrgID': 'o-1234567890'}}, True),
    ({'StringEquals': {'aws:SourceVpce': 'vpce-12345678'}}, True),
    ({'ForAnyValue:StringLike': {'aws:PrincipalOrgPaths': 'o-1234567890/r-root/ou-team/*'}}, True),
    ({'ForAnyValue:StringLike': {'aws:PrincipalOrgPaths': 'o-*/r-root/*'}}, False),
    ({'ArnLike': {'aws:SourceArn': 'arn:aws:s3:::trusted-bucket/*'}}, True),
    ({'ArnLike': {'aws:SourceArn': 'arn:aws:s3:::*'}}, False),
    ({'IpAddress': {'aws:SourceIp': '0.0.0.0/0'}}, False),
    ({'IpAddress': {'aws:SourceIp': ['0.0.0.0/1', '128.0.0.0/1']}}, False),
    ({'IpAddress': {'aws:SourceIp': '203.0.113.0/24'}}, True),
    ({'IpAddress': {'aws:SourceIp': '::/0'}}, False),
])
def test_only_required_caller_or_network_conditions_bound_a_grant(condition, bounded):
    document = json.loads(json.dumps(PUBLIC))
    document['Statement'][0]['Condition'] = condition
    violations, uncertain = review_document(document)
    assert bool(violations) is not bounded
    assert not uncertain


def test_wildcard_principal_lists_and_implicit_resources_are_reviewed():
    document = {'Statement': [{'Effect': 'Allow', 'Principal': {'AWS': [ACCOUNT, '*']}, 'NotAction': 's3:DeleteObject'}]}
    assert review_document(document)[0]


def test_denies_do_not_hide_unrelated_public_grants():
    allow = {'Effect': 'Allow', 'Principal': '*', 'Action': 's3:GetObject', 'Resource': '*'}
    deny = {'Effect': 'Deny', 'Principal': '*', 'Action': 's3:PutObject', 'Resource': '*'}
    assert review_document({'Statement': [allow, deny]})[0]
    deny['Action'] = '*'
    assert review_document({'Statement': [allow, deny]}) == ([], [])
    deny['Condition'] = {'StringNotEquals': {'aws:PrincipalAccount': ACCOUNT}}
    assert review_document({'Statement': [allow, deny]}) == ([], [])


def test_known_public_policy_survives_denied_other_family():
    class Partial(Requests):
        def pages(self, session, service, region, operation, path, **parameters):
            if service == 'kms':
                return aws.ReadResult([], 'denied', {'code': 'AccessDeniedException'})
            return super().pages(session, service, region, operation, path, **parameters)
    selected = [next(r for r in families.RECIPES if r.id == key) for key in ('s3-buckets', 'kms-keys')]
    read = families.collect(Partial(), SESSION, REGION, ACCOUNT, selected)
    assert read.status == 'partial' and len(read.items) == 1
    assert review_document(read.items[0]['Policy'])[0]
    assert read.error['families'] == [{'family': 'kms-keys', 'status': 'denied', 'code': 'AccessDeniedException'}]


def test_every_discovery_call_has_an_exact_reviewed_iam_mapping():
    from scripts.peaso_deploy_customer_policy import iam_action, build_policy
    policy = build_policy(families.READ_ACTIONS)
    actions = {a for s in policy['Statement'] for a in ([s['Action']] if isinstance(s['Action'], str) else s['Action'])}
    assert {iam_action(*pair) for pair in families.READ_ACTIONS} <= actions
    assert not any(a.endswith(':*') for a in actions)


def test_default_dispatch_combines_base_and_extended_evidence(monkeypatch):
    from peaso.collectors import aws_resource_policy_native as native
    first = {'ResourceArn': f'arn:aws:sns:{REGION}:{ACCOUNT}:topic', 'Policy': PUBLIC}
    second = {'ResourceArn': f'arn:aws:kms:{REGION}:{ACCOUNT}:key/fixture', 'Policy': PUBLIC}
    monkeypatch.setattr(native, 'base_policies', lambda *args: aws.ReadResult([first], 'collected'))
    monkeypatch.setattr(native, 'extended_policies', lambda *args: aws.ReadResult([second], 'partial', {'code': 'AccessDeniedException'}))
    read = native.policies(None, SESSION, REGION, ACCOUNT)
    assert read.status == 'partial' and {row['ResourceArn'] for row in read.items} == {first['ResourceArn'], second['ResourceArn']}


def test_policy_absence_and_missing_mandatory_document_are_distinct():
    selected = [next(r for r in families.RECIPES if r.id == 'kms-keys')]
    class Missing(Requests):
        def detail(self, *args, **kwargs):
            return {'collection_status': 'collected'}
    read = families.collect(Missing(), SESSION, REGION, ACCOUNT, selected)
    assert read.status == 'unknown' and read.error['families'][0]['code'] == 'policy_document_missing'
    class Absent(Requests):
        def detail(self, *args, **kwargs):
            return {'collection_status': 'empty', 'absent': True}
    assert families.collect(Absent(), SESSION, REGION, ACCOUNT, selected).status == 'empty'


def test_deny_on_a_different_resource_cannot_cancel_implicit_resource_grant():
    allow = {'Effect': 'Allow', 'Principal': '*', 'Action': 's3:GetObject'}
    deny = {'Effect': 'Deny', 'Principal': '*', 'Action': '*', 'Resource': 'arn:aws:s3:::other-bucket/*'}
    violations, uncertain = review_document({'Statement': [allow, deny]})
    assert not violations and uncertain
    deny['Action'] = ['*']
    deny['Resource'] = ['*']
    assert review_document({'Statement': [allow, deny]}) == ([], [])


def test_malformed_resource_does_not_hide_another_public_policy():
    selected = [next(r for r in families.RECIPES if r.id == 's3-buckets')]
    class Mixed(Requests):
        def pages(self, session, service, region, operation, path, **parameters):
            return aws.ReadResult([{}, {'Name': 'public-fixture'}], 'collected')
    read = families.collect(Mixed(), SESSION, REGION, ACCOUNT, selected)
    assert read.status == 'partial' and len(read.items) == 1
    assert review_document(read.items[0]['Policy'])[0]




@pytest.mark.parametrize('operator', ['ForAllValues:StringLike', 'StringLikeIfExists'])
@pytest.mark.parametrize('null', [None, 'true', 'false', False])
def test_existence_guard_makes_otherwise_optional_org_boundary_required(operator, null):
    condition = {operator: {'aws:PrincipalOrgID': 'o-1234567890'}}
    if null is not None:
        condition['Null'] = {'aws:PrincipalOrgID': null}
    policy = {'Statement': [{**PUBLIC['Statement'][0], 'Condition': condition}]}
    violations, uncertain = review_document(policy)
    assert not uncertain and bool(violations) == (null not in ('false', False))


@pytest.mark.parametrize('deny', [
    {'Principal': {'AWS': 'arn:aws:iam::123456789012:root'}},
    {'Principal': '*', 'Condition': {'StringEquals': {'aws:PrincipalAccount': ACCOUNT}}},
    {'NotPrincipal': '*'},
])
def test_deny_on_a_finite_population_or_empty_complement_does_not_hide_public_access(deny):
    statement = {'Effect': 'Deny', 'Action': '*', 'Resource': '*', **deny}
    violations, uncertain = review_document({'Statement': [PUBLIC['Statement'][0], statement]})
    assert violations and not uncertain


@pytest.mark.parametrize('condition', [
    {'StringNotEquals': {'aws:PrincipalOrgID': 'o-1234567890'}},
    {'ArnNotLike': {'aws:PrincipalArn': f'arn:aws:iam::{ACCOUNT}:role/*'}},
    {'NotIpAddress': {'aws:SourceIp': '203.0.113.0/24'}},
])
def test_deny_outside_a_required_boundary_protects_an_otherwise_public_grant(condition):
    deny = {'Effect': 'Deny', 'Principal': '*', 'Action': '*', 'Resource': '*', 'Condition': condition}
    assert review_document({'Statement': [PUBLIC['Statement'][0], deny]}) == ([], [])
    # Another conjunct weakens the Deny; do not infer that all outsiders are denied.
    deny['Condition']['Bool'] = {'aws:SecureTransport': 'false'}
    assert review_document({'Statement': [PUBLIC['Statement'][0], deny]})[1]


def test_notprincipal_excluding_everybody_grants_nobody():
    assert review_document({'Statement': [{'Effect': 'Allow', 'NotPrincipal': '*', 'Action': '*', 'Resource': '*'}]}) == ([], [])


@pytest.mark.parametrize('family,version_listing,version_key,build_listing,build_key,parameter,getter', [
    ('imagebuilder-images', 'list_images', 'imageVersionList', 'list_image_build_versions', 'imageSummaryList', 'imageVersionArn', 'get_image_policy'),
    ('imagebuilder-components', 'list_components', 'componentVersionList', 'list_component_build_versions', 'componentSummaryList', 'componentVersionArn', 'get_component_policy'),
])
def test_imagebuilder_checks_every_concrete_build_with_realistic_sdk_responses(family, version_listing, version_key, build_listing, build_key, parameter, getter):
    import boto3
    from botocore.stub import Stubber
    session = boto3.Session(aws_access_key_id='fixture', aws_secret_access_key='fixture', region_name=REGION)
    client = session.client('imagebuilder')
    stubber = Stubber(client)
    resource_kind = 'image' if family.endswith('images') else 'component'
    version = f'arn:aws:imagebuilder:{REGION}:{ACCOUNT}:{resource_kind}/fixture/1.2.3'
    builds = [version + '/1', version + '/2']
    stubber.add_response(version_listing, {version_key: [{'arn': version}]}, {'owner': 'Self'})
    stubber.add_response(build_listing, {build_key: [{'arn': value} for value in builds]}, {parameter: version})
    arn_argument = 'imageArn' if resource_kind == 'image' else 'componentArn'
    for number, arn in enumerate(builds):
        policy = {'Statement': [{'Effect': 'Allow', 'Principal': '*' if number else {'AWS': ACCOUNT}, 'Action': '*', 'Resource': arn}]}
        stubber.add_response(getter, {'policy': json.dumps(policy)}, {arn_argument: arn})
    stubber.activate()
    class Session:
        def get_partition_for_region(self, region):
            return 'aws'
        def client(self, service, region_name=None, **kwargs):
            assert service == 'imagebuilder'
            return client
    selected = [next(r for r in families.RECIPES if r.id == family)]
    read = families.collect(aws.Requests({'retry_attempts': 1}), Session(), REGION, ACCOUNT, selected)
    assert read.status == 'collected', read.error
    assert [row['ResourceArn'] for row in read.items] == builds
    assert not review_document(read.items[0]['Policy'])[0]
    assert review_document(read.items[1]['Policy'])[0]
    stubber.assert_no_pending_responses()
    stubber.deactivate()


def test_unsupported_sdk_recipe_is_explicit_gap_without_making_requests():
    from botocore.exceptions import UnknownServiceError
    recipe = next(r for r in families.RECIPES if r.id == 's3-files')
    class OlderSDK:
        def get_partition_for_region(self, region):
            return 'aws'
        def get_service_model(self, service):
            raise UnknownServiceError(service_name=service, known_service_names='s3')
    requests = Requests()
    read = families.collect(requests, OlderSDK(), REGION, ACCOUNT, [recipe])
    assert read.status == 'unknown' and not read.items and not requests.calls
    gap = read.error['families'][0]
    assert gap['family'] == 's3-files' and gap['status'] == 'not_supported'
    assert 'get_file_system_policy' in gap['code'] and 'list_file_systems' in gap['code']


def test_missing_policy_operation_disables_whole_recipe_read_advertisement():
    recipe = next(r for r in families.RECIPES if r.id == 'payment-keys')
    class Model:
        operation_names = ['ListKeys']
    class OlderSDK:
        def get_service_model(self, service):
            return Model()
    assert families.unsupported_operations(recipe, OlderSDK()) == ['get_resource_policy']
    assert families.READ_ACTIONS == {(r.service, op) for r in families.RECIPES
        if not families.unsupported_operations(r, SESSION) for op in families.recipe_operations(r)}


def test_cloudtrail_collects_both_regular_and_delegated_admin_policies():
    recipe = next(r for r in families.RECIPES if r.id == 'cloudtrail-dashboards')
    class BothPolicies(Requests):
        def detail(self, *args, **kwargs):
            return {'collection_status': 'collected', 'ResourcePolicy': json.dumps(PUBLIC),
                    'DelegatedAdminResourcePolicy': json.dumps(PUBLIC)}
    read = families.collect(BothPolicies(), SESSION, REGION, ACCOUNT, [recipe])
    assert read.status == 'collected' and len(read.items) == 1
    assert len(read.items[0]['Policy']['Statement']) == 2
    assert read.items[0]['_provenance']['families'] == [recipe.id]


def test_resource_type_review_requires_attachment_decisions_and_correct_read_family():
    from copy import deepcopy
    from scripts.audit_aws_resource_policy_coverage import audit_resource_types
    source = json.loads(Path('peaso/collectors/aws_resource_policy_targets.json').read_text())
    result = audit_resource_types(families.RECIPES, source)
    assert result['reviewed_actions'] == len(source['policy_actions'])
    assert result['covered_resource_types'] > 90
    unreviewed = deepcopy(source)
    unreviewed['policy_actions']['cloudtrail:GetResourcePolicy']['resource_types'].append('new-policy-target')
    with pytest.raises(AssertionError, match='Unreviewed policy resource types'):
        audit_resource_types(families.RECIPES, unreviewed)
    wrong_service = deepcopy(source)
    wrong_service['policy_actions']['cloudtrail:GetResourcePolicy']['resource_type_review']['dashboard']['families'] = ['kms-keys']
    with pytest.raises(AssertionError, match='Wrong policy attachment read'):
        audit_resource_types(families.RECIPES, wrong_service)
    missing_family = deepcopy(source)
    missing_family['policy_actions']['cloudtrail:GetResourcePolicy']['resource_type_review']['dashboard']['families'] = ['removed-recipe']
    with pytest.raises(AssertionError, match='Missing attachment family'):
        audit_resource_types(families.RECIPES, missing_family)


def test_iam_support_matrix_cannot_silently_omit_a_supported_service():
    from copy import deepcopy
    from scripts.audit_aws_resource_policy_coverage import audit_service_support
    source = json.loads(Path('peaso/collectors/aws_resource_policy_targets.json').read_text())
    audit_service_support(families.RECIPES, source)
    removed = deepcopy(source)
    del removed['iam_service_support_review']['reviewed_services']['Amazon Kinesis Data Streams']
    with pytest.raises(AssertionError, match='Unreviewed IAM support-table services'):
        audit_service_support(families.RECIPES, removed)
    wrong_family = deepcopy(source)
    wrong_family['iam_service_support_review']['reviewed_services']['Amazon Kinesis Data Streams']['families'] = ['kms-keys']
    with pytest.raises(AssertionError, match='Missing service policy coverage'):
        audit_service_support(families.RECIPES, wrong_family)


@pytest.mark.parametrize('operator,guard,restricted', [
    ('StringEqualsIgnoreCase', {}, True),
    ('StringEqualsIgnoreCaseIfExists', {}, False),
    ('StringEqualsIgnoreCaseIfExists', {'Null': {'aws:PrincipalOrgID': 'false'}}, True),
    ('ForAllValues:StringEqualsIgnoreCase', {}, False),
    ('ForAllValues:StringEqualsIgnoreCase', {'Null': {'aws:PrincipalOrgID': 'false'}}, True),
    ('ForAnyValue:StringEqualsIgnoreCase', {}, True),
])
def test_ignore_case_organization_boundaries_keep_presence_requirements(operator, guard, restricted):
    statement = {**PUBLIC['Statement'][0], 'Condition': {
        operator: {'aws:PrincipalOrgID': 'O-1234567890'}, **guard}}
    violations, uncertain = review_document({'Statement': [statement]})
    assert bool(violations) is not restricted
    assert not uncertain


@pytest.mark.parametrize('operator', ['StringNotEqualsIgnoreCase', 'ForAllValues:StringNotEqualsIgnoreCase'])
def test_covering_case_insensitive_deny_confines_grant_to_organization(operator):
    deny = {**PUBLIC['Statement'][0], 'Effect': 'Deny',
            'Condition': {operator: {'aws:PrincipalOrgID': 'O-1234567890'}}}
    assert review_document({'Statement': [PUBLIC['Statement'][0], deny]}) == ([], [])


def test_guardrail_profile_referenced_only_by_published_version_is_discovered():
    recipe = next(r for r in families.RECIPES if r.id == 'bedrock-guardrail-profiles')
    guardrail = f'arn:aws:bedrock:{REGION}:{ACCOUNT}:guardrail/abc123'
    profile = f'arn:aws:bedrock:{REGION}:{ACCOUNT}:guardrail-profile/eu.guardrail.v1:0'
    class Versions(Requests):
        def pages(self, session, service, region, operation, path, **parameters):
            if operation == 'get_guardrail':
                response = self.detail(session, service, region, operation, **parameters)
                items = jmespath.search(path, response)
                return aws.ReadResult(items, 'collected' if items else 'empty')
            self.validate(service, region, operation, parameters)
            assert operation == 'list_guardrails'
            versions = ['1', 'DRAFT'] if parameters else ['DRAFT']
            return aws.ReadResult([{'arn': guardrail, 'id': 'abc123', 'version': v} for v in versions], 'collected')
        def detail(self, session, service, region, operation, absent=(), **parameters):
            self.validate(service, region, operation, parameters)
            if operation == 'get_guardrail':
                return {'collection_status': 'collected', **({'crossRegionDetails': {'guardrailProfileArn': profile}}
                    if parameters['guardrailVersion'] == '1' else {})}
            assert operation == 'get_resource_policy' and parameters == {'resourceArn': profile}
            return {'collection_status': 'collected', 'resourcePolicy': json.dumps(PUBLIC)}
    requests = Versions()
    read = families.collect(requests, SESSION, REGION, ACCOUNT, [recipe])
    assert read.status == 'collected' and len(read.items) == 1
    assert read.items[0]['ResourceArn'] == profile
    assert review_document(read.items[0]['Policy'])[0]
    assert {call[3]['guardrailVersion'] for call in requests.calls if call[2] == 'get_guardrail'} == {'1', 'DRAFT'}


@pytest.mark.parametrize('recipe', families.RECIPES, ids=lambda r: r.id)
def test_every_policy_recipe_reaches_registered_unrestricted_grant_evaluator(recipe):
    from copy import deepcopy
    from peaso.checks import CHECKS
    check = next(c for c in CHECKS if c.id == 'aws_cis_aws_resource_policy_unrestricted_principal')
    class Unrestricted(Requests):
        def detail(self, *args, **kwargs):
            response = super().detail(*args, **kwargs)
            # The general SDK sample deliberately supplies an organization
            # restriction for SAR; omit it to exercise unrestricted sharing.
            if args[1] == 'serverlessrepo':
                for statement in response['Statements']:
                    statement.pop('PrincipalOrgIDs', None)
            return response
    read = families.collect(Unrestricted(), SESSION, REGION, ACCOUNT, [recipe])
    assert read.status == 'collected' and read.items, (recipe.id, read.error)
    index = {'context': {'provider': 'aws', 'scope': f'{ACCOUNT}/{REGION}'}}
    for row in read.items:
        status, evidence = check.evaluate(row, index)
        assert status == 'FAIL' and evidence['unrestricted_statements'], (recipe.id, status, evidence)
        confined = deepcopy(row)
        for statement in confined['Policy']['Statement']:
            statement['Condition'] = {'StringEquals': {'aws:PrincipalAccount': ACCOUNT}}
        status, evidence = check.evaluate(confined, index)
        assert status == 'PASS' and evidence['unrestricted_statements'] == [], (recipe.id, status, evidence)


@pytest.mark.parametrize('deny_scope', [
    {'Resource': 'arn:aws:s3:::different-bucket/*'},
    {'Resource': ['arn:aws:s3:::different-bucket/*', 'arn:aws:s3:::another-bucket/*']},
    {'NotResource': 'arn:aws:s3:::public-bucket/*'},
    {'NotResource': '*'},
])
def test_provably_unrelated_resource_deny_cannot_hide_public_grant(deny_scope):
    allow = {'Effect': 'Allow', 'Principal': '*', 'Action': 's3:GetObject',
             'Resource': 'arn:aws:s3:::public-bucket/*'}
    deny = {'Effect': 'Deny', 'Principal': '*', 'Action': '*', **deny_scope}
    violations, uncertain = review_document({'Statement': [allow, deny]})
    assert violations == [{'statement_index': 0, 'sid': '<unnamed>'}] and not uncertain


@pytest.mark.parametrize('excluded', ['*', 's3:GetObject', ['S3:GetObject', 's3:PutObject']])
def test_deny_excluding_the_allowed_actions_cannot_hide_public_grant(excluded):
    allow = {'Effect': 'Allow', 'Principal': '*', 'Action': 's3:GetObject', 'Resource': '*'}
    deny = {'Effect': 'Deny', 'Principal': '*', 'NotAction': excluded, 'Resource': '*'}
    violations, uncertain = review_document({'Statement': [allow, deny]})
    assert violations and not uncertain


@pytest.mark.parametrize('resource', [
    'arn:aws:s3:::public-bucket/private/*',
    'arn:aws:s3:::public-*/*',
    'arn:aws:s3:::${aws:PrincipalTag/bucket}/*',
])
def test_compatible_resource_prefixes_do_not_prove_a_deny_irrelevant(resource):
    allow = {'Effect': 'Allow', 'Principal': '*', 'Action': 's3:GetObject',
             'Resource': 'arn:aws:s3:::public-bucket/*'}
    deny = {'Effect': 'Deny', 'Principal': '*', 'Action': '*', 'Resource': resource}
    violations, uncertain = review_document({'Statement': [allow, deny]})
    assert not violations and uncertain
