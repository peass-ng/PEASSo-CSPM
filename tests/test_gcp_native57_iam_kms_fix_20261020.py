"""Exact duration and native project-root binding correction witnesses.

Native cases reuse only the previously verified finite HTTP transport, never
source CASES. Pure guard mutations are explicitly post-collection unit cases.
"""
from copy import deepcopy
from decimal import Decimal, localcontext
import json
from urllib.parse import urlsplit

import pytest

from peaso.checks import CHECKS
from peaso.checks.claude_gcp_k8s_common import duration_seconds
from peaso.checks.facts import Unavailable
from peaso.checks.gcp_ports_iam import project_roots
from peaso.collectors import gcp
from peaso.engine import _index, evaluate_snapshot
from peaso.snapshot import resources, validate
from tests.test_gcp_native57_iam_kms_review_20261020 import (
    NativeAPI, BY_ID, SCOPE, NUMBER, PROJECT, EMAIL, ROLE, CAPTURED,
    block_network_and_auth,
)

KMS = 'gcp.claude.kms_key.rotation_100_days'
ROLE_CHECKS = ['gcp.gap.iam_user_managed_sa_no_admin_roles', 'gcp.ports.service_account_mutating_role_declarations']
FUNCTION_CHECKS = ['gcp.ports.function_basic_role_declarations', 'gcp.ports.function_logging_mutation_declarations',
                   'gcp.ports.function_legacy_deployment_role_declarations']


@pytest.mark.parametrize('value,expected', [
    ('0s', '0'), ('1s', '1'), ('0001.000000001s', '1.000000001'),
    ('8640000s', '8640000'), ('8640000.000000001s', '8640000.000000001'),
    ('8640000.999999999s', '8640000.999999999'),
    ('315576000000s', '315576000000'), ('315576000000.999999999s', '315576000000.999999999'),
])
def test_pure_protobuf_duration_preserves_exact_seconds_and_nanoseconds(value, expected):
    with localcontext() as context:
        context.prec = 6
        actual = duration_seconds(value)
    assert actual == Decimal(expected)


@pytest.mark.parametrize('value', [None, True, 1, '', '1', '1d', '-1s', '+1s', '1.s', '.5s', '1e2s',
                                  'NaNs', 'Infinitys', '1.0000000001s', '315576000001s', '999999999999999999999999s'])
def test_pure_duration_rejects_unsupported_grammar_precision_and_bounds(value):
    with pytest.raises(Unavailable): duration_seconds(value)


class FixAPI(NativeAPI):
    def __init__(self, cid, variant, *, bad=False, scope=SCOPE, period=None):
        spec = BY_ID[cid] if cid in BY_ID else {'id': cid, 'family': 'role-definition'}
        super().__init__(spec, 'bad' if bad else 'good', scope)
        self.variant, self.period = variant, period

    def respond(self, request):
        url, method = request['url'], request['method']
        parsed = urlsplit(url)
        assert parsed.scheme == 'https' and parsed.port is None and not parsed.query and not parsed.fragment
        parent_chain = self.variant in ('parent-good', 'parent-bad', 'duplicate-parent', 'parent-denied')
        if parsed.hostname == 'cloudresourcemanager.googleapis.com':
            if parsed.path in ('/v3/folders/123:getIamPolicy', '/v3/organizations/999:getIamPolicy'):
                assert method == 'POST' and request['body'] == {'options': {'requestedPolicyVersion': 3}}
                assert request['scope'] == parsed.path.removeprefix('/v3/').split(':')[0]
                if self.variant == 'parent-denied' and '/folders/' in parsed.path: self.denied()
                bindings = []
                if self.variant == 'parent-bad' and '/folders/' in parsed.path:
                    role = 'roles/compute.instanceAdmin' if self.cid == ROLE_CHECKS[0] else ROLE
                    bindings = [{'role': role, 'members': ['serviceAccount:' + EMAIL]}]
                return {'bindings': bindings}
            if parsed.path == '/v3/' + self.scope and self.variant == 'project-denied': self.denied()
            data = super().respond(request)
            if parsed.path == '/v3/' + self.scope:
                if self.variant == 'foreign-id': data['projectId'] = 'foreign-project'
                if self.variant == 'foreign-number': data['name'] = 'projects/999999999999'
                if self.variant == 'noncanonical-number': data['name'] = 'projects/0' + NUMBER
                if self.variant == 'missing-id': data.pop('projectId')
                if parent_chain: data['parent'] = 'folders/123'
            if parsed.path == '/v1/' + self.scope + ':getAncestry' and parent_chain:
                data['ancestor'] += [{'resourceId': {'type': 'folder', 'id': '123'}}, {'resourceId': {'type': 'organization', 'id': '999'}}]
                if self.variant == 'duplicate-parent': data['ancestor'].insert(2, deepcopy(data['ancestor'][1]))
            if parsed.path == '/v3/' + self.scope + ':getIamPolicy':
                if parent_chain: data = {'bindings': []}
                if self.cid in FUNCTION_CHECKS and self.mode == 'bad':
                    role = 'roles/editor' if self.cid == FUNCTION_CHECKS[0] else ROLE
                    data = {'bindings': [{'role': role, 'members': ['serviceAccount:' + EMAIL]}]}
            return data
        if parsed.hostname == 'cloudfunctions.googleapis.com':
            assert method == 'GET'
            name = SCOPE + '/locations/us-central1/functions/native-function'
            if parsed.path == '/v2/' + self.scope + '/locations/-/functions':
                return {'functions': [{'name': name, 'environment': 'GEN_2', 'state': 'ACTIVE', 'serviceConfig': {'serviceAccountEmail': EMAIL}}]}
            # 75087001 made ``function`` depend on the project's Functions
            # location listing (``cloudfunctions_location``).
            if parsed.path == '/v2/' + self.scope + '/locations':
                return {'locations': [{'name': self.scope + '/locations/us-central1', 'locationId': 'us-central1'}]}
            assert parsed.path == '/v2/' + name + ':getIamPolicy'
            return {}
        if parsed.hostname == 'iam.googleapis.com' and parsed.path == '/v1/roles/editor':
            assert method == 'GET'
            return {'name': 'roles/editor', 'includedPermissions': ['resourcemanager.projects.get', 'storage.buckets.get', 'storage.buckets.update']}
        if parsed.hostname == 'iam.googleapis.com' and parsed.path == '/v1/organizations/999/roles':
            assert method == 'GET' and request['scope'] == 'organizations/999'
            assert request['params']['view'] == 'FULL' and request['params']['showDeleted'] == 'true'
            return {'roles': []}
        if parsed.hostname == 'iam.googleapis.com' and parsed.path == '/v1/' + ROLE and request['scope'] == 'folders/123':
            assert method == 'GET'
            return {'name': ROLE, 'stage': 'GA', 'etag': 'ZXRhZw==',
                    'includedPermissions': ['storage.buckets.update' if self.mode == 'bad' else 'storage.buckets.get']}
        data = super().respond(request)
        if parsed.hostname == 'iam.googleapis.com' and parsed.path == '/v1/' + self.scope + '/roles':
            if self.cid in FUNCTION_CHECKS and self.mode == 'bad':
                permission = 'logging.sinks.update' if self.cid == FUNCTION_CHECKS[1] else 'deploymentmanager.deployments.update'
                data['roles'][0]['includedPermissions'] = [permission]
        if parsed.hostname == 'cloudkms.googleapis.com' and parsed.path.endswith('/cryptoKeys') and self.period is not None:
            data['cryptoKeys'][0]['rotationPeriod'] = self.period
        return data


def collect_native(cid, variant, record_property, *, bad=False, scope=SCOPE, period=None):
    check = next(c for c in CHECKS if c.id == cid)
    kinds = list(check.dependencies)
    api = FixAPI(cid, variant, bad=bad, scope=scope, period=period)
    options = {'inventories': kinds, 'include_inherited': True, 'resource_iam': False, 'metrics_scopes': False,
               'service_account_activity': False, 'concurrency': 1, 'kms_locations': ['global']}
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [scope], 'options': options}, requirements=kinds, transport=api)
    collector.read_time = CAPTURED
    captured = collector.collect()
    assert not api.contract_errors, (api.contract_errors, api.requests)
    assert validate(captured) == captured
    original = deepcopy(captured)
    rows = evaluate_snapshot(captured, checks=[cid], include_not_applicable=True)['findings']
    assert captured == original
    json.dumps(rows, allow_nan=False)
    record_property('native_case', json.dumps({'id': cid, 'variant': variant, 'bad': bad, 'requests': api.requests, 'findings': rows}, sort_keys=True))
    return captured, rows


@pytest.mark.parametrize('period,expected,encoded', [
    ('8640000s', 'PASS', 8640000), ('8640000.000000000s', 'PASS', 8640000),
    ('8639999.999999999s', 'PASS', '8639999.999999999'),
    ('8640000.000000001s', 'FAIL', '8640000.000000001'),
    ('8640000.500s', 'FAIL', '8640000.5'), ('8640001s', 'FAIL', 8640001),
    ('8640000.0000000001s', 'UNKNOWN', None), ('315576000001s', 'UNKNOWN', None),
    ('0s', 'UNKNOWN', None), ('0.5s', 'UNKNOWN', None), ('-1s', 'UNKNOWN', None),
])
def test_native_kms_exact_boundary_and_json_evidence(period, expected, encoded, record_property):
    _, rows = collect_native(KMS, 'period', record_property, period=period)
    assert len(rows) == 1 and rows[0]['status'] == expected, rows
    if encoded is not None:
        evidence = rows[0]['evidence']
        assert evidence['rotation_seconds'] == encoded and type(evidence['rotation_seconds']) is type(encoded)
        assert evidence['rotation_period'] == period


@pytest.mark.parametrize('cid', ROLE_CHECKS)
@pytest.mark.parametrize('variant,expected', [('good', 'PASS'), ('foreign-id', 'UNKNOWN'), ('foreign-number', 'UNKNOWN'),
                                           ('noncanonical-number', 'UNKNOWN'), ('missing-id', 'UNKNOWN'), ('project-denied', 'UNKNOWN'),
                                           ('parent-good', 'PASS'), ('parent-bad', 'FAIL'), ('parent-denied', 'UNKNOWN'), ('duplicate-parent', 'UNKNOWN')])
def test_native_project_identity_and_parent_policy_joins(cid, variant, expected, record_property):
    _, rows = collect_native(cid, variant, record_property, bad=variant == 'parent-bad')
    selected = [row for row in rows if 'native_resource_id' in row]
    assert len(selected) == 1 and selected[0]['status'] == expected, rows


@pytest.mark.parametrize('cid', ROLE_CHECKS + FUNCTION_CHECKS)
@pytest.mark.parametrize('bad,expected', [(False, 'PASS'), (True, 'FAIL')])
@pytest.mark.parametrize('scope', [SCOPE, 'projects/' + NUMBER])
def test_native_valid_id_number_aliases_preserve_role_security_paths(cid, bad, expected, scope, record_property):
    _, rows = collect_native(cid, 'good', record_property, bad=bad, scope=scope)
    selected = [row for row in rows if 'native_resource_id' in row]
    assert len(selected) == 1 and selected[0]['status'] == expected, rows


@pytest.mark.parametrize('mutation', ['context-scope', 'context-provider', 'item-scope', 'project-scope', 'project-id', 'project-number',
                                     'duplicate-project', 'project-denied', 'partial-project', 'denied-id', 'empty-ancestry',
                                     'wrong-ancestry-root', 'duplicate-parent', 'parent-after-organization', 'duplicate-policy',
                                     'foreign-project-envelope', 'inherited-partial', 'inherited-denied', 'inherited-foreign-coverage'])
def test_pure_post_collection_project_guard_mutations(mutation, record_property):
    captured, _ = collect_native(ROLE_CHECKS[0], 'good', record_property)
    index = deepcopy(_index(captured, resources(captured)))
    index['context'] = {'provider': 'gcp', 'scope': SCOPE, 'metadata': captured['metadata']}
    item = index['service_account'][0]['data']
    project = index['project'][0]['data']
    if mutation == 'context-scope': index['context']['scope'] = 'projects/foreign-project'
    elif mutation == 'context-provider': index['context']['provider'] = 'aws'
    elif mutation == 'item-scope': item['_provenance']['scope'] = 'projects/foreign-project'
    elif mutation == 'project-scope': project['_provenance']['scope'] = 'projects/foreign-project'
    elif mutation == 'project-id': project['projectId'] = 'foreign-project'
    elif mutation == 'project-number': project['projectNumber'] = '999999999999'
    elif mutation == 'duplicate-project': index['project'].append(deepcopy(index['project'][0]))
    elif mutation == 'project-denied': index['collections']['project'][0]['status'] = 'denied'
    elif mutation == 'partial-project': index['collections']['project'][0]['coverage_status'] = 'partial'
    elif mutation == 'denied-id': project.setdefault('_coverage', {})['projectId'] = {'status': 'denied'}
    elif mutation == 'empty-ancestry': project['_ancestry'] = []
    elif mutation == 'wrong-ancestry-root': project['_ancestry'][0]['resourceId']['id'] = '999999999999'
    elif mutation == 'duplicate-parent': project['_ancestry'] += [{'resourceId': {'type': 'folder', 'id': '123'}}] * 2
    elif mutation == 'parent-after-organization': project['_ancestry'] += [{'resourceId': {'type': 'organization', 'id': '999'}}, {'resourceId': {'type': 'folder', 'id': '123'}}]
    elif mutation == 'duplicate-policy': index['iam_policy'].append(deepcopy(index['iam_policy'][0]))
    elif mutation == 'foreign-project-envelope': index['collections']['project'][0]['scope'] = 'projects/foreign-project'
    elif mutation == 'inherited-partial': project['_coverage']['_inherited_iam_policies']['collection_status'] = 'partial'
    elif mutation == 'inherited-denied': project['_coverage']['_inherited_iam_policies']['status'] = 'denied'
    elif mutation == 'inherited-foreign-coverage': project['_coverage']['_inherited_iam_policies']['ancestors'] = ['folders/999']
    original = deepcopy((item, index))
    with pytest.raises(Unavailable): project_roots(item, index)
    assert (item, index) == original
