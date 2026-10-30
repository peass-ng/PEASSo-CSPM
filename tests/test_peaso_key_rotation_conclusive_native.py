# Historical fixture contracts; current native admission is tested separately.
"""A conclusive exact-key rotation violation does not need negative IAM proof."""
from copy import deepcopy
from datetime import datetime, timezone
from urllib.parse import urlsplit

import pytest

from peaso.checks import evaluate_check
from peaso.collectors import collect_live, azure
from tests.archived_check_contract import evaluate_snapshot
from tests.test_peaso_azure_key_rotation_evidence_native import (
    CONTROL, KEY, NATIVE_KEY, ORIGIN, SCOPE, VAULT, project, sources,
)

DEFINITION = '/providers/Microsoft.Authorization/policyDefinitions/rotation'


def owner():
    return {'status': 'collected', 'scope': SCOPE, 'requiredKeyIds': [NATIVE_KEY],
            'maxRotationInterval': 'P90D', 'rotationPolicyDefinitionId': DEFINITION}


def index_for(actions=None, complete=False):
    incoming = sources()
    if actions is not None:
        incoming[2]['items'][0]['properties']['lifetimeActions'] = actions
    collection = project(incoming)
    row = collection['items'][0]
    if complete:
        proof = {'read_only': True, 'representation': 'full', 'source_operation': 'reviewed-effective-rights-read'}
        row['enforcementAssignments'] = [{'keyId': NATIVE_KEY,
            'assignmentId': SCOPE + '/providers/Microsoft.Authorization/policyAssignments/rotation',
            'definitionId': DEFINITION, 'scope': SCOPE, 'effect': 'Deny', 'enforcementMode': 'Default',
            'exempt': False, 'conditionsMatch': True, 'enforcesAutomaticRotation': True,
            'parameters': {'rotationInterval': 'P90D'}, '_provenance': deepcopy(proof)}]
        row['rotationIdentities'] = [{'keyId': NATIVE_KEY, 'principalId': 'reviewed-principal',
            'effectivePermissions': ['keys/rotate', 'keys/getrotationpolicy', 'keys/setrotationpolicy'],
            '_provenance': deepcopy(proof)}]
        row['_coverage'] = {field: {'status': 'collected'} for field in ('enforcementAssignments', 'rotationIdentities')}
    index = {'context': {'provider': 'azure', 'scope': SCOPE, 'created_at': datetime.now(timezone.utc).isoformat(),
        'metadata': {'compliance_policy': {'sw16': {CONTROL: owner()}}}},
        'collections': {'key_rotation_evidence': [collection]},
        'key_rotation_evidence': [{'type': 'key_rotation_evidence', 'scope': SCOPE, 'data': row}]}
    return row, index


@pytest.mark.parametrize('actions,approved', [
    ([], 'P90D'),
    ([{'action': {'type': 'Notify'}, 'trigger': {'timeBeforeExpiry': 'P30D'}}], 'P90D'),
    ([{'action': {'type': 'Rotate'}, 'trigger': {'timeAfterCreate': 'P91D'}}], 'P90D'),
    ([{'action': {'type': 'Rotate'}, 'trigger': {'timeAfterCreate': 'P4M'}}], 'P3M'),
])
def test_complete_native_policy_violation_fails_without_enforcement_or_rights(actions, approved):
    row, index = index_for(actions)
    index['context']['metadata']['compliance_policy']['sw16'][CONTROL]['maxRotationInterval'] = approved
    assert row['_coverage']['rotationIdentities']['status'] == 'not_collected'
    assert evaluate_check(CONTROL, {}, index)[0] == 'FAIL'


@pytest.mark.parametrize('mode', [
    'missing_actions', 'null_actions', 'unreadable_actions', 'unknown_action', 'bad_interval',
    'incomparable_interval', 'expiry_relative', 'foreign_key', 'foreign_policy_key',
    'foreign_arm_key', 'foreign_scope', 'incomplete_policy', 'stale_policy', 'incomplete_row',
])
def test_mandatory_policy_or_identity_uncertainty_stays_unknown(mode):
    row, index = index_for([])
    policy = row['rotationPolicy']
    if mode == 'missing_actions': policy.pop('lifetimeActions')
    elif mode == 'null_actions': policy['lifetimeActions'] = None
    elif mode == 'unreadable_actions': policy['_coverage'] = {'lifetimeActions': {'status': 'partial'}}
    elif mode == 'unknown_action': policy['lifetimeActions'] = [{'action': {'type': 'Unknown'}}]
    elif mode in ('bad_interval', 'incomparable_interval', 'expiry_relative'):
        trigger = {'timeAfterCreate': 'not-a-duration' if mode == 'bad_interval' else 'P3M'}
        if mode == 'expiry_relative': trigger = {'timeBeforeExpiry': 'P30D'}
        policy['lifetimeActions'] = [{'action': {'type': 'Rotate'}, 'trigger': trigger}]
    elif mode == 'foreign_key': row['keyId'] = NATIVE_KEY + '-foreign'
    elif mode == 'foreign_policy_key': policy['keyId'] = NATIVE_KEY + '-foreign'
    elif mode == 'foreign_arm_key': row['armKeyId'] = KEY + '-foreign'
    elif mode == 'foreign_scope': row['scope_id'] = SCOPE.replace('1111', '2222')
    elif mode == 'incomplete_policy': policy['_provenance']['representation'] = 'list'
    elif mode == 'stale_policy': policy['collection_status'] = 'stale'
    elif mode == 'incomplete_row': row['collection_status'] = 'partial'
    assert evaluate_check(CONTROL, {}, index)[0] == 'UNKNOWN'


def test_configured_policy_without_enforcement_or_permissions_stays_unknown():
    _, index = index_for()
    assert evaluate_check(CONTROL, {}, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('mode,expected', [('complete', 'PASS'), ('permissions_absent', 'FAIL'), ('ineffective_assignment', 'FAIL')])
def test_complete_existing_three_part_control_is_preserved(mode, expected):
    row, index = index_for(complete=True)
    if mode == 'permissions_absent': row['rotationIdentities'][0]['effectivePermissions'] = []
    if mode == 'ineffective_assignment': row['enforcementAssignments'][0]['effect'] = 'Audit'
    assert evaluate_check(CONTROL, {}, index)[0] == expected


@pytest.mark.parametrize('missing_rotate', [True, False])
def test_cross_vault_arm_name_cannot_attest_same_data_plane_key(missing_rotate):
    row, index = index_for([] if missing_rotate else None, complete=True)
    row['vaultId'] = VAULT + '-other'
    row['armKeyId'] = row['vaultId'] + '/keys/key'
    # The old predicate returned PASS for the configured case because it
    # matched the URL only against itself, never against the ARM vault name.
    assert evaluate_check(CONTROL, {}, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('trigger', [None, {}, {'timeBeforeExpiry': 'broken'}, {'timeAfterCreate': 'P30D'}])
def test_malformed_notify_is_not_complete_missing_rotate_proof(trigger):
    _, index = index_for()
    action = {'action': {'type': 'Notify'}}
    if trigger is not None:
        action['trigger'] = trigger
    index['key_rotation_evidence'][0]['data']['rotationPolicy']['lifetimeActions'] = [action]
    assert evaluate_check(CONTROL, {}, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('mode', ['good', 'vault_denied', 'key_denied', 'policy_denied', 'policy_timeout',
    'missing_rotate', 'slow_rotate', 'notify_only'])
def test_public_collect_live_native_policy_to_signed_control_without_fake_permissions(monkeypatch, mode):
    calls = []
    closed = []
    vault = {'id': VAULT, 'name': 'vault', 'type': 'Microsoft.KeyVault/vaults',
             'properties': {'vaultUri': ORIGIN}}
    class Transport:
        tenant = verified_tenant = '22222222-2222-2222-2222-222222222222'
        def close(self):
            closed.append(True)
        def allow_vault(self, origin):
            assert origin.rstrip('/') == ORIGIN
        def request(self, url, *, body=None, audience=azure.ARM):
            calls.append((url, audience, body))
            path = urlsplit(url).path
            if '/resourcegraph/' in path.casefold():
                assert audience == azure.ARM and isinstance(body, dict)
                return {'data': [], 'resultTruncated': False}
            assert body is None
            denied_path = {'vault_denied': SCOPE + '/providers/Microsoft.KeyVault/vaults',
                           'key_denied': '/keys', 'policy_denied': '/keys/key/rotationpolicy'}.get(mode)
            if path == denied_path:
                raise azure.AzureReadError('inert_access_denied', 403)
            if mode == 'policy_timeout' and path == '/keys/key/rotationpolicy':
                raise TimeoutError('inert_timeout')
            if audience == azure.ARM:
                if path == SCOPE + '/providers/Microsoft.KeyVault/vaults': return {'value': [deepcopy(vault)]}
                if path == VAULT: return deepcopy(vault)
            if audience == azure.VAULT:
                if path == '/keys': return {'value': [{'kid': NATIVE_KEY, 'attributes': {'enabled': True}}]}
                if path == '/keys/key/rotationpolicy':
                    actions = [{'action': {'type': 'Rotate'}, 'trigger': {'timeAfterCreate': 'P90D'}}]
                    if mode == 'missing_rotate': actions = []
                    if mode == 'slow_rotate': actions[0]['trigger']['timeAfterCreate'] = 'P91D'
                    if mode == 'notify_only': actions = [{'action': {'type': 'Notify'}, 'trigger': {'timeBeforeExpiry': 'P30D'}}]
                    return {'id': NATIVE_KEY + '/rotationpolicy', 'lifetimeActions': actions}
            raise AssertionError('unexpected native API request: ' + path)
    monkeypatch.setattr(azure, 'AzureTransport', lambda auth: Transport());monkeypatch.setattr(azure,'AzureTransportExposure',lambda auth: Transport())
    snapshot = collect_live({'provider': 'azure', 'scopes': [SCOPE],
        'auth': {'method': 'token', 'arm_token': 'inert-fixture'},
        'options': {'concurrency': 1, 'retries': 0, 'compliance_policy': {'sw16': {CONTROL: owner()}}}},
        ['key_rotation_evidence'])
    facts = [c for c in snapshot['collections'] if c['type'] == 'key_rotation_evidence']
    observed = mode in ('good', 'missing_rotate', 'slow_rotate', 'notify_only')
    expected = 'collected' if observed else 'timeout' if mode == 'policy_timeout' else 'denied'
    assert len(facts) == 1 and facts[0]['status'] == expected
    assert closed == [True]
    if observed:
        assert len(facts[0]['items']) == 1
        assert facts[0]['items'][0]['rotationIdentities'] == []
    else:
        assert facts[0]['items'] == []
    if mode not in ('vault_denied', 'key_denied'):
        assert any(url.startswith(NATIVE_KEY + '/rotationpolicy?') for url, _, _ in calls)
    findings = [f for f in evaluate_snapshot(snapshot, checks=[CONTROL])['findings'] if f['check_id'] == CONTROL]
    status = 'FAIL' if mode in ('missing_rotate', 'slow_rotate', 'notify_only') else 'DENIED' if mode.endswith('denied') else 'UNKNOWN'
    assert len(findings) == 1 and findings[0]['status'] == status


@pytest.mark.parametrize('source_position', [0, 1, 2], ids=['vault', 'key', 'policy'])
@pytest.mark.parametrize('status,expected', [('denied', 'denied'), ('timeout', 'timeout'),
    ('not_collected', 'malformed'), ('malformed', 'malformed')])
def test_native_parent_error_cause_survives_real_reader(source_position, status, expected):
    incoming = sources()
    incoming[source_position].update(status=status, items=[])
    result = project(incoming)
    assert result['status'] == expected
    assert result['items'] == []


@pytest.mark.parametrize('kind', ['rotate', 'ROTATE', 'rOtAtE', 'notify', 'NOTIFY', 'nOtIfY'])
def test_native_action_enum_uses_documented_case_insensitive_contract(kind):
    incoming = sources()
    trigger = {'timeAfterCreate': 'P90D'} if kind.casefold() == 'rotate' else {'timeBeforeExpiry': 'P30D'}
    incoming[2]['items'][0]['properties']['lifetimeActions'] = [{'action': {'type': kind}, 'trigger': trigger}]
    collection = project(incoming)
    assert collection['status'] == 'collected'
    assert collection['items'][0]['rotationPolicy']['lifetimeActions'][0]['action']['type'] == kind.capitalize()


@pytest.mark.parametrize('identity', [
    VAULT,
    SCOPE + '/providers/Microsoft.Authorization/roleAssignments/rotation',
    VAULT + '/providers/Microsoft.Authorization/policyAssignments/rotation',
    SCOPE + '/providers/Microsoft.Authorization/policyAssignments/%2e%2e',
    SCOPE + '/providers/Microsoft.Authorization/policyAssignments/..',
    SCOPE + '/providers/Microsoft.Authorization/policyAssignments/x\\y',
])
def test_enforcement_assignment_type_and_declared_parent_must_match(identity):
    row, index = index_for(complete=True)
    row['enforcementAssignments'][0]['assignmentId'] = identity
    assert evaluate_check(CONTROL, {}, index)[0] == 'UNKNOWN'


@pytest.mark.parametrize('scope', [SCOPE, VAULT, KEY])
def test_exact_supported_enforcement_assignment_parent_preserves_pass(scope):
    row, index = index_for(complete=True)
    assignment = row['enforcementAssignments'][0]
    assignment['scope'] = scope
    assignment['assignmentId'] = scope + '/providers/Microsoft.Authorization/policyAssignments/rotation'
    assert evaluate_check(CONTROL, {}, index)[0] == 'PASS'


@pytest.mark.parametrize('missing_first', [True, False])
@pytest.mark.parametrize('mode,expected', [
    ('missing_rotate', 'FAIL'), ('slow_rotate', 'FAIL'), ('permission_gap', 'FAIL'),
    ('complete_other_key', 'UNKNOWN'), ('incomplete_other_key', 'UNKNOWN'),
])
def test_required_key_order_cannot_hide_independently_proven_violation(missing_first, mode, expected):
    row, index = index_for([] if mode == 'missing_rotate' else None,
                           complete=mode in ('permission_gap', 'complete_other_key'))
    if mode == 'slow_rotate': row['rotationPolicy']['lifetimeActions'][0]['trigger']['timeAfterCreate'] = 'P91D'
    if mode == 'permission_gap': row['rotationIdentities'][0]['effectivePermissions'] = []
    required = [NATIVE_KEY + '-unavailable', NATIVE_KEY]
    if not missing_first: required.reverse()
    index['context']['metadata']['compliance_policy']['sw16'][CONTROL]['requiredKeyIds'] = required
    assert evaluate_check(CONTROL, {}, index)[0] == expected
