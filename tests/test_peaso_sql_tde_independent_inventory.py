"""A native Disabled state survives unavailable, unrelated database families."""
import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
BASE = SCOPE + '/resourceGroups/rg/providers/Microsoft.Sql/'
CHECK = 'azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5'


def capture(family, state, other_status='not_collected', *, corrupt=False):
    sources = [('sql_database_inventory', 'sql_tde_inventory', 'servers/s/databases/db'),
               ('managed_instance_database', 'managed_instance_tde', 'managedInstances/m/databases/db')]
    collections = []
    for pos, (primary, child, suffix) in enumerate(sources):
        database = BASE + suffix
        available = pos == family
        collections.extend([
            {'type': primary, 'scope': SCOPE, 'status': 'collected' if available else other_status,
             'items': [{'id': database}] if available else []},
            {'type': child, 'scope': SCOPE, 'status': 'collected' if available else other_status,
             'items': [{'id': database + '/transparentDataEncryption/current',
                        'parent_id': database, 'properties': {'state': state}}] if available else []},
        ])
    if corrupt:
        collections[2 * family + 1]['items'][0]['parent_id'] += '-foreign'
    return make_snapshot('azure', [SCOPE], collections)


def status(snapshot):
    findings = evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    assert len(findings) == 1
    return findings[0]['status']


@pytest.mark.parametrize('family', [0, 1])
@pytest.mark.parametrize('other_status', ['not_collected', 'denied', 'partial'])
def test_known_disabled_database_survives_unrelated_incomplete_family(family, other_status):
    assert status(capture(family, 'Disabled', other_status)) == 'FAIL'


@pytest.mark.parametrize('family', [0, 1])
@pytest.mark.parametrize('other_status,expected', [('not_collected', 'UNKNOWN'), ('denied', 'DENIED')])
def test_one_encrypted_family_cannot_prove_global_pass(family, other_status, expected):
    assert status(capture(family, 'Enabled', other_status)) == expected


@pytest.mark.parametrize('family', [0, 1])
def test_unbound_disabled_state_is_not_a_proven_violation(family):
    assert status(capture(family, 'Disabled', corrupt=True)) == 'UNKNOWN'


@pytest.mark.parametrize('family', [0, 1])
def test_public_readonly_native_tde_with_other_provider_inventory_denied(monkeypatch, family):
    from peaso.collectors import azure, collect_live
    from tests.test_peaso_collectors_azurek8s import FakeAzure
    server = BASE + 'servers/s'
    managed = BASE + 'managedInstances/m'
    available = server if family == 0 else managed
    database = available + '/databases/db'
    calls = []

    def response(url, body, audience):
        assert body is None
        calls.append(url)
        if '/transparentDataEncryption/current?' in url:
            return {'id': database + '/transparentDataEncryption/current', 'properties': {'state': 'Disabled'}}
        if '/databases?' in url:
            return {'value': [{'id': database, 'name': 'db', 'properties': {'status': 'Online'}}]}
        if '/providers/Microsoft.Sql/servers?' in url:
            if family != 0: raise azure.AzureReadError('denied', 403)
            return {'value': [{'id': server, 'name': 's', 'type': 'Microsoft.Sql/servers', 'properties': {}}]}
        if '/providers/Microsoft.Sql/managedInstances?' in url:
            if family != 1: raise azure.AzureReadError('denied', 403)
            return {'value': [{'id': managed, 'name': 'm', 'type': 'Microsoft.Sql/managedInstances', 'properties': {}}]}
        if url.split('?', 1)[0] == azure.ARM + available:
            return {'id': available, 'properties': {}}
        return {'value': []}

    transport = FakeAzure(response)
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda c, kinds: original(c, kinds, transport=transport))
    snapshot = collect_live({'provider': 'azure', 'scopes': [SCOPE], 'options': {'retries': 0}},
                            ['sql_database_inventory', 'sql_tde_inventory',
                             'managed_instance_database', 'managed_instance_tde'])
    assert status(snapshot) == 'FAIL'
    assert any('/transparentDataEncryption/current?' in url for url in calls)
