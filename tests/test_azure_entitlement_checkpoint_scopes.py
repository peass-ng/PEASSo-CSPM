"""Exact native entitlement scopes survive the real checkpoint privacy boundary."""
import copy
from types import SimpleNamespace

import pytest

from peaso.incremental import CheckpointSession
from peaso.snapshot_public_identity import public_snapshot_adapter

TENANT = '00000000-0000-0000-0000-000000000001'
GUID = '00000000-0000-0000-0000-000000000002'
SUB = '/subscriptions/00000000-0000-0000-0000-000000000003'


@pytest.mark.parametrize('segment,kind', [('catalogs', 'entitlement_catalog_resource'),
                                        ('accessPackages', 'entitlement_resource_role_scope')])
def test_native_entitlement_scope_survives_checkpoint_and_redaction(segment, kind):
    # Match the collector's current registered type names directly.
    from peaso.collectors.azure_entitlement_native import CATALOG_RESOURCE, RESOURCE
    kind = CATALOG_RESOURCE if segment == 'catalogs' else RESOURCE
    scope = '/tenants/' + TENANT + '/' + segment + '/' + GUID
    row = {'type': kind, 'scope': scope, 'service': 'Microsoft.Graph', 'status': 'empty', 'items': []}
    session = SimpleNamespace(provider='azure', requested_scopes=[SUB], collection_finished=False,
        final_metadata=None, sequence=319, scope_plan=None)
    raw = CheckpointSession._snapshot(session, [row])
    def redact(snapshot):
        public = copy.deepcopy(snapshot)
        public['scopes'] = ['REDACTED']
        public['collections'][0].update(type='REDACTED', scope='REDACTED')
        return public
    public = public_snapshot_adapter(redact, provider='azure', trusted_scopes=[SUB])(raw)
    assert public['scopes'] == [scope]
    assert public['collections'] == [row]
    assert public['metadata']['scope_coverage']['status'] == 'partial'


@pytest.mark.parametrize('suffix', ['catalogs/not-guid', 'accessPackages/not-guid',
    'catalogs/' + GUID + '/resources', 'accessPackages/' + GUID + '/roleScopes',
    'catalogs/../' + GUID, 'arbitrary/' + GUID, 'catalogs/%2f' + GUID])
def test_noncanonical_entitlement_scopes_still_fail_closed(suffix):
    from peaso.snapshot_public_identity import _canonical_scope
    assert not _canonical_scope('azure', '/tenants/' + TENANT + '/' + suffix)


@pytest.mark.parametrize('kind', ['cost_export_billing_scope', 'databricks_workspace_ip_policy'])
def test_exact_native_auxiliary_envelopes_pass_checkpoint(kind):
    session = SimpleNamespace(provider='azure', requested_scopes=[SUB], collection_finished=False,
        final_metadata=None, sequence=319, scope_plan=None)
    row = {'type': kind, 'scope': SUB, 'status': 'not_collected', 'items': []}
    snapshot = CheckpointSession._snapshot(session, [row])
    public = public_snapshot_adapter(copy.deepcopy, provider='azure', trusted_scopes=[SUB])(snapshot)
    assert public['collections'] == [row]


def test_arbitrary_native_type_remains_rejected():
    from peaso.snapshot import make_snapshot
    snapshot = make_snapshot('azure', [SUB], [{'type': 'arbitrary_type', 'scope': SUB,
        'status': 'empty', 'items': []}])
    with pytest.raises(ValueError, match='Unregistered native collection type'):
        public_snapshot_adapter(copy.deepcopy, provider='azure', trusted_scopes=[SUB])(snapshot)
