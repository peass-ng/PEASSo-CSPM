"""A caught inventory failure must seal explicit incomplete automatic content coverage."""
import pytest

from peaso.collectors import azure
from peaso.snapshot import validate
from tests.test_azure_unified_native_inventories import Fixture, SUB, TENANT

KINDS = (azure.azure_selected_configuration_secret_indicators.KIND,
         azure.azure_app_settings_secret_indicators.KIND)


@pytest.mark.parametrize('kinds', [(KINDS[0],), (KINDS[1],), KINDS])
def test_early_inventory_failure_keeps_automatic_content_unknown(monkeypatch, kinds):
    def interrupt(*args, **kwargs):
        raise ValueError('fixture original inventory failure')
    monkeypatch.setattr(azure.azure_containerapp_runtime, 'collect', interrupt)
    snapshot = azure.collect({'provider': 'azure', 'auth': {'tenant_id': TENANT}, 'scopes': [SUB],
        'options': {'content_secret_scans': True, '_content_secret_scan_kinds': list(kinds), 'retries': 0}},
        requirements=list(kinds), transport=Fixture(populated=False))
    validate(snapshot, read_only=True)
    metadata = snapshot['metadata']
    for kind in kinds:
        coverage = metadata['automatic_workload_environment_coverage'][kind]
        assert coverage['complete'] is False
        assert coverage['reason'] == 'source_inventory_unavailable'
        assert coverage['inspected'] == 0
        assert coverage['targets'] == []
        assert metadata['automatic_workload_environment_batches'][kind] == []
        rows = [row for row in snapshot['collections'] if row['type'] == kind]
        assert len(rows) == 1 and rows[0]['status'] == 'malformed'
        assert rows[0]['error']['code'] == 'read_failed'


def test_completed_container_coverage_survives_later_content_interruption(monkeypatch):
    def interrupt(*args, **kwargs):
        raise ValueError('fixture failure after container discovery')
    monkeypatch.setattr(azure.azure_selected_declaration_secret_indicators, 'collect', interrupt)
    snapshot = azure.collect({'provider': 'azure', 'auth': {'tenant_id': TENANT}, 'scopes': [SUB],
        'options': {'content_secret_scans': True, '_content_secret_scan_kinds': list(KINDS), 'retries': 0}},
        requirements=list(KINDS), transport=Fixture(populated=False))
    coverage = snapshot['metadata']['automatic_workload_environment_coverage']
    assert coverage[KINDS[0]]['complete'] is True
    assert coverage[KINDS[0]]['reason'] == 'complete'
    assert coverage[KINDS[1]]['complete'] is False
    assert coverage[KINDS[1]]['reason'] == 'source_inventory_unavailable'


def test_native_auxiliary_checkpoint_does_not_abort_content_collection(monkeypatch):
    import copy
    from types import SimpleNamespace
    from peaso.incremental import CheckpointSession
    from peaso.snapshot_public_identity import public_snapshot_adapter
    adapter = public_snapshot_adapter(copy.deepcopy, provider='azure', trusted_scopes=[SUB])
    state = SimpleNamespace(provider='azure', requested_scopes=[SUB], collection_finished=False,
        final_metadata=None, sequence=319, scope_plan=None)
    def checkpoint(row):
        adapter(CheckpointSession._snapshot(state, [row]))
    def native_auxiliary(reader, *args, **kwargs):
        reader.collections.append({'type': 'cost_export_billing_scope', 'scope': SUB,
            'service': 'Microsoft.CostManagement', 'status': 'empty', 'items': []})
    monkeypatch.setattr(azure.azure_containerapp_runtime, 'collect', native_auxiliary)
    snapshot = azure.collect({'provider': 'azure', 'auth': {'tenant_id': TENANT}, 'scopes': [SUB],
        'options': {'content_secret_scans': True, '_content_secret_scan_kinds': list(KINDS),
            '_collection_callback': checkpoint, 'retries': 0}}, requirements=list(KINDS),
        transport=Fixture(populated=False))
    assert all(coverage['complete'] for coverage in
        snapshot['metadata']['automatic_workload_environment_coverage'].values())
    assert all(row['error'].get('kind') != 'ValueError'
        for row in snapshot['collections'] if 'error' in row)
