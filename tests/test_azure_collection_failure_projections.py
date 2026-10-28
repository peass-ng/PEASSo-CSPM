"""A collector failure must still seal every later native projection once."""
from collections import Counter

from peaso.collectors import azure
from peaso.snapshot import validate

SUB = '0ce70b1c-9153-425d-8629-f576930f4377'
TENANT = 'fdd066e1-ee37-49bc-b08f-d0e152119b04'
PROJECTIONS = {'apim_api_evidence', 'apim_diagnostic_evidence',
               'azure_unused_arm_role_evidence', 'entra_user',
               'sql_database_inventory', 'sql_tde_inventory'}


class Denied(RuntimeError):
    status = 403


class FailedTransport:
    tenant = verified_tenant = TENANT
    def request(self, *args, **kwargs):
        raise Denied('fixture denial')
    def close(self):
        pass


def test_default_inventory_failure_keeps_one_envelope_for_each_later_projection():
    snapshot = azure.collect({'provider': 'azure', 'scopes': [SUB],
                              'auth': {'tenant_id': TENANT}, 'options': {'retries': 0}},
                             transport=FailedTransport())
    assert validate(snapshot) == snapshot
    keys = Counter((row['type'], row['scope']) for row in snapshot['collections'])
    assert max(keys.values()) == 1
    for kind in PROJECTIONS:
        assert keys[kind, '/subscriptions/' + SUB] == 1
    # Native errors remain visible; the failure cannot become complete empty data.
    assert any(row.get('error', {}).get('kind') == 'ContextUnavailable'
               for row in snapshot['collections'])
    assert all(row['status'] != 'empty' for row in snapshot['collections']
               if row['type'] in PROJECTIONS)
