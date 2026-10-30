"""Finite ancillary ARM list contracts for independent native fixtures.

An ancillary resource absent from a fixture uses the ARM list envelope
{"value": []}; existing explicit resource DTOs and denied reads take precedence.
Partial-read scenarios retain their exact fixture-authored continuation tokens.
Versions match azure_storage_backup_native, azure_containerapp_jobs (native
Container Apps Job/environment lists), azure.ENDPOINTS and the reviewed
azure_network_private_services catalog. Unknown paths, details, child lists,
other subscriptions and other API versions remain unsupported by this helper.
"""


def empty_inventory_versions(scope):
    return {
        scope + '/providers/Microsoft.NetApp/netAppAccounts': '2026-01-01',
        scope + '/providers/Microsoft.DataProtection/backupVaults': '2025-07-01',
        scope + '/providers/Microsoft.ContainerService/fleets': '2026-06-01',
        scope + '/providers/Microsoft.Kubernetes/connectedClusters': '2024-01-01',
        scope + '/providers/Microsoft.App/jobs': '2025-07-01',
        scope + '/providers/Microsoft.App/managedEnvironments': '2025-07-01',
    }


def matches_empty_inventory_query(scope, path, query):
    versions=empty_inventory_versions(scope)
    if path not in versions or set(query)-{'api-version','page','$skiptoken'}:
        return False
    # Two real collectors use different reviewed BackupVaults List versions.
    allowed={versions[path]}
    if path==scope+'/providers/Microsoft.DataProtection/backupVaults':
        allowed.add('2026-06-01')
    if query.get('api-version') not in [[version] for version in allowed]:
        return False
    # Only the continuations authored by these finite partial-read fixtures.
    return (query.get('page') in (None,['2'])
            and query.get('$skiptoken') in (None,['next'])
            and not {'page','$skiptoken'}<=set(query))
