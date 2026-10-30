"""Bound Dataform workflow execution to an exact BigQuery read or write gain."""

from __future__ import annotations

from . import inventory_status, items
from .gcp_bigquery_scheduled_query import (
    _has, _known, _ordinary_table, _permission_inventory_complete,
    _source_group_membership_complete,
)


REPOSITORY_WORKFLOW = (
    'dataform.workspaces.create', 'dataform.workspaces.writeFile',
    'dataform.compilationResults.create', 'dataform.workflowInvocations.create',
)
COMMIT_WORKFLOW = (
    'dataform.repositories.commit', 'dataform.compilationResults.create',
    'dataform.workflowInvocations.create',
)


def _creator_role(model, config):
    creator = config.get('creatorRoleConfig')
    if not isinstance(creator, dict) or creator.get('disableGrant') is True:
        return None
    name = creator.get('creatorRole', 'roles/dataform.admin')
    role = model.roles.get(name)
    if role is None or role.confidence != 'derived' or not all(
            role.has(permission.lower()) for permission in REPOSITORY_WORKFLOW):
        return None
    return role


def _self_grant_ready(model, caller, repository, project):
    if caller.kind not in ('gcp_user', 'gcp_service_account'):
        return False
    ancestors = [scope for scope in model.ancestors(project)
                 if scope.startswith(('projects/', 'folders/', 'organizations/'))
                 and scope.count('/') == 1]
    if (inventory_status(model.snapshot, 'org_policy_effective').get(project)
            not in ('collected', 'empty')):
        return False
    if any(item.get('constraint') in ('iam.allowedPolicyMemberDomains',
                                      'iam.managed.allowedPolicyMembers')
           for scope, item in items(model.snapshot, 'org_policy_effective')
           if model._norm_scope(scope) in ancestors):
        return False
    if any(model.iam_policy_inventory_status.get(scope) not in ('collected', 'empty')
           or model.iam_role_inventory_status.get(scope) not in ('collected', 'empty')
           or model.deny_status.get(scope) not in ('collected', 'empty')
           for scope in ancestors):
        return False
    return _known(model, caller, 'dataform.repositories.setIamPolicy', repository)


def _execution_route(model, caller, project):
    """Return whether an exact location or repository supports authored SQL."""
    incomplete = False
    if inventory_status(model.snapshot, 'dataform_privesc_location').get(project) not in ('collected', 'empty'):
        return False, True
    for location, config in model.dataform_locations.items():
        if not location.startswith(project + '/locations/'):
            continue
        creator = _creator_role(model, config)
        if creator is not None and _has(model, caller, 'dataform.repositories.create', location):
            if (caller.kind == 'gcp_user'
                    and config.get('enablePrivateWorkspace') is not True
                    and _known(model, caller, 'dataform.repositories.create', location)):
                return True, False
            incomplete = True
        for repository in config.get('repositories', ()):
            name = repository.get('name')
            if name not in model.dataform_repositories:
                incomplete = True
                continue
            if (all(_known(model, caller, permission, name) for permission in REPOSITORY_WORKFLOW)
                    or all(_known(model, caller, permission, name) for permission in COMMIT_WORKFLOW)):
                return True, False
            if (all(_has(model, caller, permission, name) for permission in REPOSITORY_WORKFLOW)
                    or all(_has(model, caller, permission, name) for permission in COMMIT_WORKFLOW)):
                incomplete = True
            if _self_grant_ready(model, caller, name, project):
                return True, False
            if _has(model, caller, 'dataform.repositories.setIamPolicy', name):
                incomplete = True
    return False, incomplete


def _agent_ready(model, project, sa_resource):
    numbers = [number for number, pid in model.project_alias.items()
               if number.isdecimal() and pid == project.removeprefix('projects/')]
    if len(numbers) != 1:
        return False
    member = f'serviceAccount:service-{numbers[0]}@gcp-sa-dataform.iam.gserviceaccount.com'
    agent = model.principals.get(member)
    return bool(agent and _known(model, agent, 'iam.serviceAccounts.getAccessToken', sa_resource))


def _writable_dataset(metadata):
    return (isinstance(metadata, dict)
            and metadata.get('datasetType', 'DEFAULT') == 'DEFAULT'
            and not metadata.get('linkedDatasetSource')
            and not metadata.get('externalDatasetReference'))


def _new_table_read(model, caller, sa, project):
    """Find a same-location source table and caller-readable output dataset."""
    if not _permission_inventory_complete(model, project):
        return False, True
    destinations = []
    for dataset, metadata in model.bigquery_datasets.items():
        if not _writable_dataset(metadata):
            continue
        location = metadata.get('location')
        dataset_project = dataset.split('/datasets/', 1)[0]
        if (not isinstance(location, str) or not location
                or not _permission_inventory_complete(model, dataset_project)):
            continue
        if (model.resource_policy_status.get('bigquery_dataset', {}).get(dataset) == 'collected'
                and _known(model, sa, 'bigquery.tables.create', dataset)
                and _known(model, sa, 'bigquery.tables.updateData', dataset)
                and _known(model, caller, 'bigquery.tables.getData', dataset)):
            destinations.append(location.lower())
    incomplete = not destinations
    for table in model.resource_policy_status.get('bigquery_table', {}):
        dataset = table.rsplit('/tables/', 1)[0]
        meta = model.bigquery_datasets.get(dataset)
        if not meta or str(meta.get('location', '')).lower() not in destinations:
            continue
        table_project = dataset.split('/datasets/', 1)[0]
        if (not _permission_inventory_complete(model, table_project)
                or not _source_group_membership_complete(model, caller, table_project)
                or model.resource_policy_status['bigquery_table'].get(table) != 'collected'
                or model.resource_policy_status.get('bigquery_dataset', {}).get(dataset) != 'collected'
                or model.bigquery_row_policy_status.get(table) != 'collected'
                or model.bigquery_row_policies.get(table)
                or not _ordinary_table(model, table)):
            incomplete = True
            continue
        if (_known(model, sa, 'bigquery.tables.getData', table)
                and not _has(model, caller, 'bigquery.tables.getData', table)):
            return True, False
        if (_has(model, sa, 'bigquery.tables.getData', table)
                and not _known(model, sa, 'bigquery.tables.getData', table)):
            incomplete = True
    statuses = model.resource_inventory_status.get('bigquery_table', {})
    if not statuses or any(status not in ('collected', 'empty') for status in statuses.values()):
        incomplete = True
    return False, incomplete


def _new_dataset_write(model, caller, sa, project):
    """Find a dataset where the target can create a table but the caller cannot."""
    if not _permission_inventory_complete(model, project):
        return False, True
    incomplete = False
    for dataset, metadata in model.bigquery_datasets.items():
        if not _writable_dataset(metadata) or not metadata.get('location'):
            continue
        dataset_project = dataset.split('/datasets/', 1)[0]
        if (not _permission_inventory_complete(model, dataset_project)
                or not _source_group_membership_complete(model, caller, dataset_project)
                or model.resource_policy_status.get('bigquery_dataset', {}).get(dataset) != 'collected'):
            incomplete = True
            continue
        needed = ('bigquery.tables.create', 'bigquery.tables.updateData')
        if all(_known(model, sa, permission, dataset) for permission in needed):
            if not all(_has(model, caller, permission, dataset)
                       for permission in needed):
                return True, False
        elif all(_has(model, sa, permission, dataset) for permission in needed):
            incomplete = True
    statuses = model.resource_inventory_status.get('bigquery_dataset', {})
    if not statuses or any(status not in ('collected', 'empty') for status in statuses.values()):
        incomplete = True
    return False, incomplete


def _export_table_read(model, caller, sa, project):
    """Find a protected ordinary table exportable to a caller-readable bucket."""
    if not _permission_inventory_complete(model, project):
        return False, True
    destinations = set()
    for bucket_project, buckets in model.composer_custom_buckets.items():
        if (not _permission_inventory_complete(model, bucket_project)
                or not _source_group_membership_complete(model, caller, bucket_project)
                or inventory_status(model.snapshot, 'bucket').get(bucket_project)
                not in ('collected', 'empty')):
            continue
        for resource, bucket in buckets:
            location = str(bucket.get('location') or '').lower()
            if (not location or bucket.get('_representation') != 'full'
                    or not model.bucket_ubla.get(bucket.get('name'))
                    or ((bucket.get('_coverage') or {}).get('iamPolicy') or {}).get('status') != 'collected'):
                continue
            if (all(_known(model, sa, permission, resource)
                    for permission in ('storage.objects.create', 'storage.objects.delete'))
                    and _known(model, caller, 'storage.objects.get', resource)):
                destinations.add(location)
    incomplete = not destinations
    for table in model.resource_policy_status.get('bigquery_table', {}):
        dataset = table.rsplit('/tables/', 1)[0]
        meta = model.bigquery_datasets.get(dataset)
        if not meta or str(meta.get('location', '')).lower() not in destinations:
            continue
        table_project = dataset.split('/datasets/', 1)[0]
        if (not _permission_inventory_complete(model, table_project)
                or not _source_group_membership_complete(model, caller, table_project)
                or model.resource_policy_status['bigquery_table'].get(table) != 'collected'
                or model.resource_policy_status.get('bigquery_dataset', {}).get(dataset) != 'collected'
                or model.bigquery_row_policy_status.get(table) != 'collected'
                or model.bigquery_row_policies.get(table)
                or not _ordinary_table(model, table)):
            incomplete = True
            continue
        needed = ('bigquery.tables.getData', 'bigquery.tables.export')
        if (all(_known(model, sa, permission, table) for permission in needed)
                and not _has(model, caller, 'bigquery.tables.getData', table)):
            return True, False
        if all(_has(model, sa, permission, table) for permission in needed):
            incomplete = True
    return False, incomplete


def select(model, candidates, caller):
    if caller is None:
        return {}
    out = {}
    for ident, target in candidates.items():
        project = target.attrs.get('project') or target.scope
        sa = model.sas.get('serviceAccount:' + str(target.attrs.get('email') or ''))
        if sa is None or sa.attrs.get('disabled'):
            continue
        # Google-managed agents (e.g. {number}@cloudservices) are modeled from
        # the project number only; their IAM policy is Google-owned, so the
        # Dataform service agent cannot be granted Token Creator on them.
        if sa.attrs.get('service_agent'):
            continue
        if not _has(model, caller, 'iam.serviceAccounts.actAs', sa.attrs['resource']):
            continue
        if not _known(model, caller, 'iam.serviceAccounts.actAs', sa.attrs['resource']):
            out[ident] = ('unknown', 'dataform_actas_condition_unresolved')
            continue
        if _known(model, caller, 'iam.serviceAccounts.getAccessToken', sa.attrs['resource']):
            continue
        if _has(model, caller, 'iam.serviceAccounts.getAccessToken', sa.attrs['resource']):
            out[ident] = ('unknown', 'dataform_prior_token_access_unresolved')
            continue
        observed_hosts = {name.split('/locations/', 1)[0]
                          for name in model.dataform_locations}
        hosts = sorted(observed_hosts | {f'projects/{pid}'
                                         for pid in model.project_alias.values()})
        for host in hosts:
            route, route_unknown = _execution_route(model, caller, host)
            if not route:
                if route_unknown and (host in observed_hosts or _has(
                        model, caller, 'dataform.repositories.create', host)):
                    out[ident] = ('unknown', 'dataform_execution_route_unresolved')
                continue
            if host != project:
                attachment = model._effective_boolean_policy(
                    project, 'iam.disableCrossProjectServiceAccountUsage')
                if attachment is not False:
                    out[ident] = ('unknown', 'dataform_cross_project_attachment_unverified')
                    continue
            if not _agent_ready(model, host, sa.attrs['resource']):
                out[ident] = ('unknown', 'dataform_service_agent_token_authority_unverified')
                continue
            if not _known(model, sa, 'bigquery.jobs.create', host):
                out[ident] = ('unknown', 'dataform_bigquery_job_authority_unverified')
                continue
            gained, unknown = _new_table_read(model, caller, sa, host)
            if gained:
                out[ident] = ('conditional', 'dataform_exact_bigquery_table_read_gain')
                break
            write_gain, write_unknown = _new_dataset_write(model, caller, sa, host)
            if write_gain:
                out[ident] = ('conditional', 'dataform_exact_bigquery_dataset_write_gain')
                break
            export_gain, export_unknown = _export_table_read(model, caller, sa, host)
            if export_gain:
                out[ident] = ('conditional', 'dataform_exact_bigquery_table_export_gain')
                break
            if unknown or write_unknown or export_unknown:
                out[ident] = ('unknown', 'dataform_bigquery_gain_unresolved')
    return out
