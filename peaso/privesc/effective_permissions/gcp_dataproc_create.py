"""Resolve Dataproc create-and-actAs paths to a runnable service account."""

from __future__ import annotations

import re

from . import inventory_status, items
from .gcp_datafusion_artifact import _rights


_WORKER = ('dataproc.agents.create', 'dataproc.agents.get',
           'dataproc.agents.update', 'dataproc.agents.delete',
           'dataproc.tasks.lease', 'dataproc.tasks.reportStatus',
           'storage.objects.create', 'storage.objects.get',
           'storage.objects.delete', 'storage.objects.list')


def _states(model, kind):
    return {model._norm_scope(scope): state for scope, state in
            inventory_status(model.snapshot, kind).items()}


def _api(model, project, service='dataproc'):
    if _states(model, 'service_usage').get(project) not in ('collected', 'empty'):
        return 'uncertain'
    matches = [row.get('state') for scope, row in items(model.snapshot, 'service_usage')
               if model._norm_scope(scope) == project
               and model._norm_scope(row.get('name')) == project + '/services/' + service + '.googleapis.com']
    if matches == ['ENABLED']:
        return 'derived'
    if not matches or matches == ['DISABLED']:
        return 'denied'
    return 'uncertain'


def _role_on_project(model, principal, project, role):
    return any(scope == project and granted == role and not condition
               for scope, granted, condition, _ in model.grants.get(principal, ()))


def _agent(model, project, runtime='legacy'):
    numbers = [number for number, pid in model.project_alias.items()
               if pid == project.removeprefix('projects/') and number.isdecimal()]
    if len(numbers) != 1:
        return 'uncertain'
    if runtime == 'node3':
        principal = 'serviceAccount:service-' + numbers[0] + '@gcp-sa-dataprocrmnode.iam.gserviceaccount.com'
        role = 'roles/dataprocrm.nodeServiceAgent'
    else:
        principal = 'serviceAccount:service-' + numbers[0] + '@dataproc-accounts.iam.gserviceaccount.com'
        role = 'roles/dataproc.serviceAgent'
    if _role_on_project(model, principal, project, role):
        return 'derived'
    return 'uncertain'


def _subnet(model, project):
    if _states(model, 'subnetwork').get(project) not in ('collected', 'empty'):
        return 'uncertain'
    if _states(model, 'network').get(project) not in ('collected', 'empty'):
        return 'uncertain'
    networks = {model._norm_scope((row.get('selfLink') or '').split('/compute/v1/', 1)[-1])
                for scope, row in items(model.snapshot, 'network')
                if model._norm_scope(scope) == project}
    for scope, row in items(model.snapshot, 'subnetwork'):
        if model._norm_scope(scope) != project:
            continue
        link = (row.get('selfLink') or '').split('/compute/v1/', 1)[-1]
        network = (row.get('network') or '').split('/compute/v1/', 1)[-1]
        if (re.fullmatch(re.escape(project) + r'/regions/[a-z0-9-]+/subnetworks/[^/]+', link)
                and network in networks and row.get('purpose', 'PRIVATE') == 'PRIVATE'
                and row.get('state', 'READY') == 'READY'):
            return 'derived'
    return 'denied'


def _script(model, source, target):
    """A new script can serve a PySpark batch or a cluster init action."""
    if not model.bucket_projects:
        return 'uncertain'
    for name in model.bucket_projects:
        bucket = '//storage.googleapis.com/projects/_/buckets/' + name
        object_resource = bucket + '/objects/__peaso_dataproc_payload.py'
        model.parents.setdefault(object_resource, bucket)
        if (_rights(model, source, bucket, ('storage.objects.create',)) == 'derived'
                and _rights(model, target, object_resource, ('storage.objects.get',)) == 'derived'):
            return 'derived'
    # An external or uncollected code source may still be usable.
    return 'uncertain'


def select(model, candidates, source):
    if source is None:
        return {}
    projects = sorted({model._norm_scope(scope) for scope, _ in items(model.snapshot, 'project')})
    out = {}
    project_rights = {}  # source rights per project do not depend on the target
    for target_id, target in candidates.items():
        if target_id == source.id or target.kind != 'gcp_service_account' or target.attrs.get('disabled'):
            continue
        resource = target.attrs.get('resource')
        target_project = target.attrs.get('project') or target.scope
        if not isinstance(resource, str) or not isinstance(target_project, str):
            continue
        actas = _rights(model, source, resource, ('iam.serviceAccounts.actAs',))
        if actas == 'denied':
            continue
        uncertain = actas == 'uncertain'
        for project in projects:
            rights = project_rights.get(project)
            if rights is None:
                rights = project_rights[project] = (
                    _rights(model, source, project, ('dataproc.clusters.create',)),
                    _rights(model, source, project, ('dataproc.batches.create',)))
            cluster, batch = rights
            if cluster == batch == 'denied':
                continue
            if target_project != project:
                uncertain = True  # Cross-project service-agent and organization-policy gates.
                continue
            if cluster != 'derived' and batch != 'derived':
                uncertain = True
                continue
            if _api(model, project) == 'denied':
                continue
            if _api(model, project) != 'derived' or _subnet(model, project) != 'derived':
                uncertain = True
                continue
            legacy = (_agent(model, project) == 'derived'
                      and _rights(model, target, project, _WORKER) == 'derived'
                      and (cluster == 'derived'  # Inline startup-script metadata needs no GCS payload.
                           or (batch == 'derived' and
                               _script(model, source, target) == 'derived')))
            node3 = (batch == 'derived' and _api(model, project, 'dataprocrm') == 'derived'
                     and _agent(model, project, 'node3') == 'derived'
                     and _role_on_project(model, target.id, project,
                                          'roles/dataproc.serverlessNode')
                     and _role_on_project(model, target.id, project,
                                          'roles/dataprocrm.nodeServiceAgent')
                     and _script(model, source, target) == 'derived')
            if not legacy and not node3:
                uncertain = True
                continue
            if actas == 'derived':
                out[target_id] = ('conditional', 'dataproc_create_with_runnable_worker_and_script')
                break
            uncertain = True
        if target_id not in out and uncertain:
            out[target_id] = ('unknown', 'dataproc_create_runtime_or_attachment_unresolved')
    return out
