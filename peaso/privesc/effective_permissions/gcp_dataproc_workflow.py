"""Check whether a complete managed-cluster workflow can use a chosen SA."""

from __future__ import annotations

from . import items
from .gcp_datafusion_artifact import _rights
from .gcp_dataproc_create import _WORKER, _agent, _api, _script, _subnet


def select(model, candidates, source):
    if source is None:
        return {}
    projects = sorted({model._norm_scope(scope) for scope, _ in items(model.snapshot, 'project')})
    out = {}
    project_rights = {}  # source rights per project do not depend on the target
    for target_id, target in candidates.items():
        if (target_id == source.id or target.kind != 'gcp_service_account'
                or target.attrs.get('disabled')):
            continue
        resource = target.attrs.get('resource')
        target_project = target.attrs.get('project') or target.scope
        if not isinstance(resource, str) or not isinstance(target_project, str):
            continue
        actas = _rights(model, source, resource, ('iam.serviceAccounts.actAs',))
        if actas == 'denied':
            continue
        unresolved = actas != 'derived'
        for project in projects:
            rights = project_rights.get(project)
            if rights is None:
                rights = project_rights[project] = tuple(
                    _rights(model, source, project, (action,)) for action in (
                        'dataproc.workflowTemplates.create', 'dataproc.workflowTemplates.instantiate',
                        'dataproc.workflowTemplates.instantiateInline',
                        'dataproc.workflowTemplates.setIamPolicy'))
            create, instantiate, inline, policy = rights
            template = create == 'derived' and instantiate == 'derived'
            immediate = inline == 'derived'
            if not template and not immediate:
                if create != 'denied' and (instantiate != 'denied' or policy != 'denied'):
                    unresolved = True
                elif inline != 'denied':
                    unresolved = True
                continue
            if target_project != project:
                unresolved = True  # Cross-project attachment needs a separate agent grant.
                continue
            if _api(model, project) == 'denied':
                continue
            if (_api(model, project) != 'derived' or _agent(model, project) != 'derived'
                    or _subnet(model, project) != 'derived'):
                unresolved = True
                continue
            if (_rights(model, target, project, _WORKER) != 'derived' or
                    _script(model, source, target) != 'derived'):
                unresolved = True
                continue
            if actas != 'derived':
                unresolved = True
                continue
            out[target_id] = ('conditional', 'managed_workflow_with_runnable_init_payload')
            break
        if target_id not in out and unresolved:
            out[target_id] = ('unknown', 'managed_workflow_runtime_or_attachment_unresolved')
    return out
