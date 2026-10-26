"""Join a replacement service account to one controlled existing VM."""

from __future__ import annotations

from collections import Counter

from . import inventory_status, items
from .gcp_metadata_vm import _scope_grant
from .gcp_oslogin import (_UNRESOLVED, _firewall_permits_ssh, _flag,
                          _project_metadata, _vm_resource)


def _login_path(model, source, project, vm, resource):
    metadata = _project_metadata(model, project)
    instance_flag = _flag(vm.get("metadata"), "enable-oslogin")
    project_flag = _flag(metadata, "enable-oslogin")
    enabled = instance_flag if instance_flag is not None else project_flag
    if enabled is not True:
        return "unknown"
    login = _scope_grant(model, source, "compute.instances.osLogin", resource)
    if login != "derived":
        return "unknown"
    instance_2fa = _flag(vm.get("metadata"), "enable-oslogin-2fa")
    project_2fa = _flag(metadata, "enable-oslogin-2fa")
    twofa = instance_2fa if instance_2fa is not None else project_2fa
    if source.kind == "gcp_user" and twofa in (True, _UNRESOLVED):
        return "unknown"
    if source.kind == "gcp_user":
        for org in (scope for scope in model.ancestors(project) if scope.startswith("organizations/")):
            if _scope_grant(model, source, "compute.oslogin.updateExternalUser", org) != "derived":
                return "unknown"
    return "login" if _firewall_permits_ssh(model, project, vm) else "unknown"


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    rows = []
    for scope, vm in items(model.snapshot, "instance"):
        project = model._norm_scope(scope)
        resource = _vm_resource(model, vm, project)
        if resource:
            rows.append((project, resource, vm))
    counts = Counter(resource for _, resource, _ in rows)
    result = {}
    vm_rights = {}  # source rights on one VM do not depend on the target
    for tid, target in candidates.items():
        if target.attrs.get("disabled") is True:
            continue
        actas = _scope_grant(model, source, "iam.serviceAccounts.actAs", target.attrs.get("resource"))
        if actas is None:
            continue
        for project, resource, vm in rows:
            if any(isinstance(account, dict) and account.get("email") == target.attrs.get("email")
                   and "https://www.googleapis.com/auth/cloud-platform" in (account.get("scopes") or [])
                   for account in vm.get("serviceAccounts") or []):
                continue
            model.parents.setdefault(resource, project)
            rights = vm_rights.get(resource)
            if rights is None:
                rights = vm_rights[resource] = (
                    _scope_grant(model, source, "compute.instances.setServiceAccount", resource),
                    _scope_grant(model, source, "compute.instances.start", resource))
            change, start = rights
            if change is None:
                continue
            state = vm.get("status")
            stop = (_scope_grant(model, source, "compute.instances.stop", resource)
                    if state == "RUNNING" else "derived")
            if counts[resource] != 1:
                verdict = ("unknown", "sa_swap_vm_identity_conflict")
            elif project != target.scope:
                verdict = ("unknown", "sa_swap_cross_project_usage_unresolved")
            elif inventory_status(model.snapshot, "instance").get(project) != "collected":
                verdict = ("unknown", "sa_swap_vm_inventory_unresolved")
            elif state not in ("RUNNING", "TERMINATED", "STOPPED"):
                verdict = ("unknown", "sa_swap_vm_state_unresolved")
            elif start is None or stop is None:
                verdict = ("unknown", "sa_swap_lifecycle_permission_or_future_stop_unresolved")
            elif any(grant != "derived" for grant in (actas, change, start, stop)):
                verdict = ("unknown", "sa_swap_iam_condition_unresolved")
            else:
                metadata = all(_scope_grant(model, source, action, resource) == "derived" for action in
                               ("compute.instances.get", "compute.instances.setMetadata"))
                route = "metadata" if metadata else _login_path(model, source, project, vm, resource)
                verdict = (None if route in ("metadata", "login") else
                           ("unknown", "sa_swap_execution_or_login_unresolved"))
            if verdict is None or tid not in result:
                result[tid] = verdict
    return result
