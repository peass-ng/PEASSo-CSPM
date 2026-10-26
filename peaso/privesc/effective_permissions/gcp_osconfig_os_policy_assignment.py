"""Match zonal OS policy assignment writes to an active VM and its service account."""

from __future__ import annotations

import re
from collections import Counter

from . import ANY, inventory_status, items
from .gcp_osconfig_guest_policy import _vm_verdict
from .gcp_oslogin import _vm_resource
from .gcp_osconfig_index import memo, rows_in


def _attached_vms(model, target):
    for scope, vm in rows_in(model, "instance", target.scope):
        if any(isinstance(sa, dict) and sa.get("email") == target.attrs.get("email")
               for sa in vm.get("serviceAccounts") or []):
            resource = _vm_resource(model, vm, target.scope)
            match = re.fullmatch(re.escape(target.scope) + r"/zones/([^/]+)/instances/[^/]+",
                                 resource) if isinstance(resource, str) else None
            yield vm, resource, (target.scope + "/locations/" + match[1]) if match else None


def _assignment_names(model, project, zone):
    names = memo(model, "assignments", (project, zone), lambda: _assignment_names_uncached(model, project, zone))
    return None if names is None else list(names)


def _assignment_names_uncached(model, project, zone):
    status = inventory_status(model.snapshot, "osconfig_os_policy_assignment").get(project)
    if status not in ("collected", "empty"):
        return None
    names = []
    for scope, row in items(model.snapshot, "osconfig_os_policy_assignment"):
        if model._norm_scope(scope) != project:
            continue
        name = model._norm_scope(row.get("name"))
        if not re.fullmatch(re.escape(project) + r"/locations/[^/]+/osPolicyAssignments/[^/]+", name):
            return None
        if name.startswith(zone + "/osPolicyAssignments/"):
            names.append(name)
    if status == "empty" and names or len(set(names)) != len(names):
        return None
    return sorted(names)


def resources(model, target, *, assignments):
    if inventory_status(model.snapshot, "instance").get(target.scope) not in ("collected", "empty"):
        return None
    zones = {zone for _, _, zone in _attached_vms(model, target) if zone}
    if not zones:
        return None
    if not assignments:
        return sorted(zones)
    names = []
    for zone in sorted(zones):
        known = _assignment_names(model, target.scope, zone)
        if known is None:
            return None
        prospective = zone + "/osPolicyAssignments/cspm-prospective"
        model.parents.setdefault(prospective, zone)
        names.extend(known)
        names.append(prospective)
    return sorted(set(names))


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    out = {}
    for tid, target in candidates.items():
        vms = list(_attached_vms(model, target))
        counts = Counter(resource for _, resource, _ in vms if resource)
        unresolved = None
        for vm, resource, zone in vms:
            if resource is None or zone is None or counts[resource] != 1:
                unresolved = ("unknown", "osconfig_vm_identity_ambiguous")
                continue
            state = _vm_verdict(model, target.scope, vm, resource, source,
                                feature="tasks", require_ga=True)
            if state == "disabled":
                continue
            create = model.check(source, {"action": "osconfig.osPolicyAssignments.create"}, zone)
            names = _assignment_names(model, target.scope, zone)
            if names is None:
                update = model.check(source, {"action": "osconfig.osPolicyAssignments.update"}, ANY)
            else:
                prospective = zone + "/osPolicyAssignments/cspm-prospective"
                model.parents.setdefault(prospective, zone)
                update = next((grant for name in [*names, prospective]
                               if (grant := model.check(source,
                                  {"action": "osconfig.osPolicyAssignments.update"}, name)) is not None), None)
            possible_update = model.check(source, {"action": "osconfig.osPolicyAssignments.update"}, ANY)
            if (state is None and any(grant is not None and grant.confidence == "derived"
                                      for grant in (create, update))):
                out[tid] = None
                break
            if create is not None or update is not None or possible_update is not None:
                unresolved = state if isinstance(state, tuple) else (
                    "unknown", "osconfig_assignment_permission_or_runtime_unresolved")
        else:
            if unresolved is not None:
                out[tid] = unresolved
    return out
