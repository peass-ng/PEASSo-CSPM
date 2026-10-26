"""Bind policy-orchestrator writes to their actual parent and eligible VMs."""

from __future__ import annotations

import re
from collections import Counter

from . import ANY, inventory_status, items
from .gcp_osconfig_guest_policy import _vm_verdict
from .gcp_osconfig_index import memo
from .gcp_osconfig_os_policy_assignment import _attached_vms


def _parents(model, project):
    result = []
    for parent in model.ancestors(project):
        if re.fullmatch(r"(?:projects/[^/]+|folders/[1-9][0-9]*|organizations/[1-9][0-9]*)", parent):
            location = parent + "/locations/global"
            model.parents.setdefault(location, parent)
            result.append((parent, location))
    return result


def _known(model, parent):
    known = memo(model, "orchestrators", parent, lambda: _known_uncached(model, parent))
    return None if known is None else list(known)


def _known_uncached(model, parent):
    status = {model._norm_scope(scope): value for scope, value in
              inventory_status(model.snapshot, "osconfig_policy_orchestrator").items()}.get(parent)
    if status not in ("collected", "empty"):
        return None
    names = []
    prefix = parent + "/locations/global/policyOrchestrators/"
    for scope, row in items(model.snapshot, "osconfig_policy_orchestrator"):
        if model._norm_scope(scope) != parent:
            continue
        name = model._norm_scope(row.get("name"))
        if not re.fullmatch(re.escape(prefix) + r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", name):
            return None
        names.append(name)
    if status == "empty" and names or len(names) != len(set(names)):
        return None
    return sorted(names)


def resources(model, project, *, orchestrators):
    parents = _parents(model, project)
    if not parents:
        return None
    if not orchestrators:
        return [location for _, location in parents]
    names = []
    for parent, _ in parents:
        known = _known(model, parent)
        if known is not None:
            names.extend(known)
    return sorted(names) if names else None


def _service_agents(model, parent):
    return memo(model, "service_agents", parent, lambda: _service_agents_uncached(model, parent))


def _service_agents_uncached(model, parent):
    status = {model._norm_scope(scope): value for scope, value in
              inventory_status(model.snapshot, "iam_policy").items()}
    if status.get(parent) not in ("collected", "empty"):
        return ("unknown", "orchestrator_parent_iam_unresolved")
    number = parent.split("/", 1)[1]
    if parent.startswith("projects/"):
        projects = [row for scope, row in items(model.snapshot, "project")
                    if model._norm_scope(scope) == parent]
        if len(projects) != 1:
            return ("unknown", "orchestrator_project_identity_unresolved")
        number = str(projects[0].get("name") or "").rsplit("/", 1)[-1]
        if not number.isdecimal():
            return ("unknown", "orchestrator_project_number_unresolved")
        prefix = "service-"
    else:
        prefix = "service-folder-" if parent.startswith("folders/") else "service-org-"
    required = {
        ("serviceAccount:" + prefix + number + "@gcp-sa-osconfig.iam.gserviceaccount.com",
         "roles/osconfig.serviceAgent"),
        ("serviceAccount:" + prefix + number + "@gcp-sa-osconfig-rollout.iam.gserviceaccount.com",
         "roles/osconfig.rolloutServiceAgent"),
        ("serviceAccount:" + prefix + number + "@gcp-sa-progrollout.iam.gserviceaccount.com",
         "roles/progressiverollout.serviceAgent"),
    }
    observed = set()
    for scope, policy in items(model.snapshot, "iam_policy"):
        if model._norm_scope(policy.get("name") or scope) != parent:
            continue
        for binding in policy.get("bindings") or []:
            if not isinstance(binding, dict) or binding.get("condition"):
                continue
            for member in binding.get("members") or []:
                observed.add((member, binding.get("role")))
    if not required <= observed:
        return ("unknown", "orchestrator_service_agent_roles_unresolved")
    return None


def _project_apis(model, parent):
    return memo(model, "project_apis", parent, lambda: _project_apis_uncached(model, parent))


def _project_apis_uncached(model, parent):
    if not parent.startswith("projects/"):
        return ("unknown", "orchestrator_quota_project_unresolved")
    status = {model._norm_scope(scope): value for scope, value in
              inventory_status(model.snapshot, "service_usage").items()}
    if status.get(parent) not in ("collected", "empty"):
        return ("unknown", "orchestrator_api_state_unresolved")
    enabled = {model._norm_scope(row.get("name")) for scope, row in
               items(model.snapshot, "service_usage") if model._norm_scope(scope) == parent
               and row.get("state") == "ENABLED"}
    if not {parent + "/services/osconfig.googleapis.com",
            parent + "/services/progressiverollout.googleapis.com"} <= enabled:
        return ("unknown", "orchestrator_required_api_unresolved")
    return None


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    out = {}
    writes, verdicts = {}, {}  # one source per call: its writes and VM verdicts do not depend on the target
    for tid, target in candidates.items():
        project = target.scope
        vms = list(_attached_vms(model, target))
        counts = Counter(resource for _, resource, _ in vms if resource)
        unresolved = None
        for parent, location in _parents(model, project):
            if (parent, location) not in writes:
                create = model.check(source, {"action": "osconfig.policyOrchestrators.create"}, location)
                known = _known(model, parent)
                updates = [] if known is None else [grant for name in known
                    if (grant := model.check(source, {"action": "osconfig.policyOrchestrators.update"}, name))]
                possible = (model.check(source, {"action": "osconfig.policyOrchestrators.update"}, ANY)
                            if known is None else None)
                writes[(parent, location)] = (create, updates, possible)
            create, updates, possible = writes[(parent, location)]
            if create is None and not updates and possible is None:
                continue
            agent_state = _service_agents(model, parent)
            api_state = _project_apis(model, parent)
            for vm, resource, _ in vms:
                if resource is None or counts[resource] != 1:
                    unresolved = ("unknown", "orchestrator_vm_identity_ambiguous")
                    continue
                vm_key = (project, id(vm), resource)
                if vm_key not in verdicts:
                    verdicts[vm_key] = _vm_verdict(model, project, vm, resource, source,
                                                   feature="tasks", require_ga=True)
                state = verdicts[vm_key]
                if state == "disabled":
                    continue
                if (state is None and agent_state is None and api_state is None and
                    any(grant.confidence == "derived" for grant in
                        ([create] if create else []) + updates)):
                    out[tid] = None
                    break
                unresolved = next((x for x in (state, agent_state, api_state)
                                   if isinstance(x, tuple)),
                                  ("unknown", "orchestrator_write_or_inventory_unresolved"))
            if tid in out:
                break
        if tid not in out and unresolved is not None:
            out[tid] = unresolved
    return out
