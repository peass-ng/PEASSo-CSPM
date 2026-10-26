"""Bind legacy guest-policy writes to an exact VM and attached identity."""

from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timedelta, timezone

from . import ANY, inventory_status, items
from .gcp_oslogin import _vm_resource
from .gcp_osconfig_index import memo, rows_in


def policy_resources(model, project):
    """Return exact project policy names, or None when the list is incomplete."""
    names = memo(model, "guest_policies", project, lambda: _policy_resources_uncached(model, project))
    return None if names is None else list(names)


def _policy_resources_uncached(model, project):
    status = inventory_status(model.snapshot, "osconfig_guest_policy").get(project)
    if status not in ("collected", "empty"):
        return None
    names = []
    for scope, row in items(model.snapshot, "osconfig_guest_policy"):
        if model._norm_scope(scope) != project:
            continue
        name = model._norm_scope(row.get("name"))
        if not re.fullmatch(re.escape(project) + r"/guestPolicies/[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", name):
            return None
        names.append(name)
    if status == "empty" and names:
        return None
    return sorted(names) if len(set(names)) == len(names) else None


def _metadata_flag(metadata):
    if not isinstance(metadata, dict) or not isinstance(metadata.get("items"), list):
        return None
    values = [str(row.get("value", "")).lower() for row in metadata["items"]
              if isinstance(row, dict) and row.get("key") == "enable-osconfig"]
    if not values:
        return None
    return values[0] == "true" if len(values) == 1 and values[0] in ("true", "false") else "invalid"


def _disabled_features(metadata):
    if not isinstance(metadata, dict) or not isinstance(metadata.get("items"), list):
        return None
    values = [row.get("value") for row in metadata["items"]
              if isinstance(row, dict) and row.get("key") == "osconfig-disabled-features"]
    if not values:
        return None
    if len(values) != 1 or not isinstance(values[0], str):
        return "invalid"
    features = [part.strip().lower() for part in values[0].split(",") if part.strip()]
    return set(features)


def _time(value):
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        return None


def _agent_inventory(model, project, vm, resource):
    if inventory_status(model.snapshot, "os_inventory").get(project) not in ("collected", "empty"):
        return None
    zone = resource.split("/zones/", 1)[-1].split("/", 1)[0]
    number = str(vm.get("id") or "")
    if not number.isdecimal():
        return None
    suffix = f"/locations/{zone}/instances/{number}/inventory"
    matches = [row for scope, row in rows_in(model, "os_inventory", project)
               if row.get("instanceName") == vm.get("name")
               and isinstance(row.get("name"), str) and row["name"].endswith(suffix)
               and model._norm_scope(row["name"].split("/locations/", 1)[0]) == project]
    if len(matches) != 1:
        return None
    captured = (_time((matches[0].get("_provenance") or {}).get("collected_at"))
                or _time(model.snapshot.get("created_at")))
    if captured is None:
        return None
    updated = _time(matches[0].get("updateTime"))
    return matches[0] if updated is not None and timedelta(0) <= captured - updated <= timedelta(hours=2) else None


def _vm_verdict(model, project, vm, resource, source, *, feature="guestpolicies", require_ga=False):
    if inventory_status(model.snapshot, "instance").get(project) not in ("collected", "empty"):
        return ("unknown", "osconfig_vm_inventory_incomplete")
    if vm.get("status") != "RUNNING":
        return ("unknown", "osconfig_vm_not_running")
    projects = [row for scope, row in rows_in(model, "project", project)]
    if len(projects) != 1:
        return ("unknown", "osconfig_project_metadata_incomplete")
    instance_flag = _metadata_flag(vm.get("metadata"))
    project_flag = _metadata_flag(projects[0].get("commonInstanceMetadata"))
    enabled = instance_flag if instance_flag is not None else project_flag
    if enabled is False:
        # A distinct metadata-write path may enable the agent later; the
        # guest-policy permission by itself cannot override this setting.
        return ("unknown", "osconfig_agent_explicitly_disabled") if model.check(
            source, {"action": "compute.instances.setMetadata"}, resource) else "disabled"
    if enabled is not True:
        return ("unknown", "osconfig_agent_enablement_unresolved")
    instance_disabled = _disabled_features(vm.get("metadata"))
    project_disabled = _disabled_features(projects[0].get("commonInstanceMetadata"))
    disabled = instance_disabled if instance_disabled is not None else project_disabled
    if disabled == "invalid":
        return ("unknown", "osconfig_disabled_features_unresolved")
    if isinstance(disabled, set) and feature in disabled:
        return ("unknown", "osconfig_required_feature_disabled") if model.check(
            source, {"action": "compute.instances.setMetadata"}, resource) else "disabled"
    settings = [row for scope, row in rows_in(model, "osconfig_project_feature_settings", project)]
    if (inventory_status(model.snapshot, "osconfig_project_feature_settings").get(project)
            not in ("collected", "empty") or len(settings) != 1
            or settings[0].get("name") != project + "/locations/global/projectFeatureSettings"
            or settings[0].get("patchAndConfigFeatureSet") != "OSCONFIG_C"):
        return ("unknown", "osconfig_full_feature_set_unresolved")
    inventory = _agent_inventory(model, project, vm, resource)
    if inventory is None:
        return ("unknown", "osconfig_agent_heartbeat_unresolved")
    if require_ga:
        version = (inventory.get("osInfo") or {}).get("osconfigAgentVersion")
        match = re.match(r"^(\d{8})(?:[.\-+]|$)", version) if isinstance(version, str) else None
        if not match or int(match[1]) < 20210427:
            return ("unknown", "osconfig_ga_agent_version_unresolved")
    accounts = [row for row in vm.get("serviceAccounts") or []
                if isinstance(row, dict) and isinstance(row.get("email"), str)]
    if len(accounts) != 1:
        return ("unknown", "osconfig_vm_service_account_ambiguous")
    scopes = accounts[0].get("scopes")
    if not isinstance(scopes, list) or "https://www.googleapis.com/auth/cloud-platform" not in scopes:
        return ("unknown", "osconfig_vm_oauth_scopes_limit_access")
    return None


def selector(model, value, candidates, source):
    if value is not True or source is None:
        return {}
    rows = []
    for scope, vm in items(model.snapshot, "instance"):
        project = model._norm_scope(scope)
        resource = _vm_resource(model, vm, project)
        rows.append((project, resource, vm))
    counts = Counter(resource for _, resource, _ in rows if resource)
    out = {}
    for tid, target in candidates.items():
        project = target.scope
        policies = policy_resources(model, project)
        create = model.check(source, {"action": "osconfig.guestPolicies.create"}, project)
        update = (model.check(source, {"action": "osconfig.guestPolicies.update"}, ANY)
                  if policies is None else next((grant for name in policies
                      if (grant := model.check(source, {"action": "osconfig.guestPolicies.update"}, name))
                      is not None), None))
        if create is None and update is None:
            continue
        unresolved = None
        success = False
        for vm_project, resource, vm in rows:
            if vm_project != project:
                continue
            if not any(isinstance(account, dict) and account.get("email") == target.attrs.get("email")
                       for account in vm.get("serviceAccounts") or []):
                continue
            if resource is None or counts[resource] != 1:
                unresolved = ("unknown", "osconfig_vm_identity_ambiguous")
                continue
            vm_state = _vm_verdict(model, project, vm, resource, source)
            if vm_state == "disabled":
                continue
            if create is not None and create.confidence == "derived" and vm_state is None:
                success = True
                break
            unresolved = (vm_state if isinstance(vm_state, tuple) else
                          ("unknown", "osconfig_guest_policy_update_recipe_state_unresolved")
                          if update is not None else
                          ("unknown", "osconfig_guest_policy_create_permission_unresolved"))
        if success:
            out[tid] = None
        elif unresolved is not None:
            out[tid] = unresolved
    return out
