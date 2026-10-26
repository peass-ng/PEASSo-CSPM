"""Bind Automation identity attachment to an executable account and runbook."""
from __future__ import annotations

import re

from . import as_list, inventory_status, items


ACCOUNT_TYPE = "microsoft.automation/automationaccounts"
ACCOUNT_ID = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.automation/automationaccounts/[^/]+")
GROUP_ID = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+")
RUNBOOK_TYPE = ACCOUNT_TYPE + "/runbooks"


def pivots(model):
    accounts = {rid for rid, resource in model.resources.items()
                if resource.get("type") == ACCOUNT_TYPE and ACCOUNT_ID.fullmatch(rid)}
    groups = {str(item.get("id") or "").lower() for _, item in items(model.snapshot, "resource_group")}
    for group in groups:
        if GROUP_ID.fullmatch(group):
            prefix = group + "/providers/microsoft.automation/automationaccounts/"
            name, suffix = "peassprobe", 0
            while prefix + name in model.resources:
                suffix += 1
                name = "peassprobe" + str(suffix)
            accounts.add(prefix + name)
    if accounts:
        return [{"pivot": rid, "created": rid not in model.resources} for rid in sorted(accounts)]
    statuses = [inventory_status(model.snapshot, kind) for kind in ("automation_account", "resource_graph", "resource_group")]
    if not statuses[0] and not statuses[1] or not statuses[2]:
        return None
    if any(state not in ("collected", "empty") for group in statuses for state in group.values()):
        return None
    return []


def _check(model, source, action, scope):
    return model.cached_check(source, {"action": "Microsoft.Automation/automationAccounts/" + action}, scope)


def _path(model, source, checks):
    grants = [_check(model, source, action, scope) for action, scope in checks]
    if any(grant is None for grant in grants):
        return None
    if any(grant.confidence == "unknown" for grant in grants):
        return "unknown"
    if any(grant.confidence == "conditional" for grant in grants):
        return "conditional"
    return "derived"


def _child_scopes(model, source, account, child_type):
    prefix = account + "/" + child_type + "/"
    return {str(assignment["scope"]).lower() for pid in [source.id, *source.attrs.get("groups", ())]
            for assignment in model.assignments.get(pid, ())
            if str(assignment["scope"]).lower().startswith(prefix)
            and "/" not in str(assignment["scope"])[len(prefix):]}


def _runbook_index(model):
    """Runbook resource ids in model.resources order: ({account: ids with exactly one "/runbooks/"}, [other ids]).
    model.resources is fixed after _load."""
    index = model.__dict__.get("_automation_runbook_index") if hasattr(model, "__dict__") else None
    if index is None:
        single, nested = {}, []
        for rid, resource in model.resources.items():
            if resource.get("type") != RUNBOOK_TYPE:
                continue
            if rid.count("/runbooks/") == 1:
                single.setdefault(rid.partition("/runbooks/")[0], []).append(rid)
            else:
                nested.append(rid)
        index = (single, nested)
        if hasattr(model, "__dict__"):
            model.__dict__["_automation_runbook_index"] = index
    return index


def execution_paths(model, source, account, created=False):
    paths = []
    missing_runbook_inventory = False
    prefix = account + "/runbooks/"
    name, suffix = "peassprobe", 0
    while prefix + name in model.resources:
        suffix += 1
        name = "peassprobe" + str(suffix)
    runbooks = {prefix + name} | _child_scopes(model, source, account, "runbooks")
    jobs = {account + "/jobs/peassprobe"} | _child_scopes(model, source, account, "jobs")
    for runbook in sorted(runbooks):
        if runbook in model.resources:
            continue
        for job in sorted(jobs):
            paths.append((created, _path(model, source, [
                ("runbooks/write", runbook), ("runbooks/draft/content/write", runbook),
                ("runbooks/publish/action", runbook), ("jobs/write", job)])))
    single, nested = _runbook_index(model)
    if not single.get(account) and not any(rid.startswith(prefix) for rid in nested):
        if any(_check(model, source, "runbooks/draft/write", runbook) is not None
               and _check(model, source, "runbooks/draft/content/write", runbook) is not None
               for runbook in runbooks):
            missing_runbook_inventory = True
    for rid in single.get(account, ()):
        content = [("runbooks/draft/write", rid), ("runbooks/draft/content/write", rid)]
        for job in sorted(jobs):
            paths.append((created, _path(model, source, content + [
                ("runbooks/publish/action", rid), ("jobs/write", job)])))
        paths.append((created, _path(model, source, content + [
            ("runbooks/draft/testJob/write", rid + "/draft/testJob")])))
    return paths, missing_runbook_inventory


def select(model, candidates, source, pivot):
    if source is None:
        return {}
    supplied = {str(item.get("pivot") or "").lower(): bool(item.get("created"))
                for item in as_list(pivot) if isinstance(item, dict)}
    known = {item["pivot"]: bool(item["created"]) for item in pivots(model) or ()}
    paths = []
    missing_runbook_inventory = False
    for account, created in supplied.items():
        if account not in known or created != known[account] or not ACCOUNT_ID.fullmatch(account):
            continue
        route_paths, missing = execution_paths(model, source, account, created)
        paths.extend(route_paths)
        missing_runbook_inventory |= missing
    possible = ["conditional" if created and verdict == "derived" else verdict
                for created, verdict in paths if verdict]
    if "derived" in possible:
        return {tid: None for tid in candidates}
    if "conditional" in possible:
        return {tid: ("conditional", "automation_account_or_runbook_condition") for tid in candidates}
    if "unknown" in possible or missing_runbook_inventory or not supplied or not known:
        return {tid: ("unknown", "automation_account_or_runbook_unverified") for tid in candidates}
    return {}


def select_attached_identity(model, candidates, source):
    if source is None:
        return {}
    result = {}
    for tid, target in candidates.items():
        accounts = {str(host).lower() for host in target.attrs.get("hosts", ())
                    if ACCOUNT_ID.fullmatch(str(host).lower())
                    and model.resources.get(str(host).lower(), {}).get("type") == ACCOUNT_TYPE}
        paths = []
        missing = False
        for account in sorted(accounts):
            found, unresolved = execution_paths(model, source, account)
            paths.extend(found)
            missing |= unresolved
        confidence = {verdict for _, verdict in paths if verdict}
        if "derived" in confidence:
            result[tid] = None
        elif "conditional" in confidence:
            result[tid] = ("conditional", "automation_runbook_execution_condition")
        elif ("unknown" in confidence or missing or
              (not accounts and (target.attrs.get("hosts") or not all(
                  status and all(value in ("collected", "empty") for value in status.values())
                  for status in (inventory_status(model.snapshot, "automation_account"),
                                 inventory_status(model.snapshot, "resource_graph")))))):
            result[tid] = ("unknown", "automation_account_or_runbook_unverified")
    return result


def select_hybrid_worker(model, candidates, source):
    """Require a runnable path and a linked worker on the same Automation account."""
    if source is None:
        return {}
    result = {}
    accounts = {rid for rid, resource in model.resources.items()
                if resource.get("type") == ACCOUNT_TYPE and ACCOUNT_ID.fullmatch(rid)}
    for account in sorted(accounts):
        if not ACCOUNT_ID.fullmatch(account) or model.resources.get(account, {}).get("type") != ACCOUNT_TYPE:
            continue
        linked = model._host_linked("automation_hybrid_worker", candidates, [account])
        account_has_identity = any(account in node.attrs.get("hosts", ())
                                   for node in model.principals.values()
                                   if node.kind == "azure_managed_identity")
        paths, missing = execution_paths(model, source, account)
        verdicts = {verdict for _, verdict in paths if verdict}
        path = ("conditional" if "derived" in verdicts or "conditional" in verdicts else
                "unknown" if "unknown" in verdicts or missing else None)
        for tid, link in linked.items():
            if path is None:
                continue
            if account_has_identity and any(
                    model.resources.get(host, {}).get("type") == "microsoft.hybridcompute/machines"
                    for host in candidates[tid].attrs.get("hosts", ())):
                continue
            state = "unknown" if (link and link[0] == "unknown") or path == "unknown" else "conditional"
            previous = result.get(tid)
            if previous and previous[0] == "conditional":
                continue
            result[tid] = (state, "hybrid_worker_execution_or_link_unverified")
    return result
