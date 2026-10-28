"""Read-only Azure Lighthouse registration assignments with expanded definitions."""
from __future__ import annotations

import re


ARM = "https://management.azure.com"
VERSION = "2022-10-01"
KIND = "lighthouse_delegation"
SERVICE = "Microsoft.ManagedServices"
UUID = r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"


def _guid(value):
    return isinstance(value, str) and re.fullmatch(UUID, value) is not None


def _roles(rows):
    if not isinstance(rows, list):
        raise ValueError("Lighthouse authorization list missing")
    safe = []
    for row in rows:
        if (not isinstance(row, dict) or not _guid(row.get("principalId"))
                or not _guid(row.get("roleDefinitionId"))):
            raise ValueError("malformed Lighthouse authorization")
        delegated = row.get("delegatedRoleDefinitionIds") or []
        if not isinstance(delegated, list) or any(not _guid(value) for value in delegated):
            raise ValueError("malformed delegated role IDs")
        safe.append({"principalId": row["principalId"], "roleDefinitionId": row["roleDefinitionId"],
                     "delegatedRoleDefinitionIds": delegated})
    return safe


def _assignment(row, scope):
    rid = row.get("id") if isinstance(row, dict) else None
    props = row.get("properties") if isinstance(row, dict) else None
    if (not isinstance(rid, str) or re.fullmatch(re.escape(scope) + r"/providers/Microsoft\.ManagedServices/registrationAssignments/" + UUID, rid, re.I) is None
            or str(row.get("type", "")).casefold() != (SERVICE + "/registrationAssignments").casefold()
            or not isinstance(props, dict)):
        raise ValueError("foreign or malformed Lighthouse assignment")
    definition_id = props.get("registrationDefinitionId")
    subscription = re.match(r"/subscriptions/([^/]+)", scope, re.I)
    if (subscription is None or not isinstance(definition_id, str) or re.fullmatch(
            r"/subscriptions/" + re.escape(subscription.group(1)) + r"/providers/Microsoft\.ManagedServices/registrationDefinitions/" + UUID,
            definition_id, re.I) is None):
        raise ValueError("Lighthouse assignment references foreign definition")
    safe = {"id": rid, "name": row.get("name"), "type": SERVICE + "/registrationAssignments",
            "scope": scope, "properties": {"registrationDefinitionId": definition_id,
                                           "provisioningState": props.get("provisioningState")}}
    definition = props.get("registrationDefinition")
    if not isinstance(definition, dict) or str(definition.get("id", "")).casefold() != definition_id.casefold():
        safe["_coverage"] = {"registrationDefinition": {"status": "unknown"}}
        return safe
    details = definition.get("properties")
    if not isinstance(details, dict) or not _guid(details.get("managedByTenantId")) or not _guid(details.get("manageeTenantId")):
        safe["_coverage"] = {"registrationDefinition": {"status": "unknown"}}
        return safe
    try:
        active = _roles(details.get("authorizations"))
        eligible = _roles(details.get("eligibleAuthorizations") or [])
    except ValueError:
        safe["_coverage"] = {"registrationDefinition": {"status": "malformed"}}
        return safe
    safe["properties"]["registrationDefinition"] = {
        "managedByTenantId": details["managedByTenantId"], "manageeTenantId": details["manageeTenantId"],
        "provisioningState": details.get("provisioningState"),
        "authorizations": active, "eligibleAuthorizations": eligible}
    safe["_coverage"] = {"registrationDefinition": {"status": "collected"}}
    return safe


def collect(reader, request, scopes, wanted):
    if KIND not in wanted:
        return
    group_inventory = {c.get("scope", "").casefold(): c for c in reader.collections if c.get("type") == "resource_group"}
    for subscription in scopes:
        group_collection = group_inventory.get(subscription.casefold())
        targets = [subscription]
        groups_valid = bool(group_collection and group_collection.get("status") in ("collected", "empty"))
        if groups_valid:
            for group in group_collection.get("items", []):
                rid = group.get("id") if isinstance(group, dict) else None
                if (not isinstance(rid, str) or re.fullmatch(
                        re.escape(subscription) + r"/resourceGroups/[^/?#%\\\s]+", rid, re.I) is None):
                    groups_valid = False
                    continue
                targets.append(rid)
        for scope in targets:
            url = ARM + scope + "/providers/Microsoft.ManagedServices/registrationAssignments?api-version=" + VERSION + "&$expandRegistrationDefinition=true"
            def fetch(scope=scope, url=url):
                seen = set()
                for page in reader.pages(request, url):
                    projected = []
                    for row in page:
                        item = _assignment(row, scope)
                        if item["id"].casefold() in seen:
                            raise ValueError("duplicate Lighthouse assignment")
                        seen.add(item["id"].casefold())
                        projected.append(item)
                    yield projected
            reader.collections.append(reader._read((KIND, scope, SERVICE, fetch)))
        if not groups_valid:
            # Subscription assignments remain useful, but RG discovery is not complete.
            for collection in reader.collections:
                if collection.get("type") == KIND and collection.get("scope") == subscription:
                    collection["resource_group_scope_coverage"] = "unknown"
