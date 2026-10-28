"""Read-only, principal-only projection of classic Purview Data Map policies."""
from __future__ import annotations

import re

KIND = "purview_metadata_policy"
AUDIENCE = "https://purview.azure.net"
VERSION = "2021-07-01-preview"
_ACCOUNT = re.compile(r"^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft\.Purview/accounts/([a-zA-Z0-9-]{3,63})$", re.I)
_GUID = re.compile(r"^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$", re.I)


def _principals(rule):
    """Project only direct object IDs; conditional expressions stay unresolved."""
    result = {"ids": [], "groups": [], "conditional": False}
    conditions = rule.get("dnfCondition")
    if not isinstance(conditions, list):
        raise ValueError("Purview role conditions missing")
    for conjunction in conditions:
        if not isinstance(conjunction, list):
            raise ValueError("Purview role conjunction malformed")
        for condition in conjunction:
            if not isinstance(condition, dict):
                raise ValueError("Purview role condition malformed")
            attr = condition.get("attributeName")
            if attr not in ("principal.microsoft.id", "principal.microsoft.groups"):
                if attr != "derived.purview.role":
                    result["conditional"] = True
                continue
            values = condition.get("attributeValueIncludedIn")
            if not isinstance(values, list) or any(not isinstance(v, str) or not _GUID.fullmatch(v) for v in values):
                raise ValueError("Purview principal IDs malformed")
            target = "ids" if attr.endswith(".id") else "groups"
            result[target].extend(v.lower() for v in values)
    result["ids"] = sorted(set(result["ids"]))
    result["groups"] = sorted(set(result["groups"]))
    return result


def collect(reader, request, transport, wanted):
    if KIND not in wanted:
        return
    jobs = []
    for parent in [row for row in reader.collections if row["type"] == "purview_account"]:
        if parent["status"] not in ("collected", "empty"):
            reader.collections.append({"type": KIND, "scope": parent["scope"], "service": "Purview Data Map",
                                       "status": parent["status"], "items": [], "error": {"code": "parent_incomplete"}})
            continue
        for account in parent["items"]:
            rid = account.get("id")
            match = _ACCOUNT.fullmatch(rid) if isinstance(rid, str) else None
            if match is None:
                reader.collections.append({"type": KIND, "scope": rid or parent["scope"], "service": "Purview Data Map",
                                           "status": "not_collected", "items": [], "error": {"code": "account_endpoint_unresolved"}})
                continue
            name = match.group(1)
            if hasattr(transport, "allow_purview"):
                transport.allow_purview(name)
            endpoint = f"https://{name.lower()}.purview.azure.com/policyStore/metadataPolicies?api-version={VERSION}"

            def pages(endpoint=endpoint, rid=rid):
                seen = set()
                for page in reader.pages(request, endpoint, audience=AUDIENCE, key="values"):
                    projected = []
                    for raw in page:
                        policy_id = raw.get("id") if isinstance(raw, dict) else None
                        if not isinstance(policy_id, str) or not _GUID.fullmatch(policy_id) or policy_id.lower() in seen:
                            raise ValueError("Purview policy identity missing or duplicate")
                        seen.add(policy_id.lower())
                        props = raw.get("properties")
                        if not isinstance(props, dict) or not isinstance(props.get("attributeRules"), list):
                            raise ValueError("Purview attribute rules missing")
                        collection = props.get("collection")
                        reference = collection.get("referenceName") if isinstance(collection, dict) else None
                        if not isinstance(reference, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", reference):
                            raise ValueError("Purview collection identity missing")
                        roles = []
                        for rule in props["attributeRules"]:
                            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
                                raise ValueError("Purview role missing")
                            role_id = rule["id"]
                            if not re.fullmatch(r"[A-Za-z0-9_-]+:[A-Za-z0-9_-]+", role_id):
                                raise ValueError("Purview role identity malformed")
                            roles.append({"role": role_id.split(":", 1)[0], **_principals(rule)})
                        projected.append({"id": rid + "/metadataPolicies/" + policy_id.lower(),
                                          "account_id": rid, "collection": reference, "roles": roles})
                    yield projected

            jobs.append((KIND, rid, "Purview Data Map", pages))
        if not parent["items"]:
            reader.collections.append({"type": KIND, "scope": parent["scope"], "service": "Purview Data Map",
                                       "status": "empty", "items": [], "parent_inventory": "purview_account"})
    reader.run(jobs)
