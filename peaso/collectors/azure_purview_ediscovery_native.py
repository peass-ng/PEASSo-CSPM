"""Read-only, identifier-only Microsoft Purview eDiscovery case membership."""
from __future__ import annotations

import re

GRAPH = "https://graph.microsoft.com"
CASES = "purview_ediscovery_case"
MEMBERS = "purview_ediscovery_case_member"
KINDS = (CASES, MEMBERS)
GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)


def _guid(value):
    if not isinstance(value, str) or GUID.fullmatch(value) is None:
        raise ValueError("malformed eDiscovery identifier")
    return value.lower()


def collect(reader, request, wanted, tenant_scope):
    if not set(KINDS).intersection(wanted):
        return
    url = GRAPH + "/v1.0/security/cases/ediscoveryCases"

    def cases():
        seen = set()
        for page in reader.pages(request, url, audience=GRAPH, next_key="@odata.nextLink"):
            output = []
            for raw in page:
                cid = _guid(raw.get("id"))
                if cid in seen:
                    raise ValueError("duplicate eDiscovery case")
                seen.add(cid)
                status = raw.get("status")
                if not isinstance(status, str):
                    raise ValueError("eDiscovery case status missing")
                output.append({"id": cid, "status": status})
            yield output

    reader.run([(CASES, tenant_scope, "Microsoft.Graph eDiscovery", cases)])
    if MEMBERS not in wanted:
        return
    jobs = []
    for parent in [row for row in reader.collections if row["type"] == CASES]:
        if parent["status"] not in ("collected", "empty"):
            reader.collections.append({"type": MEMBERS, "scope": parent["scope"],
                                       "service": "Microsoft.Graph eDiscovery", "status": parent["status"],
                                       "items": [], "error": {"code": "case_inventory_incomplete"}})
            continue
        for case in parent["items"]:
            cid = _guid(case["id"])
            member_url = url + "/" + cid + "/caseMembers"

            def members(member_url=member_url, cid=cid, status=case["status"]):
                seen = set()
                for page in reader.pages(request, member_url, audience=GRAPH, next_key="@odata.nextLink"):
                    output = []
                    for raw in page:
                        mid = _guid(raw.get("id"))
                        if mid in seen:
                            raise ValueError("duplicate eDiscovery case member")
                        seen.add(mid)
                        member_type = raw.get("recipientType")
                        if member_type not in ("user", "roleGroup", "unknownFutureValue"):
                            raise ValueError("eDiscovery member type unavailable")
                        output.append({"id": cid + "/caseMembers/" + mid, "case_id": cid,
                                       "member_id": mid, "recipient_type": member_type,
                                       "case_status": status})
                    yield output

            jobs.append((MEMBERS, tenant_scope + "/ediscoveryCases/" + cid,
                         "Microsoft.Graph eDiscovery", members))
        if not parent["items"]:
            reader.collections.append({"type": MEMBERS, "scope": tenant_scope,
                                       "service": "Microsoft.Graph eDiscovery", "status": "empty",
                                       "items": [], "parent_inventory": CASES})
    reader.run(jobs)
