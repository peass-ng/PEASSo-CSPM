"""Read-only, bounded Graph cross-tenant access policy inventory."""

import re


GRAPH = "https://graph.microsoft.com"
DEFAULT = "external_id_cross_tenant_default"
PARTNER = "external_id_cross_tenant_partner"
KINDS = frozenset((DEFAULT, PARTNER))
GUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", re.I)


def _setting(value):
    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("cross-tenant B2B setting malformed")
    output = {}
    for key in ("usersAndGroups", "applications"):
        part = value.get(key)
        if part is None:
            output[key] = None
            continue
        if not isinstance(part, dict) or not isinstance(part.get("targets"), list):
            raise ValueError("cross-tenant B2B target malformed")
        output[key] = {"accessType": part.get("accessType"),
                       "targets": [{"target": target.get("target"),
                                    "targetType": target.get("targetType")}
                                   for target in part["targets"] if isinstance(target, dict)]}
    return output


def project(kind, row, tenant):
    if kind not in KINDS or not isinstance(row, dict):
        raise ValueError("cross-tenant policy malformed")
    if kind == PARTNER:
        partner = row.get("tenantId")
        if not isinstance(partner, str) or GUID.fullmatch(partner) is None:
            raise ValueError("cross-tenant partner ID malformed")
        rid = "/tenants/" + tenant + "/policies/crossTenantAccessPolicy/partners/" + partner
    else:
        partner = None
        rid = "/tenants/" + tenant + "/policies/crossTenantAccessPolicy/default"
    trust = row.get("inboundTrust")
    if trust is not None and not isinstance(trust, dict):
        raise ValueError("cross-tenant inbound trust malformed")
    sync = row.get("identitySynchronization")
    inbound = sync.get("userSyncInbound") if isinstance(sync, dict) else None
    if inbound is not None and not isinstance(inbound, dict):
        raise ValueError("cross-tenant user sync malformed")
    properties = {"tenantId": partner,
                  "isServiceDefault": row.get("isServiceDefault") if kind == DEFAULT else None,
                  "isInMultiTenantOrganization": row.get("isInMultiTenantOrganization") if kind == PARTNER else None,
                  "b2bCollaborationInbound": _setting(row.get("b2bCollaborationInbound")),
                  "b2bDirectConnectInbound": _setting(row.get("b2bDirectConnectInbound")),
                  "inboundTrust": {key: trust.get(key) for key in (
                      "isMfaAccepted", "isCompliantDeviceAccepted", "isHybridAzureADJoinedDeviceAccepted")}
                      if isinstance(trust, dict) else None,
                  "userSyncInboundAllowed": inbound.get("isSyncAllowed") if isinstance(inbound, dict) else None}
    return {"id": rid, "properties": properties,
            "_provenance": {"source_operation": "CrossTenantAccessPolicy_" +
                            ("GetDefault" if kind == DEFAULT else "ListPartners"),
                            "read_only": True, "tenant_id": tenant}}


def collect(reader, request, wanted, transport):
    if not KINDS.intersection(wanted):
        return
    tenant = getattr(transport, "tenant", None) or "selected"
    scope = "/tenants/" + tenant
    jobs = []
    if DEFAULT in wanted:
        url = GRAPH + "/v1.0/policies/crossTenantAccessPolicy/default"

        def default():
            yield [project(DEFAULT, reader.call(request, url, audience=GRAPH), tenant)]

        jobs.append((DEFAULT, scope, "Microsoft.Graph", default))
    if PARTNER in wanted:
        url = GRAPH + "/v1.0/policies/crossTenantAccessPolicy/partners?$expand=identitySynchronization"

        def partners():
            seen = set()
            for page in reader.pages(request, url, audience=GRAPH, next_key="@odata.nextLink"):
                projected = [project(PARTNER, row, tenant) for row in page]
                for row in projected:
                    if row["id"].casefold() in seen:
                        raise ValueError("duplicate cross-tenant partner")
                    seen.add(row["id"].casefold())
                yield projected

        jobs.append((PARTNER, scope, "Microsoft.Graph", partners))
    reader.run(jobs)
