"""Secret-free Microsoft Entra Domain Services resource inventory."""

import re


KIND = "entra_domain_service"
VERSION = "2022-12-01"


def project(row, subscription):
    rid = row.get("id") if isinstance(row, dict) else None
    props = row.get("properties") if isinstance(row, dict) else None
    pattern = re.escape(subscription.rstrip("/")) + r"/resourceGroups/[^/?#%\s]+/providers/Microsoft\.AAD/domainServices/[^/?#%\s]+"
    if (not isinstance(rid, str) or re.fullmatch(pattern, rid, re.I) is None
            or str(row.get("type", "")).casefold() != "microsoft.aad/domainservices"
            or not isinstance(props, dict)):
        raise ValueError("foreign or malformed Domain Services resource")
    ldaps = props.get("ldapsSettings")
    notification = props.get("notificationSettings")
    forest = props.get("resourceForestSettings")
    replicas = props.get("replicaSets")
    if replicas is not None and not isinstance(replicas, list):
        raise ValueError("Domain Services replica sets malformed")
    if forest is not None and not isinstance(forest, dict):
        raise ValueError("Domain Services forest settings malformed")
    trusts = forest.get("settings") if isinstance(forest, dict) else None
    if trusts is not None and not isinstance(trusts, list):
        raise ValueError("Domain Services forest trusts malformed")
    recipients = notification.get("additionalRecipients") if isinstance(notification, dict) else None
    if recipients is not None and (not isinstance(recipients, list) or any(not isinstance(x, str) for x in recipients)):
        raise ValueError("Domain Services notification recipients malformed")
    safe_replicas = []
    for replica in replicas or []:
        if not isinstance(replica, dict):
            raise ValueError("Domain Services replica malformed")
        safe_replicas.append({key: replica.get(key) for key in (
            "subnetId", "externalAccessIpAddress", "domainControllerIpAddress", "serviceStatus")})
    safe_trusts = []
    for trust in trusts or []:
        if not isinstance(trust, dict):
            raise ValueError("Domain Services forest trust malformed")
        safe_trusts.append({key: trust.get(key) for key in ("trustedDomainFqdn", "trustDirection")})
    return {"id": rid, "name": row.get("name"), "type": row["type"], "location": row.get("location"),
            "properties": {"domainName": props.get("domainName"),
                           "ldapsSettings": {key: ldaps.get(key) for key in ("ldaps", "externalAccess")}
                           if isinstance(ldaps, dict) else None,
                           "replicaSets": safe_replicas,
                           "resourceForestSettings": {"settings": safe_trusts},
                           "notificationSettings": {"additionalRecipients": recipients}},
            "_provenance": {"source_operation": "DomainService_List", "api_version": VERSION,
                            "read_only": True, "selected_scope": subscription}}


def collect(reader, request, subscriptions, wanted):
    if KIND not in wanted:
        return
    jobs = []
    for subscription in subscriptions:
        url = ("https://management.azure.com" + subscription.rstrip("/")
               + "/providers/Microsoft.AAD/domainServices?api-version=" + VERSION)

        def pages(subscription=subscription, url=url):
            seen = set()
            for page in reader.pages(request, url):
                projected = [project(row, subscription) for row in page]
                for row in projected:
                    if row["id"].casefold() in seen:
                        raise ValueError("duplicate Domain Services resource")
                    seen.add(row["id"].casefold())
                yield projected

        jobs.append((KIND, subscription, "Microsoft.AAD", pages))
    reader.run(jobs)
