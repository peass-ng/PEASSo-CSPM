"""Read-only Azure Attestation provider inventory with explicit field allowlist."""

import re
from urllib.parse import urlsplit


KIND = "attestation_provider"
VERSION = "2021-06-01"


def project(row, subscription):
    rid = row.get("id") if isinstance(row, dict) else None
    props = row.get("properties") if isinstance(row, dict) else None
    pattern = re.escape(subscription.rstrip("/")) + r"/resourceGroups/[^/?#%\s]+/providers/Microsoft\.Attestation/attestationProviders/[^/?#%\s]+"
    if (not isinstance(rid, str) or re.fullmatch(pattern, rid, re.I) is None
            or str(row.get("type", "")).casefold() != "microsoft.attestation/attestationproviders"
            or not isinstance(props, dict)):
        raise ValueError("foreign or malformed attestation provider")
    uri = props.get("attestUri")
    parsed = urlsplit(uri) if isinstance(uri, str) else None
    host = parsed.hostname if parsed is not None and parsed.scheme == "https" else None
    if uri is not None and (not host or not re.fullmatch(r"[a-zA-Z0-9.-]+", host)):
        raise ValueError("malformed attestation endpoint")
    safe = {key: props.get(key) for key in ("status", "trustModel", "publicNetworkAccess",
                                           "tpmAttestationAuthentication")}
    safe["attestHost"] = host.casefold() if host else None
    return {"id": rid, "name": row.get("name"), "type": row["type"], "location": row.get("location"),
            "properties": safe, "_provenance": {"source_operation": "AttestationProviders_List",
                                                  "api_version": VERSION, "read_only": True,
                                                  "selected_scope": subscription}}


def collect(reader, request, subscriptions, wanted):
    if KIND not in wanted:
        return
    jobs = []
    for subscription in subscriptions:
        url = ("https://management.azure.com" + subscription.rstrip("/")
               + "/providers/Microsoft.Attestation/attestationProviders?api-version=" + VERSION)

        def pages(subscription=subscription, url=url):
            seen = set()
            for page in reader.pages(request, url):
                projected = [project(row, subscription) for row in page]
                for row in projected:
                    if row["id"].casefold() in seen:
                        raise ValueError("duplicate attestation provider")
                    seen.add(row["id"].casefold())
                yield projected

        jobs.append((KIND, subscription, "Microsoft.Attestation", pages))
    reader.run(jobs)
