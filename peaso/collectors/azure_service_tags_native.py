"""Read-only Azure service-tag prefixes scoped to each subscription."""
from __future__ import annotations

import re

API_VERSION = "2025-09-01"


def collection_jobs(reader, request, scopes, wanted, options):
    if "service_tag" not in wanted:
        return []
    location = options.get("service_tag_location", "westcentralus")
    if not isinstance(location, str) or re.fullmatch(r"[a-z0-9]{2,32}", location) is None:
        raise ValueError("service_tag_location must be a native Azure region name")
    jobs = []
    for scope in scopes:
        url = ("https://management.azure.com" + scope + "/providers/Microsoft.Network/locations/"
               + location + "/serviceTags?api-version=" + API_VERSION)

        def pages(scope=scope, url=url):
            for page in reader.pages(request, url, key="values"):
                output = []
                for value in page:
                    name = value.get("name") if isinstance(value, dict) else None
                    prefixes = value.get("properties", {}).get("addressPrefixes") if isinstance(value, dict) else None
                    if not isinstance(name, str) or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", name) is None or not isinstance(prefixes, list):
                        raise ValueError("malformed Azure service tag")
                    output.append({**value, "id": scope + "/providers/Microsoft.Network/serviceTags/" + name,
                        "_provenance": {"source_operation": "ServiceTags_List", "api_version": API_VERSION,
                            "reference_location": location}})
                yield output

        jobs.append(("service_tag", scope, "Microsoft.Network", pages))
    return jobs


def collect(reader, request, scopes, wanted, options):
    jobs = collection_jobs(reader, request, scopes, wanted, options)
    if jobs:
        reader.run(jobs)
