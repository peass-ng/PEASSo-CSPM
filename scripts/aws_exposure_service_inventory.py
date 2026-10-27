"""Reproducible public AWS service/collector inventory for exposure review.

This is a screening inventory, not a claim that service exposure is covered.
Only service names and API operation names are written; no account data is read.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
import gzip
import json
from pathlib import Path

import botocore.session
import requests
from bs4 import BeautifulSoup

IAM_SERVICES = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-services-that-work-with-iam.html"
PRODUCTS = "https://aws.amazon.com/products/"
READ_PREFIXES = ("Get", "List", "Describe", "BatchGet", "Search")
EXPOSURE_WORDS = ("Policy", "Permission", "Acl", "Access", "Public", "Share", "Endpoint", "Domain", "Url", "Trust", "Auth")


def inventory(snapshot_path):
    response = requests.get(IAM_SERVICES, timeout=30)
    response.raise_for_status()
    soup = BeautifulSoup(response.text, "html.parser")
    table = soup.find("table")
    if table is None:
        raise ValueError("official IAM service table missing")
    heads = [x.get_text(" ", strip=True) for x in table.find_all("th")]
    if heads[:4] != ["Service", "Actions", "Resource-level permissions", "Resource-based policies"]:
        raise ValueError("official IAM service table columns changed")
    official = []
    for tr in table.find_all("tr")[1:]:
        cells = [x.get_text(" ", strip=True) for x in tr.find_all("td")]
        if len(cells) != len(heads):
            continue
        official.append({"service": cells[0], "resource_based_policies": cells[3]})
    if len(official) < 400:
        raise ValueError("official IAM service table unexpectedly short")

    with gzip.open(snapshot_path, "rt") as stream:
        snapshot = json.load(stream)
    collected = Counter(c.get("service") for c in snapshot["collections"])
    session = botocore.session.get_session()
    api_services = []
    for name in session.get_available_services():
        model = session.get_service_model(name)
        operations = [op for op in model.operation_names if op.startswith(READ_PREFIXES)
                      and any(word.lower() in op.lower() for word in EXPOSURE_WORDS)]
        api_services.append({"api": name, "collected_families": collected.get(name, 0),
                             "candidate_read_operations": sorted(operations)})
    return {"schema": "aws-exposure-service-screen-v1", "screened_at": date.today().isoformat(),
            "sources": {"official_iam_services": IAM_SERVICES, "official_products": PRODUCTS,
                        "sdk_service_models": "installed botocore"},
            "limitations": "Operation-name screening is not a semantic exposure audit; IAM service names and SDK endpoint names are not a one-to-one mapping.",
            "counts": {"official_iam_services": len(official),
                       "official_resource_policy_yes_or_partial": sum(r["resource_based_policies"] in ("Yes", "Partial") for r in official),
                       "sdk_service_apis": len(api_services),
                       "sdk_apis_matching_collector_service_name": sum(bool(r["collected_families"]) for r in api_services),
                       "snapshot_service_names": len(collected),
                       "snapshot_resource_types": len({c["type"] for c in snapshot["collections"]})},
            "official_iam_services": official, "sdk_service_apis": api_services,
            "snapshot_service_names": sorted(collected)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", default="/Users/carlospolop/peaso-work/replay/snapshot.bin")
    parser.add_argument("--output", default="outputs/aws-exposure-service-screen-20261027.json")
    args = parser.parse_args()
    result = inventory(args.snapshot)
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result["counts"], sort_keys=True))


if __name__ == "__main__":
    main()
