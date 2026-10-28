"""Observed Lake Formation grants on owned S3 Tables catalogs.

Only read-only list calls are made. SDK responses are projected before the
per-scan request cache receives them; no table data or tag values are read.
"""
from __future__ import annotations

import hashlib
import json
import re

SPECS = {"s3tables_lf_grant": ("lakeformation", "list_permissions", "PrincipalResourcePermissions")}
NATIVE_IDS = {"s3tables_lf_grant": "GrantId"}
READ_ACTIONS = {("lakeformation", "list_permissions"), ("s3tables", "list_table_buckets")}


class _Client:
    def __init__(self, native, service):
        self.native, self.service = native, service

    def __getattr__(self, operation):
        native = getattr(self.native, operation)
        if (self.service, operation) not in READ_ACTIONS:
            return native

        def read(**arguments):
            from .aws_content_sdk_logging import private_sdk_logs
            with private_sdk_logs():
                response = native(**arguments)
            if not isinstance(response, dict):
                return {}
            rows = response.get("PrincipalResourcePermissions")
            if not isinstance(rows, list):
                return {}
            projected = []
            for row in rows:
                if not isinstance(row, dict):
                    return {}
                principal = row.get("Principal")
                resource = row.get("Resource")
                if not isinstance(principal, dict) or not isinstance(resource, dict):
                    return {}
                native_resource = {}
                for kind in ("Catalog", "Database", "Table", "TableWithColumns", "LFTagPolicy", "LFTagExpression"):
                    value = resource.get(kind)
                    if isinstance(value, dict):
                        native_resource[kind] = {key: value[key] for key in
                                                 ("Id", "CatalogId", "Name", "DatabaseName", "TableWildcard",
                                                  "ResourceType", "ExpressionName")
                                                 if key in value}
                        if kind == "LFTagPolicy":
                            native_resource[kind]["ExpressionPresent"] = bool(value.get("Expression"))
                projected.append({
                    "Principal": {"DataLakePrincipalIdentifier": principal.get("DataLakePrincipalIdentifier")},
                    "Resource": native_resource,
                    "Permissions": row.get("Permissions"),
                    "ConditionPresent": bool(row.get("Condition")),
                })
            return {"PrincipalResourcePermissions": projected,
                    **({"NextToken": response["NextToken"]} if "NextToken" in response else {})}
        return read


class _Session:
    def __init__(self, native):
        self.native = native

    def client(self, service, **arguments):
        return _Client(self.native.client(service, **arguments), service)


def _bucket(resource, account, owned):
    """Return a proven owned table bucket from either documented catalog form."""
    if not isinstance(resource, dict) or len(resource) != 1:
        return None
    kind, value = next(iter(resource.items()))
    if kind not in {"Catalog", "Database", "Table", "TableWithColumns", "LFTagPolicy"} or not isinstance(value, dict):
        return None
    catalog = value.get("Id") if kind == "Catalog" else value.get("CatalogId")
    if not isinstance(catalog, str):
        return None
    prefix = account + ":s3tablescatalog/"
    if catalog.startswith(prefix):
        name = catalog[len(prefix):]
        return owned.get(name) if name and "/" not in name else None
    if catalog == account and kind in {"Database", "Table", "TableWithColumns"}:
        database = value.get("Name") if kind == "Database" else value.get("DatabaseName")
        if isinstance(database, str) and database.startswith("s3tablescatalog/"):
            parts = database.split("/")
            return owned.get(parts[1]) if len(parts) >= 3 and parts[1] else None
    return None


def collect(requests, session, region, account):
    from .aws import ReadResult
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    # The table bucket list is shared with the existing S3 Tables policy and
    # regional-data collectors through the scan's ordinary Requests cache.
    buckets = requests.pages(session, "s3tables", region, "list_table_buckets", "tableBuckets")
    if buckets.status not in {"collected", "empty"}:
        return ReadResult([], buckets.status, buckets.error)
    owned, failures = {}, []
    for row in buckets.items:
        if not isinstance(row, dict):
            failures.append("malformed")
            continue
        name, arn = row.get("name"), row.get("arn")
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or
                arn != f"arn:{partition}:s3tables:{region}:{account}:bucket/{name}" or
                row.get("ownerAccountId", account) != account):
            failures.append("malformed")
            continue
        owned[name] = arn
    if not owned:
        status = failures[0] if failures else "empty"
        return ReadResult([], status, {"code": "s3tables_bucket_identity_incomplete"} if failures else None)
    rows, seen = [], set()
    with requests._lock:
        wrappers = getattr(requests, "_s3tables_lf_sessions", None)
        if wrappers is None:
            wrappers = requests._s3tables_lf_sessions = {}
        session = wrappers.setdefault(id(session), _Session(session))
    for catalog in [account, *(account + ":s3tablescatalog/" + name for name in sorted(owned))]:
        grants = requests.pages(session, "lakeformation", region, "list_permissions",
                                "PrincipalResourcePermissions", _tokens=("NextToken", "NextToken"),
                                CatalogId=catalog)
        if grants.status not in {"collected", "empty"}:
            failures.append(grants.status)
        for grant in grants.items:
            if not isinstance(grant, dict):
                failures.append("malformed")
                continue
            bucket_arn = _bucket(grant.get("Resource"), account, owned)
            if bucket_arn is None:
                continue
            principal = grant.get("Principal", {}).get("DataLakePrincipalIdentifier")
            permissions = grant.get("Permissions")
            if not isinstance(principal, str) or not principal or not isinstance(permissions, list) or any(
                    not isinstance(permission, str) for permission in permissions):
                failures.append("malformed")
                continue
            body = {"BucketArn": bucket_arn, "Principal": principal,
                    "Permissions": sorted(set(permissions)), "Resource": grant["Resource"],
                    "ConditionPresent": grant.get("ConditionPresent") is True}
            key = json.dumps(body, sort_keys=True, separators=(",", ":"))
            if key in seen:
                continue
            seen.add(key)
            body["GrantId"] = hashlib.sha256(key.encode()).hexdigest()
            rows.append(body)
    status = "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": "s3tables_lakeformation_grants_incomplete"} if failures else None)


FETCHERS = {"s3tables_lf_grant": collect}
