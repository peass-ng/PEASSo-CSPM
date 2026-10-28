"""Owned Redshift datashare and private endpoint grants from cached list reads."""
from __future__ import annotations

import re

SPECS = {"redshift_datashare": ("redshift", "describe_data_shares", "DataShares"),
         "redshift_endpoint_authorization": ("redshift", "describe_endpoint_authorization", "EndpointAuthorizationList")}
NATIVE_IDS = {"redshift_datashare": "DataShareArn", "redshift_endpoint_authorization": "id"}
READ_ACTIONS = {("redshift", "describe_data_shares"), ("redshift", "describe_endpoint_authorization")}


class _Client:
    def __init__(self, native):
        self.native = native

    def __getattr__(self, operation):
        native = getattr(self.native, operation)
        if operation not in {"describe_data_shares", "describe_endpoint_authorization"}:
            return native

        def read(**arguments):
            from .aws_content_sdk_logging import private_sdk_logs
            with private_sdk_logs():
                response = native(**arguments)
            root = "DataShares" if operation == "describe_data_shares" else "EndpointAuthorizationList"
            if not isinstance(response, dict) or not isinstance(response.get(root), list):
                return {}
            projected = []
            for share in response[root]:
                if operation == "describe_endpoint_authorization":
                    if not isinstance(share, dict):
                        return {}
                    projected.append({key: share[key] for key in (
                        "Grantor", "Grantee", "ClusterIdentifier", "ClusterStatus", "Status",
                        "AllowedAllVPCs", "AllowedVPCs", "EndpointCount") if key in share})
                    continue
                if not isinstance(share, dict) or not isinstance(share.get("DataShareAssociations", []), list):
                    return {}
                associations = []
                for association in share.get("DataShareAssociations", []):
                    if not isinstance(association, dict):
                        return {}
                    associations.append({key: association[key] for key in (
                        "ConsumerIdentifier", "Status", "ConsumerRegion", "ProducerAllowedWrites",
                        "ConsumerAcceptedWrites") if key in association})
                projected.append({**{key: share[key] for key in (
                    "DataShareArn", "ProducerArn", "AllowPubliclyAccessibleConsumers", "ManagedBy",
                    "DataShareType") if key in share}, "DataShareAssociations": associations})
            return {root: projected, **({"Marker": response["Marker"]} if "Marker" in response else {})}
        return read


class _Session:
    def __init__(self, native):
        self.native = native

    def client(self, service, **arguments):
        native = self.native.client(service, **arguments)
        return _Client(native) if service == "redshift" else native


def collect(requests, session, region, account):
    from .aws import ReadResult
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    with requests._lock:
        wrappers = getattr(requests, "_redshift_datashare_sessions", None)
        if wrappers is None:
            wrappers = requests._redshift_datashare_sessions = {}
        session = wrappers.setdefault(id(session), _Session(session))
    read = requests.pages(session, "redshift", region, "describe_data_shares", "DataShares")
    rows, failures, seen = [], [], set()
    if read.status not in {"collected", "empty"}:
        failures.append(read.status)
    for share in read.items:
        if not isinstance(share, dict):
            failures.append("malformed")
            continue
        arn, producer = share.get("DataShareArn"), share.get("ProducerArn")
        pattern = rf"arn:{re.escape(partition)}:redshift:{re.escape(region)}:{account}:datashare:([0-9a-fA-F-]{{36}})/[^/]+"
        match = re.fullmatch(pattern, arn) if isinstance(arn, str) else None
        if match is None or producer != f"arn:{partition}:redshift:{region}:{account}:namespace:{match.group(1)}" or arn in seen:
            failures.append("malformed")
            continue
        seen.add(arn)
        rows.append(share)
    status = "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": "redshift_datashare_inventory_incomplete"} if failures else None)


FETCHERS = {"redshift_datashare": collect}


def collect_endpoint_authorizations(requests, session, region, account):
    from .aws import ReadResult
    with requests._lock:
        wrappers = getattr(requests, "_redshift_datashare_sessions", None)
        if wrappers is None:
            wrappers = requests._redshift_datashare_sessions = {}
        session = wrappers.setdefault(id(session), _Session(session))
    read = requests.pages(session, "redshift", region, "describe_endpoint_authorization",
                          "EndpointAuthorizationList", Grantee=False)
    rows, failures, seen = [], [], set()
    if read.status not in {"collected", "empty"}:
        failures.append(read.status)
    for authorization in read.items:
        if not isinstance(authorization, dict):
            failures.append("malformed")
            continue
        cluster, grantor, grantee = (authorization.get(key) for key in
                                     ("ClusterIdentifier", "Grantor", "Grantee"))
        if (not isinstance(cluster, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,62}", cluster) or
                grantor != account or not isinstance(grantee, str) or not re.fullmatch(r"[0-9]{12}", grantee)):
            failures.append("malformed")
            continue
        identity = f"{account}/{region}/redshift-endpoint/{cluster}/{grantee}"
        if identity in seen:
            failures.append("malformed")
            continue
        seen.add(identity)
        rows.append({**authorization, "id": identity})
    status = "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": "redshift_endpoint_authorizations_incomplete"} if failures else None)


FETCHERS["redshift_endpoint_authorization"] = collect_endpoint_authorizations
