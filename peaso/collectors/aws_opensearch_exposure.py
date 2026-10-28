"""Owned OpenSearch UI applications and private-domain endpoint grants."""

APPLICATION = "opensearch_ui_application"
ACCESS = "opensearch_vpc_endpoint_access"
SPECS = {APPLICATION: ("opensearch", "list_applications", "ApplicationSummaries"),
         ACCESS: ("opensearch", "list_domain_names", "DomainNames")}
NATIVE_IDS = {APPLICATION: "arn", ACCESS: "DomainArn"}
READ_ACTIONS = {("opensearch", name) for name in
                ("list_applications", "get_application", "list_vpc_endpoint_access",
                 "list_domain_names", "describe_domain")}


def collect_applications(requests, session, region, account):
    from .aws import ReadResult
    from .aws_network_inventory import MetadataSession

    safe = MetadataSession(session)
    listing = requests.pages(safe, "opensearch", region, "list_applications", "ApplicationSummaries")
    if listing.status not in {"collected", "empty"}:
        return listing
    partition = session.get_partition_for_region(region)
    rows, failures = [], []
    for summary in listing.items:
        if not isinstance(summary, dict):
            failures.append("malformed")
            continue
        ident, arn = summary.get("id"), summary.get("arn")
        if (not isinstance(ident, str) or not ident or
                arn != f"arn:{partition}:opensearch:{region}:{account}:application/{ident}"):
            failures.append("malformed")
            continue
        detail = requests.detail(safe, "opensearch", region, "get_application", id=ident)
        row = dict(summary)
        if detail.get("collection_status") == "collected" and detail.get("arn") == arn:
            row.update(detail)
        else:
            failures.append(detail.get("collection_status", "malformed"))
            row["DetailCoverage"] = detail.get("collection_status", "malformed")
        rows.append(row)
    status = "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": "opensearch_ui_inventory_incomplete"} if failures else None)


def collect_access(requests, session, region, account):
    from .aws import ReadResult
    from .aws_network_inventory import MetadataSession

    domains = requests.pages(session, "opensearch", region, "list_domain_names", "DomainNames")
    if domains.status not in {"collected", "empty"}:
        return domains
    safe = MetadataSession(session)
    partition = session.get_partition_for_region(region)
    rows, failures = [], []
    for item in domains.items:
        name = item.get("DomainName") if isinstance(item, dict) else None
        if not isinstance(name, str) or not name:
            failures.append("malformed")
            continue
        detail = requests.detail(session, "opensearch", region, "describe_domain", DomainName=name)
        status = detail.get("DomainStatus") if isinstance(detail, dict) else None
        arn = status.get("ARN") if isinstance(status, dict) else None
        expected = f"arn:{partition}:es:{region}:{account}:domain/{name}"
        if detail.get("collection_status") != "collected" or arn != expected:
            failures.append(detail.get("collection_status", "malformed"))
            continue
        if not isinstance(status.get("VPCOptions"), dict):
            continue
        access = requests.pages(safe, "opensearch", region, "list_vpc_endpoint_access",
                                "AuthorizedPrincipalList", _tokens=("NextToken", "NextToken"),
                                DomainName=name)
        if access.status not in {"collected", "empty"}:
            failures.append(access.status)
        rows.append({"DomainArn": arn, "DomainName": name,
                     "AccessCoverage": access.status,
                     "AuthorizedPrincipals": access.items})
    status = "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": "opensearch_endpoint_access_incomplete"} if failures else None)


FETCHERS = {APPLICATION: collect_applications, ACCESS: collect_access}
