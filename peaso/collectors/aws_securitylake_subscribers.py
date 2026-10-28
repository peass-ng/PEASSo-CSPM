"""Minimal Security Lake subscriber grants and notification destinations."""

KIND = "securitylake_subscriber"
EXCEPTION_KIND = "securitylake_exception_notification"
SPECS = {KIND: ("securitylake", "list_subscribers", "subscribers"),
         EXCEPTION_KIND: ("securitylake", "get_data_lake_exception_subscription", None)}
NATIVE_IDS = {KIND: "subscriberArn", EXCEPTION_KIND: "NetworkResourceId"}
READ_ACTIONS = {("securitylake", "list_subscribers"),
                ("securitylake", "get_data_lake_exception_subscription")}


def collect(requests, session, region, account):
    from .aws import ReadResult
    from .aws_network_inventory import MetadataSession

    listed = requests.pages(MetadataSession(session), "securitylake", region,
                            "list_subscribers", "subscribers")
    if listed.status not in {"collected", "empty"}:
        return listed
    partition = session.get_partition_for_region(region)
    prefix = f"arn:{partition}:securitylake:{region}:{account}:subscriber/"
    rows, failures = [], []
    for row in listed.items:
        arn = row.get("subscriberArn") if isinstance(row, dict) else None
        if not isinstance(arn, str) or not arn.startswith(prefix) or len(arn) <= len(prefix):
            failures.append("malformed")
            continue
        rows.append(row)
    status = "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": "securitylake_subscribers_incomplete"} if failures else None)


def collect_exception_notification(requests, session, region, account):
    from .aws import ReadResult
    from .aws_network_inventory import MetadataSession

    detail = requests.detail(MetadataSession(session), "securitylake", region,
                             "get_data_lake_exception_subscription",
                             absent=("ResourceNotFoundException",))
    if detail.get("collection_status") == "empty" and detail.get("absent") is True:
        return ReadResult([], "empty")
    if detail.get("collection_status") != "collected":
        return ReadResult([], detail.get("collection_status", "malformed"),
                          detail.get("error") or {"code": "securitylake_exception_subscription_incomplete"})
    partition = session.get_partition_for_region(region)
    arn = f"arn:{partition}:securitylake:{region}:{account}:data-lake/default/exception-subscription"
    return ReadResult([{**detail, "NetworkResourceId": arn}], "collected")


FETCHERS = {KIND: collect, EXCEPTION_KIND: collect_exception_notification}
