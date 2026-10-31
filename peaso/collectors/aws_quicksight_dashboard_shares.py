"""Public and named QuickSight dashboard grants with no dashboard content."""

KIND = "quicksight_dashboard_share"
SPECS = {KIND: ("quicksight", "list_dashboards", "DashboardSummaryList")}
NATIVE_IDS = {KIND: "NetworkResourceId"}
_FAILURE_STATUSES = frozenset({"partial", "denied", "unknown", "malformed", "timeout", "not_collected"})
READ_ACTIONS = {("quicksight", operation) for operation in
                ("list_dashboards", "describe_dashboard_permissions", "describe_account_settings")}


class MetadataClient:
    def __init__(self, native):
        self.native = native

    def __getattr__(self, operation):
        native = getattr(self.native, operation)
        if operation not in {"list_dashboards", "describe_dashboard_permissions", "describe_account_settings"}:
            return native

        def read(**arguments):
            from .aws_content_sdk_logging import private_sdk_logs
            with private_sdk_logs():
                response = native(**arguments)
            if not isinstance(response, dict):
                return {}
            if operation == "describe_account_settings":
                settings = response.get("AccountSettings")
                return {"AccountSettings": {"PublicSharingEnabled": settings.get("PublicSharingEnabled")}
                        if isinstance(settings, dict) else None}
            if operation == "list_dashboards":
                items = response.get("DashboardSummaryList")
                if not isinstance(items, list) or any(not isinstance(row, dict) for row in items):
                    return {}
                token = response.get("NextToken")
                return {"DashboardSummaryList": [
                    {key: row[key] for key in ("Arn", "DashboardId") if isinstance(row.get(key), str)}
                    for row in items], **({"NextToken": token} if isinstance(token, str) else {})}
            def principals(items):
                if not isinstance(items, list) or any(not isinstance(row, dict) for row in items):
                    return None
                return [{"Principal": row.get("Principal"),
                         "Actions": row.get("Actions") if isinstance(row.get("Actions"), list) and
                         all(isinstance(action, str) for action in row["Actions"]) else None}
                        for row in items]
            link = response.get("LinkSharingConfiguration")
            return {"DashboardId": response.get("DashboardId"),
                    "DashboardArn": response.get("DashboardArn"),
                    "Permissions": principals(response.get("Permissions", [])),
                    "LinkPermissions": principals(link.get("Permissions", [])) if isinstance(link, dict) else []}
        return read


class MetadataSession:
    def __init__(self, native):
        self.native = native

    def client(self, service, **arguments):
        client = self.native.client(service, **arguments)
        return MetadataClient(client) if service == "quicksight" else client


def collect(requests, session, region, account):
    from .aws import ReadResult

    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    session = MetadataSession(session)
    settings = requests.detail(session, "quicksight", region, "describe_account_settings", AwsAccountId=account)
    public = None
    if settings.get("collection_status") == "collected":
        value = settings.get("AccountSettings")
        if isinstance(value, dict) and isinstance(value.get("PublicSharingEnabled"), bool):
            public = value["PublicSharingEnabled"]
    listed = requests.pages(session, "quicksight", region, "list_dashboards", "DashboardSummaryList",
                            _tokens=("NextToken", "NextToken"), AwsAccountId=account)
    rows, failures = [], []
    if listed.status not in {"collected", "empty"}:
        failures.append(listed.status)
    for summary in listed.items:
        if not isinstance(summary, dict):
            failures.append("malformed")
            continue
        ident, arn = summary.get("DashboardId"), summary.get("Arn")
        if (not isinstance(ident, str) or not ident or
                arn != f"arn:{partition}:quicksight:{region}:{account}:dashboard/{ident}"):
            failures.append("malformed")
            continue
        detail = requests.detail(session, "quicksight", region, "describe_dashboard_permissions",
                                 AwsAccountId=account, DashboardId=ident)
        if detail.get("collection_status") != "collected" or detail.get("DashboardArn") != arn:
            failures.append(detail.get("collection_status", "malformed"))
            detail = {}
        rows.append({"DashboardId": ident, "DashboardArn": arn, "NetworkResourceId": arn,
                     "AccountPublicSharing": public,
                     "Permissions": detail.get("Permissions"), "LinkPermissions": detail.get("LinkPermissions")})
    if rows and public is None:
        # The sharing setting only qualifies existing dashboards. An account
        # without dashboards (for example, not subscribed) has nothing to share.
        settings_status = settings.get("collection_status")
        failures.insert(0, settings_status if settings_status in _FAILURE_STATUSES else "unknown")
    failures = [value if value in _FAILURE_STATUSES else "unknown" for value in failures]
    status = "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": "quicksight_dashboard_shares_incomplete"} if failures else None)


FETCHERS = {KIND: collect}
