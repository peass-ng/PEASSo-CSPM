"""Owned Well-Architected workload, lens, profile and template shares."""

KIND = "wellarchitected_share"
SPECS = {KIND: ("wellarchitected", "list_workloads", "WorkloadSummaries")}
NATIVE_IDS = {KIND: "NetworkResourceId"}

# Parent list, response root, identity, share list, share root, share argument.
FAMILIES = (
    ("workload", "list_workloads", "WorkloadSummaries", "WorkloadArn", "WorkloadId",
     "list_workload_shares", "WorkloadShareSummaries", "WorkloadId", {}),
    ("lens", "list_lenses", "LensSummaries", "LensArn", "LensAlias",
     "list_lens_shares", "LensShareSummaries", "LensAlias", {"LensType": "CUSTOM_SELF"}),
    ("profile", "list_profiles", "ProfileSummaries", "ProfileArn", "ProfileArn",
     "list_profile_shares", "ProfileShareSummaries", "ProfileArn", {"ProfileOwnerType": "SELF"}),
    ("template", "list_review_templates", "ReviewTemplates", "TemplateArn", "TemplateArn",
     "list_template_shares", "TemplateShareSummaries", "TemplateArn", {}),
)
READ_ACTIONS = {("wellarchitected", operation) for family in FAMILIES for operation in (family[1], family[5])}


class MetadataClient:
    """Limit retained SDK responses before the shared request cache stores them."""

    ROOTS = {operation: root for family in FAMILIES for operation, root in ((family[1], family[2]), (family[5], family[6]))}
    PARENTS = {family[1]: (family[3], family[4]) for family in FAMILIES}

    def __init__(self, native):
        self.native = native

    def __getattr__(self, operation):
        method = getattr(self.native, operation)
        if operation not in self.ROOTS:
            return method

        def read(**arguments):
            from .aws_content_sdk_logging import private_sdk_logs
            with private_sdk_logs():
                response = method(**arguments)
            if not isinstance(response, dict) or not isinstance(response.get(self.ROOTS[operation]), list):
                return {}
            rows = response[self.ROOTS[operation]]
            if any(not isinstance(row, dict) for row in rows):
                return {}
            if operation in self.PARENTS:
                identity, argument = self.PARENTS[operation]
                fields = {identity, argument, "Owner"}
            else:
                fields = {"ShareId", "SharedWith", "Status", "PermissionType"}
            selected = [{key: row[key] for key in fields if key in row} for row in rows]
            token = response.get("NextToken")
            return {self.ROOTS[operation]: selected, **({"NextToken": token} if isinstance(token, str) else {})}
        return read


class MetadataSession:
    def __init__(self, native):
        self.native = native

    def client(self, service, **arguments):
        client = self.native.client(service, **arguments)
        return MetadataClient(client) if service == "wellarchitected" else client


def collect(requests, session, region, account):
    from .aws import ReadResult

    session = MetadataSession(session)
    partition = "aws-cn" if region.startswith("cn-") else "aws-us-gov" if region.startswith("us-gov-") else "aws"
    prefix = f"arn:{partition}:wellarchitected:{region}:{account}:"
    rows, failures = [], []
    for family, operation, root, arn_key, id_key, share_op, share_root, argument, filters in FAMILIES:
        parents = requests.pages(session, "wellarchitected", region, operation, root,
                                 _tokens=("NextToken", "NextToken"), **filters)
        if parents.status not in {"collected", "empty"}:
            failures.append(parents.status)
            if parents.status != "partial":
                continue
        for parent in parents.items:
            if not isinstance(parent, dict):
                failures.append("malformed")
                continue
            owner, arn, identifier = parent.get("Owner"), parent.get(arn_key), parent.get(id_key)
            if owner != account:
                if isinstance(owner, str) and owner:
                    continue  # A shared-in resource is not owned by the scanned account.
                failures.append("malformed")
                continue
            if (not isinstance(arn, str) or not arn.startswith(prefix) or
                    not isinstance(identifier, str) or not identifier):
                failures.append("malformed")
                continue
            shares = requests.pages(session, "wellarchitected", region, share_op, share_root,
                                    _tokens=("NextToken", "NextToken"), **{argument: identifier})
            if shares.status not in {"collected", "empty"}:
                failures.append(shares.status)
            for share in shares.items:
                share_id = share.get("ShareId") if isinstance(share, dict) else None
                if not isinstance(share_id, str) or not share_id:
                    failures.append("malformed")
                    continue
                rows.append({"ResourceType": family, "ResourceArn": arn,
                             "OwnerAccount": account, "ShareId": share_id,
                             "NetworkResourceId": f"{arn}/share/{share_id}",
                             **{key: share[key] for key in ("SharedWith", "Status", "PermissionType") if key in share}})
    status = "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": "wellarchitected_shares_incomplete"} if failures else None)


FETCHERS = {KIND: collect}
