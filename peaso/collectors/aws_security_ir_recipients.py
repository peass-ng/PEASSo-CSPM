"""Minimal Security Incident Response notification-recipient inventory."""

KIND = "security_ir_recipient_route"
SPECS = {KIND: ("security-ir", "list_memberships", "items")}
NATIVE_IDS = {KIND: "NetworkResourceId"}
READ_ACTIONS = {("security-ir", operation) for operation in
                ("list_memberships", "get_membership", "list_cases", "get_case")}


def project_recipients(rows):
    """Keep domains for review; never retain names or full email addresses."""
    if not isinstance(rows, list):
        return None
    domains = []
    for row in rows:
        if not isinstance(row, dict):
            return None
        email = row.get("email")
        if not isinstance(email, str) or email.count("@") != 1:
            return None
        local, domain = email.rsplit("@", 1)
        if not local or not domain or "." not in domain or any(c.isspace() for c in domain):
            return None
        domains.append(domain.lower())
    return {"RecipientCount": len(rows), "RecipientDomains": sorted(set(domains))}


def collect(requests, session, region, account):
    from .aws import ReadResult
    from .aws_network_inventory import MetadataSession

    safe = MetadataSession(session)
    listed = requests.pages(safe, "security-ir", region, "list_memberships", "items")
    if listed.status not in {"collected", "empty"}:
        return listed
    partition = session.get_partition_for_region(region)
    rows, failures = [], []
    for item in listed.items:
        if not isinstance(item, dict):
            failures.append("malformed")
            continue
        membership_id, arn = item.get("membershipId"), item.get("membershipArn")
        if (not isinstance(membership_id, str) or not membership_id or
                arn != f"arn:{partition}:security-ir:{region}:{account}:membership/{membership_id}" or
                item.get("accountId") != account):
            failures.append("malformed")
            continue
        detail = requests.detail(safe, "security-ir", region, "get_membership", membershipId=membership_id)
        if detail.get("collection_status") != "collected" or detail.get("membershipArn") != arn:
            failures.append(detail.get("collection_status", "malformed"))
            rows.append({"NetworkResourceId": arn, "ResourceArn": arn,
                         "RouteType": "membership", "RecipientCoverage": "unresolved"})
            continue
        rows.append({"NetworkResourceId": arn, "ResourceArn": arn,
                     "RouteType": "membership", "MembershipStatus": detail.get("membershipStatus"),
                     "RecipientCount": detail.get("RecipientCount"),
                     "RecipientDomains": detail.get("RecipientDomains"),
                     "RecipientCoverage": detail.get("RecipientCoverage")})
    cases = requests.pages(safe, "security-ir", region, "list_cases", "items")
    if cases.status not in {"collected", "empty"}:
        failures.append(cases.status)
    for item in cases.items:
        if not isinstance(item, dict):
            failures.append("malformed")
            continue
        case_id, arn = item.get("caseId"), item.get("caseArn")
        if (not isinstance(case_id, str) or not case_id or
                arn != f"arn:{partition}:security-ir:{region}:{account}:case/{case_id}"):
            failures.append("malformed")
            continue
        detail = requests.detail(safe, "security-ir", region, "get_case", caseId=case_id)
        if detail.get("collection_status") != "collected" or detail.get("caseArn") != arn:
            failures.append(detail.get("collection_status", "malformed"))
            rows.append({"NetworkResourceId": arn, "ResourceArn": arn,
                         "RouteType": "case", "RecipientCoverage": "unresolved"})
            continue
        rows.append({"NetworkResourceId": arn, "ResourceArn": arn, "RouteType": "case",
                     "CaseStatus": detail.get("caseStatus"),
                     "RecipientCount": detail.get("RecipientCount"),
                     "RecipientDomains": detail.get("RecipientDomains"),
                     "RecipientCoverage": detail.get("RecipientCoverage")})
    status = "partial" if rows and failures else failures[0] if failures else "collected" if rows else "empty"
    return ReadResult(rows, status, {"code": "security_ir_recipients_incomplete"} if failures else None)


FETCHERS = {KIND: collect}
