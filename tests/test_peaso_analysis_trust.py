"""Default trust boundary, external principals and federated (OIDC) trust review."""
import pytest

from peaso.analysis import analyze
from peaso.analysis.trust import azure_federated_credential, restrictive_conditions, trusted_scopes
from peaso.snapshot import make_snapshot, resources
from peaso.analysis.iam import review_findings
from peaso.analysis.internet_exposure import federated_findings

ACCOUNT = "111122223333"
SCOPE = f"{ACCOUNT}/us-east-1"


def aws(*collections, metadata=None):
    return make_snapshot("aws", [SCOPE], list(collections), created_at="2026-10-10T00:00:00+00:00", metadata=metadata)


def coll(kind, items, status=None, service="iam", scope=SCOPE):
    return {"type": kind, "scope": scope, "service": service, "status": status or ("collected" if items else "empty"), "items": items}


def role(statements, name="r"):
    return {"RoleName": name, "Arn": f"arn:aws:iam::{ACCOUNT}:role/{name}",
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": statements}}


def findings(snapshot, check):
    return [f for f in analyze(snapshot)["findings"] if f["check_id"] == check]


def principal(snapshot):
    found = findings(snapshot, "analysis.principal_exposure")
    assert len(found) <= 1
    return found[0] if found else None


def trust(principal_value, condition=None, action="sts:AssumeRole"):
    statement = {"Effect": "Allow", "Principal": principal_value, "Action": action}
    if condition:
        statement["Condition"] = condition
    return statement


def test_collected_graph_app_federated_credential_reaches_native_exposure_review():
    tenant = "/tenants/home"
    item = {"id": "applications/app/federatedIdentityCredentials/credential", "appId": "app-id",
            "issuer": "https://token.actions.githubusercontent.com",
            "subject": "repo:owner/project:ref:refs/heads/main",
            "audiences": ["api://AzureADTokenExchange"]}
    snapshot = make_snapshot("azure", [tenant], [coll("directory_federated_credential", [item], scope=tenant)],
                             metadata={"tenant_id": "home"})
    rows = federated_findings(snapshot, resources(snapshot))
    assert len(rows) == 1 and rows[0]["check_id"] == "analysis.federated_trust"
    assert rows[0]["status"] == "MANUAL"
    assert rows[0]["evidence"]["subject"] == item["subject"]


def test_exact_azure_federation_subject_needs_issuer_ownership_review():
    credential = {"data": {"issuer": "https://token.actions.githubusercontent.com",
        "subject": "repo:other-org/project:ref:refs/heads/main",
        "audiences": ["api://AzureADTokenExchange"]}}
    status, _, evidence = azure_federated_credential({}, credential)
    assert status == "MANUAL" and evidence["subject"] == credential["data"]["subject"]
    credential["data"]["issuer"] = ""
    assert azure_federated_credential({}, credential)[0] == "UNKNOWN"
    credential["data"]["issuer"] = "https://token.actions.githubusercontent.com"
    credential["data"].pop("audiences")
    assert azure_federated_credential({}, credential)[0] == "UNKNOWN"


@pytest.mark.parametrize("issuer,value,expected", [
    ("https://token.actions.githubusercontent.com",
     "claims['sub'] matches 'repo:owner/project:ref:refs/heads/*' and claims['repository_id'] eq '123'", "MANUAL"),
    ("https://token.actions.githubusercontent.com", "claims['sub'] matches 'repo:*'", "UNKNOWN"),
    ("https://gitlab.com", "claims['sub'] matches 'project_path:owner/project:*' and claims['project_id'] eq '456'", "MANUAL"),
    ("https://app.terraform.io", "claims['sub'] matches '*'", "FAIL"),
    ("https://app.terraform.io", "claims['sub'] matches 'organization:*'", "FAIL"),
    ("https://app.terraform.io", "claims['sub'] matches 'organization:owner:*'", "MANUAL"),
    ("https://token.actions.githubusercontent.com", "claims['sub'] matches 'repo:*' or claims['repository_id'] eq '123'", "UNKNOWN"),
])
def test_azure_flexible_federation_expression_is_parsed_before_risk_decision(issuer, value, expected):
    item = {"data": {"issuer": issuer, "subject": None,
            "claimsMatchingExpression": {"languageVersion": 1, "value": value},
            "audiences": ["api://AzureADTokenExchange"]}}
    status, _, evidence = azure_federated_credential({}, item)
    assert status == expected and evidence["claims_matching_expression"]["value"] == value


def test_azure_group_role_assignment_reaches_nested_guest():
    tenant, subscription = "/tenants/home", "/subscriptions/sub"
    role = {"id": "assignment", "properties": {"principalId": "outer", "principalType": "Group",
        "roleDefinitionId": subscription + "/providers/Microsoft.Authorization/roleDefinitions/reader",
        "scope": subscription}}
    snapshot = make_snapshot("azure", [subscription], [
        coll("role_assignment", [role], scope=subscription),
        coll("directory_group", [{"id": "outer"}, {"id": "inner"}], scope=tenant),
        coll("directory_user", [{"id": "guest", "userType": "Guest"}], scope=tenant),
        coll("directory_membership", [{"id": "inner"}], scope=tenant + "/groups/outer"),
        coll("directory_membership", [{"id": "guest"}], scope=tenant + "/groups/inner"),
    ], metadata={"tenant_id": "home"})
    found = [row for row in review_findings(snapshot, resources(snapshot))
             if row["check_id"] == "analysis.principal_exposure"]
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    guest = next(row for row in found[0]["evidence"]["principals"] if row["principal"] == "guest")
    assert guest["native_grant"]["viaGroup"] == "outer"
    assert guest["native_grant"]["groupPath"] == ["outer", "inner"]
    assert guest["native_grant"]["membershipSource"]


def test_azure_group_role_assignment_without_observed_external_member_is_not_claimed():
    subscription, tenant = "/subscriptions/sub", "/tenants/home"
    role = {"id": "assignment", "properties": {"principalId": "outer", "principalType": "Group",
        "roleDefinitionId": subscription + "/providers/Microsoft.Authorization/roleDefinitions/reader",
        "scope": subscription}}
    snapshot = make_snapshot("azure", [subscription], [
        coll("role_assignment", [role], scope=subscription),
        coll("directory_group", [{"id": "outer"}], scope=tenant),
        coll("directory_membership", [{"id": "missing"}], status="partial", scope=tenant + "/groups/outer"),
    ], metadata={"tenant_id": "home"})
    assert not [row for row in review_findings(snapshot, resources(snapshot))
                if row["check_id"] == "analysis.principal_exposure" and row["status"] == "FAIL"]


def test_azure_gallery_image_read_role_grant_to_external_guest():
    sub, tenant = "/subscriptions/sub", "/tenants/home"
    gallery = sub + "/resourceGroups/rg/providers/Microsoft.Compute/galleries/g"
    image = gallery + "/images/base"
    role_id = sub + "/providers/Microsoft.Authorization/roleDefinitions/reader"
    definition = {"id": role_id, "name": "reader", "properties": {"permissions": [
        {"actions": ["Microsoft.Compute/galleries/images/versions/read"], "notActions": []}]}}
    def assignment(scope, principal="guest", condition=None):
        return {"id": scope + "/providers/Microsoft.Authorization/roleAssignments/a",
                "properties": {"scope": scope, "principalId": principal, "principalType": "User",
                               "roleDefinitionId": role_id, "condition": condition}}
    def scan(grants, role=definition, denials=()):
        snap = make_snapshot("azure", [sub], [
            coll("compute_gallery", [{"id": gallery, "properties": {"sharingProfile": {"permissions": "Private"}}}], scope=sub),
            coll("role_assignment", grants, scope=sub), coll("role_definition", [role], scope="/"),
            coll("deny_assignment", list(denials), scope=sub),
            coll("directory_user", [{"id": "guest", "userType": "Guest"}], scope=tenant),
        ], metadata={"tenant_id": "home"})
        return [row for row in review_findings(snap, resources(snap))
                if row["check_id"] == "analysis.azure_gallery_rbac_share"]
    found = scan([assignment(image)])
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    assert found[0]["evidence"]["assignment_scope"] == image.lower()
    assert scan([assignment(image, condition="@Resource[x] StringEquals 'y'")])[0]["status"] == "MANUAL"
    assert not scan([assignment(sub + "/resourceGroups/other")])
    denied = {**definition, "properties": {"permissions": [{"actions": ["*"],
        "notActions": ["Microsoft.Compute/galleries/images/versions/read"]}]}}
    assert not scan([assignment(gallery)], role=denied)
    all_principal_deny = {"id": "deny", "properties": {"scope": gallery,
        "doNotApplyToChildScopes": False,
        "principals": [{"id": "00000000-0000-0000-0000-000000000000", "type": "SystemDefined"}],
        "excludePrincipals": [], "permissions": [{"actions": ["Microsoft.Compute/galleries/images/versions/read"],
                                                "notActions": []}]}}
    blocked = scan([assignment(image)], denials=[all_principal_deny])
    assert len(blocked) == 1 and blocked[0]["status"] == "PASS"
    assert blocked[0]["evidence"]["deny_source"]
    assert blocked[0]["evidence"]["effective_access"] == "blocked_for_gallery_image_version_read"
    for changes in ({"doNotApplyToChildScopes": True},
                    {"excludePrincipals": [{"id": "guest", "type": "User"}]},
                    {"permissions": [{"actions": ["*"], "notActions": ["Microsoft.Compute/galleries/images/versions/read"]}]},
                    {"condition": "@Resource[x] StringEquals 'y'"}):
        altered = {**all_principal_deny, "properties": {**all_principal_deny["properties"], **changes}}
        assert scan([assignment(image)], denials=[altered])[0]["status"] == "FAIL"


def test_azure_gallery_image_read_inherited_through_observed_group_member():
    sub, tenant = "/subscriptions/sub", "/tenants/home"
    gallery = sub + "/resourceGroups/rg/providers/Microsoft.Compute/galleries/g"
    role_id = sub + "/providers/Microsoft.Authorization/roleDefinitions/reader"
    snap = make_snapshot("azure", [sub], [
        coll("compute_gallery", [{"id": gallery, "properties": {"sharingProfile": {"permissions": "Private"}}}], scope=sub),
        coll("role_assignment", [{"id": "assignment", "properties": {"scope": gallery,
            "principalId": "group", "principalType": "Group", "roleDefinitionId": role_id}}], scope=sub),
        coll("role_definition", [{"id": role_id, "name": "reader", "properties": {"permissions": [
            {"actions": ["Microsoft.Compute/galleries/*/read"], "notActions": []}]}}], scope="/"),
        coll("directory_group", [{"id": "group"}], scope=tenant),
        coll("directory_user", [{"id": "guest", "userType": "Guest"}], scope=tenant),
        coll("directory_membership", [{"id": "guest"}], scope=tenant + "/groups/group"),
    ], metadata={"tenant_id": "home"})
    found = [row for row in review_findings(snap, resources(snap))
             if row["check_id"] == "analysis.azure_gallery_rbac_share"]
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    assert found[0]["evidence"]["via_group"] == "group"
    assert found[0]["evidence"]["membership_source"]


def test_scanned_account_and_org_members_are_trusted_by_default():
    snapshot = aws(coll("iam_role", [role([trust({"AWS": f"arn:aws:iam::{ACCOUNT}:root"})])]))
    assert principal(snapshot) is None
    org = coll("organization_account", [{"Id": "444455556666"}], service="organizations")
    assert principal(aws(coll("iam_role", [role([trust({"AWS": "arn:aws:iam::444455556666:root"})])]), org)) is None
    assert trusted_scopes(aws(org))["sources"]["444455556666"] == "organization_account"


def test_external_account_fails_with_external_id():
    result = principal(aws(coll("iam_role", [role([trust({"AWS": "arn:aws:iam::999988887777:root"})])])))
    assert result["status"] == "FAIL" and result["severity"] == "high"
    assert result["evidence"]["external_scope_ids"] == ["999988887777"]
    with_external_id = principal(aws(coll("iam_role", [role([trust({"AWS": "arn:aws:iam::999988887777:root"}, {"StringEquals": {"sts:ExternalId": "x"}})])])))
    assert with_external_id["status"] == "FAIL" and with_external_id["severity"] == "medium"


def test_trusted_scope_ids_stays_an_extra_allowlist():
    snapshot = aws(coll("iam_role", [role([trust({"AWS": "arn:aws:iam::999988887777:root"})])]), metadata={"trusted_scope_ids": ["999988887777"]})
    assert principal(snapshot) is None


def bucket_policy(condition=None):
    statement = {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}
    if condition:
        statement["Condition"] = condition
    return coll("bucket", [{"Name": "b", "Policy": {"collection_status": "collected", "Policy": {"Version": "2012-10-17", "Statement": [statement]}}}], service="s3")


@pytest.mark.parametrize("condition,expected", [
    (None, "FAIL"),
    ({"StringEquals": {"aws:SourceVpce": "vpce-1"}}, "MANUAL"),
    ({"StringEquals": {"aws:PrincipalOrgID": "o-abc"}}, "MANUAL"),
    ({"StringEqualsIfExists": {"aws:SourceVpce": "vpce-1"}}, "FAIL"),
    ({"StringNotEquals": {"aws:SourceVpce": "vpce-1"}}, "FAIL"),
    ({"StringLike": {"aws:SourceAccount": "*"}}, "FAIL"),
    ({"IpAddress": {"aws:SourceIp": "0.0.0.0/0"}}, "FAIL"),
    ({"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}, "MANUAL"),
])
def test_public_resource_policy_fails_unless_truly_restricted(condition, expected):
    assert principal(aws(bucket_policy(condition)))["status"] == expected


def test_restrictive_condition_parser():
    assert restrictive_conditions({"StringEquals": {"aws:SourceArn": "arn:x"}})
    assert not restrictive_conditions({"Bool": {"aws:SecureTransport": "true"}})


def test_service_principal_with_source_condition_is_fine():
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "lambda:InvokeFunction",
              "Condition": {"ArnLike": {"AWS:SourceArn": "arn:aws:s3:::b"}}}]}
    fn = coll("lambda_function", [{"FunctionName": "f", "FunctionArn": f"arn:aws:lambda:us-east-1:{ACCOUNT}:function:f",
                                   "Policy": {"collection_status": "collected", "Policy": policy}}], service="lambda")
    assert principal(aws(fn)) is None
    policy["Statement"][0].pop("Condition")
    result = principal(aws(fn))
    assert result["status"] == "MANUAL" and result["evidence"]["principals"][0]["reason"] == "service_without_source_condition"


def test_unattributable_principal_stays_unknown_without_scanned_account():
    snapshot = make_snapshot("aws", ["scope-a"], [coll("iam_role", [role([trust({"AWS": "arn:aws:iam::999988887777:root"})])], scope="scope-a")],
                             created_at="2026-10-10T00:00:00+00:00")
    assert principal(snapshot)["status"] == "UNKNOWN"


GITHUB = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"


@pytest.mark.parametrize("condition,expected", [
    ({"StringEquals": {"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}, "FAIL"),
    ({"StringLike": {"token.actions.githubusercontent.com:sub": "repo:*"}}, "FAIL"),
    ({"StringLike": {"token.actions.githubusercontent.com:sub": "repo:*/app:*"}}, "FAIL"),
    ({"StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*"}}, "PASS"),
    ({"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:acme/app:ref:refs/heads/main",
                       "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"}}, "PASS"),
    ({"StringEquals": {"token.actions.githubusercontent.com:sub": "repo:*"}}, "PASS"),
])
def test_github_oidc_trust_requires_pinned_subject(condition, expected):
    statement = trust({"Federated": GITHUB}, condition, "sts:AssumeRoleWithWebIdentity")
    found = findings(aws(coll("iam_role", [role([statement])])), "analysis.federated_trust")
    assert len(found) == 1 and found[0]["status"] == expected
    if expected == "FAIL":
        assert found[0]["severity"] == "critical"


def test_cognito_trust_without_aud_fails():
    statement = trust({"Federated": "cognito-identity.amazonaws.com"}, {"ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"}},
                      "sts:AssumeRoleWithWebIdentity")
    found = findings(aws(coll("iam_role", [role([statement])])), "analysis.federated_trust")
    codes = {p["code"] for r in found[0]["evidence"]["federated_trusts"] for p in r["problems"]}
    assert found[0]["status"] == "FAIL" and codes == {"cognito_no_aud", "cognito_unauthenticated"}


def test_gcp_workload_identity_provider_condition():
    def provider(condition=None, issuer="https://token.actions.githubusercontent.com"):
        item = {"name": "projects/1/locations/global/workloadIdentityPools/p/providers/gh", "oidc": {"issuerUri": issuer}}
        if condition:
            item["attributeCondition"] = condition
        return make_snapshot("gcp", ["projects/p1"], [coll("workload_identity_provider", [item], scope="projects/p1")], created_at="2026-10-10T00:00:00+00:00")
    assert findings(provider(), "analysis.federated_trust")[0]["status"] == "MANUAL"
    assert findings(provider("assertion.repository_owner == 'acme'"), "analysis.federated_trust")[0]["status"] == "PASS"
    assert findings(provider(issuer="https://idp.example.com"), "analysis.federated_trust")[0]["status"] == "MANUAL"


def test_gcp_wif_joins_exact_pool_service_account_impersonation_binding():
    from peaso.analysis.trust import gcp_wif_provider
    name = "projects/1/locations/global/workloadIdentityPools/p/providers/gh"
    provider = {"type": "workload_identity_provider", "data": {"name": name,
                "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"}}}
    member = "principalSet://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/*"
    account = {"name": "projects/p1/serviceAccounts/sa@p1.iam.gserviceaccount.com",
               "iamPolicy": {"collection_status": "collected", "bindings": [{
                   "role": "roles/iam.workloadIdentityUser", "members": [member]}]}}
    snapshot = {"collections": [{"type": "service_account", "status": "collected", "items": [account]}]}
    status, _, evidence = gcp_wif_provider(snapshot, provider)
    assert status == "FAIL" and evidence["service_account_bindings"][0]["members"] == [member]
    account["iamPolicy"]["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    account["iamPolicy"]["bindings"][0]["members"] = [member.replace("/p/*", "/another/*")]
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"


def test_gcp_public_binding_fails_and_project_sa_is_trusted():
    policy = {"name": "projects/p1", "bindings": [{"role": "roles/viewer", "members": ["allUsers", "serviceAccount:sa@p1.iam.gserviceaccount.com"]}]}
    snapshot = make_snapshot("gcp", ["projects/p1"], [coll("iam_policy", [policy], scope="projects/p1")], created_at="2026-10-10T00:00:00+00:00")
    result = principal(snapshot)
    assert result["status"] == "FAIL" and [p["principal"] for p in result["evidence"]["principals"]] == ["allUsers"]
    policy["bindings"][0]["members"] = ["serviceAccount:sa@other.iam.gserviceaccount.com"]
    snapshot = make_snapshot("gcp", ["projects/p1"], [coll("iam_policy", [policy], scope="projects/p1")], created_at="2026-10-10T00:00:00+00:00")
    result = principal(snapshot)
    assert result["status"] == "FAIL" and result["evidence"]["external_scope_ids"] == ["other"]


def test_gcp_member_forms_attribute_to_scanned_projects_and_org_domain():
    project = {"projectId": "p1", "projectNumber": "123", "name": "projects/123"}
    org = {"name": "organizations/9", "displayName": "example.com"}

    def verdict(*members):
        policy = {"name": "projects/p1", "bindings": [{"role": "roles/viewer", "members": list(members)}]}
        snapshot = make_snapshot("gcp", ["projects/p1"], [coll("iam_policy", [policy], scope="projects/p1"),
            coll("project", [project], scope="projects/p1"), coll("organization", [org], scope="organizations/9")],
            created_at="2026-10-10T00:00:00+00:00")
        return principal(snapshot)
    # Trusted: basic-role convenience members, default Compute/App Engine
    # accounts, Google service agents and deleted principals of scanned projects.
    trusted = ["projectOwner:p1", "projectViewer:p1", "serviceAccount:123-compute@developer.gserviceaccount.com",
               "serviceAccount:p1@appspot.gserviceaccount.com", "serviceAccount:service-123@gs-project-accounts.iam.gserviceaccount.com",
               "serviceAccount:service-123@gcp-sa-logging.iam.gserviceaccount.com",
               "deleted:serviceAccount:old@p1.iam.gserviceaccount.com?uid=1234", "domain:example.com", "user:alice@example.com",
               "serviceAccount:service-123@gae-api-prod.google.com.iam.gserviceaccount.com",
               "principalSet://agents.global.org-9.system.id.goog/attribute.platformContainer/run/projects/123"]
    assert verdict(*trusted) is None
    # External (FAIL): other projects' service agents/defaults, foreign domains, consumer accounts.
    for member, scope in [("serviceAccount:service-999@gs-project-accounts.iam.gserviceaccount.com", "999"),
                          ("serviceAccount:999-compute@developer.gserviceaccount.com", "999"),
                          ("projectEditor:other-project", "other-project"),
                          ("deleted:serviceAccount:x@other.iam.gserviceaccount.com?uid=1", "other"),
                          ("principalSet://agents.global.org-77.system.id.goog/attribute.x/y", "77"),
                          ("domain:attacker.example", None), ("user:someone@gmail.com", None)]:
        result = verdict(*trusted, member)
        assert result["status"] == "FAIL", member
        assert [p["principal"] for p in result["evidence"]["principals"]] == [member]
        assert result["evidence"]["external_scope_ids"] == ([scope] if scope else [])
    # Unattributable without a scope or a trusted domain: stays UNKNOWN, never trusted.
    policy = {"name": "projects/p1", "bindings": [{"role": "roles/viewer", "members": ["user:someone@gmail.com"]}]}
    snapshot = make_snapshot("gcp", ["projects/p1"], [coll("iam_policy", [policy], scope="projects/p1")], created_at="2026-10-10T00:00:00+00:00")
    assert principal(snapshot)["status"] == "UNKNOWN"


def test_cognito_guest_role_on_pinned_pool_is_manual():
    statement = trust({"Federated": "cognito-identity.amazonaws.com"}, {"StringEquals": {"cognito-identity.amazonaws.com:aud": "us-east-1:pool"},
                      "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "unauthenticated"}}, "sts:AssumeRoleWithWebIdentity")
    found = findings(aws(coll("iam_role", [role([statement])])), "analysis.federated_trust")
    assert found[0]["status"] == "MANUAL" and found[0]["severity"] == "medium"


def test_vpc_endpoint_default_policy_is_review_not_fail():
    endpoint = {"VpcEndpointId": "vpce-1", "PolicyDocument": {"Version": "2008-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}}
    result = principal(aws(coll("vpc_endpoint", [endpoint], service="ec2")))
    assert result["status"] == "MANUAL"


def test_generic_resource_policy_endpoint_arn_is_network_bound():
    document = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]}
    for suffix in ("vpc-endpoint/vpce-1", "vpc-endpoint-service/vpce-svc-1"):
        endpoint = {"ResourceArn": f"arn:aws:ec2:us-east-1:{ACCOUNT}:{suffix}", "Policy": document}
        found = principal(aws(coll("aws_resource_policy", [endpoint], service="ec2")))
        assert found is not None and found["status"] == "MANUAL"
