"""Default trust boundary, external principals and federated (OIDC) trust review."""
import copy
import pytest

from peaso.analysis import analyze
from peaso.analysis.trust import restrictive_conditions, trusted_scopes
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
    assert rows[0]["evidence"]["subject"] == item["subject"]


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
SAML = f"arn:aws:iam::{ACCOUNT}:saml-provider/Company"


def github_provider(client_ids=("sts.amazonaws.com",), detail_status="collected"):
    return coll("iam_oidc_provider", [{"Arn": GITHUB, "Provider": {
        "collection_status": detail_status, "Url": "token.actions.githubusercontent.com",
        "ClientIDList": list(client_ids)}}])


@pytest.mark.parametrize("condition,expected,codes", [
    ({"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml"}},
     "FAIL", {"saml_issuer_wide"}),
    ({"StringEquals": {"SAML:aud": "https://signin.aws.amazon.com/saml", "SAML:sub": "alice@example.com"}},
     "MANUAL", {"saml_claim_scope"}),
    ({"StringLike": {"SAML:aud": "*", "SAML:sub": "*"}},
     "FAIL", {"saml_no_aud", "saml_issuer_wide"}),
])
def test_saml_role_trust_classifies_issuer_wide_and_claim_scoped_access(condition, expected, codes):
    statement = trust({"Federated": SAML}, condition, "sts:AssumeRoleWithSAML")
    found = findings(aws(coll("iam_role", [role([statement])]),
                         coll("iam_saml_provider", [{"Arn": SAML}])), "analysis.federated_trust")
    assert len(found) == 1 and found[0]["status"] == expected
    assert {problem["code"] for review in found[0]["evidence"]["federated_trusts"]
            for problem in review["problems"]} == codes


def test_saml_provider_needs_matching_assume_role_action():
    from peaso.analysis.trust import aws_federated_trust

    statement = trust({"Federated": SAML}, None, "sts:AssumeRoleWithWebIdentity")
    assert aws_federated_trust(aws(coll("iam_role", [])), {"data": role([statement])}) is None


def test_saml_trust_requires_provider_inventory_and_absent_provider_blocks():
    statement = trust({"Federated": SAML}, None, "sts:AssumeRoleWithSAML")
    role_row = coll("iam_role", [role([statement])])
    absent = findings(aws(role_row, coll("iam_saml_provider", [])), "analysis.federated_trust")
    assert len(absent) == 1 and absent[0]["status"] == "PASS"
    assert absent[0]["evidence"]["federated_trusts"][0]["problems"][0]["code"] == "saml_provider_absent"

    missing = findings(aws(role_row), "analysis.federated_trust")
    assert len(missing) == 1 and missing[0]["status"] == "MANUAL"
    assert missing[0]["evidence"]["federated_trusts"][0]["problems"][0]["code"] == "saml_provider_unknown"

    partial = findings(aws(role_row, coll("iam_saml_provider", [], status="partial")), "analysis.federated_trust")
    assert len(partial) == 1 and partial[0]["status"] == "MANUAL"

    from peaso.analysis.catalog import REQUIRED_TYPES
    assert "iam_saml_provider" in REQUIRED_TYPES["aws"]["exposure"]


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
    found = findings(aws(coll("iam_role", [role([statement])]), github_provider()), "analysis.federated_trust")
    assert len(found) == 1 and found[0]["status"] == expected
    if expected == "FAIL":
        assert found[0]["severity"] == "critical"


def test_oidc_provider_absence_and_disjoint_registered_audience_block_trust():
    from peaso.finding_observation import evidence_summary
    statement = trust({"Federated": GITHUB},
                      {"StringEquals": {"token.actions.githubusercontent.com:aud": "another-client"}},
                      "sts:AssumeRoleWithWebIdentity")
    role_row = coll("iam_role", [role([statement])])
    disjoint = findings(aws(role_row, github_provider()), "analysis.federated_trust")
    assert len(disjoint) == 1 and disjoint[0]["status"] == "PASS"
    assert disjoint[0]["evidence"]["federated_trusts"][0]["problems"][0]["code"] == "oidc_audience_disjoint"
    assert "does not match any registered client ID" in evidence_summary(disjoint[0])
    contradicted = copy.deepcopy(disjoint[0])
    contradicted["evidence"]["federated_trusts"][0]["conditions"]["StringEquals"]["token.actions.githubusercontent.com:aud"] = "sts.amazonaws.com"
    assert evidence_summary(contradicted) is None

    absent = findings(aws(role_row, coll("iam_oidc_provider", [])), "analysis.federated_trust")
    assert len(absent) == 1 and absent[0]["status"] == "PASS"
    assert absent[0]["evidence"]["federated_trusts"][0]["problems"][0]["code"] == "oidc_provider_absent"
    assert "absent from the complete account inventory" in evidence_summary(absent[0])

    missing = findings(aws(role_row), "analysis.federated_trust")
    assert len(missing) == 1 and missing[0]["status"] == "MANUAL"
    assert missing[0]["evidence"]["federated_trusts"][0]["problems"][0]["code"] == "oidc_provider_unknown"
    assert "inventory is missing or incomplete" in evidence_summary(missing[0])

    incomplete = findings(aws(role_row, github_provider(detail_status="access_denied")), "analysis.federated_trust")
    assert incomplete[0]["status"] == "FAIL"
    assert "oidc_provider_detail_unknown" in {p["code"] for p in incomplete[0]["evidence"]["federated_trusts"][0]["problems"]}

    from peaso.analysis.catalog import REQUIRED_TYPES
    assert "iam_oidc_provider" in REQUIRED_TYPES["aws"]["exposure"]


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
    assert findings(provider("assertion.repository_owner == 'acme'"), "analysis.federated_trust")[0]["status"] == "MANUAL"
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
    account["iamPolicy"]["bindings"][0]["condition"] = {}
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    account["iamPolicy"]["bindings"][0]["members"] = [member.replace("/p/*", "/another/*")]
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"


def test_gcp_wif_direct_resource_grant_and_scoped_identity():
    from peaso.analysis.trust import gcp_wif_provider
    pool = "projects/1/locations/global/workloadIdentityPools/p"
    provider = {"data": {"name": pool + "/providers/gh",
                         "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"}}}
    member = "principalSet://iam.googleapis.com/" + pool + "/*"
    policy = {"name": "projects/p1", "bindings": [{"role": "roles/storage.objectViewer", "members": [member]}]}
    snapshot = {"collections": [{"type": "iam_policy", "status": "collected", "items": [policy]}]}
    status, _, evidence = gcp_wif_provider(snapshot, provider)
    assert status == "FAIL"
    assert evidence["direct_resource_bindings"][0]["resource"] == "projects/p1"
    policy["bindings"][0]["members"] = [member.replace("/*", "/attribute.repository/acme")]
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    policy["bindings"][0]["members"] = [member]
    policy["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    policy["bindings"][0]["condition"] = {}
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    policy["bindings"][0].pop("condition")
    policy["bindings"][0]["members"] = [member.replace("/p/*", "/other/*")]
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    provider["data"]["oidc"]["issuerUri"] = "https://token.actions.githubusercontent.com.attacker.example"
    policy["bindings"][0]["members"] = [member]
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"


def test_gcp_wif_joins_verified_inherited_project_policy():
    from peaso.analysis.trust import gcp_wif_provider
    pool = "projects/1/locations/global/workloadIdentityPools/p"
    provider = {"data": {"name": pool + "/providers/gh",
                         "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"}}}
    member = "principalSet://iam.googleapis.com/" + pool + "/*"
    ancestor = {"name": "folders/42", "ancestor": "folders/42", "collection_status": "collected",
                "bindings": [{"role": "roles/storage.objectViewer", "members": [member]}]}
    project = {"name": "projects/p1", "_inherited_iam_policies": [ancestor],
               "_coverage": {"_inherited_iam_policies": {"status": "collected"}}}
    snapshot = {"collections": [{"type": "project", "scope": "projects/p1", "status": "collected",
                                 "items": [project]}]}
    status, _, evidence = gcp_wif_provider(snapshot, provider)
    assert status == "FAIL"
    assert evidence["direct_resource_bindings"][0]["inherited_from"] == "folders/42"
    project["_coverage"]["_inherited_iam_policies"]["status"] = "partial"
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    project["_coverage"]["_inherited_iam_policies"]["status"] = "collected"
    ancestor["name"] = "folders/another"
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    ancestor["name"] = "folders/42"
    ancestor["bindings"][0]["condition"] = {}
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    ancestor["bindings"][0].pop("condition")
    snapshot["collections"][0]["scope"] = "projects/other"
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"


def test_gcp_wif_provider_and_pool_disabled_existing_token_semantics():
    from peaso.analysis.trust import gcp_wif_provider
    pool_name = "projects/1/locations/global/workloadIdentityPools/p"
    provider = {"data": {"name": pool_name + "/providers/gh", "disabled": True,
                         "oidc": {"issuerUri": "https://token.actions.githubusercontent.com"}}}
    member = "principalSet://iam.googleapis.com/" + pool_name + "/*"
    policy = {"name": "projects/p1", "bindings": [{"role": "roles/viewer", "members": [member]}]}
    pool = {"name": pool_name, "state": "ACTIVE"}
    snapshot = {"collections": [
        {"type": "iam_policy", "status": "collected", "items": [policy]},
        {"type": "workload_identity_pool", "status": "collected", "items": [pool]}]}
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    provider["data"]["disabled"] = False
    provider["data"]["state"] = "DELETED"
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    pool["disabled"] = True
    status, _, evidence = gcp_wif_provider(snapshot, provider)
    assert status == "PASS" and evidence["pool_disabled"] is True


def test_gcp_wif_external_aws_provider_with_pool_wide_grant():
    from peaso.analysis.trust import gcp_wif_provider
    pool = "projects/1/locations/global/workloadIdentityPools/p"
    provider = {"data": {"name": pool + "/providers/aws", "aws": {"accountId": "999988887777"}}}
    member = "principalSet://iam.googleapis.com/" + pool + "/*"
    policy = {"name": "projects/p1", "bindings": [{"role": "roles/viewer", "members": [member]}]}
    snapshot = {"provider": "gcp", "metadata": {}, "collections": [
        {"type": "iam_policy", "status": "collected", "items": [policy]}]}
    status, _, evidence = gcp_wif_provider(snapshot, provider)
    assert status == "FAIL" and evidence["provider_type"] == "aws"
    assert evidence["aws_account"] == "999988887777"
    snapshot["metadata"]["trusted_scope_ids"] = ["999988887777"]
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    snapshot["metadata"].clear()
    policy["bindings"][0]["condition"] = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    policy["bindings"][0]["condition"] = {}
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"
    policy["bindings"][0].pop("condition")
    policy["bindings"][0]["members"] = [member.replace("/*", "/subject/pinned")]
    assert gcp_wif_provider(snapshot, provider)[0] == "FAIL"
    policy["bindings"][0]["members"] = [member.replace("/*", "/attribute.team/pinned")]
    assert gcp_wif_provider(snapshot, provider)[0] == "FAIL"
    policy["bindings"].clear()
    assert gcp_wif_provider(snapshot, provider)[0] == "MANUAL"


def test_gcp_unknown_dataset_acl_role_does_not_assert_public_or_foreign_grant():
    dataset = {"name": "projects/p1/datasets/shared", "access": [
        {"specialGroup": "allUsers", "role": "roles/bigquery.metadataViewer"},
        {"userByEmail": "alice@foreign.example", "role": "roles/bigquery.metadataViewer"}]}
    def result():
        snapshot = make_snapshot("gcp", ["projects/p1"], [coll("bigquery_dataset", [dataset],
            scope="projects/p1", service="bigquery")], created_at="2026-10-10T00:00:00+00:00",
            metadata={"trusted_domains": ["owned.example"]})
        return findings(snapshot, "analysis.principal_exposure")[0]
    found = result()
    assert found["status"] == "UNKNOWN" and found["evidence"]["reason"] == "unrecognized_dataset_acl_role"
    dataset["access"][0]["role"] = "READER"
    assert result()["status"] == "FAIL"


def test_gcp_verified_inherited_iam_external_principal():
    ancestor = {"name": "folders/42", "ancestor": "folders/42", "collection_status": "collected",
                "bindings": [{"role": "roles/viewer", "members": ["allUsers", "user:alice@foreign.example"]}]}
    project = {"name": "projects/p1", "_inherited_iam_policies": [ancestor],
               "_coverage": {"_inherited_iam_policies": {"status": "collected"}}}
    def result():
        snapshot = make_snapshot("gcp", ["projects/p1"], [coll("project", [project], scope="projects/p1")],
                                 created_at="2026-10-10T00:00:00+00:00", metadata={"trusted_domains": ["owned.example"]})
        return findings(snapshot, "analysis.principal_exposure")
    found = result()
    assert len(found) == 1 and found[0]["status"] == "FAIL"
    evidence = found[0]["evidence"]
    assert {entry["principal"] for entry in evidence["principals"]} == {"allUsers", "user:alice@foreign.example"}
    project["_coverage"]["_inherited_iam_policies"]["status"] = "partial"
    assert not result()
    project["_coverage"]["_inherited_iam_policies"]["status"] = "collected"
    ancestor["name"] = "folders/other"
    assert not result()
    ancestor["name"] = "folders/42"
    ancestor["bindings"][0]["condition"] = {}
    found = result()
    assert len(found) == 1 and found[0]["status"] == "MANUAL"


def test_gcp_public_binding_fails_and_project_sa_is_trusted():
    policy = {"name": "projects/p1", "bindings": [{"role": "roles/viewer", "members": ["allUsers", "serviceAccount:sa@p1.iam.gserviceaccount.com"]}]}
    snapshot = make_snapshot("gcp", ["projects/p1"], [coll("iam_policy", [policy], scope="projects/p1")], created_at="2026-10-10T00:00:00+00:00")
    result = principal(snapshot)
    assert result["status"] == "FAIL" and [p["principal"] for p in result["evidence"]["principals"]] == ["allUsers"]
    policy["bindings"][0]["members"] = ["serviceAccount:sa@other.iam.gserviceaccount.com"]
    snapshot = make_snapshot("gcp", ["projects/p1"], [coll("iam_policy", [policy], scope="projects/p1")], created_at="2026-10-10T00:00:00+00:00")
    result = principal(snapshot)
    assert result["status"] == "FAIL" and result["evidence"]["external_scope_ids"] == ["other"]


def test_gcp_conditional_public_and_external_grants_need_review():
    condition = {"expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}
    policy = {"name": "projects/p1", "bindings": [{"role": "roles/viewer", "members": [
        "allUsers", "serviceAccount:sa@other.iam.gserviceaccount.com"], "condition": condition}]}
    snapshot = make_snapshot("gcp", ["projects/p1"], [coll("iam_policy", [policy], scope="projects/p1")],
                             created_at="2026-10-10T00:00:00+00:00")
    result = principal(snapshot)
    assert result["status"] == "MANUAL"
    assert {row["reason"] for row in result["evidence"]["principals"]} == {
        "public_conditional", "external_conditional"}
    policy["bindings"][0].pop("condition")
    snapshot = make_snapshot("gcp", ["projects/p1"], [coll("iam_policy", [policy], scope="projects/p1")],
                             created_at="2026-10-10T00:00:00+00:00")
    assert principal(snapshot)["status"] == "FAIL"


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


def test_gcp_owned_group_with_external_transitive_member_is_third_party_grant():
    scope = "projects/p1"
    policy = {"name": scope, "bindings": [{"role": "roles/viewer", "members": ["group:team@example.com"]}]}
    group = {"name": "groups/123", "groupKey": {"id": "team@example.com"},
             "_coverage": {"transitiveMemberships": {"status": "collected"}}}
    member = {"name": "groups/123/transitive/users/guest", "group": "groups/123",
              "membershipKind": "transitive", "preferredMemberKey": [{"id": "guest@outside.example"}],
              "membershipCoverage": {"status": "collected", "completeTransitiveClosure": True}}
    def result(status="collected", members=None):
        snap = make_snapshot("gcp", [scope], [
            coll("iam_policy", [policy], scope=scope),
            coll("group", [group], scope=scope),
            coll("group_membership", [member] if members is None else members, status=status, scope=scope)],
            created_at="2026-10-10T00:00:00+00:00", metadata={"trusted_domains": ["example.com"]})
        return principal(snap)
    exposed = result()
    assert exposed["status"] == "FAIL"
    assert exposed["evidence"]["principals"][0]["group_membership"]["external_members"] == ["guest@outside.example"]
    member["preferredMemberKey"][0]["id"] = "alice@example.com"
    assert result() is None
    assert result(status="partial")["status"] == "UNKNOWN"
    member["preferredMemberKey"] = [{"id": "unattributed", "namespace": "identity-source"}]
    assert result()["status"] == "UNKNOWN"


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


def test_gcp_grant_summary_retains_present_empty_condition():
    from peaso.analysis.iam import _grants, grant_summary
    binding = {"role": "roles/owner", "members": ["user:foreign@example.com"], "condition": {}}
    resource = {"provider": "gcp", "type": "iam_policy", "data": {"bindings": [binding]}}
    declared = _grants(resource)
    assert declared[0]["conditional"] is True
    assert grant_summary(declared)["conditional"] == 1
    binding.pop("condition")
    assert _grants(resource)[0]["conditional"] is False


def test_gcp_private_storage_acl_domain_hint_detects_foreign_principals_without_identity():
    from peaso.collectors.gcp_storage_acl_native import _acl
    raw = {"bucket": "sample-bucket", "object": "private/file.txt", "generation": "123",
           "entity": "user-person@foreign.example", "role": "READER"}
    row = _acl(raw, "sample-bucket", "a" * 64, "private/file.txt", "123")
    assert row["principalKind"] == "user" and row["principalDomain"] == "foreign.example"
    assert "person" not in str(row) and "private/file" not in str(row)
    def verdict(item):
        snapshot = make_snapshot("gcp", ["projects/p1"], [coll("object_acl", [item],
            scope="projects/p1", service="storage")], created_at="2026-10-10T00:00:00+00:00",
            metadata={"trusted_domains": ["owned.example"]})
        return principal(snapshot)
    found = verdict(row)
    assert found["status"] == "FAIL"
    assert found["evidence"]["principals"][0]["principal"] == "domain:foreign.example"
    assert "person" not in str(found["evidence"])
    raw["entity"] = "group-team@foreign.example"
    assert verdict(_acl(raw, "sample-bucket", "a" * 64, "private/file.txt", "123"))["status"] == "FAIL"
    raw["entity"] = "group-team@owned.example"
    assert verdict(_acl(raw, "sample-bucket", "a" * 64, "private/file.txt", "123"))["status"] == "UNKNOWN"
    raw["entity"] = "user-person@owned.example"
    assert verdict(_acl(raw, "sample-bucket", "a" * 64, "private/file.txt", "123")) is None
    raw["entity"] = "group-123456"
    assert verdict(_acl(raw, "sample-bucket", "a" * 64, "private/file.txt", "123"))["status"] == "UNKNOWN"
    bucket_acl = _acl({"bucket": "sample-bucket", "entity": "domain-foreign.example", "role": "WRITER"},
                      "sample-bucket")
    snapshot = make_snapshot("gcp", ["projects/p1"], [coll("bucket_acl", [bucket_acl],
        scope="projects/p1", service="storage")], created_at="2026-10-10T00:00:00+00:00",
        metadata={"trusted_domains": ["owned.example"]})
    assert principal(snapshot)["status"] == "FAIL"
    def project_team_result(number):
        acl = _acl({"bucket": "sample-bucket", "entity": "project-viewers-" + number,
                    "role": "READER"}, "sample-bucket")
        assert acl["principalKind"] == "project" and acl["principalProject"] == number
        snap = make_snapshot("gcp", ["projects/p1"], [
            coll("bucket_acl", [acl], scope="projects/p1", service="storage"),
            coll("project", [{"name": "projects/123", "projectId": "p1", "projectNumber": "123"}],
                 scope="projects/p1", service="cloudresourcemanager")],
            created_at="2026-10-10T00:00:00+00:00")
        return principal(snap)
    assert project_team_result("999")["status"] == "FAIL"
    assert project_team_result("123") is None
