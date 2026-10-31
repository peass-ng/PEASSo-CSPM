"""Cloud Asset returns service account policies next to the project root (named by project ID).

A service account under its nested IAM name is a resource peer, so it must not make the
project root ambiguous and leave project IAM partial.
"""
from peaso.gcp_project_alias import root_candidate
from tests.test_peaso_gcp_project_alias_collector import NUMBER, SCOPE, Transport, collect, inventory

SA_NAME = "//iam.googleapis.com/projects/fixture-project/serviceAccounts/app@fixture-project.iam.gserviceaccount.com"


class WithServiceAccount(Transport):
    def request(self, method, url, **kwargs):
        data, request_id = super().request(method, url, **kwargs)
        if url.endswith(":searchAllIamPolicies"):
            data["results"][0]["resource"] = "//cloudresourcemanager.googleapis.com/" + SCOPE
            data["results"].append({"resource": SA_NAME, "assetType": "iam.googleapis.com/ServiceAccount",
                                    "project": NUMBER, "policy": {"bindings": [
                                        {"role": "roles/iam.serviceAccountUser", "members": ["user:dev@example.invalid"]}]}})
        return data, request_id


def test_service_account_policy_does_not_make_project_root_ambiguous():
    envelope = inventory(collect(WithServiceAccount(cai_policy={"bindings": []})), "iam_policy")
    assert envelope["coverage_status"] == "collected"
    assert any(row["name"] == SA_NAME for row in envelope["items"])


def test_service_account_type_with_root_like_name_stays_a_root_candidate():
    row = {"name": "//cloudresourcemanager.googleapis.com/projects/fixture-project",
           "assetType": "iam.googleapis.com/ServiceAccount", "project": NUMBER,
           "_provenance": {"representation": "partial", "source_requests": ["r"], "scope": "projects/fixture-project"}}
    assert root_candidate(row) is True
