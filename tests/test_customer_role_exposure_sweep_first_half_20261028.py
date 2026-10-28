"""Exact customer-role allocation for combined Exposure inventory reads."""
import json
import shutil
from pathlib import Path

from scripts import peaso_deploy_customer_policy as policy


def test_stage_export_and_portal_reads_keep_exact_iam_scope():
    assert policy.iam_action("apigatewayv2", "export_api") == "apigateway:GET"
    assert policy.GATEWAY_PATHS[("apigatewayv2", "export_api")] == ("/apis/*/exports/OAS30",)
    portal = policy.NATIVE_METADATA_STATEMENTS[("apigatewayv2", "list_portals")]
    assert portal["Action"] == "apigateway:ListPortals"
    assert portal["Resource"]["Fn::Sub"].endswith(":${AWS::AccountId}:/portals/*")
    assert policy.iam_action("budgets", "describe_budgets") == "budgets:ViewBudget"
    assert policy.iam_action("backupsearch", "get_search_result_export_job") == "backup-search:GetSearchResultExportJob"
    try:
        policy.iam_action("apigatewayv2", "import_api")
    except ValueError:
        pass
    else:
        raise AssertionError("API Gateway mutation entered the metadata role")


def test_full_exposure_role_fits_default_attachment_quota(tmp_path):
    source = Path(__file__).resolve().parents[1] / "infra/aws/customer-role.json"
    target = tmp_path / "infra/aws/customer-role.json"
    target.parent.mkdir(parents=True)
    shutil.copy2(source, target)
    policy.refresh(tmp_path)
    resources = json.loads(target.read_text())["Resources"]
    generated = [name for name in resources if name.startswith(policy.MANAGED_POLICY_PREFIX)]
    managed = resources["AuditRole"]["Properties"]["ManagedPolicyArns"]
    assert len(generated) == 8
    assert len(generated) + len(managed) == policy.IAM_MANAGED_POLICIES_PER_ROLE
    assert "arn:aws:iam::aws:policy/IAMAccessAnalyzerFullAccess" not in managed
    assert all(policy.policy_size(resources[name]["Properties"]["PolicyDocument"])
               <= policy.IAM_MANAGED_POLICY_LIMIT for name in generated)
