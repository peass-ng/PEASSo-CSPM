from scripts.permission_risk_classifier import (
    classify_all,
    classify_permission,
)


def test_single_permission_entries_override_generic_heuristics():
    assert classify_permission("aws", "codebuild:StartBuild") == "critical"
    assert classify_permission("gcp", "container.pods.create") == "high"
    assert classify_permission("azure", "Microsoft.DocumentDB/mongoClusters/write") == "critical"


def test_aws_combination_requires_every_permission():
    permissions = [
        "servicecatalog:CreateProvisioningArtifact",
        "servicecatalog:ProvisionProduct",
    ]
    assert classify_permission("aws", permissions[0]) != "critical"
    assert classify_permission("aws", permissions[1]) != "critical"
    classified = classify_all("aws", permissions)
    assert classified["critical"] == permissions


def test_gcp_combination_requires_every_permission():
    permissions = ["run.jobs.run", "run.jobs.runWithOverrides"]
    assert classify_all("gcp", permissions[:1])["critical"] == []
    assert classify_all("gcp", permissions)["critical"] == permissions


def test_azure_combination_is_case_insensitive():
    permissions = ["policy.read.all", "POLICY.READWRITE.CONDITIONALACCESS"]
    assert classify_all("azure", permissions[:1])["critical"] == []
    assert classify_all("azure", permissions)["critical"] == permissions


def test_azure_combination_supports_permission_patterns():
    permissions = [
        "Microsoft.Automation/automationAccounts/webhooks/write",
        "Microsoft.Automation/automationAccounts/runbooks/read",
    ]
    assert classify_all("azure", permissions[:1])["high"] == []
    assert classify_all("azure", permissions)["high"] == permissions
