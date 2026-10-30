"""Isolated signed sw47 AWS checks; run this draft file with --noconftest."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS, evaluate_check
from peaso.checks import compliance_new_sw47 as sw

SCOPE = "123456789012/us-east-1"
ACCOUNT = "123456789012"
REGION = "us-east-1"
TRAIL = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/test"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/partner"
LOG = f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:test"
KEY = f"arn:aws:kms:{REGION}:{ACCOUNT}:key/abc"
ENV = f"arn:aws:elasticbeanstalk:{REGION}:{ACCOUNT}:environment/app/prod"
VAULT = f"arn:aws:backup:{REGION}:{ACCOUNT}:backup-vault:remote"
MONITOR = f"arn:aws:ce::{ACCOUNT}:anomalymonitor/one"
SUB = f"arn:aws:ce::{ACCOUNT}:anomalysubscription/one"
CLUSTER = f"arn:aws:eks:{REGION}:{ACCOUNT}:cluster/one"


@pytest.fixture(scope="module", autouse=True)
def clean_registry():
    yield
    CHECKS[:] = [check for check in CHECKS if check.id not in sw.SPECS]


def facts(**policies):
    return {"context": {"provider": "aws", "scope": SCOPE,
                        "metadata": {"enabled_regions": [REGION],
                                     "compliance_policy": policies}},
            "collections": {}}


def add(index, kind, items, *, global_kind=False, status=None):
    envelope = {"type": kind, "scope": SCOPE, "status": status or ("collected" if items else "empty"),
                "items": items, "account_id": ACCOUNT}
    if global_kind:
        envelope["global"] = True
    index["collections"][kind] = [envelope]
    index[kind] = [{"type": kind, "scope": SCOPE, "account_id": ACCOUNT, "data": x} for x in items]
    return index


def policy(**fields):
    return {"status": "collected", **fields}


def key(enabled=True):
    return {"KeyArn": KEY, "KeyId": "abc", "Metadata": {"collection_status": "collected",
            "KeyMetadata": {"KeyState": "Enabled" if enabled else "Disabled", "KeyManager": "CUSTOMER"}}}


def trail(**fields):
    return {"TrailARN": TRAIL, "Status": {"collection_status": "collected", "IsLogging": True},
            "EventSelectors": {"collection_status": "collected", "EventSelectors": [
                {"IncludeManagementEvents": True, "ReadWriteType": "All"}]},
            "CloudWatchLogsLogGroupArn": LOG, "CloudWatchLogsRoleArn": ROLE, "KmsKeyId": KEY,
            **fields}


def cluster():
    return {"name": "one", "Cluster": {"collection_status": "collected",
            "cluster": {"name": "one", "arn": CLUSTER, "version": "1.30"}}}


def monitor(*, tag=None):
    return {"MonitorArn": MONITOR, "Status": "ACTIVE", "MonitorType": "CUSTOM",
            "MonitorSpecification": {"Tags": {"Key": "Environment", "Values": [tag or "Prod"],
                                              "MatchOptions": ["EQUALS"]}}}


def subscription(*, subscriber=True):
    return {"SubscriptionArn": SUB, "MonitorArnList": [MONITOR],
            "Subscribers": [{"Address": "ops@example.test", "Type": "EMAIL"}] if subscriber else [],
            "ThresholdExpression": {"Dimensions": {"Key": "ANOMALY_TOTAL_IMPACT_ABSOLUTE",
                                                    "Values": ["100"]}}}


def beanstalk():
    return {"EnvironmentArn": ENV, "EnvironmentName": "prod", "Status": "Ready",
            "Configuration": {"collection_status": "collected", "hostmanager_options_complete": True, "ConfigurationSettings": [
                {"EnvironmentName": "prod", "OptionSettings": [
                    {"Namespace": "aws:elasticbeanstalk:hostmanager", "OptionName": "LogPublicationControl",
                     "Value": "true"}]}]},
            "S3LogDestination": {"collection_status": "collected", "bucket": "logs", "prefix": "env/", "resolved": True},
            "EnvironmentResources": {"collection_status": "collected", "LoadBalancers": [{"Name": "lb"}]},
            "AssociatedLoadBalancers": [{"Name": "lb", "Type": "application", "Listeners": [
                {"Protocol": "HTTPS", "Certificates": [{"CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/one"}], "DefaultActions": []},
                {"Protocol": "HTTP", "Certificates": [], "DefaultActions": [
                    {"Type": "redirect", "RedirectConfig": {"Protocol": "HTTPS"}}]}],
                "Attributes": [{"Key": "access_logs.s3.enabled", "Value": "true"}]}]}


def _case(cid, fail=False):
    i = facts()
    if cid == "aws_partner_role_external_ids_unique":
        one = {"Arn": ROLE, "AssumeRolePolicyDocument": {"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
             "Condition": {"StringEquals": {"sts:ExternalId": "alpha"}}}]}}
        other_arn = ROLE.replace("partner", "other")
        two = {"Arn": other_arn, "AssumeRolePolicyDocument": {"Statement": [
            {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
             "Condition": {"StringEquals": {"sts:ExternalId": "alpha" if fail else "beta"}}}]}}
        i["context"]["metadata"]["compliance_policy"]["partner_roles"] = policy(customer_roles=[
            {"role_arn": ROLE, "customer_id": "A"}, {"role_arn": other_arn, "customer_id": "B"}])
        add(i, "iam_role", [one, two], global_kind=True)
        return one, i
    if cid == "aws.pci.cloudtrail.authentication_events":
        t = trail()
        if fail:
            t["EventSelectors"]["EventSelectors"][0]["ReadWriteType"] = "ReadOnly"
        add(i, "cloudtrail_trail", [t])
        return {"scope": SCOPE}, i
    if cid == "aws_fedramp_cloudtrail_cloudwatch_integration":
        t = trail()
        add(i, "cloudtrail_trail", [t])
        add(i, "cloudtrail_delivery_permission", [{"role_arn": ROLE, "log_group_arn": LOG,
            "simulation_context_complete": True, "trust_valid": True,
            "decisions": {"logs:CreateLogStream": "allowed", "logs:PutLogEvents": "implicitDeny" if fail else "allowed"}}])
        return t, i
    if cid == "aws_fedramp_cloudtrail_destination_kms":
        t = trail()
        add(i, "cloudtrail_trail", [t])
        add(i, "kms_key", [key()])
        add(i, "cloudwatch_log_group", [{"arn": LOG, "kmsKeyId": "" if fail else KEY}])
        return t, i
    if cid == "aws_nist_codebuild_project_plaintext_env_variables_no_sensitive_aws_values":
        i["context"]["metadata"]["compliance_policy"]["codebuild_sensitive_values"] = policy(
            approved_secret_values=["secret"], sensitive_name_patterns=["TOKEN$"])
        project = {"name": "build", "Configuration": {"collection_status": "collected", "projects": [
            {"name": "build", "environment": {"environmentVariables": [
                {"name": "MY_TOKEN" if fail else "PUBLIC", "type": "PLAINTEXT", "value": "safe"}]}}]}}
        add(i, "codebuild_project", [project])
        return project, i
    if cid == "aws_eks_cluster_current_supported_version":
        i["context"]["metadata"]["compliance_policy"]["eks_version_floor"] = policy(min_version="1.31" if fail else "1.30")
        c = cluster(); add(i, "eks_cluster", [c]); return c, i
    if cid == "aws_eks_cluster_supported_version_catalog":
        i["context"]["metadata"]["compliance_policy"]["eks_version_support"] = policy(allowed_support_types=["STANDARD"])
        c = cluster(); add(i, "eks_cluster", [c])
        add(i, "eks_version_catalog", [{"region": REGION, "versions": [
            {"clusterVersion": "1.30", "status": "UNSUPPORTED" if fail else "SUPPORTED", "supportType": "STANDARD"}]}])
        return c, i
    if cid == "aws_eks_runtime_image_integrity":
        i["context"]["metadata"]["compliance_policy"]["eks_image_integrity"] = policy(
            designated_cluster_arns=[CLUSTER], approved_verifier_services=[{"namespace": "security", "name": "verifier"}])
        c = cluster(); add(i, "eks_cluster", [c])
        add(i, "k8s_admission_policy", [{"cluster_arn": CLUSTER, "validating_webhook_configurations": [
            {"metadata": {"name": "verify"}, "webhooks": [{"failurePolicy": "Ignore" if fail else "Fail",
             "clientConfig": {"service": {"namespace": "security", "name": "verifier"}},
             "rules": [{"operations": ["CREATE"], "apiGroups": [""], "apiVersions": ["v1"], "resources": ["pods"]}]}]}]}])
        return c, i
    if cid in {"aws_costexplorer_anomaly_alert", "aws_costexplorer_prod_anomaly_monitor", "aws_costexplorer_qa_anomaly_monitor"}:
        mode = "qa" if cid.endswith("qa_anomaly_monitor") else "prod"
        i["context"]["metadata"]["compliance_policy"]["cost_anomaly_alerts"] = policy(
            approved_recipients=["ops@example.test"], cost_allocation_tag_key="Environment",
            prod_tag_value="Prod", qa_tag_value="QA")
        add(i, "cost_anomaly_monitor", [monitor(tag="QA" if mode == "qa" else "Prod")], global_kind=True)
        add(i, "cost_anomaly_subscription", [subscription(subscriber=not fail)], global_kind=True)
        return {"scope": SCOPE}, i
    if cid in {"aws_cis_beanstalk_persistent_logs_s3", "aws_cis_elasticbeanstalk_https_listener",
               "aws_cis_elasticbeanstalk_load_balancer_access_logs"}:
        e = beanstalk()
        if cid == "aws_cis_beanstalk_persistent_logs_s3" and fail:
            e["Configuration"]["ConfigurationSettings"][0]["OptionSettings"][0]["Value"] = "false"
        elif cid == "aws_cis_elasticbeanstalk_https_listener" and fail:
            e["AssociatedLoadBalancers"][0]["Listeners"][0]["Certificates"] = []
        elif cid == "aws_cis_elasticbeanstalk_load_balancer_access_logs" and fail:
            e["AssociatedLoadBalancers"][0]["Attributes"][0]["Value"] = "false"
        add(i, "elastic_beanstalk_environment", [e]); return e, i
    if cid == "aws_backup_copy_encrypted":
        i["context"]["metadata"]["compliance_policy"]["remote_backup_vaults"] = policy(vault_arns=[VAULT])
        v = {"BackupVaultArn": VAULT, "Configuration": {"collection_status": "collected",
             "BackupVaultArn": VAULT, "EncryptionKeyArn": KEY}}
        add(i, "backup_vault", [v]); add(i, "kms_key", [key()])
        add(i, "backup_recovery_point", [{"RecoveryPointArn": f"arn:aws:backup:{REGION}:{ACCOUNT}:recovery-point:one",
            "BackupVaultArn": VAULT, "CreatedBy": {"CopyJobId": "job"}, "IsEncrypted": not fail}])
        return v, i
    raise AssertionError(cid)


@pytest.mark.parametrize("cid", list(sw.SPECS))
def test_signed_pass_and_fail(cid):
    good, index = _case(cid)
    assert evaluate_check(cid, good, index)[0] == "PASS", cid
    bad, index = _case(cid, fail=True)
    assert evaluate_check(cid, bad, index)[0] == "FAIL", cid


@pytest.mark.parametrize("cid", list(sw.SPECS))
def test_incomplete_malformed_and_missing_fact_are_unknown(cid):
    item, index = _case(cid)
    kind = sw.SPECS[cid]["kind"]
    incomplete = copy.deepcopy(index)
    incomplete["collections"][kind][0]["status"] = "partial"
    assert evaluate_check(cid, item, incomplete)[0] == "UNKNOWN", cid
    malformed = copy.deepcopy(index)
    malformed["collections"][kind][0]["items"] = "bad"
    assert evaluate_check(cid, item, malformed)[0] == "UNKNOWN", cid
    missing = copy.deepcopy(index)
    del missing["collections"][kind]
    assert evaluate_check(cid, item, missing)[0] == "UNKNOWN", cid
    foreign = copy.deepcopy(index)
    foreign["context"]["scope"] = "999999999999/eu-west-1"
    assert evaluate_check(cid, item, foreign)[0] == "UNKNOWN", cid


@pytest.mark.parametrize("cid", [
    "aws_partner_role_external_ids_unique", "aws_fedramp_cloudtrail_cloudwatch_integration",
    "aws_fedramp_cloudtrail_destination_kms", "aws_eks_runtime_image_integrity",
    "aws_cis_beanstalk_persistent_logs_s3", "aws_cis_elasticbeanstalk_https_listener",
    "aws_cis_elasticbeanstalk_load_balancer_access_logs", "aws_backup_copy_encrypted"])
def test_not_applicable_scope(cid):
    item, index = _case(cid)
    if cid == "aws_partner_role_external_ids_unique":
        index["context"]["metadata"]["compliance_policy"]["partner_roles"]["customer_roles"] = []
    elif cid.startswith("aws_fedramp_cloudtrail"):
        item["Status"]["IsLogging"] = False
    elif cid == "aws_eks_runtime_image_integrity":
        index["context"]["metadata"]["compliance_policy"]["eks_image_integrity"]["designated_cluster_arns"] = []
    elif cid.startswith("aws_cis_"):
        item["Status"] = "Terminated"
    else:
        index["context"]["metadata"]["compliance_policy"]["remote_backup_vaults"]["vault_arns"] = [
            VAULT.replace("remote", "elsewhere")]
    assert evaluate_check(cid, item, index)[0] == "NOT_APPLICABLE", cid


def test_partner_unconditioned_allow_is_a_failure_even_with_an_external_id():
    item, index = _case("aws_partner_role_external_ids_unique")
    item["AssumeRolePolicyDocument"]["Statement"].append({
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"}})
    assert evaluate_check("aws_partner_role_external_ids_unique", item, index)[0] == "FAIL"


def test_cloudtrail_restricted_advanced_selector_does_not_cover_all_authentication_events():
    item, index = _case("aws.pci.cloudtrail.authentication_events")
    selector = item["scope"]
    trail_row = index["collections"]["cloudtrail_trail"][0]["items"][0]
    trail_row["EventSelectors"] = {"collection_status": "collected", "AdvancedEventSelectors": [
        {"FieldSelectors": [{"Field": "eventCategory", "Equals": ["Management"]},
                            {"Field": "eventName", "Equals": ["ConsoleLogin"]}]}]}
    assert selector == SCOPE
    assert evaluate_check("aws.pci.cloudtrail.authentication_events", item, index)[0] == "FAIL"


def test_trail_disabled_cmk_fails_even_if_linked_log_group_is_unreadable():
    item, index = _case("aws_fedramp_cloudtrail_destination_kms")
    index["collections"]["kms_key"][0]["items"][0]["Metadata"]["KeyMetadata"]["KeyState"] = "Disabled"
    del index["collections"]["cloudwatch_log_group"]
    assert evaluate_check("aws_fedramp_cloudtrail_destination_kms", item, index)[0] == "FAIL"


def test_eks_cluster_scoped_webhook_rule_cannot_cover_pods():
    item, index = _case("aws_eks_runtime_image_integrity")
    rule = index["collections"]["k8s_admission_policy"][0]["items"][0]["validating_webhook_configurations"][0]["webhooks"][0]["rules"][0]
    rule["scope"] = "Cluster"
    assert evaluate_check("aws_eks_runtime_image_integrity", item, index)[0] == "FAIL"


def test_foreign_backup_point_is_unknown():
    item, index = _case("aws_backup_copy_encrypted")
    point = index["collections"]["backup_recovery_point"][0]["items"][0]
    point["BackupVaultArn"] = point["BackupVaultArn"].replace(ACCOUNT, "999999999999")
    assert evaluate_check("aws_backup_copy_encrypted", item, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("cid", list(sw.SPECS))
def test_malformed_native_field_is_unknown(cid):
    item, index = _case(cid)
    if cid == "aws_partner_role_external_ids_unique":
        item["AssumeRolePolicyDocument"] = 42
    elif cid == "aws.pci.cloudtrail.authentication_events":
        index["collections"]["cloudtrail_trail"][0]["items"][0]["EventSelectors"]["EventSelectors"][0]["ReadWriteType"] = 42
    elif cid == "aws_fedramp_cloudtrail_cloudwatch_integration":
        index["collections"]["cloudtrail_delivery_permission"][0]["items"][0]["decisions"]["logs:PutLogEvents"] = "maybe"
    elif cid == "aws_fedramp_cloudtrail_destination_kms":
        index["collections"]["kms_key"][0]["items"][0]["Metadata"]["KeyMetadata"]["KeyState"] = 42
    elif cid == "aws_nist_codebuild_project_plaintext_env_variables_no_sensitive_aws_values":
        item["Configuration"]["projects"][0]["environment"]["environmentVariables"][0]["value"] = 42
    elif cid == "aws_eks_cluster_current_supported_version":
        index["context"]["metadata"]["compliance_policy"]["eks_version_floor"]["min_version"] = "invalid"
    elif cid == "aws_eks_cluster_supported_version_catalog":
        index["collections"]["eks_version_catalog"][0]["items"][0]["versions"][0]["status"] = "FUTURE"
    elif cid == "aws_eks_runtime_image_integrity":
        index["collections"]["k8s_admission_policy"][0]["items"][0]["validating_webhook_configurations"][0]["webhooks"][0]["failurePolicy"] = 42
    elif cid.startswith("aws_costexplorer"):
        index["collections"]["cost_anomaly_subscription"][0]["items"][0]["ThresholdExpression"] = 42
    elif cid == "aws_cis_beanstalk_persistent_logs_s3":
        item["Configuration"]["ConfigurationSettings"][0]["OptionSettings"][0]["Value"] = 42
    elif cid == "aws_cis_elasticbeanstalk_https_listener":
        item["AssociatedLoadBalancers"][0]["Listeners"][0]["Protocol"] = 42
    elif cid == "aws_cis_elasticbeanstalk_load_balancer_access_logs":
        item["AssociatedLoadBalancers"][0]["Attributes"][0]["Value"] = "maybe"
    elif cid == "aws_backup_copy_encrypted":
        index["collections"]["backup_recovery_point"][0]["items"][0]["IsEncrypted"] = 42
    assert evaluate_check(cid, item, index)[0] == "UNKNOWN", cid


def test_absent_beanstalk_hostmanager_option_is_fail_only_on_complete_options():
    cid = "aws_cis_beanstalk_persistent_logs_s3"
    item, index = _case(cid)
    item["Configuration"]["ConfigurationSettings"][0]["OptionSettings"] = []
    assert evaluate_check(cid, item, index)[0] == "FAIL"
    item["Configuration"]["hostmanager_options_complete"] = False
    assert evaluate_check(cid, item, index)[0] == "UNKNOWN"


def test_partner_explicit_empty_external_id_is_a_failure():
    item, index = _case("aws_partner_role_external_ids_unique")
    item["AssumeRolePolicyDocument"]["Statement"][0]["Condition"]["StringEquals"]["sts:ExternalId"] = ""
    assert evaluate_check("aws_partner_role_external_ids_unique", item, index)[0] == "FAIL"
