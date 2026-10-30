"""Source-bound behavior for sw06 signed AWS checks."""
from __future__ import annotations

import copy

import pytest

from peaso.checks import CHECKS
from peaso.checks import compliance_new_sw06 as sw06  # noqa: F401  (registration side effect)


SCOPE = "123456789012/us-east-1"


def facts(kind, row, *, params=None, status="collected", scope=None):
    scope = scope or ("123456789012/global" if kind in {"route53_zone", "cloudfront_distribution"} else SCOPE)
    return {"context": {"provider": "aws", "scope": scope,
                         "created_at": "2026-10-12T00:00:00+00:00",
                         "metadata": {"parameters": params or {}}},
            "collections": {kind: [{"type": kind, "scope": scope,
                                    "status": status, "items": [row]}]},
            kind: [{"type": kind, "scope": scope, "data": row}]}


def run(check_id, row, *, params=None, status="collected", scope=None, missing=False):
    check = next(check for check in CHECKS if check.id == check_id)
    index = facts(check.kind, row, params=params, status=status, scope=scope)
    if missing:
        index["collections"] = {}
    return check.evaluate(row, index)[0]


def sg(rules):
    return {"GroupId": "sg-1", "IpPermissions": rules}


def rule(proto="tcp", first=22, last=22, cidr="::/0"):
    return {"IpProtocol": proto, "FromPort": first, "ToPort": last,
            "Ipv6Ranges": [{"CidrIpv6": cidr}]}


@pytest.mark.parametrize("check_id,port", [
    ("aws_security_group_common_ports_ipv6_all", 3306),
    ("aws_security_group_ssh_ipv6_all", 22),
])
def test_ipv6_port_checks(check_id, port):
    assert run(check_id, sg([rule(first=443, last=443)])) == "PASS"
    assert run(check_id, sg([rule(first=port, last=port)])) == "FAIL"
    assert run(check_id, sg([rule("-1")])) == "FAIL"
    assert run(check_id, sg([rule(cidr="2001:db8::/32")])) == "PASS"
    assert run(check_id, sg([rule(cidr="invalid")])) == "UNKNOWN"
    assert run(check_id, sg([rule()]), status="partial") == "UNKNOWN"
    assert run(check_id, sg([rule()]), missing=True) == "UNKNOWN"


def test_ipv6_tcp_udp_any_port():
    check = "aws_security_group_tcp_udp_ipv6_all"
    assert run(check, sg([rule("6", 8080, 8080, "2001:db8::/32")])) == "PASS"
    assert run(check, sg([rule("17", 443, 443)])) == "FAIL"
    assert run(check, sg([rule("-1")])) == "FAIL"
    assert run(check, sg([rule("bogus")])) == "UNKNOWN"
    assert run(check, sg([rule()]), status="denied") == "UNKNOWN"
    assert run(check, sg([rule()]), missing=True) == "UNKNOWN"


def test_msk_in_cluster_tls():
    check = "aws_msk_in_cluster_tls_enabled"
    row = {"ClusterArn": "arn:aws:kafka:us-east-1:123456789012:cluster/c/1", "ClusterType": "PROVISIONED",
           "Detail": {"ClusterInfo": {"ClusterArn": "arn:aws:kafka:us-east-1:123456789012:cluster/c/1",
                                      "Provisioned": {"EncryptionInfo": {"EncryptionInTransit": {"InCluster": True}}}}}}
    assert run(check, row) == "PASS"
    bad = copy.deepcopy(row)
    bad["Detail"]["ClusterInfo"]["Provisioned"]["EncryptionInfo"]["EncryptionInTransit"]["InCluster"] = False
    assert run(check, bad) == "FAIL"
    assert run(check, {**row, "ClusterType": "SERVERLESS"}) == "NOT_APPLICABLE"
    malformed = copy.deepcopy(row)
    malformed["Detail"]["ClusterInfo"]["Provisioned"]["EncryptionInfo"]["EncryptionInTransit"]["InCluster"] = "false"
    assert run(check, malformed) == "UNKNOWN"
    assert run(check, row, status="partial") == "UNKNOWN"
    assert run(check, row, missing=True) == "UNKNOWN"


def test_snapshot_trusted_accounts():
    check = "aws_ebs_snapshot_trusted_accounts"
    params = {"trusted_account_ids": ["210987654321"]}
    row = {"SnapshotId": "snap-1", "OwnerId": "123456789012",
           "CreateVolumePermissions": [{"UserId": "210987654321"}]}
    assert run(check, row, params=params) == "PASS"
    assert run(check, {**row, "CreateVolumePermissions": [{"Group": "all"}]}, params=params) == "FAIL"
    assert run(check, {**row, "CreateVolumePermissions": [{"UserId": "333333333333"}]}, params=params) == "FAIL"
    assert run(check, {**row, "CreateVolumePermissions": [{"UserId": 3}]}, params=params) == "UNKNOWN"
    assert run(check, row, params=params, status="partial") == "UNKNOWN"
    assert run(check, row, params=params, missing=True) == "UNKNOWN"
    assert run(check, row) == "UNKNOWN"


def test_vpn_authentication():
    check = "aws_client_vpn_authentication_configured"
    row = {"ClientVpnEndpointId": "cvpn-1", "Status": {"Code": "available"},
           "ServerCertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/x",
           "AuthenticationOptions": [{"Type": "federated-authentication"}]}
    assert run(check, row) == "PASS"
    assert run(check, {**row, "AuthenticationOptions": []}) == "FAIL"
    assert run(check, {**row, "Status": {"Code": "deleted"}}) == "NOT_APPLICABLE"
    assert run(check, {**row, "AuthenticationOptions": [{}]}) == "UNKNOWN"
    assert run(check, row, status="partial") == "UNKNOWN"
    assert run(check, row, missing=True) == "UNKNOWN"


def test_lambda_code_signing():
    check = "aws_lambda_code_signing_configured"
    arn = "arn:aws:lambda:us-east-1:123456789012:function:f"
    row = {"FunctionArn": arn, "Configuration": {"State": "Active"},
           "CodeSigning": {"FunctionArn": arn, "CodeSigningConfigArn": "csc-1"},
           "CodeSigningConfig": {"CodeSigningConfig": {"CodeSigningConfigArn": "csc-1",
               "AllowedPublishers": {"SigningProfileVersionArns": ["arn:aws:signer:us-east-1:123456789012:/signing-profiles/p/1"]},
               "CodeSigningPolicies": {"UntrustedArtifactOnDeployment": "Enforce"}}}}
    assert run(check, row) == "PASS"
    assert run(check, {**row, "CodeSigning": {"FunctionArn": arn, "CodeSigningConfigArn": ""}}) == "FAIL"
    assert run(check, {**row, "Configuration": {"State": "Inactive"}}) == "NOT_APPLICABLE"
    malformed = copy.deepcopy(row)
    malformed["CodeSigningConfig"]["CodeSigningConfig"]["AllowedPublishers"]["SigningProfileVersionArns"] = [3]
    assert run(check, malformed) == "UNKNOWN"
    assert run(check, row, status="partial") == "UNKNOWN"
    assert run(check, row, missing=True) == "UNKNOWN"


def test_lightsail_bucket_access_logging():
    check = "aws_cis_lightsail_bucket_access_logging"
    row = {"name": "b", "accessLogConfig": {"enabled": True, "destination": "logs"}}
    assert run(check, row) == "PASS"
    assert run(check, {**row, "accessLogConfig": {"enabled": False, "destination": "logs"}}) == "FAIL"
    assert run(check, {**row, "accessLogConfig": {"enabled": "true", "destination": "logs"}}) == "UNKNOWN"
    assert run(check, {"name": "b"}) == "UNKNOWN"
    assert run(check, row, status="partial") == "UNKNOWN"
    assert run(check, row, missing=True) == "UNKNOWN"


def test_route53_dnssec():
    check = "aws_route53_hosted_zone_dnssec_enabled"
    row = {"Id": "/hostedzone/Z1", "Config": {"PrivateZone": False},
           "DNSSEC": {"HostedZoneId": "/hostedzone/Z1", "Status": {"ServeSignature": "SIGNING"},
                      "KeySigningKeys": [{"Status": "ACTIVE"}]}}
    assert run(check, row) == "PASS"
    bad = copy.deepcopy(row)
    bad["DNSSEC"]["Status"]["ServeSignature"] = "NOT_SIGNING"
    assert run(check, bad) == "FAIL"
    assert run(check, {**row, "Config": {"PrivateZone": True}}) == "NOT_APPLICABLE"
    assert run(check, {**row, "DNSSEC": {"collection_status": "denied"}}) == "UNKNOWN"
    assert run(check, row, status="partial") == "UNKNOWN"
    assert run(check, row, missing=True) == "UNKNOWN"


def test_securityhub_critical_findings():
    check = "aws_securityhub_no_critical_findings"
    params = {"audited_regions": ["us-east-1"]}
    row = {"HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default",
           "CriticalFindings": {"collection_status": "empty", "covered_regions": ["us-east-1"], "items": []}}
    assert run(check, row, params=params) == "PASS"
    finding = {"Id": "finding-1", "Severity": {"Label": "CRITICAL"},
               "RecordState": "ACTIVE", "Region": "us-east-1", "Workflow": {"Status": "NEW"}}
    bad = {**row, "CriticalFindings": {"collection_status": "collected", "covered_regions": ["us-east-1"], "items": [finding]}}
    assert run(check, bad, params=params) == "FAIL"
    malformed = copy.deepcopy(bad)
    malformed["CriticalFindings"]["items"][0]["Severity"]["Label"] = "HIGH"
    assert run(check, malformed, params=params) == "UNKNOWN"
    assert run(check, row, params=params, status="partial") == "UNKNOWN"
    assert run(check, row, params=params, missing=True) == "UNKNOWN"
    assert run(check, row) == "UNKNOWN"


def test_kms_expiry():
    check = "aws_kms_key_expiry"
    row = {"KeyId": "key-1", "Metadata": {"KeyMetadata": {"KeyId": "key-1", "Origin": "EXTERNAL",
           "KeyState": "Enabled", "ValidTo": "2027-01-01T00:00:00+00:00"}}, "Tags": []}
    assert run(check, row) == "PASS"
    bad = copy.deepcopy(row)
    bad["Metadata"]["KeyMetadata"]["ValidTo"] = "2026-01-01T00:00:00+00:00"
    assert run(check, bad) == "FAIL"
    assert run(check, {**row, "Tags": [{"TagKey": "Retired", "TagValue": "true"}]}) == "FAIL"
    assert run(check, {**row, "Tags": "unavailable"}) == "UNKNOWN"
    assert run(check, row, status="partial") == "UNKNOWN"
    assert run(check, row, missing=True) == "UNKNOWN"


def test_kms_cryptoperiod():
    check = "aws.pci.kms.cryptoperiod_rotation"
    params = {"cardholder_data_key_ids": ["key-1"], "approved_cryptoperiod_days": 365}
    row = {"KeyId": "key-1", "Metadata": {"KeyMetadata": {"KeyId": "key-1", "Origin": "AWS_KMS"}},
           "Rotation": {"KeyRotationEnabled": True, "RotationPeriodInDays": 180}}
    assert run(check, row, params=params) == "PASS"
    assert run(check, {**row, "Rotation": {"KeyRotationEnabled": True, "RotationPeriodInDays": 730}}, params=params) == "FAIL"
    assert run(check, {**row, "KeyId": "key-2"}, params=params) == "NOT_APPLICABLE"
    assert run(check, {**row, "Rotation": {"KeyRotationEnabled": "true", "RotationPeriodInDays": 180}}, params=params) == "UNKNOWN"
    assert run(check, row, params=params, status="partial") == "UNKNOWN"
    assert run(check, row, params=params, missing=True) == "UNKNOWN"
    assert run(check, row) == "UNKNOWN"


def test_cloudfront_tls_policy():
    check = "aws.pci.cloudfront.min_tls_policy"
    params = {"minimum_tls_policy": "TLSv1.2_2021"}
    row = {"Id": "D1", "Config": {"DistributionConfig": {"ViewerCertificate": {
        "MinimumProtocolVersion": "TLSv1.2_2021"}}}}
    assert run(check, row, params=params) == "PASS"
    bad = copy.deepcopy(row)
    bad["Config"]["DistributionConfig"]["ViewerCertificate"]["MinimumProtocolVersion"] = "TLSv1"
    assert run(check, bad, params=params) == "FAIL"
    assert run(check, row) == "UNKNOWN"
    assert run(check, {"Id": "D1", "Config": {}}, params=params) == "UNKNOWN"
    assert run(check, row, params=params, status="partial") == "UNKNOWN"
    assert run(check, row, params=params, missing=True) == "UNKNOWN"


def test_lambda_expected_configuration():
    check = "aws.pci.lambda.expected_configuration"
    arn = "arn:aws:lambda:us-east-1:123456789012:function:f"
    config = {"FunctionArn": arn, "Runtime": "python3.12", "Role": "arn:aws:iam::123456789012:role/f",
              "Timeout": 30, "MemorySize": 256}
    row = {"FunctionArn": arn, "Configuration": config}
    params = {"expected_lambda_configuration": {arn: dict(config)}}
    assert run(check, row, params=params) == "PASS"
    bad = copy.deepcopy(row)
    bad["Configuration"]["Timeout"] = 60
    assert run(check, bad, params=params) == "FAIL"
    assert run(check, row) == "UNKNOWN"
    assert run(check, {**row, "Configuration": {"FunctionArn": arn, "Runtime": "python3.12"}}, params=params) == "UNKNOWN"
    assert run(check, row, params=params, status="partial") == "UNKNOWN"
    assert run(check, row, params=params, missing=True) == "UNKNOWN"


def test_client_vpn_authorize_all_groups():
    check = "aws.pci.client_vpn.no_authorize_all_groups"
    row = {"ClientVpnEndpointId": "cvpn-1", "AuthorizationRules": {
        "ClientVpnEndpointId": "cvpn-1", "collection_status": "collected", "items": [
            {"Status": {"Code": "active"}, "AuthorizeAllGroups": False, "DestinationCidr": "10.0.0.0/8"}]}}
    params = {"approved_authorize_all_groups_endpoint_ids": []}
    assert run(check, row, params=params) == "PASS"
    bad = copy.deepcopy(row)
    bad["AuthorizationRules"]["items"][0]["AuthorizeAllGroups"] = True
    assert run(check, bad, params=params) == "FAIL"
    assert run(check, bad, params={"approved_authorize_all_groups_endpoint_ids": ["cvpn-1"]}) == "PASS"
    malformed = copy.deepcopy(bad)
    malformed["AuthorizationRules"]["items"][0]["AuthorizeAllGroups"] = "true"
    assert run(check, malformed, params=params) == "UNKNOWN"
    assert run(check, row, params=params, status="partial") == "UNKNOWN"
    assert run(check, row, params=params, missing=True) == "UNKNOWN"


def test_vpc_required_service_endpoints():
    check_id = "aws_cis_vpc_service_endpoints_required"
    check = next(check for check in CHECKS if check.id == check_id)
    row = {"VpcId": "vpc-1"}
    endpoint = {"VpcEndpointId": "vpce-1", "VpcId": "vpc-1", "ServiceName": "com.amazonaws.us-east-1.s3",
                "State": "available"}
    params = {"required_vpc_endpoint_services": {"vpc-1": ["com.amazonaws.us-east-1.s3"]}}
    index = facts("vpc", row, params=params)
    index["collections"]["vpc_endpoint"] = [{"type": "vpc_endpoint", "scope": SCOPE,
        "status": "collected", "items": [endpoint]}]
    index["vpc_endpoint"] = [{"type": "vpc_endpoint", "scope": SCOPE, "data": endpoint}]
    assert check.evaluate(row, index)[0] == "PASS"
    bad = copy.deepcopy(index)
    bad["collections"]["vpc_endpoint"][0]["items"][0]["State"] = "pending"
    bad["vpc_endpoint"][0]["data"]["State"] = "pending"
    assert check.evaluate(row, bad)[0] == "FAIL"
    malformed = copy.deepcopy(index)
    malformed["collections"]["vpc_endpoint"][0]["items"][0]["State"] = "unexpected"
    malformed["vpc_endpoint"][0]["data"]["State"] = "unexpected"
    assert check.evaluate(row, malformed)[0] == "UNKNOWN"
    partial = copy.deepcopy(index)
    partial["collections"]["vpc_endpoint"][0]["status"] = "partial"
    assert check.evaluate(row, partial)[0] == "UNKNOWN"
    missing = copy.deepcopy(index)
    missing["collections"].pop("vpc_endpoint")
    assert check.evaluate(row, missing)[0] == "UNKNOWN"


def test_lightsail_bucket_instance_access():
    check = "aws_cis_lightsail_bucket_instance_access"
    instance = "arn:aws:lightsail:us-east-1:123456789012:Instance/i"
    row = {"name": "bucket-1", "resourcesReceivingAccess": [instance]}
    params = {"required_lightsail_bucket_instance_arns": {"bucket-1": [instance]}}
    assert run(check, row, params=params) == "PASS"
    assert run(check, {**row, "resourcesReceivingAccess": []}, params=params) == "FAIL"
    assert run(check, row, params={"required_lightsail_bucket_instance_arns": {"bucket-1": []}}) == "NOT_APPLICABLE"
    assert run(check, {**row, "resourcesReceivingAccess": [3]}, params=params) == "UNKNOWN"
    assert run(check, row, params=params, status="partial") == "UNKNOWN"
    assert run(check, row, params=params, missing=True) == "UNKNOWN"


@pytest.mark.parametrize("check_id", ["aws_security_group_common_ports_ipv6_all", "aws_security_group_ssh_ipv6_all", "aws_security_group_tcp_udp_ipv6_all"])
def test_review_numeric_protocols_and_missing_identity(check_id):
    assert run(check_id, sg([rule("006")])) == "FAIL"
    assert run(check_id, sg([rule("999")])) == "UNKNOWN"
    assert run(check_id, {"GroupId": "", "IpPermissions": []}) == "UNKNOWN"


def test_review_projection_is_exact_and_native_identity_unique():
    check = next(check for check in CHECKS if check.id == "aws_security_group_ssh_ipv6_all")
    row = sg([])
    other = {"GroupId": "sg-2", "IpPermissions": []}
    index = facts(check.kind, row)
    index[check.kind].append({"type": check.kind, "scope": SCOPE, "data": other})
    index["collections"][check.kind][0]["items"] = [row, row]
    assert check.evaluate(row, index)[0] == "UNKNOWN"
    index["collections"][check.kind][0]["items"] = [row, other]
    assert check.evaluate(row, index)[0] == "PASS"
    other["GroupId"] = "sg-1"
    assert check.evaluate(row, index)[0] == "UNKNOWN"


@pytest.mark.parametrize("kind,check_id,field,arn", [
    ("lambda_function", "aws_lambda_code_signing_configured", "FunctionArn", "arn:aws:lambda:eu-west-1:123456789012:function:f"),
    ("msk_cluster", "aws_msk_in_cluster_tls_enabled", "ClusterArn", "arn:aws:kafka:us-east-1:999999999999:cluster/c/1"),
    ("securityhub_hub", "aws_securityhub_no_critical_findings", "HubArn", "arn:aws:securityhub:eu-west-1:123456789012:hub/default"),
])
def test_review_foreign_native_arn_in_same_scope_wrapper(kind, check_id, field, arn):
    row = {field: arn, "ClusterType": "SERVERLESS", "Configuration": {"State": "Inactive"},
           "CriticalFindings": {"collection_status": "empty", "covered_regions": ["us-east-1"], "items": []}}
    assert run(check_id, row, params={"audited_regions": ["us-east-1"]}) == "UNKNOWN"


def test_review_snapshot_grant_selector_and_coverage():
    row = {"SnapshotId": "snap-1", "OwnerId": "123456789012"}
    params = {"trusted_account_ids": ["210987654321"]}
    for grant in ({"Group": "all", "UserId": "210987654321"},
                  {"UserId": "210987654321", "_coverage": {"UserId": {"status": "denied"}}}):
        assert run("aws_ebs_snapshot_trusted_accounts", {**row, "CreateVolumePermissions": [grant]}, params=params) == "UNKNOWN"


@pytest.mark.parametrize("enabled", [False, True])
def test_review_lightsail_documented_destination_omission_and_mask(enabled):
    row = {"name": "b", "accessLogConfig": {"enabled": enabled}}
    assert run("aws_cis_lightsail_bucket_access_logging", row) == "FAIL"
    row["accessLogConfig"]["_coverage"] = {"destination": {"status": "denied"}}
    assert run("aws_cis_lightsail_bucket_access_logging", row) == "UNKNOWN"


def test_review_kms_disabled_rotation_without_optional_period_is_failure():
    row = {"KeyId": "key-1", "Metadata": {"KeyMetadata": {"KeyId": "key-1", "Origin": "AWS_KMS"}},
           "Rotation": {"collection_status": "collected", "KeyRotationEnabled": False}}
    params = {"cardholder_data_key_ids": ["key-1"], "approved_cryptoperiod_days": 365}
    assert run("aws.pci.kms.cryptoperiod_rotation", row, params=params) == "FAIL"
    row["Rotation"]["collection_status"] = "denied"
    assert run("aws.pci.kms.cryptoperiod_rotation", row, params=params) == "UNKNOWN"


def test_review_cloudfront_current_policies_and_default_certificate_floor():
    check_id = "aws.pci.cloudfront.min_tls_policy"
    certificate = {"CloudFrontDefaultCertificate": False, "MinimumProtocolVersion": "TLSv1.2_2025"}
    row = {"Id": "D1", "Config": {"DistributionConfig": {"ViewerCertificate": certificate}}}
    params = {"minimum_tls_policy": "TLSv1.2_2021"}
    assert run(check_id, row, params=params, scope="123456789012/global") == "PASS"
    certificate["CloudFrontDefaultCertificate"] = True
    assert run(check_id, row, params=params, scope="123456789012/global") == "FAIL"
    certificate["CloudFrontDefaultCertificate"] = "true"
    assert run(check_id, row, params=params) == "UNKNOWN"


def test_review_expected_lambda_negative_capacity_is_unknown():
    arn = "arn:aws:lambda:us-east-1:123456789012:function:f"
    expected = {"FunctionArn": arn, "Runtime": "python3.13", "Role": "arn:aws:iam::123456789012:role/f", "Timeout": -1, "MemorySize": 128}
    row = {"FunctionArn": arn, "Configuration": expected}
    params = {"expected_lambda_configuration": {arn: expected}}
    assert run("aws.pci.lambda.expected_configuration", row, params=params) == "UNKNOWN"


def test_review_vpn_safe_rule_still_requires_valid_destination():
    row = {"ClientVpnEndpointId": "cvpn-1", "AuthorizationRules": {"ClientVpnEndpointId": "cvpn-1", "collection_status": "collected", "items": [
        {"Status": {"Code": "active"}, "AuthorizeAllGroups": False, "DestinationCidr": "bad"}]}}
    assert run("aws.pci.client_vpn.no_authorize_all_groups", row, params={"approved_authorize_all_groups_endpoint_ids": []}) == "UNKNOWN"


def test_review_resolved_critical_finding_still_requires_identity():
    finding = {"Severity": {"Label": "CRITICAL"}, "RecordState": "ACTIVE", "Region": "us-east-1", "Workflow": {"Status": "RESOLVED"}}
    row = {"HubArn": "arn:aws:securityhub:us-east-1:123456789012:hub/default", "CriticalFindings": {"collection_status": "collected", "covered_regions": ["us-east-1"], "items": [finding]}}
    assert run("aws_securityhub_no_critical_findings", row, params={"audited_regions": ["us-east-1"]}) == "UNKNOWN"


def test_review_vpc_endpoint_projection_cannot_duplicate_one_good_row():
    check = next(check for check in CHECKS if check.id == "aws_cis_vpc_service_endpoints_required")
    row = {"VpcId": "vpc-1"}
    good = {"VpcEndpointId": "vpce-1", "VpcId": "vpc-1", "ServiceName": "com.amazonaws.us-east-1.s3", "State": "available"}
    other = {**good, "VpcEndpointId": "vpce-2", "VpcId": "vpc-2"}
    index = facts("vpc", row, params={"required_vpc_endpoint_services": {"vpc-1": [good["ServiceName"]]}})
    index["vpc_endpoint"] = [{"type": "vpc_endpoint", "scope": SCOPE, "data": x} for x in (good, other)]
    index["collections"]["vpc_endpoint"] = [{"type": "vpc_endpoint", "scope": SCOPE, "status": "collected", "items": [good, good]}]
    assert check.evaluate(row, index)[0] == "UNKNOWN"


def test_review_owner_parameters_survive_real_engine_context():
    from tests.archived_check_contract import evaluate_snapshot
    from peaso.snapshot import make_snapshot
    check_id = "aws_ebs_snapshot_trusted_accounts"
    row = {"SnapshotId": "snap-12345678", "OwnerId": "123456789012", "CreateVolumePermissions": [{"UserId": "210987654321"}]}
    snapshot = make_snapshot("aws", [SCOPE], [{"type": "ebs_snapshot", "scope": SCOPE, "service": "ec2", "status": "collected", "items": [row]}],
        created_at="2026-10-12T00:00:00+00:00", metadata={"parameters": {"trusted_account_ids": ["210987654321"]}})
    report = evaluate_snapshot(snapshot, checks=[check_id])
    findings = [row for row in report["findings"] if row["check_id"] == check_id]
    assert len(findings) == 1 and findings[0]["status"] == "PASS"


@pytest.mark.parametrize("check_id,row,scope,params", [
    ("aws_security_group_ssh_ipv6_all", {"GroupId": "sg-1", "IpPermissions": []}, "123456789012/global", {}),
    ("aws_route53_hosted_zone_dnssec_enabled", {"Id": "Z1", "Config": {"PrivateZone": True}}, SCOPE, {}),
    ("aws.pci.cloudfront.min_tls_policy", {"Id": "D1", "Config": {"DistributionConfig": {"ViewerCertificate": {"MinimumProtocolVersion": "TLSv1.2_2021"}}}}, SCOPE, {"minimum_tls_policy": "TLSv1"}),
])
def test_review_global_and_regional_kinds_use_collector_scope(check_id, row, scope, params):
    assert run(check_id, row, scope=scope, params=params) == "UNKNOWN"


def test_review_explicit_empty_required_endpoint_services_is_valid_owner_policy():
    check = next(check for check in CHECKS if check.id == "aws_cis_vpc_service_endpoints_required")
    row = {"VpcId": "vpc-1"}
    index = facts("vpc", row, params={"required_vpc_endpoint_services": {"vpc-1": []}})
    index["vpc_endpoint"] = []
    index["collections"]["vpc_endpoint"] = [{"type": "vpc_endpoint", "scope": SCOPE, "status": "empty", "items": []}]
    assert check.evaluate(row, index)[0] == "PASS"


def test_review_kms_and_security_group_explicit_account_identity():
    row = {"KeyId": "key-1", "KeyArn": "arn:aws:kms:us-east-1:999999999999:key/key-1", "Metadata": {"KeyMetadata": {"KeyId": "key-1", "Origin": "AWS_KMS", "KeyState": "Enabled"}}, "Tags": []}
    assert run("aws_kms_key_expiry", row) == "UNKNOWN"
    row.pop("KeyArn")
    row["Metadata"]["KeyMetadata"]["AWSAccountId"] = "999999999999"
    assert run("aws_kms_key_expiry", row) == "UNKNOWN"
    assert run("aws_security_group_ssh_ipv6_all", {"GroupId": "sg-1", "OwnerId": "999999999999", "IpPermissions": []}) == "UNKNOWN"
