"""Non-network AWS resources and the default IoT endpoint must not become internet-reachable assets."""

from peaso.analysis.internet_exposure import internet_findings
from peaso.snapshot import make_snapshot, resources

ACCOUNT, REGION = "111111111111", "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
AWS_OWNED = "518166789864"


def _collection(kind, items, scope=SCOPE, status="collected"):
    return {"type": kind, "scope": scope, "service": kind.split("_")[0], "status": status, "items": items}


def _findings(*collections, kind):
    snap = make_snapshot("aws", [SCOPE, f"{ACCOUNT}/global"], list(collections))
    return [f for f in internet_findings(snap, resources(snap))
            if (f["evidence"].get("source") or {}).get("resource_type") == kind]


def _config_rule(arn_tail, lambda_account, created_by=None):
    arn = f"arn:aws:config:{REGION}:{ACCOUNT}:config-rule/{arn_tail}"
    row = {"id": arn, "ConfigRuleArn": arn, "ConfigRuleName": arn_tail.rsplit("/", 1)[-1],
           "ConfigRuleState": "ACTIVE",
           "Source": {"Owner": "CUSTOM_LAMBDA",
                      "SourceIdentifier": f"arn:aws:lambda:{REGION}:{lambda_account}:function:evaluator"}}
    if created_by:
        row["CreatedBy"] = created_by
    return row


def test_service_linked_config_rule_is_not_exposure_but_foreign_custom_lambda_is():
    linked = _config_rule("aws-service-rule/securityhub.amazonaws.com/config-rule-abc", AWS_OWNED,
                          created_by="securityhub.amazonaws.com")
    legacy = _config_rule("aws-service-rule/securityhub.amazonaws.com/config-rule-def", AWS_OWNED)
    foreign = _config_rule("config-rule-xyz", "222222222222")
    rows = _findings(_collection("config_rule_lambda_delivery", [linked, legacy, foreign]),
                     kind="config_rule_lambda_delivery")
    assert [r["evidence"]["source"]["resource_id"] for r in rows] == [foreign["ConfigRuleArn"]]
    assert rows[0]["status"] == "FAIL"
    assert "internet" not in rows[0]["title"].lower()


def _trail(bucket):
    arn = f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/org-trail"
    return {"id": arn, "TrailARN": arn, "Name": "org-trail", "HomeRegion": REGION, "IsOrganizationTrail": True,
            "S3BucketName": bucket, "Status": {"collection_status": "collected", "IsLogging": True}}


def test_trail_to_bucket_of_unknown_owner_is_not_an_internet_fail():
    buckets = _collection("bucket", [{"Name": "own-bucket"}], scope=f"{ACCOUNT}/global")
    rows = _findings(_collection("cloudtrail", [_trail("org-trail-logs-333333333333")]), buckets, kind="cloudtrail")
    assert len(rows) == 1
    assert rows[0]["status"] == "UNKNOWN"
    assert "internet" not in rows[0]["title"].lower()
    assert _findings(_collection("cloudtrail", [_trail("own-bucket")]), buckets, kind="cloudtrail") == []


def _domain(name, domain_type="ENDPOINT", authorizer=None):
    arn = f"arn:aws:iot:{REGION}:{ACCOUNT}:domainconfiguration/{name}"
    return {"id": arn, "DomainConfigurationArn": arn, "DomainConfigurationName": name,
            "DomainName": f"abc123-ats.iot.{REGION}.amazonaws.com" if domain_type == "ENDPOINT" else "iot.example.com",
            "Status": "ENABLED", "DomainType": domain_type, "ServiceType": "DATA",
            "AuthenticationType": "DEFAULT", "ApplicationProtocol": "DEFAULT",
            "DefaultAuthorizerName": authorizer}


def _iot(domains, rules=(), aliases=(), status="collected"):
    return (_collection("iot_data_domain", list(domains)),
            _collection("iot_topic_rule", list(rules), status=status),
            _collection("iot_role_alias", list(aliases), status=status))


def test_default_iot_endpoint_is_silent_in_an_account_without_iot_configuration():
    assert _findings(*_iot([_domain("iot:Data-ATS")]), kind="iot_data_domain") == []


def test_default_iot_endpoint_is_reported_once_the_account_uses_iot():
    alias = {"id": "alias", "RoleAlias": "devices"}
    for collections in (_iot([_domain("iot:Data-ATS")], aliases=[alias]),
                        _iot([_domain("iot:Data-ATS"), _domain("custom", "CUSTOMER_MANAGED")]),
                        _iot([_domain("iot:Data-ATS", authorizer="token-auth")])):
        rows = [r for r in _findings(*collections, kind="iot_data_domain")
                if r["evidence"]["source"]["resource_id"].endswith("iot:Data-ATS")]
        assert len(rows) == 1 and rows[0]["status"] == "FAIL"
        assert rows[0]["evidence"]["authenticated_endpoint"] is True


def test_default_iot_endpoint_is_kept_when_iot_usage_was_not_collected():
    rows = _findings(*_iot([_domain("iot:Data-ATS")], status="denied"), kind="iot_data_domain")
    assert len(rows) == 1
