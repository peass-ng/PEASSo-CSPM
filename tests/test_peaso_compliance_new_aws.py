"""Semantic fixtures for signed, source-bound AWS compliance additions."""
from peaso.checks import evaluate_check
from peaso.checks import compliance_new_aws  # noqa: F401  (registration side effect)


def evaluate(check_id, item, index=None):
    return evaluate_check(check_id, item, index or {})


def test_cloudfront_failover_requires_existing_distinct_origins_and_codes():
    check_id = "aws_cloudfront_origin_failover_configured"
    origins = {"Quantity": 2, "Items": [{"Id": "primary"}, {"Id": "secondary"}]}
    group = {"Id": "failover", "Members": {"Quantity": 2, "Items": [{"OriginId": "primary"}, {"OriginId": "secondary"}]},
             "FailoverCriteria": {"StatusCodes": {"Quantity": 2, "Items": [500, 503]}}}
    item = {"Config": {"DistributionConfig": {"Origins": origins, "OriginGroups": {"Quantity": 1, "Items": [group]}}}}
    assert evaluate(check_id, item)[0] == "PASS"
    assert evaluate(check_id, {"Config": {"DistributionConfig": {"Origins": origins, "OriginGroups": {"Quantity": 0}}}})[0] == "FAIL"
    assert evaluate(check_id, {"Config": {"DistributionConfig": {"Origins": origins}}})[0] == "FAIL"
    bad = {**group, "Members": {"Quantity": 2, "Items": [{"OriginId": "primary"}, {"OriginId": "missing"}]}}
    assert evaluate(check_id, {"Config": {"DistributionConfig": {"Origins": origins, "OriginGroups": {"Quantity": 1, "Items": [bad]}}}})[0] == "FAIL"
    unsupported = {**group, "FailoverCriteria": {"StatusCodes": {"Quantity": 1, "Items": [418]}}}
    assert evaluate(check_id, {"Config": {"DistributionConfig": {"Origins": origins, "OriginGroups": {"Quantity": 1, "Items": [unsupported]}}}})[0] == "UNKNOWN"
    assert evaluate(check_id, {"Config": {"DistributionConfig": {"Origins": origins, "_coverage": {"OriginGroups": {"status": "denied"}}}}})[0] == "UNKNOWN"
    truncated = {"Config": {"DistributionConfig": {"Origins": origins, "OriginGroups": {"Quantity": 2, "Items": [group]}}}}
    assert evaluate(check_id, truncated)[0] == "UNKNOWN"


def test_config_continuous_recorder_requires_matching_status_and_all_fields():
    check_id = "aws_config_continuous_inventory"
    item = {"name": "default", "recordingGroup": {"allSupported": True},
            "recordingMode": {"recordingFrequency": "CONTINUOUS"},
            "Status": {"ConfigurationRecordersStatus": [{"name": "default", "recording": True}]}}
    assert evaluate(check_id, item)[0] == "PASS"
    assert evaluate(check_id, {**item, "recordingMode": {"recordingFrequency": "DAILY"}})[0] == "FAIL"
    daily_override = {"recordingFrequency": "DAILY", "resourceTypes": ["AWS::EC2::Instance"]}
    assert evaluate(check_id, {**item, "recordingMode": {"recordingFrequency": "CONTINUOUS", "recordingModeOverrides": [daily_override]}})[0] == "FAIL"
    assert evaluate(check_id, {**item, "recordingMode": {"recordingFrequency": "CONTINUOUS", "recordingModeOverrides": [{**daily_override, "recordingFrequency": "CONTINUOUS"}]}})[0] == "PASS"
    assert evaluate(check_id, {**item, "recordingMode": {"recordingFrequency": "CONTINUOUS", "recordingModeOverrides": [{**daily_override, "recordingFrequency": "BOGUS"}]}})[0] == "UNKNOWN"
    assert evaluate(check_id, {**item, "Status": {"ConfigurationRecordersStatus": []}})[0] == "UNKNOWN"
    assert evaluate(check_id, {**item, "Status": {"collection_status": "denied"}})[0] == "UNKNOWN"
    assert evaluate(check_id, {**item, "recordingGroup": {"allSupported": "true"}})[0] == "UNKNOWN"


def test_acm_lifecycle_uses_snapshot_clock_and_in_use_scope():
    check_id = "aws_acm_certificate_lifecycle"
    clock = {"context": {"created_at": "2026-10-12T00:00:00Z"}}
    body = {"Certificate": {"Certificate": {"Status": "ISSUED", "NotAfter": "2026-11-20T00:00:00Z",
                                        "RenewalEligibility": "INELIGIBLE", "InUseBy": ["arn:aws:elasticloadbalancing:eu-west-1:111122223333:loadbalancer/app/example"]}}}
    assert evaluate(check_id, body, clock)[0] == "PASS"
    far_expiry_without_eligibility = {"Certificate": {"Certificate": {key: value for key, value in body["Certificate"]["Certificate"].items() if key != "RenewalEligibility"}}}
    assert evaluate(check_id, far_expiry_without_eligibility, clock)[0] == "PASS"
    assert evaluate(check_id, {"Certificate": {"Certificate": {**body["Certificate"]["Certificate"], "NotAfter": "2026-10-20T00:00:00Z"}}}, clock)[0] == "FAIL"
    assert evaluate(check_id, {"Certificate": {"Certificate": {**body["Certificate"]["Certificate"], "NotAfter": "2026-10-20T00:00:00Z", "RenewalEligibility": "ELIGIBLE"}}}, clock)[0] == "PASS"
    assert evaluate(check_id, {"Certificate": {"Certificate": {**body["Certificate"]["Certificate"], "InUseBy": []}}}, clock)[0] == "NOT_APPLICABLE"
    assert evaluate(check_id, {"Certificate": {"Certificate": {**body["Certificate"]["Certificate"], "NotAfter": "2026-10-20T00:00:00Z", "RenewalEligibility": None}}}, clock)[0] == "UNKNOWN"
    assert evaluate(check_id, {"Certificate": {"Certificate": {**far_expiry_without_eligibility["Certificate"]["Certificate"], "NotAfter": "2026-10-11T00:00:00Z"}}}, clock)[0] == "FAIL"
    assert evaluate(check_id, body, {})[0] == "UNKNOWN"


def test_cloudwatch_action_requires_enabled_switch_and_any_state_action():
    check_id = "aws_nist_cloudwatch_alarm_action_enabled"
    item = {"ActionsEnabled": True, "AlarmActions": [], "OKActions": ["arn:aws:sns:us-east-1:111122223333:alerts"], "InsufficientDataActions": []}
    assert evaluate(check_id, item)[0] == "PASS"
    assert evaluate(check_id, {**item, "ActionsEnabled": False})[0] == "FAIL"
    assert evaluate(check_id, {**item, "OKActions": []})[0] == "FAIL"
    assert evaluate(check_id, {**item, "AlarmActions": "not-a-list"})[0] == "UNKNOWN"
    assert evaluate(check_id, {"ActionsEnabled": True})[0] == "UNKNOWN"


def test_config_all_supported_resources_respects_exclusion_strategy():
    check_id = "aws_config_recorder_all_supported_resources"
    assert evaluate(check_id, {"recordingGroup": {"allSupported": True}})[0] == "PASS"
    assert evaluate(check_id, {"recordingGroup": {"allSupported": False, "resourceTypes": ["AWS::EC2::Instance"]}})[0] == "FAIL"
    group = {"allSupported": False, "recordingStrategy": {"useOnly": "EXCLUSION_BY_RESOURCE_TYPES"},
             "exclusionByResourceTypes": {"resourceTypes": []}}
    assert evaluate(check_id, {"recordingGroup": group})[0] == "PASS"
    assert evaluate(check_id, {"recordingGroup": {**group, "exclusionByResourceTypes": {"resourceTypes": ["AWS::S3::Bucket"]}}})[0] == "FAIL"
    assert evaluate(check_id, {"recordingGroup": {**group, "exclusionByResourceTypes": {"collection_status": "denied"}}})[0] == "UNKNOWN"
    assert evaluate(check_id, {})[0] == "UNKNOWN"
