"""Only an accepted table setting change creates the timestamp signal."""

from copy import deepcopy
from pathlib import Path

from peaso.attack_detection.aws_keyspaces_timestamps_next import normalize
from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
KEYSPACE = "synthetic"
TABLE = "records"
ARN = f"arn:aws:cassandra:us-east-1:{ACCOUNT}:/keyspace/{KEYSPACE}/table/{TABLE}"


def event():
    return {
        "eventSource": "cassandra.amazonaws.com", "eventName": "AlterTable",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-event", "eventTime": "2026-10-21T12:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": {
            "keyspaceName": KEYSPACE, "tableName": TABLE,
            "rawquery": (
                'ALTER TABLE "synthetic"."records" WITH CUSTOM_PROPERTIES = '
                "{'client_side_timestamps': {'status': 'enabled'}}"
            ),
        },
        "resources": [{"type": "AWS::Cassandra::Table", "ARN": ARN}],
    }




def test_denial_other_setting_and_foreign_resource_do_not_match():
    accepted = event()
    assert normalize(accepted) is not None
    denied = deepcopy(accepted); denied["errorCode"] = "AccessDeniedException"
    disabled = deepcopy(accepted); disabled["requestParameters"]["rawquery"] = (
        disabled["requestParameters"]["rawquery"].replace("enabled", "disabled")
    )
    unrelated = deepcopy(accepted); unrelated["requestParameters"]["rawquery"] = (
        'ALTER TABLE "synthetic"."records" ADD comment text '
        "/* client_side_timestamps: {'status': 'enabled'} */"
    )
    foreign = deepcopy(accepted); foreign["resources"][0]["ARN"] = ARN.replace(ACCOUNT, "111111111111")
    read_only = deepcopy(accepted); read_only["readOnly"] = True
    assert all(normalize(item) is None for item in (denied, disabled, unrelated, foreign, read_only))
