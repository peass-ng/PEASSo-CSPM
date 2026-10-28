"""CloudFormation StackSet target-account declaration."""
from peaso.analysis.internet_exposure import Inventory, _aws_cloudformation_stack_instance
from peaso.collectors import aws, aws_facts_ext as facts


ACCOUNT = "123456789012"
TARGET = "999999999999"
REGION = "us-east-1"
SCOPE = f"{ACCOUNT}/{REGION}"
STACK = f"arn:aws:cloudformation:{REGION}:{TARGET}:stack/prod/abc123"


def _assess(data, trusted=()):
    resource = {"id": f"{SCOPE}/cloudformation_stack_instance/prod/{TARGET}",
                "scope": SCOPE, "type": "cloudformation_stack_instance", "data": data}
    snapshot = {"provider": "aws", "scopes": [SCOPE],
                "metadata": {"trusted_scope_ids": list(trusted)},
                "collections": [{"type": resource["type"], "scope": SCOPE, "status": "collected"}]}
    return _aws_cloudformation_stack_instance(snapshot, Inventory(snapshot, [resource]), resource)


def test_stackset_collector_and_foreign_target_assessment():
    class Requests:
        def pages(self, session, service, region, operation, expression, **kwargs):
            if operation == "list_stack_sets":
                assert kwargs == {"Status": "ACTIVE"}
                return aws.ReadResult([{"StackSetName": "prod", "StackSetId": "prod:1234",
                    "PermissionModel": "SELF_MANAGED"}], "collected")
            assert (operation, kwargs) == ("list_stack_instances", {"StackSetName": "prod"})
            return aws.ReadResult([{"StackSetId": "prod:1234", "Account": TARGET,
                "Region": REGION, "StackId": STACK, "Status": "CURRENT",
                "ParameterOverrides": [{"ParameterKey": "PASSWORD", "ParameterValue": "SYNTHETIC_SECRET"}]}], "collected")
    read = facts.FETCHERS["cloudformation_stack_instance"](Requests(), None, REGION, ACCOUNT)
    assert read.status == "collected" and len(read.items) == 1
    assert "SYNTHETIC_SECRET" not in str(read.items)
    found = _assess(read.items[0])
    assert found.verdict() == "FAIL" and found.external_ids == [TARGET]
    assert _assess(read.items[0], trusted=[TARGET]) is None


def test_inoperable_or_mismatched_stackset_target_is_unknown():
    row = {"StackSetName": "prod", "StackSetId": "prod:1234", "Account": TARGET,
           "Region": REGION, "StackId": STACK, "Status": "INOPERABLE"}
    assert _assess(row).verdict() == "UNKNOWN"
    row["Status"] = "CURRENT"
    row["StackId"] = STACK.replace(TARGET, ACCOUNT)
    assert _assess(row).verdict() == "UNKNOWN"
