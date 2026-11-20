"""Compact reproducible registry fixtures; never used to evaluate real snapshots."""
CASES = {}


def nest(path, value):
    result = value
    for part in reversed(path.split(".")):
        result = {part: result}
    return result


# aws_config_all_resources_recorded: its evaluator module is hash-pinned, so its shared fixtures live here.
# One account/Region scope over the complete config_recorder inventory (same envelope as scope_fixture).
_CONFIG_SCOPE = {"scope": "123456789012/us-east-1"}
_CONFIG_ALL = {"allSupported": True, "includeGlobalResourceTypes": True, "resourceTypes": [],
    "exclusionByResourceTypes": {"resourceTypes": []}, "recordingStrategy": {"useOnly": "ALL_SUPPORTED_RESOURCE_TYPES"}}
_CONFIG_EXCLUDED = {"allSupported": False, "includeGlobalResourceTypes": False, "resourceTypes": [],
    "exclusionByResourceTypes": {"resourceTypes": ["AWS::EC2::NetworkInterface"]},
    "recordingStrategy": {"useOnly": "EXCLUSION_BY_RESOURCE_TYPES"}}


def _config_index(group, last="Success"):
    recorder = {"name": "default", "roleARN": "arn:aws:iam::123456789012:role/config-recorder", "recordingGroup": group,
        "Status": {"ConfigurationRecordersStatus": [{"name": "default", "recording": True, "lastStatus": last}],
                   "collection_status": "collected"}}
    return {"collections": {"config_recorder": [{"type": "config_recorder", "scope": _CONFIG_SCOPE["scope"],
        "status": "collected", "items": [recorder], "global": True, "account_id": "123456789012"}]}}


CASES["aws_config_all_resources_recorded"] = {
    "pass": _CONFIG_SCOPE, "pass_index": _config_index(_CONFIG_ALL),
    "fail": _CONFIG_SCOPE, "fail_index": _config_index(_CONFIG_EXCLUDED),
    "unknown": _CONFIG_SCOPE, "unknown_index": _config_index(_CONFIG_ALL, last="Pending"),
    "missing": {}, "malformed": _CONFIG_SCOPE, "index": _config_index("malformed")}

CASES["aws.ec2.prevent_public_snapshot_sharing"] = {
    "pass": {"SnapshotBlockPublicAccessState": "block-new-sharing"},
    "fail": {"SnapshotBlockPublicAccessState": "unblocked"},
    "unknown": {"SnapshotBlockPublicAccessState": "unexpected"},
}

# Central cases for the three native intake IDs; fixture-only import avoids registry cycles.
from .central_native_fixtures import install as _install_central_native_fixtures
_install_central_native_fixtures(CASES)
del _install_central_native_fixtures

# Reviewed real collector-shaped cases for the single signed remaining-native batch.
import json as _batch_json
from pathlib import Path as _BatchPath
_batch_cases = _batch_json.loads(_BatchPath(__file__).with_name('central_batch_fixtures.json').read_text())
if set(CASES) & set(_batch_cases):
    raise ValueError('remaining-native fixture IDs overlap existing cases')
CASES.update(_batch_cases)


def restore_remaining_batch_cases():
    """Keep reviewed batch cases after legacy modules install dormant fixtures."""
    CASES.update(_batch_cases)


del _batch_json, _BatchPath
