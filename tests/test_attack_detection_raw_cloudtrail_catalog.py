"""Catalog-only CloudTrail rules use a bounded, private envelope."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from urllib.parse import quote

import pytest

from peaso.attack_detection.rules import detect_aws_events, load_rules


ACCOUNT = "999999999999"
TABLE = f"arn:aws:cassandra:us-east-1:{ACCOUNT}:/keyspace/synthetic/table/records"
STREAM = TABLE + "/stream/synthetic-label"


def rule(directory: Path, *, extra: str = "", selection_extra: str = ""):
    (directory / "example.yml").write_text(
        """title: Synthetic CDC request
id: 14400000-0000-4000-8000-000000000001
status: experimental
description: Synthetic test rule.
references: [https://example.test/source]
logsource: {product: aws, service: cloudtrail}
detection:
  selection:
    event.source: cassandra.amazonaws.com
    event.name: GetRecords
    event.category: Data
    event.outcome: success
    resource.type: AWS::Cassandra::Table
""" + selection_extra + """  condition: selection
falsepositives: [Approved CDC poll]
level: medium
tags: [attack.collection]
x_hacktricks_technique_id: synthetic-cdc-request
x_cloudtrail_raw: true
""" + extra, encoding="utf-8")
    return load_rules(directory, product="aws")


def event():
    return {
        "eventSource": "cassandra.amazonaws.com", "eventName": "GetRecords",
        "eventType": "AwsApiCall", "eventCategory": "Data",
        "managementEvent": False, "readOnly": True,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-event", "eventTime": "2026-10-21T12:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
        "requestParameters": {"shardIterator": "private-opaque-iterator"},
        "resources": [
            {"type": "AWS::Cassandra::Stream", "ARN": STREAM},
            {"type": "AWS::Cassandra::Table", "ARN": TABLE},
        ],
    }


def test_new_catalog_rule_matches_without_service_normalizer(tmp_path):
    hits = detect_aws_events([event()], rule(tmp_path))
    assert len(hits) == 1
    assert hits[0].technique_id == "synthetic-cdc-request"
    assert hits[0].target_id.startswith("sha256:")
    assert TABLE not in str(hits)
    assert "private-opaque-iterator" not in str(hits)


def test_denials_cross_account_resources_and_wrong_categories_fail_closed(tmp_path):
    selected = rule(tmp_path)
    denied = deepcopy(event()); denied["errorCode"] = "AccessDeniedException"
    foreign = deepcopy(event()); foreign["resources"][1]["ARN"] = TABLE.replace(ACCOUNT, "111111111111")
    wrong = deepcopy(event()); wrong["eventCategory"] = "Management"
    no_resources = deepcopy(event()); no_resources["resources"] = []
    assert detect_aws_events([denied, foreign, wrong, no_resources], selected) == []








def test_raw_rule_grammar_rejects_request_fields_and_unsafe_modes(tmp_path):
    with pytest.raises(ValueError, match="Unsupported raw CloudTrail rule"):
        rule(tmp_path, selection_extra="    request.shard_iterator: private\n")
    with pytest.raises(ValueError, match="Unsupported raw CloudTrail rule"):
        rule(tmp_path, extra="x_cloudtrail_raw: maybe\n")


def test_existing_rules_do_not_match_the_raw_envelope(tmp_path):
    selected = rule(tmp_path)
    old = selected[0].__class__(**{**selected[0].__dict__, "raw_cloudtrail": False})
    assert detect_aws_events([event()], [old]) == []


def test_latest_catalog_preserves_raw_rule_opt_in(monkeypatch, tmp_path):
    from peaso.attack_detection import catalog

    rule(tmp_path)
    source = (tmp_path / "example.yml").read_text(encoding="utf-8")
    monkeypatch.setattr(catalog, "resolve_main_commit", lambda _repo: "a" * 40)
    monkeypatch.setattr(catalog, "fetch_rules", lambda _repo, _commit, _digest: {
        "aws/keyspaces/example.yml": source,
    })
    selected = catalog.select_catalog("latest", product="aws")
    assert selected.commit == "a" * 40
    assert selected.rules[0].raw_cloudtrail is True
    assert len(detect_aws_events([event()], selected.rules)) == 1


def test_resource_path_prefix_scopes_raw_rule_without_exposing_arn(tmp_path):
    selected = rule(tmp_path, extra="x_cloudtrail_resource_path_prefix: /keyspace/system\n",
                    selection_extra="    resource.path_scope_checked: true\n")
    assert detect_aws_events([event()], selected) == []
    system = deepcopy(event())
    system["resources"] = [{
        "type": "AWS::Cassandra::Table",
        "ARN": f"arn:aws:cassandra:us-east-1:{ACCOUNT}:/keyspace/system_schema/table/tables",
    }]
    hits = detect_aws_events([system], selected)
    assert len(hits) == 1
    assert "/keyspace/system" not in str(hits)


def test_resource_path_prefix_rejects_unsafe_or_nonraw_values(tmp_path):
    with pytest.raises(ValueError, match="Unsupported raw CloudTrail resource prefix"):
        rule(tmp_path, extra="x_cloudtrail_resource_path_prefix: ../private\n")
    with pytest.raises(ValueError, match="Unsupported raw CloudTrail resource prefix"):
        rule(tmp_path, extra="x_cloudtrail_resource_path_prefix: /keyspace/system\n")




def test_twinmaker_service_field_cannot_be_used_for_other_raw_events(tmp_path):
    with pytest.raises(ValueError, match="Unsupported raw CloudTrail rule"):
        rule(tmp_path, selection_extra="    actor.invoked_by_service: iottwinmaker.amazonaws.com\n")


