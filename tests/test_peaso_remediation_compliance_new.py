"""Signed new-check remediation shards stay bound to real registered predicates."""
import json
from pathlib import Path

import pytest

from peaso.checks.catalog import proposal_provenance_for
from peaso.remediation import _merge_compliance_reviewed, details_for, rules, template


AWS_ID = "aws_config_continuous_inventory"
AZURE_ID = "azure.cis.mysql_flexible_cmk"


def _candidate(check_id, status="approved"):
    return {"review_status": status,
            "proposed_spec_sha256": proposal_provenance_for(check_id)["signed_spec_sha256"],
            "summary": "Review the observed setting with the resource owner.",
            "steps": ["Inspect the current provider configuration before an approved change."],
            "references": ["https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html"]}


def _shard(tmp_path: Path, name: str, rows: dict) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(rows))
    return path




def test_new_remediation_rejects_wrong_provider(tmp_path):
    with pytest.raises(ValueError, match="ID/provider"):
        _merge_compliance_reviewed({}, ((_shard(tmp_path, "provider.json", {AWS_ID: _candidate(AWS_ID)}), "gcp"),))
    with pytest.raises(ValueError, match="ID/provider"):
        _merge_compliance_reviewed({}, ((_shard(tmp_path, "unsigned.json", {"aws_fake_new_id": _candidate(AWS_ID)}), "aws"),))


def test_new_remediation_drafts_stay_unrendered_and_status_is_bounded(tmp_path):
    candidate = _candidate(AWS_ID, "draft")
    value = {}
    _merge_compliance_reviewed(value, ((_shard(tmp_path, "draft.json", {AWS_ID: candidate}), "aws"),))
    assert value[AWS_ID] == candidate and value[AWS_ID]["review_status"] == "draft"
    candidate["review_status"] = "source_bound_pending_review"
    _merge_compliance_reviewed({}, ((_shard(tmp_path, "pending.json", {AWS_ID: candidate}), "aws"),))
    candidate["review_status"] = "reviewed_without_approval"
    with pytest.raises(ValueError, match="review status"):
        _merge_compliance_reviewed({}, ((_shard(tmp_path, "status.json", {AWS_ID: candidate}), "aws"),))


def test_new_remediation_rejects_duplicate_and_approved_conflict(tmp_path):
    candidate = _candidate(AWS_ID)
    first = _shard(tmp_path, "first.json", {AWS_ID: candidate})
    second = _shard(tmp_path, "second.json", {AWS_ID: candidate})
    with pytest.raises(ValueError, match="duplicate"):
        _merge_compliance_reviewed({}, ((first, "aws"), (second, "aws")))
    with pytest.raises(ValueError, match="approved template"):
        _merge_compliance_reviewed({AWS_ID: {"review_status": "approved", "summary": "Different approved text"}},
                                   ((first, "aws"),))
