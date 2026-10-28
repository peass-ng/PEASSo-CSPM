import gzip
import json

from scripts.compare_aws_collect_coverage import compare


def test_coverage_gate_distinguishes_identity_and_status_regressions(tmp_path):
    before = tmp_path / "before.json.gz"
    after = tmp_path / "after.json.gz"

    def save(path, rows):
        with gzip.open(path, "wt") as stream:
            json.dump({"provider": "aws", "collections": rows}, stream)

    first = {"type": "bucket", "scope": "123456789012/us-east-1", "service": "s3",
             "account_id": "123456789012", "global": True, "status": "collected", "items": [{}]}
    second = {**first, "type": "ecs_task_definition", "service": "ecs", "global": False,
              "status": "empty", "items": []}
    save(before, [first, second])
    save(after, [first, {**second, "status": "partial"}])

    result = compare(before, after, expected_identities=2)
    assert not result["passed"]
    assert result["complete_to_incomplete_regressions"] == 1
    assert result["missing_identities"] == result["added_identities"] == 0
    assert result["after_incomplete"] == 1

    save(before, [first, {**second, "status": "partial"}])
    assert compare(before, after, expected_identities=2)["passed"]
    assert not compare(before, after, expected_identities=2, require_zero_incomplete=True)["passed"]

    save(after, [first, {**second, "status": "denied"}])
    result = compare(before, after, expected_identities=2)
    assert not result["passed"] and result["partial_to_unreadable_regressions"] == 1

    save(before, [first, second])
    save(after, [first, {**second, "type": "other"}])
    result = compare(before, after, expected_identities=2)
    assert not result["passed"]
    assert result["missing_identities"] == result["added_identities"] == 1
