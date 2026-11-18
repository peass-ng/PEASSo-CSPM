"""Wire mutability modes are decided on frozen engine resources."""
import pytest
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

@pytest.mark.parametrize("mode,filters,expected", [
    ("IMMUTABLE", [], "PASS"), ("MUTABLE", [], "FAIL"),
    ("MUTABLE_WITH_EXCLUSION", [{"filterType": "WILDCARD", "filter": "release-*"}], "FAIL"),
    ("IMMUTABLE_WITH_EXCLUSION", [{"filterType": "WILDCARD", "filter": "latest"}], "FAIL"),
    ("IMMUTABLE_WITH_EXCLUSION", [{"filterType": "WILDCARD", "filter": "sha256-*.sig"}], "PASS"),
    ("FUTURE", [], "UNKNOWN"),
])
def test_observed_tag_modes(mode, filters, expected):
    scope = "123456789012/us-east-1"
    row = {"repositoryArn": "arn:aws:ecr:us-east-1:123456789012:repository/app",
           "imageTagMutability": mode, "imageTagMutabilityExclusionFilters": filters}
    snapshot = make_snapshot("aws", [scope], [{"type": "ecr_repository", "scope": scope,
        "status": "collected", "items": [row]}])
    finding, = evaluate_snapshot(snapshot, checks=["aws.ecr.immutable_tags"])["findings"]
    assert finding["status"] == expected
