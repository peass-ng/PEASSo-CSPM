"""Exercise every provider's exposure dispatcher after source unions."""

import pytest

from peaso.analysis.internet_exposure import assess, internet_findings
from peaso.snapshot import make_snapshot


@pytest.mark.parametrize("provider,scope", [
    ("aws", "123456789012/us-east-1"),
    ("gcp", "projects/example"),
    ("azure", "/subscriptions/00000000-0000-0000-0000-000000000000"),
    ("k8s", "cluster"),
])
def test_exposure_dispatch_accepts_each_provider_and_related_snapshots(provider, scope):
    snapshot = make_snapshot(provider, [scope], [], created_at="2026-10-28T00:00:00+00:00")
    assert isinstance(assess(snapshot, [], related_snapshots=()), list)
    assert isinstance(internet_findings(snapshot, [], related_snapshots=()), list)
