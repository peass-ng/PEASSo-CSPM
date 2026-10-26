import pytest

from peaso.demo import demo_snapshot
from peaso.snapshot_public_identity import public_snapshot_adapter


@pytest.mark.parametrize("provider", ["aws", "gcp", "azure", "k8s"])
def test_demo_snapshot_passes_worker_public_snapshot_adapter(provider):
    # A demo connector has no scopes, so the worker trusts ["*"]; the final
    # publication must still accept every demo collection row.
    snapshot = demo_snapshot(provider)
    adapter = public_snapshot_adapter(lambda native: native, provider=provider, trusted_scopes=["*"])
    assert adapter(snapshot)["collections"]
