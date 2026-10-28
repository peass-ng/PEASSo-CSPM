"""Public SSH settings on Azure ML compute instances."""

from peaso.analysis.internet_exposure import assess
from peaso.snapshot import make_snapshot, resources


SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001"
COMPUTE = SCOPE + "/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/w/computes/c"


def _assessment(public):
    snap = make_snapshot("azure", [SCOPE], [{"type": "ml_compute", "scope": SCOPE,
        "service": "Microsoft.MachineLearningServices", "status": "collected", "items": [{
            "id": COMPUTE, "properties": {"computeType": "ComputeInstance", "properties": {
                "sshSettings": {"sshPublicAccess": public, "sshPort": 50000}}}}]}])
    return next(a for a in assess(snap, resources(snap)) if a.resource["type"] == "ml_compute")


def test_compute_instance_public_ssh_policy():
    enabled = _assessment("Enabled")
    assert enabled.verdict() == "UNKNOWN"
    assert enabled.ports == {"tcp": ((50000, 50000),)}
    assert any(step["layer"] == "public_ssh" for step in enabled.path)
    assert _assessment("Disabled").verdict() == "PASS"
    assert _assessment(None).verdict() == "UNKNOWN"
