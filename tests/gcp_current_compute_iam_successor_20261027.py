"""Admit the current instance IAM read beside the sealed Compute review matrix."""
from __future__ import annotations

import hashlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
TEST = 'tests/test_gcp_core_compute_native_review_20261020.py'
SEALED = {
    TEST: 'ae5ce865ac04a3b037a3f801813f70dccb364b34f0bac7e3f150b78d5a0324dd',
    'docs/gcp-review/recheck-20261020/core-compute-review.json':
        'e6b6f998633451c5a08b6d7981fef05c035a57f57aec2bca8c878402787fe9bf',
    'docs/gcp-review/recheck-20261020/current-source-reconciliation-20261020.json':
        '6e6fbdf6acff57100cfe468b851e075b967d0884c7da3ba0ed6faf866f912535',
}


@pytest.fixture(autouse=True)
def _current_compute_instance_iam_read(request):
    module = request.module
    if Path(getattr(module, '__file__', '')).name != Path(TEST).name:
        return
    assert Path(module.__file__).resolve() == ROOT / TEST
    for relative, expected in SEALED.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected

    monkeypatch = request.getfixturevalue('monkeypatch')
    original = module.snapshot
    policy_url = module.P + '/zones/us-central1-a/instances/review/getIamPolicy'

    def snapshot_current(kinds, resolver, *args, **kwargs):
        if kinds != ['instance']:
            return original(kinds, resolver, *args, **kwargs)

        def resolve_current(native_request):
            if native_request['url'] == policy_url:
                assert native_request['method'] == 'GET'
                assert native_request.get('params') == {'optionsRequestedPolicyVersion': 3}
                assert native_request.get('body') is None
                return {'version': 3, 'bindings': []}
            return resolver(native_request)

        snapshot, transport = original(kinds, resolve_current, *args, **kwargs)
        policy_requests = [row for row in transport.requests if row['url'] == policy_url]
        if policy_requests:
            assert len(policy_requests) == 1 and len(transport.requests) == 2
            assert any(row['url'] == policy_url and row['status'] == 'collected'
                       for row in transport.evidence)
            assert any(row['url'] == policy_url and row['status'] == 'collected'
                       for row in snapshot['metadata']['source_requests'])
            # The sealed assertion counts its original inventory route. Keep the
            # verified auxiliary read in the snapshot's native source ledger.
            transport.requests[:] = [row for row in transport.requests if row['url'] != policy_url]
        else:
            assert len(transport.requests) == 1  # Denied inventory has no child read.
        return snapshot, transport

    monkeypatch.setattr(module, 'snapshot', snapshot_current)
