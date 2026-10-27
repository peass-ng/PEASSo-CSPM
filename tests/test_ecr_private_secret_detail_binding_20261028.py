"""ECR package matches retain their selected image identity through grouping."""
import json
import hashlib
from pathlib import Path

import pytest

from peaso import secret_evidence as private
from peaso.secret_findings import deduplicate_secret_findings
from peaso.secret_scanning import _fingerprint


CHECK = 'aws.review.ecr_repository.package_content_secret_indicators'
SCOPE = '123456789012/us-east-1'
REPO = 'arn:aws:ecr:us-east-1:123456789012:repository/fixture'
DIGEST = 'sha256:' + 'a' * 64
LAYER = 'sha256:' + 'b' * 64
IMAGE = REPO + '@' + DIGEST
VALUE = 'synthetic-ecr-credential-Q9w8e7R6!'


def finding(*, check=CHECK, source=IMAGE, fingerprint=None):
    fingerprint = fingerprint or _fingerprint(VALUE)
    return {'id': 'native', 'provider': 'aws', 'check_id': check, 'status': 'FAIL',
            'resource_id': 'inventory-hash', 'native_resource_id': REPO,
            'scope': SCOPE, 'frameworks': [], 'evidence': {
                'resource_id': source, 'secret_leaks': [{'fingerprint': fingerprint,
                    'detectors': [{'engine': 'kingfisher', 'rule': 'synthetic'}],
                    'locations': [{'path': 'app/config.env', 'line': 3, 'layer': LAYER}]}]}}


def test_ecr_grouped_finding_binds_exact_private_image_match():
    cipher = private.EphemeralCipher()
    fp = _fingerprint(VALUE)
    with private.capture(cipher, tenant='owner', scan_id='scan') as sink:
        with private.source_context(resource_id=IMAGE, scope=SCOPE, image_digest=DIGEST,
                                    layer=LAYER, check_ids={CHECK}):
            private.remember(VALUE, fp, path='app/config.env', line=3,
                             engine='kingfisher', rule='synthetic')
        document = sink.document()
    grouped, = deduplicate_secret_findings([finding()])
    assert grouped['evidence']['secret_leaks'][0]['locations'][0]['resource_id'] == IMAGE
    assert VALUE not in json.dumps(grouped)
    assert VALUE not in json.dumps(document)
    detail = private.details(grouped, document, cipher, tenant='owner', scan_id='scan')
    assert detail['status'] == 'available'
    assert [match['value'] for match in detail['matches']] == [VALUE]
    assert detail['matches'][0]['locations'][0]['resource_id'] == IMAGE


def test_ecr_binding_rejects_other_image_and_untrusted_source_identity():
    cipher = private.EphemeralCipher()
    fp = _fingerprint(VALUE)
    with private.capture(cipher, tenant='owner', scan_id='scan') as sink:
        with private.source_context(resource_id=IMAGE, scope=SCOPE, layer=LAYER, check_ids={CHECK}):
            private.remember(VALUE, fp, path='app/config.env', line=3,
                             engine='kingfisher', rule='synthetic')
        document = sink.document()
    other = REPO + '@sha256:' + 'c' * 64
    grouped, = deduplicate_secret_findings([finding(source=other)])
    assert private.details(grouped, document, cipher, tenant='owner', scan_id='scan')['status'] == 'unavailable'
    for source in (REPO + '@sha256:bad', 'arn:aws:ecr:us-east-1:123456789012:repository/other@' + DIGEST):
        grouped, = deduplicate_secret_findings([finding(source=source)])
        assert grouped['evidence']['secret_leaks'][0]['locations'][0]['resource_id'] == REPO
    grouped, = deduplicate_secret_findings([finding(check='aws.review.other')])
    assert grouped['evidence']['secret_leaks'][0]['locations'][0]['resource_id'] == REPO


def test_reviewed_source_transition_reconstructs_only_the_pinned_predecessor():
    from peaso import private_secret_source_epoch_20261021 as epoch
    from peaso.checks import private_secret_shared_source_successor_20261021 as shared

    root = Path(__file__).resolve().parents[1]
    relative = 'peaso/secret_findings.py'
    current = (root / relative).read_bytes()
    receipt, _ = epoch._receipt()
    transition = receipt['current_reviewed_files'][relative]
    assert transition['current_sha256'] == hashlib.sha256(current).hexdigest()
    assert transition['predecessor_sha256'] == '5ca5fa75a345863b6c266f7b1055c4423c7d8a99f190542dbef4ce542919e470'
    previous = epoch.predecessor_bytes(relative, current, transition['predecessor_sha256'], root)
    assert hashlib.sha256(previous).hexdigest() == transition['predecessor_sha256']
    assert b'_secret_location_resource' not in previous
    with pytest.raises(epoch.AdmissionError):
        epoch.predecessor_bytes(relative, current + b'\n', transition['predecessor_sha256'], root)
    with pytest.raises(epoch.AdmissionError):
        epoch.predecessor_bytes(relative, current, '0' * 64, root)
    callable_transition = shared._private_receipt()['provider_group_callables'][relative + ':deduplicate_secret_findings']
    assert callable_transition['predecessor_sha256'] == 'd5a2e6dff15f82e6508fe0f38758e3f53fd2ff099766b958e750276b1eb9bdfe'
    row = {'path': relative, 'qualname': 'deduplicate_secret_findings',
           'sha256': callable_transition['predecessor_sha256'], 'defaults': None, 'kwdefaults': None}
    shared._check_function(deduplicate_secret_findings, row, root, {})
