"""ECR package matches retain their selected image identity through grouping."""
import json

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
