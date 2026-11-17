"""Automatic ECR image selection skips cosign/sigstore signatures and attestations.

Signed repositories push a small signature/attestation artifact right after
every image, so "newest pushed digest" must mean "newest container image".
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from peaso.checks import evaluate_check
from peaso.checks import claude2_aws_b  # noqa: F401 - register native checks
from peaso.collectors import aws_ecr_repository_lanes_20261029 as lanes
from peaso.collectors import aws_package_content_indicators as content
from peaso.collectors.aws import ReadResult
from peaso.collectors.aws_facts_data_identity import _ecr_repository

ACCOUNT, REGION, REPO = '111122223333', 'us-east-1', 'team/api'
OCI = 'application/vnd.oci.image.manifest.v1+json'
DOCKER = 'application/vnd.docker.distribution.manifest.v2+json'
INDEX = 'application/vnd.oci.image.index.v1+json'
OCI_CONFIG = 'application/vnd.oci.image.config.v1+json'
DOCKER_CONFIG = 'application/vnd.docker.container.image.v1+json'
WHEN = datetime(2026, 11, 17, 12, tzinfo=timezone.utc)


def digest(n):
    return 'sha256:' + format(n, '064x')


def image(n, minutes, size=25_000_000, manifest=OCI, artifact=OCI_CONFIG, tags=('v1',)):
    return {'registryId': ACCOUNT, 'repositoryName': REPO, 'imageDigest': digest(n),
            'imagePushedAt': WHEN + timedelta(minutes=minutes), 'imageSizeInBytes': size,
            'imageManifestMediaType': manifest, 'artifactMediaType': artifact, 'imageTags': list(tags)}


def sigstore_bundle(n, minutes, subject):
    row = image(n, minutes, size=4990, artifact='application/vnd.dev.sigstore.bundle.v0.3+json', tags=())
    row['subjectManifestDigest'] = subject
    return row


def legacy_cosign(n, minutes, subject, suffix):
    # Legacy cosign .sig/.att manifests carry an image-config media type; only the tag tells.
    return image(n, minutes, size=1200, tags=('sha256-' + subject.split(':')[1] + suffix,))


SIGNED_REPO = [
    image(1, 0), sigstore_bundle(2, 1, digest(1)),
    image(3, 30, manifest=DOCKER, artifact=DOCKER_CONFIG, tags=('release',)),
    sigstore_bundle(4, 31, digest(3)),
    legacy_cosign(5, 32, digest(3), '.sig'),
    legacy_cosign(6, 33, digest(3), '.att'),
    image(7, 34, size=900, artifact='application/vnd.cyclonedx+json', tags=()),
]


class Requests:
    content_secret_scans = True

    def __init__(self, rows):
        self.rows, self.read = rows, []

    def detail(self, session, service, region, operation, **kwargs):
        if service == 'sts':
            return {'collection_status': 'collected', 'Account': ACCOUNT,
                    'Arn': f'arn:aws:sts::{ACCOUNT}:assumed-role/test/runner'}
        assert (service, operation) == ('ecr', 'batch_get_image')
        self.read.append(kwargs['imageIds'][0]['imageDigest'])
        return {'collection_status': 'collected', 'ImageDigest': self.read[-1]}

    def pages(self, session, service, region, operation, member, **kwargs):
        return SimpleNamespace(status='collected', items=self.rows)


def scan(rows):
    requests = Requests(rows)
    item = {'repositoryArn': f'arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{REPO}',
            'repositoryName': REPO, 'registryId': ACCOUNT}
    return content.enrich('ecr_repository', requests, object(), REGION, [item])[0]['PackageContentSource'], requests


def test_content_scan_reads_newest_image_not_newer_signatures_attestations_or_sbom():
    source, requests = scan(SIGNED_REPO)
    assert requests.read == [digest(3)]
    assert source['SelectedImageDigest'] == digest(3)


def test_content_scan_keeps_image_index_as_a_candidate():
    rows = SIGNED_REPO + [image(8, 40, size=2000, manifest=INDEX, artifact=None, tags=('multi',)),
                          sigstore_bundle(9, 41, digest(8))]
    rows[-2].pop('artifactMediaType')
    source, requests = scan(rows)
    assert requests.read == [digest(8)]


def test_repository_holding_only_signatures_reads_no_image_and_names_cause():
    source, requests = scan([sigstore_bundle(2, 1, digest(1)), legacy_cosign(5, 2, digest(1), '.sig')])
    assert requests.read == []
    assert source == {'collection_status': 'not_collected', 'error': {'code': 'ecr_no_container_image'}}


def test_parallel_lane_budget_uses_the_selected_image_size():
    requests = Requests(SIGNED_REPO)
    item = {'repositoryArn': f'arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{REPO}',
            'repositoryName': REPO, 'registryId': ACCOUNT}
    bound = lanes._upper_bound(requests, object(), REGION, ACCOUNT, item)
    assert bound is not None and bound > 25_000_000 + 25_000_000 // 4


def test_latest_scan_findings_target_the_image_not_a_legacy_attestation():
    rows = [{**row, 'imagePushedAt': row['imagePushedAt']} for row in SIGNED_REPO]
    read = []

    class FactsRequests:
        ecr_latest_scan_requested = True
        max_pages = None

        def pages(self, session, service, region, operation, member, **kwargs):
            return ReadResult(rows, 'collected')

        def call(self, session, service, region, operation, **kwargs):
            read.append(kwargs['imageId']['imageDigest'])
            return {'imageId': kwargs['imageId'], 'repositoryName': REPO, 'registryId': ACCOUNT,
                    'imageScanStatus': {'status': 'COMPLETE'},
                    'imageScanFindings': {'findingSeverityCounts': {}, 'imageScanCompletedAt': WHEN.isoformat()}}

    repo = {'repositoryName': REPO, 'registryId': ACCOUNT, 'imageScanningConfiguration': {'scanOnPush': True}}
    out = _ecr_repository(FactsRequests(), object(), REGION, [repo])[0]
    assert read == [digest(3)]

    # The native check over the collected snapshot agrees on the same digest.
    for row in out['Images']['items']:
        row['imagePushedAt'] = row['imagePushedAt'].isoformat()
    state, evidence = evaluate_check('aws.c2b.ecr.latest_image_no_medium_plus_findings', out, {})
    assert state == 'PASS' and evidence['image_digest'] == digest(3)
