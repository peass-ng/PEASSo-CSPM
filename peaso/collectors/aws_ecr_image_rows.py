"""Tell ECR container images apart from signatures, attestations and SBOMs.

Repositories signed with cosign/sigstore hold, next to every image, small OCI
artifacts that reference it: sigstore bundles and in-toto attestations (OCI
1.1 referrers with ``subjectManifestDigest`` and a non-image
``artifactMediaType``) or legacy cosign ``sha256-<digest>.sig``/``.att``/
``.sbom`` tags (whose config media type can look like an image config). Those
are usually pushed right after the image, so "newest pushed digest" picks a
~5 KB signature instead of the container image. Only DescribeImages row
fields are used; nothing here reads the registry.
"""
import re

OCI_MANIFEST = 'application/vnd.oci.image.manifest.v1+json'
DOCKER_MANIFEST = 'application/vnd.docker.distribution.manifest.v2+json'
SINGLE_MANIFEST_TYPES = frozenset((OCI_MANIFEST, DOCKER_MANIFEST))
INDEX_TYPES = frozenset(('application/vnd.oci.image.index.v1+json',
                         'application/vnd.docker.distribution.manifest.list.v2+json'))
CONTAINER_CONFIG_TYPES = frozenset(('application/vnd.oci.image.config.v1+json',
                                    'application/vnd.docker.container.image.v1+json'))
# cosign's tag-schema fallback: sha256-<subject hex>[.sig|.att|.sbom|...].
REFERRER_TAG = re.compile(r'sha256-[0-9a-f]+(?:\.[A-Za-z0-9_-]{1,32})?\Z')


def is_referrer(row):
    """True for a signature, attestation, SBOM or other artifact attached to an image."""
    if not isinstance(row, dict):
        return False
    if row.get('subjectManifestDigest'):
        return True
    tags = row.get('imageTags')
    return isinstance(tags, list) and any(isinstance(tag, str) and REFERRER_TAG.match(tag) for tag in tags)


def is_container_image(row):
    """True when a DescribeImages row is a runnable container image or an image index.

    Rows from older snapshots/fixtures without media type fields are kept unless
    their tags or subject mark them as attached artifacts.
    """
    if not isinstance(row, dict) or is_referrer(row):
        return False
    manifest, artifact = row.get('imageManifestMediaType'), row.get('artifactMediaType')
    if manifest in INDEX_TYPES:
        return artifact is None or artifact in INDEX_TYPES or artifact in CONTAINER_CONFIG_TYPES
    if manifest is None or manifest in SINGLE_MANIFEST_TYPES:
        return artifact is None or artifact in CONTAINER_CONFIG_TYPES
    return False
