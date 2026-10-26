import base64
import hashlib

import pytest

from peaso import container_image_archive_20261020 as archive

CONFIG = b'{"rootfs":{"type":"layers","diff_ids":[]},"os":"linux"}'
assert len(CONFIG) % 3  # its base64 carries padding


def _desc(raw=CONFIG, **extra):
    item = {'mediaType': 'application/vnd.oci.image.config.v1+json',
            'digest': 'sha256:' + hashlib.sha256(raw).hexdigest(), 'size': len(raw)}
    item.update(extra)
    return item


def test_embedded_data_matching_the_descriptor_is_accepted():
    item = _desc(data=base64.b64encode(CONFIG).decode())
    assert archive.descriptor(item, archive.CONFIGS, archive.MAX_CONFIG) is item


@pytest.mark.parametrize('data', [
    base64.b64encode(CONFIG + b' ').decode(),            # other bytes
    base64.b64encode(CONFIG).decode().rstrip('='),       # non-canonical padding
    base64.b64encode(CONFIG).decode() + '\n',            # not strict base64
    'not base64!',
    7, None, ['x'],
])
def test_embedded_data_that_does_not_match_is_rejected(data):
    with pytest.raises(ValueError, match='unsupported_descriptor'):
        archive.descriptor(_desc(data=data), archive.CONFIGS, archive.MAX_CONFIG)


def test_other_unknown_descriptor_fields_stay_rejected():
    with pytest.raises(ValueError, match='unsupported_descriptor'):
        archive.descriptor(_desc(urls=['https://example.invalid/blob']), archive.CONFIGS,
                           archive.MAX_CONFIG)
