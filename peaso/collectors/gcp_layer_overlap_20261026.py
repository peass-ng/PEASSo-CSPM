"""Validate Artifact Registry image layers while later layers are still downloading.

The layers are read with the same capture reader calls, in the same order and
from one thread, as the serial loop they replace. Meanwhile the archive is
validated ahead of the caller's own archive.validate(), which replays that
result for the identical image (see container_image_archive.prebuild).
"""
from peaso import container_image_archive_20261020 as archive
from peaso.image_layer_overlap_20261026 import download_then_prebuild


def read_layers(reader, uri, layers, cap, scope, digest, config_digest):
    """Read `layers` like the serial loop; leave the prebuilt image on `reader.prebuilt`."""
    state = vars(reader)
    state.pop('prebuilt', None)
    blobs = state.get('_blobs')
    if type(blobs) is not dict:  # not a capture reader: the serial loop
        for layer in layers:
            reader.get(uri, 'blobs', layer['digest'], cap, layer['size'])
        return None

    def download(put):
        for index, layer in enumerate(layers):
            reader.get(uri, 'blobs', layer['digest'], cap, layer['size'])
            put(index, blobs[('blobs', layer['digest'])])
        return [blobs[('blobs', layer['digest'])] for layer in layers]

    def build(ready):
        identity = {'provider': 'gcp', 'scope': scope, 'manifest_digest': digest,
                    'immutable_reference': uri.removeprefix('https://').rsplit('@', 1)[0] + '@' + digest,
                    'config_digest': config_digest}
        return archive.prebuild(identity, blobs[('manifests', digest)], blobs[('blobs', config_digest)],
                                len(layers), reader.check, ready, for_validate=True)

    _, prebuilt = download_then_prebuild(download, build, len(layers), reader.check)
    state['prebuilt'] = prebuilt
    return prebuilt
