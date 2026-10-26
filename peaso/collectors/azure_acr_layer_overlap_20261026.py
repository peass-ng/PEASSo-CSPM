"""Validate ACR image layers while later layers are still downloading.

The layers are read with the same Reader.blob calls, in the same order and
from one thread, as the serial loop they replace; validation starts on each
finished layer. Outcomes keep the serial order (see image_layer_overlap).
"""
from peaso import container_image_archive_20261020 as archive
from peaso.image_layer_overlap_20261026 import download_then_validate


def download_and_validate(reader, token, layers, root, image, manifest, config):
    """Return the downloaded layer paths after archive.validate(stage=True)."""
    def download(put):
        paths = []
        for number, desc in enumerate(layers):
            reader.check()
            path = root / ('layer-' + str(number) + '.blob')
            reader.blob('blobs', desc['digest'], archive.MAX_LAYER, token, desc['size'], destination=path)
            paths.append(path)
            put(number, path)
        return paths

    def validate(ready):
        archive.validate(image, manifest, config, [None] * len(layers), reader.check, stage=True,
                         ready=ready)

    return download_then_validate(download, validate, len(layers), reader.check)
