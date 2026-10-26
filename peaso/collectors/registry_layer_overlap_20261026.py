"""Validate registry image layers while later layers are still downloading.

The layers are read with the same RegistryReader.get calls, in the same order
and from one thread, as the serial list they replace. Meanwhile the archive is
validated ahead of the caller's own validate()/visit_files(), which replay that
result for the identical image (see container_image_archive.prebuild).
"""
from peaso import container_image_archive_20261020 as archive
from peaso.image_layer_overlap_20261026 import download_then_prebuild


def fetch_layers(reader, descriptors, directory, name, image, manifest, config, check):
    """Return (layer paths, prebuilt or None); `check` is the caller's validation check."""
    def download(put):
        layers = []
        for index, desc in enumerate(descriptors):
            layers.append(reader.get('blobs', desc['digest'], archive.MAX_LAYER,
                                     size=desc['size'], destination=directory / name(index)))
            put(index, layers[-1])
        return layers

    return download_then_prebuild(
        download, lambda ready: archive.prebuild(image, manifest, config, len(descriptors),
                                                 check, ready),
        len(descriptors), check)
