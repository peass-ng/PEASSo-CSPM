"""Validate ECR image layers while later layers are still downloading.

The download transports are the existing ones (aws_image_layer_pipeline); this
only listens for each finished layer so archive validation can start on it.
Outcomes keep the serial order (see peaso.image_layer_overlap_20261026).
"""


def download_and_validate(reader, repo, descriptors, root, image_digest, validate, *,
                          validating=lambda: None):
    from peaso.image_layer_overlap_20261026 import download_then_validate
    from .aws_image_layer_pipeline_20261022 import download_layers
    index = {root / f'layer-{i}.blob': i for i in range(len(descriptors))}

    def download(put):
        # Reader.blob reports each finished layer; worker copies of the Reader
        # inherit the hook, and it is removed before the Reader is reused.
        try:
            reader.layer_ready = lambda path, data: path in index and put(index[path], data)
        except AttributeError:  # no hook: validation waits for the whole download
            return download_layers(reader, repo, descriptors, root, image_digest)
        try:
            return download_layers(reader, repo, descriptors, root, image_digest)
        finally:
            del reader.layer_ready

    return download_then_validate(download, validate, len(descriptors), reader.check,
                                  validating=validating)
