"""Bounded per-repository lanes for the ECR package content enricher.

The reviewed package content enricher is item-wise: every output row depends
only on its own repository row, the scan-local request cache and the
scan-wide image capture. It used to walk every repository of a region in one
thread, so a region's wall time was the sum of its image downloads and
scanner runs. Here each repository is enriched in its own call
(``enricher([item])``), at most ``LANES`` at a time, and rows are returned in
input order. No extra AWS read is issued: the image inventory each lane would
read first is read once by the dispatcher through the same cached call.

Image capture capacity is a scan-wide cumulative byte bound. A repository is
started next to running lanes only when every running image and the new one
fit in the capture headroom at their upper bounds, so concurrency never makes
an image hit ``image_capture_bound`` that a serial walk would have captured.
Otherwise the dispatcher waits and runs the repository alone, as before.
No payload, digest list, path or secret is retained or logged here.
"""
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
import threading

LANES = 3
CONFIG_BYTES = 1024 * 1024
SINGLE_MANIFEST_TYPES = frozenset({'application/vnd.oci.image.manifest.v1+json',
                                   'application/vnd.docker.distribution.manifest.v2+json'})


def _upper_bound(requests, session, region, account, item):
    """Capture bytes the item may reserve; ``None`` keeps it exclusive."""
    from datetime import datetime
    from . import aws_package_content_indicators as package
    try:
        own, native = package._arn(item['repositoryArn'], 'ecr', region)
        repo = item['repositoryName']
    except Exception:
        return 0  # The enricher rejects this row before any image read.
    if own != account or item.get('registryId') != account or native != 'repository/' + repo:
        return 0
    inventory = requests.pages(session, 'ecr', region, 'describe_images', 'imageDetails',
                               registryId=account, repositoryName=repo)
    if inventory.status != 'collected' or not inventory.items or len(inventory.items) > 5000:
        return 0
    latest, tie = None, False
    for row in inventory.items:
        pushed = row.get('imagePushedAt') if isinstance(row, dict) else None
        if not isinstance(pushed, datetime) or pushed.tzinfo is None:
            return None
        if latest is None or pushed > latest[0]:
            latest, tie = (pushed, row), False
        elif pushed == latest[0]:
            tie = True
    if tie:
        return None
    row = latest[1]
    size = row.get('imageSizeInBytes')
    if row.get('imageManifestMediaType') not in SINGLE_MANIFEST_TYPES or type(size) is not int or size < 0:
        return None
    # One single-manifest image never captures more than its compressed bound.
    return min(package.ECR_IMAGE_LIMIT, size + size // 4 + CONFIG_BYTES)


def lanes(kind, enricher):
    if kind != 'ecr_repository':
        return enricher

    def enrich(requests, session, region, items):
        from . import aws_package_content_indicators as package
        from .aws_image_capture_20261022 import MAX_CAPTURE_BLOBS
        from .aws_request_pool import parallel_enabled
        capture = getattr(requests, '_ecr_image_capture', None)
        selected = getattr(requests, 'content_secret_scan_kinds', None)
        if (not isinstance(items, list) or len(items) < 2 or capture is None
                or getattr(requests, 'content_secret_scans', False) is not True
                or (selected is not None and kind not in selected) or not parallel_enabled(requests)):
            return enricher(requests, session, region, items)
        try:
            account = package._own_account(requests, session, region)
        except Exception:
            return enricher(requests, session, region, items)
        width = min(LANES, len(items))
        condition = threading.Condition()
        active = {}

        def fits(bound):
            if not active:
                return True
            if bound is None or None in active.values() or len(active) >= width:
                return False
            with capture.lock:
                headroom = capture.capacity - capture.reserved
                blobs = len(capture.entries)
            return (headroom >= sum(active.values()) + bound and
                    blobs + (len(active) + 1) * (package.MEMBER_LIMIT + 1) <= MAX_CAPTURE_BLOBS)

        def run(index):
            try:
                return enricher(requests, session, region, [items[index]])
            finally:
                with condition:
                    del active[index]
                    condition.notify_all()

        futures = []
        with ThreadPoolExecutor(max_workers=width, thread_name_prefix='peaso-ecr-repo') as pool:
            for index, item in enumerate(items):
                try:
                    bound = _upper_bound(requests, session, region, account, item)
                except Exception:
                    bound = None
                with condition:
                    while not fits(bound):
                        condition.wait(.05)
                    active[index] = bound
                futures.append(pool.submit(copy_context().run, run, index))
        output = []
        for future in futures:
            output.extend(future.result())
        return output
    enrich.serial_enricher = enricher
    return enrich
