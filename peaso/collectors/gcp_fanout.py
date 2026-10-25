"""Order-preserving, bounded per-location fan-out for GCP list reads.

Regional list APIs are read one location at a time. ``location_fanout`` keeps
the observable result of that serial loop (same pages, same order, same first
error) while reading the locations concurrently:

* the first location is read alone as a probe; a ``SERVICE_DISABLED`` probe is
  handed back before any other location is requested, so a project-wide
  disabled API still costs one call;
* the remaining locations are read on the collector's dedicated
  ``location_pool`` (never the hydration pool, whose per-item reads the
  location reads themselves use), each into its own page buffer;
* buffers are replayed strictly in input order as ``(location, pages, error)``
  so each call site applies its existing error rules (location policy skips,
  disabled-service short-circuit, first-failure-wins) unchanged.

``error`` is the location's ``ReadError`` (pages read before it are kept). Any
other exception is re-raised right after that location's pages, exactly where
the serial loop would have raised it. Calls made from inside a pool worker, a
collector without a location pool, or a single location fall back to the
serial path, so nested fan-outs never wait on their own pool.
"""

import threading

POOL_PREFIX = "gcp-location"
_SERIAL_PREFIXES = (POOL_PREFIX, "gcp-hydrate")
SHORT_CIRCUIT_REASONS = frozenset(("SERVICE_DISABLED",))


def _reason(error):
    detail = getattr(error, "error", None)
    return detail.get("reason") if isinstance(detail, dict) else None


def _is_read_error(exc):
    # Matched by definition rather than identity so a reloaded collector
    # module (tests reload it) still classifies its own read errors.
    return any(cls.__name__ == "ReadError" and cls.__module__ == "peaso.collectors.gcp"
               for cls in type(exc).__mro__)


def _drain(fetch_one, location):
    pages = []
    try:
        for page in fetch_one(location):
            pages.append(page)
    except Exception as exc:  # non-read errors are replayed at the serial position
        if _is_read_error(exc):
            return pages, exc, None
        return pages, None, exc
    return pages, None, None


def _serial_only(collector):
    pool = getattr(collector, "location_pool", None)
    name = threading.current_thread().name
    return pool is None or name.startswith(_SERIAL_PREFIXES)


def location_fanout(collector, locations, fetch_one):
    locations = list(locations)
    if len(locations) <= 1 or _serial_only(collector):
        for location in locations:
            pages, error, other = _drain(fetch_one, location)
            yield location, pages, error
            if other is not None:
                raise other
        return
    first = locations[0]
    pages, error, other = _drain(fetch_one, first)
    if other is not None:
        yield first, pages, error
        raise other
    if _reason(error) in SHORT_CIRCUIT_REASONS:
        # Hand a disabled-service probe back before reading anything else;
        # only a call site that keeps going pays for the other locations.
        yield first, pages, error
        probed = True
    else:
        probed = False
    futures = [(location, collector.location_pool.submit(_drain, fetch_one, location))
               for location in locations[1:]]
    try:
        if not probed:
            yield first, pages, error
        for location, future in futures:
            pages, error, other = future.result()
            yield location, pages, error
            if other is not None:
                raise other
    finally:
        # A caller that stops early (disabled service, resource limit) does not
        # need the locations it will never replay.
        for _, future in futures:
            future.cancel()


def fanout_pages(collector, locations, fetch_one):
    """Fan out a per-location loop that stops at its first failure.

    Pages are replayed in location order and the first failing location's
    error is raised right after its pages, as the serial loop did."""
    for _location, pages, error in location_fanout(collector, locations, fetch_one):
        yield from pages
        if error is not None:
            raise error
