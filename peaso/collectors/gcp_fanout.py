"""Ordered, bounded streaming per-location fan-out for GCP list reads.

The first location streams synchronously as a SERVICE_DISABLED probe. Remaining
locations have at most one pending page per active location, with an active
window bounded by the dedicated location pool. Tuples may contain one page or
an empty terminal/error batch; callers consume pages before handling error.
Explicit resource caps and nested pool calls use serial streaming with no
speculative reads. Closing a consumer cancels queued work and stops each active
iterator after its current native read; no worker waits on a producer queue.
"""
import threading

POOL_PREFIX = "gcp-location"
_SERIAL_PREFIXES = (POOL_PREFIX, "gcp-hydrate")
SHORT_CIRCUIT_REASONS = frozenset(("SERVICE_DISABLED",))


def _reason(error):
    detail = getattr(error, "error", None)
    return detail.get("reason") if isinstance(detail, dict) else None


def _is_read_error(exc):
    return any(cls.__name__ == "ReadError" and cls.__module__ == "peaso.collectors.gcp"
               for cls in type(exc).__mro__)


def _serial_only(collector):
    options = getattr(collector, "options", {})
    capped = (getattr(collector, "max_items", None) is not None
              or isinstance(options, dict) and options.get("max_resources") is not None)
    return (getattr(collector, "location_pool", None) is None or capped
            or threading.current_thread().name.startswith(_SERIAL_PREFIXES))


def _close(iterator):
    close = getattr(iterator, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            pass


def _serial_location(fetch_one, location):
    iterator, emitted = None, False
    try:
        iterator = iter(fetch_one(location))
        while True:
            try:
                page = next(iterator)
            except StopIteration:
                if not emitted:
                    yield location, [], None
                return None
            emitted = True
            yield location, [page], None
    except Exception as exc:
        if _is_read_error(exc):
            yield location, [], exc
            return exc
        if not emitted:
            yield location, [], None
        raise
    finally:
        _close(iterator)


def _cancel_check(collector):
    check = getattr(getattr(collector, "transport", None), "check_cancelled", None)
    return check if callable(check) else None


class _Cursor:
    def __init__(self, fetch_one, location, stop, cancelled=None):
        self.fetch_one, self.location, self.stop = fetch_one, location, stop
        self.cancelled = cancelled
        self.iterator = None

    def step(self):
        if self.stop.is_set():
            _close(self.iterator)
            return "end", None
        try:
            # A cancelled or expired scan stops every producer before its next
            # native read; the error replays at this location's serial position.
            if self.cancelled is not None:
                self.cancelled()
            if self.iterator is None:
                self.iterator = iter(self.fetch_one(self.location))
            page = next(self.iterator)
        except StopIteration:
            _close(self.iterator)
            return "end", None
        except Exception as exc:
            _close(self.iterator)
            return ("read-error" if _is_read_error(exc) else "other-error"), exc
        if self.stop.is_set():
            _close(self.iterator)
            return "end", None
        return "page", page


def location_fanout(collector, locations, fetch_one):
    locations = list(locations)
    if len(locations) <= 1 or _serial_only(collector):
        for location in locations:
            yield from _serial_location(fetch_one, location)
        return
    # Do not read another location until the complete probe is consumed. A
    # caller breaking on SERVICE_DISABLED never schedules background requests.
    yield from _serial_location(fetch_one, locations[0])
    pool = collector.location_pool
    width = max(1, min(64, getattr(pool, "_max_workers", 1)))
    stop, active = threading.Event(), {}
    cancelled = _cancel_check(collector)
    following = 1

    def fill():
        nonlocal following
        while following < len(locations) and len(active) < width:
            index = following
            cursor = _Cursor(fetch_one, locations[index], stop, cancelled)
            active[index] = (cursor, pool.submit(cursor.step))
            following += 1

    try:
        fill()
        for index in range(1, len(locations)):
            emitted = False
            while True:
                cursor, future = active[index]
                kind, value = future.result()
                if kind == "page":
                    # At most one next page overlaps consumer processing. No
                    # completed-location page arrays or future lists are kept.
                    active[index] = (cursor, pool.submit(cursor.step))
                    emitted = True
                    yield locations[index], [value], None
                    continue
                active.pop(index)
                if kind == "read-error":
                    yield locations[index], [], value
                elif kind == "other-error":
                    if not emitted:
                        yield locations[index], [], None
                    raise value
                elif not emitted:
                    yield locations[index], [], None
                fill()
                break
    finally:
        stop.set()
        for cursor, future in active.values():
            # Queued steps never start; a running step closes its iterator once
            # its current read returns (immediately when already finished).
            future.cancel()
            future.add_done_callback(lambda _future, cursor=cursor: _close(cursor.iterator))
        active.clear()


def fanout_pages(collector, locations, fetch_one):
    """Replay pages and the first failure in serial location order."""
    stream = location_fanout(collector, locations, fetch_one)
    try:
        for _location, pages, error in stream:
            yield from pages
            if error is not None:
                raise error
    finally:
        stream.close()
