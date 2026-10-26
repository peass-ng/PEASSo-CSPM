"""Validate image layers while later layers are still downloading.

Downloads run in one background thread exactly as before; each finished layer
is handed to the validator, which walks layers in image order and waits for the
next one. Outcomes keep the serial order: a download error wins over any
validation error, and validation is reported only once every download joined.
"""
import contextvars
import threading

WAIT_SECONDS = 0.05


class DownloadStopped(Exception):
    """The download thread ended before this layer arrived."""


class LayerFeed:
    def __init__(self, count, check):
        self.check = check
        self._cond = threading.Condition()
        self._values = [None] * count
        self._ready = [False] * count
        self._finished = False

    def put(self, index, value):
        with self._cond:
            self._values[index], self._ready[index] = value, True
            self._cond.notify_all()

    def finish(self):
        with self._cond:
            self._finished = True
            self._cond.notify_all()

    def get(self, index):
        while True:
            with self._cond:
                if self._ready[index]:
                    return self._values[index]
                if self._finished:
                    raise DownloadStopped(index)
                self._cond.wait(WAIT_SECONDS)
            self.check()

    def values(self):
        with self._cond:
            return list(self._values) if all(self._ready) else None


def download_then_validate(download, validate, count, check, *, validating=lambda: None):
    """Run `download(put)` in the background and `validate(get)` here.

    `download` returns the layer list and calls `put(index, value)` once a layer
    is complete. `validating()` runs where the serial flow would have started
    validation: after a successful download, before the validation outcome.
    """
    feed = LayerFeed(count, check)
    outcome = {}

    def run():
        try:
            outcome['layers'] = download(feed.put)
        except BaseException as exc:  # re-raised by the joining thread
            outcome['error'] = exc
        finally:
            feed.finish()

    worker = threading.Thread(target=contextvars.copy_context().run, args=(run,),
                              name='peaso-layer-download', daemon=True)
    worker.start()
    try:
        validate(feed.get)
        failure = None
    except BaseException as exc:
        failure = exc
    finally:
        worker.join()
    if 'error' in outcome:
        raise outcome['error']
    layers = outcome['layers']
    validating()
    if feed.values() != list(layers) or isinstance(failure, DownloadStopped):
        # The download returned other values than it handed over: validate
        # exactly what the serial flow would have.
        validate(lambda index: layers[index])
    elif failure is not None:
        raise failure
    return layers


def download_then_prebuild(download, build, count, check):
    """Run `download(put)` in the background and `build(get)` here.

    Returns (layers, prebuilt or None). Download errors are raised exactly as
    the serial download raised them. A build that fails or that saw other
    values than the download returned yields None, and the caller then
    validates serially, so its errors and visits keep their serial order.
    """
    feed = LayerFeed(count, check)
    outcome, built = {}, []

    def run():
        try:
            outcome['layers'] = download(feed.put)
        except BaseException as exc:  # re-raised by the joining thread
            outcome['error'] = exc
        finally:
            feed.finish()

    worker = threading.Thread(target=contextvars.copy_context().run, args=(run,),
                              name='peaso-layer-download', daemon=True)
    worker.start()
    try:
        built.append(build(feed.get))
    except Exception:  # noqa: BLE001 - the serial validation reproduces it
        pass
    finally:
        worker.join()
    prebuilt = built[0] if built else None
    if 'error' in outcome or feed.values() != list(outcome['layers']):
        if prebuilt is not None:
            prebuilt.discard()
        if 'error' in outcome:
            raise outcome['error']
        prebuilt = None
    return outcome['layers'], prebuilt
