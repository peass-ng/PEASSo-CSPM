"""Run the pinned-version probe while the owned image archive is being written.

`trivy --version` reads nothing from the archive, so it can wait on its own
process while the archive copy runs. Its result is used only after the archive
was written; a probe that did not finish cleanly is run again at that point so
an unclean outcome matches the serial order exactly.
"""
import contextvars
import threading
import time

from . import container_scan_process_20261020 as process

PROBE_SECONDS = 10


class VersionProbe:
    def __init__(self, executable, env, root, end, cancel):
        self._argv = [str(executable), '--version']
        self._env, self._root, self._end, self._cancel = env, root, end, cancel
        self._result = None
        context = contextvars.copy_context()
        self._thread = threading.Thread(target=context.run, args=(self._run,),
                                        name='peaso-trivy-version', daemon=True)
        self._thread.start()

    def _run(self):
        try:
            self._result = self._execute()
        except BaseException:  # _execute reports failures as values; keep it that way
            self._result = None

    def _execute(self):
        return process._execute(self._argv, self._env, self._root,
                                min(self._end, time.monotonic() + PROBE_SECONDS), self._cancel)

    def wait(self):
        """Block until the background probe stopped (archive failed or not)."""
        self._thread.join()

    def result(self):
        self.wait()
        result = self._result
        if result is None or result[2] != 0 or result[3] is not None:
            result = self._execute()
        return result
