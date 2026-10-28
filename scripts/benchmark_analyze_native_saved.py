"""Profile native evaluation and optional local publication of a saved snapshot.

Prints only timings, process memory, and report counts. No collection or cloud
client is used. Pass the private snapshot path explicitly; never copy it into
the repository or print native items.
"""
from __future__ import annotations

import argparse
import contextlib
import gzip
import json
import platform
import resource
import tempfile
import threading
import time
from collections import defaultdict
from pathlib import Path

import psutil
import peaso.runtime_metrics as metrics


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("--publish", action="store_true", help="also write a local report bundle into a temporary directory")
    args = parser.parse_args()
    phases = defaultdict(lambda: {"wall_seconds": 0.0, "cpu_seconds": 0.0, "peak_rss_bytes": 0, "calls": 0})
    active = []
    stopped = threading.Event()
    process = psutil.Process()

    def rss():
        return process.memory_info().rss

    def sample():
        while not stopped.wait(0.05):
            used = rss()
            for name in active[:]:
                phases[name]["peak_rss_bytes"] = max(phases[name]["peak_rss_bytes"], used)

    @contextlib.contextmanager
    def span(name):
        active.append(name)
        wall, cpu = time.perf_counter(), time.process_time()
        try:
            yield
        finally:
            row = phases[name]
            row["wall_seconds"] += time.perf_counter() - wall
            row["cpu_seconds"] += time.process_time() - cpu
            row["peak_rss_bytes"] = max(row["peak_rss_bytes"], rss())
            row["calls"] += 1
            active.remove(name)

    metrics.span = span
    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    with span("replay.load"):
        opener = gzip.open if args.snapshot.suffix == ".gz" else open
        with opener(args.snapshot, "rt") as stream:
            snapshot = json.load(stream)
    from peaso.snapshot import frozen_view
    from peaso.engine import evaluate_snapshot
    snapshot = frozen_view(snapshot)
    with span("replay.evaluate"):
        report = evaluate_snapshot(snapshot, include_not_applicable=False)
    if args.publish:
        from peaso.storage.artifacts import FileArtifacts
        from peaso.storage.reports import publish_report
        with tempfile.TemporaryDirectory(prefix="peaso-native-replay-") as directory:
            with span("replay.publish"):
                publish_report(FileArtifacts(Path(directory)), "replay", "1" * 32, report, snapshot)
    stopped.set()
    sampler.join(timeout=1)
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if platform.system() != "Darwin":
        peak *= 1024
    print(json.dumps({"resources": len(report["resources"]), "findings": len(report["findings"]),
                      "peak_rss_bytes": peak, "phases": dict(phases)}, sort_keys=True))


if __name__ == "__main__":
    main()
