"""Fail-closed Access Analyzer inventory without live service calls.

Saved snapshot replay may contain previously collected analyzer findings. A new
scan has no authorized live Access Analyzer read or mutation path, so its
regional inventory remains unknown rather than claiming analyzers are absent.
"""
from __future__ import annotations


class AnalyzerLifecycle:
    def __init__(self, requests, events, progress=None):
        self.events = events

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return None

    def prepare(self, session, identity, regions):
        # Do not construct an Access Analyzer client, even to list existing
        # analyzers. Only results already present in saved snapshots may be used.
        return None

    def collect(self, session, identity, region, enrich):
        from .aws import ReadResult

        return ReadResult([], "unknown", {"code": "access_analyzer_saved_result_unavailable"})
