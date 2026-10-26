"""Streaming exports retain frozen report bytes without a document-sized string."""
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path

import pytest

from peaso import reports
from peaso.snapshot import freeze


# Reuse the established golden fixtures, including archived guidance variants.
_spec = importlib.util.spec_from_file_location(
    "markdown_stream_anchor_cases", Path(__file__).with_name("test_peaso_markdown_anchor_parity.py"))
_anchors = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_anchors)


@pytest.mark.parametrize(("name", "report"), _anchors._cases())
def test_stream_matches_frozen_report_bytes(name, report, monkeypatch):
    # These fixtures use synthetic.check, which has no catalog entry. Avoid
    # initializing unrelated provider/scanner catalogs for command binding.
    monkeypatch.setattr("peaso.remediation._check_kinds", lambda: {})
    expected = json.loads(_anchors.EXPECTED.read_text(encoding="utf-8"))[name]
    before = deepcopy(report)
    stream = io.BytesIO()
    if "error" in expected:
        exception_type = {"ValueError": ValueError, "TypeError": TypeError}[expected["error"]]
        with pytest.raises(exception_type) as raised:
            reports.write_markdown(report, stream)
        assert str(raised.value) == expected["message"]
    else:
        length = reports.write_markdown(report, stream)
        assert stream.getvalue() == expected["markdown"].encode("utf-8")
        assert length == len(stream.getvalue())
    assert report == before
    assert not stream.closed


@pytest.mark.parametrize("value", [
    None, True, 2**100, 1.25, float("inf"), {"z": [], "a": "é 😀 漢字"},
    freeze({"z": [1, False, None], "a": "snapshot"}),
    {"ticks": "`" * 31 + "x" + "`" * 25},
    {"newlines": "\n\r\t\x00", "unicode": "\u2028\u2029"},
    {1: "numeric key"},
])
def test_streamed_json_preserves_legacy_format_and_fences(value, monkeypatch):
    # Force the disk path and split backtick runs across token/replay chunks.
    monkeypatch.setattr(reports, "_SMALL_JSON_BYTES", 0)
    monkeypatch.setattr(reports, "_MARKDOWN_CHARS", 7)
    stream = io.BytesIO()
    sink = reports._MarkdownStream(stream)
    sink.json(value)
    sink.finish()
    expected = "\n".join(reports._json_block(value)).rstrip() + "\n"
    assert stream.getvalue() == expected.encode("utf-8")


def test_small_bounded_json_uses_the_existing_fast_encoder(monkeypatch):
    value = {"id": "synthetic", "data": {"enabled": True, "label": "é"}}
    real = reports._pretty_json
    calls = []
    monkeypatch.setattr(reports, "_pretty_json", lambda item: calls.append(item) or real(item))
    stream = io.BytesIO()
    reports._MarkdownStream(stream).json(value)
    assert calls == [value]
    assert reports._small_json(value)
    assert not reports._small_json({"oversized": "x" * reports._SMALL_JSON_BYTES})
    assert not reports._small_json(list(range(2000)))


def test_large_json_avoids_full_pretty_encoding_and_bounds_writes(monkeypatch):
    value = {"nodes": [{"id": str(i), "label": "é" * 100} for i in range(2000)]}
    expected = "\n".join(reports._json_block(value)).rstrip() + "\n"

    def forbidden(*args, **kwargs):
        raise AssertionError("A large JSON tree reached the full-string encoder")

    class RecordedStream(io.BytesIO):
        largest_write = 0

        def write(self, body):
            self.largest_write = max(self.largest_write, len(body))
            return super().write(body)

    monkeypatch.setattr(reports, "_pretty_json", forbidden)
    stream = RecordedStream()
    sink = reports._MarkdownStream(stream)
    sink.json(value)
    sink.finish()
    assert stream.getvalue() == expected.encode("utf-8")
    assert stream.largest_write <= 4 * reports._MARKDOWN_CHARS


def test_disk_json_spool_closes_on_encoder_failure(monkeypatch):
    files = []
    original = reports.tempfile.TemporaryFile

    def tracked(*args, **kwargs):
        stream = original(*args, **kwargs)
        files.append(stream)
        return stream

    monkeypatch.setattr(reports.tempfile, "TemporaryFile", tracked)
    monkeypatch.setattr(reports, "_SMALL_JSON_BYTES", 0)
    cycle = []
    cycle.append(cycle)
    with pytest.raises(ValueError, match="Circular reference"):
        reports._MarkdownStream(io.BytesIO()).json(cycle)
    assert files and all(stream.closed for stream in files)


def test_disk_spool_closes_and_caller_stream_survives_write_failure(monkeypatch):
    files = []
    original = reports.tempfile.TemporaryFile

    def tracked(*args, **kwargs):
        stream = original(*args, **kwargs)
        files.append(stream)
        return stream

    class FailedStream(io.BytesIO):
        def write(self, body):
            raise OSError("synthetic disk full")

    monkeypatch.setattr(reports.tempfile, "TemporaryFile", tracked)
    monkeypatch.setattr(reports, "_SMALL_JSON_BYTES", 0)
    stream = FailedStream()
    with pytest.raises(OSError, match="synthetic disk full"):
        reports._MarkdownStream(stream).json({"evidence": "synthetic"})
    assert files and all(item.closed for item in files)
    assert not stream.closed


def test_sink_preserves_whitespace_semantics_and_replaces_file_tail(monkeypatch):
    monkeypatch.setattr(reports, "_MARKDOWN_CHARS", 2)
    stream = io.BytesIO(b"prefix-old tail must disappear")
    stream.seek(len(b"prefix-"))
    sink = reports._MarkdownStream(stream)
    lines = ["é 😀  ", "", "last\t\u2003", "", " \t\u2003"]
    sink.extend(lines)
    length = sink.finish()
    expected = ("\n".join(lines).rstrip() + "\n").encode("utf-8")
    assert stream.getvalue() == b"prefix-" + expected
    assert length == len(expected)


def test_partial_binary_writes_are_completed():
    class ShortStream(io.BytesIO):
        def write(self, body):
            return super().write(body[:3])

    stream = ShortStream()
    assert reports.write_markdown({}, stream) == len(reports.render_markdown({}).encode("utf-8"))
    assert stream.getvalue() == reports.render_markdown({}).encode("utf-8")


def test_nonprogressing_output_fails_without_returning_success():
    class StalledStream(io.BytesIO):
        def write(self, body):
            return 0

    with pytest.raises(OSError, match="did not accept"):
        reports.write_markdown({}, StalledStream())


def test_lone_surrogate_rejects_utf8_like_legacy_publication():
    report = {"checks": [{"text": "\ud800"}]}
    with pytest.raises(UnicodeEncodeError):
        reports.render_markdown(report).encode("utf-8")
    with pytest.raises(UnicodeEncodeError):
        reports.write_markdown(report, io.BytesIO())


def test_grouped_observations_and_inline_native_data_are_complete():
    observations = [
        {"id": f"observation-{i}", "resource_id": f"resource-{i}",
         "scope": "111111111111/us-east-1", "status": "FAIL",
         "evidence_summary": f"Recorded setting {i}.", "evidence": {"value": "é" * 100}}
        for i in range(1200)
    ]
    report = {
        "provider": "aws", "stats": {}, "coverage": [],
        "findings": [{"id": "group", "check_id": "synthetic.check", "grouped": True,
                      "title": "Synthetic declaration", "status": "FAIL",
                      "evidence_summary": "Recorded settings vary.", "observations": observations}],
        "resources": [{"id": "inline", "type": "synthetic", "scope": "scope",
                       "data": {"native": {"all_values": list(range(1500))}}}],
        "graphs": {"iam": {"nodes": [{"id": "node", "evidence": {"native_document": {
            "Statement": [{"Effect": "Allow", "Action": ["synthetic:Read"], "Resource": "*"}]}}}], "edges": []}},
    }
    before = deepcopy(report)
    stream = io.BytesIO()
    reports.write_markdown(report, stream)
    assert stream.getvalue() == reports.render_markdown(report).encode("utf-8")
    text = stream.getvalue().decode("utf-8")
    assert '"observation-1199"' in text
    assert '"all_values"' in text and "1499" in text
    assert '"native_document"' in text and "synthetic:Read" in text
    assert report == before
