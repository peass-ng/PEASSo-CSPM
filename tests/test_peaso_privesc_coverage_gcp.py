"""GCP privesc coverage ledger <-> catalog consistency.

The ledger (``docs/privesc-ledgers/privesc-gcp.md``; ``PEASO_GCP_PRIVESC_LEDGER`` overrides the path) maps every HackTricks Cloud GCP heading to catalog ids,
an ``_excluded.yaml`` item or a NEEDS SCHEMA proposal. These tests keep the ledger and the catalog in sync. With explicitly selected source checkouts, the current GCP tree is also enumerated at the canonical pinned revision; historical citations are checked separately by test_peaso_privesc_catalog_sources.py.
"""
import os
import re
import json
from collections import Counter

import pytest
from pathlib import Path

import yaml

from peaso.privesc.schema import load_catalog
from test_peaso_privesc_catalog_sources import _checkouts, _slug, _HEADING

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "peaso" / "privesc" / "catalog" / "gcp"
LEDGER = Path(os.environ.get("PEASO_GCP_PRIVESC_LEDGER") or ROOT / "docs" / "privesc-ledgers" / "privesc-gcp.md")

ROW = re.compile(r"^\| `#([^`]+)` \| (.*) \| ([A-Z+-]+) \| (.*) \|$")
PAGE = re.compile(r"^### `(src/[^`]+\.md)`$")
CURRENT = re.compile(r"^\| `(gcp-[a-z0-9-]+)` \| `([^`]+)` \| (ACTIVE|RETIRED) \| (.*) \|$")


def _current_rows():
    text = LEDGER.read_text(encoding="utf-8")
    manifest_revision = json.loads((ROOT / "risk_rules/hacktricks-privesc-source.json").read_text())["revision"]
    assert f"## Current CSPM catalog reconciliation (HackTricks Cloud `{manifest_revision}`)" in text
    section = text.split("## Current CSPM catalog reconciliation", 1)[1]
    return {m.group(1): (m.group(2), m.group(3), m.group(4))
            for line in section.splitlines() if (m := CURRENT.match(line))}


def _ledger_rows(text=None):
    assert LEDGER.is_file(), f"GCP privesc ledger not found at {LEDGER}"
    page = None
    rows = []
    for line in (LEDGER.read_text(encoding="utf-8") if text is None else text).splitlines():
        m = PAGE.match(line)
        if m:
            page = m.group(1)
            continue
        m = ROW.match(line)
        if m and page:
            rows.append((page, m.group(1), m.group(3), m.group(4)))
    assert rows, "ledger has no mapping rows"
    return rows


def _catalog_ids():
    catalog = load_catalog()
    gcp_errors = [e for e in catalog["errors"] if "gcp" in str(e)]
    assert not gcp_errors, "GCP catalog errors:\n" + "\n".join(map(str, gcp_errors))
    return {e["id"] for e in catalog["entries"] if e.get("provider") == "gcp"}


def _excluded_sources():
    return {item["source"] for item in yaml.safe_load((CATALOG / "_excluded.yaml").read_text()) or []}


GCP_CURRENT_SOURCE_REVISION = "171e422299df4e3c1477847d80439c13aadf55fc"
GCP_SOURCE_TREE = Path("src/pentesting-cloud/gcp-security")


def _current_gcp_checkout():
    selected = os.environ.get("HACKTRICKS_CLOUD_ROOT", "")
    if not selected:
        assert os.environ.get("PEASO_PRIVESC_STRICT_SOURCES") != "1", "strict GCP heading coverage requires explicitly selected source checkouts"
        # Ordinary catalog-consistency checks remain local; no implicit checkout
        # inspection and no extra default pytest skip is introduced.
        return None
    matching = [root for root, revision in _checkouts()
                if revision == GCP_CURRENT_SOURCE_REVISION and (root / GCP_SOURCE_TREE).is_dir()]
    if matching:
        return matching[0]
    # A selected checkout at the current CSPM source revision uses the
    # reconciliation rows. An unrelated checkout must not silently satisfy
    # the historical heading sweep.
    current_revision = json.loads((ROOT / "risk_rules/hacktricks-privesc-source.json").read_text())["revision"]
    if any(revision == current_revision for _, revision in _checkouts()):
        return None
    raise AssertionError("historical GCP heading coverage requires source revision " + GCP_CURRENT_SOURCE_REVISION)


def _gcp_heading_sources(root):
    headings = set()
    for page in sorted((root / GCP_SOURCE_TREE).rglob("*.md")):
        seen, fence = Counter(), None
        for line in page.read_text(encoding="utf-8").splitlines():
            marker = re.match(r"^\s*(`{3,}|~{3,})", line)
            if marker:
                char = marker.group(1)[0]
                if fence is None:
                    fence = char
                elif fence == char:
                    fence = None
                continue
            match = None if fence else _HEADING.match(line)
            if not match:
                continue
            slug = _slug(match.group(2))
            anchor = slug if seen[slug] == 0 else f"{slug}-{seen[slug]}"
            seen[slug] += 1
            headings.add(page.relative_to(root).as_posix() + "#" + anchor)
    return headings


def _gcp_disposition_sources(text=None):
    # Ordinary ledger rows carry COVERED/EXCLUDED/NON-PRIVESC/STRUCTURAL. The
    # compressed structural rows explicitly enumerate another 1,993 anchors.
    text = LEDGER.read_text(encoding="utf-8") if text is None else text
    sources = {page + "#" + anchor for page, anchor, _, _ in _ledger_rows(text)}
    page = None
    for line in text.splitlines():
        match = PAGE.match(line)
        if match:
            page = match.group(1)
        elif page and "| STRUCTURAL |" in line:
            sources.update(page + "#" + anchor for anchor in re.findall(r"`#([^`]+)`", line))
    # Existing consistency tests validate every mapped catalog ID/exclusion.
    return sources


def _assert_gcp_heading_dispositions(headings, dispositions):
    missing = sorted(headings - dispositions)
    assert not missing, f"{len(missing)} current GCP headings lack a declared disposition: {missing[:10]}"




def test_strict_gcp_heading_sources_cannot_silently_skip(monkeypatch):
    monkeypatch.setenv("PEASO_PRIVESC_STRICT_SOURCES", "1")
    monkeypatch.delenv("HACKTRICKS_CLOUD_ROOT", raising=False)
    with pytest.raises(AssertionError, match="explicitly selected"):
        _current_gcp_checkout()


def test_historical_checkout_cannot_replace_current_gcp_tree(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("a53b46392c11fa2a1b2ce85e69e7f704b8f79fbf\n")
    (tmp_path / GCP_SOURCE_TREE).mkdir(parents=True)
    monkeypatch.setenv("HACKTRICKS_CLOUD_ROOT", str(tmp_path))
    with pytest.raises(AssertionError, match=GCP_CURRENT_SOURCE_REVISION):
        _current_gcp_checkout()
