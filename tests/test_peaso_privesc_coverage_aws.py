"""AWS privilege-escalation coverage ledger checks.

The ledger (`ledgers/privesc-aws.md`, generated against hacktricks-cloud master 171e422299) lists every
technique heading of the AWS privesc pages, and every privesc-relevant heading elsewhere under `aws-security/`,
with the catalog ids that implement it or the reason it is not an edge. These tests check that

* every COVERED id is active, and every active AWS entry has a covered source row,
* no heading is left UNREVIEWED and the summary matches the table,
* the number of COVERED technique headings does not regress, and
* (when a hacktricks-cloud checkout at the ledger revision is available) every heading of every
  `aws-privilege-escalation/**` page has a ledger row.

The ledger lives in the repository at `docs/privesc-ledgers/privesc-aws.md`; PEASO_PRIVESC_LEDGER_DIR (a path list)
overrides it. Only the heading rescan is skipped, when no hacktricks-cloud checkout at the ledger revision is available.
"""
from __future__ import annotations

import os
import re
from collections import Counter
from pathlib import Path

import pytest

from peaso.privesc.schema import HACKTRICKS_CLOUD, checkout_revision, load_catalog, revision_matches

REPO = Path(__file__).resolve().parents[1]
LEDGER_REVISION = "171e422299"
# COVERED technique headings when the ledger was last regenerated; raise it when coverage grows.
MIN_COVERED_HEADINGS = 172
MIN_COVERED_IDS = 161
STATUSES = {"COVERED", "EXCLUDED", "NEEDS SCHEMA", "STRUCTURAL", "NOT PRIVESC", "SUPERSEDED", "UNREVIEWED"}
_ROW = re.compile(r"^\| `([^`]*)` \| (.*) \| (.*) \| (" + "|".join(sorted(STATUSES, key=len, reverse=True)) + r") \| (.*) \|$")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_ID = re.compile(r"`(aws-[a-z0-9-]+)`")
PRIVESC_ROOT = "src/pentesting-cloud/aws-security/aws-privilege-escalation/"


def _ledger_path():
    candidates = [Path(p) / "privesc-aws.md" for p in os.environ.get("PEASO_PRIVESC_LEDGER_DIR", "").split(os.pathsep) if p]
    candidates.append(REPO / "docs" / "privesc-ledgers" / "privesc-aws.md")
    return next((p for p in candidates if p.is_file()), None)


@pytest.fixture(scope="module")
def ledger():
    path = _ledger_path()
    assert path is not None, "AWS privesc ledger not found (docs/privesc-ledgers/privesc-aws.md or PEASO_PRIVESC_LEDGER_DIR)"
    rows, summary, page = [], {}, None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("### "):
            page = "src/pentesting-cloud/aws-security/" + line[4:].strip()
            continue
        m = re.match(r"^- ([A-Z ]+): (\d+)$", line)
        if m and m.group(1) in STATUSES:
            summary[m.group(1)] = int(m.group(2))
            continue
        m = _ROW.match(line)
        if m and page:
            rows.append({"key": f"{page}#{m.group(1)}", "page": page, "status": m.group(4), "ids": _ID.findall(m.group(5))})
    assert rows, f"no ledger rows parsed from {path}"
    return {"rows": rows, "summary": summary}


@pytest.fixture(scope="module")
def aws_entries():
    return {e["id"]: e for e in load_catalog()["entries"] if e.get("provider") == "aws"}


def test_mapped_ids_exist(ledger, aws_entries):
    missing = sorted({(r["key"], i) for r in ledger["rows"] if r["status"] == "COVERED" for i in r["ids"] if i not in aws_entries})
    assert not missing, f"ledger maps headings to unknown catalog ids: {missing[:20]}"
    empty = [r["key"] for r in ledger["rows"] if r["status"] == "COVERED" and not r["ids"]]
    assert not empty, f"COVERED rows without catalog ids: {empty[:20]}"


def test_every_aws_entry_has_a_ledger_row(ledger, aws_entries):
    covered = {r["key"]: set(r["ids"]) for r in ledger["rows"] if r["status"] == "COVERED"}
    orphans = []
    for entry in aws_entries.values():
        sources = entry["source"] if isinstance(entry["source"], list) else [entry["source"]]
        if not any(entry["id"] in covered.get(source, set()) for source in sources):
            orphans.append(entry["id"])
    assert not orphans, f"Active AWS entries missing a covered source row: {sorted(orphans)[:20]}"


def test_no_unreviewed_rows_and_summary_matches(ledger):
    counts = Counter(r["status"] for r in ledger["rows"])
    unreviewed = [r["key"] for r in ledger["rows"] if r["status"] == "UNREVIEWED"]
    assert not unreviewed, f"{len(unreviewed)} UNREVIEWED ledger rows, e.g. {unreviewed[:10]}"
    assert len({r["key"] for r in ledger["rows"]}) == len(ledger["rows"]), "duplicate ledger rows"
    for status, n in ledger["summary"].items():
        assert counts.get(status, 0) == n, f"summary says {n} {status}, table has {counts.get(status, 0)}"


def test_covered_count(ledger, aws_entries):
    covered = [r for r in ledger["rows"] if r["status"] == "COVERED"]
    ids = {i for r in covered for i in r["ids"]}
    assert len(covered) >= MIN_COVERED_HEADINGS, f"only {len(covered)} COVERED AWS technique headings"
    assert len(ids) >= MIN_COVERED_IDS, f"only {len(ids)} distinct AWS catalog ids referenced by the ledger"


def _slug(text):
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    return "".join(ch if (ch.isalnum() or ch in "_-") else "-" if ch.isspace() else "" for ch in text)


def _checkout():
    candidates = [p for p in os.environ.get("HACKTRICKS_CLOUD_ROOT", "").split(os.pathsep) if p] + [str(HACKTRICKS_CLOUD)]
    for path in candidates:
        root = Path(path).expanduser()
        if (root / PRIVESC_ROOT).is_dir():
            rev = checkout_revision(root)
            if rev and revision_matches(LEDGER_REVISION, rev):
                return root
    return None


