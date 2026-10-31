"""Kubernetes privesc coverage ledger <-> catalog consistency.

The ledger (``docs/privesc-ledgers/privesc-k8s.md``, or ``PEASO_K8S_PRIVESC_LEDGER``) maps every heading
of the in-scope HackTricks Cloud Kubernetes/OpenShift pages (revision 4202559) to k8s catalog ids, a k8s
``_excluded.yaml`` item, or a structural / out-of-scope reason. These tests keep the ledger and the catalog in sync;
the heading-completeness check runs only against a checkout at the ledger revision.
"""
import os
import re
import subprocess
import json
from collections import Counter
from pathlib import Path

import pytest
import yaml

from peaso.privesc.schema import HACKTRICKS_CLOUD, checkout_revision, load_catalog

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "peaso" / "privesc" / "catalog" / "k8s"
LEDGER = Path(os.environ.get("PEASO_K8S_PRIVESC_LEDGER", ROOT / "docs" / "privesc-ledgers" / "privesc-k8s.md"))
CURRENT_LEDGER_REVISION = "4202559da31f53bb101052ab4622a636d243c4a5"
LEDGER_REVISION = CURRENT_LEDGER_REVISION
PC = "src/pentesting-cloud/"
SCOPE = [
    "kubernetes-security/kubernetes-privilege-escalation",
    "kubernetes-security/kubernetes-post-exploitation",
    "kubernetes-security/kubernetes-unauthenticated-access",
    "kubernetes-security/kubernetes-persistence",
    "kubernetes-security/spiffe-spire-workload-identity-spoofing.md",
    "openshift-pentesting",
]
STATUSES = {"covered", "excluded", "structural", "out-of-scope"}

ROW = re.compile(r"^\| `([^`#]+\.md)#([^`]+)` \| (.*?) \| (.*?) \| ([a-z-]+) \| (.*) \|$")
CURRENT = re.compile(r"^\| `(k8s-[a-z0-9-]+)` \| `([^`]+)` \| (ACTIVE|RETIRED) \| (.*) \|$")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


def _current_rows():
    text = LEDGER.read_text(encoding="utf-8")
    revision = json.loads((ROOT / "risk_rules/hacktricks-privesc-source.json").read_text())["revision"]
    assert f"## Current CSPM catalog reconciliation (HackTricks Cloud `{revision}`)" in text
    section = text.split("## Current CSPM catalog reconciliation", 1)[1]
    return {m.group(1): (m.group(2), m.group(3), m.group(4))
            for line in section.splitlines() if (m := CURRENT.match(line))}


def _ledger_rows():
    assert LEDGER.is_file(), f"k8s privesc ledger not found at {LEDGER}"
    rows = []
    for line in LEDGER.read_text(encoding="utf-8").splitlines():
        m = ROW.match(line)
        if m:
            page, anchor, _title, _reqs, status, mapping = m.groups()
            rows.append((page, anchor, status, mapping))
    assert rows, "ledger has no mapping rows"
    return rows


def _catalog_ids():
    catalog = load_catalog()
    errors = [e for e in catalog["errors"] if "k8s" in str(e)]
    assert not errors, "k8s catalog errors:\n" + "\n".join(map(str, errors))
    return {e["id"] for e in catalog["entries"] if e.get("provider") == "k8s" or str(e.get("id", "")).startswith("k8s-")}


def _excluded():
    return yaml.safe_load((CATALOG / "_excluded.yaml").read_text(encoding="utf-8")) or []


def _slug(text):
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    return "".join(ch if (ch.isalnum() or ch in "_-") else "-" if ch.isspace() else "" for ch in text)


def _anchors(page):
    out, seen, code = [], Counter(), False
    for line in page.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("```"):
            code = not code
            continue
        m = None if code else _HEADING.match(line)
        if m:
            s = _slug(m.group(2))
            out.append(s if seen[s] == 0 else f"{s}-{seen[s]}")
            seen[s] += 1
    return out


def _checkout_at_ledger_revision():
    candidates = [p for p in os.environ.get("HACKTRICKS_CLOUD_ROOT", "").split(os.pathsep) if p]
    candidates += [str(ROOT.parent / "htc"), str(HACKTRICKS_CLOUD)]
    for path in candidates:
        root = Path(path).expanduser()
        rev = checkout_revision(root) if (root / "src").is_dir() else None
        if rev and str(rev).lower().startswith(LEDGER_REVISION):
            return root
    return None


def test_every_in_scope_heading_has_a_ledger_row():
    root = _checkout_at_ledger_revision()
    if root is None:
        pytest.skip(f"no hacktricks-cloud checkout at {LEDGER_REVISION} (set HACKTRICKS_CLOUD_ROOT)")
    rows = {f"{p}#{a}" for p, a, _, _ in _ledger_rows()}
    base = root / PC
    pages = []
    for scope in SCOPE:
        p = base / scope
        pages += sorted(p.rglob("*.md")) if p.is_dir() else [p]
    missing = [f"{page.relative_to(base)}#{a}" for page in pages for a in _anchors(page)
               if f"{page.relative_to(base)}#{a}" not in rows]
    assert not missing, "in-scope headings without a ledger row:\n" + "\n".join(missing)




# ------------------------------------------------------------------ catalog wiring of the admission blockers
# Fixtures run the real catalog entries (not synthetic ones) through the model-evaluated K8s blockers.
def _catalog_entries(*ids):
    by_id = {e["id"]: e for e in load_catalog()["entries"]}
    return [by_id[i] for i in ids]


def test_catalog_privileged_pod_edge_is_blocked_by_psa_restricted():
    from peaso import privesc
    from tests.test_peaso_privesc_schema_ext import reached
    from tests.test_peaso_privesc_schema_ext_k8s_blockers import DEV, NODE, RESTRICTED, snap

    got = privesc.analyze(snap({"a": RESTRICTED}), entries=_catalog_entries("k8s-nodes-privileged-pod-create"))
    assert reached(got, DEV, "k8s-nodes-privileged-pod-create") == {}
    record = got["stats"]["blocked"][0]
    assert record["technique"] == "k8s-nodes-privileged-pod-create" and record["targets"] == [NODE]
    assert record["blockers"][0]["id"] == "pivot_namespace_psa_enforce_baseline_or_restricted"


def test_catalog_plain_pod_edge_is_not_blocked_by_psa_restricted():
    from peaso import privesc
    from tests.test_peaso_privesc_schema_ext import reached
    from tests.test_peaso_privesc_schema_ext_k8s import C, sa
    from tests.test_peaso_privesc_schema_ext_k8s_blockers import DEV, RESTRICTED, snap

    entry = _catalog_entries("k8s-workloads-pods-create")[0]
    assert not {"pod_security_admission", "pivot_namespace_psa_enforce_baseline_or_restricted"} & set(entry["blockers"])
    got = privesc.analyze(snap({"a": RESTRICTED}, sas=[sa("x", "a")]), entries=[entry])
    assert f"k8s:{C}:sa:a:x" in reached(got, DEV, "k8s-workloads-pods-create")
    assert got["stats"]["blocked"] == []


def test_catalog_does_not_report_admission_change_as_a_privesc_target():
    from peaso import privesc
    from tests.test_peaso_privesc_schema_ext import reached
    from tests.test_peaso_privesc_schema_ext_k8s import crb, user
    from tests.test_peaso_privesc_schema_ext_k8s_blockers import DEV, RELABEL, RESTRICTED, snap

    assert not any(e["target"]["kind"] == "k8s_admission_control"
                   for e in load_catalog()["entries"] if e["provider"] == "k8s")
    s = snap({"a": RESTRICTED}, clusterroles=[RELABEL], crbs=[crb("rl", "relabel", user("dev"))])
    got = privesc.analyze(s, entries=_catalog_entries("k8s-nodes-privileged-pod-create"))
    assert reached(got, DEV, "k8s-nodes-privileged-pod-create") == {}
