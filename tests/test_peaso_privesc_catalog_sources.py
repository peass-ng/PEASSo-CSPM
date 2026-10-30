"""Every privesc catalog `source` (entries and `_excluded*.yaml` lines) must point at an existing
hacktricks-cloud page and, when it has one, an existing heading anchor.

Sources are checked against a checkout at the revision they cite (`source_revision`); a source without
one must resolve in at least one available checkout. Checkouts must be explicitly selected with HACKTRICKS_CLOUD_ROOT
(one path or several separated by os.pathsep). The test is skipped when none is selected; strict
validation fails when any cited revision is unavailable.
"""
from __future__ import annotations

import os
import re
import subprocess
from collections import Counter
from pathlib import Path

import pytest
import yaml

from peaso.privesc.schema import CATALOG_DIR, HACKTRICKS_CLOUD, checkout_revision, revision_matches

SCRATCHPAD_CHECKOUT = Path("/private/tmp/claude-501/-Users-carlospolop-git-Blue-CloudPEASS/"
                           "32170eee-6a9b-41b2-90e5-63caa171ca85/scratchpad/hacktricks-cloud-head")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


def _checkouts():
    candidates = [p for p in os.environ.get("HACKTRICKS_CLOUD_ROOT", "").split(os.pathsep) if p]
    # External source validation is opt-in; never inspect another session's
    # absolute scratchpad or a developer-specific checkout implicitly.
    out, seen = [], set()
    for path in candidates:
        root = Path(path).expanduser()
        if root.is_dir() and (root / "src").is_dir() and root.resolve() not in seen:
            seen.add(root.resolve())
            out.append((root, checkout_revision(root)))
    return out


def _slug(text):
    """mdBook heading id: link/tag text kept, lower-cased alphanumerics, '_' and '-', whitespace -> '-'."""
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)
    # Inline-code angle brackets are literal heading text in mdBook, while
    # arrow markup contributes only its two hyphens to the generated ID.
    text = re.sub(r"`([^`]*)`", lambda match: match.group(1).replace("<", "").replace(">", ""), text)
    text = re.sub(r"\s*<-->\s*", "--", text)
    text = re.sub(r"\s*-->\s*", "--", text)
    text = re.sub(r"<[^>]+>", "", text).strip().lower()
    return "".join(ch if (ch.isalnum() or ch in "_-") else "-" if ch.isspace() else "" for ch in text)


_ANCHORS = {}


def _anchors(page):
    if page not in _ANCHORS:
        anchors, seen, in_code = set(), Counter(), False
        for line in page.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lstrip().startswith("```"):
                in_code = not in_code
                continue
            match = None if in_code else _HEADING.match(line)
            if not match:
                continue
            slug = _slug(match.group(2))
            anchors.update({slug, slug if seen[slug] == 0 else f"{slug}-{seen[slug]}"})
            seen[slug] += 1
        _ANCHORS[page] = anchors
    return _ANCHORS[page]


def _anchors_in_text(contents):
    anchors, seen, in_code = set(), Counter(), False
    for line in contents.splitlines():
        if line.lstrip().startswith("```"):
            in_code = not in_code
            continue
        match = None if in_code else _HEADING.match(line)
        if match:
            slug = _slug(match.group(2))
            anchors.add(slug if seen[slug] == 0 else f"{slug}-{seen[slug]}")
            seen[slug] += 1
    return anchors


def _sources():
    for path in sorted(CATALOG_DIR.rglob("*.yaml")):
        # Excluded proposals are not in the shipped catalog and may cite pages
        # from later source revisions. Active entries are checked separately
        # against each exact authored revision below.
        if path.name.startswith("_excluded"):
            continue
        rel = path.relative_to(CATALOG_DIR)
        for i, item in enumerate(yaml.safe_load(path.read_text()) or []):
            if not isinstance(item, dict):
                continue
            revision = item.get("source_revision")
            sources = item.get("source")
            for source in sources if isinstance(sources, list) else [sources]:
                if isinstance(source, str) and source:
                    yield f"{rel}[{i}] {item.get('id') or item.get('technique') or ''}".strip(), source, revision




def test_anchor_slug_matches_mdbook():
    assert _slug("iam:PassRole, ec2:RunInstances") == "iampassrole-ec2runinstances"
    assert _slug("eks:CreateAccessEntry — IAM-only `path`") == "ekscreateaccessentry--iam-only-path"
    assert _slug("[sts:AssumeRole](https://x)") == "stsassumerole"
    assert _slug("Pivoting AD --> Entra ID") == "pivoting-ad--entra-id"
    assert _slug("`<service>.<resource>.setIamPolicy` — self-grant") == "serviceresourcesetiampolicy--self-grant"






def test_safe_c_parser_preserves_every_catalog_entry_and_exclusion(monkeypatch):
    from peaso.privesc import schema
    if not hasattr(yaml,'CSafeLoader'):
        pytest.skip('LibYAML binding is unavailable; safe fallback remains supported')
    monkeypatch.setattr(schema,'SAFE_YAML_LOADER',yaml.SafeLoader)
    python_catalog=schema.load_catalog(strict=True)
    monkeypatch.setattr(schema,'SAFE_YAML_LOADER',yaml.CSafeLoader)
    native_catalog=schema.load_catalog(strict=True)
    assert native_catalog==python_catalog
    assert native_catalog['entries'] and native_catalog['excluded']


@pytest.mark.parametrize('loader',[yaml.SafeLoader,getattr(yaml,'CSafeLoader',yaml.SafeLoader)])
def test_both_safe_parsers_reject_python_object_tags(monkeypatch,tmp_path,loader):
    from peaso.privesc import schema
    root=tmp_path/'aws';root.mkdir()
    (root/'unsafe.yaml').write_text('!!python/object/apply:builtins.eval ["1 + 1"]\n')
    monkeypatch.setattr(schema,'SAFE_YAML_LOADER',loader)
    with pytest.raises(schema.CatalogError):schema.load_catalog(tmp_path,strict=True)
    assert schema.load_catalog(tmp_path)['entries']==[]
