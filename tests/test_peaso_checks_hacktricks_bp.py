"""HackTricks Cloud Best Practices framework: per-check page references and module contract."""
import os
from pathlib import Path

import pytest

from peaso.checks import CHECKS
from peaso.checks.hacktricks_bp_common import HACKTRICKS_PAGES, HTBP_IDS, link
from peaso.checks.hacktricks_bp_links import LINKS
from peaso.checks import CHECKS, HACKTRICKS, HACKTRICKS_URL
from peaso.checks.hacktricks_bp_common import HACKTRICKS_BASE, HACKTRICKS_PAGES, HTBP_IDS, link

REGISTRY = {c.id: c for c in CHECKS}


def test_linked_checks_exist_and_are_not_reimplemented():
    for cid in LINKS:
        assert cid in REGISTRY, cid
        assert cid not in HTBP_IDS


@pytest.mark.parametrize("page", ["../etc/passwd.md", "https://x/y.md", "pentesting-cloud/a b.md", "pentesting-cloud/x.txt"])
def test_link_rejects_non_page_paths(page):
    with pytest.raises(ValueError):
        link("x.y", page)


def test_referenced_pages_exist_in_hacktricks_checkout():
    root = os.environ.get("PEASO_HACKTRICKS_ROOT")
    if not root:
        pytest.skip("set PEASO_HACKTRICKS_ROOT to a hacktricks-cloud checkout to verify page paths")
    missing = sorted({p for pages in HACKTRICKS_PAGES.values() for p in pages if not (Path(root) / "src" / p).is_file()})
    assert not missing
