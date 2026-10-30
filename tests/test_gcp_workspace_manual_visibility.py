"""Workspace pivots needing tenant or user interaction stay out of the active map."""

from pathlib import Path

import yaml

from peaso import privesc


MANUAL_IDS = {
    "gcp-workspace-dwd-keyless-signjwt",
    "gcp-workspace-dwd-key-create",
    "gcp-workspace-cloud-dns-admin-recovery",
    "gcp-workspace-addons-deployment-update",
}


def test_unverifiable_workspace_pivots_are_documented_but_not_loaded():
    root = Path(__file__).resolve().parents[1]
    # PR #181 recorded these exclusions in _excluded_main_reconciliation.yaml; every
    # catalog/gcp/_excluded*.yaml file is part of the excluded catalog.
    documented = {item.get("id") for path in sorted((root / "peaso/privesc/catalog/gcp").glob("_excluded*.yaml"))
                  for item in yaml.safe_load(path.read_text()) or [] if isinstance(item, dict)}
    active = {item["id"] for item in privesc.catalog()["entries"]}
    assert MANUAL_IDS <= documented
    assert MANUAL_IDS.isdisjoint(active)
