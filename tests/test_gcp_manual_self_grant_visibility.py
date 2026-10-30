"""Evidence-only resource self-grants stay outside automatic CSPM checks."""

from pathlib import Path

import yaml

from peaso import privesc


IDS = {
    "gcp-runtimeconfig-configs-setiampolicy-config-self-grant",
    "gcp-servicedirectory-namespaces-setiampolicy-self-grant",
    "gcp-servicedirectory-services-setiampolicy-self-grant",
    "gcp-spanner-databases-setiampolicy-database-self-grant",
    "gcp-spanner-instances-setiampolicy-instance-self-grant",
}


def test_manual_self_grants_are_documented_but_not_active_checks():
    active = {entry["id"] for entry in privesc.catalog()["entries"]}
    # PR #181 recorded these exclusions in _excluded_main_reconciliation.yaml; every
    # catalog/gcp/_excluded*.yaml file is part of the excluded catalog.
    catalog_dir = Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/gcp"
    excluded = {entry.get("id"): entry for path in sorted(catalog_dir.glob("_excluded*.yaml"))
                for entry in yaml.safe_load(path.read_text()) or [] if isinstance(entry, dict)}
    assert IDS.isdisjoint(active)
    for ident in IDS:
        record = excluded[ident]
        assert "Manual-only" in record["reason"]
        assert record["source"].startswith("src/pentesting-cloud/")
