"""Permissions seen in live least-privilege reviews must have a bundled criticality.

The GCP/AWS role definitions collected in validation snapshots carried permissions
that no catalog entry or rule recognized, so peaso reported them as
``permission_criticality_unknown``. These checks cover a sample of the audited
additions and keep the categorized catalogs internally consistent.
"""
from pathlib import Path

import pytest
import yaml

from peaso.analysis.iam import permission_severity

ROOT = Path(__file__).resolve().parents[1]
LEVELS = ("low", "medium", "high", "critical")


@pytest.mark.parametrize("provider,permission,level", [
    ("gcp", "chronicle.dataTableRows.bulkGet", "low"),
    ("gcp", "cloudaicompanion.settingBindings.loggingSettingsList", "low"),
    ("gcp", "compute.instances.performMaintenance", "medium"),
    ("gcp", "dataplex.entryGroups.useDocumentEntry", "medium"),
    ("gcp", "cloudaicompanion.settingBindings.loggingSettingsUpdate", "medium"),
    # Secret, data-copy and code-delivery primitives documented in HackTricks Cloud.
    ("gcp", "parametermanager.parameterVersions.render", "high"),
    ("gcp", "datastore.databases.clone", "high"),
    ("gcp", "compute.recoverableSnapshots.recover", "high"),
    ("gcp", "developerconnect.gitRepositoryLinks.gitProxyWrite", "high"),
    ("gcp", "securesourcemanager.pullRequests.merge", "high"),
    ("gcp", "eventarc.messageBuses.use", "high"),
    ("gcp", "firebaseappcheck.tokens.mint", "high"),
    ("gcp", "iam.googleapis.com/workforcePoolProviderScimGroups.put", "critical"),
    ("aws", "sqs:SendMessageBatch", "high"),
    ("aws", "datazone:QueryGraph", "low"),
    ("aws", "acm:searchCertificates", "low"),
    # Legacy topic-policy action that grants nothing.
    ("aws", "SNS:Receive", "low"),
])
def test_previously_unknown_permissions_are_classified(provider, permission, level):
    assert permission_severity(provider, permission) == level


@pytest.mark.parametrize("permission", [
    "edgecontainer.serviceaccounts.generatekey",
    "firebasedataconnect.connectors.impersonateMutation",
    "cloudkms.cryptoKeyVersions.trustedImportExport",
    "backupdr.bvbackups.useReadOnlyForCloudSqlInstance",
])
def test_credential_and_data_access_additions_are_not_low(permission):
    assert permission_severity("gcp", permission) in {"high", "critical"}


@pytest.mark.parametrize("provider", ["aws", "gcp", "azure"])
def test_catalogs_have_no_duplicates_and_match_bundled_rules(provider):
    path = ROOT / f"{provider}_permissions_cat.yaml"
    if path.is_file():
        raw = path.read_bytes()
    else:
        rules = yaml.safe_load((ROOT / "risk_rules" / f"{provider}.yaml").read_text())
        raw = yaml.safe_dump(rules["permission_categories"], sort_keys=False, allow_unicode=True).encode()
    catalog = yaml.safe_load(raw)
    assert tuple(catalog) == LEVELS
    norm = str.casefold if provider in {"aws", "azure"} else (lambda p: p)
    seen = {}
    for level in LEVELS:
        values = catalog[level]
        assert values == sorted(values), (provider, level)
        assert len(values) == len(set(values)), (provider, level)
        for permission in values:
            # Upstream keeps some same-level case variants (AWS/Azure match
            # case-insensitively); a permission must never sit in two levels.
            assert seen.setdefault(norm(permission), level) == level, (provider, permission, seen[norm(permission)], level)
    rules = yaml.safe_load((ROOT / "risk_rules" / f"{provider}.yaml").read_text())
    assert rules["permission_categories"] == catalog
