"""Observed privilege-path copy stays tied to the recorded GCP path."""

import pytest

from peaso import privesc
from peaso.privesc.gcp_observed_impact import evidence_summary


IDS = (
    "gcp-workflows-create-actas-execute",
    "gcp-workflows-create-cross-project-actas",
    "gcp-workflows-update-actas",
    "gcp-workflows-update-source-retain-sa",
    "gcp-workflows-update-source-await-execution",
    "gcp-workstations-config-create-actas",
    "gcp-workstations-config-update-code",
    "gcp-workstations-use-existing-workstation",
    "gcp-workstations-create-from-existing-config",
)
ENTRIES = {entry["id"]: entry for entry in privesc.catalog()["entries"]}


def finding(cid, confidence):
    status = {"derived": "FAIL", "conditional": "MANUAL", "unknown": "UNKNOWN"}[confidence]
    missing = confidence == "unknown"
    return {
        "provider": "gcp", "category": "privesc", "check_id": cid, "status": status,
        "evidence": {
            "technique": {"id": cid, "source": ENTRIES[cid]["source"]},
            "source": {"id": "user:dev@example.com", "label": "dev@example.com"},
            "targets": [{"id": "serviceAccount:worker@example.com", "label": "worker@example.com",
                         "type": "gcp_service_account", **({"underlying_count": 0} if missing else {})}],
            "target_count": 0 if missing else 1,
            "confidence": confidence,
            "conditions": ["target_account_unresolved"] if missing else [],
            "granting_permissions": [] if missing else [{"permission": "recorded.permission"}],
            "granting_statements": [],
        },
    }


@pytest.mark.parametrize("cid", IDS)
def test_copy_rejects_unvalidated_path_evidence(cid):
    row = finding(cid, "derived")
    row["evidence"]["granting_permissions"] = []
    assert evidence_summary(row) is None
