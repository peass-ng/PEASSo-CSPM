"""Fresh-main technique decisions keep manual paths out of the active catalog."""

import json
from pathlib import Path

import yaml

from peaso import privesc
from tests.test_peaso_privesc_schema_ext_azure import az, RG, ROLE_ID, SUB
from peaso.privesc.effective_permissions.azure import AzureModel
from peaso.privesc.evaluator import Evaluator


ROOT = Path(__file__).resolve().parents[1]


def test_retired_main_only_paths_are_absent_and_source_recorded():
    active = {entry["id"] for entry in privesc.catalog()["entries"]}
    for provider in ("gcp", "azure"):
        excluded = yaml.safe_load((ROOT / "peaso/privesc/catalog" / provider /
                                   "_excluded_main_reconciliation.yaml").read_text())
        assert excluded
        assert active.isdisjoint(item["id"] for item in excluded)
        for item in excluded:
            assert item["source"] and item["reason"]


def test_related_automatic_paths_remain_active():
    active = {entry["id"] for entry in privesc.catalog()["entries"]}
    assert {
        "gcp-cloudfunctions-create-actas",
        "gcp-cloudfunctions-update-sourcecodeset-actas",
        "gcp-firebase-signjwt-exact-custom-token-user",
        "gcp-artifactregistry-upload-artifacts",
        "azure-apim-policy-write-managed-identity-token",
    } <= active


def test_static_web_apps_token_requires_exact_existing_site_and_effective_permission():
    technique = next(e for e in privesc.catalog()["entries"]
                     if e["id"] == "azure-audit-microsoftwebstaticsiteslistsecretsaction")
    site = f"{RG}/providers/Microsoft.Web/staticSites/portal"
    other = f"{RG}/providers/Microsoft.Web/staticSites/other"
    graph = ({"id": site, "name": "portal", "type": "Microsoft.Web/staticSites"},
             {"id": other, "name": "other", "type": "Microsoft.Web/staticSites"},
             {"id": f"{RG}/providers/Microsoft.Web/sites/web", "name": "web", "type": "Microsoft.Web/sites"})
    target = f"azure_verified_authority:{site.lower()}"
    wrong_target = f"azure_verified_authority:{other.lower()}"
    action = "Microsoft.Web/staticSites/listSecrets/action"
    roles = {ROLE_ID: ([action], [])}

    def evaluate(assignments, resources=graph, assigned_roles=roles):
        model = AzureModel(az(assignments=assignments, roles=assigned_roles, graph=resources))
        reaches = Evaluator(model, [technique]).run()
        return {target_id: grant.confidence for reach in reaches if reach.source.id == "u-alice"
                for target_id, grant in reach.targets.items()}

    exact = evaluate((("u-alice", "User", site, ROLE_ID),))
    assert exact[target] == "conditional"
    assert wrong_target not in exact
    assert evaluate((("u-alice", "User", f"{RG}/providers/Microsoft.Web/sites/web", ROLE_ID),)) == {}
    assert evaluate((("u-alice", "User", site, ROLE_ID),), resources=()) == {}
    assert evaluate((), assigned_roles=roles) == {}
    assert evaluate((("u-alice", "User", site, ROLE_ID),),
                    assigned_roles={ROLE_ID: (["Microsoft.Web/staticSites/read"], [])}) == {}
