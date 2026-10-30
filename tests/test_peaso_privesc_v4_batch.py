"""Guard legacy escalation claims held for exact target and consumer evidence."""

from __future__ import annotations

import copy
import pytest
import json
from pathlib import Path

from peaso import privesc
from peaso.engine import privesc_technique_details
from peaso.privesc.schema import validate_entry
from peaso.privesc.effective_permissions.credential_evidence import SCOPED_IDS
from peaso.privesc.effective_permissions.azure_disclosure_effects import CONTRACT as DISCLOSURES
from peaso.privesc.versioned_catalog import (
    BINDING_SCHEMA, LEGACY_MANIFEST, LEGACY_REVISION, card_technique_ids,
    current_binding, lookup_entries, V4_MANIFEST, V4_EFFECTIVE_TREE, V4_REVISION,
)
from peaso.privesc import versioned_catalog as vc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import az
from tests.test_peaso_privesc_schema_v3_azure import _case as azure_challenge_case


HELD = (
    "aws-codecommit-gitpush-pipeline-source",
    "aws-ec2-passrole-associate-instance-profile",
    "aws-v3-05-add-or-replace-a-workspaces-web-portal-saml-oidc-identi",
    "gcp-appengine-versions-create-actas",
    "gcp-appintegration-runas-sa-actas",
    "gcp-artifactregistry-gcrio-namespace-squat",
    "gcp-privatecatalog-product-version-poison",
)
_HISTORY = json.loads((Path(__file__).resolve().parents[1] /
                       "peaso/privesc/catalog_versions/legacy-0b3633-delta.json").read_text())
# Behavioral fixtures here describe the archived v4 catalog, including claims
# intentionally removed from the strict active escalation catalog.
_ARCHIVED, _ = vc._verified_prior()
_CATALOG = tuple({key: value for key, value in entry.items() if key != "_file"}
                 for entry in _ARCHIVED.values())
_BY_ID = {entry["id"]: entry for entry in _CATALOG}
ADDED_IDS = tuple(entry["id"] for entry in _CATALOG
                  if entry["id"] not in set(_HISTORY["legacy_ids"]) and entry["id"] not in SCOPED_IDS and entry["target"].get("outcome") != "bounded_authority")


def _entry(ident):
    return copy.deepcopy(_BY_ID[ident])


def _col(kind, scope, items, status="collected"):
    return {"type": kind, "scope": scope, "service": kind, "status": status,
            "items": items, "error": None}


def _required_actions(value):
    if isinstance(value, dict):
        actions = [value["action"]] if isinstance(value.get("action"), str) else []
        return actions + [action for child in value.values() for action in _required_actions(child)]
    if isinstance(value, list):
        return [action for child in value for action in _required_actions(child)]
    return []


def _snapshot(entry):
    if entry["provider"] == "aws":
        scope = "111111111111/us-east-1"
        source = "arn:aws:iam::111111111111:user/alice"
        target = "arn:aws:iam::111111111111:role/victim"
        actions = sorted(set(_required_actions(entry.get("requires", {}))))
        user = {"UserName": "alice", "Arn": source, "GroupList": [], "AttachedManagedPolicies": [],
                "UserPolicyList": [{"PolicyName": "test", "PolicyDocument": {"Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": actions or ["*"], "Resource": "*"}]}}]}
        role = {"RoleName": "victim", "Arn": target, "Path": "/", "RolePolicyList": [],
                "AttachedManagedPolicies": [], "InstanceProfileList": [],
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}}
        fact = {"TechniqueId": entry["id"], "SourceArn": source,
                "TargetKind": entry["target"]["kind"], "TargetId": target,
                "TargetAccount": "111111111111", "Status": "verified",
                "VerifiedPreconditions": True}
        collections = [_col("iam_user", scope, [user]), _col("iam_role", scope, [role]),
                       _col("iam_group", scope, []), _col("iam_policy", scope, []),
                       _col("scp_policy", scope, [], "empty"),
                       _col("aws_privesc_challenge_evidence", scope, [fact])]
    else:
        scope = "projects/p1"
        source = "user:alice@corp.com"
        target = "serviceAccount:victim@p1.iam.gserviceaccount.com"
        role_name = "projects/p1/roles/tester"
        actions = sorted(set(_required_actions(entry.get("requires", {}))))
        fact = {"TechniqueId": entry["id"], "SourceId": source,
                "TargetKind": entry["target"]["kind"], "TargetId": target,
                "TargetScope": scope, "Status": "verified", "VerifiedPreconditions": True}
        collections = [_col("project", scope, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
                       _col("iam_policy", scope, [{"name": scope,
                                                   "bindings": [{"role": role_name, "members": [source]}]}]),
                       _col("iam_role", scope, [{"name": role_name, "includedPermissions": actions}]),
                       _col("service_account", scope, [{"email": "victim@p1.iam.gserviceaccount.com",
                                                          "projectId": "p1", "name": "projects/p1/serviceAccounts/victim@p1.iam.gserviceaccount.com"}]),
                       _col("iam_deny_policy", scope, [], "empty"),
                       _col("gcp_privesc_challenge_evidence", scope, [fact])]
    return {"schema_version": 1, "provider": entry["provider"], "scopes": [scope],
            "collections": collections, "metadata": {}}


@pytest.mark.parametrize("ident", HELD)
@pytest.mark.parametrize("include_unknown", (True, False))
def test_unreviewed_legacy_claim_has_no_reach_even_with_synthetic_fact(ident, include_unknown):
    entry = _entry(ident)
    result = privesc.analyze(_snapshot(entry), entries=[entry], include_unknown=include_unknown)
    assert not any(ident in edge.get("techniques", ()) for edge in result["graph"]["edges"])
    assert not any(f["status"] == "FAIL" for f in result["findings"])
    assert any(c.get("status") == "unresolved" and ident in c.get("reason", "")
               for c in result["coverage"])






@pytest.mark.parametrize("ident", ADDED_IDS)
def test_new_principal_rule_never_claims_definite_reach_without_exact_fact(ident):
    entry = _entry(ident)
    assert validate_entry(entry)[0] == []
    assert entry["confidence"] == "conditional"
    assert entry["target"]["kind"] in {
        "gcp_service_account", "azure_service_principal", "azure_managed_identity",
        "aws_role", "gcp_workspace_user", "k8s_service_account", "azure_user",
        "aws_account_admin", "aws_user",
    }
    if entry["provider"] == "azure":
        snap = az()
    else:
        snap = _snapshot(entry)
        snap["collections"] = [c for c in snap["collections"]
                               if not c["type"].endswith("_privesc_challenge_evidence")]
    result = privesc.analyze(snap, entries=[entry])
    assert not any(f["check_id"] == entry["id"] and f["status"] == "FAIL"
                   for f in result["findings"])
    assert not any(edge["confidence"] in ("derived", "confirmed")
                   and entry["id"] in edge.get("techniques", ()) for edge in result["graph"]["edges"])


def test_aws_cdk_fact_binds_exact_user_and_role():
    entry = _entry("aws-pa-persist-s01-30")
    source = "arn:aws:iam::111111111111:user/alice"
    target = "arn:aws:iam::111111111111:role/victim"
    snap = _snapshot(entry)
    user = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    user["UserPolicyList"] = [{"PolicyName": "p", "PolicyDocument": {"Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "cloudformation:UpdateStack", "Resource": "*"}]}}]
    fact = next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")["items"][0]
    fact.update({"TechniqueId": entry["id"], "SourceArn": source, "TargetKind": "aws_role", "TargetId": target})
    assert reached(privesc.analyze(snap, entries=[entry]), source, entry["id"]) == {target: "conditional"}
    for change in ({"SourceArn": source + "-other"}, {"TargetId": target + "-other"},
                   {"VerifiedPreconditions": False}, {"Status": "disproven"}):
        next(c for c in snap["collections"] if c["type"] == "aws_privesc_challenge_evidence")["items"] = [
            {**fact, **change}]
        assert target not in reached(privesc.analyze(snap, entries=[entry]), source, entry["id"])


def test_gcp_privatecatalog_fact_binds_exact_source_and_service_account():
    entry = _entry("gcp-privatecatalog-terraform-version-poison")
    source = "user:alice@corp.com"
    target = "serviceAccount:victim@p1.iam.gserviceaccount.com"
    snap = _snapshot(entry)
    role = "projects/p1/roles/tester"
    next(c for c in snap["collections"] if c["type"] == "iam_policy")["items"][0]["bindings"] = [
        {"role": role, "members": [source]}]
    next(c for c in snap["collections"] if c["type"] == "iam_role")["items"] = [
        {"name": role, "includedPermissions": ["cloudprivatecatalogproducer.products.update"]}]
    fact = next(c for c in snap["collections"] if c["type"] == "gcp_privesc_challenge_evidence")["items"][0]
    fact.update({"TechniqueId": entry["id"], "SourceId": source, "TargetKind": "gcp_service_account",
                 "TargetId": target})
    assert reached(privesc.analyze(snap, entries=[entry]), source, entry["id"]) == {target: "conditional"}
    for change in ({"SourceId": "user:bob@corp.com"}, {"TargetId": target + "-other"},
                   {"VerifiedPreconditions": False}, {"Status": "disproven"}):
        next(c for c in snap["collections"] if c["type"] == "gcp_privesc_challenge_evidence")["items"] = [
            {**fact, **change}]
        assert target not in reached(privesc.analyze(snap, entries=[entry]), source, entry["id"])


def test_azure_vm_fact_binds_exact_source_and_managed_identity():
    entry = _entry("azure-vm-verified-ssrf-imds")
    snap, source = azure_challenge_case(entry)
    got = reached(privesc.analyze(snap, entries=[entry]), source, entry["id"])
    assert len(got) == 1 and set(got.values()) == {"conditional"}
    for variant in ("wrong_source", "disproven", "unverified", "empty"):
        snap, source = azure_challenge_case(entry, facts=variant)
        got = reached(privesc.analyze(snap, entries=[entry]), source, entry["id"])
        assert all(confidence == "unknown" for confidence in got.values())

