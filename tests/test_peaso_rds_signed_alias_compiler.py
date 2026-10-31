"""Exact reviewed RDS alias lineage and seeded-catalog guard discrimination."""
from pathlib import Path
import copy
from dataclasses import replace
import json
import pytest
import peaso.checks as registry
from scripts import peaso_compliance_compile as compiler
ROOT = Path(__file__).resolve().parents[1]
ALIAS = "aws_fedramp_rds_cluster_members_enhanced_monitoring"
SURVIVOR = "aws.nist.rds_cluster_member_enhanced_monitoring"

@pytest.fixture
def inputs():
    pack = json.loads((ROOT / "peaso/rulepacks/compliance_requirements.json").read_text())
    proposals = {spec["id"]: spec for spec in pack["proposed_checks"]}
    check = next(check for check in registry.CHECKS if check.id == SURVIVOR)
    return pack, proposals, check

def seed(check):
    return {SURVIVOR: {"id": SURVIVOR, "provider": check.provider, "title": check.title}}

def resolve(proposals, native, row=None):
    row = row or next(iter(compiler.REVIEWED_RDS_CLUSTER_EQUIVALENT["rows"]))
    return compiler.reviewed_equivalent_proposal(proposals[ALIAS], *row, native)

def test_exact_seed_requires_live_registered_source_and_both_specs(inputs):
    pack, proposals, check = inputs
    compiler._reviewed_rds_signed_specs(proposals)
    for row in compiler.REVIEWED_RDS_CLUSTER_EQUIVALENT["rows"]:
        assert resolve(proposals, seed(check), row) == SURVIVOR
    assert resolve(proposals, {}) is None

@pytest.mark.parametrize("field,value", [("provider", "gcp"), ("type", "kms_key"), ("category", "least_privilege"), ("severity", "high"), ("target", "scope")])
def test_full_catalog_metadata_when_present_must_match(inputs, field, value):
    _, proposals, check = inputs
    native = seed(check)
    native[SURVIVOR].update(type="rds_cluster", category="hardening", severity="medium", target="resource")
    assert resolve(proposals, native) == SURVIVOR
    native[SURVIVOR][field] = value
    with pytest.raises(ValueError): resolve(proposals, native)

@pytest.mark.parametrize("field,value", [("provider", "gcp"), ("kind", "kms_key"), ("category", "least_privilege"), ("severity", "high"), ("target", "scope"), ("declared_dependencies", ("rds_cluster",))])
def test_actual_registered_declaration_must_match(inputs, monkeypatch, field, value):
    _, proposals, check = inputs
    changed = replace(check, **{field: value})
    monkeypatch.setattr(registry, "CHECKS", [changed if old.id == SURVIVOR else old for old in registry.CHECKS])
    with pytest.raises(ValueError): resolve(proposals, seed(check))

def test_wrong_alias_table_rejected(inputs, monkeypatch):
    _, proposals, check = inputs
    monkeypatch.setitem(registry.CHECK_ALIASES, ALIAS, "aws.cb.rds.instance_enhanced_monitoring_except_m1_small")
    with pytest.raises(ValueError): resolve(proposals, seed(check))

def test_absent_actual_registration_rejected(inputs, monkeypatch):
    _, proposals, check = inputs
    monkeypatch.setattr(registry, "CHECKS", [old for old in registry.CHECKS if old.id != SURVIVOR])
    with pytest.raises(ValueError): resolve(proposals, seed(check))

def test_foreign_callback_rejected(inputs, monkeypatch):
    _, proposals, check = inputs
    changed = replace(check, evaluate=lambda item, index: ("PASS", {}))
    monkeypatch.setattr(registry, "CHECKS", [changed if old.id == SURVIVOR else old for old in registry.CHECKS])
    with pytest.raises(ValueError): resolve(proposals, seed(check))

@pytest.mark.parametrize("cid", [ALIAS, SURVIVOR])
def test_changed_signed_ten_field_digest_rejected(inputs, cid):
    _, proposals, check = inputs
    altered = copy.deepcopy(proposals)
    altered[cid]["description"] += " changed"
    with pytest.raises(ValueError): compiler._reviewed_rds_signed_specs(altered)
    if cid == ALIAS:
        with pytest.raises(ValueError): resolve(altered, seed(check))

def test_moved_control_rejected(inputs):
    _, proposals, check = inputs
    with pytest.raises(ValueError): resolve(proposals, seed(check), ("unknown", "unknown"))

def test_real_compiled_alias_edges_stay_partial_and_no_duplicate_native(inputs):
    pack, proposals, check = inputs
    expected = compiler.REVIEWED_RDS_CLUSTER_EQUIVALENT["rows"]
    tags = pack["by_check"][SURVIVOR]
    assert expected <= {(tag["framework_id"], tag["requirement_id"]) for tag in tags}
    assert all(tag["runtime_status"] == "partial" and tag["decision"] == "PARTIAL" for tag in tags)
    assert len(tags) == 5
    assert ALIAS not in pack["by_check"]
    catalog = json.loads((ROOT / "peaso/rulepacks/native_catalog.json").read_text())
    assert sum(row["id"] == SURVIVOR for row in catalog["checks"]) == 1
    assert all(row["id"] != ALIAS for row in catalog["checks"])
    assert registry.CHECK_ALIASES[ALIAS] == SURVIVOR
