"""Fail-closed intake for supervisor-verified framework requirement ledgers."""
from collections import Counter
import hashlib
import json

import pytest

from scripts.peaso_compliance_compile import (catalog_with_registered_checks, compile_verified,
                                              coverage_matrix, lookup_index, spec_digest, strict_json)
from scripts.peaso_compliance_merge_new import main as stage_descriptions, merge


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded(value))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fixture_tree(tmp_path):
    root = tmp_path / "ledgers"
    native = {"checks": [{"id": "aws.fixture.existing", "provider": "aws", "title": "Existing check"}]}
    matrix = {"hacktricks_best_practices": {"status": "thematic guidance only", "requirements_total": None,
                                            "reason": "No independent numbered requirements in this fixture."},
              "frameworks": [{"id": "aws_fixture", "name": "Pinned fixture", "provider": "aws",
                              "counts": {"automated_reference": 1, "missing_or_partial": 1, "missing_unmapped": 1},
                              "requirements": [{"id": "1", "name": "Existing requirement"},
                                               {"id": "2", "name": "Partially tested requirement"},
                                               {"id": "3", "name": "Proposed technical requirement"}]}]}
    frozen = {"slice": "aws-fixture", "frameworks": [{"id": "aws_fixture", "name": "Pinned fixture", "provider": "aws",
                 "requirements": [{"id": str(n), "name": name} for n, name in
                                  [(1, "Existing requirement"), (2, "Partially tested requirement"), (3, "Proposed technical requirement")]]}]}
    rows = [
        {"requirement_id": "1", "name": "Existing requirement", "decision": "MAPPED",
         "native_checks": ["aws.fixture.existing"], "removed_checks": [],
         "reason": "The existing native predicate evaluates the exact fixture field.",
         "evidence": ["pinned/source:1"], "new_checks": []},
        {"requirement_id": "2", "name": "Partially tested requirement", "decision": "PARTIAL",
         "native_checks": ["aws.fixture.existing"], "removed_checks": [],
         "reason": "The fixture has a separate process-only attestation remainder.",
         "evidence": ["pinned/source:2"], "new_checks": []},
        {"requirement_id": "3", "name": "Proposed technical requirement", "decision": "NEW_CHECK",
         "native_checks": [], "removed_checks": [],
         "reason": "The technical field is absent from current native checks.",
         "evidence": ["pinned/source:3"], "new_checks": [{"id": "aws.fixture.proposed", "provider": "aws",
          "resource_kind": "fixture", "data_source": "snapshot.fixture", "predicate": "enabled is true",
          "severity": "medium", "category": "hardening", "title": "Fixture enabled",
          "description": "Read the enabled field and fail when it is false because the fixture becomes exposed.",
          "remediation_hint": "Enable the fixture."}]},
    ]
    ledger = {"slice": "aws-fixture", "generated_from": "inputs/aws-fixture.json",
              "frameworks": [{"id": "aws_fixture", "provider": "aws", "requirements": rows}]}
    description = {"description": "Evaluates the fixture.enabled field and identifies disabled fixtures that can expose the account.",
                   "evaluated": ["fixture.enabled"], "pass_when": "The enabled field is true.",
                   "fail_when": "The enabled field is false.", "not_applicable_when": None}
    desc = {"aws.fixture.existing": description}
    write(root / "inputs/check-index.json", native["checks"])
    write(root / "inputs/aws-fixture.json", frozen)
    write(root / "inputs/desc-fixture.json", ["aws.fixture.existing"])
    write(root / "aws-fixture.json", ledger)
    write(root / "descriptions/desc-fixture.json", desc)
    refresh_manifest(root)
    return root, matrix, native


def refresh_manifest(root):
    sha = lambda relative: hashlib.sha256((root / relative).read_bytes()).hexdigest()
    manifest = {"version": 1, "check_index_sha256": sha("inputs/check-index.json"),
                "slices": {"aws-fixture": {"path": "aws-fixture.json", "sha256": sha("aws-fixture.json"),
                                           "input_sha256": sha("inputs/aws-fixture.json"), "requirements_total": 3,
                                           "verified": True}},
                "descriptions": {"desc-fixture": {"path": "descriptions/desc-fixture.json",
                                                  "sha256": sha("descriptions/desc-fixture.json"),
                                                  "input_sha256": sha("inputs/desc-fixture.json"), "checks": 1,
                                                  "verified": True}}}
    write(root / "manifest.json", manifest)


def test_verified_ledger_maps_both_directions_and_preserves_unknown(tmp_path):
    root, matrix, native = fixture_tree(tmp_path)
    requirements, descriptions = compile_verified(root, matrix, native)
    assert len(requirements["frameworks"]) == 1 and len(descriptions["checks"]) == 1
    rows = requirements["frameworks"][0]["requirements"]
    assert [(row["requirement_id"], row["runtime_status"]) for row in rows] == [
        ("1", "automated"), ("2", "partial"), ("3", "not_assessed")]
    assert rows[2]["pending_checks"] == ["aws.fixture.proposed"]
    assert [(tag["framework_id"], tag["requirement_id"]) for tag in requirements["by_check"]["aws.fixture.existing"]] == [
        ("aws_fixture", "1"), ("aws_fixture", "2")]
    assert requirements["counts"] == {"automated": 1, "not_assessed": 1, "partial": 1}
    matrix_report = coverage_matrix(matrix, requirements)
    assert matrix_report["pending_automatable_requirements"] == 1
    assert matrix_report["frameworks"][0]["pending_automatable_requirement_ids"] == ["3"]
    assert matrix_report["unique_implemented_native_checks"] == 1


def extension_tree(tmp_path, linked=False):
    root, matrix, native = fixture_tree(tmp_path)
    spec = {"id": "aws.fixture.security_extension", "provider": "aws", "resource_kind": "fixture",
            "data_source": "Read-only fixture policy document", "predicate": "Restrictive policy is present",
            "severity": "medium", "category": "hardening", "title": "Fixture policy is restrictive",
            "description": "Checks the independent fixture policy document for its explicit restrictive condition.",
            "remediation_hint": "Restrict the fixture policy."}
    native["checks"].append({"id": spec["id"], "provider": "aws", "title": spec["title"],
                             "type": "fixture", "category": "hardening", "severity": "medium",
                             "target": "resource", "dependencies": ["fixture"]})
    row = {"spec": spec, "sources": [{"url": "https://example.org/pinned/fixture.py", "sha256": "a" * 64}],
           "requirements": ([{"framework_id": "aws_fixture", "requirement_id": "2",
                              "reason": "This policy is an additional technical signal only; the process remainder is unchanged."}]
                            if linked else [])}
    path = "native-extensions/aws-fixture.json"
    sha = write(root / path, {"schema_version": 1, "checks": [row]})
    description = {"description": spec["description"], "evaluated": [spec["data_source"]],
                   "pass_when": "The restrictive condition is present.",
                   "fail_when": "The restrictive condition is absent.", "not_applicable_when": None,
                   "proposed_spec_sha256": spec_digest(spec)}
    supplemental = "descriptions/implemented-new-checks.json"
    desc_sha = write(root / supplemental, {spec["id"]: description})
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["native_extensions"] = [{"path": path, "sha256": sha, "verified": True}]
    manifest["new_descriptions"] = {"path": supplemental, "sha256": desc_sha, "verified": True, "checks": 1}
    write(root / "manifest.json", manifest)
    return root, matrix, native


@pytest.mark.parametrize("linked", [False, True])
def test_reviewed_security_extensions_preserve_truthful_checklist_scope(tmp_path, linked):
    root, matrix, native = extension_tree(tmp_path, linked)
    pack, descriptions = compile_verified(root, matrix, native)
    cid = "aws.fixture.security_extension"
    assert cid in descriptions["checks"]
    assert cid in {s["id"] for s in pack["proposed_checks"]}
    assert len(pack["by_check"][cid]) == int(linked)
    if linked:
        assert pack["by_check"][cid] == [{"framework_id": "aws_fixture", "requirement_id": "2",
                                         "decision": "PARTIAL", "runtime_status": "partial"}]
    else:
        assert all(cid not in r["native_checks"] for f in pack["frameworks"] for r in f["requirements"])


@pytest.mark.parametrize("change", ["unverified", "hash", "duplicate", "no_sources", "unknown_requirement", "foreign_provider"])
def test_native_extension_intake_is_fail_closed(tmp_path, change):
    root, matrix, native = extension_tree(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text())
    entry = manifest["native_extensions"][0]
    document = json.loads((root / entry["path"]).read_text())
    row = document["checks"][0]
    if change == "unverified":
        entry["verified"] = False
    elif change == "hash":
        entry["sha256"] = "0" * 64
    else:
        if change == "duplicate":
            document["checks"].append(row)
        elif change == "no_sources":
            row["sources"] = []
        elif change == "unknown_requirement":
            row["requirements"] = [{"framework_id": "aws_fixture", "requirement_id": "invented",
                                    "reason": "This is not an existing reviewed checklist requirement."}]
        else:
            row["spec"]["provider"] = "azure"
        entry["sha256"] = write(root / entry["path"], document)
    write(root / "manifest.json", manifest)
    with pytest.raises(ValueError):
        compile_verified(root, matrix, native)


@pytest.mark.parametrize("field,value", [("resource_kind", "wrong_kind"), ("category", "exposure"),
                                        ("category", "historical_compliance_category"),
                                        ("severity", "critical"), ("severity", "UNSPECIFIED")])
def test_rehashed_extension_must_match_registered_typed_contract(tmp_path, field, value):
    root, matrix, native = extension_tree(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text())
    entry = manifest["native_extensions"][0]
    document = json.loads((root / entry["path"]).read_text())
    document["checks"][0]["spec"][field] = value
    entry["sha256"] = write(root / entry["path"], document)
    write(root / "manifest.json", manifest)
    with pytest.raises(ValueError, match="registered typed contract"):
        compile_verified(root, matrix, native)


@pytest.mark.parametrize("target", [None, "invalid", "scope"])
def test_extension_cannot_silently_change_registered_target(tmp_path, target):
    root, matrix, native = extension_tree(tmp_path)
    native["checks"][-1]["target"] = target
    with pytest.raises(ValueError, match="registered typed contract"):
        compile_verified(root, matrix, native)


def test_scope_extension_requires_explicit_matching_target(tmp_path):
    root, matrix, native = extension_tree(tmp_path)
    native["checks"][-1]["target"] = "scope"
    manifest = json.loads((root / "manifest.json").read_text())
    entry = manifest["native_extensions"][0]
    document = json.loads((root / entry["path"]).read_text())
    document["checks"][0]["target"] = "scope"
    entry["sha256"] = write(root / entry["path"], document)
    write(root / "manifest.json", manifest)
    pack, _ = compile_verified(root, matrix, native)
    assert "aws.fixture.security_extension" in pack["by_check"]


def test_extension_validation_uses_live_contract_even_with_stale_stored_native_row(tmp_path):
    from types import SimpleNamespace
    root, matrix, native = extension_tree(tmp_path)
    existing = SimpleNamespace(id="aws.fixture.existing", provider="aws", title="Existing check")
    changed = SimpleNamespace(id="aws.fixture.security_extension", provider="aws", title="Fixture policy is restrictive",
                               kind="changed_runtime_kind", category="hardening", severity="medium", target="resource")
    augmented = catalog_with_registered_checks(native, [existing, changed])
    assert native["checks"][-1]["type"] == "fixture"  # Input and historical metadata untouched.
    assert augmented["checks"][-1]["type"] == "fixture"
    with pytest.raises(ValueError, match="registered typed contract"):
        compile_verified(root, matrix, augmented)


@pytest.mark.parametrize("mutation", [None, "prior", "replacement", "unsigned"])
def test_description_errata_preserve_exact_ancestry(tmp_path, mutation):
    root, matrix, native = fixture_tree(tmp_path)
    original = json.loads((root / "descriptions/desc-fixture.json").read_text())["aws.fixture.existing"]
    replacement = {**original, "description": "Checks the exact enabled configuration flag; unresolved collection remains unknown and does not imply disabled protection."}
    row = {"prior_sha256": spec_digest(original), "replacement_sha256": spec_digest(replacement),
           "description": replacement, "reason": "A reviewed clarification preserves the actual existing predicate semantics."}
    if mutation == "prior":
        row["prior_sha256"] = "0" * 64
    elif mutation == "replacement":
        row["replacement_sha256"] = "0" * 64
    path = "descriptions/reviewed-errata.json"
    sha = write(root / path, {"schema_version": 1, "checks": {"aws.fixture.existing": row}})
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["description_errata"] = {"path": path, "sha256": sha, "verified": mutation != "unsigned"}
    write(root / "manifest.json", manifest)
    if mutation:
        with pytest.raises(ValueError):
            compile_verified(root, matrix, native)
    else:
        assert compile_verified(root, matrix, native)[1]["checks"]["aws.fixture.existing"] == replacement


def test_empty_pinned_title_can_be_enriched_but_nonempty_title_cannot_change(tmp_path):
    root, matrix, native = fixture_tree(tmp_path)
    matrix["frameworks"][0]["requirements"][0]["name"] = ""
    frozen = json.loads((root / "inputs/aws-fixture.json").read_text())
    frozen["frameworks"][0]["requirements"][0]["name"] = ""
    write(root / "inputs/aws-fixture.json", frozen)
    refresh_manifest(root)
    assert compile_verified(root, matrix, native)[0]["frameworks"][0]["requirements"][0]["name"] == "Existing requirement"
    matrix["frameworks"][0]["requirements"][0]["name"] = "Different pinned title"
    frozen["frameworks"][0]["requirements"][0]["name"] = "Different pinned title"
    write(root / "inputs/aws-fixture.json", frozen)
    refresh_manifest(root)
    with pytest.raises(ValueError, match="name or decision mismatch"):
        compile_verified(root, matrix, native)


def test_structured_source_evidence_requires_complete_location(tmp_path):
    root, matrix, native = fixture_tree(tmp_path)
    ledger = json.loads((root / "aws-fixture.json").read_text())
    evidence = {"check_id": "aws.fixture.existing", "source": "peaso/checks/fixture.py", "line": 12,
                "predicate": "fixture.enabled is true"}
    ledger["frameworks"][0]["requirements"][0]["evidence"] = [evidence]
    write(root / "aws-fixture.json", ledger)
    refresh_manifest(root)
    assert compile_verified(root, matrix, native)[0]["frameworks"][0]["requirements"][0]["evidence"] == [evidence]
    evidence["line"] = 0
    write(root / "aws-fixture.json", ledger)
    refresh_manifest(root)
    with pytest.raises(ValueError, match="Invalid requirement evidence"):
        compile_verified(root, matrix, native)


def test_runtime_helpers_use_compiled_tags_and_reviewed_description(tmp_path, monkeypatch):
    from peaso.checks import catalog
    root, matrix, native = fixture_tree(tmp_path)
    requirements, descriptions = compile_verified(root, matrix, native)
    pack = tmp_path / "pack"
    full_sha = write(pack / "compliance_requirements.json", requirements)
    write(pack / "compliance_lookup.json", lookup_index(requirements, full_sha))
    write(pack / "check_descriptions.json", descriptions)
    write(pack / "runtime_metadata.json", {"frameworks": [{"id": "aws_fixture", "name": "Pinned fixture", "provider": "aws",
         "native_check_ids": [], "supported_native_checks": 0, "status": "partially_supported"}],
         "mappings": {}, "framework_lookup": {}, "coverage": {}})
    monkeypatch.setattr(catalog, "PACK", pack)
    catalog.clear_caches()
    try:
        assert catalog.framework_ids_for("aws.fixture.existing") == ["aws_fixture"]
        assert [tag["requirement_id"] for tag in catalog.requirement_tags_for("aws.fixture.existing")] == ["1", "2"]
        assert catalog.description_for("aws.fixture.existing")["evaluated"] == ["fixture.enabled"]
        assert catalog.full_requirements()["frameworks"][0]["requirements"][0]["reason"] == (
            "The existing native predicate evaluates the exact fixture field.")
        proposal = catalog.proposal_provenance_for("aws.fixture.proposed")
        assert proposal["signed_category"] == "hardening"
        assert proposal["signed_provider"] == "aws" and proposal["signed_severity"] == "medium"
        assert proposal["signed_spec_sha256"] == spec_digest(requirements["proposed_checks"][0])
        version = catalog.framework_catalog()[0]
        assert version["requirements_total"] == 3
        assert version["requirements_by_status"] == {"automated": 1, "not_assessed": 1, "partial": 1}
        assert version["native_check_ids"] == ["aws.fixture.existing"]
        mapping = catalog.mappings_for("aws.fixture.existing", "hardening", "fixture")
        assert [item["control_id"] for item in mapping["Pinned fixture"]["controls"]] == ["1", "2"]
        value = catalog.description_for("aws.fixture.existing")
        value["evaluated"].append("untrusted mutation")
        assert catalog.description_for("aws.fixture.existing")["evaluated"] == ["fixture.enabled"]
        (pack / "compliance_requirements.json").write_text("{}")
        catalog.full_requirements.cache_clear()
        with pytest.raises(ValueError, match="changed after lookup"):
            catalog.full_requirements()
    finally:
        catalog.clear_caches()


@pytest.mark.parametrize("mutation", ["missing_manifest", "unverified", "wrong_hash", "missing_slice", "path_escape", "missing_decision", "extra_file"])
def test_incomplete_or_tampered_ledger_rejected(tmp_path, mutation):
    root, matrix, native = fixture_tree(tmp_path)
    manifest = json.loads((root / "manifest.json").read_text())
    if mutation == "missing_manifest":
        (root / "manifest.json").unlink()
    elif mutation == "unverified":
        manifest["slices"]["aws-fixture"]["verified"] = False
        write(root / "manifest.json", manifest)
    elif mutation == "wrong_hash":
        manifest["slices"]["aws-fixture"]["sha256"] = "0" * 64
        write(root / "manifest.json", manifest)
    elif mutation == "missing_slice":
        manifest["slices"] = {}
        write(root / "manifest.json", manifest)
    elif mutation == "path_escape":
        manifest["descriptions"]["desc-fixture"]["path"] = "../descriptions/desc-fixture.json"
        write(root / "manifest.json", manifest)
    elif mutation == "missing_decision":
        ledger = json.loads((root / "aws-fixture.json").read_text())
        ledger["frameworks"][0]["requirements"].pop()
        write(root / "aws-fixture.json", ledger)
        refresh_manifest(root)
    elif mutation == "extra_file":
        write(root / "unlisted.json", {})
    with pytest.raises(ValueError):
        compile_verified(root, matrix, native)


def test_research_json_is_not_treated_as_unsigned_runtime_input(tmp_path):
    root, matrix, native = fixture_tree(tmp_path)
    write(root / "new-checks-aws.json", [])
    write(root / "descriptions/desc-azure-2.problems.json", {})
    write(root / ".work/review/inventory.json", {})
    assert compile_verified(root, matrix, native)[0]["counts"]["automated"] == 1


def test_signed_proposal_creates_bidirectional_tag_when_implemented(tmp_path):
    root, matrix, native = fixture_tree(tmp_path)
    native["checks"].append({"id": "aws.fixture.proposed", "provider": "aws", "title": "Fixture enabled"})
    index = json.loads((root / "inputs/check-index.json").read_text())
    index.append(native["checks"][-1])
    write(root / "inputs/check-index.json", index)
    ids = json.loads((root / "inputs/desc-fixture.json").read_text()) + ["aws.fixture.proposed"]
    write(root / "inputs/desc-fixture.json", ids)
    descriptions = json.loads((root / "descriptions/desc-fixture.json").read_text())
    descriptions["aws.fixture.proposed"] = {"description": "Evaluates the independent fixture.enabled field and identifies exposure when it is disabled.",
        "evaluated": ["fixture.enabled"], "pass_when": "The fixture enabled field is true.",
        "fail_when": "The fixture enabled field is false.", "not_applicable_when": None}
    write(root / "descriptions/desc-fixture.json", descriptions)
    refresh_manifest(root)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["descriptions"]["desc-fixture"]["checks"] = 2
    write(root / "manifest.json", manifest)
    pack = compile_verified(root, matrix, native)[0]
    rows = pack["frameworks"][0]["requirements"]
    assert rows[2]["runtime_status"] == "automated"
    assert rows[2]["pending_checks"] == []
    assert rows[2]["native_checks"] == ["aws.fixture.proposed"]
    assert pack["by_check"]["aws.fixture.proposed"][0]["requirement_id"] == "3"


def test_declared_but_unimplemented_proposed_check_is_not_a_pass(tmp_path):
    root, matrix, native = fixture_tree(tmp_path)
    ledger = json.loads((root / "aws-fixture.json").read_text())
    ledger["frameworks"][0]["requirements"][2]["native_checks"] = ["aws.fixture.proposed"]
    write(root / "aws-fixture.json", ledger)
    refresh_manifest(root)
    result = compile_verified(root, matrix, native)[0]
    proposed = result["frameworks"][0]["requirements"][2]
    assert proposed["runtime_status"] == "not_assessed"
    assert proposed["native_checks"] == [] and proposed["declared_check_ids"] == ["aws.fixture.proposed"]
    assert "aws.fixture.proposed" not in result["by_check"]


@pytest.mark.parametrize("change", ["empty", "title_copy", "boilerplate", "missing_field"])
def test_description_quality_gate_rejects_unreviewed_text(tmp_path, change):
    root, matrix, native = fixture_tree(tmp_path)
    path = root / "descriptions/desc-fixture.json"
    rows = json.loads(path.read_text())
    value = rows["aws.fixture.existing"]
    if change == "empty":
        value["description"] = ""
    elif change == "title_copy":
        value["description"] = "Existing check"
    elif change == "boilerplate":
        value["description"] = "Existing check; inspect collected configuration without inferring effective access."
    else:
        value["evaluated"] = []
    write(path, rows)
    refresh_manifest(root)
    with pytest.raises(ValueError):
        compile_verified(root, matrix, native)


def test_wrong_provider_mapping_rejected(tmp_path):
    root, matrix, native = fixture_tree(tmp_path)
    native["checks"][0]["provider"] = "azure"
    with pytest.raises(ValueError, match="provider"):
        compile_verified(root, matrix, native)


def test_unreviewed_new_registered_id_cannot_bypass_frozen_description_index(tmp_path):
    root, matrix, native = fixture_tree(tmp_path)
    native["checks"].append({"id": "aws.fixture.unreviewed", "provider": "aws", "title": "Unreviewed"})
    with pytest.raises(ValueError, match="signed proposal descriptions"):
        compile_verified(root, matrix, native)


def test_registry_additions_wait_for_signed_proposal_and_description(tmp_path):
    from types import SimpleNamespace
    root, matrix, native = fixture_tree(tmp_path)
    existing = SimpleNamespace(id="aws.fixture.existing", provider="aws", title="Existing check")
    proposed = SimpleNamespace(id="aws.fixture.proposed", provider="aws", title="Fixture enabled",
                               kind="fixture", category="hardening", severity="medium", target="resource",
                               dependencies=["fixture"])
    augmented = catalog_with_registered_checks(native, [existing, proposed])
    assert [row["id"] for row in augmented["checks"]] == [existing.id, proposed.id]
    assert augmented["checks"][-1] == {"id": proposed.id, "provider": "aws", "title": proposed.title,
                                         "type": "fixture", "category": "hardening", "severity": "medium",
                                         "target": "resource", "dependencies": ["fixture"]}
    with pytest.raises(ValueError, match="signed proposal descriptions"):
        compile_verified(root, matrix, augmented)
    with pytest.raises(ValueError, match="provider differs"):
        catalog_with_registered_checks({"checks": [{"id": existing.id, "provider": "gcp"}]}, [existing])
    with pytest.raises(ValueError, match="unregistered"):
        catalog_with_registered_checks(native, [proposed])


def test_archived_legacy_category_bootstrap_preserves_history_without_admitting_new_categories():
    from types import SimpleNamespace
    legacy = SimpleNamespace(id="aws.fixture.archived", provider="aws", title="Historical contract",
                              kind="fixture", category="compliance", severity="medium", target="resource",
                              dependencies=["fixture"])
    native = {"checks": [], "archived_checks": [{"id": legacy.id, "provider": "aws", "category": "compliance"}]}
    result = catalog_with_registered_checks(native, [legacy])
    assert result["checks"][0]["category"] == "compliance"
    assert result["checks"][0]["type"] == "fixture"
    assert native["checks"] == []
    with pytest.raises(ValueError, match="typed contract"):
        catalog_with_registered_checks({"checks": [], "archived_checks": []}, [legacy])


@pytest.mark.parametrize("change", ["valid", "wrong_spec_hash", "legacy_override", "unknown_extra", "unsigned"])
def test_signed_new_check_description_supplement_is_exact(tmp_path, change):
    root, matrix, native = fixture_tree(tmp_path)
    cid = "aws.fixture.proposed"
    native["checks"].append({"id": cid, "provider": "aws", "title": "Fixture enabled"})
    ledger = json.loads((root / "aws-fixture.json").read_text())
    requirement = ledger["frameworks"][0]["requirements"][2]
    spec = requirement["new_checks"][0]
    write(root / "aws-fixture.json", ledger)
    refresh_manifest(root)
    descriptions = {cid: {"description": "Evaluates snapshot.fixture.enabled and identifies disabled fixtures that can expose the account to avoidable risk.",
                          "evaluated": ["snapshot.fixture.enabled"], "pass_when": "The fixture enabled field is true.",
                          "fail_when": "The fixture enabled field is false.", "not_applicable_when": None,
                          "proposed_spec_sha256": spec_digest(spec)}}
    if change == "wrong_spec_hash":
        descriptions[cid]["proposed_spec_sha256"] = "0" * 64
    if change == "legacy_override":
        descriptions["aws.fixture.existing"] = dict(descriptions[cid])
    if change == "unknown_extra":
        descriptions["aws.fixture.unlisted"] = dict(descriptions[cid])
    supplement_path = root / "descriptions/implemented-new-checks.json"
    sha = write(supplement_path, descriptions)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["new_descriptions"] = {"path": "descriptions/implemented-new-checks.json", "sha256": sha,
                                    "checks": len(descriptions), "verified": change != "unsigned"}
    write(root / "manifest.json", manifest)
    if change == "valid":
        requirements, prose = compile_verified(root, matrix, native)
        result = requirements["frameworks"][0]["requirements"][2]
        assert result["runtime_status"] == "automated" and result["native_checks"] == [cid]
        assert requirements["by_check"][cid][0]["requirement_id"] == "3"
        assert prose["checks"][cid]["evaluated"] == ["snapshot.fixture.enabled"]
        assert "proposed_spec_sha256" not in prose["checks"][cid]
    else:
        with pytest.raises(ValueError):
            compile_verified(root, matrix, native)


def test_one_of_multiple_signed_proposals_keeps_requirement_not_assessed(tmp_path):
    root, matrix, native = fixture_tree(tmp_path)
    cid = "aws.fixture.proposed"
    native["checks"].append({"id": cid, "provider": "aws", "title": "Fixture enabled"})
    ledger = json.loads((root / "aws-fixture.json").read_text())
    row = ledger["frameworks"][0]["requirements"][2]
    first = row["new_checks"][0]
    second = {**first, "id": "aws.fixture.second", "title": "Second fixture setting"}
    row["new_checks"].append(second)
    write(root / "aws-fixture.json", ledger)
    refresh_manifest(root)
    supplement = {cid: {"description": "Evaluates the collected fixture.enabled field; a disabled fixture exposes the account to avoidable risk.",
                        "evaluated": ["fixture.enabled"], "pass_when": "The enabled field is true.",
                        "fail_when": "The enabled field is false.", "not_applicable_when": None,
                        "proposed_spec_sha256": spec_digest(first)}}
    sha = write(root / "descriptions/implemented-new-checks.json", supplement)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["new_descriptions"] = {"path": "descriptions/implemented-new-checks.json", "sha256": sha,
                                    "checks": 1, "verified": True}
    write(root / "manifest.json", manifest)
    pack, _ = compile_verified(root, matrix, native)
    result = pack["frameworks"][0]["requirements"][2]
    assert result["runtime_status"] == "not_assessed"
    assert result["native_checks"] == [cid]
    assert result["pending_checks"] == [second["id"]]
    assert pack["by_check"][cid][0]["runtime_status"] == "not_assessed"


@pytest.mark.parametrize("change,expected", [
    ("valid", None), ("wrong_hash", "signed spec hash"),
    ("unknown_id", "unsigned"), ("wrong_provider", "cross-provider"),
    ("duplicate_description", "duplicate new description"),
])
def test_provider_description_shard_merge_checks_signed_specs(tmp_path, change, expected):
    root, _, _ = fixture_tree(tmp_path)
    ledger = json.loads((root / "aws-fixture.json").read_text())
    spec = ledger["frameworks"][0]["requirements"][2]["new_checks"][0]
    shard_dir = tmp_path / "handoff"
    shard = {spec["id"]: {"description": "Evaluates collected fixture.enabled and detects disabled fixtures that can expose the account to avoidable risk.",
                          "evaluated": ["fixture.enabled"], "pass_when": "The fixture enabled field is true.",
                          "fail_when": "The fixture enabled field is false.", "not_applicable_when": None,
                          "proposed_spec_sha256": spec_digest(spec)}}
    path = shard_dir / "compliance-new-descriptions-aws.json"
    if change == "wrong_hash":
        shard[spec["id"]]["proposed_spec_sha256"] = "0" * 64
    elif change == "unknown_id":
        shard["aws.fixture.unsigned"] = shard.pop(spec["id"])
    elif change == "wrong_provider":
        path = shard_dir / "compliance-new-descriptions-gcp.json"
    elif change == "duplicate_description":
        second = {**spec, "id": "aws.fixture.second", "title": "Different setting"}
        ledger["frameworks"][0]["requirements"][2]["new_checks"].append(second)
        write(root / "aws-fixture.json", ledger)
        refresh_manifest(root)
        shard[second["id"]] = {**shard[spec["id"]], "proposed_spec_sha256": spec_digest(second)}
    write(path, shard)
    if expected is None:
        assert set(merge(root, shard_dir)) == {spec["id"]}
    else:
        with pytest.raises(ValueError, match=expected):
            merge(root, shard_dir)


def test_description_stage_requires_exact_new_registered_batch(tmp_path, monkeypatch):
    from types import SimpleNamespace
    root, _, _ = fixture_tree(tmp_path)
    spec = json.loads((root / "aws-fixture.json").read_text())["frameworks"][0]["requirements"][2]["new_checks"][0]
    shard_dir = tmp_path / "handoff"
    shard = {spec["id"]: {"description": "Evaluates fixture.enabled and identifies a disabled fixture that can expose this account to avoidable risk.",
                          "evaluated": ["fixture.enabled"], "pass_when": "The fixture enabled field is true.",
                          "fail_when": "The fixture enabled field is false.", "not_applicable_when": None,
                          "proposed_spec_sha256": spec_digest(spec)}}
    write(shard_dir / "compliance-new-descriptions-aws.json", shard)
    output = root / ".work/implemented-new-checks.json"
    argv = ["--ledger-root", str(root), "--shard-dir", str(shard_dir), "--output", str(output), "--write"]
    import peaso.checks
    monkeypatch.setattr(peaso.checks, "CHECKS", [SimpleNamespace(id="aws.fixture.existing")])
    with pytest.raises(ValueError, match="exactly match"):
        stage_descriptions(argv)
    assert not output.exists()
    monkeypatch.setattr(peaso.checks, "CHECKS", [SimpleNamespace(id="aws.fixture.existing"),
                                                 SimpleNamespace(id=spec["id"], provider="aws", severity="medium")])
    assert stage_descriptions(argv) == 0
    assert json.loads(output.read_text()) == shard
    monkeypatch.setattr(peaso.checks, "CHECKS", [SimpleNamespace(id="aws.fixture.existing"),
                                                 SimpleNamespace(id=spec["id"], provider="aws", severity="high")])
    with pytest.raises(ValueError, match="provider/severity"):
        stage_descriptions(argv)


def test_later_description_stage_preserves_published_supplement(tmp_path):
    root, _, _ = fixture_tree(tmp_path)
    spec = json.loads((root / "aws-fixture.json").read_text())["frameworks"][0]["requirements"][2]["new_checks"][0]
    cid = spec["id"]
    published = {cid: {"description": "Evaluates the signed fixture.enabled setting and explains why a disabled fixture leaves avoidable exposure.",
                       "evaluated": ["fixture.enabled"], "pass_when": "The observed fixture enabled setting is true.",
                       "fail_when": "The observed fixture enabled setting is false.", "not_applicable_when": None,
                       "proposed_spec_sha256": spec_digest(spec)}}
    sha = write(root / "descriptions/implemented-new-checks.json", published)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["new_descriptions"] = {"path": "descriptions/implemented-new-checks.json",
                                    "sha256": sha, "checks": 1, "verified": True}
    write(root / "manifest.json", manifest)
    shard_dir = tmp_path / "handoff"
    old = {cid: {**published[cid], "description": "Old provider staging description that the signed reviewer deliberately superseded.",
                 "proposed_spec_sha256": "0" * 64}}
    write(shard_dir / "compliance-new-descriptions-aws.json", old)
    assert merge(root, shard_dir) == published
    extra = write(shard_dir / "compliance-new-descriptions-aws-second.json", published)
    assert extra
    with pytest.raises(ValueError, match="Duplicate"):
        merge(root, shard_dir, (shard_dir / "compliance-new-descriptions-aws-second.json",))
    with pytest.raises(ValueError, match="under shard-dir"):
        merge(root, shard_dir, (root / "descriptions/implemented-new-checks.json",))
    linked = shard_dir / "compliance-new-descriptions-aws-linked.json"
    linked.symlink_to(shard_dir / "compliance-new-descriptions-aws-second.json")
    with pytest.raises(ValueError, match="under shard-dir"):
        merge(root, shard_dir, (linked,))


def test_duplicate_description_requires_reviewed_reason_and_canonical_id(tmp_path):
    root, matrix, native = fixture_tree(tmp_path)
    second = {"id": "aws.fixture.second", "provider": "aws", "title": "Second check"}
    native["checks"].append(second)
    index = json.loads((root / "inputs/check-index.json").read_text()) + [second]
    write(root / "inputs/check-index.json", index)
    write(root / "inputs/desc-fixture.json", ["aws.fixture.existing", "aws.fixture.second"])
    rows = json.loads((root / "descriptions/desc-fixture.json").read_text())
    rows["aws.fixture.second"] = dict(rows["aws.fixture.existing"])
    write(root / "descriptions/desc-fixture.json", rows)
    refresh_manifest(root)
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["descriptions"]["desc-fixture"]["checks"] = 2
    write(root / "manifest.json", manifest)
    with pytest.raises(ValueError, match="duplicate"):
        compile_verified(root, matrix, native)
    manifest["duplicate_description_allowlist"] = {"aws.fixture.existing": {
        "allowed_ids": ["aws.fixture.second"], "reason": "Both fixture checks intentionally use the same evaluated field and condition."}}
    write(root / "manifest.json", manifest)
    assert len(compile_verified(root, matrix, native)[1]["checks"]) == 2


def test_pinned_description_index_includes_native_and_seven_analysis_checks():
    from pathlib import Path
    from peaso.analysis import ANALYSIS_CHECKS, MANUAL_ONLY_ANALYSIS_CHECK_IDS
    from peaso.checks import CHECK_ALIASES, resolve_check_id
    from scripts.peaso_compliance_compile import ANALYSIS_IDS
    root = Path(__file__).resolve().parents[1]
    indexed = {row["id"]: row for row in json.loads((root / "docs/compliance-ledgers/inputs/check-index.json").read_text())}
    catalog = json.loads((root / "peaso/rulepacks/native_catalog.json").read_text())
    native = {row["id"] for row in catalog["checks"] + catalog.get("archived_checks", [])}
    assert len(indexed) == 3112 and len(native) >= 3105
    # Signed index rows that are neither native nor analysis are retired ids
    # kept only as historical aliases of live native checks.
    retired = set(indexed) - native - ANALYSIS_IDS
    assert all(cid in CHECK_ALIASES and resolve_check_id(cid) in native for cid in retired)
    indexed_analysis = ANALYSIS_IDS & set(indexed)
    assert len(indexed_analysis) == 7
    assert {indexed[cid]["provider"] for cid in indexed_analysis} == {"all"}
    # Analysis checks registered after the signed index was frozen.
    assert ANALYSIS_IDS - set(indexed) == {"analysis.exposed_privileged_workload"}
    assert {row["id"] for row in ANALYSIS_CHECKS} | MANUAL_ONLY_ANALYSIS_CHECK_IDS == ANALYSIS_IDS


def test_production_compiled_pack_matches_signed_manifest_and_registry():
    from pathlib import Path
    from peaso.analysis import ANALYSIS_CHECKS
    from peaso.checks import CHECKS
    from peaso.checks.catalog import framework_catalog, requirement_tags_for

    base = Path(__file__).resolve().parents[1]
    pack = base / "peaso/rulepacks"
    source = base / "docs/compliance-ledgers/manifest.json"
    requirements = json.loads((pack / "compliance_requirements.json").read_text())
    lookup = json.loads((pack / "compliance_lookup.json").read_text())
    descriptions = json.loads((pack / "check_descriptions.json").read_text())
    signed_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    assert requirements["source_manifest_sha256"] == descriptions["source_manifest_sha256"] == signed_hash
    assert lookup == lookup_index(requirements, hashlib.sha256((pack / "compliance_requirements.json").read_bytes()).hexdigest())
    check_ids = {check.id for check in CHECKS} | {row["id"] for row in ANALYSIS_CHECKS}
    # Same contract as peaso_compliance_materialize: reviewed descriptions also
    # cover manual-only analysis ids and historical aliases of live checks; the
    # only live id outside the signed descriptions is the newer analysis check.
    from peaso.analysis import MANUAL_ONLY_ANALYSIS_CHECK_IDS
    from peaso.checks import CHECK_ALIASES, resolve_check_id
    from peaso.checks.catalog import description_for
    active = check_ids | MANUAL_ONLY_ANALYSIS_CHECK_IDS
    reviewed = set(descriptions["checks"])
    assert reviewed - active
    assert all(cid in CHECK_ALIASES and resolve_check_id(cid) in active for cid in reviewed - active)
    assert active - reviewed == {"analysis.exposed_privileged_workload"}
    assert description_for("analysis.exposed_privileged_workload") is not None
    forward = {(framework["id"], row["requirement_id"], cid)
               for framework in requirements["frameworks"] for row in framework["requirements"]
               for cid in row["native_checks"]}
    reverse = {(tag["framework_id"], tag["requirement_id"], cid)
               for cid, tags in requirements["by_check"].items() for tag in tags}
    assert forward == reverse
    assert set(requirements["by_check"]) <= check_ids | (reviewed - active)
    for cid, tags in requirements["by_check"].items():
        # Runtime tags of a surviving check also carry its historical aliases' tags.
        inherited = [tag for old, survivor in CHECK_ALIASES.items() if survivor == cid
                     for tag in requirements["by_check"].get(old, [])]
        assert requirement_tags_for(cid) == tags + inherited
    versions = {row["id"]: row for row in framework_catalog() if row["provider"] in {"aws", "gcp", "azure", "k8s"}}
    assert set(versions) == {row["id"] for row in requirements["frameworks"]}
    for framework in requirements["frameworks"]:
        version = versions[framework["id"]]
        assert version["requirements_total"] == len(framework["requirements"])
        assert version["requirements_by_status"] == dict(Counter(row["runtime_status"] for row in framework["requirements"]))
        assert version["pending_automatable_requirements"] == sum(bool(row["pending_checks"])
                                                                  for row in framework["requirements"])


def test_verified_json_rejects_duplicate_object_keys():
    with pytest.raises(ValueError, match="Duplicate key"):
        strict_json(b'{"id":"trusted","id":"shadow"}')


def test_proposed_ids_have_one_definition_across_catalogues_and_ledgers():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1] / "docs/compliance-ledgers"
    catalog = {}
    spec_fields = {"id", "provider", "resource_kind", "data_source", "predicate", "severity", "category", "title", "description", "remediation_hint"}
    for path in root.glob("new-checks-*.json"):
        for entry in json.loads(path.read_text()):
            spec = {key: entry[key] for key in spec_fields}
            assert entry["id"] not in catalog
            catalog[entry["id"]] = spec
    occurrences = set()
    for path in root.glob("*.json"):
        if path.name.startswith("new-checks-") or not (root / "inputs" / path.name).exists():
            continue
        for framework in json.loads(path.read_text())["frameworks"]:
            for requirement in framework["requirements"]:
                for spec in requirement["new_checks"]:
                    assert spec == catalog[spec["id"]], (path.name, framework["id"], requirement["requirement_id"], spec["id"])
                    occurrences.add(spec["id"])
    assert occurrences


def test_runtime_preserves_source_mappings_without_reviewed_pack(tmp_path, monkeypatch):
    from peaso.checks import catalog
    import json
    row = {"check_id": "upstream.example", "repository": "repo", "source": "check.py",
           "revision": "rev", "license": "MIT", "disposition": "ported",
           "frameworks": [{"framework_id": "sample", "framework": "Sample", "control": "1"}],
           "official_docs": ["https://example.org/control"]}
    payload = {"mappings": {"aws.example": [row]}, "frameworks": [], "manual_requirements": []}
    (tmp_path / "runtime_metadata.json").write_text(json.dumps(payload))
    monkeypatch.setattr(catalog, "PACK", tmp_path)
    monkeypatch.setattr(catalog, "_compliance", lambda: None)
    catalog._runtime.cache_clear()
    catalog._mappings.cache_clear()
    try:
        assert catalog._runtime() == payload
        assert catalog.provenance_for("aws.example") == [
            {key: row[key] for key in ("check_id", "repository", "source", "revision", "license", "disposition")}]
    finally:
        catalog._runtime.cache_clear()
        catalog._mappings.cache_clear()


def test_runtime_shares_verified_mapping_authority_and_preserves_manual_evidence(tmp_path, monkeypatch):
    from peaso.checks import catalog
    import json
    row = {"check_id": "upstream.example", "repository": "repo", "source": "check.py",
           "revision": "rev", "license": "MIT", "disposition": "ported",
           "frameworks": [{"framework_id": "sample", "framework": "Sample", "control": "1"}],
           "official_docs": ["https://example.org/control"]}
    manual = {"id": "manual.example", "provider": "aws", "frameworks": row["frameworks"], "question": "Review evidence"}
    payload = {"mappings": {"aws.example": [row]}, "frameworks": [], "manual_requirements": [manual]}
    (tmp_path / "runtime_metadata.json").write_text(json.dumps(payload))
    monkeypatch.setattr(catalog, "PACK", tmp_path)
    monkeypatch.setattr(catalog, "_compliance", lambda: ({}, {}))
    catalog._runtime.cache_clear()
    catalog._mappings.cache_clear()
    try:
        assert catalog.provenance_for("aws.example") == [
            {key: row[key] for key in ("check_id", "repository", "source", "revision", "license", "disposition")}]
        assert catalog.manual_requirements() == [manual]
        public = catalog.manual_requirements()
        public[0]["frameworks"].clear()
        assert catalog.manual_requirements() == [manual]
        assert "frameworks" not in catalog._runtime()["mappings"]["aws.example"][0]
    finally:
        catalog._runtime.cache_clear()
        catalog._mappings.cache_clear()
