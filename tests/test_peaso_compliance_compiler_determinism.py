"""The signed description pack must not depend on Python's hash seed."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
PACK = ROOT / "peaso/rulepacks"
FIELD_ORDER = ("description", "fail_when", "evaluated", "not_applicable_when", "pass_when")
SUPERVISOR = json.loads((ROOT / "docs/compliance-ledgers/manifest.json").read_text())
EXTENSIONS = [row for entry in SUPERVISOR.get("native_extensions", [])
              for row in json.loads((ROOT / "docs/compliance-ledgers" / entry["path"]).read_text())["checks"]]
EXTENSION_IDS = {row["spec"]["id"] for row in EXTENSIONS}


def _compile_into(tmp_path, seed):
    output = tmp_path / str(seed)
    output.mkdir()
    paths = {name: output / name for name in
             ("compliance_requirements.json", "compliance_lookup.json", "check_descriptions.json")}
    environment = os.environ.copy()
    # The suite-wide PEASO_SOURCE_ATTESTATION=always re-proves every pinned source on
    # each nested call (minutes of CPU for a cold peaso.checks import). This child
    # does not test attestation, so it runs the shipped mode, which still proves
    # every pinned source once on first use.
    environment.update(PYTHONHASHSEED=str(seed), PYTHONDONTWRITEBYTECODE="1", PEASO_SOURCE_ATTESTATION="once")
    command = [sys.executable, "scripts/peaso_compliance_compile.py",
               "--ledger-root", "docs/compliance-ledgers",
               "--audit-matrix", "docs/compliance-ledgers/inputs/compliance-requirements-matrix.json.gz",
               "--audit-summary", "docs/compliance-ledgers/inputs/compliance-requirements-summary.json",
               "--native-catalog", str(PACK / "native_catalog.json"),
               "--requirements-output", str(paths["compliance_requirements.json"]),
               "--lookup-output", str(paths["compliance_lookup.json"]),
               "--descriptions-output", str(paths["check_descriptions.json"])]
    completed = subprocess.run(command, cwd=ROOT, env=environment, text=True,
                               capture_output=True, check=True, timeout=120)
    assert json.loads(completed.stdout) == {
        "descriptions": 3993 + len(EXTENSION_IDS), "frameworks": 160, "requirements": 22212,
        "states": json.loads((PACK / "compliance_requirements.json").read_text())["counts"],
    }
    return {name: path.read_bytes() for name, path in paths.items()}


def _edges_from_requirements(pack):
    return {(check_id, framework["id"], requirement["requirement_id"],
             requirement["decision"], requirement["runtime_status"])
            for framework in pack["frameworks"]
            for requirement in framework["requirements"]
            for check_id in requirement["native_checks"]}


def _edges_from_reverse(mapping):
    return {(check_id, tag["framework_id"], tag["requirement_id"],
             tag["decision"], tag["runtime_status"])
            for check_id, tags in mapping.items() for tag in tags}


def test_reviewed_compiler_outputs_are_identical_across_hash_seeds(tmp_path):
    first = _compile_into(tmp_path, 0)
    second = _compile_into(tmp_path, 167)
    assert first == second
    assert first["compliance_requirements.json"] == (PACK / "compliance_requirements.json").read_bytes()
    assert first["compliance_lookup.json"] == (PACK / "compliance_lookup.json").read_bytes()
    descriptions_bytes = first["check_descriptions.json"]
    assert descriptions_bytes == (PACK / "check_descriptions.json").read_bytes()
    compiled = json.loads(descriptions_bytes)["checks"]
    current = json.loads((PACK / "check_descriptions.json").read_bytes())["checks"]
    corrected = {"azure.iam.no_full_custom_role", "gcp.compute.restrict_internet_ingress"}
    assert set(current) == set(compiled)
    assert compiled == current  # Reviewed base-text errata now reproduce exactly.
    native_by_id = {row["id"]: row for row in json.loads((PACK / "native_catalog.json").read_bytes())["checks"]}
    from peaso.checks import azure_finding_clarity_reviewed, gcp_remaining_clarity_reviewed
    overlays={"azure.iam.no_full_custom_role":azure_finding_clarity_reviewed,
              "gcp.compute.restrict_internet_ingress":gcp_remaining_clarity_reviewed}
    for check_id in corrected:
        final=overlays[check_id].description(check_id,current[check_id])
        assert {k:v for k,v in final.items() if k!="description"}=={k:v for k,v in current[check_id].items() if k!="description"}
        assert all(final[field] == native_by_id[check_id][field]
                   for field in ("description", "pass_when", "fail_when"))

    descriptions = compiled
    supplemental = json.loads((ROOT / "docs/compliance-ledgers/descriptions/implemented-new-checks.json").read_bytes())
    assert len(descriptions) == 3993 + len(EXTENSION_IDS) and len(supplemental) == 881 + len(EXTENSION_IDS)
    assert all(tuple(descriptions[check_id]) == FIELD_ORDER for check_id in supplemental)
    assert all(descriptions[check_id] == {field: source[field] for field in FIELD_ORDER}
               for check_id, source in supplemental.items())

    requirements = json.loads(first["compliance_requirements.json"])
    lookup = json.loads(first["compliance_lookup.json"])
    native = json.loads((PACK / "native_catalog.json").read_bytes())
    # Native-only admission partitions the unchanged historical registry.
    active = {row["id"] for row in native["checks"]}
    archived = {row["id"] for row in native["archived_checks"]}
    assert len(active) == len(native["checks"])
    assert len(archived) == len(native["archived_checks"])
    assert not active.intersection(archived)
    # Retired duplicate ids keep reviewed metadata only as historical aliases of
    # live native checks; together they still partition the historical registry.
    from peaso.checks import CHECK_ALIASES, resolve_check_id
    retired = {cid for cid in descriptions if cid not in active | archived and not cid.startswith("analysis.")}
    assert all(cid in CHECK_ALIASES and resolve_check_id(cid) in active | archived for cid in retired)
    assert len(active | archived | retired) == 3986 + len(EXTENSION_IDS)
    assert archived == set(native["excluded_controls"])
    assert native["automation_scope"]["manual_attestations"] is False
    assert len(requirements["frameworks"]) == 160
    assert sum(len(row["requirements"]) for row in requirements["frameworks"]) == 22212
    forward = _edges_from_requirements(requirements)
    # Seven reviewed baseline links supplement the existing user-data signal;
    # they remain PARTIAL and are separate from new-control extension links.
    baseline_signals = {
        ("aws_ai_security_framework_aws", "AISF-DATA-05"),
        ("aws_well_architected_framework_security_pillar_aws", "SEC02-BP03"),
        ("kisa_isms_p_2023_aws", "2.10.2"),
        ("kisa_isms_p_2023_korean_aws", "2.10.2"),
        ("mitre_attack_aws", "T1552"),
        ("nist_csf_2.0_aws", "ds_5"),
        ("secnumcloud_3.2_aws", "10.5"),
    }
    assert {("aws_cis_ec2_userdata_embedded_secrets", fid, rid, "PARTIAL", "partial")
            for fid, rid in baseline_signals} <= forward
    assert len(forward) == (22953 + len(baseline_signals) +
                            sum(len(row["requirements"]) for row in EXTENSIONS))
    assert forward == _edges_from_reverse(requirements["by_check"])
    assert forward == _edges_from_reverse(lookup["by_check"])


def test_current_azure_descriptions_are_hash_bound_overlays_of_signed_rows():
    from peaso.checks.catalog import description_for
    from peaso.checks.azure_defender_applicability_description_overlay import ROWS

    signed = json.loads((PACK / "check_descriptions.json").read_bytes())["checks"]
    native = {row["id"]: row for row in json.loads((PACK / "native_catalog.json").read_bytes())["checks"]}
    for check_id, overlay in ROWS.items():
        original = signed[check_id]
        original_hash = hashlib.sha256(json.dumps(
            original, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        assert original_hash == overlay["base_row_sha256"]
        current = description_for(check_id)
        assert current != original
        for field in ("description", "evaluated", "pass_when", "fail_when",
                      "not_applicable_when", "description_correction"):
            assert native[check_id][field] == current[field]
