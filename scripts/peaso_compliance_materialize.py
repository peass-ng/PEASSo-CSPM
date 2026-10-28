"""Materialize catalog views from one verified compliance pack and live registry.

The upstream reference manifest remains a separate provenance input. This
script never rebuilds it or turns a reference mapping into a requirement pass.
"""
from __future__ import annotations

import argparse
import hashlib
import gzip
import os
import tempfile
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
PACK = ROOT / "peaso/rulepacks"
FRONTEND = ROOT / "frontend/src/frameworkCatalog.json"
LEDGER = ROOT / "docs/compliance-ledgers"


def render_documents() -> dict[Path, bytes]:
    from peaso.analysis import ANALYSIS_CHECKS, MANUAL_ONLY_ANALYSIS_CHECK_IDS
    from peaso.checks import CHECKS
    from peaso.checks.hacktricks_scope import validate_review
    validate_review([check.id for check in CHECKS] + [check["id"] for check in ANALYSIS_CHECKS])
    from peaso.finding_types import validate_review as validate_types
    validate_types([check.id for check in CHECKS] + [check["id"] for check in ANALYSIS_CHECKS])
    from peaso.checks.catalog import (_compliance, clear_caches, description_for, framework_catalog,
                                      full_requirements, manifest, proposal_provenance_for, runtime_metadata)
    from peaso.collectors import supported_types
    from peaso.server.catalog_view import frameworks_view_from_catalog
    from scripts.peaso_compliance_compile import lookup_index, spec_digest, verified_file

    clear_caches()
    packed = _compliance()
    if packed is None:
        raise ValueError("Verified compliance packs are missing")
    requirements, descriptions = packed
    from peaso.checks.ecs_uid_description_overlay import validate_rows as validate_ecs_description_rows
    validate_ecs_description_rows(descriptions["checks"])
    from peaso.checks.aws_launch_ip_description_overlay import validate_rows as validate_launch_ip_rows
    validate_launch_ip_rows(descriptions["checks"])
    from peaso.checks.cloudtrail_management_description_overlay import validate_rows as validate_trail_rows
    validate_trail_rows(descriptions["checks"])
    from peaso.checks.native_rotation_archive_description_overlay import validate_rows as validate_rotation_archive_rows
    validate_rotation_archive_rows(descriptions["checks"])
    from peaso.checks.gcp_inherited_description_overlay import validate_rows as validate_gcp_inherited_rows
    validate_gcp_inherited_rows(descriptions["checks"])
    from peaso.checks.azure_defender_applicability_description_overlay import validate_rows as validate_azure_defender_rows
    validate_azure_defender_rows(descriptions["checks"])
    from peaso.checks.aws_native_status_description_overlay import validate_rows as validate_aws_status_rows
    validate_aws_status_rows(descriptions["checks"])
    canonical = full_requirements()
    if lookup_index(canonical, requirements["full_pack_sha256"]) != requirements:
        raise ValueError("Compact lookup differs from canonical signed requirement pack")
    signed = hashlib.sha256((LEDGER / "manifest.json").read_bytes()).hexdigest()
    if requirements["source_manifest_sha256"] != signed or descriptions["source_manifest_sha256"] != signed:
        raise ValueError("Compiled packs do not match the current supervisor manifest")
    from peaso.checks import CHECK_ALIASES, resolve_check_id
    native_ids = {check.id for check in CHECKS}
    if len(native_ids) != len(CHECKS):
        raise ValueError("Duplicate registered native check")
    indexed = {row["id"] for row in json.loads((LEDGER / "inputs/check-index.json").read_text())}
    # Retain reviewed metadata for archived reports without advertising runnable controls.
    analysis_ids = {row["id"] for row in ANALYSIS_CHECKS} | MANUAL_ONLY_ANALYSIS_CHECK_IDS
    reviewed_ids = set(descriptions["checks"])
    active_ids = native_ids | analysis_ids
    historical_aliases = {cid for cid in reviewed_ids - active_ids
                          if cid in CHECK_ALIASES and resolve_check_id(cid) in active_ids}
    new_analysis_ids = {"analysis.exposed_privileged_workload"}
    if (reviewed_ids - active_ids != historical_aliases or
            active_ids - reviewed_ids != new_analysis_ids or
            any(description_for(cid) is None for cid in new_analysis_ids)):
        raise ValueError("Every registered check needs exactly one reviewed description")
    new_ids = native_ids - indexed
    if not new_ids <= set(requirements["by_check"]):
        raise ValueError("New registered checks lack reviewed requirement/control tags")
    for check in CHECKS:
        if check.id not in new_ids:
            continue
        signed_spec = proposal_provenance_for(check.id)
        if (signed_spec is None or check.provider != signed_spec["signed_provider"] or
                check.severity != signed_spec["signed_severity"]):
            raise ValueError("New check provider or severity differs from signed proposal: " + check.id)
        collected = set(supported_types(check.provider))
        if check.kind not in collected or any(kind not in collected for kind in check.dependencies):
            from peaso.checks.bulk_pending import MANIFEST as bulk_manifest
            from peaso.collectors.bulk_evidence import declared_types
            declared = collected | declared_types(check.provider)
            if check.id not in bulk_manifest['checks'] or not set(check.dependencies+[check.kind]) <= declared:
                raise ValueError("New check kind or dependency is not collected: " + check.id)
    supervisor = json.loads((LEDGER / "manifest.json").read_text())
    thematic_extensions = set()
    for entry in supervisor.get("native_extensions", []):
        extension, _ = verified_file(LEDGER, entry, prefix="native-extensions/")
        for row in extension["checks"]:
            if row["requirements"] == []:
                thematic_extensions.add(row["spec"]["id"])
    for cid, tags in requirements["by_check"].items():
        if resolve_check_id(cid) not in active_ids or (not tags and cid not in thematic_extensions):
            raise ValueError("Requirement map contains an absent or untagged check")

    source = manifest()
    runtime = runtime_metadata(source)
    runtime["compliance"] = {"schema_version": requirements["schema_version"],
                             "source_manifest_sha256": signed,
                             "requirements_total": sum(requirements["counts"].values())}
    framework_rows = framework_catalog(source)
    from peaso.checks.native_only import automated_checks, scope as automation_scope, exclusions
    active = automated_checks(CHECKS)
    from peaso.checks import azure_vm_ssh_source_correction, gcp_cloudsql_lockout_source_correction
    source_corrections = {module.CHECK_ID: {"spec": module.CORRECTED_SPEC,
                                          "provenance": module.correction_provenance()}
                          for module in (azure_vm_ssh_source_correction, gcp_cloudsql_lockout_source_correction)}
    from peaso.checks.gcp_api_key_service_names_native import CHECK_ID as api_key_id, source_correction as api_key_correction
    prior_api_key = next((row for row in canonical['proposed_checks'] if row['id'] == api_key_id), None)
    if prior_api_key is None:
        raise ValueError('Historical GCP API key proposal missing')
    corrected_api_key, api_key_provenance = api_key_correction(spec_digest(prior_api_key))
    source_corrections[api_key_id] = {'spec': corrected_api_key, 'provenance': api_key_provenance}
    from peaso.checks.aws_policy_source_correction import CORRECTIONS
    source_corrections.update({cid: {"spec": row["spec"], "provenance": row["provenance"]}
                               for cid, row in CORRECTIONS.items()})
    from peaso.checks import aws_ecr_source_correction as ecr_correction
    prior_ecr = next((row for row in canonical['proposed_checks']
                      if row['id'] == ecr_correction.CHECK_ID), None)
    if prior_ecr is None:
        raise ValueError('Historical ECR Public proposal missing')
    ecr_correction.validate_prior_spec(prior_ecr)
    source_corrections[ecr_correction.CHECK_ID] = {
        "spec": ecr_correction.CORRECTED_SPEC,
        "provenance": ecr_correction.correction_provenance(),
    }
    from peaso.checks import aws_pci_iam_scoped_source_correction as scoped_iam_correction
    prior_scoped_iam = next((row for row in canonical['proposed_checks']
                             if row['id'] == scoped_iam_correction.CHECK_ID), None)
    if prior_scoped_iam is None:
        raise ValueError('Historical scoped IAM customer-policy proposal missing')
    scoped_iam_correction.validate_prior_spec(prior_scoped_iam)
    source_corrections[scoped_iam_correction.CHECK_ID] = {
        "spec": scoped_iam_correction.CORRECTED_SPEC,
        "provenance": scoped_iam_correction.correction_provenance(),
    }
    from peaso.checks import aws_apigateway_logging_source_correction as apigw_logging_correction
    prior_apigw_logging = next((row for row in canonical["proposed_checks"]
                               if row["id"] == apigw_logging_correction.CHECK_ID), None)
    if prior_apigw_logging is None:
        raise ValueError("Historical API Gateway logging proposal missing")
    apigw_logging_correction.validate_prior_spec(prior_apigw_logging)
    source_corrections[apigw_logging_correction.CHECK_ID] = {
        "spec": apigw_logging_correction.CORRECTED_SPEC,
        "provenance": apigw_logging_correction.correction_provenance(),
    }
    public = [check.public() for check in active]
    if {check["id"] for check in public} != {check.id for check in active}:
        raise ValueError("Public native catalog differs from the registry")
    for check in public:
        if check["framework_ids"] != sorted({tag["framework_id"] for tag in check["requirement_controls"]}):
            raise ValueError("Public check framework IDs differ from reviewed control tags: " + check["id"])
    from peaso.collectors.bulk_evidence import coverage as evidence_coverage
    inventory_coverage = evidence_coverage()
    has_evidence_gaps = any(row['unavailable_projections'] for row in inventory_coverage.values())
    summary = {**runtime["coverage"], "active_native_checks": len(active), "automation_scope": automation_scope(), "inventory_coverage": inventory_coverage,
               "phase": "expansion_in_progress" if runtime["coverage"]["upstream"]["pending"] or has_evidence_gaps else "review_complete"}
    frontend = frameworks_view_from_catalog(public, framework_rows, runtime["coverage"])
    fixture = {key: frontend[key] for key in ("schema_version", "providers", "frameworks", "framework_versions", "limitations")}
    in_scope = {"aws", "azure", "gcp", "k8s", "all"}
    fixture["framework_versions"] = [row for row in frontend["framework_versions"]
                                      if row["provider"] in in_scope]
    version_ids = {row["id"] for row in fixture["framework_versions"]}
    fixture["frameworks"] = [
        {**row, "framework_ids": [identifier for identifier in row.get("framework_ids", [])
                                  if identifier in version_ids]}
        for row in frontend["frameworks"]
        if not row.get("framework_ids") or version_ids.intersection(row["framework_ids"])
    ]
    fixture["limitations"] = ["demo findings are illustrative fixtures; they are not a tenant assessment or compliance claim.",
                              *frontend["limitations"]]
    fixture["source"] = "peaso.server.catalog_view.frameworks_view"
    fixture["compliance_source_manifest_sha256"] = signed

    def encoded(value, *, compact=False):
        return (json.dumps(value, ensure_ascii=False, separators=(",", ":") if compact else None,
                           indent=None if compact else 2) + "\n").encode()

    outputs = {PACK / "runtime_metadata.json": encoded(runtime, compact=True),
            PACK / "native_catalog.json": encoded({"schema_version": "1.0", "evaluator_version": "1.0.0",
                                                    "compliance_source_manifest_sha256": signed, "automation_scope": automation_scope(), "checks": public,
                                                    "archived_checks": [check.public() for check in CHECKS if check.id in exclusions()],
                                                    "excluded_controls": exclusions(), "source_corrections": source_corrections}, compact=True),
            PACK / "framework_catalog.json": encoded({"schema_version": "1.0", "compliance_source_manifest_sha256": signed,
                                                       "frameworks": framework_rows}),
            PACK / "catalog_summary.json": encoded(summary),
            PACK / "manual_catalog.json": encoded({"schema_version": "1.1", "requirements": runtime["manual_requirements"]}),
            FRONTEND: encoded(fixture, compact=True)}


    # API metadata is captured only after the complete native registry and
    # reviewed packs above have passed their build-time admission checks.
    from peaso.engine import get_catalog, PROVIDERS, FRAMEWORK_ALIASES
    from peaso.server.catalog_view import summary as api_summary, frameworks_view
    from peaso.server.validation import _selector_index
    from peaso.server.materialized_catalog import MAX_WIRE_BYTES, MAX_DOCUMENT_BYTES, MAX_COMPRESSED_BYTES, SOURCE_PATHS, wire_fits
    full = get_catalog()
    compact_summary = dict(api_summary(), privesc_catalog=full["privesc_catalog"])
    frameworks = frameworks_view()
    selectors = {provider: dict(zip(("categories", "checks", "frameworks"),
                                    (sorted(values) for values in _selector_index(provider))))
                 for provider in PROVIDERS}
    # Explicit content scans name their checks. Preserve the engine's privilege
    # selectors in that same request without importing native code in the API.
    from peaso.engine import PRIVESC_CHECK_ID
    for provider, index in selectors.items():
        technique_ids = {row["id"] for row in full["privesc_techniques"]
                         if row.get("provider") == provider}
        index["checks"] = sorted(set(index["checks"]) | technique_ids | {PRIVESC_CHECK_ID})
    if [row["id"] for row in compact_summary["checks"]] != [row["id"] for row in full["checks"]]:
        raise ValueError("API summary/full check order differs")
    sources = {relative: hashlib.sha256(outputs.get(ROOT / relative, (ROOT / relative).read_bytes())).hexdigest()
               for relative in sorted(SOURCE_PATHS)}
    from peaso.checks import CHECK_ALIASES, CHECKS
    from peaso.remediation import template as remediation_template
    from peaso.checks.catalog import description_for, framework_selector_index, framework_display_names
    description_ids = native_ids | analysis_ids | set(CHECK_ALIASES)
    reviewed_descriptions = {cid: description_for(cid) for cid in sorted(description_ids)}
    # Archived alias findings are absent from the current check rows. Preserve
    # their approved native templates in the verified API document itself.
    alias_templates = {}
    current_ids = {row["id"] for row in full["checks"]} | {check.id for check in CHECKS}
    for cid in sorted(CHECK_ALIASES):
        if cid in current_ids:
            continue
        candidate = remediation_template(cid)
        if candidate is None:
            continue
        if any(remediation_template(cid, provider) != candidate
               for provider in ("aws", "gcp", "azure", "k8s", "other")):
            raise ValueError("Archived remediation alias varies by provider: " + cid)
        alias_templates[cid] = candidate
    document = encoded({"schema_version": 1, "sources": sources, "full": full,
                        "descriptions": reviewed_descriptions,
                        "remediation_aliases": alias_templates,
                        "native_kinds": {check.id: [check.provider, check.kind] for check in CHECKS},
                        "framework_expansion": {key: sorted(values) for key, values in sorted(framework_selector_index().items())},
                        "framework_display": framework_display_names(), "framework_aliases": FRAMEWORK_ALIASES,
                        "summary": compact_summary, "frameworks": frameworks, "selectors": selectors}, compact=True)
    compressed = gzip.compress(document, compresslevel=9, mtime=0)
    if (len(document) > MAX_DOCUMENT_BYTES or len(compressed) > MAX_COMPRESSED_BYTES
            or any(not wire_fits(encoded(view, compact=True)) for view in (compact_summary, frameworks))):
        raise ValueError("Materialized API catalog exceeds bounded package/wire budgets")
    outputs[PACK / "api_catalog.json.gz"] = compressed
    outputs[PACK / "api_catalog_manifest.json"] = encoded({"schema_version": 1, "sources": sources,
        "gzip_sha256": hashlib.sha256(compressed).hexdigest(),
        "document_sha256": hashlib.sha256(document).hexdigest(), "uncompressed_bytes": len(document)}, compact=True)
    return outputs


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Write the reviewed catalog views after all checks pass")
    args = parser.parse_args(argv)
    outputs = render_documents()
    stale = [path for path, payload in outputs.items() if not path.is_file() or path.read_bytes() != payload]
    if args.write:
        for path, payload in outputs.items():
            if path not in stale:
                continue
            # Atomic replacement also makes a hardlinked release staging safe.
            with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
                stream.write(payload)
                temporary = stream.name
            os.chmod(temporary, 0o644)
            os.replace(temporary, path)
        print(json.dumps({"written": [str(path.relative_to(ROOT)) for path in stale], "checked": len(outputs)}))
        return 0
    print(json.dumps({"stale": [str(path.relative_to(ROOT)) for path in stale], "checked": len(outputs)}))
    return 1 if stale else 0


if __name__ == "__main__":
    raise SystemExit(main())
