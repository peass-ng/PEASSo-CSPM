"""Reviewed upstream references, isolated from executable rules."""
from functools import lru_cache
from collections import Counter
import json
from pathlib import Path
from copy import deepcopy
import gzip
import sys

PACK = Path(__file__).resolve().parent.parent / "rulepacks"


def _shared_metadata_strings(row):
    """Share immutable public labels; keep every dictionary/list independent.

    The reviewed runtime pack repeats framework names, URLs and labels hundreds
    of thousands of times. JSON already shares keys within a decode; sharing
    these values avoids retaining a second string for every mapping edge.
    This hook is only for static reviewed metadata, never user snapshots.
    """
    # object_hook owns this freshly decoded dictionary. JSON already shares
    # keys within a decode; keep its independent container instead of allocating
    # another dictionary for every metadata row. Only immutable values are shared.
    for key, value in row.items():
        if isinstance(value, str):
            row[key] = sys.intern(value)
        elif isinstance(value, list):
            for position, item in enumerate(value):
                if isinstance(item, str):
                    value[position] = sys.intern(item)
    return row


@lru_cache(maxsize=1)
def _compliance():
    """Load the compiled lookup without parsing full requirement evidence."""
    requirements = PACK / "compliance_requirements.json"
    lookup = PACK / "compliance_lookup.json"
    descriptions = PACK / "check_descriptions.json"
    if not requirements.exists() and not lookup.exists() and not descriptions.exists():
        return None
    if not requirements.is_file() or not lookup.is_file() or not descriptions.is_file():
        raise ValueError("Incomplete compiled compliance metadata")
    rules = json.loads(lookup.read_text(), object_hook=_shared_metadata_strings)
    prose = json.loads(descriptions.read_text(), object_hook=_shared_metadata_strings)
    if (rules.get("schema_version") != 1 or prose.get("schema_version") != 1 or
            not isinstance(rules.get("by_check"), dict) or not isinstance(rules.get("frameworks"), list) or
            not isinstance(rules.get("proposed_checks"), list) or not isinstance(prose.get("checks"), dict)):
        raise ValueError("Compiled compliance metadata does not match")
    return rules, prose


@lru_cache(maxsize=1)
def full_requirements():
    """Load canonical requirement reasons/evidence only for an explicit detail consumer."""
    packed = _compliance()
    if packed is None:
        return None
    full = json.loads((PACK / "compliance_requirements.json").read_bytes())
    if full.get("schema_version") != packed[0]["schema_version"]:
        raise ValueError("Canonical compliance requirements differ from lookup")
    return full


def description_for(check_id):
    """Apply reviewed concise copy without changing signed source contracts."""
    from . import (finding_clarity_reviewed, gcp_firewall_clarity_reviewed,
                   k8s_finding_clarity_reviewed, azure_finding_clarity_reviewed,
                   aws_finding_clarity_reviewed, gcp_scalar_clarity_reviewed,
                   k8s_workload_clarity_reviewed, k8s_gc_threshold_source_correction,
                   gcp_remaining_clarity_reviewed, aws_database_clarity_reviewed, azure_bulk_clarity_reviewed, aws_remaining_clarity_reviewed, aws_final_clarity_reviewed, aws_bulk_clarity_reviewed, aws_compute_storage_clarity_reviewed)
    original = _base_description_for(check_id)
    for overlay in (finding_clarity_reviewed, gcp_firewall_clarity_reviewed,
                    k8s_finding_clarity_reviewed, azure_finding_clarity_reviewed,
                    aws_finding_clarity_reviewed, gcp_scalar_clarity_reviewed,
                    k8s_workload_clarity_reviewed, k8s_gc_threshold_source_correction,
                   gcp_remaining_clarity_reviewed, aws_database_clarity_reviewed, azure_bulk_clarity_reviewed, aws_remaining_clarity_reviewed, aws_final_clarity_reviewed, aws_bulk_clarity_reviewed, aws_compute_storage_clarity_reviewed):
        if check_id in overlay.ROWS:
            original = overlay.description(check_id, original)
    if check_id == "aws_cis_aws_resource_policy_unrestricted_principal":
        original = {
            "description": "Reviews collected AWS resource-policy documents for wildcard-principal Allow statements without a recognized positive caller or network boundary. Services and nested resources are enumerated by explicit read-only discovery recipes. Missing/denied policies remain collection gaps; a readable unrestricted grant can fail even when another family could not be read.",
            "evaluated": ["aws_resource_policy.ResourceArn", "aws_resource_policy.Policy.Statement[]", "Statement.Principal/NotPrincipal, Effect, Action/NotAction, Resource/NotResource and Condition", "collector account, Region and home-endpoint provenance"],
            "pass_when": "The observed policy has no unrestricted wildcard Allow, or a covering unconditional Deny prevents that Allow.",
            "fail_when": "An observed wildcard-principal Allow lacks a positive, non-tautological caller/network boundary and no relevant Deny can constrain it.",
            "not_applicable_when": None,
        }
    if check_id == 'aws.claude_a.vpc.sg_no_world_any_port_on_customer_enis':
        from .aws_sg_any_port_description_correction_20261021 import description
        original = description(original)
    return original


def _base_description_for(check_id):
    if check_id == 'gcp.review.app_engine_flex.selected_version_image_secret_indicators':
        return {'description': 'Reads one selected App Engine Flex Version full view and the exact same-project immutable image digest.', 'evaluated': ['Version name/id/env and deployment.container.image before and after', 'project, Docker repository, image metadata and verified OCI bytes', 'Kingfisher and TruffleHog detector outcomes'], 'pass_when': 'The bound selected image bytes are complete and both detectors find no supported secret.', 'fail_when': 'A detector finds a likely secret in verified selected image bytes; partial positive coverage remains FAIL.', 'not_applicable_when': 'Unselected versions and mutable tags are outside scope; missing native or registry bytes yield UNKNOWN.'}
    if check_id == 'gcp.review.app_engine_flex.selected_version_image_high_vulnerabilities':
        return {'description': 'Runs an optional fresh offline Trivy scan for one selected App Engine Flex Version immutable image digest.', 'evaluated': ['selected Flex Version declaration before and after', 'same-project image metadata and verified OCI bytes', 'fresh Trivy HIGH/CRITICAL package findings'], 'pass_when': 'The bound image has a fresh complete scan without HIGH or CRITICAL findings.', 'fail_when': 'A bound image has a typed HIGH or CRITICAL finding.', 'not_applicable_when': 'Missing read rights, mutable tags and incomplete clean scans yield UNKNOWN.'}
    if check_id == 'gcp.review.gke.selected_pod_image_secret_indicators':
        return {'description': 'Reviews only an explicitly selected GKE Pod container at an immutable image digest after native GKE, Kubernetes and OCI binding.', 'evaluated': ['selected GKE project/location/cluster GET identity and native endpoint CA', 'selected kube-system namespace UID and exact Pod UID/resourceVersion/container', 'verified OCI digest bytes and two offline secret detectors'], 'pass_when': 'The selected Pod image bytes are complete and both detectors find no supported secret.', 'fail_when': 'A supported detector finds a likely secret in the bound selected image; partial positive coverage is retained.', 'not_applicable_when': 'Unselected resources are not evaluated; missing Kubernetes or registry read capability yields UNKNOWN.'}
    if check_id == 'gcp.review.gke.selected_pod_image_high_vulnerabilities':
        return {'description': 'Reviews a fresh optional Trivy scan of one exact GKE Pod immutable image digest after native GKE, Kubernetes and OCI binding.', 'evaluated': ['selected GKE cluster and Pod image identity', 'verified OCI manifest/config/layers', 'fresh offline Trivy HIGH/CRITICAL findings and scan coverage'], 'pass_when': 'The bound image has a complete fresh scan with no HIGH or CRITICAL package findings.', 'fail_when': 'A bound selected image scan has at least one typed HIGH or CRITICAL package finding.', 'not_applicable_when': 'Missing read capability and incomplete clean scans yield UNKNOWN.'}
    if check_id == 'azure.review.aks.selected_pod_image_secret_indicators':
        return {'description': 'Reviews only an explicitly selected AKS Pod container at an immutable image digest after native ARM, Kubernetes and OCI binding.', 'evaluated': ['selected AKS managed cluster ARM identity and resourceUID', 'selected kube-system namespace UID and exact Pod UID/resourceVersion/container', 'verified OCI digest bytes and two offline secret detectors'], 'pass_when': 'The exact selected Pod image bytes are complete and both detectors find no supported secret.', 'fail_when': 'A supported detector finds a likely secret in the bound selected image; partial positive coverage is retained.', 'not_applicable_when': 'Unselected resources are not evaluated; Arc and missing Kubernetes or registry read capability yield UNKNOWN.'}
    if check_id == 'azure.review.aks.selected_pod_image_high_vulnerabilities':
        return {'description': 'Reviews a fresh optional Trivy scan of one exact AKS Pod immutable image digest after native ARM, Kubernetes and OCI binding.', 'evaluated': ['selected AKS managed cluster and Pod image identity', 'verified OCI manifest/config/layers', 'fresh offline Trivy HIGH/CRITICAL findings and scan coverage'], 'pass_when': 'The bound image has a complete fresh scan with no HIGH or CRITICAL package findings.', 'fail_when': 'A bound selected image scan has at least one typed HIGH or CRITICAL package finding.', 'not_applicable_when': 'Arc, missing read capability and incomplete clean scans yield UNKNOWN.'}
    if check_id == 'gcp.review.developerconnect.selected_repository_file_secret_indicators':
        return {
            'description': 'Reads only explicitly selected files from public GitHub, GitLab.com or Bitbucket Cloud repository links at a pinned commit and Git blob hash through a short-lived Developer Connect read token.',
            'evaluated': ['GitRepositoryLink.name/uid/cloneUri/etag/reconciling', 'Cloud Resource Manager project name/projectId/state', 'selected commit SHA-1, file path SHA-256 and Git blob SHA-1', 'verified file bytes and Kingfisher/TruffleHog outcomes'],
            'pass_when': 'The selected linked file matches its pinned Git blob and both detectors complete without finding a supported secret.',
            'fail_when': 'A supported detector finds a likely secret in bytes verified against the selected Git blob; partial content coverage does not erase the finding.',
            'not_applicable_when': 'Unselected repositories are not evaluated; unsupported enterprise hosts, branches, denied tokens or incomplete content yield UNKNOWN.',
        }
    if check_id == 'azure.review.synapse.selected_notebook_source_secret_indicators':
        path = Path(__file__).with_name('azure_synapse_selected_notebook_secret_review_20261021_descriptions.json')
        return deepcopy(json.loads(path.read_text())[check_id])
    if check_id == "analysis.exposed_privileged_workload":
        return {
            "description": "Links a declared public workload path to the workload's runtime identity and a high-impact allowed grant. The finding depends on an application compromise and does not claim that the grant is effective or used.",
            "evaluated": ["public endpoint and its resolved workload backend", "workload runtime identity", "allowed high or critical permissions classified by the bundled offline permission catalog"],
            "pass_when": "Never emits PASS; workloads without both a declared public path and a resolved high-impact runtime grant produce no finding.",
            "fail_when": "A resolved workload is linked to a declared public endpoint and its runtime identity has a high or critical allowed grant.",
            "not_applicable_when": "No public workload path or resolved high-impact runtime grant is present.",
        }
    if check_id == "aws_nist_apigateway_stage_logging_enabled":
        from .aws_apigateway_logging_source_correction import description
        return description()
    if check_id == 'aws.pci.iam.wildcard_action_scoped_resource':
        from .aws_pci_iam_scoped_source_correction import description
        return description()
    if check_id == 'aws_g6_ecr_public_repositories_absent':
        from .aws_ecr_source_correction import description
        return description()
    from .aws_policy_source_correction import CORRECTIONS, description as aws_policy_description
    if check_id in CORRECTIONS:
        return aws_policy_description(check_id)
    """Reviewed condition, fields and rationale, or None while the pack is pending."""
    if check_id == 'azure_vm_8_2_1_1_712e1ad':
        from .azure_vm_ssh_source_correction import description
        return description()
    if check_id == "gcp_cloudsql_failed_attempts_lockout":
        from .gcp_cloudsql_lockout_source_correction import description
        return description()
    packed = _compliance()
    if not packed:
        return None
    original = packed[1]["checks"].get(check_id)
    if check_id in ("aws.a.cloudtrail.bucket_access_logging", "aws.a.cloudtrail.bucket_mfa_delete",
                    "aws.a.iam.attached_policy_no_star_star"):
        from .aws_native_status_description_overlay import description
        return description(check_id, original)
    if check_id == "aws.pci.iam.policy_attached_to_active_principal":
        from .aws_pci_iam_attachment_description_overlay import description
        return description(original)
    if check_id in ("aws.b.ecs.declared_nonroot_users", "aws.b.ecs.host_network_nonprivileged"):
        from .ecs_uid_description_overlay import description
        return description(check_id, original)
    if check_id in ("aws.c2b.autoscaling.lc_no_public_ip", "aws.c2b.autoscaling.group_lc_no_public_ip"):
        from .aws_launch_ip_description_overlay import description
        return description(check_id, original)
    if check_id == "aws.cloudtrail.management_events":
        from .cloudtrail_management_description_overlay import description
        return description(check_id, original)
    if check_id in ("aws_log_archive_immutable", "aws_nist_secretsmanager_secret_automatic_rotation_enabled"):
        from .native_rotation_archive_description_overlay import description
        return description(check_id, original)
    if check_id in ("gcp.claude.logging.project_sink_all_entries", "gcp.claude.project.audit_logs_configured", "gcp.claude.project.storage_data_access_audit_logs"):
        from .gcp_inherited_description_overlay import description
        return description(check_id, original)
    if check_id in ("azure.claude.defender_default_initiative_no_disabled_effects", "azure.claude.defender_iot_security_solution_enabled"):
        from .azure_defender_applicability_description_overlay import description
        return description(check_id, original)
    return deepcopy(original)


def requirement_tags_for(check_id):
    packed = _compliance()
    if not packed:
        return []
    from . import CHECK_ALIASES
    source_ids = [check_id, *(old for old, survivor in CHECK_ALIASES.items() if survivor == check_id)]
    tags = []
    for source_id in source_ids:
        tags.extend(packed[0]["by_check"].get(source_id, []))
    return deepcopy(tags)


@lru_cache(maxsize=1)
def _proposals():
    packed = _compliance()
    return {row["id"]: row for row in packed[0].get("proposed_checks", [])} if packed else {}


def proposal_provenance_for(check_id):
    """Preserve the signed source category even if the native UI category differs."""
    spec = _proposals().get(check_id)
    if spec is None:
        return None
    provenance = {"signed_spec_sha256": spec["signed_spec_sha256"],
                  "signed_provider": spec["provider"], "signed_severity": spec["severity"],
                  "signed_category": spec["category"], "signed_resource_kind": spec["resource_kind"],
                  "source_manifest_sha256": _compliance()[0]["source_manifest_sha256"]}
    if check_id == "gcp.apikeys.active_service_restrictions":
        from .gcp_api_key_service_names_native import source_correction
        _, correction = source_correction(provenance["signed_spec_sha256"])
        provenance["signed_spec_status"] = "historical_superseded_for_this_check"
        provenance["source_correction"] = correction
    if check_id == 'azure_vm_8_2_1_1_712e1ad':
        from .azure_vm_ssh_source_correction import correction_provenance
        provenance["signed_spec_status"] = "historical_superseded_for_this_check"
        provenance["source_correction"] = correction_provenance()
    if check_id == "gcp_cloudsql_failed_attempts_lockout":
        from .gcp_cloudsql_lockout_source_correction import correction_provenance
        provenance["signed_spec_status"] = "historical_superseded_for_this_check"
        provenance["source_correction"] = correction_provenance()
    if check_id == 'aws_g6_ecr_public_repositories_absent':
        from .aws_ecr_source_correction import correction_provenance
        provenance['signed_spec_status'] = 'historical_superseded_for_this_check'
        provenance['source_correction'] = correction_provenance()
    if check_id == 'aws.pci.iam.wildcard_action_scoped_resource':
        from .aws_pci_iam_scoped_source_correction import correction_provenance
        provenance['signed_spec_status'] = 'historical_superseded_for_this_check'
        provenance['source_correction'] = correction_provenance()
    if check_id == "aws_nist_apigateway_stage_logging_enabled":
        from .aws_apigateway_logging_source_correction import correction_provenance
        provenance["signed_spec_status"] = "historical_superseded_for_this_check"
        provenance["source_correction"] = correction_provenance()
    from .aws_policy_source_correction import PRIOR, correction_provenance
    if check_id in PRIOR:
        provenance["signed_spec_status"] = "historical_superseded_for_this_check"
        provenance["source_correction"] = correction_provenance(check_id)
    return provenance


@lru_cache(maxsize=1)
def _runtime():
    """Load runtime metadata; reviewed compliance owns control mappings.

    Retain upstream identity/provenance, while avoiding a second retained copy
    of source-control mappings when the complete reviewed pack is verified.
    Packages without reviewed compliance retain their original full mappings.
    """
    path = PACK / "runtime_metadata.json"
    if not path.exists():
        return None
    compact = _compliance() is not None
    def decode(row):
        row = _shared_metadata_strings(row)
        if compact and "check_id" in row and all(key in row for key in (
                "repository", "source", "revision", "license", "disposition", "frameworks", "official_docs")):
            row.pop("frameworks")
            row.pop("official_docs")
        return row
    return json.loads(path.read_text(), object_hook=decode)


@lru_cache(maxsize=1)
def manifest():
    path = PACK / "upstream_manifest.json"
    if path.exists():
        return json.loads(path.read_text())
    compressed = PACK / "upstream_manifest.json.gz"
    return json.loads(gzip.decompress(compressed.read_bytes())) if compressed.exists() else {"checks": [], "sources": []}


@lru_cache(maxsize=1)
def _mappings():
    runtime = _runtime()
    if runtime is not None:
        return runtime["mappings"]
    return raw_mappings(manifest())


def raw_mappings(data):
    output = {}
    for row in data["checks"]:
        if row["disposition"] not in ("ported", "merged"):
            continue
        for native in row.get("native_checks", []):
            output.setdefault(native, []).append(row)
    return output


def mappings_for(check_id, category, control):
    from . import HACKTRICKS, HACKTRICKS_URL
    from .hacktricks_scope import includes
    from .hacktricks_bp_common import hacktricks_references
    pages = hacktricks_references(check_id)
    result = {HACKTRICKS: {"control": category, "reference": pages[0] if pages else HACKTRICKS_URL, "assurance": "thematic",
                           **({"references": pages, "assurance": "derived from the referenced HackTricks Cloud technique"} if pages else {})}}
    if not includes(check_id):
        result = {}
    display = framework_display_names()
    if _compliance() is not None:
        for tag in requirement_tags_for(check_id):
            name = display[tag["framework_id"]]
            result.setdefault(name, {"controls": [], "assurance": "reviewed requirement mapping; not certification"})["controls"].append(
                {"framework_id": tag["framework_id"], "framework": name, "control_id": tag["requirement_id"],
                 "decision": tag["decision"], "runtime_status": tag["runtime_status"]})
        return result
    for row in _mappings().get(check_id, []):
        for mapping in row.get("frameworks", []):
            name = display.get(mapping["framework_id"]) or canonical_name(mapping["framework"])
            entry = result.setdefault(name, {"controls": [], "assurance": "upstream reference mapping; predicate scope may be narrower"})
            control_mapping = deepcopy(mapping)
            if control_mapping not in entry.setdefault("controls", []):
                entry["controls"].append(control_mapping)
    return result


def family_name(mapping):
    name = mapping.get("framework_family") or mapping["framework"]
    if name.upper().startswith(("NIST-800-53", "NIST 800-53")):
        return "NIST 800-53"
    return {"SOC2": "SOC 2", "PCI": "PCI DSS", "NIST-CSF": "NIST CSF", "ISO27001": "ISO 27001"}.get(name.upper(), name)


def canonical_name(name):
    """Display form of a framework/version name (whitespace-normalized)."""
    return " ".join(str(name).split())


def _framework_rows():
    """Framework/version rows without the defensive copy (read-only use)."""
    runtime = _runtime()
    return runtime["frameworks"] if runtime is not None else _raw_catalog_rows()


@lru_cache(maxsize=1)
def _raw_catalog_rows():
    return raw_framework_catalog(manifest())


def display_names_from_rows(rows):
    return {row["id"]: canonical_name(row["name"]) for row in rows}


@lru_cache(maxsize=1)
def framework_display_names():
    """framework_id -> the ONE canonical display name of that framework and version.

    Labels on checks, findings and catalog mappings always use these names; family slugs such as
    "AWS-Foundational-Security-Best-Practices" or "CIS" stay accepted as filter aliases only."""
    return display_names_from_rows(_framework_rows())


@lru_cache(maxsize=1)
def framework_selector_index():
    """Lower-cased selector (id, display name, family label) -> framework ids it selects."""
    index = {}
    for row in _framework_rows():
        family = row.get("family") or row["name"]
        for key in {row["id"], canonical_name(row["name"]), family, family_name({"framework_family": family, "framework": row["name"]})}:
            index.setdefault(str(key).lower(), set()).add(row["id"])
    return {key: frozenset(value) for key, value in index.items()}


def expand_framework_selectors(values):
    """Requested framework selectors plus every framework id and canonical name they select.

    Accepts ids, canonical display names and family labels (case-insensitive)."""
    index, display = framework_selector_index(), framework_display_names()
    expanded = set(values)
    for value in values:
        for fid in index.get(str(value).lower(), ()):
            expanded.add(fid)
            expanded.add(display[fid])
    return expanded


def names_for_ids(ids, display=None, *, check_id=None):
    from . import HACKTRICKS
    from .hacktricks_scope import includes
    display = framework_display_names() if display is None else display
    return ([HACKTRICKS] if check_id is not None and includes(check_id) else []) + sorted({display.get(fid, fid) for fid in ids} - {HACKTRICKS})


@lru_cache(maxsize=None)
def _names_for(check_id):
    return tuple(names_for_ids(framework_ids_for(check_id), check_id=check_id))


def framework_names_for(check_id):
    """Reviewed checklist membership plus canonical upstream framework names."""
    return list(_names_for(check_id))


def clear_caches():
    from .hacktricks_scope import review
    review.cache_clear()
    for cached in (_compliance, full_requirements, _proposals, manifest, _mappings, _runtime, _raw_catalog_rows, framework_display_names, framework_selector_index, _names_for):
        cached.cache_clear()


def framework_ids_for(check_id):
    if _compliance() is not None:
        return sorted({tag["framework_id"] for tag in requirement_tags_for(check_id)})
    runtime = _runtime()
    if runtime and "framework_lookup" in runtime:
        return list(runtime["framework_lookup"].get(check_id, {}).get("ids", []))
    return sorted({mapping["framework_id"] for row in _mappings().get(check_id, []) for mapping in row["frameworks"]})


def coverage():
    from collections import Counter
    from . import CHECKS
    runtime = _runtime()
    if runtime is not None:
        result = {**deepcopy(runtime["coverage"]), "native_checks": len(CHECKS)}
        packed = _compliance()
        if packed:
            result["requirement_counts"] = deepcopy(packed[0]["counts"])
            result["requirement_versions"] = len(packed[0]["frameworks"])
            result["limitations"] = "Reviewed requirement mappings include manual, partial and not-assessed states; no certification or account compliance is implied."
        return result
    rows = manifest()["checks"]
    totals = Counter(r["disposition"] for r in rows)
    return {"native_checks": len(CHECKS), "upstream_total": len(rows), "upstream": {key: totals[key] for key in ("ported", "merged", "rejected", "pending", "out_of_scope")},
            "supported_upstream": sum(r["disposition"] in ("ported", "merged") for r in rows),
            "outside_runtime_provider_scope": sum(not r.get("runtime_provider_supported", True) for r in rows),
            "runtime_scope_upstream_total": sum(r.get("runtime_provider_supported", True) for r in rows),
            "limitations": "Pending references are not implemented. Mappings are reference tags, not certification or complete framework coverage."}


def provenance_for(check_id):
    return [{key: row[key] for key in ("check_id", "repository", "source", "revision", "license", "disposition")} for row in _mappings().get(check_id, [])]


def framework_catalog(source=None):
    """Source checklist/version selectors; availability is explicit per entry."""
    runtime = _runtime() if source is None else None
    rows = deepcopy(runtime["frameworks"]) if runtime is not None else raw_framework_catalog(manifest() if source is None else source)
    packed = _compliance()
    if packed is None:
        from .native_only import automated_frameworks
        return automated_frameworks(rows)
    requirement_rows = {row["id"]: row for row in packed[0]["frameworks"]}
    lookup = packed[0]["by_check"]
    ids_by_framework = {}
    for cid, tags in lookup.items():
        for tag in tags:
            ids_by_framework.setdefault(tag["framework_id"], set()).add(cid)
    if {row["id"] for row in rows if row["provider"] in {"aws", "gcp", "azure", "k8s"}} != set(requirement_rows):
        raise ValueError("Compiled framework versions differ from runtime metadata")
    for row in rows:
        reviewed = requirement_rows.get(row["id"])
        if reviewed is None:
            continue
        row["source_supported_native_checks"] = row["supported_native_checks"]
        row["requirements_total"] = reviewed["requirements_total"]
        row["requirements_by_status"] = deepcopy(reviewed["requirements_by_status"])
        row["pending_automatable_requirements"] = reviewed["pending_automatable_requirements"]
        row["native_check_ids"] = sorted(ids_by_framework.get(row["id"], ()))
        row["supported_native_checks"] = len(row["native_check_ids"])
        row["status"] = "partially_supported" if row["native_check_ids"] else "pending"
    from .native_only import automated_frameworks
    return automated_frameworks(rows)


def raw_framework_catalog(data):
    entries = {}
    for row in data["checks"]:
        for mapping in row["frameworks"]:
            key = (row["repository"], row["provider"], mapping["framework_id"])
            entry = entries.setdefault(key, {"id": mapping["framework_id"], "name": mapping["framework"],
                "family": mapping.get("framework_family", mapping["framework"]), "provider": row["provider"],
                "version": mapping.get("declared_version") or mapping["version"], "declared_version": mapping.get("declared_version"),
                "source_revision": row["revision"], "repository": row["repository"], "native_check_ids": set(),
                "source_check_ids": set(), "pending_source_check_ids": set(), "manual_requirement_ids": set(), "rejected_invalid_ids": set()})
            entry["source_check_ids"].add(row["check_id"])
            if row["disposition"] in ("ported", "merged"):
                entry["native_check_ids"].update(row["native_checks"])
            elif row["disposition"] == "pending":
                entry["pending_source_check_ids"].add(row["check_id"])
            elif row["disposition"] == "rejected":
                entry["manual_requirement_ids" if row.get("review_classification") == "manual_attestation" else "rejected_invalid_ids"].add(row["check_id"])
    output = []
    for key, entry in sorted(entries.items()):
        entry["native_check_ids"] = sorted(entry["native_check_ids"])
        entry["supported_native_checks"] = len(entry["native_check_ids"])
        entry["source_checks"] = len(entry.pop("source_check_ids"))
        entry["pending_source_checks"] = len(entry.pop("pending_source_check_ids"))
        entry["manual_requirements"] = len(entry.pop("manual_requirement_ids"))
        entry["rejected_invalid_predicates"] = len(entry.pop("rejected_invalid_ids"))
        entry["status"] = "out_of_scope" if entry["provider"] not in ("aws", "gcp", "azure", "k8s") else "partially_supported" if entry["native_check_ids"] else "pending"
        output.append(entry)
    return output


def runtime_metadata(data):
    from . import CHECKS
    from collections import Counter
    totals = Counter(r["disposition"] for r in data["checks"])
    fields = ("check_id", "repository", "source", "revision", "license", "disposition", "frameworks", "official_docs")
    mappings = {cid: [{key: row[key] for key in fields if key in row} for row in rows] for cid, rows in raw_mappings(data).items()}
    frameworks = raw_framework_catalog(data)
    display = display_names_from_rows(frameworks)
    lookup = {}
    for cid, rows in mappings.items():
        ids = sorted({mapping["framework_id"] for row in rows for mapping in row["frameworks"]})
        lookup[cid] = {"names": names_for_ids(ids, display, check_id=cid), "ids": ids}
    manual = manual_requirements(data)
    return {"schema_version": "1.1", "mappings": mappings, "framework_lookup": lookup, "frameworks": frameworks, "manual_requirements": manual,
        "coverage": {"native_checks": len(CHECKS), "upstream_total": len(data["checks"]),
            "upstream": {key: totals[key] for key in ("ported", "merged", "rejected", "pending", "out_of_scope")},
            "supported_upstream": totals["ported"] + totals["merged"],
            "manual_requirements": len(manual), "rejected_invalid_predicates": sum(r["disposition"] == "rejected" and r.get("review_classification") != "manual_attestation" for r in data["checks"]),
            "outside_runtime_provider_scope": totals["out_of_scope"], "runtime_scope_upstream_total": len(data["checks"]) - totals["out_of_scope"],
            "limitations": "Unported target references remain pending; other providers are explicitly out of scope. Reference tags are not certification."}}


def manual_requirements(data=None, *, provider=None, ids=None):
    if data is None:
        runtime = _runtime()
        if runtime is not None:
            rows = runtime.get("manual_requirements", [])
            selected = [row for row in rows if (provider is None or row["provider"] == provider) and (ids is None or row["id"] in ids)]
            return deepcopy(selected)
        data = manifest()
    output = []
    for row in data["checks"]:
        if row.get("review_classification") != "manual_attestation":
            continue
        if provider is not None and row["provider"] != provider or ids is not None and row["check_id"] not in ids:
            continue
        requirement = row["manual_requirement"]
        dependencies = row.get("dependencies", [])
        scope_kinds = sorted({{"aws_account": "account", "gcp_project": "project", "azure_subscription": "subscription",
            "azure_tenant": "tenant", "azuread_tenant": "tenant", "kubernetes_namespace": "namespace"}[kind]
            for kind in dependencies if kind in ("aws_account", "gcp_project", "azure_subscription", "azure_tenant", "azuread_tenant", "kubernetes_namespace")})
        output.append({"id": row["check_id"], "provider": row["provider"], "title": requirement.get("title", row["title"]),
            "question": requirement["question"], "guidance": requirement.get("guidance", row.get("rationale", "")),
            "scope_kinds": requirement.get("scope_kinds", scope_kinds), "source_dependencies": dependencies,
            "status": "MANUAL", "source": row["source"], "revision": row["revision"], "license": row["license"],
            "frameworks": deepcopy(row["frameworks"]), "reason": row["reason"], "automated": False})
    return output


def manual_requirement_ids(provider=None):
    runtime = _runtime()
    if runtime is not None:
        return {row["id"] for row in runtime.get("manual_requirements", []) if provider is None or row["provider"] == provider}
    return {row["id"] for row in manual_requirements(provider=provider)}
