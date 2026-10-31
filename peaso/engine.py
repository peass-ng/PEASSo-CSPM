"""Public snapshot engine. Evaluation is deterministic and never calls a provider."""
from __future__ import annotations
import copy
import json
import re
from urllib.parse import quote
from collections import Counter, defaultdict
from importlib import import_module
from .snapshot import SCHEMA_VERSION, PROVIDERS, digest, freeze, validate, resources, resource_id, seal
from .progress import emit_progress
from .report_quality import normalize_unknown_reasons

CATEGORIES = ("hardening", "exposure", "least_privilege", "iam_graph", "network", "privesc",
              "monitoring", "encryption", "compliance", "logging", "identity", "recovery",
              "vulnerability", "threat_detection", "secure_development", "backup",
              "supply_chain", "malware", "asset_management", "patch_management")
# Catalog-driven privilege-escalation map (peaso.privesc). "privesc" selects every technique.
PRIVESC_CHECK_ID = "privesc"
PRIVESC_FRAMEWORK = "HackTricks Cloud Best Practices"
# Report schema 1.1 stores native items once (in the snapshot) and references them from resources and graphs;
# expand_report() restores the embedded 1.0 form and compact_report() migrates 1.0 reports to 1.1.
REPORT_SCHEMA_VERSION = "1.1"
FRAMEWORK_ALIASES = {"hacktricks": "HackTricks Cloud Best Practices", "hacktricks_cloud_best_practices": "HackTricks Cloud Best Practices",
    "nist_800_53": "NIST 800-53", "nist": "NIST 800-53"}


def _registry():
    from .checks import CHECKS
    from .checks.native_only import automated_checks
    return automated_checks(CHECKS)


def get_catalog():
    from .analysis import ANALYSIS_CHECKS
    from .checks.catalog import coverage as upstream_coverage, description_for, framework_catalog, requirement_tags_for
    from .collectors import supported_types
    from .collectors.bulk_evidence import coverage as evidence_coverage
    from .privesc.versioned_catalog import current_binding
    analysis_checks = copy.deepcopy(ANALYSIS_CHECKS)
    for check in analysis_checks:
        reviewed = description_for(check["id"])
        if reviewed:
            check.update(reviewed)
            check["rationale"] = reviewed["description"]
            check["requirement_controls"] = requirement_tags_for(check["id"])
    from .checks.native_only import scope as automation_scope, automated_coverage, automated_inventory_coverage, automated_inventory_types
    checks = [check.public() for check in _registry()] + analysis_checks
    return {"schema_version": SCHEMA_VERSION, "privesc_catalog": current_binding(), "providers": list(PROVIDERS), "categories": list(CATEGORIES),
        "inventories": {p: automated_inventory_types(p, supported_types(p)) for p in PROVIDERS}, "inventory_coverage": automated_inventory_coverage(evidence_coverage(), _registry()), "framework_versions": framework_catalog(), "manual_requirements": [], "automation_scope": automation_scope(), "checks": checks, "privesc_techniques": privesc_techniques(), "upstream_coverage": automated_coverage(upstream_coverage()), "frameworks": framework_labels(checks),
        "limitations": ["Native reviewed snapshot checks only; upstream catalogs are provenance, not migrated runtime coverage.",
                         "Framework mappings are thematic review guidance, not certification.", "Graphs describe declared relationships; effective access and reachability require separate validation."]}


catalog = get_catalog


def framework_labels(checks):
    """One row per canonical framework label: its filter id (alias or name) and the version ids it names."""
    from .checks.catalog import framework_display_names
    by_name = defaultdict(set)
    for fid, name in framework_display_names().items():
        by_name[name].add(fid)
    names = sorted({framework for check in checks for framework in check["frameworks"]})
    return [{"id": next((k for k, v in FRAMEWORK_ALIASES.items() if v == name), name), "name": name,
             "framework_ids": sorted(by_name.get(name, ()))} for name in names]


def _expand_frameworks(frameworks):
    from .checks.catalog import expand_framework_selectors
    return expand_framework_selectors([FRAMEWORK_ALIASES.get(value, value) for value in frameworks])


def privesc_techniques(provider=None):
    """Public summary of the privilege-escalation technique catalog (one row per technique)."""
    try:
        from . import privesc
        entries = privesc.catalog()["entries"]
    except ImportError:  # packages built without peaso.privesc (e.g. a trimmed API bundle)
        return []
    return [{"id": e["id"], "provider": e.get("provider"), "service": e.get("service"), "title": e.get("title"),
             "severity": e.get("severity"), "confidence": e.get("confidence"), "category": "privesc",
             "frameworks": [PRIVESC_FRAMEWORK], "source": e.get("source"), "source_revision": e.get("source_revision"),
             "mitigation": e.get("mitigation")}
            for e in entries if provider is None or e.get("provider") == provider]


ADMIN_EQUIVALENT_TECHNIQUE = {
    "id": "admin-equivalent", "title": "Principal already administers the target scope", "provider": None, "service": "iam",
    "summary": "The principal's collected grants are equivalent to administrator of the scope; no escalation step is needed.",
    "required_permissions": {"all_of": ["administrator-equivalent grant on the scope"], "any_of": [],
                             "leaves": ["administrator-equivalent grant on the scope"],
                             "alternatives": [["administrator-equivalent grant on the scope"]]}, "requires": {},
    "source": None, "source_revision": None, "conditions": [], "blockers": [], "severity": "critical", "catalog_confidence": "derived",
    "mitigation": "Review why this principal needs full administrative control; prefer scoped, time-bound access.", "references": []}


def _permission_text(requirement):
    if not isinstance(requirement, dict):
        return str(requirement)
    for key in ("action", "data_action", "entra_permission", "graph_app_permission", "entra_role", "entra_pim_eligible_role", "entra_tenant_setting"):
        if requirement.get(key):
            text = str(requirement[key])
            break
    else:
        if requirement.get("verb"):
            resource = "/".join(str(requirement[k]) for k in ("resource", "subresource") if requirement.get(k))
            group = requirement.get("api_group")
            text = f"{requirement['verb']} {group + '/' if group else ''}{resource}"
        elif requirement.get("entra_owner_of"):
            text = f"owner of {requirement['entra_owner_of']}"
        else:
            text = ", ".join(f"{k}={v}" for k, v in sorted(requirement.items()))
    where = requirement.get("resource") if "action" in requirement or "data_action" in requirement else None
    where = where or requirement.get("scope") or requirement.get("namespace") or requirement.get("resource_name")
    return f"{text} on {where}" if where and where != "*" else text


def _requirement_text(item):
    """Text of one requires item: a leaf requirement, or a nested {all_of}/{any_of} group rendered recursively
    ("(a AND b)", "(a OR (b AND c))"); a list inside any_of is one conjunction."""
    from .privesc.schema import is_group
    if not is_group(item):
        return _permission_text(item)
    key = "all_of" if "all_of" in item else "any_of"
    parts = ["(" + " AND ".join(_requirement_text(c) for c in child) + ")" if isinstance(child, list) and len(child) != 1
             else _requirement_text(child[0] if isinstance(child, list) else child) for child in item.get(key) or []]
    if len(parts) == 1:
        return parts[0]
    return "(" + (" AND " if key == "all_of" else " OR ").join(parts) + ")"


def _required_permissions(requires):
    """Readable required permissions. all_of / any_of keep the catalog's top-level structure (nested groups are
    rendered by _requirement_text); leaves lists every leaf permission (flatten_requirements) and alternatives the
    disjunctive normal form (expand_requires: each alternative is a set of permissions that together suffice)."""
    from .privesc.schema import CatalogError, expand_requires, flatten_requirements
    out = {"all_of": [_requirement_text(r) for r in requires.get("all_of") or []],
           "any_of": [[_requirement_text(r) for r in (group if isinstance(group, list) else [group])] for group in requires.get("any_of") or []],
           "leaves": list(dict.fromkeys(_permission_text(r) for r in flatten_requirements(requires)))}
    try:
        out["alternatives"] = [[_permission_text(r) for r in alternative] for alternative in expand_requires(requires)]
    except CatalogError:
        out["alternatives"] = None  # beyond the evaluator's expansion cap; the structured all_of/any_of still apply
    return out


def privesc_technique_details(technique_ids, *, catalog_binding=None, tenant_id=None):
    """Catalog details (summary, required permissions, HackTricks source, conditions, mitigation) per technique id."""
    try:
        from .privesc.versioned_catalog import lookup_entries
        entries, lookup_status = lookup_entries(technique_ids, catalog_binding, tenant_id=tenant_id)
    except ImportError:
        entries, lookup_status = {}, "catalog_unavailable"
    details = {}
    for technique in technique_ids:
        if technique == "admin-equivalent" and lookup_status in ("exact_bounded_v5", "exact_additive_v4", "exact_legacy", "legacy_unversioned_fallback"):
            details[technique] = dict(copy.deepcopy(ADMIN_EQUIVALENT_TECHNIQUE), catalog_lookup_status="synthetic")
            continue
        entry = entries.get(technique)
        if entry is None:
            details[technique] = {"id": technique, "unknown": True, "catalog_lookup_status": lookup_status}
            continue
        requires = entry.get("requires") or {}
        from .privesc.effective_permissions.principal_evidence import BULK_CONTRACT
        if technique in BULK_CONTRACT:
            requires = BULK_CONTRACT[technique]["requires"]
        details[technique] = {
            "id": technique, "title": entry.get("title"), "provider": entry.get("provider"), "service": entry.get("service"),
            "summary": entry.get("summary"), "requires": copy.deepcopy(requires),
            "required_permissions": _required_permissions(requires),
            "source": entry.get("source"), "source_revision": entry.get("source_revision"),
            "conditions": copy.deepcopy(entry.get("conditions") or []), "blockers": list(entry.get("blockers") or []),
            "severity": entry.get("severity"), "catalog_confidence": entry.get("confidence"),
            "mitigation": entry.get("mitigation"), "references": list(entry.get("references") or []),
            "catalog_lookup_status": lookup_status}
    return details


def _privesc_selected(provider, categories, checks, frameworks):
    """None when privesc is not selected; otherwise the technique-id filter (empty set = every technique)."""
    if "privesc" not in categories:
        return None
    frameworks = [FRAMEWORK_ALIASES.get(value, value) for value in frameworks] if frameworks else None
    if frameworks and PRIVESC_FRAMEWORK not in frameworks:
        return None
    if not checks or PRIVESC_CHECK_ID in checks:
        return set()
    techniques = {t["id"] for t in privesc_techniques(provider)} & set(checks)
    return techniques or None


# These optional readers require an explicit named check and selected content.
EXPLICIT_CONTENT_CHECK_IDS = frozenset({
    'gcp.review.appengine.deployment_source_secret_indicators',
    'gcp.review.artifactregistry.selected_file_secret_indicators',
    'gcp.review.batch.selected_mounted_script_source_secret_indicators',
    'gcp.review.bigquery.selected_routine_secret_indicators',
    'gcp.review.cloudbuild.artifact_secret_indicators',
    'gcp.review.cloudbuild.stored_log_secret_indicators',
    'gcp.review.clouddeploy.release_source_secret_indicators',
    'gcp.review.cloudtasks.selected_payload_secret_indicators',
    'gcp.review.dataflow.selected_package_referenced_source_secret_indicators',
    'gcp.review.dataform.selected_file_secret_indicators',
    'gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators',
    'gcp.review.dataproc.selected_job_referenced_source_secret_indicators',
    'gcp.review.gke_workload.literal_configuration_secret_indicators',
    'gcp.review.sourcerepo.selected_file_secret_indicators',
    'gcp.review.storage.selected_archive_secret_indicators',
    'gcp.review.storage.selected_object_secret_indicators',
    'gcp.review.workbench.selected_referenced_source_secret_indicators_20261020',
    'aws.review.build_deployment.referenced_source_secret_indicators',
    'aws.review.ecr_public.selected_image_high_vulnerabilities',
    'aws.review.ecr_public.selected_image_secret_indicators',
    'aws.review.workload.referenced_source_secret_indicators',
    'aws.review.workload.selected_command_literal_secret_indicators',
    'aws.review.workload.selected_image_secret_indicators',
    'azure.review.aks.selected_pod_image_high_vulnerabilities',
    'azure.review.aks.selected_pod_image_secret_indicators',
    'azure.review.app_service.runtime_support_declared',
    'gcp.review.artifact_image.selected_image_vulnerabilities',
    'gcp.review.cloud_run.selected_job_image_vulnerabilities',
    'gcp.review.cloudrun_job.declared_image_secret_indicators',
    'gcp.review.cloudrun_worker_pool.selected_revision_image_secret_indicators',
    'gcp.review.developerconnect.selected_repository_file_secret_indicators',
    'gcp.review.gke.selected_pod_image_high_vulnerabilities',
    'gcp.review.gke.selected_pod_image_secret_indicators',
    'gcp.review.app_engine_flex.selected_version_image_secret_indicators',
    'gcp.review.app_engine_flex.selected_version_image_high_vulnerabilities',
    'k8s.review.selected_flux_artifact_secret_indicators',
    'k8s.review.selected_registry_image_high_vulnerabilities',
    'k8s.review.selected_registry_image_secret_indicators',
})


def _selection(provider, categories, checks, frameworks, *, content_checks=None):
    selected_categories = ([] if categories == [] and content_checks else list(CATEGORIES)) if not categories else _string_list(categories, "categories")
    if any(category not in CATEGORIES for category in selected_categories):
        raise ValueError("unsupported category")
    registry = _registry()
    from .analysis import ANALYSIS_CHECKS
    checks = checks or None
    frameworks = frameworks or None
    if checks is not None:
        from .checks import CHECK_ALIASES
        checks = list(dict.fromkeys(CHECK_ALIASES.get(check, check) for check in _string_list(checks, "checks")))
        from .checks.native_only import exclusions
        from .checks.catalog import manual_requirement_ids
        unavailable = set(checks).intersection(exclusions()) | set(checks).intersection(manual_requirement_ids(provider))
        if unavailable:
            raise ValueError("check requires external policy or manual evidence and is not available for automated scans: " + ", ".join(sorted(unavailable)))
        known = {c.id for c in registry if c.provider == provider} | {c["id"] for c in ANALYSIS_CHECKS}
        if any(check not in known for check in checks):
            known |= {PRIVESC_CHECK_ID} | {t["id"] for t in privesc_techniques(provider)}
        unknown = [check for check in checks if check not in known]
        if unknown:
            raise ValueError("unknown check ID for selected provider: " + ", ".join(unknown[:10]))
    if frameworks is not None:
        frameworks = [FRAMEWORK_ALIASES.get(value, value) for value in _string_list(frameworks, "frameworks")]
        from .checks.catalog import _framework_rows, framework_selector_index
        provider_ids = {row["id"] for row in _framework_rows() if row["provider"] in (provider, "all")}
        supported = {f for c in registry if c.provider == provider for f in c.frameworks} | {f for c in ANALYSIS_CHECKS for f in c["frameworks"]} | provider_ids
        index = framework_selector_index()
        # Ids, canonical display names and family labels (e.g. "CIS", "NIST 800-53") are all valid selectors.
        if any(f not in supported and not provider_ids.intersection(index.get(f.lower(), ())) for f in frameworks):
            raise ValueError("unsupported framework")
        frameworks = _expand_frameworks(frameworks)
    selected = [c for c in registry if c.provider == provider and c.category in selected_categories
        and (checks is None or c.id in checks) and (frameworks is None or (set(c.frameworks) | set(getattr(c, "framework_ids", []))).intersection(frameworks))]
    selected = [c for c in selected if c.id not in EXPLICIT_CONTENT_CHECK_IDS or checks is not None and c.id in checks]
    if content_checks:
        from .content_scan_selection import known_content_checks
        content_checks = _string_list(content_checks, 'content_checks')
        allowed = known_content_checks(provider)
        if set(content_checks) - allowed:
            raise ValueError('Unsupported content check for selected provider')
        known = {check.id for check in selected}
        selected.extend(check for check in registry if check.provider == provider
                        and check.id in content_checks and check.id not in known)
    return selected_categories, selected


def _known_content_checks(provider):
    from .content_scan_selection import known_content_checks
    return known_content_checks(provider)


def _drop_unrequested_content(provider, snapshot, selected, checks, content_checks):
    """Leave out opt-in content checks the snapshot's collection did not request.

    Only snapshots that record their requested content checks are filtered;
    older snapshots keep their previous evaluation.
    """
    plan = (snapshot.get("metadata") or {}).get("collection_plan")
    if not isinstance(plan, dict) or not isinstance(plan.get("content_checks"), list):
        return selected, []
    requested = set(plan["content_checks"]) | set(content_checks or []) | set(checks or [])
    known = _known_content_checks(provider)
    skipped = sorted({c.id for c in selected if c.id in known and c.id not in requested})
    return [c for c in selected if c.id not in skipped], skipped


def _string_list(value, name):
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError(name + " must be a string list")
    return list(dict.fromkeys(value))


def _request(request):
    if not isinstance(request, dict):
        raise ValueError("scan request must be an object")
    from .content_scan_selection import named_checks, normalize_request, validate_content_checks
    # API compatibility accepts either a connector or the complete scan request.
    connector = request.get("connector", request if "provider" in request else None)
    if not isinstance(connector, dict) or connector.get("provider") not in PROVIDERS:
        raise ValueError("connector requires a supported provider")
    for field in ("auth", "options"):
        if field in connector and not isinstance(connector[field], dict):
            raise ValueError("connector " + field + " must be an object")
    if "scopes" in connector:
        _string_list(connector["scopes"], "scopes")
    request = normalize_request(request)
    if request.get('leaks_enabled') is False or request.get('images_enabled') is False:
        connector = dict(connector, options=dict(connector.get('options', {})))
        if request.get('leaks_enabled') is False:
            connector['options']['content_secret_scans'] = False
        if request.get('images_enabled') is False:
            connector['options']['image_vulnerability_scans'] = False
    validate_content_checks(connector['provider'], connector.get('options', {}), request.get('content_checks') or [])
    _selection(connector["provider"], request.get("categories"), request.get("checks"), request.get("frameworks"), content_checks=request.get('content_checks'))
    content_options = connector.get('options', {})
    from .gcp_image_selection_20261021 import OPTION as REGISTRY_CVE_OPTION, selections as registry_cve_selection
    if REGISTRY_CVE_OPTION in content_options:
        if connector['provider'] != 'gcp':
            raise ValueError('Selected registry images require GCP')
        registry_cve_selection(content_options, connector.get('scopes', []))
    from .collectors.aws_workload_command_runtime_20261020 import targets as workload_command_targets
    workload_command_targets(content_options, connector.get('scopes', []), named_checks(request), connector['provider'])
    from .collectors.gcp_cloudrun_job_image_runtime_20261020 import validate_request as validate_cloudrun_job_images
    validate_cloudrun_job_images(connector, dict(request, checks=named_checks(request)))
    from .collectors.gcp_workerpool_image_runtime_20261021 import validate_request as validate_workerpool_images
    validate_workerpool_images(connector, dict(request, checks=named_checks(request)))
    from .gcp_appengine_flex_image_selection_20261021 import selected as selected_flex_images
    if connector['provider'] == 'gcp':
        selected_flex_images(content_options, connector.get('scopes', []), named_checks(request))
    from .collectors.gcp_developerconnect_file_runtime_20261021 import validate_request as validate_developerconnect_files
    validate_developerconnect_files(connector, dict(request, checks=named_checks(request)))
    from .collectors.gcp_job_image_vulnerability_runtime_20261021 import validate_request as validate_job_image_vulnerabilities
    if connector['provider'] == 'gcp':
        validate_job_image_vulnerabilities(connector, dict(request, checks=named_checks(request)))
    from .aws_image_selection_20261021 import validate_request as validate_aws_image_vulnerabilities
    validate_aws_image_vulnerabilities(connector, dict(request, checks=named_checks(request)))
    from .collectors.azure_function_package_integration_20261020 import preflight as package_preflight
    package_preflight(content_options, connector.get('scopes', []), named_checks(request), provider=connector['provider'])
    from .collectors.aws_codebuild_buildspec_runtime_20261020 import targets as codebuild_inline_targets
    codebuild_inline_targets(content_options, connector.get('scopes', []), named_checks(request), connector['provider'])
    if 'selected_aws_s3_sources' in content_options and connector['provider'] != 'aws':
        raise ValueError('Selected S3 sources require AWS provider')
    from .collectors.gcp_dataflow_batch_source_runtime_20261020 import preflight as selected_job_preflight
    selected_job_preflight(content_options, connector.get('scopes', []), named_checks(request), connector['provider'])
    from .collectors.gcp_workbench_source_runtime_20261020 import source as workbench_source, preflight as workbench_preflight, CHECK as WORKBENCH_SOURCE_CHECK
    workbench_named = [cid for cid in (named_checks(request)) if cid == WORKBENCH_SOURCE_CHECK]
    if workbench_source.OPTION in content_options or (content_options.get('content_secret_scans') is True and workbench_named):
        if connector['provider'] != 'gcp':
            raise ValueError('Selected Workbench sources require GCP provider')
        workbench_preflight(content_options, connector.get('scopes', []), workbench_named)
    from .collectors.gcp_dataproc_source_runtime_20261020 import source as dataproc_source, preflight as dataproc_preflight, CHECKS as DATAPROC_SOURCE_CHECKS
    dataproc_named = [cid for cid in (named_checks(request)) if cid in DATAPROC_SOURCE_CHECKS]
    if dataproc_source.OPTION in content_options or (content_options.get('content_secret_scans') is True and dataproc_named):
        if connector['provider'] != 'gcp':
            raise ValueError('Selected Dataproc sources require GCP provider')
        dataproc_preflight(content_options, connector.get('scopes', []), dataproc_named)
    from .collectors.azure_selected_declaration_secret_indicators import PROFILES as DECLARATION_PROFILES, selected_targets as declaration_targets
    declaration_named = [p['kind'] for p in DECLARATION_PROFILES.values() if p['check'] in (named_checks(request))]
    if any(p['option'] in content_options for p in DECLARATION_PROFILES.values()) or (content_options.get('content_secret_scans') is True and declaration_named):
        if connector['provider'] != 'azure':
            raise ValueError('Selected Azure declarations require Azure provider')
        declaration_targets({**content_options, '_content_secret_scan_kinds': declaration_named}, connector.get('scopes', []))
    from .collectors.azure_selected_log_sample_secret_indicators import PROFILES as LOG_SAMPLE_PROFILES, selected_targets as log_sample_targets
    log_sample_named = [p['kind'] for p in LOG_SAMPLE_PROFILES.values() if p['check'] in (named_checks(request))]
    if any(p['option'] in content_options for p in LOG_SAMPLE_PROFILES.values()) or (content_options.get('content_secret_scans') is True and log_sample_named):
        if connector['provider'] != 'azure':
            raise ValueError('Selected Azure log samples require Azure provider')
        log_sample_targets({**content_options, '_content_secret_scan_kinds': log_sample_named}, connector.get('scopes', []))
    from .collectors.azure_ml_selected_job_secret_indicators import KIND as ML_JOB_KIND, CHECK as ML_JOB_CHECK, OPTION as ML_JOB_OPTION, selected_targets as ml_job_targets
    if ML_JOB_OPTION in content_options or (content_options.get('content_secret_scans') is True and ML_JOB_CHECK in (named_checks(request))):
        if connector['provider'] != 'azure':
            raise ValueError('Selected Azure ML jobs require Azure provider')
        ml_job_targets({**content_options, '_content_secret_scan_kinds': [ML_JOB_KIND] if ML_JOB_CHECK in (named_checks(request)) else []}, connector.get('scopes', []))
    from .collectors.azure_databricks_notebook_secret_indicators import KIND as NOTEBOOK_KIND, CHECK as NOTEBOOK_CHECK, OPTION as NOTEBOOK_OPTION, FILE_OPTION as DATABRICKS_FILE_OPTION, RUN_OPTION as DATABRICKS_RUN_OPTION, selected_targets as notebook_targets
    if any(key in content_options for key in (NOTEBOOK_OPTION,DATABRICKS_FILE_OPTION,DATABRICKS_RUN_OPTION)) or (content_options.get('content_secret_scans') is True and NOTEBOOK_CHECK in (named_checks(request))):
        if connector['provider'] != 'azure':
            raise ValueError('Selected Azure Databricks content requires Azure provider')
        notebook_targets({**content_options, '_content_secret_scan_kinds': [NOTEBOOK_KIND] if NOTEBOOK_CHECK in (named_checks(request)) else []}, connector.get('scopes', []))
    from .collectors.azure_ml_selected_asset_secret_indicators import PROFILES as ML_ASSET_PROFILES, selected_targets as ml_asset_targets
    ml_asset_named = [p['kind'] for p in ML_ASSET_PROFILES.values() if p['check'] in (named_checks(request))]
    if any(p['option'] in content_options for p in ML_ASSET_PROFILES.values()) or (content_options.get('content_secret_scans') is True and ml_asset_named):
        if connector['provider'] != 'azure':
            raise ValueError('Selected Azure ML assets require Azure provider')
        ml_asset_targets({**content_options, '_content_secret_scan_kinds': ml_asset_named}, connector.get('scopes', []))
    from .collectors.azure_function_settings_declarations_20261020 import OPTION as FUNCTION_SETTINGS_OPTION, CHECKS as FUNCTION_SETTINGS_CHECKS, preflight as function_settings_preflight
    function_named = [cid for cid in (named_checks(request)) if cid in FUNCTION_SETTINGS_CHECKS]
    if FUNCTION_SETTINGS_OPTION in content_options or (content_options.get('content_secret_scans') is True and function_named):
        if connector['provider'] != 'azure':
            raise ValueError('Selected Function settings require Azure provider')
        function_settings_preflight(content_options, connector.get('scopes', []), function_named)
    if connector['provider'] == 'aws':
        from .collectors.aws_lambda_environment_secret_indicators import selected_targets as lambda_environment_targets, KIND as LAMBDA_ENV_KIND, CHECK as LAMBDA_ENV_CHECK, OPTION as LAMBDA_ENV_OPTION
        from .collectors.aws_selected_configuration_secret_indicators import selected_targets as configuration_content_targets, KIND as CONFIG_CONTENT_KIND, CHECK as CONFIG_CONTENT_CHECK, OPTION as CONFIG_CONTENT_OPTION
        from .collectors.aws_s3_selected_source_secret_indicators import selected_targets as s3_source_targets, KIND as S3_SOURCE_KIND, CHECK as S3_SOURCE_CHECK, OPTION as S3_SOURCE_OPTION
        from .collectors.aws_ecs_environment_file_secret_indicators import selected_targets as ecs_file_targets, KIND as ECS_FILE_KIND, CHECK as ECS_FILE_CHECK, OPTION as ECS_FILE_OPTION
        from .collectors.aws_workload_referenced_source_indicators import selected_targets as workload_targets, KIND as WORKLOAD_KIND, CHECK as WORKLOAD_CHECK, OPTION as WORKLOAD_OPTION
        from .collectors.aws_build_deployment_referenced_source_indicators import selected_targets as build_targets, KIND as BUILD_KIND, CHECK as BUILD_CHECK, OPTION as BUILD_OPTION
        if ECS_FILE_OPTION in content_options or (content_options.get('content_secret_scans') is True and ECS_FILE_CHECK in (named_checks(request))):
            ecs_file_targets({**content_options, '_content_secret_scan_kinds': [ECS_FILE_KIND] + ([WORKLOAD_KIND] if WORKLOAD_CHECK in (named_checks(request)) else []) + ([BUILD_KIND] if BUILD_CHECK in (named_checks(request)) else []) + ([S3_SOURCE_KIND] if S3_SOURCE_CHECK in (named_checks(request)) else [])}, connector.get('scopes', []))
        if WORKLOAD_OPTION in content_options or (content_options.get('content_secret_scans') is True and WORKLOAD_CHECK in (named_checks(request))):
            workload_targets({**content_options, '_content_secret_scan_kinds': [WORKLOAD_KIND] + ([ECS_FILE_KIND] if ECS_FILE_CHECK in (named_checks(request)) else []) + ([BUILD_KIND] if BUILD_CHECK in (named_checks(request)) else []) + ([S3_SOURCE_KIND] if S3_SOURCE_CHECK in (named_checks(request)) else [])}, connector.get('scopes', []))
        if BUILD_OPTION in content_options or (content_options.get('content_secret_scans') is True and BUILD_CHECK in (named_checks(request))):
            build_targets({**content_options, '_content_secret_scan_kinds': [BUILD_KIND] + ([ECS_FILE_KIND] if ECS_FILE_CHECK in (named_checks(request)) else []) + ([WORKLOAD_KIND] if WORKLOAD_CHECK in (named_checks(request)) else []) + ([S3_SOURCE_KIND] if S3_SOURCE_CHECK in (named_checks(request)) else [])}, connector.get('scopes', []))
        if S3_SOURCE_OPTION in content_options or (content_options.get('content_secret_scans') is True and S3_SOURCE_CHECK in (named_checks(request))):
            s3_source_targets({**content_options, '_content_secret_scan_kinds': [S3_SOURCE_KIND]}, connector.get('scopes', []))
        if 'content_secret_scans' in content_options and type(content_options['content_secret_scans']) is not bool:
            raise ValueError('content_secret_scans must be a boolean')
        if LAMBDA_ENV_OPTION in content_options:
            lambda_environment_targets({**content_options, '_content_secret_scan_kinds': [LAMBDA_ENV_KIND]}, connector.get('scopes', []))
        if CONFIG_CONTENT_OPTION in content_options:
            configuration_content_targets({**content_options, '_content_secret_scan_kinds': [CONFIG_CONTENT_KIND]}, connector.get('scopes', []))
    from .collectors.k8s_selected_registry_image_20261021 import OPTION as K8S_IMAGE_OPTION, ALLOWLIST as K8S_IMAGE_ALLOWLIST, selected_targets as k8s_image_targets, registry_credentials as k8s_image_credentials, SECRET_CHECK as K8S_IMAGE_SECRET_CHECK, VULN_CHECK as K8S_IMAGE_VULN_CHECK
    if K8S_IMAGE_OPTION in content_options and connector['provider'] != 'k8s':
        raise ValueError('Selected Kubernetes registry images require Kubernetes provider')
    if connector['provider'] == 'k8s':
        k8s_targets = k8s_image_targets(content_options, connector.get('scopes', []), named_checks(request))
        k8s_image_credentials(connector.get('auth', {}), k8s_targets, content_options.get(K8S_IMAGE_ALLOWLIST, []))
    if 'selected_k8s_flux_artifacts' in content_options and connector['provider'] != 'k8s':
        raise ValueError('Selected Flux artifacts require Kubernetes provider')
    if connector['provider'] == 'k8s':
        from .collectors.k8s_selected_flux_artifact_20261021 import selected_targets as flux_targets
        flux_targets(content_options, connector.get('scopes', []), named_checks(request))
    if 'selected_k8s_metadata_resources' in content_options and connector['provider'] != 'k8s':
        raise ValueError('Selected Kubernetes metadata requires Kubernetes provider')
    if connector['provider'] == 'k8s':
        from .collectors.k8s_selected_metadata_runtime_20261020 import preflight as k8s_metadata_preflight
        k8s_metadata_preflight(content_options, connector.get('scopes', []), named_checks(request))
        from .collectors.k8s_literal_secret_indicators import selected_targets as k8s_literal_targets, KIND as K8S_LITERAL_KIND, CHECK as K8S_LITERAL_CHECK, OPTION as K8S_LITERAL_OPTION
        if ('content_secret_scans' in content_options and type(content_options['content_secret_scans']) is not bool):
            raise ValueError('content_secret_scans must be a boolean')
        if K8S_LITERAL_OPTION in content_options:
            k8s_literal_targets({**content_options, '_content_secret_scan_kinds': [K8S_LITERAL_KIND]}, connector.get('scopes', []))
        from .collectors.k8s_selected_text_content import selected_targets as k8s_text_targets, KIND as K8S_TEXT_KIND, CHECK as K8S_TEXT_CHECK, OPTION as K8S_TEXT_OPTION
        if K8S_TEXT_OPTION in content_options or (content_options.get('content_secret_scans') is True and K8S_TEXT_CHECK in (named_checks(request))):
            k8s_text_targets({**content_options, '_content_secret_scan_kinds': [K8S_TEXT_KIND] if K8S_TEXT_CHECK in (named_checks(request)) else []}, connector.get('scopes', []))
        from .collectors.k8s_selected_log_sample_secret_indicators import selected_targets as k8s_log_targets, KIND as K8S_LOG_KIND, CHECK as K8S_LOG_CHECK, OPTION as K8S_LOG_OPTION
        if K8S_LOG_OPTION in content_options or (content_options.get('content_secret_scans') is True and K8S_LOG_CHECK in (named_checks(request))):
            k8s_log_targets({**content_options, '_content_secret_scan_kinds': [K8S_LOG_KIND]}, connector.get('scopes', []))
    if connector['provider'] == 'azure':
        from .collectors.azure_app_settings_secret_indicators import selected_targets as azure_settings_targets, KIND as AZURE_SETTINGS_KIND, CHECK as AZURE_SETTINGS_CHECK, OPTION as AZURE_SETTINGS_OPTION
        if ('content_secret_scans' in content_options and type(content_options['content_secret_scans']) is not bool):
            raise ValueError('content_secret_scans must be a boolean')
        if AZURE_SETTINGS_OPTION in content_options:
            azure_settings_targets({**content_options, '_content_secret_scan_kinds': [AZURE_SETTINGS_KIND]}, connector.get('scopes', []))
        from .collectors.azure_acr_image_secret_indicators import selected_targets as azure_acr_targets, KIND as AZURE_ACR_KIND, CHECK as AZURE_ACR_CHECK, OPTION as AZURE_ACR_OPTION
        from .collectors.azure_acr_image_vulnerabilities_20261021 import selected_targets as azure_acr_vuln_targets, KIND as AZURE_ACR_VULN_KIND, CHECK as AZURE_ACR_VULN_CHECK, OPTION as AZURE_ACR_VULN_OPTION
        if AZURE_ACR_OPTION in content_options or (content_options.get('content_secret_scans') is True and AZURE_ACR_CHECK in (named_checks(request))):
            azure_acr_targets({**content_options, '_content_secret_scan_kinds': [AZURE_ACR_KIND]}, connector.get('scopes', []))
        if AZURE_ACR_VULN_OPTION in content_options or (content_options.get('image_vulnerability_scans') is True and AZURE_ACR_VULN_CHECK in (named_checks(request))):
            azure_acr_vuln_targets(content_options, connector.get('scopes', []))
        from .collectors.azure_selected_configuration_secret_indicators import selected_targets as azure_configuration_targets, KIND as AZURE_CONFIG_KIND, CHECK as AZURE_CONFIG_CHECK, OPTION as AZURE_CONFIG_OPTION
        if AZURE_CONFIG_OPTION in content_options:
            azure_configuration_targets({**content_options, '_content_secret_scan_kinds': [AZURE_CONFIG_KIND]}, connector.get('scopes', []))
        from .collectors.azure_selected_storage_secret_indicators import selected_targets as storage_targets, KIND as STORAGE_KIND, CHECK as STORAGE_CHECK, OPTION as STORAGE_OPTION
        if STORAGE_OPTION in content_options or (content_options.get('content_secret_scans') is True and STORAGE_CHECK in (named_checks(request))):
            storage_targets({**content_options, '_content_secret_scan_kinds': [STORAGE_KIND]}, connector.get('scopes', []))
        from .collectors.azure_flex_deployment_archives_20261021 import selected_targets as flex_targets, KIND as FLEX_KIND, CHECK as FLEX_CHECK, OPTION as FLEX_OPTION
        if FLEX_OPTION in content_options or (content_options.get('content_secret_scans') is True and FLEX_CHECK in (named_checks(request))):
            flex_targets({**content_options, '_content_secret_scan_kinds':[FLEX_KIND] if FLEX_CHECK in (named_checks(request)) else [],
                '_azure_flex_named_checks':[FLEX_CHECK] if FLEX_CHECK in (named_checks(request)) else []},connector.get('scopes',[]))
        from .collectors.azure_devops_selected_content_secret_indicators import selected_targets as devops_targets, KIND as DEVOPS_KIND, CHECK as DEVOPS_CHECK, OPTION as DEVOPS_OPTION
        if DEVOPS_OPTION in content_options or (content_options.get('content_secret_scans') is True and DEVOPS_CHECK in (named_checks(request))):
            devops_targets({**content_options, '_content_secret_scan_kinds': [DEVOPS_KIND]}, connector.get('scopes', []), connector.get('auth', {}))
    if (connector['provider'] == 'gcp' and content_options.get('content_secret_scans') is True
            and 'gcp.review.artifactregistry.selected_file_secret_indicators' in (named_checks(request))):
        from .collectors.gcp_artifact_file_secret_indicators import normalize_selection, KIND as ARTIFACT_FILE_KIND, Incomplete as ArtifactFileIncomplete
        try:
            normalize_selection({**content_options, '_content_secret_scan_kinds': [ARTIFACT_FILE_KIND]}, connector.get('scopes', []))
        except ArtifactFileIncomplete:
            raise ValueError('Artifact file inspection requires exact scoped file names, expected SHA256 and supported formats') from None
    if connector['provider'] == 'gcp' and 'selected_gke_pod_images' in content_options:
        from .gcp_gke_image_selection_20261021 import selected as selected_gke_images, kubernetes_auth as gke_image_auth, registry_auth as gke_registry_auth
        selected_images = selected_gke_images(content_options, connector.get('scopes', []), named_checks(request))
        gke_image_auth(connector.get('auth', {}), selected_images)
        gke_registry_auth(connector.get('auth', {}), selected_images, content_options.get('selected_registry_hosts', []))
    if (connector['provider'] == 'gcp' and content_options.get('content_secret_scans') is True
            and 'gcp.review.gke_workload.literal_configuration_secret_indicators' in (named_checks(request))):
        from types import SimpleNamespace
        from .collectors.gcp_gke_literal_secret_indicators import selected as gke_selected, KIND as GKE_KIND
        try:
            requested_scopes = connector.get('scopes', [])
            gke_selected(SimpleNamespace(options={**content_options, '_content_secret_scan_kinds': [GKE_KIND]},
                requested_scopes=requested_scopes), (requested_scopes or [''])[0])
        except Exception:
            raise ValueError('GKE content inspection requires exact scoped cluster selections and optional namespace mapping') from None
    if (connector['provider'] == 'gcp' and content_options.get('content_secret_scans') is True
            and 'gcp.review.dataform.selected_file_secret_indicators' in (named_checks(request))):
        from .collectors.gcp_dataform_secret_indicators import selected_targets as dataform_targets, KIND as DATAFORM_KIND, Incomplete as DataformIncomplete
        try:
            dataform_targets({**content_options, '_content_secret_scan_kinds': [DATAFORM_KIND]}, connector.get('scopes', []))
        except DataformIncomplete:
            raise ValueError('Selected Dataform inspection requires exact scoped repository/file and commit SHA or explicit workspace targets') from None
    if (connector['provider'] == 'gcp' and 'content_secret_scans' in content_options
            and type(content_options['content_secret_scans']) is not bool):
        raise ValueError('content_secret_scans must be a boolean')
    if (connector['provider'] == 'gcp' and content_options.get('content_secret_scans') is True
            and 'gcp.review.storage.selected_archive_secret_indicators' in (named_checks(request))):
        from .collectors.gcp_selected_archive_secret_indicators import normalize_selection, KIND
        try:
            normalize_selection({**content_options, '_content_secret_scan_kinds': [KIND]}, connector.get('scopes', []))
            if len(content_options.get('selected_gcs_objects', [])) + len(content_options.get('selected_gcs_archives', [])) > 10:
                raise ValueError('combined target limit')
        except Exception:
            raise ValueError('Selected archive inspection requires exact scoped object generations, supported formats and at most 10 combined object/archive targets') from None
    if (connector['provider'] == 'gcp' and content_options.get('content_secret_scans') is True
            and 'gcp.review.storage.selected_object_secret_indicators' in (named_checks(request))):
        from .collectors.gcp_selected_object_secret_indicators import selected_targets, KIND, Incomplete
        try:
            selected_targets({**content_options, '_content_secret_scan_kinds': [KIND]}, connector.get('scopes', []))
        except Incomplete:
            raise ValueError('Selected object inspection requires exact project, bucket, object and generation targets in the requested project scopes') from None
    image_options = connector.get('options', {})
    if (connector['provider'] == 'gcp' and content_options.get('content_secret_scans') is True
            and 'gcp.review.cloudbuild.stored_log_secret_indicators' in (named_checks(request))):
        from .collectors.gcp_cloudbuild_log_secret_indicators import selected_builds, KIND, Incomplete
        try:
            selected_builds({**content_options, '_content_secret_scan_kinds': [KIND]}, connector.get('scopes', []))
        except Incomplete:
            raise ValueError('Cloud Build log inspection requires bounded exact same-project Build names') from None
    if connector['provider'] == 'gcp':
        from .collectors.gcp_selected_task_routine_secret_indicators import SPECS as task_routine_specs, selected_targets as task_routine_targets, Incomplete as TaskRoutineIncomplete
        for kind, spec in task_routine_specs.items():
            if spec['option'] in content_options or (content_options.get('content_secret_scans') is True
                    and spec['check'] in (named_checks(request))):
                try:
                    task_routine_targets({**content_options, 'content_secret_scans': True,
                        '_content_secret_scan_kinds': [kind]}, connector.get('scopes', []), kind)
                except TaskRoutineIncomplete:
                    raise ValueError('Task/routine inspection requires 1-8 exact unique names in one matching project-ID scope') from None
    if (connector['provider'] == 'gcp' and content_options.get('content_secret_scans') is True
            and 'gcp.review.sourcerepo.selected_file_secret_indicators' in (named_checks(request))):
        from .collectors.gcp_sourcerepo_secret_indicators import selected_targets, KIND, Incomplete
        try:
            selected_targets({**content_options, '_content_secret_scan_kinds': [KIND]}, connector.get('scopes', []))
        except Incomplete:
            raise ValueError('Source Repository inspection requires one exact project, repository, commit and bounded file selection') from None
    if (connector['provider'] == 'gcp' and content_options.get('content_secret_scans') is True
            and 'gcp.review.clouddeploy.release_source_secret_indicators' in (named_checks(request))):
        from .collectors.gcp_clouddeploy_source_secret_indicators import selected_releases, KIND, Incomplete
        try:
            selected_releases({**content_options, '_content_secret_scan_kinds': [KIND]}, connector.get('scopes', []))
        except Incomplete:
            raise ValueError('Cloud Deploy source inspection requires bounded exact same-project Release names') from None
    if (connector['provider'] == 'gcp' and content_options.get('content_secret_scans') is True
            and 'gcp.review.cloudbuild.artifact_secret_indicators' in (named_checks(request))):
        from .collectors.gcp_cloudbuild_artifact_secret_indicators import selected_builds, KIND, Incomplete
        try:
            selected_builds({**content_options, '_content_secret_scan_kinds': [KIND]}, connector.get('scopes', []))
        except Incomplete:
            raise ValueError('Cloud Build artifact inspection requires bounded exact same-project Build names') from None
    if (connector['provider'] == 'gcp' and content_options.get('content_secret_scans') is True
            and 'gcp.review.appengine.deployment_source_secret_indicators' in (named_checks(request))):
        from .collectors.gcp_appengine_source_secret_indicators import selected_versions, KIND, Incomplete
        try:
            selected_versions({**content_options, '_content_secret_scan_kinds': [KIND]}, connector.get('scopes', []))
        except Incomplete:
            raise ValueError('App Engine source inspection requires bounded exact same-project Version names') from None
    if (connector['provider'] == 'gcp' and image_options.get('content_secret_scans') is True
            and 'gcp.review.artifact_image.content_secret_indicators' in (named_checks(request))):
        from .collectors.gcp_image_secret_indicators import normalize_selected
        image_scopes = connector.get('scopes', [])
        if not image_scopes or any(not scope.startswith('projects/') for scope in image_scopes):
            raise ValueError('selected image inspection requires explicit project scopes')
        if 'selected_cloudrun_services' in image_options:
            from .collectors.gcp_cloudrun_image_inspection import validate_selection
            validate_selection(image_options['selected_cloudrun_services'], image_scopes)
        if 'selected_artifact_images' in image_options or 'selected_cloudrun_services' not in image_options:
            from .gcp_image_selection_20261021 import OPTION, grouped_selections
            grouped_selections({**image_options, OPTION: image_options.get('selected_artifact_images')}, image_scopes)
    return copy.deepcopy(connector)


def _full_selection(provider, categories, selected):
    selected = list(selected) + [c for c in _registry() if c.provider == provider and c.id in EXPLICIT_CONTENT_CHECK_IDS]
    return set(categories) == set(CATEGORIES) and {c.id for c in selected} == {c.id for c in _registry() if c.provider == provider}


def collect_snapshot(request):
    from .content_scan_selection import named_checks, normalize_request
    request = normalize_request(request)
    connector = _request(request)
    collection_callback = request.get("_collection_callback")
    if collection_callback is not None:
        if not callable(collection_callback):
            raise TypeError("internal collection callback must be callable")
        connector.setdefault("options", {})["_collection_callback"] = collection_callback
    emit_progress(phase="collecting", provider=connector["provider"], completed=0, total=None, resources=0, dynamic_total=True)
    options = connector.get("options", {})
    if "snapshot" in options:
        snapshot = validate(options["snapshot"])
        if snapshot["provider"] != connector["provider"]:
            raise ValueError("connector/snapshot provider mismatch")
        requested = connector.get("scopes", [])
        if requested and requested != snapshot["scopes"]:
            raise ValueError("connector/snapshot scope mismatch")
        if collection_callback is not None:
            for collection in snapshot["collections"]:
                collection_callback(collection)
        emit_progress(phase="collecting", provider=connector["provider"], completed=len(snapshot["collections"]),
                      total=len(snapshot["collections"]), resources=sum(len(c["items"]) for c in snapshot["collections"]), dynamic_total=False)
        return snapshot
    if options.get("demo"):
        from .demo import demo_snapshot
        snapshot = demo_snapshot(connector["provider"])
        if collection_callback is not None:
            for collection in snapshot["collections"]:
                collection_callback(collection)
        emit_progress(phase="collecting", provider=connector["provider"], completed=len(snapshot["collections"]),
                      total=len(snapshot["collections"]), resources=sum(len(c["items"]) for c in snapshot["collections"]), dynamic_total=False)
        return snapshot
    from .collectors import collect_live
    requirements = plan_collection(request, _runtime_connector=connector)
    # Repository inventory is shared by ECR checks. Carry the selected native
    # predicate as an internal collector fact signal without adding a fake
    # inventory type to the public collection plan.
    if connector["provider"] == "aws":
        _, selected = _selection("aws", request.get("categories"), request.get("checks"), request.get("frameworks"), content_checks=request.get("content_checks"))
        from .collectors.aws_image_vulnerability_runtime_20261021 import issue_engine_grant as grant_aws_image_vulnerabilities
        grant_aws_image_vulnerabilities(connector.setdefault('options', {}), connector.get('scopes', []),
            [check.id for check in selected if check.id in (named_checks(request))])
        from .collectors.aws_ecr_public_image_runtime_20261021 import issue_engine_grant as grant_ecr_public_image
        grant_ecr_public_image(connector.setdefault('options', {}), connector.get('scopes', []),
            [check.id for check in selected if check.id in (named_checks(request))])
        from .collectors.aws_workload_image_secret_native_20261021 import issue_engine_grant as grant_workload_image_secrets
        grant_workload_image_secrets(connector.setdefault('options', {}), connector.get('scopes', []),
            [check.id for check in selected if check.id in (named_checks(request))])
        connector.setdefault("options", {})["_ecr_latest_scan_requested"] = any(
            check.id == "aws.c2b.ecr.latest_image_no_medium_plus_findings" for check in selected)
        connector.setdefault('options', {})['_ec2_clock_metric_requested'] = any(
            check.id == 'aws_ec2_instance_time_offset_monitored' for check in selected)
        connector.setdefault('options', {})['_ebs_optimization_facts_requested'] = any(
            check.id == 'aws.claude_a.ec2.instance_ebs_optimized' for check in selected)
        connector.setdefault('options', {})['_sqs_dead_letter_sources_requested'] = any(
            check.id == 'aws.cb.sqs.dead_letter_queue' for check in selected)
        usage_report_checks = {
            'aws.claude_a.iam.user_long_lived_keys_only_iam_sts',
            'aws.claude_a.iam.user_bedrock_access_not_stale',
            'aws.claude_a.iam.user_sagemaker_access_not_stale',
            'aws.claude_a.iam.role_bedrock_access_not_stale',
        }
        credential_report = any(check.kind == 'iam_credential_report' or
                                'iam_credential_report' in check.dependencies for check in selected)
        usage_report = any(check.id in usage_report_checks for check in selected)
        connector['options']['_iam_report_generation_requested'] = credential_report or usage_report
        connector['options']['_iam_credential_report_generation_requested'] = credential_report
        connector['options']['_iam_service_access_reports_requested'] = usage_report
        # Content inspection needs both the opt-in option and named check IDs.
        # Category/framework/all-check selection must never read application data.
        content_kinds = {
            'aws_cis_ec2_userdata_embedded_secrets': 'instance',
            'aws.review.codecommit.default_commit_secret_indicators': 'codecommit_repository',
            'aws.review.cloudwatch.sampled_log_secret_indicators': 'log_group',
            'aws.review.lambda.selected_environment_secret_indicators': 'lambda_selected_environment',
            'aws.review.configuration.selected_content_secret_indicators': 'configuration_selected_content',
            'aws.review.s3.selected_source_secret_indicators': 's3_selected_source_content',
            'aws.review.ecs.selected_environment_file_secret_indicators': 'ecs_selected_environment_file_content',
            'aws.review.workload.referenced_source_secret_indicators': 'workload_referenced_source_content',
            'aws.review.build_deployment.referenced_source_secret_indicators': 'build_deployment_referenced_source_content',
            'aws.review.lambda_function.package_content_secret_indicators': 'lambda_function',
            'aws.review.lambda_layer_version.package_content_secret_indicators': 'lambda_layer_version',
            'aws.review.ecr_repository.package_content_secret_indicators': 'ecr_repository',
        }
        named = set(named_checks(request))
        connector.setdefault('options', {})['_content_secret_scan_kinds'] = sorted({
            content_kinds[c.id] for c in selected if c.id in named and c.id in content_kinds})
        from .collectors.aws_codebuild_buildspec_runtime_20261020 import issue_engine_grant as grant_codebuild_inline, CHECK as CODEBUILD_INLINE_CHECK, KIND as CODEBUILD_INLINE_KIND
        if CODEBUILD_INLINE_CHECK in named:
            connector['options']['_content_secret_scan_kinds'].append(CODEBUILD_INLINE_KIND)
        grant_codebuild_inline(connector['options'], connector.get('scopes', []), [c.id for c in selected if c.id in named])
        from .collectors.aws_workload_command_runtime_20261020 import issue_engine_grant as grant_workload_commands, CHECK as WORKLOAD_COMMAND_CHECK, KIND as WORKLOAD_COMMAND_KIND
        if WORKLOAD_COMMAND_CHECK in named:
            connector['options']['_content_secret_scan_kinds'].append(WORKLOAD_COMMAND_KIND)
        grant_workload_commands(connector['options'], connector.get('scopes', []), [c.id for c in selected if c.id in named])
    if connector["provider"] == "gcp":
        _, selected = _selection("gcp", request.get("categories"), request.get("checks"), request.get("frameworks"), content_checks=request.get("content_checks"))
        content_kinds = {
            'gcp.review.dataflow.selected_package_referenced_source_secret_indicators': 'dataflow_selected_package_source',
            'gcp.review.cloudrun_job.declared_image_secret_indicators': 'cloudrun_job_declared_image',
            'gcp.review.developerconnect.selected_repository_file_secret_indicators': 'developerconnect_selected_file',
            'gcp.review.cloudrun_worker_pool.selected_revision_image_secret_indicators': 'cloudrun_worker_pool_selected_revision_image',
            'gcp.review.batch.selected_mounted_script_source_secret_indicators': 'batch_selected_mounted_script_source',
            'gcp.review.workbench.selected_referenced_source_secret_indicators_20261020': 'workbench_selected_referenced_source_20261020',
            'gcp.review.dataproc.selected_job_referenced_source_secret_indicators': 'dataproc_selected_job_source',
            'gcp.review.dataproc.selected_initialization_referenced_source_secret_indicators': 'dataproc_selected_initialization_source',
            'gcp.review.function.literal_environment_secret_indicators': 'function',
            'gcp.review.function.resolved_source_archive_secret_indicators': 'function_source_archive',
            'gcp.review.gke_workload.literal_configuration_secret_indicators': 'gke_workload_literal',
            'gcp.review.gke.selected_pod_image_secret_indicators': 'gke_selected_pod_image_secrets',
            'gcp.review.composer_environment.literal_configuration_secret_indicators': 'composer_environment',
            'gcp.review.workbench_instance.literal_configuration_secret_indicators': 'workbench_instance',
            'gcp.review.artifactregistry.selected_file_secret_indicators': 'artifact_selected_file',
            'gcp.review.dataform.selected_file_secret_indicators': 'dataform_selected_file',
            'gcp.review.composer.dag_source_secret_indicators': 'composer_dag_source',
            'gcp.review.cloudbuild.stored_log_secret_indicators': 'cloudbuild_log_source',
            'gcp.review.sourcerepo.selected_file_secret_indicators': 'source_repository_file',
            'gcp.review.cloudtasks.selected_payload_secret_indicators': 'cloudtasks_selected_task',
            'gcp.review.bigquery.selected_routine_secret_indicators': 'bigquery_selected_routine',
            'gcp.review.clouddeploy.release_source_secret_indicators': 'clouddeploy_release_source',
            'gcp.review.cloudbuild.artifact_secret_indicators': 'cloudbuild_artifact_source',
            'gcp.review.appengine.deployment_source_secret_indicators': 'appengine_deployment_source',
            'gcp.review.dataflow_job.literal_configuration_secret_indicators': 'dataflow_job',
            'gcp.review.batch_job.literal_configuration_secret_indicators': 'batch_job',
            'gcp.review.dataproc_cluster.literal_configuration_secret_indicators': 'dataproc_cluster',
            'gcp.review.dataproc_job.literal_configuration_secret_indicators': 'dataproc_job',
            'gcp.review.scheduler_job.literal_target_secret_indicators': 'scheduler_job',
            'gcp.review.app_engine_version.literal_environment_secret_indicators': 'app_engine_version_secret',
            'gcp.review.app_engine_flex.selected_version_image_secret_indicators': 'appengine_flex_selected_version_image_secrets',
            'gcp.review.workflow.deployed_source_secret_indicators': 'workflow_source',
            'gcp.review.artifact_image.content_secret_indicators': 'artifact_image',
            'gcp.review.storage.selected_object_secret_indicators': 'gcs_selected_object',
            'gcp.review.storage.selected_archive_secret_indicators': 'gcs_selected_archive',
            'gcp.review.logging.application_log_secret_indicators': 'log_secret_sample',
            'gcp.review.instance.literal_configuration_secret_indicators': 'instance',
            'gcp.review.instance_template.literal_configuration_secret_indicators': 'instance_template',
            'gcp.review.project.literal_configuration_secret_indicators': 'project',
            'gcp.review.cloudrun_service.literal_configuration_secret_indicators': 'cloudrun_service',
            'gcp.review.cloudrun_job.literal_configuration_secret_indicators': 'cloudrun_job',
            'gcp.review.cloudbuild_trigger.literal_configuration_secret_indicators': 'cloudbuild_trigger',
            'gcp.review.cloudbuild_build.literal_configuration_secret_indicators': 'cloudbuild_build',
        }
        named = set(named_checks(request))
        from .gcp_gke_image_selection_20261021 import SECRET_CHECK as GKE_IMAGE_SECRET_CHECK, VULN_CHECK as GKE_IMAGE_VULN_CHECK
        connector.setdefault('options', {})['_gke_image_named_checks'] = [cid for cid in named if cid in (GKE_IMAGE_SECRET_CHECK, GKE_IMAGE_VULN_CHECK)]
        from .gcp_appengine_flex_image_selection_20261021 import SECRET_CHECK as FLEX_SECRET_CHECK, VULN_CHECK as FLEX_VULN_CHECK
        connector.setdefault('options', {})['_appengine_flex_image_named_checks'] = [c for c in named if c in (FLEX_SECRET_CHECK, FLEX_VULN_CHECK)]
        connector.setdefault('options', {})['_content_secret_scan_kinds'] = sorted({
            content_kinds[c.id] for c in selected if c.id in named and c.id in content_kinds})
        from .collectors.gcp_dataproc_source_runtime_20261020 import CHECKS as DATAPROC_SOURCE_CHECKS, NAMED as DATAPROC_SOURCE_NAMED
        connector['options'][DATAPROC_SOURCE_NAMED] = [c.id for c in selected if c.id in named and c.id in DATAPROC_SOURCE_CHECKS]
        from .collectors.gcp_dataflow_batch_source_runtime_20261020 import issue_engine_grants as grant_selected_job_sources
        grant_selected_job_sources(connector['options'], connector.get('scopes', []), [c.id for c in selected if c.id in named])
        from .collectors.gcp_workbench_source_runtime_20261020 import issue_engine_grant as grant_workbench_source
        grant_workbench_source(connector['options'], connector.get('scopes', []), [c.id for c in selected if c.id in named])
        from .collectors.gcp_cloudrun_job_image_runtime_20261020 import issue_engine_grant as grant_cloudrun_job_images
        grant_cloudrun_job_images(connector['options'], connector.get('scopes', []), [c.id for c in selected if c.id in named])
        from .collectors.gcp_job_image_vulnerability_runtime_20261021 import issue_engine_grant as grant_job_image_vulnerabilities
        grant_job_image_vulnerabilities(connector['options'], connector.get('scopes', []),
            [c.id for c in selected if c.id in named])
        from .collectors.gcp_registry_trivy_runtime_20261021 import issue_engine_grant as grant_registry_cves
        grant_registry_cves(connector['options'], connector.get('scopes', []), [c.id for c in selected if c.id in named])
    if connector["provider"] == "k8s":
        from .collectors.k8s_selected_registry_image_20261021 import SECRET_CHECK as K8S_IMAGE_SECRET_CHECK, VULN_CHECK as K8S_IMAGE_VULN_CHECK
        connector.setdefault('options', {})['_registry_image_named_checks'] = [cid for cid in (named_checks(request)) if cid in (K8S_IMAGE_SECRET_CHECK, K8S_IMAGE_VULN_CHECK)]
        from .collectors.k8s_selected_flux_artifact_20261021 import CHECK as FLUX_CHECK
        connector.setdefault('options', {})['_flux_artifact_named_checks'] = [FLUX_CHECK] if FLUX_CHECK in (named_checks(request)) else []
        from .collectors.k8s_selected_metadata_runtime_20261020 import authorize as authorize_k8s_metadata
        authorize_k8s_metadata(connector.setdefault('options', {}), connector.get('scopes', []), named_checks(request))
        from .collectors.k8s_literal_secret_indicators import KIND as K8S_LITERAL_KIND, CHECK as K8S_LITERAL_CHECK
        from .collectors.k8s_selected_log_sample_secret_indicators import KIND as K8S_LOG_KIND, CHECK as K8S_LOG_CHECK
        from .collectors.k8s_selected_text_content import KIND as K8S_TEXT_KIND, CHECK as K8S_TEXT_CHECK
        connector.setdefault('options', {})['_content_secret_scan_kinds'] = [kind for cid, kind in (
            (K8S_LITERAL_CHECK, K8S_LITERAL_KIND), (K8S_LOG_CHECK, K8S_LOG_KIND), (K8S_TEXT_CHECK, K8S_TEXT_KIND)) if cid in (named_checks(request))]
    if connector["provider"] == "azure":
        _, selected = _selection("azure", request.get("categories"), request.get("checks"), request.get("frameworks"), content_checks=request.get("content_checks"))
        from .collectors.azure_app_settings_secret_indicators import KIND as AZURE_SETTINGS_KIND, CHECK as AZURE_SETTINGS_CHECK
        from .collectors.azure_acr_image_secret_indicators import KIND as AZURE_ACR_KIND, CHECK as AZURE_ACR_CHECK
        from .collectors.azure_selected_aks_image_20261021 import KIND as AKS_IMAGE_KIND, CHECK as AKS_IMAGE_CHECK, VULN_KIND as AKS_VULN_KIND, VULN_CHECK as AKS_VULN_CHECK
        from .collectors.azure_acr_image_vulnerabilities_20261021 import KIND as AZURE_ACR_VULN_KIND, CHECK as AZURE_ACR_VULN_CHECK
        from .collectors.azure_selected_configuration_secret_indicators import KIND as AZURE_CONFIG_KIND, CHECK as AZURE_CONFIG_CHECK
        from .collectors.azure_selected_storage_secret_indicators import KIND as STORAGE_KIND, CHECK as STORAGE_CHECK
        from .collectors.azure_flex_deployment_archives_20261021 import KIND as FLEX_KIND, CHECK as FLEX_CHECK
        from .collectors.azure_devops_selected_content_secret_indicators import KIND as DEVOPS_KIND, CHECK as DEVOPS_CHECK
        from .collectors.azure_selected_declaration_secret_indicators import PROFILES as DECLARATION_PROFILES
        from .collectors.azure_selected_log_sample_secret_indicators import PROFILES as LOG_SAMPLE_PROFILES
        from .collectors.azure_ml_selected_job_secret_indicators import KIND as ML_JOB_KIND, CHECK as ML_JOB_CHECK
        from .collectors.azure_databricks_notebook_secret_indicators import KIND as NOTEBOOK_KIND, CHECK as NOTEBOOK_CHECK
        from .collectors.azure_synapse_selected_notebook_secret_indicators import KIND as SYNAPSE_NOTEBOOK_KIND, CHECK as SYNAPSE_NOTEBOOK_CHECK
        from .collectors.azure_ml_selected_asset_secret_indicators import PROFILES as ML_ASSET_PROFILES
        azure_content_pairs = ((AZURE_SETTINGS_CHECK,AZURE_SETTINGS_KIND),(AZURE_ACR_CHECK,AZURE_ACR_KIND),(AKS_IMAGE_CHECK,AKS_IMAGE_KIND),(AZURE_CONFIG_CHECK,AZURE_CONFIG_KIND),(STORAGE_CHECK,STORAGE_KIND),(FLEX_CHECK,FLEX_KIND),(DEVOPS_CHECK,DEVOPS_KIND)) + tuple((p['check'],p['kind']) for p in DECLARATION_PROFILES.values()) + tuple((p['check'],p['kind']) for p in LOG_SAMPLE_PROFILES.values()) + ((ML_JOB_CHECK,ML_JOB_KIND),(NOTEBOOK_CHECK,NOTEBOOK_KIND),(SYNAPSE_NOTEBOOK_CHECK,SYNAPSE_NOTEBOOK_KIND)) + tuple((p['check'],p['kind']) for p in ML_ASSET_PROFILES.values())
        connector.setdefault('options', {})['_content_secret_scan_kinds'] = sorted(kind for cid,kind in azure_content_pairs if cid in (named_checks(request)))
        connector['options']['_azure_flex_named_checks']=[FLEX_CHECK] if FLEX_CHECK in (named_checks(request)) else []
        connector['options']['_azure_aks_image_named_checks'] = [cid for cid in (named_checks(request)) if cid in (AKS_IMAGE_CHECK, AKS_VULN_CHECK)]
        connector['options']['_image_vulnerability_scan_kinds'] = [AZURE_ACR_VULN_KIND] if (connector['options'].get('image_vulnerability_scans') is True and AZURE_ACR_VULN_CHECK in (named_checks(request))) else []
        from .collectors.azure_function_settings_declarations_20261020 import CHECKS as FUNCTION_SETTINGS_CHECKS
        connector.setdefault('options', {})['_azure_function_settings_checks'] = [cid for cid in (named_checks(request)) if cid in FUNCTION_SETTINGS_CHECKS]
        connector.setdefault('options', {})['_azure_app_service_runtime_checks'] = [c.id for c in selected if c.id == 'azure.review.app_service.runtime_support_declared' and c.id in (named_checks(request))]
        from .collectors.azure_function_package_integration_20261020 import issue_engine_grant as grant_package_source, KIND as PACKAGE_KIND
        grant_package_source(connector['options'], connector.get('scopes', []),
            [c.id for c in selected if c.id in (named_checks(request))])
        connector.setdefault("options", {})["_azure_database_native_requested"] = any(
            check.id in {"azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d",
                         "azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a",
                         "azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf"}
            for check in selected)
        connector.setdefault("options", {})["_azure_apim_diagnostics_checks"] = [
            check.id for check in selected if check.id in {
                "azure_api_management_app_http_logs_enabled_21c108d",
                "azure_api_management_app_http_logs_enabled_9b3b56e",
                "azure_api_management_app_http_logs_enabled_9ef06db"}]
    if connector['provider'] == 'azure':
        from .collectors.azure_function_package_integration_20261020 import GRANT as PACKAGE_GRANT, collect_pipeline as collect_package_pipeline
        if PACKAGE_GRANT in connector.get('options', {}):
            return collect_package_pipeline(connector, requirements, request)
    from .collection_events import scope_plan_callback
    with scope_plan_callback(request.get('_scope_plan_callback')):
        collected = collect_live(connector, requirements)
    snapshot = validate(collected, metadata_entry=("collection_plan", {"mode": "collect_all" if options.get("collect_all") else "explicit_inventories" if "inventories" in options else "full_default" if _full_selection(connector["provider"], *_selection(connector["provider"], request.get("categories"), request.get("checks"), request.get("frameworks"), content_checks=request.get("content_checks"))) else "dependencies", "requirements": requirements,
        "categories": request.get("categories") or list(CATEGORIES), "checks": request.get("checks") or "all_selected", "frameworks": request.get("frameworks") or "all_selected",
        "content_checks": sorted(set(named_checks(request)) & _known_content_checks(connector["provider"]))}))
    if collection_callback is not None:
        # Finalizers and reviewed aliases may add or revise envelopes after their scheduler
        # emitted earlier settlements; the checkpoint deduplicates unchanged content. It gets
        # the collector's verified envelopes; the returned validated copy is independent.
        for collection in collected["collections"]:
            collection_callback(collection)
    emit_progress(phase="collecting", provider=connector["provider"], completed=len(snapshot["collections"]),
                  total=len(snapshot["collections"]), resources=sum(len(c["items"]) for c in snapshot["collections"]), dynamic_total=False)
    return snapshot


def _analysis_selection(provider, categories, checks, frameworks):
    from .analysis import ANALYSIS_CHECKS
    frameworks = _expand_frameworks(frameworks) if frameworks else None
    return [c for c in ANALYSIS_CHECKS if c["category"] in categories and c.get("provider") in (provider, "all")
        and (not checks or c["id"] in checks) and (not frameworks or set(c["frameworks"]).intersection(frameworks))]


# Bulk log/audit event streams. No registered check, analysis, graph or privesc rule reads them, and on
# large tenants they dominate the snapshot (Azure: ~75% of items and peak memory). They are collected
# only on explicit request (options.inventories, or collect_all) or when a selected check declares them.
BULK_STREAM_TYPES = {
    "azure": frozenset({"azure_selected_function_settings_declaration", "azure_ml_selected_environment_conda", "azure_ml_selected_code_file", "azure_databricks_selected_notebook", "azure_ml_selected_command_job", "azure_selected_workspace_log_sample", "azure_selected_application_trace_sample", "azure_app_configuration_selected_values", "azure_data_factory_selected_declarations", "azure_synapse_selected_pipelines", "azure_storage_selected_source", "azure_devops_selected_content", "azure_configuration_selected_content", "acr_selected_image", "acr_selected_image_vulnerabilities", "azure_selected_aks_pod_image", "azure_selected_aks_pod_image_vulnerabilities", "app_service_selected_settings", "activity_log", "directory_audit", "sign_in_log", "directory_sign_in"}),
    "gcp": frozenset({"dataflow_selected_package_source", "batch_selected_mounted_script_source", "workbench_selected_referenced_source_20261020", "dataproc_selected_job_source", "dataproc_selected_initialization_source", "activity", "log_entry", "audit_log_entry", "log_secret_sample", "app_engine_version_secret", "workflow_source", "gke_workload_literal", "gke_selected_pod_image_secrets", "gke_selected_pod_image_vulnerabilities", "function_source_archive", "artifact_selected_file", "composer_dag_source", "cloudbuild_log_source", "source_repository_file", "clouddeploy_release_source", "cloudbuild_artifact_source", "appengine_deployment_source", "cloudtasks_selected_task", "bigquery_selected_routine", "gcs_selected_object", "gcs_selected_archive", "dataform_selected_file", "dataflow_job", "batch_job", "dataproc_job"}),
    "aws": frozenset({"ecs_selected_environment_file_content", "workload_referenced_source_content", "build_deployment_referenced_source_content", "s3_selected_source_content", "lambda_selected_environment", "cloudtrail_event", "cloudtrail_lookup_event"}),
    "k8s": frozenset({"event", "audit_event", "k8s_selected_literals", "k8s_selected_log_samples", "k8s_selected_metadata", "k8s_selected_text_content", "k8s_selected_registry_image_secrets", "k8s_selected_registry_image_vulnerabilities", "k8s_selected_flux_artifact"}),
}
BULK_STREAM_TYPES['aws'] = BULK_STREAM_TYPES['aws'] | {'codebuild_selected_inline_buildspec'}
BULK_STREAM_TYPES['aws'] = BULK_STREAM_TYPES['aws'] | {'aws_selected_workload_command_literals'}
BULK_STREAM_TYPES['azure'] = BULK_STREAM_TYPES['azure'] | {'azure_function_package_portable_20261020'}
BULK_STREAM_TYPES['gcp'] = BULK_STREAM_TYPES['gcp'] | {'cloud_run_selected_job_image_vulnerabilities', 'artifact_selected_image_vulnerabilities', 'cloudrun_worker_pool_selected_revision_image', 'developerconnect_selected_file', 'appengine_flex_selected_version_image_secrets', 'appengine_flex_selected_version_image_vulnerabilities'}


def _selected_graph_categories(categories, native, analyzed, explicit_categories, checks, frameworks):
    """Filtered requests collect graphs only for categories actually selected."""
    selected = set(explicit_categories or categories)
    if not explicit_categories and (checks or frameworks):
        selected = {check.category for check in native} | {check["category"] for check in analyzed}
    return selected & {"network", "iam_graph"}


def plan_collection(request, *, _runtime_connector=None):
    from .content_scan_selection import named_checks, normalize_request
    request = normalize_request(request)
    connector = _request(request)
    provider = connector["provider"]
    categories, checks = _selection(provider, request.get("categories"), request.get("checks"), request.get("frameworks"), content_checks=request.get("content_checks"))
    from .collectors import supported_types
    from .analysis import REQUIRED_TYPES, privesc_required_types
    from .checks.native_only import automated_inventory_types
    available = set(automated_inventory_types(provider, supported_types(provider)))
    required = {kind for check in checks for kind in getattr(check, "dependencies", [check.kind])}
    if provider == "k8s" and _runtime_connector is not None:
        from .collectors.k8s_legacy_psp_planner_20261020 import select as select_legacy_psp
        if _runtime_connector.get('provider') != provider:
            raise ValueError('runtime planner connector provider mismatch')
        select_legacy_psp(_runtime_connector, checks)
    # The signed PCI bucket read-grant predicate needs ACL closure only when
    # this exact check is selected; other bucket-only checks stay cheap.
    if provider == "gcp" and any(c.id == "gcp_pci_bucket_157fb0c69361" for c in checks):
        required.update({"bucket_acl", "object_acl"})
    # Extra facts required by cross-resource native predicates.
    if any(c.id == "k8s.network.namespace_policy_inventory" for c in checks):
        required.add("networkpolicy")
    # Read key metadata opportunistically for a definite configured-CMK failure.
    # It is not a check dependency: an unavailable key read must not suppress
    # independent contradictions already observed on the recovery vault.
    if provider == "azure" and any(c.id == "azure.gap.recovery_service_vault_encrypted_with_cmk" for c in checks):
        required.add("vault_key")
    if provider == "azure" and any(c.id == "azure_cosmos_account_10_2_1_1_13_5c115b0" for c in checks):
        required.add("diagnostic_category")
    if provider == "azure" and any(c.id == "azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9" for c in checks):
        required.add("sql_database_inventory")
    analysis_selected = _analysis_selection(provider, categories, request.get("checks"), request.get("frameworks"))
    graph_categories = _selected_graph_categories(categories, checks, analysis_selected,
        request.get("categories"), request.get("checks"), request.get("frameworks"))
    for category in {c["category"] for c in analysis_selected} | graph_categories:
        required.update(REQUIRED_TYPES.get(provider, {}).get(category, []))
    if _privesc_selected(provider, categories, request.get("checks"), request.get("frameworks")) is not None:
        required.update(privesc_required_types(provider))
    collect_all = connector.get("options", {}).get("collect_all", False)
    if type(collect_all) is not bool:
        raise ValueError("collect_all must be a boolean")
    if collect_all and "inventories" in connector.get("options", {}):
        raise ValueError("collect_all and inventories are mutually exclusive")
    default_full = _full_selection(provider, categories, checks)
    if collect_all:
        return sorted(available)
    inventories = connector.get("options", {}).get("inventories")
    if inventories is not None:
        if not isinstance(inventories, list) or any(kind not in available for kind in inventories):
            raise ValueError("inventories must be supported resource types")
        required = set(inventories)
    if default_full and inventories is None:
        # The full default plan keeps inventories used by graphs, cards and resource views.
        # Bulk event streams and the AWS-owned managed policy library are opt-in
        # when no selected check or analysis consumer declares them.
        named = set(named_checks(request))
        explicit_required = {kind for check in checks if check.id in named
            for kind in getattr(check, "dependencies", [check.kind])}
        return sorted(available - (BULK_STREAM_TYPES.get(provider, frozenset()) - explicit_required)
                      - ({"iam_managed_policy"} if provider == "aws" and "iam_managed_policy" not in required else set()))
    from .collectors.bulk_evidence import declared_types, expand_native_requirements
    required = expand_native_requirements(provider, required)
    # Explicit check selections can request declared evidence contracts; the
    # dispatcher records unavailable projections as not_collected, never empty.
    if request.get('checks') or request.get('frameworks') or request.get('content_checks'):
        available |= declared_types(provider)
    return sorted(required & available)


def _index(snapshot, inventory):
    index = defaultdict(list)
    # resources() sorts public wrappers by native identity. Dependency rows
    # must instead preserve the authoritative collection order: predicates
    # verify that complete_items() matches the collection's exact items.
    # Keep wrappers and duplicate handling unchanged; only their index order
    # changes. Missing/conflicting rows still fail the inventory guards.
    by_identity = {(row['type'], row['scope'], row['native_id']): row for row in inventory}
    ordered = []
    seen = set()
    for collection in snapshot['collections']:
        for item in collection['items']:
            key = (collection['type'], collection['scope'],
                   resource_id(snapshot['provider'], collection['type'], collection['scope'], item))
            if key not in seen:
                seen.add(key)
                row = by_identity.get(key)
                if row is not None:
                    ordered.append(row)
    # Preserve the old stable-sort fallback for a caller supplying extra wrappers.
    ordered.extend(row for row in inventory
                   if (row['type'], row['scope'], row['native_id']) not in seen)
    for resource in ordered:
        index[resource["type"]].append(resource)
    collections = defaultdict(list)
    for collection in snapshot["collections"]:
        # A completely enumerated empty inventory is still present evidence.
        # Keep its typed resource list so scope predicates can distinguish it
        # from an inventory that was never collected. Envelope status remains
        # authoritative for denied, partial and foreign-scope facts.
        index.setdefault(collection["type"], [])
        collections[collection["type"]].append(collection)
    index["collections"] = dict(collections)
    return dict(index)


def _finding(check, provider, scope, rid, service, status, evidence, frameworks=None):
    from .finding_types import type_for
    from .finding_priority import effective_priority
    from .check_services import service_for_check
    service = service_for_check(check.id, provider, check.kind, service)
    current = {"id": digest([provider, scope, rid, check.id]), "category": check.category, "check_id": check.id,
        "finding_type": type_for(check.id),
        "title": check.title, "provider": provider, "service": service, "resource_id": rid, "scope": scope,
        "severity": effective_priority(check.id, check.severity), "status": status, "frameworks": list(check.frameworks if frameworks is None else frameworks),
        "evidence": evidence, "remediation": check.remediation}
    if provider == "aws":
        from .checks.aws_finding_priority import contextual_severity as aws_contextual_severity
        from .checks.aws_compute_storage_priority import contextual_severity as compute_contextual_severity
        current["severity"] = compute_contextual_severity(current, aws_contextual_severity(current, current["severity"]))
    if provider == "azure":
        from .checks.azure_finding_priority import contextual_severity
        current["severity"] = contextual_severity(current, current["severity"])
    return current


def _finding_factory(check, provider, frameworks=None):
    """Reuse immutable check metadata within one evaluation of that check.

    Preserve per-row service fallback, identifiers, framework-list ownership,
    evidence and contextual priority. Commit cached values only after a row
    completes; no native facts or errors are retained in the factory.
    """
    missing = object()
    finding_type = baseline = missing
    functions = aws_functions = azure_function = None
    services = {}

    def emit(scope, rid, service, status, evidence):
        nonlocal finding_type, baseline, functions, aws_functions, azure_function
        if functions is None:
            from .finding_types import type_for
            from .finding_priority import effective_priority
            from .check_services import service_for_check
            functions = (type_for, effective_priority, service_for_check)
        type_for, effective_priority, service_for_check = functions
        source_service = service
        cache_service = type(source_service) is str
        if cache_service and source_service in services:
            service = services[source_service]
        else:
            service = service_for_check(check.id, provider, check.kind, source_service)
        # Keep first-call failures in the predecessor order: service, ID,
        # type, baseline priority, framework copy, contextual priority.
        ident = digest([provider, scope, rid, check.id])
        row_type = type_for(check.id) if finding_type is missing else finding_type
        row_baseline = effective_priority(check.id, check.severity) if baseline is missing else baseline
        current = {"id": ident, "category": check.category, "check_id": check.id,
            "finding_type": row_type,
            "title": check.title, "provider": provider, "service": service, "resource_id": rid, "scope": scope,
            "severity": row_baseline, "status": status, "frameworks": list(check.frameworks if frameworks is None else frameworks),
            "evidence": evidence, "remediation": check.remediation}
        if provider == "aws":
            if aws_functions is None:
                from .checks.aws_finding_priority import contextual_severity as aws_priority
                from .checks.aws_compute_storage_priority import contextual_severity as compute_priority
                aws_functions = (aws_priority, compute_priority)
            aws_priority, compute_priority = aws_functions
            current["severity"] = compute_priority(current, aws_priority(current, current["severity"]))
        if provider == "azure":
            if azure_function is None:
                from .checks.azure_finding_priority import contextual_severity
                azure_function = contextual_severity
            current["severity"] = azure_function(current, current["severity"])
        finding_type, baseline = row_type, row_baseline
        if cache_service and source_service not in services and len(services) < 64:
            services[source_service] = service
        return current

    return emit


def _unknown_coverage_reason(findings=(), *, collection_status=None):
    """Describe evidence gaps without copying SDK messages or native payloads."""
    states = {"denied": "Read access to required inventory was denied.",
              "malformed": "Required inventory response was malformed.",
              "timeout": "Required inventory read timed out.",
              "partial": "Required inventory collection is partial; conclusions need the missing evidence.",
              "not_collected": "Required inventory was not collected.",
              "unknown": "Required inventory could not be collected conclusively."}
    if collection_status in states:
        return states[collection_status]
    import re
    reasons = []
    for finding in findings:
        if finding.get("status") not in {"UNKNOWN", "DENIED"}:
            continue
        evidence = finding.get("evidence", {})
        reason = evidence.get("reason") if isinstance(evidence, dict) else None
        if not isinstance(reason, str):
            continue
        field = re.fullmatch(r"missing fact: ([A-Za-z_][A-Za-z0-9_.]{0,120})", reason)
        lower = reason.lower()
        if field:
            safe = "Missing collected field: " + field[1] + "."
        elif "user inherited from uninspected image metadata" == reason:
            safe = "Container user is inherited from image metadata that was not inspected."
        elif "denied" in lower or finding.get("status") == "DENIED":
            safe = "A required metadata read was denied."
        elif "dependency" in lower or "required scoped inventory" in lower or "incomplete" in lower:
            safe = "Required dependency inventory is missing or incomplete."
        elif "applicability" in lower:
            safe = "Check applicability is unresolved because required evidence is unavailable."
        elif "window" in lower or "activity" in lower or "observation" in lower:
            safe = "The required observation window lacks conclusive evidence."
        elif "malformed" in lower or "invalid" in lower:
            safe = "Required native facts are malformed or invalid."
        elif lower.startswith(("unknown ", "unrecognized ", "unsupported ")):
            safe = "The selected check cannot interpret a provider setting or version."
        elif "missing" in lower or "unavailable" in lower or "not collected" in lower:
            safe = "Required native facts are missing or unavailable."
        else:
            safe = "No conclusive evidence was available for this selected check."
        if safe not in reasons:
            reasons.append(safe)
        if len(reasons) == 3:
            break
    return " ".join(reasons) or "No conclusive evidence was available for this selected check."


def _safe_collection_error_code(collection):
    """Known machine error identifiers remain evidence; arbitrary text is omitted."""
    error = collection.get("error", {})
    code = error.get("code") if isinstance(error, dict) else None
    known = {"demo_permission_denied", "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "Forbidden", "Unauthorized",
             "PermissionDenied", "permission_denied", "PERMISSION_DENIED", "401", "403", "read_timeout",
             "resource_limit", "page_limit", "scope_limit", "collection_cancelled", "malformed_response",
             "not_requested", "unsupported_inventory", "api_unavailable", "SERVICE_DISABLED", "NOT_FOUND"}
    return code if isinstance(code, str) and code in known else None


def _unsupported_aws_region(snapshot, collection):
    """Recognize the collector's SDK-backed proof that a service has no regional endpoint."""
    return (snapshot.get("provider") == "aws"
        and collection.get("scope") in snapshot.get("scopes", ())
        and collection.get("status") == "not_collected"
        and collection.get("items") == []
        and isinstance(collection.get("error"), dict)
        and collection["error"].get("code") == "unsupported_region_service")


def _unsupported_aws_region_evidence(collection):
    return {"reason": "service is unavailable in this AWS Region",
        "region": collection["scope"].rsplit("/", 1)[-1],
        "collection_status": collection["status"],
        "semantics": "Regional service applicability, not a resource security pass."}


_AWS_MANAGEMENT_ACCOUNT_ONLY_CHECKS = frozenset({
    "aws.claude_a.guardduty.prowler_delegated_admin_region",
    "aws.claude_a.securityhub.prowler_delegated_admin_region",
    "aws.claude_a.iam.root_credentials_management",
    "aws.claude_a.organizations.ai_services_opt_out",
    "aws.claude_a.organizations.scp_restricts_regions",
    "aws.claude_a.organizations.tag_policy_attached",
    "aws_cis_organizations_policy_management_delegated",
})


def _aws_management_account_only_evidence(snapshot, check_id, scope):
    """Use a collected Organizations identity to exclude management-only API checks."""
    import re
    if snapshot.get("provider") != "aws" or check_id not in _AWS_MANAGEMENT_ACCOUNT_ONLY_CHECKS:
        return None
    account = scope.split("/", 1)[0]
    if not re.fullmatch(r"[0-9]{12}", account):
        return None
    matches = [collection for collection in snapshot["collections"]
        if collection.get("type") == "aws_account_configuration"
        and collection.get("scope") == account + "/global"
        and collection.get("status") == "collected"
        and len(collection.get("items", [])) == 1]
    if len(matches) != 1:
        return None
    item = matches[0]["items"][0]
    if not isinstance(item, dict):
        return None
    org = item.get("Organization")
    if (item.get("AccountId") != account or not isinstance(org, dict)
            or org.get("collection_status") != "collected"
            or not isinstance(org.get("OrganizationId"), str)
            or not org["OrganizationId"].startswith("o-")
            or not isinstance(org.get("MasterAccountId"), str)
            or not re.fullmatch(r"[0-9]{12}", org["MasterAccountId"])):
        return None
    if org["MasterAccountId"] == account:
        return None
    return {"reason": "organization management account differs from audited account",
        "audited_account": account, "management_account": org["MasterAccountId"],
        "organization_id": org["OrganizationId"]}


def _retired_collection_evidence(provider, snapshot, collection):
    """Interpret a no-call marker only for a reviewed exact kind and clock."""
    from datetime import datetime
    from .aws_service_lifecycle import RETIRED_SERVICES, retirement_state

    error = collection.get("error", {})
    if provider != "aws" or not isinstance(error, dict) or error.get("code") != "retired_service":
        return None
    kind = collection.get("type")
    entry = next(((service, value) for service, value in RETIRED_SERVICES.items()
        if collection.get("service") == service and kind in value["applies_to_service_kinds"]), None)
    if entry is None:
        return None
    service, reviewed = entry
    stamp = snapshot.get("created_at")
    try:
        observed = datetime.fromisoformat(stamp.replace("Z", "+00:00")) if isinstance(stamp, str) else None
    except ValueError:
        observed = None
    state = retirement_state(kind, observed)
    evidence = {"reason": f"{reviewed['name']} is in full shutdown; current inventory is not applicable.",
        "service": service, "end_of_support": reviewed["end_of_support"].isoformat(),
        "no_access_after": reviewed["no_access_after"].isoformat(), "source": reviewed["primary_url"],
        "collection_status": collection.get("status"), "semantics": "Service lifecycle coverage, not a resource security pass."}
    if state != "retired" or collection.get("status") != "empty" or collection.get("items"):
        return "unknown", {**evidence, "reason": "Retired-service marker conflicts with collection status or observation date; applicability is unknown.", "lifecycle_state": state}
    return "retired", evidence


# Reviewed PSP-object predicates only. A later scope or enforcement check must opt in
# through a separate source review, even if it uses the same collection kind.
_PSP_RESOURCE_CHECK_IDS = frozenset({
    "k8s.ports.podsecuritypolicy.pod_security_policy_container_privilege_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_hostpid_sharing_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_hostipc_sharing_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_host_network_access_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_container_privilege_escalation_disabled",
    "k8s.ports.podsecuritypolicy.pod_security_policy_immutable_container_filesystem",
    "k8s.ports.podsecuritypolicy.pod_security_policy_non_root_container",
    "k8s.claude.podsecuritypolicy.allowed_host_path_restricted",
    "k8s.claude.podsecuritypolicy.default_seccomp_profile",
    "k8s.claude.podsecuritypolicy.security_services_hardening",
})


def _psp_resource_absence_evidence(provider, snapshot, collection):
    """Recognize only the native, same-cluster proof that PSP objects cannot exist."""
    if provider != "k8s" or collection.get("type") != "podsecuritypolicy":
        return None
    error, marker = collection.get("error"), collection.get("applicability")
    if (collection.get("scope") not in snapshot.get("scopes", ())
            or collection.get("service") != "kubernetes"
            or collection.get("status") != "not_collected"
            or collection.get("coverage_status") != "not_applicable"
            or collection.get("items") != [] or not isinstance(error, dict)
            or error.get("kind") != "not_applicable"
            or error.get("code") != "pod_security_policy_api_absent"
            or not isinstance(marker, dict)
            or marker.get("observed_resource_absent") != "policy/v1beta1/podsecuritypolicies"
            or marker.get("source") != "GET /apis and GET /version"):
        return None
    cluster = snapshot.get("metadata", {}).get("cluster_id")
    if not isinstance(cluster, str) or not cluster or len(cluster) > 256:
        return None
    discovery = [row for row in snapshot["collections"]
        if row.get("type") == "api_discovery" and row.get("scope") == collection["scope"]]
    if (len(discovery) != 1 or discovery[0].get("service") != "kubernetes"
            or discovery[0].get("status") != "collected"
            or discovery[0].get("error") or len(discovery[0].get("items", [])) != 1):
        return None
    item = discovery[0]["items"][0]
    provenance = item.get("provenance")
    if (item.get("id") != "k8s://" + quote(cluster, safe="") + "/api-discovery"
            or not isinstance(provenance, dict)
            or provenance.get("cluster_id") != cluster
            or provenance.get("source") != "GET /apis"
            or item.get("_coverage")
            or item.get("podSecurityPolicyAdvertised") is not False):
        return None
    server_version = item.get("serverVersion")
    version = server_version.get("gitVersion") if isinstance(server_version, dict) else None
    if (not isinstance(version, str) or len(version) > 128
            or marker.get("kubernetes_version") != version):
        return None
    match = re.fullmatch(r"v?([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})([-+][0-9A-Za-z.\-]{1,96})?", version)
    if not match or tuple(int(part) for part in match.groups()[:3]) < (1, 25, 0):
        return None
    suffix = match.group(4) or ""
    # A hyphen may be a vendor build or a prerelease; accept only recognized
    # release build labels. Unknown labels cannot prove a stable server.
    if suffix.startswith("-") and not re.fullmatch(
            r"-(?:gke[.-][0-9]+|(?:eks|aks)[.-][0-9a-f]+|k3s[0-9]+|rke2r[0-9]+)", suffix):
        return None
    return {"reason": "PodSecurityPolicy resource API removed on observed Kubernetes version; legacy PSP resource check is not applicable.",
        "kubernetes_version": version, "observed_resource_absent": "policy/v1beta1/podsecuritypolicies",
        "source": "GET /apis and GET /version", "collection_status": collection["status"],
        "semantics": "Legacy PSP resource applicability only; no secure admission or enforcement conclusion."}


AGGREGATED_STATUSES = ("NOT_APPLICABLE", "EMPTY")
AGGREGATE_SCOPE_CAP = 500
AGGREGATE_SAMPLE = 5


class _FindingAggregator:
    """Per-check counts for NOT_APPLICABLE / EMPTY rows (they carry no security conclusion per resource)."""

    def __init__(self, enabled):
        self.enabled, self.rows = enabled, {}

    def __call__(self, findings):
        if not self.enabled:
            return findings
        kept = []
        for finding in findings:
            if finding["status"] not in AGGREGATED_STATUSES:
                kept.append(finding)
                continue
            key = (finding["category"], finding["check_id"], finding["status"])
            row = self.rows.get(key)
            if row is None:
                row = self.rows[key] = {"category": finding["category"], "check_id": finding["check_id"], "title": finding.get("title"),
                    "provider": finding["provider"], "service": finding.get("service"), "severity": finding.get("severity"),
                    "status": finding["status"], "frameworks": list(finding.get("frameworks", [])), "count": 0, "scopes": {},
                    "sample_resource_ids": []}
            row["count"] += 1
            # A cross-scope inventory row (see _dedupe_cross_scope) still reports every scope it covers.
            merged_scopes = finding["evidence"].get("scopes") if str(finding.get("resource_id", "")).startswith("inventory:") and isinstance(finding.get("evidence"), dict) else None
            for scope in merged_scopes if isinstance(merged_scopes, list) else [finding.get("scope", "unknown")]:
                if scope in row["scopes"] or len(row["scopes"]) < AGGREGATE_SCOPE_CAP:
                    row["scopes"][scope] = row["scopes"].get(scope, 0) + 1
                else:
                    row["scopes_truncated"] = True
            if len(row["sample_resource_ids"]) < AGGREGATE_SAMPLE:
                row["sample_resource_ids"].append(finding["resource_id"])
        return kept

    def result(self):
        return [self.rows[key] for key in sorted(self.rows)]


def _arn_region(arn):
    parts = arn.split(":", 5)
    return parts[3] if len(parts) > 3 else ""


def _common_scope(provider, scopes):
    if len(scopes) == 1:
        return scopes[0]
    import re
    accounts = {scope.split("/", 1)[0] for scope in scopes}
    if provider == "aws" and len(accounts) == 1 and re.fullmatch(r"[0-9]{12}", next(iter(accounts))):
        return next(iter(accounts))
    return "selected_scopes"


def _dedupe_cross_scope(findings, native_ids, provider):
    """One finding per (check, global resource) and per (provider, check) EMPTY inventory row.

    A resource whose native id is an ARN is globally unique; when several regional collections return
    it (e.g. a multi-region CloudTrail trail listed by every region) and every copy reached the same
    status, a single finding is kept (the home-region copy when the ARN names a region) with the
    scopes listed in evidence. The home-region copy is also kept alone when every other copy is
    NOT_APPLICABLE (a home-region-only predicate evaluated on shadow copies). Other status differences
    stay separate, and resources without an ARN (per-region settings such as EBS default encryption or
    registry scanning) are never merged. Inventory rows of one check (EMPTY, or UNKNOWN when the
    collection was not collected) with the same status and evidence collapse to one row whose evidence
    lists every scope; coverage stays per scope."""
    groups = defaultdict(list)
    for position, finding in enumerate(findings):
        native = native_ids.get(finding["resource_id"])
        if isinstance(native, str) and native.startswith("arn:"):
            groups[("arn", native)].append(position)
        elif finding["resource_id"].startswith("inventory:") and finding["status"] in ("EMPTY", "UNKNOWN"):
            shape = json.dumps(finding.get("evidence"), sort_keys=True, default=str)
            groups[("inventory", (finding["resource_id"], finding["status"], shape))].append(position)
    replaced, dropped = {}, set()
    for (kind, key), members in groups.items():
        if len(members) < 2:
            continue
        rows = [findings[position] for position in members]
        scopes = list(dict.fromkeys(row["scope"] for row in rows))
        if kind == "arn":
            region = _arn_region(key)
            home = [row for row in rows if region and row["scope"].rsplit("/", 1)[-1] == region]
            if len({row["status"] for row in rows}) == 1:
                note = "Same ARN returned by several scoped collections; reported once."
            elif len(home) == 1 and all(row["status"] == "NOT_APPLICABLE" for row in rows if row is not home[0]):
                note = "Same ARN returned by several scoped collections; the home-region result is reported and NOT_APPLICABLE shadow copies are folded."
            else:
                continue
            primary = home[0] if home else rows[0]
            merged = dict(primary, evidence=dict(primary["evidence"], observed_in_scopes=scopes, deduplication=note))
        else:
            first = rows[0]
            scope = _common_scope(provider, scopes)
            merged = dict(first, id=digest([provider, scope, first["resource_id"], first["check_id"]]), scope=scope,
                evidence=dict(first["evidence"], scopes=scopes, scope_count=len(scopes)))
        replaced[members[0]] = merged
        dropped.update(members[1:])
    if not replaced:
        return findings
    return [replaced.get(position, finding) for position, finding in enumerate(findings) if position not in dropped]


def _scope_check_scopes(snapshot, check):
    """Explicit tenant questions run once on their verified native tenant capture."""
    import re
    selected = snapshot["scopes"] or ["unknown"]
    callback, seen, tenant_question, account_question = check.evaluate, set(), False, False
    tenant_anchor_kind = check.kind
    for _ in range(8):
        if callback is None or id(callback) in seen:
            break
        seen.add(id(callback))
        if getattr(callback, "evaluation_scope", None) == "aws_account":
            account_question = True
            break
        if getattr(callback, "evaluation_scope", None) == "tenant":
            tenant_question = True
            tenant_anchor_kind = getattr(callback, "evaluation_scope_kind", check.kind)
            break
        callback = getattr(callback, "__wrapped__", None)
    if snapshot.get("provider") == "aws" and not account_question:
        from .check_scope import evaluation_scope
        account_question = evaluation_scope(check) == "aws_account"
    if snapshot.get("provider") == "aws" and account_question:
        accounts = sorted({scope.split("/", 1)[0] for scope in selected
            if isinstance(scope, str) and re.fullmatch(r"[0-9]{12}/(?:global|[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)", scope)})
        return [account + "/global" for account in accounts] or selected
    if snapshot.get("provider") != "azure" or not tenant_question:
        return selected
    metadata = snapshot.get("metadata", {})
    tenant = metadata.get("tenant_id")
    if (metadata.get("tenant_verified") is not True or not isinstance(tenant, str)
            or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", tenant, re.I)):
        return selected
    bindings = metadata.get("subscription_tenants", {})
    if not isinstance(bindings, dict) or not any(isinstance(bound, str) and bound.casefold() == tenant.casefold()
            and scope.casefold() in {str(s).casefold() for s in selected}
            for scope, bound in bindings.items() if isinstance(scope, str)):
        return selected
    tenant_scope = "/tenants/" + tenant.casefold()
    for collection in snapshot["collections"]:
        if collection.get("type") != tenant_anchor_kind or str(collection.get("scope", "")).casefold() != tenant_scope:
            continue
        proof = collection.get("_provenance", {})
        if (isinstance(proof, dict) and proof.get("tenant_verified") is True and proof.get("read_only") is True
                and isinstance(proof.get("tenant_id"), str) and proof["tenant_id"].casefold() == tenant.casefold()
                and all(isinstance(metadata.get(field), str) and metadata[field]
                        and proof.get(field) == metadata[field] for field in ("credential_context_id", "customer_context_id"))):
            return [tenant_scope]
    return selected


def _azure_tenant_group_collection_authorized(scope, metadata, collection):
    """Expose only this scan's exact tenant-child native group inventory."""
    import re
    guid = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
    if (collection.get("type") != "conditional_access_group_membership"
            or collection.get("service") != "Microsoft.Graph"
            or not isinstance(scope, str) or not re.fullmatch("/tenants/" + guid, scope, re.I)
            or not isinstance(metadata, dict) or metadata.get("tenant_verified") is not True):
        return False
    tenant = scope.removeprefix("/tenants/").casefold()
    if (str(metadata.get("tenant_id", "")).casefold() != tenant
            or not re.fullmatch(re.escape(scope) + "/groups/" + guid,
                                str(collection.get("scope", "")), re.I)):
        return False
    expected = {key: metadata.get(key) for key in ("credential_context_id", "customer_context_id")}
    if any(not isinstance(value, str) or not value for value in expected.values()):
        return False
    def bound(proof, *, item=False):
        return (isinstance(proof, dict) and proof.get("tenant_verified") is True
                and str(proof.get("tenant_id", "")).casefold() == tenant
                and all(proof.get(key) == value for key, value in expected.items())
                and (not item or proof.get("read_only") is True))
    rows = collection.get("items")
    return (bound(collection.get("_provenance")) and isinstance(rows, list)
            and all(isinstance(row, dict) and bound(row.get("_provenance"), item=True) for row in rows))


def evaluate_snapshot(snapshot, categories=None, checks=None, frameworks=None, timings=None, include_not_applicable=True,
                      related_snapshots=None, *, completed_graph_sections=None, content_checks=None):
    """timings: optional dict that receives wall-clock timings; they never enter the deterministic report.

    related_snapshots: other-provider snapshots of the same scan group (e.g. the GCP project of a GKE
    cluster scan). They are read only and joined by privesc and native exposure
    analysis; findings and coverage remain attributed to `snapshot`.

    completed_graph_sections: optional partial-evaluation schedule, containing network and/or iam_graph.
    None preserves final graph selection; an empty set defers both graphs. With this partial schedule,
    checks=[] means no ready checks (a graph-only checkpoint), rather than the final default selection.

    include_not_applicable=False keeps NOT_APPLICABLE / EMPTY results out of findings and reports them as
    per-check counts in finding_aggregates (stats.by_status still counts every result). Scan entry points
    (CLI, run_scan, the worker) default to False; this library default stays True for compatibility."""
    from .checks.facts import MemoIndex
    from .runtime_metrics import span as _runtime_span
    collapse = _FindingAggregator(not include_not_applicable)
    emit_progress(phase="evaluating", provider=snapshot.get("provider") if isinstance(snapshot, dict) else None,
                  completed=0, total=None, dynamic_total=True)
    with _runtime_span('engine.validate'):
        snapshot = validate(snapshot, read_only=True)
    provider = snapshot["provider"]
    related = _related_snapshots(snapshot, related_snapshots)
    selected_categories, selected = _selection(provider, categories, checks, frameworks, content_checks=content_checks)
    selected, skipped_opt_in = _drop_unrequested_content(provider, snapshot, selected, checks, content_checks)
    graph_only_checkpoint = completed_graph_sections is not None and checks == []
    if graph_only_checkpoint:
        selected = []
    with _runtime_span('engine.resources'):
        inventory = resources(snapshot)
    with _runtime_span('engine.index'):
        index = _index(snapshot, inventory)
    coverage, findings = [], []
    for collection in snapshot["collections"]:
        retirement = _retired_collection_evidence(provider, snapshot, collection)
        psp_absence = _psp_resource_absence_evidence(provider, snapshot, collection)
        unsupported_region = _unsupported_aws_region(snapshot, collection)
        coverage_status = "unknown" if retirement and retirement[0] == "unknown" else "not_applicable" if psp_absence or unsupported_region else collection["status"]
        from .check_services import service_for
        coverage.append({"level": "collection", "type": collection["type"], "scope": collection["scope"],
            "service": service_for(provider, collection["type"], collection.get("service")), "status": coverage_status,
            "resource_count": len(collection["items"]), "reason": retirement[1]["reason"] if retirement else psp_absence["reason"] if psp_absence else _unsupported_aws_region_evidence(collection)["reason"] if unsupported_region else
                _unknown_coverage_reason(collection_status=collection["status"])
                if collection["status"] not in ("collected", "empty") else ""})
        code = "retired_service" if retirement else "pod_security_policy_api_absent" if psp_absence else _safe_collection_error_code(collection)
        if code is not None:
            coverage[-1]["error_code"] = code
    scoped_indexes = {}
    evaluation_metadata = freeze(snapshot.get("metadata", {}))
    native_ids = {resource["id"]: resource["native_id"] for resource in inventory}
    by_scope = defaultdict(list)
    for resource in inventory:
        by_scope[(resource["type"], resource["scope"])].append(resource)
    def scoped_index(scope):
        if scope not in scoped_indexes:
            import re
            azure_sql_scopes = set()
            azure_storage_scopes = set()
            azure_subnet_scopes = set()
            azure_vault_collection_scopes = set()
            azure_service_diagnostic_scopes = set()
            if provider == 'azure' and scope.lower().startswith('/subscriptions/'):
                from .collectors.azure_sql_inventory import authorized_database_scopes
                azure_sql_scopes = authorized_database_scopes(snapshot, scope)
                from .collectors.azure_swc import authorized_storage_service_scopes
                azure_storage_scopes = authorized_storage_service_scopes(snapshot, scope)
                from .collectors.azure_swc import authorized_subnet_scopes
                azure_subnet_scopes = authorized_subnet_scopes(snapshot, scope)
                from .collectors.azure_swc import authorized_vault_collection_scopes
                azure_vault_collection_scopes = authorized_vault_collection_scopes(snapshot, scope)
                from .collectors.azure_swc import authorized_service_diagnostic_scopes
                azure_service_diagnostic_scopes = authorized_service_diagnostic_scopes(snapshot, scope)
            account = scope.split("/", 1)[0] if provider == "aws" else None
            if not account or not re.fullmatch(r"[0-9]{12}", account):
                account = None
            def relevant(collection):
                # An exact scope cannot authenticate contradictory AWS global
                # provenance. Missing legacy markers remain unknown, not invented.
                if provider == "aws" and account and collection.get("global") is True:
                    if (collection.get("account_id") not in (None, account)
                            or any(item.get("AccountId") not in (None, account)
                                   for item in collection["items"])):
                        return False
                if (provider == 'azure' and collection.get('service') == 'Microsoft.Graph'
                        and scope.lower().startswith('/subscriptions/')):
                    from .checks.facts import azure_directory_join_authorized
                    return azure_directory_join_authorized(scope, snapshot.get('metadata', {}), collection)
                if (provider == "azure" and _azure_tenant_group_collection_authorized(
                        scope, snapshot.get("metadata", {}), collection)):
                    return True
                if collection["scope"] == scope:
                    return True
                if (provider == 'azure' and (collection['type'], collection['scope']) in azure_vault_collection_scopes):
                    return True
                if (provider == 'azure' and (collection['type'], collection['scope']) in azure_service_diagnostic_scopes):
                    return True
                if (provider == 'azure' and collection['type'] == 'sql_database'
                        and collection['scope'] in azure_sql_scopes):
                    return True
                if (provider == 'azure' and collection['type'] == 'storage_service'
                        and collection['scope'] in azure_storage_scopes):
                    return True
                if (provider == 'azure' and collection['type'] == 'subnet'
                        and collection['scope'] in azure_subnet_scopes):
                    return True
                return bool(account and collection.get("global") is True and collection.get("account_id") == account
                    and collection["scope"].split("/", 1)[0] == account
                    and all(item.get("AccountId") == account for item in collection["items"]))
            selected_collections = [c for c in snapshot["collections"] if relevant(c)]
            resource_scopes = {(c["type"], c["scope"]) for c in selected_collections}
            # MemoIndex: joins that checks derive from this read-only index are computed once per scope.
            scoped_indexes[scope] = MemoIndex({kind: [r for r in rows if (r["type"], r["scope"]) in resource_scopes] for kind, rows in index.items() if kind != "collections"})
            # Cross-scope joins over one immutable snapshot can reuse the first
            # existing memo; ordinary collection joins remain scope-local.
            first_index = next(iter(scoped_indexes.values()))
            if first_index is not scoped_indexes[scope]:
                scoped_indexes[scope].memo[("_shared_snapshot_memo",)] = first_index.memo
            scoped_indexes[scope]["collections"] = {kind: [c for c in rows if relevant(c)] for kind, rows in index["collections"].items()}
            context = {"provider": provider, "scope": scope, "_scope": scope, "created_at": snapshot["created_at"],
                "snapshot_id": snapshot["snapshot_id"], "metadata": evaluation_metadata}
            if account:
                context["Account"] = account
                if scope == account + "/global":
                    context["evaluation_scope"] = "aws_account"
            # One read-only view per scope, shared by every scoped check (no per-check deep copy).
            context = freeze(context)
            scoped_indexes[scope]["context"] = context
            scoped_indexes[scope]["_snapshot"] = context
            if provider == 'azure':
                from .azure_function_package_index_20261020 import attach as attach_package_source
                attach_package_source(scoped_indexes[scope], snapshot, scope)
        return scoped_indexes[scope]

    automatic_batch_adapter = None
    if evaluation_metadata.get('automatic_workload_environment_batches'):
        from .checks import automatic_workload_batch as automatic_batch_adapter
    with _runtime_span('engine.native_checks'):
        for settled_checks, check in enumerate(selected):
            emit_progress(phase="evaluating", provider=provider, completed=settled_checks,
                          total=len(selected), resources=len(inventory), dynamic_total=False)
            check_frameworks = list(check.frameworks)
            emit_finding = _finding_factory(check, provider, check_frameworks)
            if getattr(check, "target", "resource") == "scope":
                for scope in _scope_check_scopes(snapshot, check):
                    scoped = scoped_index(scope)
                    management_only = _aws_management_account_only_evidence(snapshot, check.id, scope)
                    incomplete = [{"type": kind, "status": "not_collected"} for kind in check.dependencies if not scoped["collections"].get(kind)]
                    incomplete += [{"type": kind, "status": c["status"]} for kind in check.dependencies for c in scoped["collections"].get(kind, []) if c["status"] not in ("collected", "empty")]
                    if management_only:
                        status, evidence = "NOT_APPLICABLE", management_only
                    elif incomplete:
                        status, evidence = "DENIED" if any(row["status"] == "denied" for row in incomplete) else "UNKNOWN", {"reason": "required scoped inventory incomplete", "dependencies": incomplete, "target": "scope"}
                        empty_dependencies = getattr(check, "empty_applicability_dependencies", ())
                        empty_applicable = bool(empty_dependencies) and set(empty_dependencies) <= set(check.dependencies) and all(
                            scoped["collections"].get(kind) and all(
                                collection["status"] == "empty" and collection["items"] == []
                                for collection in scoped["collections"][kind])
                            for kind in empty_dependencies)
                        if getattr(check, "allow_incomplete_failure", False) or empty_applicable:
                            # A conclusive violation or an explicitly empty target
                            # inventory may resolve the check. Their independent
                            # opt-ins can never produce PASS from incomplete data.
                            try:
                                observed_status, observed_evidence = check.evaluate(scoped["context"], scoped)
                                if (observed_status == "FAIL" and getattr(check, "allow_incomplete_failure", False)
                                        and isinstance(observed_evidence, dict)):
                                    status = "FAIL"
                                    evidence = {**observed_evidence, "incomplete_dependencies": incomplete}
                                elif observed_status == "NOT_APPLICABLE" and empty_applicable and isinstance(observed_evidence, dict):
                                    status = "NOT_APPLICABLE"
                                    evidence = {**observed_evidence, "incomplete_dependencies": incomplete,
                                                "empty_applicability_dependencies": list(empty_dependencies)}
                            except (KeyError, TypeError, ValueError, AttributeError, IndexError, OverflowError):
                                pass
                    else:
                        try:
                            status, evidence = check.evaluate(scoped["context"], scoped)
                            if status not in ("PASS", "FAIL", "UNKNOWN", "DENIED", "MANUAL", "NOT_APPLICABLE") or not isinstance(evidence, dict):
                                raise ValueError("invalid scoped check result")
                        except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
                            status, evidence = "UNKNOWN", {"reason": "missing or malformed scoped facts", "error_kind": type(exc).__name__}
                    findings.extend(collapse([emit_finding(scope, "scope:" + scope, check.kind, status, evidence)]))
                    coverage.append({"level": "check", "check_id": check.id, "type": check.kind, "scope": scope,
                        "target": "scope", "status": "unknown" if status in ("UNKNOWN", "DENIED") else "manual" if status == "MANUAL" else "evaluated",
                        "by_status": {status: 1}, "reason": _unknown_coverage_reason([{"status": status, "evidence": evidence}])
                        if status in ("UNKNOWN", "DENIED") else "Scoped presence/aggregate evaluation over collected facts."})
                continue
            check_findings = []
            collections = index["collections"].get(check.kind, [])
            # Global inventories may use native account/global scope; their explicit envelope is authoritative.
            if not collections:
                from .check_scope import evaluation_scope
                missing_scopes = snapshot["scopes"] or ["unknown"]
                if evaluation_scope(check) == "global_resource":
                    accounts = sorted({scope.split("/", 1)[0] for scope in missing_scopes
                        if re.fullmatch(r"[0-9]{12}/(?:global|[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+)", scope)})
                    missing_scopes = [account + "/global" for account in accounts] or missing_scopes
                collections = [{"type": check.kind, "scope": scope, "service": check.kind, "status": "not_collected", "items": []} for scope in missing_scopes]
            for collection in collections:
                scope, collection_status = collection["scope"], collection["status"]
                management_only = _aws_management_account_only_evidence(snapshot, check.id, scope)
                scope_account = scope.split("/", 1)[0]
                global_binding_conflict = bool(provider == "aws" and collection.get("global") is True
                    and re.fullmatch(r"[0-9]{12}", scope_account)
                    and (collection.get("account_id") not in (None, scope_account)
                         or any(item.get("AccountId") not in (None, scope_account)
                                for item in collection["items"])))
                retirement = _retired_collection_evidence(provider, snapshot, collection)
                psp_absence = (_psp_resource_absence_evidence(provider, snapshot, collection)
                    if check.id in _PSP_RESOURCE_CHECK_IDS and check.kind == "podsecuritypolicy"
                    and getattr(check, "target", "resource") == "resource" else None)
                unsupported_region = _unsupported_aws_region(snapshot, collection)
                scope_findings = []
                prepared_automatic = (automatic_batch_adapter.prepare(scoped_index(scope), check.id)
                    if automatic_batch_adapter is not None else None)
                for resource in by_scope.get((check.kind, scope), []):
                    # The rule index is scoped; foreign subscriptions/namespaces cannot satisfy a check.
                    scoped = scoped_index(scope)
                    try:
                        # Sealed native data is a read-only view: checks share it instead of deep-copying it.
                        if global_binding_conflict:
                            raise ValueError("contradictory AWS global account provenance")
                        status, evidence = (("NOT_APPLICABLE", management_only) if management_only else
                            automatic_batch_adapter.evaluate_prepared(resource["data"], scoped, check.evaluate, prepared_automatic)
                            if prepared_automatic is not None else check.evaluate(resource["data"], scoped))
                        if status not in ("PASS", "FAIL", "UNKNOWN", "DENIED", "EMPTY", "MANUAL", "NOT_APPLICABLE") or not isinstance(evidence, dict):
                            raise ValueError("invalid check result")
                    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as exc:
                        status, evidence = "UNKNOWN", {"reason": "missing or malformed provider facts", "error_kind": type(exc).__name__}
                    scope_findings.append(emit_finding(scope, resource["id"], resource["service"], status, evidence))
                unavailable = (collection_status not in ("collected", "empty") and not psp_absence and not unsupported_region and not management_only) or bool(retirement and retirement[0] == "unknown")
                empty_evaluated = False
                if (not retirement and not scope_findings and collection_status == "empty"
                        and collection.get("type") == check.kind and collection.get("scope") == scope
                        and collection.get("items") == []):
                    # Private opt-in for controls whose scoped decision is meaningful
                    # without a primary resource. No incomplete collection can enter.
                    callback, visited, empty_callback = check.evaluate, set(), None
                    for _ in range(8):
                        if callback is None or id(callback) in visited:
                            break
                        visited.add(id(callback))
                        candidate = getattr(callback, "evaluate_empty_inventory", None)
                        if callable(candidate):
                            empty_callback = candidate
                            break
                        callback = getattr(callback, "__wrapped__", None)
                    if empty_callback is not None:
                        try:
                            if sum(c.get("scope") == scope for c in collections) != 1:
                                raise ValueError("ambiguous empty primary inventory")
                            outcome = empty_callback(scoped_index(scope)["context"], freeze(collection))
                            if outcome is not None:
                                status, evidence = outcome
                                if status not in ("PASS", "FAIL", "UNKNOWN", "DENIED", "MANUAL", "NOT_APPLICABLE") or not isinstance(evidence, dict):
                                    raise ValueError("invalid empty inventory decision")
                                evidence = {**evidence, "evaluation_target": "scope", "empty_primary_inventory": check.kind}
                                empty_evaluated = True
                        except Exception as exc:
                            status, evidence = "UNKNOWN", {"reason": "empty inventory decision unavailable",
                                "error_kind": type(exc).__name__, "evaluation_target": "scope", "empty_primary_inventory": check.kind}
                            empty_evaluated = True
                        if empty_evaluated:
                            scope_findings.append(emit_finding(scope, "scope:" + scope,
                                collection.get("service", check.kind), status, evidence))
                if unavailable or not scope_findings:
                    status = "UNKNOWN" if retirement and retirement[0] == "unknown" else "NOT_APPLICABLE" if retirement or psp_absence or unsupported_region or management_only else "DENIED" if collection_status == "denied" else "EMPTY" if collection_status == "empty" else "UNKNOWN"
                    scope_findings.append(emit_finding(scope, "inventory:" + check.kind, collection.get("service", check.kind), status,
                        retirement[1] if retirement else psp_absence if psp_absence else _unsupported_aws_region_evidence(collection) if unsupported_region else management_only if management_only else {"collection_status": collection_status, "reason": collection.get("error", {}).get("code", "no collected resources"),
                         "semantics": "Inventory coverage, not a resource security pass."}))
                check_findings.extend(scope_findings)
                counts = dict(Counter(f["status"] for f in scope_findings))
                check_status = "not_applicable" if management_only or unsupported_region else "partial" if unavailable and collection_status == "partial" else "denied" if collection_status == "denied" else "unknown" if unavailable or counts.get("UNKNOWN") or counts.get("DENIED") else "empty" if collection_status == "empty" else "manual" if counts.get("MANUAL") else "evaluated"
                if empty_evaluated:
                    check_status = "unknown" if counts.get("UNKNOWN") or counts.get("DENIED") else "manual" if counts.get("MANUAL") else "evaluated"
                coverage.append({"level": "check", "check_id": check.id, "type": check.kind, "scope": scope,
                    **({"target": "scope"} if empty_evaluated else {}),
                    "status": check_status, "by_status": counts, "reason": _unknown_coverage_reason(scope_findings, collection_status=collection_status)
                    if check_status in ("unknown", "denied", "partial") and not retirement and not psp_absence else retirement[1]["reason"] if retirement else psp_absence["reason"] if psp_absence else ""})
            findings.extend(collapse(_dedupe_cross_scope(check_findings, native_ids, provider)))
    emit_progress(phase="evaluating", provider=provider, completed=len(selected), total=len(selected),
                  resources=len(inventory), dynamic_total=False)
    # Native predicate count is known, but graph/manual/post-processing work
    # does not have the same unit. Do not estimate the remainder from that count.
    emit_progress(phase="evaluating", provider=provider, completed=len(selected), total=None,
                  resources=len(inventory), dynamic_total=True)
    from .analysis import analysis_context
    from scripts.cloud_permission_risks import offline_rules
    with offline_rules(), analysis_context(snapshot):
        analysis_selected = [] if graph_only_checkpoint else _analysis_selection(provider, selected_categories, checks, frameworks)
        if analysis_selected:
            from .analysis import analyze_findings
            expected_ids = {c["id"] for c in analysis_selected}
            with _runtime_span('engine.analysis'):
                analyzed = [f for f in analyze_findings(snapshot, inventory, index, include_manual_only=False,
                    categories={c["category"] for c in analysis_selected}, related_snapshots=related)
                    if f["check_id"] in expected_ids and f["category"] in selected_categories]
            # Group once (order kept) instead of rescanning every analyzed finding per analysis check.
            analyzed_by_check = defaultdict(list)
            for f in analyzed:
                analyzed_by_check[f["check_id"]].append(f)
            findings.extend(collapse(analyzed))
            for check in analysis_selected:
                own = analyzed_by_check.get(check["id"], [])
                by_status = dict(Counter(f["status"] for f in own))
                coverage.append({"level": "check", "check_id": check["id"], "type": "projection", "scope": "selected_scopes",
                    "status": "unknown" if by_status.get("UNKNOWN") else "manual" if by_status.get("MANUAL") else "evaluated",
                    "by_status": by_status, "reason": _unknown_coverage_reason(own)
                    if by_status.get("UNKNOWN") else "Defensive review signals; no finding is not an effective-access pass."})
        graphs = {"network": {"nodes": [], "edges": []}, "iam": {"nodes": [], "edges": []}}
        graph_categories = _selected_graph_categories(selected_categories, selected, analysis_selected,
            categories, checks, frameworks)
        if completed_graph_sections is not None:
            graph_categories &= set(completed_graph_sections)
        if graph_categories:
            from .analysis import build_graphs
            # The report keeps the complete (uncollapsed) graph; bounded views are server-side projections.
            with _runtime_span('engine.graphs'):
                built = build_graphs(snapshot, inventory, index, max_nodes=None, collapse_unreferenced=not include_not_applicable,
                    graph_kinds={"network" if category == "network" else "iam" for category in graph_categories})
            for graph, category in (("network", "network"), ("iam", "iam_graph")):
                if category in graph_categories:
                    graphs[graph] = built[graph]
            if not include_not_applicable:  # unassigned role definitions -> per-scope aggregates with member refs
                from .analysis import collapse_unreferenced_definitions
                graphs["iam"] = collapse_unreferenced_definitions(graphs["iam"])
    privesc_stats = None
    graphs.setdefault("privesc", {"nodes": [], "edges": []})
    privesc_filter = None if graph_only_checkpoint else _privesc_selected(provider, selected_categories, checks, frameworks)
    if privesc_filter is not None:
        with _runtime_span('engine.privesc'):
            privesc_findings, privesc_coverage, graphs["privesc"], privesc_stats, privesc_timing = _run_privesc(snapshot, privesc_filter, related, inventory)
        if timings is not None:
            timings["privesc"] = privesc_timing
        findings.extend(collapse(privesc_findings))
        coverage.extend(privesc_coverage)
    from .checks.catalog import framework_display_names
    display_names = framework_display_names()
    # Attestation questions are source references, not provider-API checks.
    # Historic reports retain their original manual findings unchanged.
    selected_manual = []
    resource_lookup = {resource["id"]: resource for resource in inventory}
    for finding in findings:
        resource = resource_lookup.get(finding["resource_id"])
        if resource is None:
            continue
        data = resource["data"]
        name = data.get("UserName") or data.get("RoleName") or data.get("name") or data.get("Name") or (data.get("metadata", {}).get("name") if isinstance(data.get("metadata", {}), dict) else None)
        tags = data.get("Tags", [])
        if not name and isinstance(tags, list):
            name = next((tag.get("Value") for tag in tags if isinstance(tag, dict) and tag.get("Key") == "Name" and isinstance(tag.get("Value"), str)), None)
        finding["native_resource_id"] = resource["native_id"]
        from .finding_groups import placement
        _, location = placement(finding, data, kind=resource["type"])
        if location:
            finding["region"] = location
        finding["resource_name"] = name if isinstance(name, str) else resource["native_id"]
    selected_framework_versions = []
    from .checks.catalog import _framework_rows
    from .checks.native_only import automated_frameworks
    if frameworks:
        # Only explicitly requested versions (id or canonical name); a family label selects checks, not checklists.
        requested_frameworks = {FRAMEWORK_ALIASES.get(value, value) for value in frameworks}
        selected_framework_versions = [copy.deepcopy(row) for row in _framework_rows() if (row["id"] in requested_frameworks or display_names.get(row["id"]) in requested_frameworks) and row["provider"] in (provider, "all")]
        selected_native_ids = {c.id for c in selected}
        for row in selected_framework_versions:
            covered_ids = selected_native_ids.intersection(row["native_check_ids"])
            coverage.append({"level": "framework", "framework_id": row["id"], "framework_name": row["name"],
                "scope": "selected_scopes", "status": "unknown" if not covered_ids else "partial" if row["pending_source_checks"] else "evaluated",
                "selected_native_checks": len(covered_ids), "source_checks": row["source_checks"], "pending_source_checks": row["pending_source_checks"],
                "reason": "Pending upstream definitions are unimplemented; selected native predicates do not establish complete checklist coverage."})
    else:
        # Unfiltered run: every provider checklist version that has selected native checks or findings.
        selected_native_ids = {c.id for c in selected}
        labelled = {label for finding in findings for label in finding.get("frameworks", ())}
        labelled.update(label for row in collapse.rows.values() for label in row.get("frameworks", ()))
        selected_framework_versions = [copy.deepcopy(row) for row in _framework_rows() if row["provider"] in (provider, "all")
            and (selected_native_ids.intersection(row["native_check_ids"]) or display_names.get(row["id"]) in labelled)]
    scope_coverage = snapshot.get("metadata", {}).get("scope_coverage", {})
    if snapshot.get("metadata", {}).get("intentional_partial") is True or (isinstance(scope_coverage, dict) and scope_coverage.get("status") not in (None, "collected", "complete")):
        coverage.append({"level": "scope", "scope": "requested_scopes", "status": "partial" if snapshot.get("metadata", {}).get("intentional_partial") else "unknown",
            "reason": scope_coverage.get("reason", "Explicit scope limit or incomplete discovery") if isinstance(scope_coverage, dict) else "Malformed scope coverage metadata"})
    from .secret_findings import deduplicate_secret_findings
    function_secret_pre_dedup = normalize_unknown_reasons(findings)
    findings = deduplicate_secret_findings(function_secret_pre_dedup)
    from .gcp_function_secret_page_persistence_20261020 import retain_function_secret_pairs
    findings = retain_function_secret_pairs(function_secret_pre_dedup, findings)
    from .azure_function_package_provenance_20261020 import retain_package_source_assertions
    findings = retain_package_source_assertions(function_secret_pre_dedup, findings)
    selected_framework_versions = automated_frameworks(selected_framework_versions)
    counts = Counter(f["status"] for f in findings)
    aggregates = collapse.result()
    for row in aggregates:
        counts[row["status"]] += row["count"]
    counts = dict(counts)
    complete = bool(selected or analysis_selected or privesc_stats is not None) and all(c["status"] in ("empty", "evaluated") for c in coverage if c["level"] in ("check", "framework", "manual", "scope"))
    inventory_complete = all(c["status"] in ("collected", "empty") for c in coverage if c["level"] in ("collection", "scope"))
    from .finding_priority import VERSION as risk_model_version
    report = {"schema_version": REPORT_SCHEMA_VERSION, "risk_model_version": risk_model_version, "snapshot_id": snapshot["snapshot_id"], "provider": provider,
        "scopes": list(snapshot["scopes"]), "created_at": snapshot["created_at"],
        "resources": [{key: value for key, value in resource.items() if key != "data"} for resource in inventory],
        "native_data": dict(NATIVE_DATA, snapshot_id=snapshot["snapshot_id"]),
        "findings": sorted(findings, key=lambda f: (f["category"], f["check_id"], f["scope"], f["resource_id"])),
        "coverage": sorted(coverage, key=lambda row: (row["level"], row.get("check_id", ""), row.get("framework_id", ""), row.get("type", ""), row.get("scope", ""))), "framework_versions": selected_framework_versions, "snapshot_metadata": copy.deepcopy(snapshot.get("metadata", {})), "manual_requirements": selected_manual, "graphs": graphs, "stats": {"resource_count": len(inventory), "finding_count": len(findings),
            "check_count": len(selected) + len(analysis_selected), "manual_requirement_count": len(selected_manual), "by_status": counts, "by_severity": dict(Counter(f["severity"] for f in findings if f["status"] == "FAIL")),
            "coverage_complete": complete, "inventory_complete": inventory_complete, "categories": selected_categories,
            "limitations": ["Framework mappings retain reviewed source provenance; they are not compliance certification.", "Declared IAM relationships are not effective access.",
                "Network inventory relationships are not proven reachability.", "Upstream hardening catalogs have not all been ported; only selected native checks ran."]}}
    if skipped_opt_in:
        report["skipped_opt_in_checks"] = {"reason": "content_scanning_not_requested",
            "summary": "Content scanning was off for this scan, so content checks were not evaluated.",
            "check_ids": skipped_opt_in}
    if collapse.enabled:
        # NOT_APPLICABLE / EMPTY results are per-check counts, not rows; stats.by_status still counts them.
        report["finding_aggregates"] = aggregates
        report["stats"]["aggregated_finding_count"] = sum(row["count"] for row in aggregates)
        report["stats"]["aggregated_statuses"] = list(AGGREGATED_STATUSES)
    if privesc_stats is not None:
        from .privesc.versioned_catalog import current_binding
        report["privesc_catalog"] = current_binding()
        report["stats"]["privesc"] = privesc_stats
        report["stats"]["check_count"] += 1
        report["stats"]["limitations"].append("Privilege-escalation paths are derived offline from collected policies and the technique catalog; they are not exploited or proven.")
    if related:
        # Provenance of the joined snapshots (the report stays reproducible from them plus `snapshot`).
        report["related_snapshots"] = [{"snapshot_id": r["snapshot_id"], "provider": r["provider"], "scopes": list(r["scopes"]),
                                        "created_at": r["created_at"]} for r in related]
    from .remediation import report_templates
    report["remediation_templates"] = report_templates((f["check_id"] for f in report["findings"]), provider)
    for finding in report["findings"]:
        detail = report["remediation_templates"].get(finding["check_id"])
        if detail and finding["check_id"] != "analysis.internet_exposure":
            finding["remediation"] = detail["summary"]
    report["check_frameworks"] = factor_frameworks(report["findings"])
    report["check_meta"] = encode_check_meta(
        attach_reviewed_description_meta(factor_check_meta(report["findings"])),
        report["remediation_templates"])
    report["check_meta_encoding"] = dict(CHECK_META_ENCODING)
    return report


def _related_snapshots(snapshot, related_snapshots):
    """Validated related snapshots: other providers only, the primary and duplicates dropped, stable order."""
    from .related_snapshots import related_view
    out, seen = [], {snapshot["snapshot_id"]}
    for candidate in related_snapshots or ():
        candidate = related_view(candidate)
        if candidate["snapshot_id"] in seen or candidate["provider"] == snapshot["provider"]:
            continue
        seen.add(candidate["snapshot_id"])
        out.append(candidate)
    return sorted(out, key=lambda r: (r["provider"], r["snapshot_id"]))


def factor_frameworks(findings):
    """Move per-finding framework labels to one list per check (schema 1.1 check_frameworks).

    A check's default is the label list most of its findings carry (ties: the lexically smallest);
    those findings drop "frameworks", and any finding whose labels differ (e.g. a manual requirement)
    keeps its own explicit list. Findings are modified in place; hydrate_frameworks reverses it."""
    tallies = defaultdict(Counter)
    for finding in findings:
        if isinstance(finding.get("frameworks"), list):
            tallies[finding["check_id"]][tuple(finding["frameworks"])] += 1
    defaults = {check_id: min(tally.items(), key=lambda item: (-item[1], item[0]))[0] for check_id, tally in tallies.items()}
    for finding in findings:
        if isinstance(finding.get("frameworks"), list) and tuple(finding["frameworks"]) == defaults.get(finding["check_id"]):
            del finding["frameworks"]
    return {check_id: list(labels) for check_id, labels in sorted(defaults.items())}


def finding_frameworks(finding, check_frameworks):
    """The labels of one finding: its explicit list, else its check's default list."""
    if "frameworks" in finding:
        return list(finding["frameworks"])
    return list((check_frameworks or {}).get(finding.get("check_id"), []))


CHECK_META_FIELDS = ("title", "remediation", "service", "category", "severity",
                     "finding_type",
                     "description", "evaluated", "pass_when", "fail_when", "not_applicable_when", "rationale", "clarity_evaluation_contract")
CHECK_META_ENCODING = {"version": 1, "per_check_marker": "_derived",
                       "r": "description", "m": "remediation_templates.summary"}


def attach_reviewed_description_meta(meta):
    """Keep verified check prose once per check, without copying it into every finding row."""
    from .checks.catalog import description_for
    from .finding_presentation import evaluator_contract_fingerprint
    for check_id, values in meta.items():
        reviewed = description_for(check_id)
        if not isinstance(reviewed, dict):
            continue
        values["clarity_evaluation_contract"] = evaluator_contract_fingerprint()
        for field in ("description", "evaluated", "pass_when", "fail_when", "not_applicable_when"):
            value = reviewed.get(field)
            if isinstance(value, str) and value.strip():
                values[field] = value
            elif field == "evaluated" and isinstance(value, list) and value and all(isinstance(item, str) and item.strip() for item in value):
                values[field] = list(value)
        if "description" in values:
            values["rationale"] = values["description"]
    return meta


def encode_check_meta(meta, remediation_templates):
    """Keep identical archived prose once and mark exactly which defaults were removed."""
    encoded = {}
    templates = remediation_templates if isinstance(remediation_templates, dict) else {}
    for check_id, values in meta.items():
        fields = dict(values)
        flags = ""
        if isinstance(fields.get("description"), str) and fields.get("rationale") == fields["description"]:
            del fields["rationale"]
            flags += "r"
        template = templates.get(check_id)
        summary = template.get("summary") if isinstance(template, dict) else None
        if isinstance(summary, str) and fields.get("remediation") == summary:
            del fields["remediation"]
            flags += "m"
        if flags:
            fields["_derived"] = flags
        encoded[check_id] = fields
    return encoded


def factor_check_meta(findings):
    """Move per-check finding fields (CHECK_META_FIELDS) to one value per check (schema 1.1 check_meta).

    Per field and check, the default is the most common string value (ties: the lexically smallest);
    findings carrying it drop the field, and findings whose value differs (e.g. a check that picks
    severity per resource) keep it. A field is factored only when every finding of the check carries
    it, so hydration never adds a field a finding did not have. Findings are modified in place."""
    tallies = defaultdict(lambda: defaultdict(Counter))
    totals, present = Counter(), Counter()
    for finding in findings:
        totals[finding["check_id"]] += 1
        for field in CHECK_META_FIELDS:
            if field in finding:
                present[finding["check_id"], field] += 1
                value = finding[field]
                if isinstance(value, str):
                    tallies[finding["check_id"]][field][value] += 1
                elif field == "evaluated" and isinstance(value, list) and all(isinstance(item, str) for item in value):
                    tallies[finding["check_id"]][field][tuple(value)] += 1
    meta = {}
    for check_id, fields in tallies.items():
        defaults = {}
        for field, tally in fields.items():
            if present[check_id, field] == totals[check_id]:
                chosen = min(tally.items(), key=lambda item: (-item[1], item[0]))[0]
                defaults[field] = list(chosen) if field == "evaluated" and isinstance(chosen, tuple) else chosen
        if defaults:
            meta[check_id] = defaults
    for finding in findings:
        for field, value in meta.get(finding["check_id"], {}).items():
            if finding[field] == value:
                del finding[field]
        # Deletion leaves the original large hash table allocated. Rebuild only
        # its storage while retaining this finding's identity, order and values.
        compact = {key: value for key, value in finding.items()}
        finding.clear()
        finding.update(compact)
    return {check_id: meta[check_id] for check_id in sorted(meta)}


def hydrate_finding(finding, check_frameworks=None, check_meta=None, check_meta_encoding=None,
                    remediation_templates=None):
    """One finding with its per-check defaults (frameworks and CHECK_META_FIELDS) restored; not modified in place."""
    defaults = (check_meta or {}).get(finding.get("check_id")) or {}
    encoded = check_meta_encoding == CHECK_META_ENCODING
    flags = defaults.get("_derived", "") if encoded else ""
    if not isinstance(flags, str) or flags not in {"r", "m", "rm"}:
        flags = ""
    missing = {field: value for field, value in defaults.items()
               if field not in finding and (field != "_derived" or not encoded)}
    if "r" in flags and "rationale" not in finding and "rationale" not in defaults:
        description = defaults.get("description")
        if isinstance(description, str):
            missing["rationale"] = description
    if "m" in flags and "remediation" not in finding and "remediation" not in defaults:
        templates = remediation_templates if isinstance(remediation_templates, dict) else {}
        template = templates.get(finding.get("check_id"))
        summary = template.get("summary") if isinstance(template, dict) else None
        if isinstance(summary, str):
            missing["remediation"] = summary
    if check_frameworks is not None and "frameworks" not in finding:
        missing["frameworks"] = list(check_frameworks.get(finding.get("check_id"), []))
    hydrated = dict(finding, **missing) if missing else finding
    if finding.get("check_id") == "analysis.internet_exposure":
        from .remediation import exposure_action
        return dict(hydrated, remediation=exposure_action(finding.get("evidence"), finding.get("status")))
    return hydrated


def hydrate_frameworks(report):
    """Per-finding frameworks and per-check fields restored from check_frameworks / check_meta (no snapshot
    needed); the input is not modified. Reports without either map (schema 1.0, or 1.1 written before
    factoring) are returned unchanged."""
    labels = report.get("check_frameworks") if isinstance(report.get("check_frameworks"), dict) else None
    meta = report.get("check_meta") if isinstance(report.get("check_meta"), dict) else None
    if labels is None and meta is None:
        return report
    out = {key: value for key, value in report.items() if key not in ("check_frameworks", "check_meta")}
    out["findings"] = [hydrate_finding(finding, labels, meta, report.get("check_meta_encoding"),
                                       report.get("remediation_templates")) for finding in report.get("findings", [])]
    return out


hydrate_findings = hydrate_frameworks


NATIVE_DATA = {"mode": "snapshot_reference",
    "resources": "resources[].data is omitted; the native item is the snapshot item that resources(snapshot) maps to resources[].id",
    "graph_nodes": "evidence.native_resource_ref is a resources[].id; policy_document evidence.native_document_ref is a path inside the referenced native resource",
    "referenced_grants": "card.referenced_grants[].grant_count is the referenced source_node's card.grant_count (all declared grants); its card.source_grants is a bounded highest-risk sample and the full list is behind card.detail_ref (GET /api/scans/{id}/graphs/iam/grants/{detail_ref.resource_ref}; expand_report inlines it)",
    "frameworks": "findings[].frameworks is omitted when it equals check_frameworks[check_id]; peaso.engine.hydrate_frameworks(report) restores it",
    "check_meta": "Per-check defaults live in check_meta; check_meta_encoding marks rationale equal to stored description and remediation equal to the same report's stored template summary. peaso.engine.hydrate_frameworks(report) restores them without a live catalog lookup",
    "expand": "peaso.engine.expand_report(report, snapshot) restores schema 1.0 with embedded native data"}


def _referenced_full_grants(source_node, inventory, provider, cache):
    """The complete declared grants behind a referenced graph node. Cards keep a bounded sample
    (card.source_grants); the full list is re-derived from the node's native resource, falling back
    to the stored sample only when that resource is not in the snapshot."""
    from .analysis.iam import full_grants
    card = source_node.get("card") or {}
    evidence = source_node.get("evidence") or {}
    ref = evidence.get("native_resource_ref") or (card.get("detail_ref") or {}).get("resource_ref")
    if ref not in inventory:
        return card.get("source_grants", [])
    if ref not in cache:
        try:
            cache[ref] = full_grants(inventory[ref], provider)
        except (TypeError, AttributeError, KeyError, ValueError, IndexError):
            cache[ref] = card.get("source_grants", [])
    return cache[ref]


def expand_report(report, snapshot=None, *, _inventory=None):
    """Schema 1.1 -> 1.0: inline native data by reference (objects are shared, never copied).
    The input report is not modified; the snapshot comes from the argument or report["snapshot"]."""
    if report.get("schema_version") != REPORT_SCHEMA_VERSION:
        return report
    snapshot = snapshot if snapshot is not None else report.get("snapshot")
    if snapshot is None:
        raise ValueError("expanding a schema 1.1 report needs its snapshot")
    if snapshot.get("snapshot_id") != report.get("snapshot_id"):
        raise ValueError("snapshot does not match the report snapshot_id")
    from .analysis.iam import policy_documents
    inventory = {resource["id"]: resource for resource in (resources(snapshot) if _inventory is None else _inventory)}
    by_native = {(r["scope"], r["type"], r["native_id"]): r for r in inventory.values()}
    out = {key: value for key, value in hydrate_frameworks(report).items() if key != "native_data"}
    out["schema_version"] = SCHEMA_VERSION
    out["resources"] = [dict(resource, data=inventory[resource["id"]]["data"]) if resource.get("id") in inventory and "data" not in resource
                        else resource for resource in report.get("resources", [])]
    documents = {}
    full_lists = {}  # resource id -> complete grant list, shared by every node that references it
    graphs = {}
    for name, graph in (report.get("graphs") or {}).items():
        if not isinstance(graph, dict) or not graph.get("nodes"):
            graphs[name] = graph
            continue
        by_id = {n.get("id"): n for n in graph["nodes"]}
        nodes = []
        for current in graph["nodes"]:
            evidence = current.get("evidence")
            card = current.get("card")
            changed = False
            if isinstance(evidence, dict) and "native_resource_ref" in evidence and evidence["native_resource_ref"] in inventory:
                data = inventory[evidence["native_resource_ref"]]["data"]
                evidence = {("native_resource" if k == "native_resource_ref" else k): (data if k == "native_resource_ref" else v) for k, v in evidence.items()}
                changed = True
            if isinstance(evidence, dict) and "native_document_ref" in evidence:
                src = evidence.get("source") or {}
                owner = by_native.get((src.get("scope"), src.get("resource_type"), src.get("resource_id")))
                if owner is not None:
                    if owner["id"] not in documents:
                        documents[owner["id"]] = dict(policy_documents(owner["data"]))
                    doc = documents[owner["id"]].get(evidence["native_document_ref"])
                    if doc is not None:
                        evidence = {("native_document" if k == "native_document_ref" else k): (doc if k == "native_document_ref" else v) for k, v in evidence.items()}
                        changed = True
            if isinstance(card, dict) and card.get("referenced_grants"):
                refs = []
                for ref in card["referenced_grants"]:
                    if isinstance(ref, dict) and "grant_count" in ref and "grants" not in ref:
                        grants = _referenced_full_grants(by_id.get(ref.get("source_node")) or {}, inventory, report.get("provider"), full_lists)
                        ref = {("grants" if k == "grant_count" else k): (grants if k == "grant_count" else v) for k, v in ref.items()}
                    refs.append(ref)
                card = dict(card, referenced_grants=refs)
                changed = True
            if changed:
                current = dict(current, evidence=evidence)
                if card is not None:
                    current["card"] = card
            nodes.append(current)
        graphs[name] = dict(graph, nodes=nodes)
    out["graphs"] = graphs
    return out


def compact_report(report):
    """Schema 1.0 -> 1.1 migration (the inverse of expand_report); the input report is not modified."""
    if report.get("schema_version") == REPORT_SCHEMA_VERSION:
        return report
    findings = [dict(finding) for finding in report.get("findings", [])]
    out = dict(report, schema_version=REPORT_SCHEMA_VERSION,
               resources=[{k: v for k, v in r.items() if k != "data"} for r in report.get("resources", [])],
               native_data=dict(NATIVE_DATA, snapshot_id=report.get("snapshot_id")),
               findings=findings, check_frameworks=factor_frameworks(findings))
    # A historical report without stored templates must not acquire today's
    # remediation text during schema migration.
    out.setdefault("remediation_templates", {})
    out["check_meta"] = encode_check_meta(factor_check_meta(findings), out["remediation_templates"])
    out["check_meta_encoding"] = dict(CHECK_META_ENCODING)
    graphs = {}
    for name, graph in (report.get("graphs") or {}).items():
        if not isinstance(graph, dict) or not graph.get("nodes"):
            graphs[name] = graph
            continue
        nodes = []
        for current in graph["nodes"]:
            evidence, card = current.get("evidence"), current.get("card")
            if isinstance(evidence, dict) and "native_resource" in evidence and current.get("resource_id"):
                evidence = {("native_resource_ref" if k == "native_resource" else k): (current["resource_id"] if k == "native_resource" else v) for k, v in evidence.items()}
            if isinstance(evidence, dict) and "native_document" in evidence and isinstance((evidence.get("source") or {}).get("path"), str):
                evidence = {("native_document_ref" if k == "native_document" else k): (evidence["source"]["path"] if k == "native_document" else v) for k, v in evidence.items()}
            if isinstance(card, dict) and card.get("referenced_grants"):
                card = dict(card, referenced_grants=[{("grant_count" if k == "grants" else k): (len(v) if k == "grants" else v) for k, v in ref.items()}
                                                     if isinstance(ref, dict) else ref for ref in card["referenced_grants"]])
            if evidence is not current.get("evidence") or card is not current.get("card"):
                current = dict(current, evidence=evidence)
                if card is not None:
                    current["card"] = card
            nodes.append(current)
        graphs[name] = dict(graph, nodes=nodes)
    out["graphs"] = graphs
    return out


def _run_privesc(snapshot, technique_filter, related=(), inventory=None):
    """Run the read-only privesc evaluator; an evaluator failure becomes coverage, never a crashed scan."""
    import time
    started = time.perf_counter()
    try:
        from . import privesc
        # Related snapshots join cross-provider paths (see docs/privesc.md).
        # A missing target inventory or unresolved selector is coverage evidence,
        # not an identified principal that can be reached by an escalation path.
        # Keep those diagnostics in coverage without emitting memberless graph nodes.
        extra = {"include_unknown": False}
        if inventory is not None:
            # The engine's resources(snapshot) for this same snapshot; entry-point
            # annotation would otherwise rebuild the identical inventory.
            extra["inventory"] = inventory
        if related:
            extra["related_snapshots"] = list(related)
        if technique_filter:
            entries = [e for e in privesc.catalog()["entries"] if e["id"] in technique_filter]
            result = privesc.analyze(snapshot, entries=entries, **extra)
        else:
            result = privesc.analyze(snapshot, **extra)
        findings = [dict(f) for f in result.get("findings", [])]
        coverage = list(result.get("coverage", []))
        graph = result.get("graph") or {"nodes": [], "edges": []}
        stats = dict(result.get("stats", {}))
        # Wall-clock timings are reported out of band so evaluation stays repeatable.
        timing = dict(stats.pop("timing_seconds", None) or {})
    except Exception as exc:  # noqa: BLE001 - the evaluator must not abort the other categories
        elapsed = round(time.perf_counter() - started, 4)
        return [], [{"level": "check", "check_id": PRIVESC_CHECK_ID, "type": "privesc", "scope": "selected_scopes", "status": "unknown",
                     "by_status": {}, "error_kind": type(exc).__name__,
                     "reason": "Privilege-escalation evaluation failed; no privesc result is a pass."}], \
            {"nodes": [], "edges": []}, {"error": type(exc).__name__}, {"engine_seconds": elapsed}
    for finding in findings:
        finding["category"] = "privesc"
        finding.setdefault("frameworks", [PRIVESC_FRAMEWORK])
        if PRIVESC_FRAMEWORK not in finding["frameworks"]:
            finding["frameworks"] = [PRIVESC_FRAMEWORK] + list(finding["frameworks"])
        finding.setdefault("scope", "unknown")
        source = (finding.get("evidence") or {}).get("source") or {}
        finding.setdefault("native_resource_id", finding.get("resource_id"))
        if isinstance(source.get("label"), str):
            finding.setdefault("resource_name", source["label"])
    coverage.append({"level": "check", "check_id": PRIVESC_CHECK_ID, "type": "privesc", "scope": "selected_scopes",
                     "status": "unknown" if any(c.get("status") != "partial" for c in coverage) else "evaluated",
                     "by_status": dict(Counter(f["status"] for f in findings)),
                     "reason": "Catalog-driven privilege-escalation paths; see coverage level privesc."})
    timing["engine_seconds"] = round(time.perf_counter() - started, 4)
    return findings, coverage, graph, stats, timing


def scan(request):
    """Collect and evaluate: (report, snapshot). The report references the snapshot by snapshot_id only.

    request["include_not_applicable"] (default False) keeps per-resource NOT_APPLICABLE / EMPTY rows;
    request["related_snapshots"] (optional) are other-provider snapshots joined by the privesc evaluator."""
    from .content_scan_selection import normalize_request
    request = normalize_request(request)
    snapshot = collect_snapshot(request)
    timings = {}
    report = evaluate_snapshot(snapshot, request.get("categories"), request.get("checks"), request.get("frameworks"), timings=timings,
                               include_not_applicable=bool(request.get("include_not_applicable", False)),
                               related_snapshots=request.get("related_snapshots"), content_checks=request.get("content_checks"))
    if timings:
        report["timings"] = timings
    return report, snapshot


def run_scan(request):
    """scan() as one report; request["embed_snapshot"] (default False) also embeds the collected snapshot."""
    report, snapshot = scan(request)
    if request.get("embed_snapshot"):
        report["snapshot"] = snapshot
    return report


def diff_reports(before, after):
    """Compare stable finding IDs and full evidence; timestamp-only scan differences are ignored."""
    if before.get("provider") != after.get("provider"):
        raise ValueError("cannot diff reports across providers")
    if set(before.get("scopes", [])) != set(after.get("scopes", [])):
        raise ValueError("cannot diff reports across different scope selections")
    before, after = hydrate_frameworks(before), hydrate_frameworks(after)
    def observations(report):
        if report.get("finding_grouping") != "check-v1":
            return report
        return dict(report, findings=[member for group in report["findings"] for member in group.get("observations", [])])
    before, after = observations(before), observations(after)
    def canonical(findings):
        # Findings stored under a retired duplicate check id are keyed as their surviving check; when the survivor's
        # finding for the same resource is also present, the retired duplicate is dropped.
        from .checks import CHECK_ALIASES
        rows = {}
        for f in findings:
            survivor = CHECK_ALIASES.get(f.get("check_id"))
            if survivor:
                f = dict(f, check_id=survivor, id=digest([f.get("provider"), f.get("scope"), f.get("resource_id"), survivor]))
                rows.setdefault(f["id"], f)
            else:
                rows[f["id"]] = f
        return rows
    left = canonical(before.get("findings", []))
    right = canonical(after.get("findings", []))
    added = [right[key] for key in sorted(right.keys() - left.keys())]
    removed = [left[key] for key in sorted(left.keys() - right.keys())]
    def comparable(value):
        if isinstance(value, dict):
            return {k: comparable(v) for k, v in value.items() if k != "snapshot_id"}
        if isinstance(value, list):
            return [comparable(v) for v in value]
        return value
    changed = [{"id": key, "before": left[key], "after": right[key]} for key in sorted(left.keys() & right.keys()) if comparable(left[key]) != comparable(right[key])]

    return {"schema_version": SCHEMA_VERSION, "provider": before["provider"], "scopes": before.get("scopes", []),
        "before_snapshot_id": before.get("snapshot_id"), "after_snapshot_id": after.get("snapshot_id"),
        "added": added, "removed": removed, "changed": changed,
        "stats": {"added": len(added), "removed": len(removed), "changed": len(changed)},
        "coverage_before": before.get("coverage", []), "coverage_after": after.get("coverage", [])}
