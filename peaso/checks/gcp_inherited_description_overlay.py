"""Public source corrections for native GCP inherited logging facts.

The compiled reviewed rows and upstream source manifest remain immutable.
These two legacy controls have no signed new-check proposal specification.
"""
from copy import deepcopy

VERSION = "gcp-inherited-logging-description-overlay-v1"
ROWS = {
    "gcp.claude.logging.project_sink_all_entries": {
        "base_row_sha256": "d38e14db01242b985f280a08afece5c6de1a748f552ab7c0cfec2ca3943b4701",
        "base_catalog_row_sha256": "98aa7ff8c6a7afd71be90b039cf08174efaba86102a95e544a5b88cc0e0e1a47",
        "prior_source": "https://github.com/turbot/steampipe-mod-gcp-compliance/blob/3ac653021a284b68c69b14c75afa2ebc1feff665/policy_bundle/logging.pp#L131",
        "official_references": [
            "https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/projects.sinks",
            "https://docs.cloud.google.com/logging/docs/export/aggregated_sinks",
            "https://docs.cloud.google.com/logging/docs/export/aggregated_sinks_overview",
        ],
        "history": "Original reviewed same-project-only PASS and no-FAIL/MANUAL absence are superseded for source-bound native project and ancestor sink evidence; the pinned upstream SQL counted project sinks only.",
        "fields": {
            "description": "For a GCP project, evaluate configured all-entry routing through a same-project sink or a complete, source-bound folder/organization ancestor sink. This is a configuration check, not proof of log delivery, destination access, or writer authorization. Incomplete, denied, foreign, or malformed hierarchy/sink evidence is UNKNOWN; synthetic legacy rows without native ancestry retain MANUAL absence.",
            "evaluated": ["projectId and project ancestry", "project log_sink inventory", "_inherited_sinks and its complete ancestor/source-request coverage", "sink.name, destination, filter, disabled, exclusions, includeChildren, interceptChildren"],
            "pass_when": "PASS when a complete, source-bound project or ancestor route has an enabled sink, empty filter, no active exclusions, and a destination; ancestor sinks must include children. A project or lower-level ancestor sink is not sufficient when an active interceptor higher in the hierarchy can divert entries.",
            "fail_when": "FAIL when complete, identity-bound project and ancestor sink inventories prove no eligible all-entry route. Incomplete/denied/foreign/malformed evidence is UNKNOWN.",
            "not_applicable_when": None,
        },
    },
    "gcp.claude.project.audit_logs_configured": {
        "base_row_sha256": "872ac98ea689da135afbd8661bbb69e0f214e50f88b0545ac328184e4cbb448a",
        "base_catalog_row_sha256": "668dd3f52effbed705495e4f72de15e69ecec56928970474f0ad6b00263aecbb",
        "prior_source": "https://github.com/prowler-cloud/prowler/blob/61d2cc55c4539a6b48a3cf9f3729d8f2af300882/prowler/providers/gcp/services/iam/iam_audit_logs_enabled/iam_audit_logs_enabled.metadata.json",
        "official_references": [
            "https://cloud.google.com/logging/docs/audit/configure-data-access",
            "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getAncestry",
        ],
        "history": "Original reviewed direct-project-only PASS and no-FAIL/MANUAL absence are superseded for complete, source-bound native project and ancestor IAM audit policy evidence.",
        "fields": {
            "description": "For a project root IAM policy, a direct auditConfigs declaration or a complete, source-bound project/folder/organization auditConfigs union establishes configured audit policy presence. This does not prove individual audit types, required principals, emitted events, or log delivery. Incomplete, denied, foreign, or malformed ancestry/policy evidence is UNKNOWN; synthetic legacy rows without native union retain MANUAL absence.",
            "evaluated": ["direct project auditConfigs[].service", "effectiveAuditConfigs project/ancestor union", "ordered ancestor scopes and complete getAncestry/getIamPolicy source-request coverage"],
            "pass_when": "PASS when the direct full project IAM policy declares at least one auditConfigs entry, or a complete source-bound project/ancestor union contains at least one such entry.",
            "fail_when": "FAIL when a complete source-bound project/ancestor IAM policy union proves no auditConfigs entry; missing or incomplete native union remains UNKNOWN.",
            "not_applicable_when": "Not a direct full project root IAM policy.",
        },
    },
    "gcp.claude.project.storage_data_access_audit_logs": {
        "version": "gcp-inherited-storage-audit-description-overlay-v1",
        "base_row_sha256": "241d3063b763bef9eb95ad3df481500b9dea9cdc221104ba72cb9de36c4e2b6e",
        "base_catalog_row_sha256": "6e2cf2d4a09606faf604e2e0590e2a8e19a6bc1fbc137abcf7e20bf38be170c8",
        "prior_source": "https://github.com/prowler-cloud/prowler/blob/61d2cc55c4539a6b48a3cf9f3729d8f2af300882/prowler/providers/gcp/services/cloudstorage/cloudstorage_audit_logs_enabled/cloudstorage_audit_logs_enabled.metadata.json",
        "official_references": [
            "https://docs.cloud.google.com/logging/docs/audit/configure-data-access",
            "https://cloud.google.com/resource-manager/reference/rest/v1/projects/getAncestry",
        ],
        "history": "Original reviewed direct-project-only PASS and no-FAIL/MANUAL absence are superseded for complete, source-bound native project and ancestor Cloud Storage Data Access audit policy evidence.",
        "fields": {
            "description": "For the direct full project IAM policy, evaluate configured Cloud Storage Data Access audit types across a complete, source-bound project/folder/organization audit policy union. DATA_READ and DATA_WRITE may be declared for storage.googleapis.com or allServices across those scopes. Relevant exemptions leave universal logging UNKNOWN without a required-principal proof. This does not prove emitted events, method-level behavior, or log delivery; incomplete, denied, foreign, or malformed ancestry/policy evidence is UNKNOWN. Synthetic legacy rows without native union retain the prior direct-declaration PASS/MANUAL behavior.",
            "evaluated": ["direct and effectiveAuditConfigs[].service", "effectiveAuditConfigs[].auditLogConfigs[].logType and exemptedMembers", "ordered project/ancestor scopes and complete getAncestry/getIamPolicy source-request coverage"],
            "pass_when": "PASS when complete source-bound project/ancestor audit policies configure both DATA_READ and DATA_WRITE for storage.googleapis.com or allServices, with no relevant exemption. A legacy synthetic direct declaration retains PASS without claiming inherited coverage.",
            "fail_when": "FAIL when complete source-bound project/ancestor audit policy evidence proves DATA_READ or DATA_WRITE missing. Relevant exemptions or incomplete/denied/foreign/malformed evidence are UNKNOWN.",
            "not_applicable_when": "Not the direct full project getIamPolicy document.",
        },
    },
}


def description(check_id, original):
    row = ROWS.get(check_id)
    if row is None:
        return deepcopy(original)
    corrected = deepcopy(original) if isinstance(original, dict) else {}
    corrected.update(deepcopy(row["fields"]))
    corrected["description_correction"] = {
        "version": row.get("version", VERSION),
        "base_row_sha256": row["base_row_sha256"],
        "base_catalog_row_sha256": row["base_catalog_row_sha256"],
        "prior_source": row["prior_source"],
        "source_relationship": row["history"],
        "official_references": list(row["official_references"]),
        "signed_spec_status": "no_signed_new_check_proposal; frozen compiled descriptions unchanged",
    }
    return corrected


def validate_rows(checks):
    for check_id in ROWS:
        description(check_id, checks.get(check_id))
