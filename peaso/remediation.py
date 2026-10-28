"""Bounded, defensive remediation templates and safe finding identity bindings.

Templates are stored once by check ID. Nothing in this module executes commands or
changes a provider resource. Raw evidence and credential material are never copied
into a command.
"""
from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
import re
import shlex
from urllib.parse import unquote

def _read_static_rulepack(path):
    """Share immutable package metadata strings; retain independent containers.

    This loader is only for bundled JSON rulepacks, never findings or customer
    values. Public template APIs still return their existing defensive copies.
    """
    from .checks.catalog import _shared_metadata_strings
    return json.loads(path.read_text(), object_hook=_shared_metadata_strings)


RULEPACK = Path(__file__).resolve().parent / "rulepacks/remediation_details.json"
CURATED = Path(__file__).resolve().parent / "rulepacks/remediation_curated.json"
AWS_REVIEWED = Path(__file__).resolve().parent / "rulepacks/remediation_aws_reviewed.json"
AWS_FAMILIES_REVIEWED = Path(__file__).resolve().parent / "rulepacks/remediation_aws_families_reviewed.json"
AZURE_REVIEWED = Path(__file__).resolve().parent / "rulepacks/remediation_azure_reviewed.json"
COMPLIANCE_REVIEWED = (
    (Path(__file__).resolve().parent / "rulepacks/remediation_native_gcp_selected_20261020.json", "gcp"),
    (Path(__file__).resolve().parent / "rulepacks/remediation_native_k8s_declarations_20261020.json", "k8s"),
    (Path(__file__).resolve().parent / "rulepacks/remediation_native_aws_selected_20261020.json", "aws"),
    (Path(__file__).resolve().parent / "rulepacks/remediation_compliance_new_aws.json", "aws"),
    (Path(__file__).resolve().parent / "rulepacks/remediation_compliance_new_gcp.json", "gcp"),
    (Path(__file__).resolve().parent / "rulepacks/remediation_compliance_new_azure.json", "azure"),
    (Path(__file__).resolve().parent / "rulepacks/remediation_compliance_new_k8s.json", "k8s"),
    (Path(__file__).resolve().parent / "rulepacks/remediation_compliance_batch_remaining_aws.json", "aws"),
    (Path(__file__).resolve().parent / "rulepacks/remediation_compliance_batch_remaining_azure.json", "azure"),
    (Path(__file__).resolve().parent / "rulepacks/remediation_compliance_batch_remaining_gcp.json", "gcp"),
    (Path(__file__).resolve().parent / "rulepacks/remediation_compliance_batch_remaining_k8s.json", "k8s"),
    (Path(__file__).resolve().parent / "rulepacks/remediation_native_azure_review_20261020.json", "azure"),
)
MAX_IDENTITY_LENGTH = 512
_SAFE_AWS_ID = re.compile(r"(?:sg|sgr|i|subnet|vpc|vol|db|fs|eni)-[0-9a-fA-F]{8,32}\Z")
_SAFE_EBS_SNAPSHOT_ID = re.compile(r"snap-[0-9a-fA-F]{8,32}\Z")
_SAFE_EC2_IMAGE_ID = re.compile(r"ami-[0-9a-fA-F]{8,32}\Z")
_SAFE_AWS_ARN = re.compile(r"arn:aws(?:-[a-z]+)?:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:[A-Za-z0-9_./+=,@:-]{1,256}\Z")
_SAFE_S3_ARN = re.compile(r"arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_SAFE_S3_BUCKET = re.compile(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\Z")
_SAFE_AWS_NAMED = re.compile(r"[A-Za-z0-9][A-Za-z0-9+=,.@_-]{0,127}\Z")
_SAFE_LAMBDA_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_SAFE_RDS_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]{0,62}\Z")
_SAFE_ECR_NAME = re.compile(r"[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:\.|_|__|-+)[a-z0-9]+)*)*\Z")
_SAFE_ECR_ARN = re.compile(r"arn:aws:ecr:[a-z0-9-]+:([0-9]{12}):repository/([a-z0-9_./-]{2,256})\Z")
_SAFE_GCP_PROJECT = re.compile(r"[a-z][a-z0-9-]{4,61}[a-z0-9]\Z")
_SAFE_GCP_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,127}\Z")
_SAFE_GCP_COMPUTE_NAME = re.compile(r"[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?\Z")
_SAFE_AZURE_ARM = re.compile(r"/subscriptions/([0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})/resourceGroups/([A-Za-z0-9_.()_-]{1,90})/providers/[A-Za-z][A-Za-z0-9.]+/[A-Za-z0-9_./()-]{1,256}\Z", re.I)
_SAFE_K8S_NAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z")
_SAFE_K8S_KIND = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z")
_SAFE_AWS_SCOPE = re.compile(r"([0-9]{12})(?:/(global|[a-z]{2}(?:-gov)?-[a-z]+-[0-9]))?\Z")
_GCP_PROJECT_PART = r"([a-z][a-z0-9-]{4,61}[a-z0-9]|[1-9][0-9]{5,19})"
_SAFE_GCP_SCOPE = re.compile(r"projects/" + _GCP_PROJECT_PART + r"\Z")
_SAFE_GCP_LOCATION_SCOPE = re.compile(r"projects/" + _GCP_PROJECT_PART + r"/(?:locations|regions|zones)/([a-z0-9-]{2,64})\Z")
_SAFE_GCP_PARENT_SCOPE = re.compile(r"(organizations|folders)/([1-9][0-9]{0,19})\Z")
_SAFE_LOCATION = re.compile(r"[a-z][a-z0-9-]{1,63}\Z")
_SAFE_K8S_NATIVE = re.compile(r"k8s://([^/]{1,128})/([^/]{1,64})/([^/]{1,253})/([^/]{1,253})\Z")
_AWS_NAMED_KINDS = {
    "bucket": _SAFE_S3_BUCKET,
    "lambda_function": _SAFE_LAMBDA_NAME,
    "iam_policy": _SAFE_AWS_NAMED,
    "iam_role": _SAFE_AWS_NAMED,
    "iam_user": _SAFE_AWS_NAMED,
    "iam_group": _SAFE_AWS_NAMED,
    "rds_instance": _SAFE_RDS_NAME,
    "rds_cluster": _SAFE_RDS_NAME,
    "ecr_repository": _SAFE_ECR_NAME,
}


@lru_cache(maxsize=1)
def _check_kinds() -> dict[str, str]:
    from .checks import CHECKS
    return {check.id: check.kind for check in CHECKS}


def _merge_compliance_reviewed(value: dict, shards=COMPLIANCE_REVIEWED) -> None:
    """Bind only registered, signed new-check templates from named review shards."""
    from .checks import CHECKS
    from .checks.catalog import proposal_provenance_for

    providers = {check.id: check.provider for check in CHECKS}
    seen = set()
    for shard_path, provider in shards:
        if not shard_path.is_file():
            continue
        reviewed = _read_static_rulepack(shard_path)
        if not isinstance(reviewed, dict):
            raise ValueError("compliance remediation shard must be an object: " + shard_path.name)
        for check_id, candidate in reviewed.items():
            if not isinstance(check_id, str) or check_id in seen:
                raise ValueError("duplicate or malformed compliance remediation ID: " + str(check_id))
            seen.add(check_id)
            signed = proposal_provenance_for(check_id)
            if providers.get(check_id) != provider or signed is None or signed["signed_provider"] != provider:
                raise ValueError("compliance remediation ID/provider is not registered and signed: " + check_id)
            if not isinstance(candidate, dict) or candidate.get("review_status") not in {
                    "approved", "draft", "source_bound_pending_review"}:
                raise ValueError("compliance remediation lacks a recognized review status: " + check_id)
            if candidate.get("proposed_spec_sha256") != signed["signed_spec_sha256"]:
                raise ValueError("compliance remediation differs from the signed proposed spec: " + check_id)
            previous = value.get(check_id)
            if previous is not None and (not isinstance(previous, dict) or previous.get("review_status") == "approved"):
                if previous != candidate:
                    raise ValueError("compliance remediation conflicts with an approved template: " + check_id)
                continue
            if candidate["review_status"] == "approved" or previous is None:
                value[check_id] = candidate


@lru_cache(maxsize=1)
def rules() -> dict:
    value = _read_static_rulepack(RULEPACK) if RULEPACK.is_file() else {}
    if not isinstance(value, dict):
        raise ValueError("remediation rulepack must be an object")
    if CURATED.is_file():
        curated = _read_static_rulepack(CURATED)
        if not isinstance(curated, dict):
            raise ValueError("curated remediation rulepack must be an object")
        value.update(curated)
    shard_seen = {}
    for shard_path, provider_prefix in ((AWS_REVIEWED, "aws."),
                                        (AWS_FAMILIES_REVIEWED, "aws."),
                                        (AZURE_REVIEWED, "azure.")):
        if not shard_path.is_file():
            continue
        reviewed = _read_static_rulepack(shard_path)
        if not isinstance(reviewed, dict):
            raise ValueError(f"reviewed {provider_prefix} remediation shard must be an object: {shard_path.name}")
        if any(not isinstance(check_id, str) or not check_id.startswith(provider_prefix) for check_id in reviewed):
            raise ValueError(f"reviewed remediation shard may contain only native {provider_prefix} IDs")
        if any(not isinstance(candidate, dict) or not isinstance(candidate.get("review_status"), str) for candidate in reviewed.values()):
            raise ValueError("reviewed remediation shard entries need an explicit review_status")
        conflicts = []
        for check_id, candidate in reviewed.items():
            if check_id in shard_seen and shard_seen[check_id] != candidate:
                conflicts.append(check_id)
                continue
            shard_seen[check_id] = candidate
            previous = value.get(check_id)
            if previous is None:
                value[check_id] = candidate
            elif previous == candidate:
                # Explicit byte-equivalent duplicate; no change in meaning or precedence.
                continue
            elif previous.get("review_status") != "approved" and isinstance(candidate, dict) and candidate.get("review_status") == "approved":
                # A separately reviewed shard entry promotes a nonrendered generated draft.
                value[check_id] = candidate
            elif previous.get("review_status") != "approved" and isinstance(candidate, dict) and candidate.get("review_status") != "approved":
                # Keep the earlier nonrendered draft; neither version reaches the product.
                continue
            else:
                conflicts.append(check_id)
        if conflicts:
            raise ValueError("reviewed remediation shard conflicts with approved IDs: " + ", ".join(sorted(conflicts)[:10]))
    _merge_compliance_reviewed(value)
    from .checks.aws_native_status_description_overlay import ROWS as aws_status_rows, remediation as aws_status_remediation
    for check_id in aws_status_rows:
        value[check_id] = aws_status_remediation(check_id, value.get(check_id))
    from .checks.cloudtrail_management_description_overlay import remediation as trail_remediation
    if "aws.cloudtrail.management_events" in value:
        value["aws.cloudtrail.management_events"] = trail_remediation(value["aws.cloudtrail.management_events"])
    from .checks.finding_clarity_reviewed import ROWS as clarity_rows, remediation as concise_remediation
    from .checks.gcp_firewall_clarity_reviewed import ROWS as firewall_rows, remediation as firewall_remediation
    for check_id in clarity_rows:
        value[check_id] = concise_remediation(check_id, value.get(check_id))
    for check_id in firewall_rows:
        value[check_id] = firewall_remediation(check_id, value.get(check_id))
    from .checks.k8s_finding_clarity_reviewed import ROWS as k8s_rows, remediation as k8s_remediation
    from .checks.azure_finding_clarity_reviewed import ROWS as azure_rows, remediation as azure_remediation
    for check_id in k8s_rows:
        value[check_id] = k8s_remediation(check_id, value.get(check_id))
    for check_id in azure_rows:
        value[check_id] = azure_remediation(check_id, value.get(check_id))
    from .checks.aws_finding_clarity_reviewed import ROWS as aws_rows, remediation as aws_remediation
    for check_id in aws_rows:
        value[check_id] = aws_remediation(check_id, value.get(check_id))
    from .checks.gcp_scalar_clarity_reviewed import ROWS as scalar_rows, remediation as scalar_remediation
    for check_id in scalar_rows:
        value[check_id] = scalar_remediation(check_id, value.get(check_id))
    from .checks.k8s_workload_clarity_reviewed import ROWS as workload_rows, remediation as workload_remediation
    for check_id in workload_rows:
        value[check_id] = workload_remediation(check_id, value.get(check_id))
    from .checks.k8s_gc_threshold_source_correction import ROWS as gc_rows, remediation as gc_remediation
    for check_id in gc_rows:
        value[check_id] = gc_remediation(check_id, value.get(check_id))
    from .checks.gcp_remaining_clarity_reviewed import ROWS as gcp_remaining_rows, remediation as gcp_remaining_remediation
    for check_id in gcp_remaining_rows:
        value[check_id] = gcp_remaining_remediation(check_id, value.get(check_id))
    from .checks.aws_database_clarity_reviewed import ROWS as database_rows, remediation as database_remediation
    for check_id in database_rows:
        value[check_id] = database_remediation(check_id, value.get(check_id))
    from .checks.azure_bulk_clarity_reviewed import ROWS as bulk_rows, remediation as bulk_remediation
    for check_id in bulk_rows:
        value[check_id] = bulk_remediation(check_id, value.get(check_id))
    from .checks.aws_remaining_clarity_reviewed import ROWS as remaining_rows, remediation as remaining_remediation
    for check_id in remaining_rows:
        value[check_id] = remaining_remediation(check_id, value.get(check_id))
    from .checks.aws_final_clarity_reviewed import ROWS as final_rows, remediation as final_remediation
    for check_id in final_rows:
        value[check_id] = final_remediation(check_id, value.get(check_id))
    from .checks.aws_bulk_clarity_reviewed import ROWS as final_rows, remediation as final_remediation
    for check_id in final_rows:
        value[check_id] = final_remediation(check_id, value.get(check_id))
    from .checks.aws_compute_storage_clarity_reviewed import ROWS as final_rows, remediation as final_remediation
    for check_id in final_rows:
        value[check_id] = final_remediation(check_id, value.get(check_id))
    return value


def template(check_id: str, provider: str | None = None) -> dict | None:
    if check_id == "gcp_cloudsql_failed_attempts_lockout" and provider in (None, "gcp"):
        from .checks.gcp_cloudsql_lockout_source_correction import REMEDIATION, SOURCE_URL, correction_provenance
        return {"review_status": "approved", "summary": REMEDIATION,
                "steps": ["Bind the complete in-scope customer login-account universe and each authentication path.",
                          "Review documented managed user lockout policies and independent rate limiting for unsupported paths."],
                "caveats": ["API-visible user policy is configuration evidence, not complete principal scope or an observed login test."],
                "references": [{"title": "Cloud SQL user password policy API", "url": SOURCE_URL}],
                "source_correction": correction_provenance()}
    if check_id == "azure_vm_8_2_1_1_712e1ad" and provider in (None, "azure"):
        from .checks.azure_vm_ssh_source_correction import (REMEDIATION, SOURCE_URL,
                                                              correction_provenance)
        from .checks.azure_bulk_clarity_reviewed import dynamic_remediation
        return dynamic_remediation(check_id, {"review_status": "approved", "summary": REMEDIATION,
                "steps": ["Review the complete VM launch SSH public-key array and the applicable source criterion with the asset owner.",
                          "If this criterion is adopted, update the approved VM deployment configuration and verify the recorded array is explicitly empty."],
                "caveats": ["This criterion does not establish effective guest SSH or password authentication."],
                "references": [{"title": "Original Azure PCI source at pinned revision", "url": SOURCE_URL}],
                "source_correction": correction_provenance()})
    value = rules().get(f"{check_id}@{provider}") if provider else None
    if value is None:
        value = rules().get(check_id)
    return value if isinstance(value, dict) and value.get("review_status") == "approved" else None


def _bounded(value, expression):
    if not isinstance(value, str) or not value or len(value) > MAX_IDENTITY_LENGTH or not expression.fullmatch(value):
        return None
    return value


def identity_bindings(finding: dict) -> dict[str, str]:
    """Allowlisted identifiers only; invalid or unavailable identity is omitted.

    Bindings are for display/command placeholders. They are never accepted from
    arbitrary finding evidence. Every emitted value is shell-quoted downstream.
    """
    if not isinstance(finding, dict):
        return {}
    provider = finding.get("provider")
    scope = finding.get("scope")
    native = finding.get("native_resource_id") or finding.get("resource_id")
    name = finding.get("resource_name")
    values: dict[str, str] = {}
    if provider == "aws":
        matched = _SAFE_AWS_SCOPE.fullmatch(scope) if isinstance(scope, str) and len(scope) <= 128 else None
        if matched:
            values["ACCOUNT_ID"] = matched.group(1)
            if matched.group(2) and matched.group(2) != "global":
                values["REGION"] = matched.group(2)
        kind = _check_kinds().get(finding.get("check_id"))
        for value in (native, name):
            if kind == "ebs_snapshot" and _bounded(value, _SAFE_EBS_SNAPSHOT_ID):
                values["RESOURCE_ID"] = value
                break
            if kind == "ec2_image" and _bounded(value, _SAFE_EC2_IMAGE_ID):
                values["RESOURCE_ID"] = value
                break
            if _bounded(value, _SAFE_AWS_ID):
                values["RESOURCE_ID"] = value
                break
            if _bounded(value, _SAFE_S3_ARN):
                values["RESOURCE_ARN"] = value
                values["BUCKET_NAME"] = value.removeprefix("arn:aws:s3:::")
                values["RESOURCE_NAME"] = values["BUCKET_NAME"]
                break
            if _bounded(value, _SAFE_AWS_ARN):
                if "ACCOUNT_ID" in values and value.split(":", 5)[4] != values["ACCOUNT_ID"]:
                    continue
                values["RESOURCE_ARN"] = value
                break
        if kind == "ecr_repository" and isinstance(native, str):
            ecr = _SAFE_ECR_ARN.fullmatch(native)
            if ecr and ("ACCOUNT_ID" not in values or values["ACCOUNT_ID"] == ecr.group(1)) and _bounded(ecr.group(2), _SAFE_ECR_NAME):
                values["REPOSITORY_NAME"] = ecr.group(2)
                values["RESOURCE_NAME"] = ecr.group(2)
        expression = _AWS_NAMED_KINDS.get(kind)
        if expression and _bounded(name, expression):
            values["RESOURCE_NAME"] = name
            if kind == "bucket":
                values["BUCKET_NAME"] = name
            if kind == "iam_policy" and "RESOURCE_ARN" in values:
                values["POLICY_ARN"] = values["RESOURCE_ARN"]
            if kind == "ecr_repository":
                values["REPOSITORY_NAME"] = name
    elif provider == "gcp":
        matched = (_SAFE_GCP_SCOPE.fullmatch(scope) or _SAFE_GCP_LOCATION_SCOPE.fullmatch(scope)) if isinstance(scope, str) and len(scope) <= 128 else None
        if matched:
            project = matched.group(1)
            values["PROJECT_ID_OR_NUMBER"] = project
            values["PROJECT_NUMBER" if project.isdecimal() else "PROJECT_ID"] = project
            if matched.lastindex and matched.lastindex > 1:
                values["LOCATION"] = matched.group(2)
        elif isinstance(scope, str) and len(scope) <= 128:
            parent = _SAFE_GCP_PARENT_SCOPE.fullmatch(scope)
            if parent:
                values["ORGANIZATION_ID" if parent.group(1) == "organizations" else "FOLDER_ID"] = parent.group(2)
        if _bounded(finding.get("location"), _SAFE_LOCATION):
            values["LOCATION"] = finding["location"]
        kind = _check_kinds().get(finding.get("check_id"))
        expression = _SAFE_GCP_COMPUTE_NAME if kind in {"firewall", "instance"} else _SAFE_GCP_NAME
        for value in (name, native):
            if _bounded(value, expression):
                values["RESOURCE_NAME"] = value
                break
    elif provider == "azure":
        matched = _SAFE_AZURE_ARM.fullmatch(native) if isinstance(native, str) and len(native) <= MAX_IDENTITY_LENGTH else None
        if matched:
            values["RESOURCE_ID"] = native
            values["SUBSCRIPTION_ID"] = matched.group(1)
            values["RESOURCE_GROUP"] = matched.group(2)
            leaf = native.rsplit("/", 1)[-1]
            if _bounded(leaf, _SAFE_GCP_NAME):
                values["RESOURCE_NAME"] = leaf
        if _bounded(finding.get("location"), _SAFE_LOCATION):
            values["LOCATION"] = finding["location"]
    elif provider == "k8s":
        matched = _SAFE_K8S_NATIVE.fullmatch(native) if isinstance(native, str) and len(native) <= MAX_IDENTITY_LENGTH else None
        if matched:
            cluster, kind, namespace, object_id = (unquote(part) for part in matched.groups())
            if all(len(part) <= MAX_IDENTITY_LENGTH for part in (cluster, kind, namespace, object_id)):
                if len(cluster) <= 253 and _bounded(cluster, _SAFE_K8S_NAME):
                    values["CLUSTER"] = cluster
                if _bounded(kind, _SAFE_K8S_KIND):
                    values["KIND"] = kind
                if len(namespace) <= 253 and _bounded(namespace, _SAFE_K8S_NAME) and namespace != "_cluster":
                    values["NAMESPACE"] = namespace
                if isinstance(finding.get("resource_name"), str) and len(finding["resource_name"]) <= 253 and _bounded(finding["resource_name"], _SAFE_K8S_NAME):
                    values["RESOURCE_NAME"] = finding["resource_name"]
    return values


_PLACEHOLDER = re.compile(r"<([A-Z][A-Z0-9_]*)>")


def bind_command(code: str, finding: dict) -> str:
    """Replace only known placeholders with shell-quoted allowlisted identity.

    Unknown placeholders remain visible for the operator. No evidence value is
    interpolated here; approved CIDRs, rule IDs and replacement files stay blank.
    """
    bound = identity_bindings(finding)
    return _PLACEHOLDER.sub(lambda match: shlex.quote(bound[match.group(1)]) if match.group(1) in bound else match.group(), code)


def exposure_action(evidence, status):
    """One next action from an exposure finding; never interpret an UNKNOWN as open."""
    evidence = evidence if isinstance(evidence, dict) else {}
    if status in ("UNKNOWN", "DENIED", "MANUAL", "EMPTY"):
        return "Collect the missing configuration before deciding whether access needs to change."
    if status == "PASS":
        return "Keep the access restrictions in place."
    if evidence.get("exposure_kind") == "external_log_stream":
        return "Review the CloudWatch Logs subscription destination; remove or redirect an unintended external export."
    if evidence.get("exposure_kind") == "public_registry":
        return "Review whether this ECR Public repository is intended; remove or migrate it if its images should be private."
    if evidence.get("exposure_kind") == "external_network":
        source = evidence.get("source") if isinstance(evidence.get("source"), dict) else {}
        if source.get("resource_type") == "transit_gateway_attachment":
            return "Review whether the route to this foreign Transit Gateway attachment is needed; remove unnecessary routes or attachments."
        return "Review whether this VPC peering route and external account connection are needed; remove unnecessary routes or peering."
    if evidence.get("exposure_kind") == "external_share" or evidence.get("external_scope_ids"):
        source = evidence.get("source") if isinstance(evidence.get("source"), dict) else {}
        if source.get("resource_type") == "ec2_image":
            return "Restrict AMI launch permission to the accounts, organizations or OUs that need it."
        return "Restrict snapshot restore access to the accounts that need it."
    if evidence.get("data_exposure"):
        source = evidence.get("source") if isinstance(evidence.get("source"), dict) else {}
        if source.get("resource_type") == "ec2_image":
            return "Remove public AMI launch permission if broad sharing is unnecessary."
        if source.get("resource_type") in ("rds_snapshot", "rds_cluster_snapshot"):
            return "Remove public snapshot restore access; share only with the accounts that need it."
        return "If public data access is unnecessary, restrict the granting policy or ACL to the readers that need it."
    if evidence.get("exposure_kind") == "control_plane":
        return "Restrict control-plane access to the source networks that need it."
    return "Consider whether this endpoint needs internet access; restrict unnecessary source networks or ports."


def exposure_details(finding, details):
    """Adapt presentation without changing stored evidence, verdicts or shared templates."""
    if finding.get("check_id") != "analysis.internet_exposure" or not isinstance(details, dict):
        return details
    action = exposure_action(finding.get("evidence"), finding.get("status"))
    return dict(details, summary=action, steps=[action])


def details_for(check_id: str, finding: dict | None = None, provider: str | None = None) -> dict | None:
    value = template(check_id, provider or (finding or {}).get("provider"))
    if value is None:
        return None
    result = {key: item for key, item in value.items() if key not in {"review_status", "field_binding", "proposed_spec_sha256"}}
    if finding:
        result["cli"] = [dict(command, code=bind_command(command["code"], finding)) for command in value.get("cli", [])]
    return exposure_details(finding, result) if finding else result


def report_templates(check_ids, provider: str | None = None) -> dict[str, dict]:
    return {cid: details_for(cid, provider=provider) for cid in sorted(set(check_ids)) if template(cid, provider) is not None}
