"""Native-free exact remediation identity, command, and exposure presentation.

Generated from peaso/remediation.py by build_proposal.py; use only with a
verified materialized catalog. No checks package is imported here.
"""
from __future__ import annotations
from functools import lru_cache
import re
import shlex
from urllib.parse import unquote

@lru_cache(maxsize=1)
def _check_kinds() -> dict[str, str]:
    from peaso.server.materialized_catalog import native_kinds
    return {cid: kind for cid, (_, kind) in native_kinds().items()}

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
    if evidence.get("exposure_kind") == "external_registry_share":
        return "Restrict the ECR repository policy to the accounts and roles that need image pull access."
    if evidence.get("exposure_kind") == "external_registry_policy_pull":
        return "Restrict the ECR registry policy's image-pull actions to intended accounts and repositories."
    if evidence.get("exposure_kind") == "external_registry_template_pull":
        return "Restrict the ECR creation template's repository policy before it is applied to new repositories."
    if evidence.get("exposure_kind") == "external_redshift_snapshot_share":
        return "Revoke Redshift manual snapshot restore access for accounts that should not receive the snapshot, and review its KMS key access."
    if evidence.get("exposure_kind") == "external_redshift_serverless_snapshot_share":
        return "Revoke Redshift Serverless snapshot restore access for accounts that should not receive the snapshot, and review its KMS key access."
    if evidence.get("exposure_kind") == "external_cluster_snapshot_share":
        return "Restrict the DocumentDB or Neptune manual snapshot restore attribute to intended accounts, and review its KMS key access."
    if evidence.get("exposure_kind") == "external_generic_policy_grant":
        return "Restrict this resource policy to the intended AWS principals, actions and resource paths."
    if evidence.get("exposure_kind") == "vpn_client_authorization":
        return "Restrict the Client VPN authorization rule to intended user groups and destination networks, and review its route and security controls."
    if evidence.get("exposure_kind") == "external_secret_grant":
        return "Restrict the secret resource policy and customer KMS key policy to the intended readers."
    if evidence.get("exposure_kind") == "external_queue_receive":
        return "Restrict the SQS queue policy and any customer KMS key policy to the intended message consumers."
    if evidence.get("exposure_kind") == "external_topic_subscription":
        return "Review the SNS topic subscription owner and remove subscriptions that should not receive topic messages."
    if evidence.get("exposure_kind") == "external_topic_subscribe_grant":
        return "Restrict the SNS topic policy's Subscribe grant to intended accounts and endpoint conditions."
    if evidence.get("exposure_kind") == "external_kms_decrypt_grant":
        return "Restrict the KMS key policy's Decrypt grant to the accounts and roles that need it."
    if evidence.get("exposure_kind") == "external_kms_grant":
        return "Review and revoke the KMS grant if this foreign grantee should not decrypt with the key."
    if evidence.get("exposure_kind") == "external_lambda_invoke":
        return "Restrict the Lambda function or alias policy's InvokeFunction grant to intended callers."
    if evidence.get("exposure_kind") == "external_layer_share":
        return "Restrict the Lambda layer version policy's GetLayerVersion grant to intended accounts."
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


_PLACEHOLDER = re.compile(r"<([A-Z][A-Z0-9_]*)>")

