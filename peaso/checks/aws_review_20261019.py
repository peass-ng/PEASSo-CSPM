"""Register only the AWS security extensions admitted by the reviewed compiler.

Predicates remain pure. The supervisor manifest binds specifications, source
references, descriptions and formal requirement links independently of this hook.
"""
from copy import deepcopy
from importlib import import_module
import re

from . import CHECKS, register
from .facts import Unavailable, get

MODULES = (
    "aws_kms_enclave_review_20261019", "aws_policy_constraints_review_20261019",
    "aws_bedrock_review_20261019", "aws_configuration_secret_review_20261019",
    "aws_enclave_debug_review_20261019",
    "aws_additional_secret_review_20261019", "aws_s3_object_acl_review_20261019",
    "aws_service_status_review_20261019",
    "aws_configuration_payload_secret_review_20261019",
    "aws_code_log_content_review_20261019",
    "aws_package_content_review_20261019",
    "aws_lambda_role_policy_review_20261019",
    "aws_cognito_rotation_review_20261019",
)


def _bound_kms(item, index):
    scope = get(index, "context.scope", str)
    match = re.fullmatch(r"([0-9]{12})/([a-z0-9-]+)", scope)
    if get(index, "context.provider", str) != "aws" or match is None:
        raise Unavailable("KMS account and Region context unavailable")
    key_id = get(item, "KeyId", str)
    metadata = get(item, "Metadata.KeyMetadata", dict)
    arn = get(metadata, "Arn", str)
    identity = re.fullmatch(r"arn:(aws(?:-[a-z0-9-]+)?):kms:([^:]+):([0-9]{12}):key/(.+)", arn)
    if (identity is None or identity[2] != match[2] or identity[3] != match[1] or
            identity[4] != key_id or get(metadata, "KeyId", str) != key_id or
            ("KeyArn" in item and get(item, "KeyArn", str) != arn)):
        raise Unavailable("KMS metadata does not match the assessed native key")


def _forward(function, check_id):
    def reviewed_predicate(item, index):
        if check_id.startswith("aws.review.kms.enclave_") and check_id != "aws.review.kms.enclave_debug_measurements":
            _bound_kms(item, index)
        status, evidence = function(item, index)
        if check_id.startswith("aws.review.kms.enclave_") and "sensitive_allow_statements" in evidence:
            count, bad = evidence["sensitive_allow_statements"], len(evidence["violating_statement_sids"])
            if check_id.endswith("attestation_enforced"):
                text = (f"{bad} sensitive Allow statements do not require enclave attestation." if bad else
                        f"All {count} sensitive Allow statements require enclave attestation.")
            elif check_id.endswith("no_bypass"):
                text = (f"{bad} sensitive Allow statements have no proved attestation guard." if bad else
                        f"All {count} sensitive Allow statements have a proved attestation guard.")
            else:
                text = (f"{bad} attested Allow statements lack a fixed deployment binding." if bad else
                        "Every attested sensitive Allow has a fixed deployment binding.")
            evidence = {**evidence, "observed": text}
        return status, evidence
    reviewed_predicate.reviewed_target = function
    empty = getattr(function, "evaluate_empty_inventory", None)
    if callable(empty):
        reviewed_predicate.evaluate_empty_inventory = empty
    return reviewed_predicate


def _kms_runtime_cases():
    scope = "123456789012/us-east-1"
    key_id = "11111111-2222-3333-4444-555555555555"
    arn = "arn:aws:kms:us-east-1:123456789012:key/" + key_id
    def item(condition):
        statement = {"Effect": "Allow", "Principal": "*", "Action": "kms:Decrypt", "Resource": "*"}
        if condition is not None:
            statement["Condition"] = condition
        return {"KeyId": key_id, "KeyArn": arn, "Metadata": {"collection_status": "collected", "KeyMetadata": {
            "KeyId": key_id, "Arn": arn, "KeyManager": "CUSTOMER", "KeyState": "Enabled", "Description": "Nitro enclave"}},
            "Policy": {"collection_status": "collected", "Policy": {"Statement": [statement]}}, "Tags": [], "Aliases": []}
    def index(row):
        return {"context": {"provider": "aws", "scope": scope},
                "collections": {"kms_key": [{"type": "kms_key", "scope": scope, "status": "collected", "items": [row]}]},
                "kms_key": [{"type": "kms_key", "scope": scope, "data": row}]}
    result = {}
    for suffix in ("attestation_enforced", "no_bypass", "deployment_binding"):
        good = item({"StringEquals": {"kms:RecipientAttestation:PCR3": "ab" * 48}})
        bad = item({"StringEquals": {"kms:RecipientAttestation:PCR0": "ab" * 48}} if suffix == "deployment_binding" else None)
        result["aws.review.kms.enclave_" + suffix] = {"pass": good, "fail": bad, "pass_index": index(good),
                                                       "fail_index": index(bad), "missing": {}, "malformed": None}
    return result


def install():
    from .fixtures import CASES
    declarations, cases = [], _kms_runtime_cases()
    for name in MODULES:
        module = import_module("peaso.checks." + name)
        rows = module.ADMISSION_DATA["checks"]
        raw = getattr(module, "DECLARATIONS", getattr(module, "SPECS", []))
        raw = list(raw.values()) if isinstance(raw, dict) else raw
        options = {r["id"]: r for r in raw}
        cases.update(deepcopy(getattr(module, "RUNTIME_CASES", {})))
        for row in rows:
            spec = row["spec"]
            declaration = {**{k: row[k] for k in ("dependencies", "target") if k in row},
                           **options.get(spec["id"], {})}
            function_name = row["function"].split(":", 1)[1]
            function = getattr(module, function_name)
            declarations.append((spec, declaration, function))
    ids = {spec["id"] for spec, _, _ in declarations}
    if len(ids) != len(declarations) or ids - cases.keys():
        raise ValueError("Every reviewed AWS extension requires unique behavior cases")
    existing = ids & {check.id for check in CHECKS}
    if existing:
        if existing == ids:
            return
        raise ValueError("Partial AWS extension registration")
    for spec, declaration, function in declarations:
        register(spec["id"], spec["provider"], spec["category"], spec["resource_kind"], spec["title"],
                 spec["severity"], declaration.get("control", "security_configuration"), spec["remediation_hint"],
                 target=declaration.get("target", "resource"),
                 dependencies=declaration.get("dependencies", [spec["resource_kind"]]),
                 allow_incomplete_failure=declaration.get("allow_incomplete_failure", False))(_forward(function, spec["id"]))
    CASES.update(cases)
