"""Source erratum: the signed customer-policy predicate needs customer-only evidence.

The signed proposal and compiled packs are immutable historical ancestry.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

CHECK_ID = "aws.pci.iam.wildcard_action_scoped_resource"
PRIOR_FROZEN_SPEC_SHA256 = "704541e545d3efa379f411ebef70f39965c1db02496bddda6853da2c2132b820"
FROZEN_SPEC = {
    "id": CHECK_ID,
    "provider": "aws",
    "resource_kind": "iam_policy",
    "data_source": "existing collected type iam_policy + PolicyDocument.Statement[].Action and Resource",
    "predicate": "No customer managed policy Allow statement grants Action:* to an individual resource ARN, including NotAction equivalents",
    "severity": "high",
    "category": "hardening",
    "title": "IAM policies avoid all actions on scoped resources",
    "description": "Detects an IAM policy with an Allow Action:* or equivalent NotAction on a resource ARN; this can grant access beyond the approved identities, scope or lifetime.",
    "remediation_hint": "Replace Allow statements using Action:* or equivalent NotAction with explicit required actions and Resource ARNs.",
}


def _digest(value):
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(value.encode()).hexdigest()


TITLE = "IAM policies avoid all actions on scoped resources"
DATA_SOURCE = "iam:ListPolicies Scope=Local OnlyAttached=False; iam:GetPolicyVersion exact default document"
PREDICATE = (
    "For each customer-managed default policy, FAIL when an Allow statement pairs an individual "
    "resource ARN with Action=* or a service:* action, or an equivalent broad NotAction. "
    "PASS for a complete customer policy whose default document has no such statement. "
    "UNKNOWN on denied, partial, malformed, duplicate, foreign, or mismatched native evidence. "
    "AWS-managed and inline policies are outside this per-policy predicate."
)
DESCRIPTION_TEXT = (
    "Checks each customer-managed IAM policy default document for a declared broad Allow action "
    "on an individual resource ARN. The source collection includes unattached customer policies "
    "and excludes AWS-managed policies; this is a declared policy-shape assessment."
)
REMEDIATION = FROZEN_SPEC["remediation_hint"]
CORRECTED_SPEC = {
    "id": CHECK_ID, "provider": "aws", "resource_kind": "iam_customer_policy",
    "data_source": DATA_SOURCE, "predicate": PREDICATE, "severity": "high",
    "category": "hardening", "title": TITLE, "description": DESCRIPTION_TEXT,
    "remediation_hint": REMEDIATION,
}
SOURCE_CORRECTION = {
    "version": "peaso-source-correction-v1",
    "status": "source_erratum_successor",
    "prior_frozen_signed_spec_sha256": PRIOR_FROZEN_SPEC_SHA256,
    "prior_frozen_status": "historical_superseded_for_this_check",
    "current_canonical_spec_sha256": _digest(CORRECTED_SPEC),
    "current_predicate_sha256": _digest(PREDICATE),
    "source_contract_path": "docs/compliance-ledgers/new-checks-aws.json#aws.pci.iam.wildcard_action_scoped_resource",
    "source_description_path": "docs/compliance-ledgers/descriptions/implemented-new-checks.json#aws.pci.iam.wildcard_action_scoped_resource",
    "criterion_scope": "Customer-managed default policies, attached or unattached; individual resource ARN; declared Action/NotAction shape",
    "erratum": "The signed predicate says customer managed but names the mixed iam_policy projection; use the native Local customer-policy universe.",
}
DESCRIPTION = {
    "title": TITLE, "description": DESCRIPTION_TEXT, "evaluated": [DATA_SOURCE],
    "pass_when": "The customer-managed default document has no broad Allow action on an individual resource ARN.",
    "fail_when": "A broad Action or NotAction equivalent is declared on an individual resource ARN.",
    "not_applicable_when": "No per-customer-policy exclusion; AWS-managed policies are outside the customer collection.",
    "unknown_when": "The customer policy collection or exact default document is denied, incomplete, malformed, duplicate, or foreign.",
    "remediation": REMEDIATION, "evaluator_version": "2.0.0", "source_correction": SOURCE_CORRECTION,
}


def description():
    return deepcopy(DESCRIPTION)


def correction_provenance():
    return deepcopy(SOURCE_CORRECTION)
