"""Versioned correction of the ECR public-access control to its pinned private-ECR SQL."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json

CHECK_ID = "aws_g6_ecr_public_repositories_absent"
PRIOR_FROZEN_SPEC_SHA256 = "31ab35b82595e292dcd3e8870c373134ba3fca0fe09f592239783e73eda15d24"
SOURCE_URL = "https://raw.githubusercontent.com/turbot/steampipe-mod-aws-compliance/803dda1f7555ed5cea959aef30cfa0719b030d8c/conformance_pack/ecr.pp#L18-L113"
SOURCE_SHA256 = "06c03759465ebbc1622f1ea22def7bb6262c24e9f6c2df5950cdc6ac1db37e72"
PLUGIN_REV = "abf4584ae2fa75961bf281c2afe45d718956668b"
PLUGIN_TABLE_URL = f"https://raw.githubusercontent.com/turbot/steampipe-plugin-aws/{PLUGIN_REV}/aws/table_aws_ecr_repository.go#L132-L145"
PLUGIN_TABLE_SHA256 = "ab9f8707745396a184a5e3b6aa2532d14e66b614266d74a657b98a2ce1f4de1d"
PLUGIN_CANONICAL_URL = f"https://raw.githubusercontent.com/turbot/steampipe-plugin-aws/{PLUGIN_REV}/aws/canonical_policy.go"
PLUGIN_CANONICAL_SHA256 = "c09ac820020249aa208775cb387b0f9ec227f9b20f54e98d7563988df479686e"


def _digest(value):
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(value.encode()).hexdigest()


TITLE = "Private ECR repository policy has no wildcard AWS principal"
DESCRIPTION_TEXT = (
    "Checks the pinned upstream SQL over each private ECR repository's standardized "
    "policy_std: an Allow statement with literal * in canonical Principal.AWS and "
    "a nonempty canonical Action array fails. The plugin maps bare Principal=* and "
    "scalar AWS principals and Actions into arrays. Conditions are ignored by that SQL; "
    "this is not an effective public-access determination or ECR Public inventory test."
)
DATA_SOURCE = (
    "Read-only regional ecr:DescribeRepositories and repository-bound "
    "ecr:GetRepositoryPolicy policyText, normalized according to the pinned plugin "
    "policyToCanonical transform; documented policy-absence marker."
)
PREDICATE = (
    "For each completely collected private ECR repository, canonicalize the exact "
    "bound policy as policy_std does: wrap a single Statement, map bare Principal=* "
    "to Principal.AWS=[*], and wrap scalar AWS principals and Actions in arrays. "
    "FAIL when an Allow Statement has literal * in canonical Principal.AWS and a "
    "nonempty canonical Action array; PASS when the policy is documented absent or "
    "a complete well-formed standardized policy has no such row. UNKNOWN on denied, "
    "partial, malformed, foreign, or unsupported policy shapes. Conditions are "
    "ignored by the pinned SQL. No effective-access claim is made."
)
REMEDIATION = (
    "Review the repository policy and remove an unintended literal wildcard AWS "
    "principal from Allow statements; evaluate conditions and effective access separately."
)
CORRECTED_SPEC = {
    "id": CHECK_ID, "provider": "aws", "resource_kind": "ecr_repository",
    "data_source": DATA_SOURCE, "predicate": PREDICATE, "severity": "high",
    "category": "exposure", "title": TITLE, "description": DESCRIPTION_TEXT,
    "remediation_hint": REMEDIATION,
}
CORRECTED_SPEC_SHA256 = _digest(CORRECTED_SPEC)
PREDICATE_SHA256 = _digest(PREDICATE)
SOURCE_CORRECTION = {
    "version": "peaso-source-correction-v2",
    "status": "source_erratum_successor",
    "prior_frozen_signed_spec_sha256": PRIOR_FROZEN_SPEC_SHA256,
    "prior_frozen_status": "historical_superseded_for_this_check",
    "current_canonical_spec_sha256": CORRECTED_SPEC_SHA256,
    "current_predicate_sha256": PREDICATE_SHA256,
    "source_url": SOURCE_URL,
    "source_sha256": SOURCE_SHA256,
    "source_query": "ecr_repository_prohibit_public_access",
    "plugin_table_url": PLUGIN_TABLE_URL,
    "plugin_table_sha256": PLUGIN_TABLE_SHA256,
    "plugin_canonicalizer_url": PLUGIN_CANONICAL_URL,
    "plugin_canonicalizer_sha256": PLUGIN_CANONICAL_SHA256,
    "framework_id": "aws-compliance.benchmark.nist_csf_v2",
    "requirement_ids": ["aws-compliance.control.ecr_repository_prohibit_public_access"],
    "criterion_scope": "Per private ECR repository standardized policy_std; canonical Principal.AWS wildcard and Action array; no ECR Public registry assertion",
}
DESCRIPTION = {
    "title": TITLE,
    "description": DESCRIPTION_TEXT,
    "evaluated": [DATA_SOURCE, "Complete same-scope private ecr_repository inventory and standardized exact policy detail"],
    "pass_when": "The exact policy is documented absent, or a complete standardized policy has no pinned wildcard row.",
    "fail_when": "An Allow statement has literal * in canonical Principal.AWS and a nonempty canonical Action array.",
    "not_applicable_when": "No per-repository exclusion; an empty complete regional inventory has no resource finding.",
    "unknown_when": "Inventory or exact policy detail is denied, incomplete, malformed, or foreign.",
    "remediation": REMEDIATION,
    "evaluator_version": "2.1.0",
    "source_correction": SOURCE_CORRECTION,
}


def description():
    return deepcopy(DESCRIPTION)


def correction_provenance():
    return deepcopy(SOURCE_CORRECTION)
