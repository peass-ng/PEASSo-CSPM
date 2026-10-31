"""Clarification of the signed declared-attachment criterion."""
from copy import deepcopy

CHECK_ID = "aws.pci.iam.policy_attached_to_active_principal"
SIGNED_SPEC_SHA256 = "f2390003d62e24de8ca096e700f28a0fc91bc87b02b76c8f51d11963918b797c"
ORIGINAL_DESCRIPTION_SHA256 = "f4c9f8e3d24a766fc44fc51de6ee4b8b9466a880812775a6f7d017cdc6aa47aa"


def description(original):
    row = deepcopy(original) if isinstance(original, dict) else {}
    row.update({
        "description": "Checks whether a managed IAM policy is declared attached to a user, a populated group, or a role with a documented literal trust-principal form. This assesses configuration only; principal existence, policy use, successful role assumption, effective access, and principal activity are unassessed.",
        "evaluated": ["Complete iam:GetAccountAuthorizationDetails policy, user, group, and role inventories",
                      "AttachmentCount and each principal's AttachedManagedPolicies",
                      "UserDetail.GroupList membership and RoleDetail.AssumeRolePolicyDocument trust"],
        "pass_when": "The exact policy is attached to a user, a group with at least one bound user, or a role with a declared STS assumption allow and a syntactically recognized AWS, service, or federated principal.",
        "fail_when": "Complete bound inventories prove the policy unattached or attached only to empty groups or roles without a trusted principal.",
        "not_applicable_when": None,
        "unknown_when": "Any needed inventory, identity, count, membership, trust, or field evidence is denied, partial, foreign, contradictory, or malformed; orphaned raw principal IDs, unsupported principal forms, and effective trust ambiguity remain UNKNOWN.",
        "description_correction": {
            "version": "pci-iam-declared-attachment-description-v1",
            "signed_spec_sha256": SIGNED_SPEC_SHA256,
            "base_row_sha256": ORIGINAL_DESCRIPTION_SHA256,
            "source_relationship": "Clarifies the signed configured-attachment predicate; the original signed pack remains unchanged and does not require observed service activity.",
            "source_contract_path": "docs/compliance-ledgers/new-checks-aws.json#aws.pci.iam.policy_attached_to_active_principal",
            "official_references": [
                "https://docs.aws.amazon.com/IAM/latest/APIReference/API_UserDetail.html",
                "https://docs.aws.amazon.com/IAM/latest/APIReference/API_ManagedPolicyDetail.html",
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html",
            ],
        },
    })
    return row
