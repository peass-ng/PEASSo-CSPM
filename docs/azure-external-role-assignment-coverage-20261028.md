# Azure role assignments to outside identities

| Exposure primitive | Native decision | Test |
| --- | --- | --- |
| Direct ARM assignment to an observed Guest user | Outside principal declaration is FAIL with assignment scope and principal evidence | `test_direct_azure_external_role_assignment_preserves_condition` |
| Direct ARM assignment to an observed foreign-owned service principal | Outside owner tenant is classified from Graph and the assignment is flagged | `test_direct_azure_external_role_assignment_preserves_condition` |
| ARM assignment to a group with nested outside members | Observed transitive member and membership path are flagged | `test_azure_group_role_assignment_reaches_nested_guest`; `test_role_assignment_scan_uses_beta_membership_for_service_principals` |
| Conditional assignment to an outside principal | Condition remains in evidence and the verdict is MANUAL | `test_direct_azure_external_role_assignment_preserves_condition` |
| Unattributed assignee or partial group membership | Unknown identity yields UNKNOWN; incomplete membership does not prove an outside member absent | `test_unattributed_azure_role_assignee_is_unknown`; `test_azure_group_role_assignment_without_observed_external_member_is_not_claimed` |

Residual UNKNOWN/MANUAL handling: PIM activation, effective denies, incomplete Graph reads, uncollected ownership, and the business need for access remain unproven. The finding reports a declared grant or observed outside membership, not a successful data-plane operation.
