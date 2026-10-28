# Azure Compute Gallery exposure coverage

| Exposure primitive | Native decision | Test |
| --- | --- | --- |
| Community gallery sharing | Declared public-sharing capability is flagged | `test_compute_gallery_community_and_direct_sharing_policy` |
| Direct sharing with another subscription or Entra tenant | Foreign recipient is flagged; owner-only recipients do not create that sharing path | `test_compute_gallery_community_and_direct_sharing_policy` |
| Published image definitions and versions | Child inventory is joined to the sharing decision; partial pages are retained as incomplete | `test_gallery_public_policy_reports_observed_versions_and_partial_child_inventory`; `test_gallery_image_versions_are_read_once_with_bound_identities` |
| Azure RBAC image-version read grant to a foreign principal or observed group descendant | Native principal finding records the outside grant and membership path | `test_azure_gallery_image_read_role_grant_to_external_guest`; `test_azure_gallery_image_read_inherited_through_observed_group_member` |
| Inherited deny assignment for all principals | A matching unconditional image-read deny blocks the specific observed RBAC path | `test_azure_gallery_image_read_role_grant_to_external_guest` |

Residual UNKNOWN handling: missing or malformed sharing groups, unverified owner tenant, partial image or group inventory, conditional grants, principal exclusions, narrower deny scopes, PIM activation, and unattributable principals do not prove absence of access. A sharing capability does not claim an image version is already published. No live image retrieval is attempted.
