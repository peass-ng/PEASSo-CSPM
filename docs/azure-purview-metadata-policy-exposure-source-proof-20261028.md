# Classic Purview Data Map collection roles

## Source operations

- [Metadata Policy List All](https://learn.microsoft.com/en-us/rest/api/purview/metadatapolicydataplane/metadata-policy/list-all?view=rest-purview-metadatapolicydataplane-2021-07-01-preview) documents a read-only `GET {account}.purview.azure.com/policyStore/metadataPolicies?api-version=2021-07-01-preview`, a `values` list, and `nextLink` pagination. Its example shows `attributeRules` with built-in role IDs and `principal.microsoft.id` or `principal.microsoft.groups` object IDs.
- [Purview collection role tutorial](https://learn.microsoft.com/en-us/purview/legacy/tutorial-metadata-policy-collections-apis) explains that Purview collection role assignments moved to the data plane and lists the roles and policy API. [Data-plane authentication](https://learn.microsoft.com/en-us/purview/data-gov-api-rest-data-plane) specifies the `https://purview.azure.net` resource audience.
- [Purview Data Map permissions](https://learn.microsoft.com/en-us/purview/data-gov-classic-permissions) describes catalog reader, curator, and collection administrator rights. These are rights to catalog metadata; underlying data source access is separate.

## Native evidence

`azure_purview_metadata_policy_native.collect` binds each GET host to a previously listed ARM account, uses the Azure per-scan response cache and normal page budget, and projects only collection, built-in role, and principal object IDs. Descriptions and unrelated policy expressions are discarded. `internet_exposure._azure_purview_metadata_policy` reports catalog metadata exposure for a direct Guest or foreign-owned service principal with a reader, curator, or collection administrator role, or an observed foreign member of a granted group. The shared Graph membership collector uses its service-principal-inclusive beta route for Purview scans. Unresolved group membership, custom roles, unsupported conditions, and unknown object ownership remain `UNKNOWN`.

The Microsoft Purview product review is still open. This operation covers classic Data Map roles. Unified Catalog policies have a [separate policy API](https://learn.microsoft.com/en-us/rest/api/purview/purview-unified-catalog/policies/list?view=rest-purview-purview-unified-catalog-2026-03-20-preview), and source data permissions remain with their source services.
