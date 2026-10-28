# Microsoft Entra foreign application consent: source proof

## Native evidence and scope

Microsoft Graph [lists OAuth2 delegated permission grants](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0). The [grant resource](https://learn.microsoft.com/en-us/graph/api/resources/oauth2permissiongrant?view=graph-rest-1.0) identifies the client and resource service principals, permission scopes, and whether consent applies to all users or one user. Graph also [lists service principal app-role assignments](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments?view=graph-rest-1.0); an [assignment](https://learn.microsoft.com/en-us/graph/api/resources/approleassignment?view=graph-rest-1.0) identifies its principal, resource and app role. The [service principal resource](https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipal?view=graph-rest-1.0) includes `appOwnerOrganizationId` and `appRoles`.

The collector already obtains delegated grants, application assignments and service principals. Selection of either grant type now also selects service principals. Native analysis uses the existing verified-tenant ownership classifier and emits a foreign-client finding only when it resolves the grantee service principal to an outside organization, the client is enabled, the grant fields are complete, and an application role is enabled and resolved to a value. Default, disabled, missing-role, denied-inventory and unattributed cases remain `UNKNOWN`. It reports configured access, not proof that an access token was used or data was read.

## Limit

These Graph objects describe Entra consent and application roles. They cannot establish every relying application's downstream authorization rules or enumerate actual recipients of data outside that application. The broader Microsoft Entra ID product review remains open.
