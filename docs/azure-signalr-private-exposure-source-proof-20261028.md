# Azure SignalR foreign private endpoint exposure source proof

The read-only [SignalR GET](https://learn.microsoft.com/en-us/rest/api/signalr/signalr/get?view=rest-signalr-2024-03-01) returns parent `privateEndpointConnections`, connection approval/provisioning state, remote private-endpoint IDs, `networkACLs.privateEndpoints`, and client/server ports. The collector already performs a per-scan cached LIST and now performs one GET per parent at this API version to ensure these fields are present.

[SignalR network access controls](https://learn.microsoft.com/en-us/azure/azure-signalr/howto-network-access-control) apply request-type rules to each named private endpoint; IP rules apply only to public traffic. Native analysis joins an approved foreign-subscription connection to its named private-endpoint ACL and reports only request types admitted by the effective default/allow/deny rules. It evaluates private links even when public network access is disabled. Missing or malformed status/ACL produces UNKNOWN for an otherwise blocked public path.

Focused tests cover a foreign approved connection with client request rights, a denied connection, a local connection, no connections, missing ACL, and an independently open public path. They verify one detail GET per parent and both public/client and server ports.
