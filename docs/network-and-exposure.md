# Network and exposure analysis

This page covers the analysis that looks across resources: which assets look reachable from the
internet, whether selected private flows are allowed, which principals are public or external,
and how network and IAM graphs are built. All of it runs offline on the snapshot. **No traffic is
ever sent** and no endpoint is probed.

The code lives in `peaso/analysis/`.

## Analysis checks

These checks appear in reports next to native checks:

| ID | Category | What it reports |
| --- | --- | --- |
| `analysis.internet_exposure` | exposure | Per asset: `FAIL` when the configured layers allow inbound internet traffic, `PASS` when a layer blocks it, `UNKNOWN` when a layer's facts are missing |
| `analysis.exposed_privileged_workload` | exposure | A workload that looks internet-reachable and runs with a privileged identity |
| `analysis.principal_exposure` | exposure | Resource or trust policies that name public or external principals |
| `analysis.federated_trust` | exposure | Federated (OIDC) trust that is not pinned to a specific subject |
| `analysis.coverage` | least_privilege | Missing or failed inventory that limits the other analysis; only `UNKNOWN` |

`analysis.grant_review`, `analysis.inactive_identity` and `analysis.network_review` are
manual-only projections kept for older reports; they are not offered for new scans.

## Internet exposure

For each asset, the analysis walks the layers that decide whether inbound internet traffic can
reach it, using only recorded configuration:

- **AWS**: internet gateway and route tables, network ACLs, security groups, public IPs, load
  balancer listeners and target groups, and resource policies.
- **GCP**: external IPs, VPC firewall rules and firewall policies, forwarding rules and load
  balancers, Cloud Armor policies.
- **Azure**: public IPs, network security groups, load balancers and Application Gateways.
- **Kubernetes**: `Service` types (LoadBalancer, NodePort) and `Ingress` objects, including
  `loadBalancerSourceRanges` and similar source restrictions.

A `FAIL` means the configuration allows the path. It does not prove that a service is listening
or that anyone connected. If one layer's facts are missing, the result is `UNKNOWN`, never `PASS`.

## Selected-flow reachability

`peaso/analysis/reachability.py` answers "does the configuration allow a new TCP or UDP flow
from private endpoint A to private endpoint B on port P?" It considers network interfaces,
subnets, routes, peering, transit gateways, NAT, security groups/NSGs/firewalls and network
ACLs for AWS, GCP and Azure. Every allowance needs complete association, routing and address
evidence; otherwise the answer is `unknown`.

API requests (all `POST`, allowed for read-only workspace members too):

| Route | Body |
| --- | --- |
| `/api/scans/{id}/reachability` | `source_resource_id`, `destination_resource_id`, `protocol`, `destination_port`, optional `source_port`, `address_family` |
| `/api/scans/{id}/reachability/batch` | One source, up to 24 `destination_resource_ids` |
| `/api/scans/{id}/reachability/matrix` | 2 to 12 `endpoint_resource_ids`, all pairs |
| `/api/scans/{id}/reachability/grid` | Two lists of up to 12 endpoints each |

`protocol` is `tcp` or `udp`; `address_family` is `ipv4` (default) or `ipv6`.

## Trust boundaries

`peaso/analysis/trust.py` decides what is "internal" and what is "external":

- The scanned accounts, projects, subscriptions and tenant are trusted by default, plus AWS
  Organizations member accounts found in the snapshot.
- You can add more with the collection options `trusted_scope_ids` and `trusted_domains`.
- Everything else that can be attributed to a scope is **external**.

AWS policy conditions that bind a public principal to a caller, network or organization (for
example `aws:SourceVpc`, `aws:PrincipalOrgID`, `aws:SourceArn`) are recognized as restricting.
Negated or `IfExists` variants and bare wildcards are not. Policies on resources that are only
reachable from inside a VPC (VPC endpoints, EFS) are treated as review items, not internet exposure.

## Graphs

Reports contain IAM, network and privesc graphs. Large graphs are aggregated for display by
`projection.py`, and `subgraph.py` builds bounded privesc views around one node. API routes:

- `GET /api/scans/{id}/graphs/{kind}` and `/graphs/{kind}/expand` for `iam`, `network` and `privesc`.
- `GET /api/scans/{id}/graphs/{kind}/aggregates/{node_id}/members` to open an aggregated node.
- `GET /api/scans/{id}/graphs/network/page` and `/graphs/network/edges` for paged network data.
- `GET /api/scans/{id}/graphs/iam/grants/{resource_id}` for grants on one resource.
- `GET /api/scans/{id}/graphs/privesc/subgraph` for a bounded privesc view.

Graph edges are **declared** relationships. An IAM edge means a policy names the permission; a
network edge means configuration links two resources. Neither proves effective access or traffic.

## Least privilege

The least-privilege view (`GET /api/scans/{id}/least-privilege`, `/grants`,
`/principals/{principal_id}`) lists principals, their grants and how critical the granted
permissions are. Where activity data was collected (for example service last-accessed data or
audit logs within `activity_days`), it can show unused permissions. Grants whose criticality
cannot be classified are reported through `analysis.coverage`.

## Best practices

- Fix `UNKNOWN` exposure results by granting the missing network reads; do not assume they are safe.
- Set `trusted_scope_ids` and `trusted_domains` for partner accounts and owned domains, so
  external-principal findings focus on real third parties.
- Use reachability queries to check segmentation between critical tiers, and confirm surprising
  results with your own network tests.
- Treat graph edges as configuration facts, not proof of use.
