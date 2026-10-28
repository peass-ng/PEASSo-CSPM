# Exposure A/B integration wave, 2026-10-28

Integration base: `origin/main` at `d7a9fd42c07911138918f09e3e3bfc2173ebd4be`. Only committed source was cherry-picked from the pinned heads below; each owner's uncommitted work remains in its own worktree. This branch has not been pushed or deployed, and no hosted model or production scan was run.

| Source | Pinned head | Integrated exposure vectors |
| --- | --- | --- |
| K8s B | `b5fdb235` | Malformed Service and Ingress source ranges remain unresolved rather than being treated as a proven public path. |
| GCP B | `f7910e1b` | WIF pool and provider trust, conditional and inherited IAM, BigQuery authorized resources, external group membership, incomplete bucket and dataset policies, and live GKE Service, Ingress and Pod candidates. |
| AWS A | `e41b4d76` | Public load balancer SG/NACL intersections and return paths, REST routing and deployed methods, CloudFront origin and viewer policy declarations, OpenSearch HTTP paths, EKS IPv6, Lambda URL cutover, Redshift port evidence. |
| AWS B | `423e6fcb` | VPN and PrivateLink frontends and invitations, ECR replication and public pulls, SAML/OIDC role trust, routed peering and Transit Gateway attachments, AMI organization grants, and foreign CloudWatch Logs destinations. |
| Azure B | `2cbcfbb3` | Redis ingress, gallery sharing and image versions, Cosmos closed ingress, external application audiences and RBAC group members, ML workspace ACLs and online endpoints, Managed Redis listeners. |
| GCP read boundary | `3e0cb87f` | Firebase App Hosting project reads now follow the exact scoped route and parameter contract, rejecting the previously accepted `api_key` request. |

The combined AWS route, public registry, and log subscription findings use 3–4 connected observed-evidence lines with the recorded setting first and uncertain outcomes marked as possible. The Transit Gateway and direct image/snapshot share branches were brought into the same form during integration. The selected collector successor receipt was repinned to the merged Azure/GCP source hashes. The generated API catalog was materialized and the privilege display catalog was rebound to it; the reviewed API Python manifest was repinned to 1,718 files. The API's direct SDK client closure remains 30 literal sites in the existing service allowlist.

Verification in the isolated worktree:

- Combined Exposure, trust, GKE, Azure Redis, privilege display, and API gate tests: **268 passed**.
- Additional provider-observation and principal-exposure tests: **56 passed** after updating their snapshot expectations for the new source-backed states.
- Full GCP collector suite: **236 passed**, including all 11 read-boundary cases previously excluded. The merged collector source and successor receipt were repinned together.
- Full GCP collector, provider-observation and principal suite: **292 passed**.
- Additional AWS and Azure Exposure and collector tests: **119 passed**.
- Catalog materialization check: no stale documents. API source review: no added, removed, or changed files against its new pin; 30 direct SDK sites. Collector successor receipt loads. `git diff --check` passes.

The remaining coverage ledgers and any future owner commits must be reviewed against this integration head before another cherry-pick. No Exposure AI stage should be re-enabled as part of this wave; the root order keeps only Network and Priorities model agents.
