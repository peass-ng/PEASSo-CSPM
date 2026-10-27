# AWS native exposure ledger — 2026-10-28

Baseline: clean `origin/main` `836a78ff52923cd8cab8ce5cf371014a8b23730f`. This is an assessment of configuration recorded in a snapshot, not a claim that a packet, request, or caller can reach a resource. The detailed predecessor is `~/peaso-work/exposure-audit-aws.md` (2026-10-27). This ledger records the current branch delta and exact outstanding work.

## Native delta

`peaso/analysis/internet_exposure.py:_aws_elbv2` now reads public `AvailabilityZones[].LoadBalancerAddresses[].IPv6Address` on internet-facing NLBs. An IPv6 address is included in listener evidence only when it is a globally routable address. The listener's IPv6 path is evaluated separately against collected IPv6 security-group and NACL rules. A private IPv6 address is excluded. This closes the NLB static IPv6 subcase of the public-address row; it does not close the entire row. The focused test checks an IPv6-only admitted path and closed SG/NACL paths.

## Open vector rows

There are still **13 PARTIAL**, **0 MISSING**, and **1 IMPOSSIBLE-FROM-API** rows in the predecessor table. The impossible row is issued but unobserved S3 presigned URLs: configuration APIs do not enumerate already-issued URLs. The exact remaining API-observable joins are:

| Vector | Status | Remaining observable fact or join |
| --- | --- | --- |
| EC2/ENI public path | PARTIAL | Managed ENI type and attachment, appliance/Gateway Load Balancer route targets, and source-specific IPv4/IPv6 SG, NACL and route witnesses. |
| Public IPs/EIPs | PARTIAL | Other services' published address associations where their APIs expose them. NLB static IPv6 is now joined; DNS answers are not an inventory association. |
| ALB/NLB/Classic listeners | PARTIAL | LB and target subnet ACL directions, source-specific ACL/SG variants, and other target types. |
| API Gateway REST/HTTP | PARTIAL | Deployed route/method version, routing-rule conditions, and resource-policy action/resource/condition evaluation. |
| CloudFront origins | PARTIAL | Origin/OAC/OAI/VPC-origin association to effective S3 or custom-origin policy and backend route. |
| RDS/Redshift/OpenSearch/EKS | PARTIAL | OpenSearch narrow API/index resource and condition semantics and collected database/EKS authentication configuration. |
| Lambda Function URLs | PARTIAL | Legacy URL policy behavior by creation date and other Lambda invoke surfaces. |
| VPN/peering/TGW/private endpoints | PARTIAL | VPN, peering and TGW route/attachment facts and observable appliance/Gateway Load Balancer associations. |
| IAM trust/federation | PARTIAL | In-account caller identity policy, collected SCP/RCP boundaries, federation provider and claim conditions. |
| Runtime principal | PARTIAL | NLB LB-subnet ACL, other source/target variants and registered target types joined to workload identity. |
| Service resource policies | PARTIAL | Effective action/resource/condition/explicit Deny per resource and native ARN, with applicable public-access/organization controls. `aws_resource_policy_scope.py` detects unrestricted *declarations* across collected recipes; this is not effective authorization. |
| Other cross-account shares | PARTIAL | Registry/artifact and other service-specific share APIs and grantee account identifiers beyond RDS/EBS/AMI. |
| EKS Kubernetes workload | PARTIAL | Kubernetes Service/Ingress/Pod/RBAC objects through separately authenticated Kubernetes API and AWS LB/node joins. |

Foreign-account caller policies, live credentials or tokens, application response, third-party appliance forwarding, and current DNS resolution are not established by these AWS configuration reads. They do not convert an otherwise observable row to `IMPOSSIBLE-FROM-API`.

## Full-service screen and semantic review

`outputs/aws-exposure-service-ledger-20261028.json` enumerates **433 official IAM service names** and **416 SDK API names** from the predecessor screen. **173** SDK names appear in the 992 snapshot's collector service names; **83** have at least one current native resource-policy recipe. Each entry carries its exact collector/recipe/operation screen and an explicit remaining semantic-review gap. These counts are discovery evidence only. A recipe or candidate API operation is not proof that a service's endpoint, sharing, policy, ACL, trust, public URL and integration surfaces are covered. All **416 API service reviews** and **433 product-to-API mappings** therefore remain open in the machine ledger. This audit does not claim the full service sweep is complete.

## Exposure AI gate

**Exposure AI removable for AWS: no.** The saved 992 comparison found 36 changed verdicts among 497 keyed reviews; current native replay matches 11 of the 36 and leaves 25 mismatches. The 25 should not be forced to match unsupported AI downgrades. An AI-off decision requires zero open coverage rows, a semantic service sweep, and keyed replay of the same snapshot/finding IDs after native changes. No hosted model call or production scan was performed here.
