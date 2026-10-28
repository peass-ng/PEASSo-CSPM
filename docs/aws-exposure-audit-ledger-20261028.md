# AWS native exposure ledger — 2026-10-28

Baseline: clean `origin/main` `836a78ff52923cd8cab8ce5cf371014a8b23730f`. This is an assessment of configuration recorded in a snapshot, not a claim that a packet, request, or caller can reach a resource. The detailed predecessor is `~/peaso-work/exposure-audit-aws.md` (2026-10-27). This ledger records the current branch delta and exact outstanding work.

## Native delta

`peaso/analysis/internet_exposure.py:_aws_elbv2` now reads public `AvailabilityZones[].LoadBalancerAddresses[].IPv6Address` on internet-facing NLBs. An IPv6 address is included in listener evidence only when it is a globally routable address. The listener's IPv6 path is evaluated separately against collected IPv6 security-group and NACL rules. A private IPv6 address is excluded. This closes the NLB static IPv6 subcase of the public-address row; it does not close the entire row. The focused test checks an IPv6-only admitted path and closed SG/NACL paths.

Second slice: `_aws_nacl` now accepts an exact globally routable `/32` or `/128` ingress host on an internet-facing **ALB** listener when the attached SG admits the world for that port and the same host has an egress NACL allowance for a TCP client port in `1024–65535`. Rule order and explicit Deny are applied for that host in both directions. Evidence retains the observed source IP, listener port, NACL ID and address family. This is a configuration witness for a possible client source/port pair, not proof of a completed connection. Wider source CIDRs and mismatched narrow SG/NACL sources remain open.

The same exact public NACL host witness now applies to internet-facing NLBs (with or without an attached SG) and Classic ELBs in a VPC. The NLB listener's IPv6 path also accepts an exact globally routable `/128` host with same-host return allowance. A collected SG, when present, must admit the world on that listener port; an ordered ingress or egress Deny still blocks the host. This extends listener admission only, not backend delivery or application response.

The load-balancer listener witness now retains SG source CIDRs and their port sets instead of reducing the SG to a port union before evaluating a narrow NACL. It partitions the public address space at the collected SG and NACL CIDR boundaries, selects globally routable candidate hosts, then applies NACL rule order for both directions and the matching SG source/port rule to the **same** host. This admits positive witnesses for intersecting narrow SG/NACL CIDRs, including an allowed segment after an earlier NACL Deny; disjoint SG/ACL sources and a mismatched return CIDR do not open the listener. Prefix-list sources are considered only when their entries are completely cached. This is a bounded configuration witness; untested effective network variants remain open.

The shared AWS VPC path now requires a collected, ordered NACL egress allowance to the client ephemeral range for a world-admitting TCP/UDP ingress path. A world ingress rule followed only by an egress rule for ports below 1024 no longer produces a positive EC2 or load-balancer listener finding. A narrower same-host return rule can still yield a positive host witness. This removes a stateless-return false positive from the EC2/ENI public path and the listeners that use the same evaluator.

## Open vector rows

There are still **13 PARTIAL**, **0 MISSING**, and **1 IMPOSSIBLE-FROM-API** rows in the predecessor table. The impossible row is issued but unobserved S3 presigned URLs: configuration APIs do not enumerate already-issued URLs. The exact remaining API-observable joins are:

| Vector | Status | Remaining observable fact or join |
| --- | --- | --- |
| EC2/ENI public path | PARTIAL | World TCP/UDP ingress now requires NACL egress to ephemeral client ports. Managed ENI type and attachment, appliance/Gateway Load Balancer route targets, and other source-specific IPv4/IPv6 SG, NACL and route witnesses remain. |
| Public IPs/EIPs | PARTIAL | NLB static IPv4/IPv6 and Global Accelerator static IPv4/IPv6 now join from cached API inventory; enabled/deployed accelerators with a collected listener yield a public frontend finding. Other services' published address associations remain; DNS answers are not an inventory association. |
| ALB/NLB/Classic listeners | PARTIAL | Exact public NACL host is witnessed for ALB, Classic and NLB, including NLB IPv6. A source-aware witness also admits some wider intersecting SG/NACL CIDRs with same-host return. Other source-specific paths, LB and target subnet ACL directions, and other target types remain. |
| API Gateway REST/HTTP | PARTIAL | REST method authorization uses the stage-bound cached `GetDeployment(embed=apisummary)` MethodSnapshot. The customer-role template now grants the dedicated, scoped `apigateway:ListRoutingRules` action required for cached REST custom-domain rules. HTTP deployed route version, REST routing-rule condition satisfiability, and resource-policy action/resource/condition evaluation remain. Cached rules retain `Priority` and `ConditionCount` but omit `Conditions[]`. |
| CloudFront origins | PARTIAL | Origin/OAC/OAI/VPC-origin association to effective S3 or custom-origin policy and backend route. |
| RDS/Redshift/OpenSearch/EKS | PARTIAL | OpenSearch narrow API/index resource and condition semantics and collected database/EKS authentication configuration. |
| Lambda Function URLs | PARTIAL | Legacy URL policy behavior and other Lambda invoke surfaces. The collector has `GetFunctionUrlConfig.CreationTime` and `GetPolicy.Policy`, but [AWS's URL authorization documentation](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html) says both that new URLs require two actions starting in October 2025 and that missing either action returns 403. It does not identify a per-URL grandfathering flag or exact cutover instant, so creation date alone cannot prove a legacy one-action URL is invocable. |
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
