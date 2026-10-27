# Principal entry points in Least Privilege and the Privilege Escalation Map

Both views now use `peaso/principal_exposure.py` to correlate incoming identity access and internet-facing workloads with their runtime principals. Run a new assessment to collect the additional identity and network inputs; stored assessments retain their original artifacts.

Least Privilege includes exposure badges, evidence, a severity badge, and filters for external identities, federation, internet workloads, and unresolved paths. Exposed identities appear even without an unused-permission recommendation. Broad grants remain review advice, never evidence that a permission was unused.

The escalation map marks exposed sources and offers **Exposed sources only**. Principal inspectors show the native trust or workload evidence. Aggregate nodes count exposed members without attributing their exposure to every member. Entry points do not create compromise edges, grant credentials, or change escalation confidence.

| Provider | External identity access | Runtime identity correlation |
| --- | --- | --- |
| AWS | Role trust actions and principals; scanned accounts, Organizations membership and explicit trusted scopes establish the boundary. Conditions are retained. Web identity trust records the issuer; unpinned multi-tenant OIDC trust is elevated. | EC2 instance profiles → roles; Lambda execution roles; ECS task ENIs → running tasks → task definition `taskRoleArn`. ECS execution roles are excluded. ECS services behind public load balancers are candidates requiring backend resolution. |
| GCP | Service account IAM policies and same-scope IAM grants for Token Creator, Workload Identity User, Service Account User, basic roles and collected custom impersonation roles. Organizational/folder inheritance requires explicit ancestry evidence. `actAs` requires workload control and stays conditional. | Compute service accounts, Cloud Run template service accounts, Cloud Functions runtime service accounts. Existing reachability analysis supplies firewall, ingress and invoker decisions. |
| Azure | Guest users and service principals whose app owner is outside the trusted tenant boundary. Application federation joins by `appId`; managed identity federation joins by ARM parent ID. A configured federation subject does not prove that its owner is uncontrolled. | App Service identities and public NIC → VM identities, including user-assigned identity principal resolution. Azure Container Instances public ports and Container Apps external ingress are joined to their managed identities; Container Apps also require collected environment public access configuration. |
| Kubernetes | RBAC subjects classified against trusted domains; unresolved ownership remains unknown. External subjects with `impersonate` on service accounts correlate to collected targets, respecting namespace and `resourceNames`. Default self-discovery bindings are excluded. | Service selectors → Pods → ServiceAccounts; Ingress backends → Services → Pods. Cluster provenance and namespace must match. Disabled automount suppresses token exposure unless an explicit projected token exists. Completed/deleting Pods are excluded. |

The default trust boundary and `metadata.trusted_scope_ids` / `metadata.trusted_domains` are shared with the existing trust analyzer. External means outside that boundary, not necessarily malicious or unapproved. An ARN, issuer URL, email domain, multi-tenant app setting, container port declaration or Service type alone does not prove exploitable access.

## Priority and uncertainty

Each signal is **declared**, **conditional**, or **unknown**. A declared entry point raises priority by one tier, capped at critical: low → medium, medium → high, high → critical. Original priority is retained as `base_severity`. Unknown escalation results never receive a severity increase. Escalation findings and their individual edge technique details use the same adjusted severity; one exposed source does not recolor every other source using that technique.

Internet evidence must have an observed public address, admitted ports and no unresolved path layers before it can increase severity. Pending LoadBalancers, NodePorts, Node kubelet endpoints, public Pod IPs and host-bound Pods missing firewall/routing information, stopped workloads and unresolved backends do not qualify. Gateway API and supported ingress-controller route declarations are reported with unresolved backend/controller routing. Missing Kubernetes ServiceAccount or NetworkPolicy inventory leaves the path unknown. Kubernetes workloads with collected NetworkPolicies remain conditional because controller/CNI enforcement and backend routing are not fully evaluated. ECS load balancer candidates remain unresolved pending listener/target health/target security-group correlation.

A web application compromise is still required to steal/use a runtime identity. There is no claim of RCE, credential theft, effective cross-account authentication, or completed impersonation. Trust conditions, explicit denies, permission boundaries, IAM guardrails, group membership and uncollected provider configuration can narrow access. Current coverage does not resolve Gateway API route acceptance, selectorless Services, undeclared hostNetwork listeners, arbitrary custom-controller behavior, every managed container platform, or cloud load-balancer backends. HostPort declarations on Pods are reported with node-address and cloud-firewall uncertainty. Kubernetes third-party destination and webhook findings indicate declared paths, not observed data transfer. Missing signals do not establish isolation.

## Validation on 2026-10-19

Read-only live inventory checks used `example-audit-profile`, gcloud, and az. AWS processed 562 resources and found 63 principals with external-assumption/federation signals; Azure processed 1,602 resources and found three external identities; GCP processed six resources and found four external impersonation targets. These counts are boundary-relative review signals, not confirmed compromise paths.

A disposable local Kubernetes v1.34 cluster tested a real Pod, ServiceAccount, LoadBalancer Service and cluster-admin binding. The service had no public address, so both views retained unknown exposure without increasing its high grant priority. The cluster was deleted and Docker Desktop, started for this test, was stopped. No cloud resources were created or modified.

Regression tests cover public/private/pending endpoints, trust conditions, organization membership, OIDC subject pinning, GCP scope isolation, Azure federation joins, Kubernetes namespace/cluster/selector/token boundaries, named impersonation, ECS task-role selection, escalation confidence and immutable snapshots. Validation completed with 124 backend tests and 20 browser tests passing; frontend TypeScript checking passed. Browser coverage checks exposure evidence, filters, severity presentation and mobile layout. A broader earlier backend run passed 153 tests with four skips.

## Provider references

- [AWS IAM Access Analyzer and its zone of trust](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [AWS ECS task and execution role distinctions](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-iam-role-overview.html)
- [GCP workload federation and service account impersonation](https://docs.cloud.google.com/iam/docs/workload-identity-federation)
- [Microsoft Entra workload identity federation](https://learn.microsoft.com/entra/workload-id/workload-identity-federation)
- [Microsoft Graph service principal ownership fields](https://learn.microsoft.com/graph/api/resources/serviceprincipal?view=graph-rest-1.0)
- [Kubernetes service account token mounting](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/)
- [Kubernetes NetworkPolicy enforcement and traffic semantics](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
