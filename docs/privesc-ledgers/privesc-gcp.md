# GCP privilege-escalation coverage ledger

GCP v3 update: 49 reviewed source anchors are catalogued through exact, conditional evidence. The historical totals below describe the original coverage sweep.
Upstream: HackTricks Cloud master `329aec912e90` (`src/pentesting-cloud/gcp-security/**`). Catalog: `peaso/privesc/catalog/gcp/*.yaml`.
Generated from the mdBook heading anchors of every page; `tests/test_peaso_privesc_coverage_gcp.py` asserts that every id in the mapping column exists in the GCP catalog and that every EXCLUDED/NEEDS-SCHEMA (_excluded) row is listed in `_excluded.yaml`.

Status values: COVERED (catalog id(s)), EXCLUDED (`_excluded.yaml` item, `X: technique`), NEEDS-SCHEMA (see the NEEDS SCHEMA section), STRUCTURAL (page title / service intro / references / enumeration / pointer heading), NON-PRIVESC (reviewed technique that does not obtain another principal's privileges; reason given).

## Totals

- Catalog entries: 171; `_excluded.yaml` items: 748.
- `gcp-privilege-escalation/**`: 83 pages, 588 headings: COVERED 125, EXCLUDED 336, STRUCTURAL 127. Technique headings = 461.
- Other gcp-security pages (post-exploitation, persistence, services, unauthenticated, cross-project, basic-information, to-workspace): 352 pages, 2720 headings: COVERED 69, EXCLUDED 67, NEEDS-SCHEMA 0, NON-PRIVESC 591, STRUCTURAL 1993, UNRESOLVED 0.

## NEEDS SCHEMA

These techniques are real escalations that the current schema/evaluator cannot express precisely. Each has an
`_excluded.yaml` line pointing here (reason starts with `NEEDS SCHEMA`) so the anchor tests stay green; the schema/evaluator
owner should implement the listed additions, after which the entry can move into the catalog as written.

### NS-1 Google Groups self-join of an open group bound in IAM

Sources: `src/pentesting-cloud/gcp-security/gcp-to-workspace-pivoting/README.md#google-groups-privilege-escalation`,
`src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-google-groups-unauthenticated-enum.md#join-a-publicly-open-iam-bound-group-without-victim-tenant-access`.
The IAM-gated variant (cloudidentity membership create) is `gcp-cloudidentity-add-member-to-group`. The self-join variant
needs no GCP permission, only the group's Groups Settings `whoCanJoin` (`ANYONE_CAN_JOIN`, or `ALL_IN_DOMAIN_CAN_JOIN`
for a same-domain source) and `allowExternalMembers` for an external source.
Needs: (a) `requires` allowed to be empty when `source_selector`/`target.selector` carry the gate (today it needs a
`source_kind`), (b) a GCP target selector `gcp_group_join_open_to_source` backed by collected Groups Settings facts.

```yaml
- id: gcp-groups-self-join-open-group
  provider: gcp
  service: cloudidentity
  title: Self-join a Google Group whose join setting is open to the source
  source: src/pentesting-cloud/gcp-security/gcp-to-workspace-pivoting/README.md#google-groups-privilege-escalation
  source_revision: 171e422
  summary: The source can obtain the IAM roles of Google Groups whose whoCanJoin setting lets it join without approval.
  source_kind: [gcp_user, gcp_workspace_user]
  requires: {}
  target:
    kind: gcp_group
    selector:
      gcp_group_join_open_to_source: true   # whoCanJoin ANYONE_CAN_JOIN, or ALL_IN_DOMAIN_CAN_JOIN and source in the group's domain; external sources also need allowExternalMembers
    scope: any
    aggregate_as: "Open-join Google Groups"
  blockers: [gcp_deny_policy]
  confidence: derived
  severity: high
  mitigation: Set whoCanJoin to INVITED_CAN_JOIN/CAN_REQUEST_TO_JOIN on groups bound in IAM.
```

IMPLEMENTED: (a) `requires: {}` was already valid with a `source_kind`; (b) selector `gcp_group_join_open_to_source: true` (kind `gcp_group` only; IAM-bound groups are the targets; dynamic per source). ANYONE_CAN_JOIN with the source in the group's email domain or `allowExternalMembers: true` -> derived; ANYONE_CAN_JOIN with allowExternalMembers unknown -> conditional; ALL_IN_DOMAIN_CAN_JOIN with the same email domain -> conditional (`same_email_domain_assumed_same_customer`); INVITED/CAN_REQUEST -> no edge; a group without settings -> unresolved placeholder. Write the YAML above with ONE change: `source_kind: gcp_user` (sources are never `gcp_workspace_user` nodes). NEEDS COLLECTOR FACT: Groups Settings per IAM-bound group (`groupssettings.googleapis.com/groups/v1/groups/{email}`: whoCanJoin, allowExternalMembers), stored on the `group` item as `groupSettings` (or top-level). Until collected the technique is a coverage note (`gcp_group_join_open_to_source not evaluated`) and yields no edges. Test: tests/test_peaso_privesc_schema_ext_gcp.py.

STATUS: COVERED by `gcp-groups-self-join-open-group` (catalog/gcp/cloudidentity.yaml); the `_excluded.yaml` line was removed and the ledger rows are COVERED.

### NS-2 Cloud Domains nameserver swap to Workspace administrator recovery

Source: `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-domains-post-exploitation.md#domainsregistrationsconfiguredns--redirect-authoritative-dns`.
Same end state as `gcp-workspace-cloud-dns-admin-recovery`, but the pivot is a Cloud Domains registration, not a Cloud DNS
zone. Needs: collector support for `domains_registration` resources (`domainName`, `dnsSettings`) and an evaluator
implementation of `attached_to_service: workspace_super_admin_of_registration_domain` (Workspace super admins whose primary
domain equals the registration's `domainName`).

```yaml
- id: gcp-domains-configuredns-workspace-admin-recovery
  provider: gcp
  service: domains
  title: Repoint a Cloud Domains registration's name servers to recover the Workspace super administrator
  source: src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-domains-post-exploitation.md#domainsregistrationsconfiguredns--redirect-authoritative-dns
  source_revision: 171e422
  summary: The source can obtain the privileges of Workspace super administrators of tenants whose primary domain is registered in a Cloud Domains registration whose DNS settings it can change.
  pivot_resource_type: domains_registration
  requires:
    all_of:
      - action: domains.registrations.configureDns
        resource: "{pivot}"
  target:
    kind: gcp_workspace_user
    selector:
      attached_to_service: workspace_super_admin_of_registration_domain
    scope: any
    aggregate_as: "Workspace super administrators of domains registered in {pivot}"
  conditions:
    - {id: dnssec, description: Published DS records must be removed and aged out first.}
    - {id: recovery_process, description: Depends on Google's administrator-recovery process accepting the DNS challenge.}
  blockers: [gcp_deny_policy]
  confidence: conditional
  severity: critical
  mitigation: Restrict domains.registrations.configureDns and enable registrar lock / DNSSEC monitoring.
```

IMPLEMENTED (shape changed): no pivot. Selector `gcp_workspace_super_admin_with_registered_domain: true` (kind `gcp_workspace_user`) selects Workspace super admins whose email domain is the `domainName` of a collected registration, and placeholder `{target.domain_registration}` = those registration names. Write:

STATUS: COVERED by `gcp-domains-configuredns-workspace-admin-recovery` (catalog/gcp/domains.yaml); the `_excluded.yaml` line was removed and the ledger rows are COVERED.
`requires: {all_of: [{action: domains.registrations.configureDns, resource: "{target.domain_registration}"}]}`, `target: {kind: gcp_workspace_user, selector: {gcp_workspace_super_admin_with_registered_domain: true}, scope: any, aggregate_as: "Workspace super administrators of domains registered in Cloud Domains"}`; drop `pivot_resource_type`; conditions/blockers/confidence as above. NEEDS COLLECTOR FACT: `domains_registration` {name, domainName} (domains.googleapis.com `projects/*/locations/*/registrations`) plus workspace_user isAdmin (already collected when Workspace is enabled). Not collected -> unresolved placeholders only.

### NS-3 Poison a consumed custom image family

Source: `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-compute-persistence.md#poison-a-consumed-custom-image-family`.
Needs a selector that resolves instance templates / MIGs / later VM creations whose boot disk `sourceImage` is
`projects/<project>/global/images/family/<family>` in a project where the source can create images. Using
`attached_to_service: compute_instance` would add edges to every VM SA, which is imprecise.

```yaml
- id: gcp-compute-images-create-family-poison
  provider: gcp
  service: compute
  title: Publish a newer image into an image family consumed by templates or MIGs
  source: src/pentesting-cloud/gcp-security/gcp-persistence/gcp-compute-persistence.md#poison-a-consumed-custom-image-family
  source_revision: 171e422
  summary: The source can obtain the privileges of the service accounts of VMs later created from image families it can publish to.
  requires:
    all_of:
      - action: compute.images.create
        resource: "{target.host_resource.image_project}"
      - action: compute.disks.useReadOnly
        resource: "*"
  target:
    kind: gcp_service_account
    selector:
      gcp_image_family_consumer: true   # SAs of instance templates / MIG instances whose sourceImage is a family in the image project
    scope: any
    aggregate_as: "SAs of workloads booting from image families the source can publish to"
  conditions:
    - {id: later_boot, description: Only VMs created/recreated after the publish are affected.}
  blockers: [gcp_deny_policy, {id: org_policy_constraint, constraint: compute.trustedImageProjects}]
  confidence: conditional
  severity: high
  mitigation: Pin concrete image names in templates and restrict compute.images.create in image projects.
```

IMPLEMENTED: selector `gcp_image_family_consumer: true` (kind `gcp_service_account`): SAs of collected instance templates whose disk `initializeParams.sourceImage` is `projects/<p>/global/images/family/<f>` (pinned images do not match; SA project without template inventory -> unresolved). Placeholder `{target.image_family_project}` = `projects/<p>` of those families. Write the YAML above with the first requirement `{action: compute.images.create, resource: "{target.image_family_project}"}` (instead of `{target.host_resource.image_project}`); the `compute.disks.useReadOnly` requirement is optional. Collector: instance_template is already collected. MIG-only consumers resolve through their template.

STATUS: COVERED by `gcp-compute-images-create-family-poison` (catalog/gcp/compute.yaml); the `_excluded.yaml` line was removed and the ledger rows are COVERED.

### NS-4 External identity abusing an over-broad workload/workforce identity federation binding

Sources: `gcp-basic-information/gcp-federation-abuse.md#gcp`,
`gcp-cross-project-attacks/historical-cross-project-vulnerabilities.md#federation-and-metadata-server-abuse`,
`gcp-cross-project-attacks/iam-and-service-account-impersonation-attacks.md#workload--workforce-identity-federation-confused-deputy`.
The attacker holds no GCP permission; it only controls an external token (for example any GitHub repository's Actions
OIDC token) that matches a provider with no `attributeCondition` or a `principalSet://.../*` binding. Creating or editing
providers is already `gcp-wif-*`. Needs a non-principal source kind (an external federated identity) and a target selector
that evaluates provider attribute conditions and principalSet bindings. This may fit better as a CSPM check than as a
privesc edge.

```yaml
- id: gcp-wif-unconstrained-provider-external-identity
  provider: gcp
  service: iam
  title: Exchange an arbitrary external OIDC token through an unconstrained workload identity provider
  source: src/pentesting-cloud/gcp-security/gcp-basic-information/gcp-federation-abuse.md#gcp
  source_revision: 171e422
  summary: Any holder of a token from the provider's issuer can obtain the privileges of service accounts/roles bound to principalSets of a provider without a restrictive attribute condition.
  source_kind: external_federated_identity   # new: synthetic "anyone with a token from issuer X" principal
  requires: {}
  target:
    kind: gcp_service_account
    selector:
      gcp_wif_unconstrained_principalset_bound: true   # provider attributeCondition empty/overly broad AND roles/iam.workloadIdentityUser (or direct roles) granted to a principalSet of that pool
    scope: any
  blockers: [gcp_deny_policy]
  confidence: conditional
  severity: critical
  mitigation: Always set attributeCondition (repository_owner / repository id) and bind principal:// subjects, not pool-wide principalSets.
```

REJECTED (as a privesc edge): the attacker is not a principal in the snapshot (anyone holding a token from the issuer), so there is no source node to start a path from, and a synthetic "internet" source would make every finding reachable from outside without a GCP permission. The facts are already collected (`workload_identity_provider.attributeCondition`, principalSet bindings), so this belongs in a CSPM check: "workload/workforce identity provider without attributeCondition (or with a non-restrictive one) whose pool principalSet holds roles/iam.workloadIdentityUser or direct roles". Keep the `_excluded.yaml` line, reason "CSPM check (external identity, no principal source)".

STATUS: EXCLUDED (rejected); the `_excluded.yaml` lines now carry the rejection reason and the ledger rows are EXCLUDED.

### NS-5 External pull request / upstream repository poisoning a Cloud Build trigger

Sources: `gcp-unauthenticated-enum-and-access/gcp-cloud-build-unauthenticated-enum.md#cloudbuildyml`, `#pr-approvals`,
`gcp-services/gcp-cloud-build-enum.md#sa-permissions`, `#pr-approvals`,
`gcp-unauthenticated-enum-and-access/gcp-source-repositories-unauthenticated-enum.md#compromise-external-repository`.
No GCP permission: an outside contributor opens a PR against a repository whose Cloud Build PR trigger has comment control
disabled, or pushes to an upstream repo that triggers builds. GCP-permission variants are already
`gcp-cloudbuild-repositories-accessreadwritetoken` and `gcp-sourcerepos-update-build-trigger`. Needs a non-principal
source kind and a selector over collected trigger facts (`pullRequest.commentControl`, event source, approval
requirement).

```yaml
- id: gcp-cloudbuild-external-pr-trigger
  provider: gcp
  service: cloudbuild
  title: Run attacker cloudbuild.yaml from an external pull request on an unapproved PR trigger
  source: src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-cloud-build-unauthenticated-enum.md#pr-approvals
  source_revision: 171e422
  summary: Any contributor able to open a pull request can obtain the privileges of the service account of Cloud Build PR triggers that build untrusted PRs without comment control or approval.
  source_kind: external_scm_contributor   # new
  requires: {}
  target:
    kind: gcp_service_account
    selector:
      attached_to_service: cloudbuild_trigger_untrusted_pr   # new: trigger.pullRequest.commentControl == COMMENTS_DISABLED and approvalConfig.approvalRequired false
    scope: any
  blockers: [gcp_deny_policy]
  confidence: conditional
  severity: critical
  mitigation: Require /gcbrun comments or build approval for PR triggers and use least-privilege trigger SAs.
```

REJECTED (as a privesc edge): same as NS-4, the source is an external SCM contributor, not a principal in the snapshot; and Cloud Build triggers (`pullRequest.commentControl`, `approvalConfig.approvalRequired`, event source) are not collected. Recommended as a CSPM check once the collector lists `cloudbuild.projects.locations.triggers` (needs a collector fact: trigger {name, serviceAccount, pullRequest.commentControl, approvalConfig, github/repositoryEventConfig}). Keep the `_excluded.yaml` line.

STATUS: EXCLUDED (rejected); the `_excluded.yaml` lines now carry the rejection reason and the ledger rows are EXCLUDED.

### NS-6 Durable bounded BigLake and BigQuery access gains

Four existing privilege-escalation sections support five narrow ways for the acting principal to gain a
*new bounded effective permission*: a BigLake connection-backed table, a BigQuery remote function, an
authorized routine, one directly authorized view, or one preexisting view inside an authorized dataset.
They are active conditional rows using `gcp_bounded_access_gain: true`. A complete, unique
`gcp_bounded_access_gain_evidence` record must bind every declared source action to its exact resource, the
created or authorized intermediate object, the connection identity or dataset ACL entry, and one protected
resource. The record must prove prior denial and subsequent allowed access for the same named action and
protected resource, after the accepted mutation. The evaluator rechecks all source actions on their exact
resources and rejects partial, duplicate, stale, or mismatched evidence. The target carries only the proven
indirect access; it does not imply a direct IAM grant or possession of the connection service account.
For an authorized dataset, evidence must additionally bind the dataset entry's `VIEWS` target type, the exact
view dataset, and one view that existed before the mutation. The target names only the proven protected-table
read through that view. It does not infer access through every current or future view; creating or updating
views that reference protected source tables has its own source-table permission requirements.

## Privilege-escalation pages

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/README.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---privilege-escalation` | # GCP - Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#iam-and-organization-policies` | ## IAM and organization policies | - | EXCLUDED | X: Page intro pointer |
| `#introduction-to-gcp-privilege-escalation` | ## Introduction to GCP Privilege Escalation <a href="#introduction-to-gcp-privilege-escalation" id="introduction-to-gcp-privilege-escalation"></a> | - | EXCLUDED | X: Introduction |
| `#permissions-for-privilege-escalation-methodology` | ## Permissions for Privilege Escalation Methodology | - | EXCLUDED | X: Methodology |
| `#bypassing-access-scopes` | ## Bypassing access scopes <a href="#bypassing-access-scopes" id="bypassing-access-scopes"></a> | - | EXCLUDED | X: Bypassing access scopes<br>`gcp-audit-s01-00-steal-a-service-account-key` — conditional verified exact-target authority. |
| `#privilege-escalation-techniques` | ## Privilege Escalation Techniques | - | EXCLUDED | X: Techniques index |
| `#abusing-gcp-to-escalate-privileges-locally` | ### Abusing GCP to escalate privileges locally | - | EXCLUDED | X: Local escalation pointer |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-access-context-manager-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---access-context-manager--vpc-sc-privesc` | # GCP - Access Context Manager / VPC-SC Privesc | - | STRUCTURAL | page title / intro / references |
| `#vpc-service-controls` | ## VPC Service Controls | - | EXCLUDED | X: VPC-SC intro |
| `#access-context-manager-accesscontextmanagergoogleapiscom` | ## Access Context Manager (`accesscontextmanager.googleapis.com`) | accesscontextmanager.googleapis.com | EXCLUDED | X: Page intro |
| `#accesscontextmanageraccesslevelsupdate--loosen-context-aware-access` | ### `accesscontextmanager.accessLevels.update` — loosen context-aware access | accesscontextmanager.accessLevels.update | EXCLUDED | X: Loosen access levels<br>`gcp-audit-s01-02-loosen-access-level-for-atta` — conditional verified exact-target authority. |
| `#accesscontextmanagerserviceperimetersupdate--defeat-vpc-sc-data-exfil-protection` | ### `accesscontextmanager.servicePerimeters.update` — defeat VPC-SC data-exfil protection | accesscontextmanager.servicePerimeters.update | NON-PRIVESC | gcp-v3-36-service-perimeter-update (exact evidence; conditional)<br>gcp-audit-s01-03-create-a-bridge-perimeter-jo — conditional verified exact-target authority.<br>gcp-audit-s01-04-delete-a-perimeter-or-access — conditional verified exact-target authority. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#accesslevelsreplaceall--serviceperimetersreplaceall--atomic-bulk-overwrite-distinct-audit-method` | ### `accessLevels.replaceAll` / `servicePerimeters.replaceAll` — atomic bulk overwrite (distinct audit method) | accessLevels.replaceAll, servicePerimeters.replaceAll | NON-PRIVESC | gcp-v3-37-bulk-replaceall-of-access-levels-perimeters (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#dry-run-spec-vs-enforced-status--stealth-staging--one-call-flip` | ### Dry-run (`spec`) vs enforced (`status`) — stealth staging & one-call flip | - | NON-PRIVESC | gcp-v3-38-dry-run-spec-staging-and-enforcement-flip (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#gcpuseraccessbindings-cloud-bindings--context-removal-or-extended-workforce-sessions` | ### `gcpUserAccessBindings` (`cloud-bindings`) — context removal or extended workforce sessions | - | EXCLUDED | X: GcpUserAccessBinding context removal / extended sessions<br>`gcp-audit-s01-06-delete-or-weaken-a-group-con` — conditional verified exact-target authority. |
| `#authorizedorgsdescs-authorized-orgs--cross-org-trust-injection` | ### `authorizedOrgsDescs` (`authorized-orgs`) — cross-org trust injection | - | NON-PRIVESC | gcp-v3-39-authorized-orgs-injection (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#accesscontextmanagerpoliciessetiampolicy--the-access-policys-own-iam-plane-invisible-backdoor` | ### `accesscontextmanager.policies.setIamPolicy` — the access-policy's own IAM plane (invisible backdoor) | accesscontextmanager.policies.setIamPolicy | EXCLUDED | X: Self-grant accesscontextmanager.servicePerimeters.update on a access policy |
| `#recon--map-the-orgs-entire-exfil-posture-read-only` | ## Recon — map the org's entire exfil posture (read-only) | - | EXCLUDED | X: Recon |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-agent-registry-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---agent-registry-privilege-escalation` | # GCP - Agent Registry Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#agent-registry` | ## Agent Registry | - | STRUCTURAL | page title / intro / references |
| `#agentregistryservicesupdate--redirect-a-bound-target-and-capture-its-agent-identity-credential` | ### `agentregistry.services.update` — redirect a bound target and capture its Agent Identity credential | agentregistry.services.update | COVERED | `gcp-agentregistry-service-redirect-exact-external-principal` (requires actual subject-bound credential capture and newly allowed provider action; prior generic row remains excluded) |
| `#agentregistryskillrevisionscreate--agentregistryskillsupdate--replace-an-executable-skills-default-revision` | ### `agentregistry.skillRevisions.create` + `agentregistry.skills.update` — replace an executable Skill's default revision | agentregistry.skillRevisions.create, agentregistry.skills.update | COVERED | `gcp-agentregistry-skill-default-revision-replace`<br>gcp-audit-s01-10-replace-default-executable-s — conditional verified exact-target authority. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-analytics-hub-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---analytics-hub-privesc` | # GCP - Analytics Hub Privesc | - | STRUCTURAL | page title / intro / references |
| `#analytics-hub` | ## Analytics Hub | - | EXCLUDED | X: Page intro |
| `#bigquery-sharing-analytics-hub` | ## BigQuery sharing (Analytics Hub) | - | STRUCTURAL | page title / intro / references |
| `#analyticshublistingssubscribe--access-a-published-dataset-or-pubsub-topic` | ### `analyticshub.listings.subscribe` — access a published dataset or Pub/Sub topic | analyticshub.listings.subscribe | EXCLUDED | X: Subscribe to a listing |
| `#analyticshubdataexchangessubscribe--subscribe-to-a-data-clean-room` | ### `analyticshub.dataExchanges.subscribe` — subscribe to a data clean room | analyticshub.dataExchanges.subscribe | EXCLUDED | X: Subscribe to a data clean room |
| `#analyticshublistingssetiampolicy--analyticshubdataexchangessetiampolicy--self-grant-subscription-authority` | ### `analyticshub.listings.setIamPolicy` / `analyticshub.dataExchanges.setIamPolicy` — self-grant subscription authority | analyticshub.listings.setIamPolicy, analyticshub.dataExchanges.setIamPolicy | COVERED | `gcp-analyticshub-listings-setiampolicy-listing-self-grant`, `gcp-analyticshub-dataexchanges-setiampolicy-data-exchange-self-grant` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-apigee-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---apigee-privilege-escalation` | # GCP - Apigee Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#apigee` | ## Apigee | - | EXCLUDED | X: Section intro |
| `#apigee-1` | ## Apigee | - | STRUCTURAL | page title / intro / references |
| `#apigeeproxiescreate--apigeedeploymentscreate--apigeeproxyrevisionsdeploy--iamserviceaccountsactas--deploy-a-malicious-api-proxy-revision` | ### `apigee.proxies.create` + `apigee.deployments.create` + `apigee.proxyrevisions.deploy` (+ `iam.serviceAccounts.actAs`) — Deploy a malicious API proxy revision | apigee.proxies.create, apigee.deployments.create, apigee.proxyrevisions.deploy, iam.serviceAccounts.actAs | COVERED | `gcp-apigee-proxy-deploy-with-sa-actas` |
| `#apigeesharedflowscreate--apigeedeploymentscreate--apigeesharedflowrevisionsdeploy--apigeeflowhooksattachsharedflow--execute-a-malicious-shared-flow-across-an-environment` | ### `apigee.sharedflows.create` + `apigee.deployments.create` + `apigee.sharedflowrevisions.deploy` + `apigee.flowhooks.attachSharedFlow` — Execute a malicious shared flow across an environment | apigee.sharedflows.create, apigee.deployments.create, apigee.sharedflowrevisions.deploy, apigee.flowhooks.attachSharedFlow | COVERED | `gcp-apigee-sharedflow-flowhook-with-sa-actas` |
| `#apigeeenvironmentssetiampolicy--grant-an-environment-role-to-an-attacker-controlled-principal` | ### `apigee.environments.setIamPolicy` — Grant an environment role to an attacker-controlled principal | apigee.environments.setIamPolicy | EXCLUDED | X: Self-grant apigee.proxyrevisions.deploy on a environment |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-apikeys-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---api-keys-privesc` | # GCP - API Keys Privesc | - | STRUCTURAL | page title / intro / references |
| `#api-keys` | ## API Keys | - | EXCLUDED | X: Page intro; standard API key create / list / getKeyString / restriction update (Rhino CreateAPIKey, ViewExistingAPIKeys) |
| `#create-an-authorization-key-bound-to-a-more-privileged-service-account` | ### Create an authorization key bound to a more-privileged service account | apikeys.keys.create, iam.serviceAccounts.actAs, iam.serviceAccountApiKeyBindings.create | COVERED | `gcp-apikeys-authorization-key-bound-sa` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-app-lifecycle-manager-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---app-lifecycle-manager-privilege-escalation` | # GCP - App Lifecycle Manager Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#app-lifecycle-manager` | ## App Lifecycle Manager | - | STRUCTURAL | page title / intro / references |
| `#saasservicemgmtreleasescreate--unitoperationscreate--rolloutscreate--apply-attacker-terraform-as-an-actuation-service-account` | ### `saasservicemgmt.releases.create` + `unitOperations.create` / `rollouts.create` — apply attacker Terraform as an actuation service account | saasservicemgmt.releases.create, unitOperations.create, rollouts.create | COVERED | `gcp-saasservicemgmt-release-unit-actuation` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-appengine-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---app-engine-privilege-escalation` | # GCP - App Engine Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#app-engine` | ## App Engine | - | EXCLUDED | X: Page intro |
| `#deploy-attacker-controlled-code-as-a-version-service-account` | ### Deploy attacker-controlled code as a version service account | iam.serviceAccounts.actAs, appengine.versions.create, storage.objects.create, cloudbuild.builds.create | COVERED | `gcp-appengine-versions-create-actas`<br>`gcp-appengine-versions-create-legacy-default-sa-no-actas` |
| `#ssh-into-a-flexible-environment-instance-through-debug-mode-or-os-login` | ### SSH into a flexible-environment instance through debug mode or OS Login | appengine.instances.enableDebug, compute.instances.osLogin, iam.serviceAccounts.actAs, compute.instances.osAdminLogin | COVERED | `gcp-appengine-instances-enabledebug` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-artifact-registry-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---artifact-registry-privesc` | # GCP - Artifact Registry Privesc | - | STRUCTURAL | page title / intro / references |
| `#artifact-registry` | ## Artifact Registry | - | EXCLUDED | X: Section intro |
| `#artifactregistryrepositoriesuploadartifacts--poison-an-artifact-consumed-by-a-privileged-workload` | ### `artifactregistry.repositories.uploadArtifacts` — poison an artifact consumed by a privileged workload | artifactregistry.repositories.uploadArtifacts | COVERED | `gcp-artifactregistry-upload-artifacts` |
| `#artifactregistrytagsupdate--repoint-a-mutable-tag-to-another-stored-version` | ### `artifactregistry.tags.update` — repoint a mutable tag to another stored version | artifactregistry.tags.update | COVERED | `gcp-artifactregistry-tags-update` |
| `#artifactregistryrepositoriessetiampolicy--self-grant-control-of-a-repository` | ### `artifactregistry.repositories.setIamPolicy` — self-grant control of a repository | artifactregistry.repositories.setIamPolicy | COVERED | `gcp-artifactregistry-repositories-setiampolicy` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-bare-metal-solution-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---bare-metal-solution-privilege-escalation` | # GCP - Bare Metal Solution Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#bare-metal-solution` | ## Bare Metal Solution | - | STRUCTURAL | page title / intro / references |
| `#retrieve-a-still-valid-initial-server-password` | ### Retrieve a still-valid initial server password | secretmanager.versions.access | COVERED | `gcp-bms-direct-initial-secret-exact-server-user` (direct exact secret version only; impersonation and Preview CMEK variants remain unmodeled) |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-batch-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---batch-privesc` | # GCP - Batch Privesc | - | STRUCTURAL | page title / intro / references |
| `#batch` | ## Batch | - | EXCLUDED | X: Section intro |
| `#submit-arbitrary-code-as-a-more-privileged-job-service-account` | ### Submit arbitrary code as a more-privileged job service account | batch.jobs.create, iam.serviceAccounts.actAs | COVERED | `gcp-batch-jobs-create-actas` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-beyondcorp-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---beyondcorp-privilege-escalation` | # GCP - BeyondCorp Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#beyondcorp--chrome-enterprise-premium` | ## BeyondCorp / Chrome Enterprise Premium | - | EXCLUDED | X: Service intro |
| `#beyondcorp--chrome-enterprise-premium-secure-gateway` | ## BeyondCorp / Chrome Enterprise Premium secure gateway | - | STRUCTURAL | page title / intro / references |
| `#self-grant-access-to-an-existing-private-web-application` | ### Self-grant access to an existing private web application | - | EXCLUDED | X: Self-grant beyondcorp.sgApplications.use on a secure gateway app |
| `#repoint-an-application-the-caller-can-already-use-to-another-web-target-behind-its-existing-upstream` | ### Repoint an application the caller can already use to another web target behind its existing upstream | - | EXCLUDED | X: Repoint an application to another upstream target<br>`gcp-audit-s01-21-repoint-accessible-gateway-a` — conditional verified exact-target authority. |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-biglake-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---biglake-privilege-escalation` | # GCP - BigLake Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#biglake--lakehouse` | ## BigLake / Lakehouse | - | STRUCTURAL | page title / intro / references |
| `#bigquerytablescreate--bigqueryconnectionsdelegate--create-a-table-that-reads-as-the-connection-service-account` | ### `bigquery.tables.create` + `bigquery.connections.delegate` — create a table that reads as the connection service account | bigquery.tables.create, bigquery.connections.delegate | COVERED | `gcp-biglake-connection-table-bounded-storage-read` |
| `#biglakecatalogsnamespacestablessetiampolicy--self-grant-on-a-lakehouse-resource` | ### `biglake.{catalogs,namespaces,tables}.setIamPolicy` — self-grant on a Lakehouse resource | - | COVERED | `gcp-biglake-catalogs-setiampolicy-catalog-self-grant`, `gcp-biglake-namespaces-setiampolicy-namespace-self-grant`, `gcp-biglake-tables-setiampolicy-table-self-grant` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-bigquery-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---bigquery-privesc` | # GCP - BigQuery Privesc | - | STRUCTURAL | page title / intro / references |
| `#bigquery` | ## Bigquery | - | EXCLUDED | X: Section intro |
| `#bigquery-1` | ## BigQuery | - | STRUCTURAL | page title / intro / references |
| `#bigquerydatasetsupdate--bigquerydatasetssetiampolicy--self-grant-dataset-access` | ### `bigquery.datasets.update` / `bigquery.datasets.setIamPolicy` — self-grant dataset access | bigquery.datasets.update, bigquery.datasets.setIamPolicy | COVERED | `gcp-bigquery-datasets-setiampolicy-dataset-iam-self-grant`, `gcp-bigquery-datasets-update-dataset-acl-self-grant` |
| `#bigqueryconnectionssetiampolicy--self-grant-connection-use` | ### `bigquery.connections.setIamPolicy` — self-grant connection use | bigquery.connections.setIamPolicy | COVERED | `gcp-bigquery-connections-setiampolicy-connection-self-grant` |
| `#datacatalogtaxonomiessetiampolicy--self-grant-fine-grained-reader` | ### `datacatalog.taxonomies.setIamPolicy` — self-grant Fine-Grained Reader | datacatalog.taxonomies.setIamPolicy | COVERED | `gcp-datacatalog-taxonomies-setiampolicy-taxonomy-self-grant` |
| `#bigquerydatapoliciesupdate--weaken-masking-or-add-a-raw-data-grantee` | ### `bigquery.dataPolicies.update` — weaken masking or add a raw-data grantee | bigquery.dataPolicies.update | EXCLUDED | X: Masking-rule change is a data effect; raw-data self-grant remains inactive pending typed policy-to-column and before/after read evidence. |
| `#bigquerydatapoliciesdelete--datacatalogtaxonomiesupdate--disable-column-level-enforcement` | ### `bigquery.dataPolicies.delete` + `datacatalog.taxonomies.update` — disable column-level enforcement | bigquery.dataPolicies.delete, datacatalog.taxonomies.update | EXCLUDED | X: Disable column-level enforcement<br>`gcp-audit-s01-26-delete-policies-and-deactiva` — conditional verified exact-target authority. |
| `#bigqueryroutinescreate--bigqueryconnectionsdelegateuse--code-execution-through-a-spark-connection` | ### `bigquery.routines.create` + `bigquery.connections.delegate/use` — code execution through a Spark connection | bigquery.routines.create | COVERED | `gcp-bigquery-spark-procedure-connection-identity` |
| `#bigqueryroutinescreate--bigqueryconnectionsdelegateuse--invoke-cloud-run-through-a-remote-function` | ### `bigquery.routines.create` + `bigquery.connections.delegate/use` — invoke Cloud Run through a remote function | bigquery.routines.create | COVERED | `gcp-bigquery-remote-function-bounded-cloudrun-invoke` |
| `#dataset-acl-write--authorize-a-routine-as-an-indirect-access-path` | ### Dataset ACL write — authorize a routine as an indirect access path | - | COVERED | `gcp-bigquery-authorized-routine-bounded-table-access` |
| `#bigquerytablessetiampolicy--self-grant-table-access` | ### `bigquery.tables.setIamPolicy` — self-grant table access | bigquery.tables.setIamPolicy | COVERED | `gcp-bigquery-tables-setiampolicy-table-self-grant` |
| `#bigqueryrowaccesspolicies--widen-or-remove-row-level-security` | ### `bigquery.rowAccessPolicies.*` — widen or remove row-level security | - | EXCLUDED | X: Row access policy widening<br>`gcp-audit-s01-29-widen-or-delete-row-access-p` — conditional verified exact-target authority. |
| `#bigqueryrowaccesspoliciescreateupdate--self-grant-filtered-row-access` | #### `bigquery.rowAccessPolicies.create/update` — self-grant filtered row access | bigquery.rowAccessPolicies.create, bigquery.rowAccessPolicies.setIamPolicy, bigquery.tables.getData, bigquery.jobs.create | COVERED | `gcp-bigquery-row-policy-create-self-grant` |
| `#dataset-acl-write--authorized-view-or-dataset-as-an-indirect-read-path` | ### Dataset ACL write — authorized view or dataset as an indirect read path | - | COVERED | `gcp-bigquery-authorized-view-bounded-table-access` (direct view entry), `gcp-bigquery-authorized-dataset-existing-view-bounded-table-access` (one preexisting view) |
| `#bigquerytransfersupdate--iamserviceaccountsactas--scheduled-sql-as-a-service-account` | ### `bigquery.transfers.update` + `iam.serviceAccounts.actAs` — scheduled SQL as a service account | bigquery.transfers.update, iam.serviceAccounts.actAs | COVERED | `gcp-bigquery-transfers-scheduled-query-actas` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-bigtable-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---bigtable-privilege-escalation` | # GCP - Bigtable Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#bigtable` | ## Bigtable | - | EXCLUDED | X: Page intro |
| `#bigtableinstancessetiampolicy--self-grant-across-one-instance` | ### `bigtable.instances.setIamPolicy` — self-grant across one instance | bigtable.instances.setIamPolicy | COVERED | `gcp-bigtable-instances-setiampolicy-instance-self-grant` |
| `#bigtabletablessetiampolicy--self-grant-on-one-table` | ### `bigtable.tables.setIamPolicy` — self-grant on one table | bigtable.tables.setIamPolicy | COVERED | `gcp-bigtable-tables-setiampolicy-table-self-grant` |
| `#bigtablebackupssetiampolicy--grant-restore-access-to-a-protected-backup` | ### `bigtable.backups.setIamPolicy` — grant restore access to a protected backup | bigtable.backups.setIamPolicy | COVERED | `gcp-bigtable-backups-setiampolicy-backup-self-grant` |
| `#authorizedmaterialized-view-setiampolicy--self-grant-scoped-data-access` | ### Authorized/materialized-view `setIamPolicy` — self-grant scoped data access | - | COVERED | `gcp-bigtable-authorizedviews-setiampolicy-authorized-view-self-grant`, `gcp-bigtable-materializedviews-setiampolicy-materialized-view-self-grant` |
| `#bigtableauthorizedviewsupdate--widen-a-view-that-you-can-already-use` | ### `bigtable.authorizedViews.update` — widen a view that you can already use | bigtable.authorizedViews.update | EXCLUDED | X: Widen an authorized view<br>`gcp-audit-s01-35-widen-a-view-caller-can-alre` — conditional verified exact-target authority. |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-billing-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---cloud-billing-privilege-escalation` | # GCP - Cloud Billing Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#cloud-billing` | ## Cloud Billing | - | EXCLUDED | X: Page intro |
| `#billingaccountssetiampolicy--self-grant-billing-account-administrator` | ### `billing.accounts.setIamPolicy` — self-grant Billing Account Administrator | billing.accounts.setIamPolicy | EXCLUDED | X: Self-grant billing.accounts.updatePaymentInfo on a billing account |
| `#why-other-billing-permissions-are-not-separate-privilege-escalation-techniques` | ## Why other billing permissions are not separate privilege-escalation techniques | - | EXCLUDED | X: Other billing permissions |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-certificate-authority-service-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---certificate-authority-service-privesc` | # GCP - Certificate Authority Service Privesc | - | STRUCTURAL | page title / intro / references |
| `#certificate-authority-service` | ## Certificate Authority Service | - | EXCLUDED | X: Service intro |
| `#certificate-authority-service-cas` | ## Certificate Authority Service (CAS) | - | EXCLUDED | X: Page intro |
| `#privatecacertificatescreate--issue-a-certificate-for-a-more-privileged-identity` | ### `privateca.certificates.create` — issue a certificate for a more privileged identity | privateca.certificates.create | EXCLUDED | gcp-v3-40-issue-a-certificate-for-another-identity (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#privatecacapoolssetiampolicy--grant-certificate-issuance-on-a-ca-pool` | ### `privateca.caPools.setIamPolicy` — grant certificate issuance on a CA pool | privateca.caPools.setIamPolicy | COVERED | `gcp-privateca-capools-setiampolicy-ca-pool-self-grant` |
| `#privatecacapoolsupdate-or-privatecacertificatetemplatesupdate--issuance--relax-certificate-constraints` | ### `privateca.caPools.update` or `privateca.certificateTemplates.update` + issuance — relax certificate constraints | privateca.caPools.update, privateca.certificateTemplates.update | EXCLUDED | gcp-v3-42-relax-issuance-constraints (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloud-deploy-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---cloud-deploy-privesc` | # GCP - Cloud Deploy Privesc | - | STRUCTURAL | page title / intro / references |
| `#cloud-deploy` | ## Cloud Deploy | - | EXCLUDED | X: Section intro |
| `#pipelinetarget-configuration--releaserollout-creation--run-an-attacker-task-as-an-execution-service-account` | ### Pipeline/target configuration + release/rollout creation — run an attacker task as an execution service account | clouddeploy.releases.create, clouddeploy.rollouts.create, storage.objects.create, iam.serviceAccounts.actAs, clouddeploy.targets.update, clouddeploy.deliveryPipelines.update, clouddeploy.targets.create, clouddeploy.deliveryPipelines.create | COVERED | `gcp-clouddeploy-pipeline-target-release-actas`<br>`gcp-clouddeploy-custom-target-render-actas` |
| `#clouddeployreleasescreate--clouddeployrolloutscreate--iamserviceaccountsactas--deploy-attacker-controlled-artifacts-through-an-existing-pipeline` | ### `clouddeploy.releases.create` + `clouddeploy.rollouts.create` + `iam.serviceAccounts.actAs` — deploy attacker-controlled artifacts through an existing pipeline | clouddeploy.releases.create, clouddeploy.rollouts.create, iam.serviceAccounts.actAs | COVERED | `gcp-clouddeploy-release-existing-pipeline` |
| `#cloud-deploy-resource-setiampolicy--self-grant-deployment-permissions` | ### Cloud Deploy resource `setIamPolicy` — self-grant deployment permissions | iam.serviceAccounts.actAs, clouddeploy.deliveryPipelines.setIamPolicy, clouddeploy.targets.setIamPolicy, clouddeploy.customTargetTypes.setIamPolicy | COVERED | `gcp-clouddeploy-resource-setiampolicy` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloud-workstations-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---cloud-workstations-privesc` | # GCP - Cloud Workstations Privesc | - | STRUCTURAL | page title / intro / references |
| `#cloud-workstations` | ## Cloud Workstations | - | STRUCTURAL | page title / intro / references |
| `#workstationsworkstationconfigscreate--actas--pin-an-arbitrary-sa-and-steal-its-token` | ### `workstations.workstationConfigs.create` (+ `actAs`) — pin an arbitrary SA and steal its token | workstations.workstationConfigs.create | COVERED | `gcp-workstations-config-create-actas`, `gcp-workstations-use-existing-workstation`<br>`gcp-workstations-create-from-existing-config` |
| `#code-exec-as-sa-via---container-custom-image----startup-script-uri-no-breakout-needed` | ### Code-exec-as-SA via `--container-custom-image` / `--startup-script-uri` (no breakout needed) | workstations.workstationConfigs.update, iam.serviceAccounts.actAs | COVERED | `gcp-workstations-config-update-code` |
| `#container-breakout-via-docker-socket-container---vm---project` | ### Container Breakout via Docker Socket (Container -> VM -> Project) | - | EXCLUDED | X: Docker socket breakout<br>`gcp-audit-s01-39-escape-workstation-container` — conditional verified exact-target authority. |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloudbuild-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---cloud-build-privilege-escalation` | # GCP - Cloud Build Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#cloud-build` | ## Cloud Build | - | EXCLUDED | X: Page intro |
| `#privilege-escalation-techniques` | ## Privilege Escalation Techniques | - | STRUCTURAL | page title / intro / references |
| `#cloudbuildbuildscreate--execute-build-steps-as-a-build-service-account` | ### `cloudbuild.builds.create` — Execute Build Steps as a Build Service Account | cloudbuild.builds.create | COVERED | `gcp-cloudbuild-builds-create-custom-sa-actas`, `gcp-cloudbuild-builds-create-default-identity` |
| `#cloudbuildrepositoriesaccessreadwritetoken--poison-source-consumed-by-a-privileged-trigger` | ### `cloudbuild.repositories.accessReadWriteToken` — Poison Source Consumed by a Privileged Trigger | cloudbuild.repositories.accessReadWriteToken | COVERED | `gcp-cloudbuild-repositories-accessreadwritetoken` |
| `#cloudbuildconnectionssetiampolicy--self-grant-repository-token-access` | ### `cloudbuild.connections.setIamPolicy` — Self-Grant Repository Token Access | cloudbuild.connections.setIamPolicy | COVERED | `gcp-cloudbuild-connections-setiampolicy-token-access` |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloudfunctions-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---cloud-run-functions-privilege-escalation` | # GCP - Cloud Run Functions Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#cloud-functions` | ## Cloud Functions | - | STRUCTURAL | page title / intro / references |
| `#cloudfunctionsfunctionscreate--source-upload--iamserviceaccountsactas--create-a-runtime-token-oracle` | ### `cloudfunctions.functions.create` + source upload + `iam.serviceAccounts.actAs` — create a runtime token oracle | cloudfunctions.functions.create, iam.serviceAccounts.actAs | COVERED | `gcp-cloudfunctions-create-actas` |
| `#cloudfunctionsfunctionsupdate--source-upload--replace-an-existing-privileged-function` | ### `cloudfunctions.functions.update` + source upload — replace an existing privileged function | cloudfunctions.functions.update | COVERED | `gcp-cloudfunctions-update-sourcecodeset-actas`, `gcp-cloudfunctions-setiampolicy-actas` |
| `#cloudfunctionsfunctionsupdate--inject-a-startup-loader-without-source-update-permission` | ### `cloudfunctions.functions.update` — inject a startup loader without source-update permission | cloudfunctions.functions.update | COVERED | `gcp-cloudfunctions-update-env-actas` |
| `#source-deploy--selected-build-service-account--execute-as-the-builder-before-deployment` | ### Source deploy + selected build service account — execute as the builder before deployment | cloudfunctions.functions.create, cloudfunctions.functions.sourceCodeSet, cloudfunctions.functions.generateUploadUrl, cloudfunctions.functions.update | COVERED | `gcp-cloudfunctions-source-deploy-build-identity` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloudidentity-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---cloud-identity-privilege-escalation` | # GCP - Cloud Identity Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#iam-principals--org-policies` | ## IAM, Principals & Org Policies | - | EXCLUDED | X: Page intro pointer |
| `#cloud-identity-groups` | ## Cloud Identity groups | - | STRUCTURAL | page title / intro / references |
| `#control-an-iam-bound-groups-membership--inherit-its-existing-gcp-roles` | ### Control an IAM-bound group's membership — inherit its existing GCP roles | cloudidentity.groups.memberships.create | COVERED | `gcp-cloudidentity-add-member-to-group` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloudscheduler-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---cloud-scheduler-privesc` | # GCP - Cloud Scheduler Privesc | - | STRUCTURAL | page title / intro / references |
| `#cloud-scheduler` | ## Cloud Scheduler | - | EXCLUDED | X: Page intro |
| `#cloudschedulerjobscreate-or-update--iamserviceaccountsactas--authenticated-http-dispatch-as-a-service-account` | ### `cloudscheduler.jobs.create` or `.update` + `iam.serviceAccounts.actAs` — authenticated HTTP dispatch as a service account | cloudscheduler.jobs.create, iam.serviceAccounts.actAs | COVERED | `gcp-cloudscheduler-jobs-create-actas`, `gcp-cloudscheduler-jobs-update-actas` |
| `#cloudschedulerjobsrun--force-a-preconfigured-privileged-request` | ### `cloudscheduler.jobs.run` — force a preconfigured privileged request | cloudscheduler.jobs.run | EXCLUDED | X: Force-run an existing job |
| `#cloudschedulerjobscreate-or-update--actas-free-app-engine-handler-invocation` | ### `cloudscheduler.jobs.create` or `.update` — actAs-free App Engine handler invocation | cloudscheduler.jobs.create | EXCLUDED | X: App Engine target without actAs |
| `#cloudschedulerjobscreate-or-update--publish-to-a-same-project-pubsub-topic-as-the-scheduler-service-agent` | ### `cloudscheduler.jobs.create` or `.update` — publish to a same-project Pub/Sub topic as the Scheduler service agent | cloudscheduler.jobs.create | EXCLUDED | X: Pub/Sub publish as the Scheduler service agent |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloudtasks-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---cloud-tasks-privesc` | # GCP - Cloud Tasks Privesc | - | STRUCTURAL | page title / intro / references |
| `#cloud-tasks` | ## Cloud Tasks | - | EXCLUDED | X: Page intro |
| `#cloudtaskstaskscreate-iamserviceaccountsactas` | ### `cloudtasks.tasks.create`, `iam.serviceAccounts.actAs` | cloudtasks.tasks.create, iam.serviceAccounts.actAs | COVERED | `gcp-cloudtasks-tasks-create-actas` |
| `#cloudtasksqueuescreate--cloudtasksqueuesupdate--queue-level-urioverride-silent-traffic-hijack--token-attach` | ### `cloudtasks.queues.create` / `cloudtasks.queues.update` — queue-level `uriOverride` (silent traffic hijack + token attach) | cloudtasks.queues.create, cloudtasks.queues.update | EXCLUDED | X: Queue-level uriOverride hijack |
| `#cloudtaskstaskscreate-app-engine-target--actas-free-app-engine-app-invocation` | ### `cloudtasks.tasks.create` (App Engine target) — actAs-free App Engine app invocation | cloudtasks.tasks.create | EXCLUDED | X: App Engine tasks without actAs |
| `#cloudtaskstasksrun-cloudtaskstaskslist` | ### `cloudtasks.tasks.run`, `cloudtasks.tasks.list` | cloudtasks.tasks.run, cloudtasks.tasks.list | EXCLUDED | X: Run existing tasks |
| `#cloudtasksqueuessetiampolicy` | ### `cloudtasks.queues.setIamPolicy` | cloudtasks.queues.setIamPolicy | COVERED | `gcp-cloudtasks-queues-setiampolicy-actas` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cluster-director-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---cluster-director-privilege-escalation` | # GCP - Cluster Director Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#cluster-director` | ## Cluster Director | - | STRUCTURAL | page title / intro / references |
| `#hypercomputeclusterclustersupdate--iamserviceaccountsactas--execute-a-login-node-startup-script-as-the-retained-vm-identity` | ### `hypercomputecluster.clusters.update` + `iam.serviceAccounts.actAs` — execute a login-node startup script as the retained VM identity | hypercomputecluster.clusters.update, iam.serviceAccounts.actAs | COVERED | `gcp-hypercomputecluster-login-node-startup-actas` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-composer-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---composer-privesc` | # GCP - Composer Privesc | - | STRUCTURAL | page title / intro / references |
| `#composer` | ## Composer | - | EXCLUDED | X: Page intro |
| `#managed-service-for-apache-airflow-cloud-composer` | ## Managed Service for Apache Airflow (Cloud Composer) | - | STRUCTURAL | page title / intro / references |
| `#composerenvironmentscreate--iamserviceaccountsactas--bucket-write--create-an-environment-over-a-chosen-identity` | ### `composer.environments.create` + `iam.serviceAccounts.actAs` + bucket write — create an environment over a chosen identity | composer.environments.create, iam.serviceAccounts.actAs | COVERED | `gcp-composer-environments-create-actas` |
| `#composerenvironmentsupdate--install-attacker-controlled-python-as-the-environment-identity` | ### `composer.environments.update` — install attacker-controlled Python as the environment identity | composer.environments.update | COVERED | `gcp-composer-environments-update` |
| `#composerenvironmentsexecuteairflowcommand--retrieve-airflow-secrets-or-run-available-dag-code` | ### `composer.environments.executeAirflowCommand` — retrieve Airflow secrets or run available DAG code | composer.environments.executeAirflowCommand | COVERED | `gcp-composer-environments-executeairflowcommand` |
| `#storageobjectscreate--inject-a-dag-into-an-existing-environment-bucket` | ### `storage.objects.create` — inject a DAG into an existing environment bucket | storage.objects.create | COVERED | `gcp-composer-bucket-write` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-compute-privesc/README.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#computeimagessetiampolicy--self-grant-image-use` | ### Self-grant compute.images.useReadOnly on a image | compute.images.setIamPolicy | COVERED | `gcp-compute-images-setiampolicy-image-self-grant` |
| `#gcp---compute-privesc` | # GCP - Compute Privesc | - | STRUCTURAL | page title / intro / references |
| `#compute` | ## Compute | - | EXCLUDED | X: Page intro |
| `#computeprojectssetcommoninstancemetadata` | ### `compute.projects.setCommonInstanceMetadata` | compute.projects.setCommonInstanceMetadata | COVERED | `gcp-compute-projects-setcommoninstancemetadata` |
| `#computeinstancessetmetadata` | ### `compute.instances.setMetadata` | compute.instances.setMetadata | COVERED | `gcp-compute-instances-setmetadata-existing-vm` |
| `#computeinstancessetiampolicy` | ### `compute.instances.setIamPolicy` | compute.instances.setIamPolicy | COVERED | `gcp-compute-instances-setiampolicy` |
| `#computeinstancesoslogin` | ### **`compute.instances.osLogin`** | compute.instances.osLogin | COVERED | `gcp-compute-instances-oslogin` |
| `#computeinstancesosadminlogin` | ### **`compute.instances.osAdminLogin`** | compute.instances.osAdminLogin | COVERED | `gcp-compute-instances-osadminlogin` |
| `#computeinstancescreate--configuration-dependent-vm-permissions--iamserviceaccountsactas` | ### `compute.instances.create` + configuration-dependent VM permissions + `iam.serviceAccounts.actAs` | compute.instances.create, iam.serviceAccounts.actAs | COVERED | `gcp-compute-instances-create-actas` |
| `#computeinstancetemplatescreate--computeinstancegroupmanagerscreate--run-as-sa-via-a-managed-instance-group` | ### `compute.instanceTemplates.create` + `compute.instanceGroupManagers.create` — run-as-SA via a Managed Instance Group | compute.instanceTemplates.create, compute.instanceGroupManagers.create | COVERED | `gcp-compute-instancetemplates-mig-actas` |
| `#computeinstancessetserviceaccount-iamserviceaccountsactas--swap-an-existing-vms-service-account` | ### `compute.instances.setServiceAccount`, `iam.serviceAccounts.actAs` — swap an EXISTING VM's service account | compute.instances.setServiceAccount, iam.serviceAccounts.actAs | COVERED | `gcp-compute-instances-setserviceaccount-actas` |
| `#osconfigpatchdeploymentscreate--osconfigpatchjobsexec` | ### `osconfig.patchDeployments.create` \| `osconfig.patchJobs.exec` | osconfig.patchDeployments.create, osconfig.patchJobs.exec | EXCLUDED | X: OS Config patch deployment pre/post steps |
| `#computemachineimagessetiampolicy` | ### `compute.machineImages.setIamPolicy` | compute.machineImages.setIamPolicy | COVERED | `gcp-compute-machineimages-setiampolicy-machine-image-self-grant` |
| `#computesnapshotssetiampolicy` | ### `compute.snapshots.setIamPolicy` | compute.snapshots.setIamPolicy | COVERED | `gcp-compute-snapshots-setiampolicy-snapshot-self-grant` |
| `#computerecoverablesnapshotssetiampolicy` | ### `compute.recoverableSnapshots.setIamPolicy` | compute.recoverableSnapshots.setIamPolicy | COVERED | `gcp-compute-recoverablesnapshots-setiampolicy-recoverable-snapshot-self-grant` |
| `#computediskssetiampolicy` | ### `compute.disks.setIamPolicy` | compute.disks.setIamPolicy | COVERED | `gcp-compute-disks-setiampolicy-disk-self-grant` |
| `#local-privilege-escalation-in-gcp-compute-instance` | ### Local Privilege Escalation in GCP Compute instance | - | EXCLUDED | X: Local privesc inside a VM |
| `#computeinstancessetmetadata--windows-local-administrator-reset-windows-keys` | ### `compute.instances.setMetadata` — Windows local-Administrator reset (`windows-keys`) | compute.instances.setMetadata | EXCLUDED | X: Windows local Administrator reset via windows-keys metadata |
| `#computeinstancegroupmanagersupdate--templatevm-permissions--hijack-an-existing-managed-instance-group` | ### `compute.instanceGroupManagers.update` + template/VM permissions — hijack an EXISTING Managed Instance Group | compute.instanceGroupManagers.update | COVERED | `gcp-compute-instancegroupmanagers-update-template` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-compute-privesc/gcp-add-custom-ssh-metadata.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---add-custom-ssh-metadata` | # GCP - Add Custom SSH Metadata | - | STRUCTURAL | page title / intro / references |
| `#compute` | ## Compute | - | EXCLUDED | X: Compute intro |
| `#add-an-ssh-key-to-one-vm---computeinstancessetmetadata` | ### Add an SSH key to one VM - `compute.instances.setMetadata` | compute.instances.setMetadata | EXCLUDED | X: SSH key on one VM via compute.instances.setMetadata |
| `#add-a-project-wide-ssh-key---computeprojectssetcommoninstancemetadata` | ### Add a project-wide SSH key - `compute.projects.setCommonInstanceMetadata` | compute.projects.setCommonInstanceMetadata | EXCLUDED | X: Project-wide SSH key via compute.projects.setCommonInstanceMetadata |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-config-controller-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---config-controller-privilege-escalation` | # GCP - Config Controller Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#config-controller--config-connector-kcc` | ## Config Controller / Config Connector (KCC) | - | EXCLUDED | X: Config Controller / KCC intro |
| `#config-controller` | ## Config Controller | - | STRUCTURAL | page title / intro / references |
| `#kubernetes-rbac-over-a-kcc-resource--act-as-the-configured-config-connector-identity` | ### Kubernetes RBAC over a KCC resource — act as the configured Config Connector identity | container.thirdPartyObjects.create, container.thirdPartyObjects.update | COVERED | `gcp-configcontroller-kcc-resource-write` |
| `#kcc-iamserviceaccountkey-plus-secret-read--mint-a-long-lived-key-for-a-more-privileged-service-account` | ### KCC `IAMServiceAccountKey` plus Secret read — mint a long-lived key for a more privileged service account | - | EXCLUDED | X: KCC IAMServiceAccountKey plus Secret read |
| `#durable-instance-iam-binding-krmapihostingkrmapihostssetiampolicy` | ## Durable instance IAM binding (`krmapihosting.krmApiHosts.setIamPolicy`) | krmapihosting.krmApiHosts.setIamPolicy | COVERED | `gcp-krmapihosting-krmapihosts-setiampolicy-krm-api-host-self-grant` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-config-delivery-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---config-delivery-privesc` | # GCP - Config Delivery Privesc | - | STRUCTURAL | page title / intro / references |
| `#config-delivery` | ## Config Delivery | - | EXCLUDED | X: Config Delivery intro |
| `#config-delivery-configdeliverygoogleapiscom` | ## Config Delivery (`configdelivery.googleapis.com`) | - | STRUCTURAL | page title / intro / references |
| `#resourcebundlescreate--releasescreate--variantscreate--releasesupdate--fleetpackagescreate--publish-manifests-to-fleet-clusters` | ### `resourceBundles.create` + `releases.create` + `variants.create` + `releases.update` + `fleetPackages.create` — publish manifests to fleet clusters | resourceBundles.create, releases.create, variants.create, releases.update, fleetPackages.create | COVERED | `gcp-configdelivery-fleetpackage-publish` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-container-analysis-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---container-analysis-privilege-escalation` | # GCP - Container Analysis Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#container-analysis--artifact-analysis` | ## Container Analysis / Artifact Analysis | - | EXCLUDED | X: Container Analysis intro |
| `#container-analysis` | ## Container Analysis | - | STRUCTURAL | page title / intro / references |
| `#containeranalysisnotessetiampolicy--self-grant-control-of-one-note` | ### `containeranalysis.notes.setIamPolicy` — self-grant control of one note | containeranalysis.notes.setIamPolicy | COVERED | `gcp-containeranalysis-notes-setiampolicy-note-self-grant` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-container-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---container-privesc` | # GCP - Container Privesc | - | STRUCTURAL | page title / intro / references |
| `#containers--gke` | ## Containers & GKE | - | EXCLUDED | X: Page intro (Containers & GKE) |
| `#container` | ## container | - | EXCLUDED | X: Page intro |
| `#containerclustersget` | ### `container.clusters.get` | container.clusters.get | EXCLUDED | X: clusters.get / getCredentials |
| `#containerrolesescalate--containerclusterrolesescalate` | ### `container.roles.escalate` \| `container.clusterRoles.escalate` | container.roles.escalate, container.clusterRoles.escalate | COVERED | `gcp-container-clusterroles-escalate` |
| `#containerrolesbind--containerclusterrolesbind` | ### `container.roles.bind` \| `container.clusterRoles.bind` | container.roles.bind, container.clusterRoles.bind | COVERED | `gcp-container-clusterroles-bind`<br>`gcp-container-namespaced-rbac-ksa` |
| `#workload-and-pod-create--update-permissions` | ### Workload and Pod `create` / `update` permissions | container.pods.create, container.deployments.create, container.daemonSets.create, container.jobs.create, container.cronJobs.create, container.statefulSets.create, container.replicaSets.create, container.replicationControllers.create, container.deployments.update, container.daemonSets.update, container.statefulSets.update, container.cronJobs.update, container.pods.update | COVERED | `gcp-container-pod-template-node-sa`<br>`gcp-container-pod-template-ksa` |
| `#environment--command-injection-into-an-admitted-workload-binary-authorization-bypass` | ### Environment / command injection into an admitted workload (Binary Authorization bypass) | - | EXCLUDED | X: Env/command injection into an admitted workload (Binary Authorization bypass) |
| `#containersecretsget--containersecretslist` | ### `container.secrets.get` \| `container.secrets.list` | container.secrets.get, container.secrets.list | COVERED | `gcp-container-secrets-read-ksa-token-secret` |
| `#containerpodsexec` | ### `container.pods.exec` | container.pods.exec | COVERED | `gcp-container-pods-exec-node-sa`<br>`gcp-container-pods-exec-running-ksa` |
| `#containerpodsgetlogs` | ### `container.pods.getLogs` | container.pods.getLogs | EXCLUDED | X: Read pod logs |
| `#containerpodsattach` | ### `container.pods.attach` | container.pods.attach | EXCLUDED | X: Attach to running containers |
| `#containerpodsportforward` | ### `container.pods.portForward` | container.pods.portForward | EXCLUDED | X: Port-forward to pods |
| `#containerpodsproxy--containerservicesproxy` | ### `container.pods.proxy` \| `container.services.proxy` | container.pods.proxy, container.services.proxy | EXCLUDED | X: Proxy to pods/services |
| `#containernodesproxy` | ### `container.nodes.proxy` | container.nodes.proxy | COVERED | `gcp-container-nodes-proxy-node-sa`<br>`gcp-container-nodes-proxy-running-ksa` |
| `#containerserviceaccountscreatetoken` | ### `container.serviceAccounts.createToken` | container.serviceAccounts.createToken | COVERED | `gcp-container-serviceaccounts-createtoken` |
| `#containermutatingwebhookconfigurationscreate--containermutatingwebhookconfigurationsupdate` | ### `container.mutatingWebhookConfigurations.create` \| `container.mutatingWebhookConfigurations.update` | container.mutatingWebhookConfigurations.create, container.mutatingWebhookConfigurations.update | COVERED | `gcp-container-mutatingwebhookconfigurations-write` |
| `#containerclusterscreate-or-containerclustersupdate--iamserviceaccountsactas--run-new-nodes-as-an-attacker-chosen-sa` | ### `container.clusters.create` or `container.clusters.update` + `iam.serviceAccounts.actAs` — run new nodes as an attacker-chosen SA | container.clusters.create, container.clusters.update, iam.serviceAccounts.actAs | COVERED | `gcp-container-clusters-nodepools-create-actas` |
| `#containerclustersupdate--access-control--security-config-tamper` | ### `container.clusters.update` — access-control / security-config tamper | container.clusters.update | EXCLUDED | X: clusters.update security tamper |
| `#containerclustersupdate--enable-legacy-authorization-abac` | ### `container.clusters.update` — enable Legacy Authorization (ABAC) | container.clusters.update | EXCLUDED | X: container.clusters.update enables legacy ABAC |
| `#containerclustersimpersonate--kubernetes-usergroup-impersonation---as-groupsystemmasters` | ### `container.clusters.impersonate` — Kubernetes user/group impersonation (`--as-group=system:masters`) | container.clusters.impersonate | COVERED | `gcp-container-clusters-impersonate` |
| `#containerclustersupdate-updatenodepool--expose-an-existing-node-pools-sa-to-pods` | ### `container.clusters.update` (`UpdateNodePool`) — expose an existing node pool's SA to pods | container.clusters.update | COVERED | `gcp-container-updatenodepool-expose-node-sa` |
| `#gkehub--fleet--connect-gateway` | ## gkehub — Fleet & Connect Gateway | - | EXCLUDED | X: Fleet section intro |
| `#gkehubgatewaygeneratecredentials--kubectl-via-connect-gateway-no-network-path` | ### `gkehub.gateway.generateCredentials` — kubectl via Connect Gateway (no network path) | gkehub.gateway.generateCredentials | EXCLUDED | X: Connect Gateway credentials |
| `#gkehubmembershipssetiampolicy--self-grant-connect-gateway-access` | ### `gkehub.memberships.setIamPolicy` — self-grant Connect Gateway access | gkehub.memberships.setIamPolicy | COVERED | `gcp-gkehub-memberships-setiampolicy-membership-self-grant` |
| `#gkehubrbacrolebindingscreate--fleet-managed-in-cluster-rbac` | ### `gkehub.rbacrolebindings.create` — fleet-managed in-cluster RBAC | gkehub.rbacrolebindings.create | COVERED | `gcp-gkehub-rbacrolebindings-gateway` |
| `#gkehubfeatures--config-management--fleet-wide-manifest-push-rce` | ### `gkehub.features.*` + Config Management — fleet-wide manifest-push RCE | gkehub.features.create, gkehub.membershipfeatures.update, gkehub.features.update, gkehub.membershipfeatures.create | COVERED | `gcp-gkehub-features-configmanagement` |
| `#credential-minting-is-not-authorization` | ## Credential minting is not authorization | - | EXCLUDED | X: Credential minting helpers (gkemulticloud generateAccessToken |
| `#historical-gke-kubelet-tls-bootstrap-credential-path` | ### Historical GKE kubelet TLS bootstrap credential path | - | EXCLUDED | X: Historical GKE kubelet TLS bootstrap credentials |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-data-fusion-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---data-fusion-privilege-escalation` | # GCP - Data Fusion Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#data-fusion` | ## Data Fusion | - | STRUCTURAL | page title / intro / references |
| `#create-and-execute-a-pipeline-as-its-configured-vm-service-account` | ### Create and execute a pipeline as its configured VM service account | datafusion.instances.get, datafusion.pipelines.create, datafusion.pipelines.execute | COVERED | `gcp-datafusion-pipelines-create-execute` |
| `#preview-source-data-as-the-design-time-service-account` | ### Preview source data as the design-time service account | - | EXCLUDED | X: Pipeline Preview as the design-time identity |
| `#self-grant-a-data-fusion-instance-or-namespace-role` | ### Self-grant a Data Fusion instance or namespace role | datafusion.instances.setIamPolicy, datafusion.namespaces.setIamPolicy | COVERED | `gcp-datafusion-setiampolicy-self-grant` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-database-migration-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---database-migration-service-privesc` | # GCP - Database Migration Service Privesc | - | STRUCTURAL | page title / intro / references |
| `#database-migration-service` | ## Database Migration Service | - | EXCLUDED | X: Page intro |
| `#database-migration-service-datamigrationgoogleapiscom` | ## Database Migration Service (`datamigration.googleapis.com`) | datamigration.googleapis.com | EXCLUDED | X: Page intro |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-dataflow-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---dataflow-privilege-escalation` | # GCP - Dataflow Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#dataflow` | ## Dataflow | - | EXCLUDED | X: Page intro |
| `#storageobjectscreate--storageobjectsdelete--poison-a-trusted-dataflow-artifact` | ### `storage.objects.create` + `storage.objects.delete` — poison a trusted Dataflow artifact | storage.objects.create, storage.objects.delete | COVERED | `gcp-dataflow-udf-template-bucket-write` |
| `#dataflowjobscreate--iamserviceaccountsactas--execute-code-as-a-selected-worker-service-account` | ### `dataflow.jobs.create` + `iam.serviceAccounts.actAs` — execute code as a selected worker service account | dataflow.jobs.create, iam.serviceAccounts.actAs | COVERED | `gcp-dataflow-jobs-create-actas` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-dataform-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---dataform-privilege-escalation` | # GCP - Dataform Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#dataform` | ## Dataform | - | EXCLUDED | X: Page intro |
| `#dataformrepositoriescreate--iamserviceaccountsactas--create-an-attacker-controlled-run-as-repository` | ### `dataform.repositories.create` + `iam.serviceAccounts.actAs` — create an attacker-controlled run-as repository | dataform.repositories.create, iam.serviceAccounts.actAs | COVERED | `gcp-dataform-workflow-invocation-actas` |
| `#dataformworkflowinvocationscreate--invoke-an-existing-compilation-result-or-user-credential-workflow` | ### `dataform.workflowInvocations.create` — invoke an existing compilation result or user-credential workflow | dataform.workflowInvocations.create | NON-PRIVESC | gcp-dataform-workflowconfig-end-user-invoke<br>gcp-dataform-existing-compilation-result-actas — conditional verified exact-target authority. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-dataplex-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---dataplex-privilege-escalation` | # GCP - Dataplex Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#dataplex` | ## Dataplex | - | EXCLUDED | X: Section intro |
| `#dataplextaskscreate--iamserviceaccountsactas--execute-attacker-code-as-a-service-account` | ### `dataplex.tasks.create` + `iam.serviceAccounts.actAs` — execute attacker code as a service account | dataplex.tasks.create, iam.serviceAccounts.actAs | COVERED | `gcp-dataplex-tasks-create-actas` |
| `#dataplexlakeszonesassetssetiampolicy--self-grant-backing-data-access-through-managed-asset-iam` | ### `dataplex.{lakes,zones,assets}.setIamPolicy` — self-grant backing-data access through managed asset IAM | - | EXCLUDED | X: Self-grant storage.objects.get on a lake |
| `#datacatalogcategoriessetiampolicy--self-grant-fine-grained-access-to-policy-tagged-bigquery-columns` | ### `datacatalog.categories.setIamPolicy` — self-grant fine-grained access to policy-tagged BigQuery columns | datacatalog.categories.setIamPolicy | COVERED | `gcp-datacatalog-categories-setiampolicy-policy-tag-self-grant` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-dataproc-metastore-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---dataproc-metastore-privesc` | # GCP - Dataproc Metastore Privesc | - | STRUCTURAL | page title / intro / references |
| `#dataproc-metastore` | ## Dataproc Metastore | - | EXCLUDED | X: Page intro |
| `#metastoreservicessetiampolicy---grant-access-to-grpc-metadata` | ## `metastore.services.setIamPolicy` - grant access to gRPC metadata | metastore.services.setIamPolicy | COVERED | `gcp-metastore-services-setiampolicy-metastore-service-self-grant` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-dataproc-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp-dataproc-privilege-escalation` | # GCP Dataproc Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#dataproc` | ## Dataproc | - | EXCLUDED | X: Page intro |
| `#dataprocclustersget-dataprocclustersuse-dataprocjobscreate-dataprocjobsget-dataprocjobslist-storageobjectscreate-storageobjectsget` | ### `dataproc.clusters.get`, `dataproc.clusters.use`, `dataproc.jobs.create`, `dataproc.jobs.get`, `dataproc.jobs.list`, `storage.objects.create`, `storage.objects.get` | dataproc.clusters.get, dataproc.clusters.use, dataproc.jobs.create, dataproc.jobs.get, dataproc.jobs.list, storage.objects.create, storage.objects.get | COVERED | `gcp-dataproc-jobs-create-existing-cluster` |
| `#steps-to-exploit` | #### Steps to exploit | - | EXCLUDED | X: Exploitation steps sub-section |
| `#dataprocclusterscreate--dataprocbatchescreate--iamserviceaccountsactas--attach-an-arbitrary-service-account` | ### `dataproc.clusters.create` / `dataproc.batches.create` (+ `iam.serviceAccounts.actAs`) — attach an arbitrary service account | dataproc.clusters.create, dataproc.batches.create, iam.serviceAccounts.actAs | COVERED | `gcp-dataproc-clusters-batches-create-actas` |
| `#dataprocsessionscreate--dataprocsessiontemplatescreate--interactive-serverless-session-run-as-sa` | ### `dataproc.sessions.create` / `dataproc.sessionTemplates.create` — interactive Serverless session run-as-SA | dataproc.sessions.create, dataproc.sessionTemplates.create | COVERED | `gcp-dataproc-sessions-create-actas` |
| `#dataprocclusterssetiampolicy--self-grant-use-of-a-specific-cluster` | ### `dataproc.clusters.setIamPolicy` — self-grant use of a specific cluster | dataproc.clusters.setIamPolicy | COVERED | `gcp-dataproc-clusters-setiampolicy` |
| `#dataprocworkflowtemplatescreate----initialization-actions--template--init-action-tamper-persistence` | ### `dataproc.workflowTemplates.create` / `--initialization-actions` — template & init-action tamper (persistence) | dataproc.workflowTemplates.create | COVERED | `gcp-dataproc-workflowtemplates-actas` |
| `#--scopescloud-platform-at-cluster-create--oauth-scope-amplification-of-a-stolen-node-token` | ### `--scopes=cloud-platform` at cluster create — OAuth-scope amplification of a stolen node token | - | EXCLUDED | X: --scopes=cloud-platform at cluster create |
| `#component-gateway-jupyter--zeppelin--interactive-code-exec-as-the-cluster-sa-without-jobscreate` | ### Component Gateway (Jupyter / Zeppelin) — interactive code-exec as the cluster SA without `jobs.create` | jobs.create | COVERED | `gcp-dataproc-component-gateway-existing-cluster` |
| `#--metadata-startup-script--ssh-keys-at-cluster-create--root-node-takeover-without-an-init-action` | ### `--metadata startup-script` / `ssh-keys` at cluster create — root node takeover without an init-action | - | EXCLUDED | X: Startup-script / ssh-keys metadata at cluster create |
| `#--container-image-on-serverless-workloads--dependencyenvironment-poisoning` | ### `--container-image` on Serverless workloads — dependency/environment poisoning | - | EXCLUDED | X: Serverless --container-image dependency poisoning |
| `#dataprocclustersget--config-leak-sa--scopes--buckets--metadata--properties--staging-bucket-poison` | ### `dataproc.clusters.get` — config leak (SA / scopes / buckets / metadata / properties) + staging-bucket poison | dataproc.clusters.get | COVERED | `gcp-dataproc-staging-object-replace`<br>`gcp-dataproc-staging-object-plant` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-datastream-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---datastream-privesc` | # GCP - Datastream Privesc | - | STRUCTURAL | page title / intro / references |
| `#datastream` | ## Datastream | - | EXCLUDED | X: Page intro |
| `#datastream-datastreamgoogleapiscom` | ## Datastream (`datastream.googleapis.com`) | datastream.googleapis.com | EXCLUDED | X: Page intro |
| `#datastreamconnectionprofilescreate--datastreamstreamscreate--full-database-copy-out-confused-deputy` | ### `datastream.connectionProfiles.create` + `datastream.streams.create` — full-database copy-out (confused deputy) | datastream.connectionProfiles.create, datastream.streams.create | EXCLUDED | X: Stream database copy-out |
| `#zero-credential-native-gcp-source-spanner--pure-iam-confused-deputy` | ### Zero-credential native-GCP source (Spanner) — pure-IAM confused deputy | - | EXCLUDED | X: Spanner source zero-credential confused deputy |
| `#differences-from-dms-and-negative-results` | ### Differences from DMS and negative results | - | EXCLUDED | X: Negative results |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-deploymentmaneger-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---deployment-manager-privilege-escalation` | # GCP - Deployment Manager Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#deployment-manager` | ## Deployment Manager | - | EXCLUDED | X: Page intro |
| `#cloud-deployment-manager-deploymentmanagergoogleapiscom` | ## Cloud Deployment Manager (`deploymentmanager.googleapis.com`) | deploymentmanager.googleapis.com | EXCLUDED | X: Service availability intro |
| `#deploymentmanagerdeploymentscreate--update--deploy-through-the-google-apis-service-agent` | ### `deploymentmanager.deployments.create` / `.update` — deploy through the Google APIs Service Agent | deploymentmanager.deployments.create | COVERED | `gcp-deploymentmanager-deployments-create`, `gcp-deploymentmanager-deployments-update` |
| `#deploymentmanagerdeploymentssetiampolicy--self-grant-control-of-one-existing-deployment` | ### `deploymentmanager.deployments.setIamPolicy` — self-grant control of one existing deployment | deploymentmanager.deployments.setIamPolicy | COVERED | `gcp-deploymentmanager-deployments-setiampolicy` |
| `#rejected-or-reclassified-ideas` | ## Rejected or reclassified ideas | - | EXCLUDED | X: Rejected or reclassified ideas |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-developer-connect-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---developer-connect-privilege-escalation` | # GCP - Developer Connect Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#developer-connect` | ## Developer Connect | - | EXCLUDED | X: Page intro |
| `#fetchreadwritetoken-or-git-proxy-write---poison-a-privileged-repository-driven-pipeline` | ### `fetchReadWriteToken` or Git proxy write -> poison a privileged repository-driven pipeline | developerconnect.gitRepositoryLinks.fetchReadWriteToken | COVERED | `gcp-developerconnect-readwrite-token-pipeline-poison` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-discovery-engine-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---discovery-engine-privilege-escalation` | # GCP - Discovery Engine Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#vertex-ai-search-discovery-engine` | ## Vertex AI Search (Discovery Engine) | - | EXCLUDED | X: Page intro |
| `#discoveryengineenginesdatastorescollectionssetiampolicy--self-grant-app-or-corpus-access` | ### `discoveryengine.{engines,dataStores,collections}.setIamPolicy` — self-grant app or corpus access | - | COVERED | `gcp-discoveryengine-engines-setiampolicy-engine-self-grant`, `gcp-discoveryengine-datastores-setiampolicy-data-store-self-grant`, `gcp-discoveryengine-collections-setiampolicy-collection-self-grant` |
| `#discoveryengineidentitymappingstoresimportidentitymappings--inject-an-identity-mapping-to-bypass-per-document-acls` | ### `discoveryengine.identityMappingStores.importIdentityMappings` — inject an identity mapping to bypass per-document ACLs | discoveryengine.identityMappingStores.importIdentityMappings | EXCLUDED | X: importIdentityMappings ACL bypass |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-eventarc-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---eventarc-privesc` | # GCP - Eventarc Privesc | - | STRUCTURAL | page title / intro / references |
| `#eventarc` | ## Eventarc | - | EXCLUDED | X: Page intro |
| `#eventarcpipelinescreate--iamserviceaccountsactas--receive-an-oauth-token-for-a-service-account` | ### `eventarc.pipelines.create` + `iam.serviceAccounts.actAs` — receive an OAuth token for a service account | eventarc.pipelines.create, iam.serviceAccounts.actAs | COVERED | `gcp-eventarc-pipeline-oauth-token-actas` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-firebase-app-hosting-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---firebase-app-hosting-privesc` | # GCP - Firebase App Hosting Privesc | - | STRUCTURAL | page title / intro / references |
| `#firebase-app-hosting` | ## Firebase App Hosting | - | EXCLUDED | X: Page intro |
| `#firebaseapphostingbuildscreate--firebaseapphostingrolloutscreate--deploy-an-image-as-an-existing-backend-identity` | ### `firebaseapphosting.builds.create` + `firebaseapphosting.rollouts.create` — deploy an image as an existing backend identity | firebaseapphosting.builds.create, firebaseapphosting.rollouts.create | COVERED | `gcp-firebaseapphosting-build-rollout-existing-backend` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-firebase-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---firebase-privesc` | # GCP - Firebase Privesc | - | STRUCTURAL | page title / intro / references |
| `#firebase` | ## Firebase | - | EXCLUDED | X: Page intro |
| `#firebaseauthusersupdate--take-over-an-application-user-or-set-privileged-custom-claims` | ### `firebaseauth.users.update` — take over an application user or set privileged custom claims | firebaseauth.users.update | COVERED | `gcp-firebaseauth-users-update-exact-user-credential` (password takeover with exact reviewed user and new authorization; claim-only gain remains unmodeled) |
| `#service-account-signing-access--mint-firebase-custom-tokens-with-arbitrary-claims` | ### Service-account signing access — mint Firebase custom tokens with arbitrary claims | iam.serviceAccounts.signBlob, iam.serviceAccounts.signJwt | COVERED | `gcp-firebase-signblob-exact-custom-token-user`, `gcp-firebase-signjwt-exact-custom-token-user` (keyless signing paths with exact reviewed UID, exchange, and new authorization; offline-key path remains unmodeled) |
| `#firebaseauthconfigsupdate--hijack-identity-platform-blocking-functions` | ### `firebaseauth.configs.update` — hijack Identity Platform blocking functions | firebaseauth.configs.update | COVERED | `gcp-firebaseauth-configs-update-exact-idp-principal` (actual forwarded usable IdP token and newly allowed target action; claim-only effects remain unmodeled) |
| `#identitytoolkittenantssetiampolicy--self-grant-control-of-an-identity-platform-tenant` | ### `identitytoolkit.tenants.setIamPolicy` — self-grant control of an Identity Platform tenant | identitytoolkit.tenants.setIamPolicy | COVERED | `gcp-identitytoolkit-tenants-setiampolicy-tenant-self-grant` |
| `#firebaserulesrulesetscreate--firebaserulesreleasesupdate--open-firestore-or-storage-data-through-security-rules` | ### `firebaserules.rulesets.create` + `firebaserules.releases.update` — open Firestore or Storage data through Security Rules | firebaserules.rulesets.create, firebaserules.releases.update | EXCLUDED | X: Security Rules allow-all release |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-healthcare-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---cloud-healthcare-privilege-escalation` | # GCP - Cloud Healthcare Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#cloud-healthcare-api` | ## Cloud Healthcare API | - | EXCLUDED | X: Page intro |
| `#healthcaresetiampolicy--grant-a-clinical-data-role-to-your-principal` | ### `healthcare.*.setIamPolicy` — grant a clinical-data role to your principal | - | COVERED | `gcp-healthcare-datasets-setiampolicy-dataset-self-grant`, `gcp-healthcare-fhirstores-setiampolicy-fhir-store-self-grant`, `gcp-healthcare-dicomstores-setiampolicy-dicom-store-self-grant`, `gcp-healthcare-hl7v2stores-setiampolicy-hl7v2-store-self-grant`, `gcp-healthcare-consentstores-setiampolicy-consent-store-self-grant` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-iam-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---iam-privesc` | # GCP - IAM Privesc | - | STRUCTURAL | page title / intro / references |
| `#iam-principals--org-policies` | ## IAM, Principals & Org Policies | - | EXCLUDED | X: Page intro (IAM, Principals & Org Policies) |
| `#iam` | ## IAM | - | EXCLUDED | X: Page intro |
| `#iamrolesupdate--add-permissions-to-an-already-bound-custom-role` | ### `iam.roles.update` — add permissions to an already-bound custom role | iam.roles.update | COVERED | `gcp-iam-roles-update-own-custom-role` |
| `#iamserviceaccountsgetaccesstoken--impersonate-a-service-account` | ### `iam.serviceAccounts.getAccessToken` — impersonate a service account | iam.serviceAccounts.getAccessToken | COVERED | `gcp-iam-serviceaccounts-getaccesstoken` |
| `#iamserviceaccountkeyscreate--create-or-upload-a-durable-private-key` | ### `iam.serviceAccountKeys.create` — create or upload a durable private key | iam.serviceAccountKeys.create | COVERED | `gcp-iam-serviceaccountkeys-create` |
| `#iamserviceaccountsimplicitdelegation--reach-a-service-account-through-a-delegation-chain` | ### `iam.serviceAccounts.implicitDelegation` — reach a service account through a delegation chain | iam.serviceAccounts.implicitDelegation | COVERED | `gcp-iam-serviceaccounts-implicitdelegation` |
| `#iamserviceaccountssignblob--iamserviceaccountssignjwt--sign-an-assertion-and-exchange-it-for-tokens` | ### `iam.serviceAccounts.signBlob` / `iam.serviceAccounts.signJwt` — sign an assertion and exchange it for tokens | iam.serviceAccounts.signBlob, iam.serviceAccounts.signJwt | COVERED | `gcp-iam-serviceaccounts-signblob`, `gcp-iam-serviceaccounts-signjwt` |
| `#iamserviceaccountssetiampolicy--grant-yourself-token-creation-access` | ### `iam.serviceAccounts.setIamPolicy` — grant yourself token-creation access | iam.serviceAccounts.setIamPolicy | COVERED | `gcp-iam-serviceaccounts-setiampolicy` |
| `#iamserviceaccountsgetopenidtoken--impersonate-a-service-account-to-an-oidc-protected-application` | ### `iam.serviceAccounts.getOpenIdToken` — impersonate a service account to an OIDC-protected application | iam.serviceAccounts.getOpenIdToken | EXCLUDED | X: iam.serviceAccounts.getOpenIdToken |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-iap-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---iap-privesc` | # GCP - IAP Privesc | - | STRUCTURAL | page title / intro / references |
| `#iap` | ## IAP | - | EXCLUDED | X: Page intro |
| `#identity-aware-proxy-iap` | ## Identity-Aware Proxy (IAP) | - | EXCLUDED | X: Page intro |
| `#iaptunnelinstancesaccessviaiap--ssh--tunnel-to-internal-only-vms` | ### `iap.tunnelInstances.accessViaIAP` — SSH / tunnel to internal-only VMs | iap.tunnelInstances.accessViaIAP | EXCLUDED | X: IAP tunnel access |
| `#iaptunnelinstancessetiampolicy--iaptunnelzonessetiampolicy` | ### `iap.tunnelInstances.setIamPolicy` , `iap.tunnelZones.setIamPolicy` | iap.tunnelInstances.setIamPolicy, iap.tunnelZones.setIamPolicy | COVERED | `gcp-iap-tunnelinstances-setiampolicy-instance-self-grant`, `gcp-iap-tunnelzones-setiampolicy-zone-self-grant` |
| `#iapweb-resources` | ### `iap.web*` resources | - | EXCLUDED | X: IAP web resources |
| `#iapwebupdatesettings--weaken-iap-enforcement-settings-tamper` | ### `iap.web.updateSettings` — weaken IAP enforcement (settings tamper) | iap.web.updateSettings | EXCLUDED | X: IAP settings tamper |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-infra-manager-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---infrastructure-manager-privesc` | # GCP - Infrastructure Manager Privesc | - | STRUCTURAL | page title / intro / references |
| `#infra-manager` | ## Infra Manager | - | EXCLUDED | X: Page intro |
| `#infrastructure-manager` | ## Infrastructure Manager | - | EXCLUDED | X: Section intro |
| `#configdeploymentscreate--iamserviceaccountsactas--apply-terraform-as-a-selected-service-account` | ### `config.deployments.create` + `iam.serviceAccounts.actAs` — apply Terraform as a selected service account | config.deployments.create, iam.serviceAccounts.actAs | COVERED | `gcp-inframanager-deployments-create-actas` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-integration-connectors-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---integration-connectors-privesc` | # GCP - Integration Connectors Privesc | - | STRUCTURAL | page title / intro / references |
| `#integration-connectors` | ## Integration Connectors | - | EXCLUDED | X: Section intro |
| `#connectorsconnectionssetiampolicy--resource-level-self-grant-to-use-a-connection` | ### `connectors.connections.setIamPolicy` — resource-level self-grant to use a connection | connectors.connections.setIamPolicy | COVERED | `gcp-connectors-connections-setiampolicy-connection-self-grant` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-kms-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---kms-privesc` | # GCP - KMS Privesc | - | STRUCTURAL | page title / intro / references |
| `#kms` | ## KMS | - | EXCLUDED | X: Page intro |
| `#cloudkmscryptokeyversionsusetodecrypt` | ### `cloudkms.cryptoKeyVersions.useToDecrypt` | cloudkms.cryptoKeyVersions.useToDecrypt | EXCLUDED | X: Decrypt |
| `#cloudkmscryptokeyssetiampolicy` | ### `cloudkms.cryptoKeys.setIamPolicy` | cloudkms.cryptoKeys.setIamPolicy | COVERED | `gcp-cloudkms-cryptokeys-setiampolicy-crypto-key-self-grant` |
| `#cloudkmscryptokeyversionsusetodecryptviadelegation` | ### `cloudkms.cryptoKeyVersions.useToDecryptViaDelegation` | cloudkms.cryptoKeyVersions.useToDecryptViaDelegation | EXCLUDED | X: Decrypt via delegation |
| `#setting-up-for-delegation` | #### Setting Up for Delegation | - | EXCLUDED | X: Delegation setup |
| `#autokey-confused-deputy-cloudkmsautokeyconfigsupdate--cloudkmskeyhandlescreate` | ### Autokey confused-deputy: `cloudkms.autokeyConfigs.update` & `cloudkms.keyHandles.create` | cloudkms.autokeyConfigs.update, cloudkms.keyHandles.create | EXCLUDED | X: Autokey confused deputy |
| `#ekm-connection-hijack-attacker-ekm--mitm-of-external-key-material-cloudkmsekmconnectionsupdate` | ### EKM connection hijack (attacker-EKM / MITM of external key material): `cloudkms.ekmConnections.update` | cloudkms.ekmConnections.update | EXCLUDED | X: EKM connection hijack |
| `#cloudkmscryptokeyversionsupdate--targeted-external-key-route-override-per-version-ekm-interception--dos` | ### `cloudkms.cryptoKeyVersions.update` — targeted external-key route override (per-version EKM interception / DoS) | cloudkms.cryptoKeyVersions.update | EXCLUDED | X: cloudkms.cryptoKeyVersions.update external-key route override |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-local-privilege-escalation-ssh-pivoting.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---local-privilege-escalation-ssh-pivoting` | # GCP - local privilege escalation ssh pivoting | - | STRUCTURAL | page title / intro / references |
| `#compute` | ## Compute | - | EXCLUDED | X: Page intro |
| `#read-the-scripts` | ## Read the scripts <a href="#follow-the-scripts" id="follow-the-scripts"></a> | - | EXCLUDED | X: Read VM scripts |
| `#custom-metadata` | ## Custom Metadata | - | EXCLUDED | X: Custom metadata secrets |
| `#abusing-iam-permissions` | ## **Abusing IAM permissions** | - | EXCLUDED | X: Abusing the attached SA's IAM permissions |
| `#search-for-keys-in-the-filesystem` | ## Search for Keys in the filesystem | - | EXCLUDED | X: Search keys on filesystem |
| `#more-api-key-regexes` | ### More API key regexes | - | EXCLUDED | X: API key regexes |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-looker-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---looker-privilege-escalation` | # GCP - Looker Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#looker` | ## Looker | - | EXCLUDED | X: Page intro |
| `#privilege-escalation-boundaries` | ## Privilege-escalation boundaries | - | EXCLUDED | X: Looker privilege-escalation boundaries |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-lustre-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---managed-lustre-privilege-escalation` | # GCP - Managed Lustre Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#managed-lustre` | ## Managed Lustre | - | EXCLUDED | X: Page intro |
| `#managed-lustre-lustregoogleapiscom` | ## Managed Lustre (`lustre.googleapis.com`) | lustre.googleapis.com | EXCLUDED | X: Managed Lustre service intro |
| `#read-a-cloud-storage-bucket-through-the-managed-lustre-transfer-service-agent` | ### Read a Cloud Storage bucket through the Managed Lustre transfer service agent | - | EXCLUDED | X: Lustre importData/exportData service-agent bucket read |
| `#reclassified-operations` | ## Reclassified operations | - | EXCLUDED | X: Reclassified operations |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-managed-kafka-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---managed-kafka-privilege-escalation` | # GCP - Managed Kafka Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#managed-kafka` | ## Managed Kafka | - | EXCLUDED | X: Page intro |
| `#no-standalone-managed-kafka-privilege-escalation-primitive-is-retained` | ## No standalone Managed Kafka privilege-escalation primitive is retained | - | EXCLUDED | X: No Managed Kafka primitive |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-misc-perms-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---generic-permission-privilege-escalation` | # GCP - Generic Permission Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#iam-principals--org-policies` | ## IAM, Principals & Org Policies | - | EXCLUDED | X: Page intro |
| `#generic-permission-patterns` | ## Generic permission patterns | - | EXCLUDED | X: Generic permission patterns |
| `#serviceresourcesetiampolicy--self-grant-on-the-governed-resource` | ### `<service>.<resource>.setIamPolicy` — self-grant on the governed resource | - | STRUCTURAL | Generic permission pattern; concrete self-grants are mapped under their service entries. |
| `#iamserviceaccountsactas--a-code-executing-resource-write--run-as-an-attached-identity` | ### `iam.serviceAccounts.actAs` + a code-executing resource write — run as an attached identity | iam.serviceAccounts.actAs | EXCLUDED | X: Generic actAs + code-executing resource write |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-connectivity-center-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---network-connectivity-center-privilege-escalation` | # GCP - Network Connectivity Center Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#vpc--networking` | ## VPC & Networking | - | EXCLUDED | X: Page intro |
| `#resource-iam-self-grants` | ## Resource IAM self-grants | - | COVERED | `gcp-networkconnectivity-hubs-setiampolicy-hub-self-grant`, `gcp-networkconnectivity-groups-setiampolicy-group-self-grant` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---network-docker-escape` | # GCP - Network Docker Escape | - | STRUCTURAL | page title / intro / references |
| `#compute` | ## Compute | - | EXCLUDED | X: Page intro |
| `#initial-state` | ## Initial State | - | EXCLUDED | X: Initial state |
| `#attack-explanation` | ## Attack Explanation | - | EXCLUDED | X: Metadata response injection |
| `#escape-technique` | ### Escape Technique | - | EXCLUDED | X: Escape technique |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-networksecurity-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---network-security-privilege-escalation` | # GCP - Network Security Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#network-security` | ## Network Security | - | EXCLUDED | X: Page intro |
| `#network-security-networksecuritygoogleapiscom` | ## Network Security (`networksecurity.googleapis.com`) | networksecurity.googleapis.com | EXCLUDED | X: Page intro |
| `#networksecurityauthzpoliciescreate--update---grant-access-through-an-application-load-balancer-or-gateway` | ### `networksecurity.authzPolicies.create` / `.update` - grant access through an Application Load Balancer or gateway | networksecurity.authzPolicies.create | EXCLUDED | X: authzPolicies create/update |
| `#networksecurityauthorizationpoliciesupdate---relax-an-attached-legacy-mesh-authorization-policy` | ### `networksecurity.authorizationPolicies.update` - relax an attached legacy mesh authorization policy | networksecurity.authorizationPolicies.update | EXCLUDED | X: Relax legacy mesh authorization policy |
| `#networksecurityservertlspoliciesupdate---permit-plaintext-alongside-mesh-mtls` | ### `networksecurity.serverTlsPolicies.update` - permit plaintext alongside mesh mTLS | networksecurity.serverTlsPolicies.update | EXCLUDED | X: serverTlsPolicies permit plaintext |
| `#networksecurityaddressgroupsupdate---add-an-attacker-source-to-a-trusted-rule` | ### `networksecurity.addressGroups.update` - add an attacker source to a trusted rule | networksecurity.addressGroups.update | EXCLUDED | X: addressGroups add attacker source |
| `#networksecurityinterceptdeploymentscreate---inject-an-inspection-appliance-into-a-trusted-deployment-group` | ### `networksecurity.interceptDeployments.create` - inject an inspection appliance into a trusted deployment group | networksecurity.interceptDeployments.create | EXCLUDED | X: interceptDeployments inspection appliance |
| `#networksecuritysetiampolicy---self-grant-control-of-one-policy-resource` | ### `networksecurity.*.setIamPolicy` - self-grant control of one policy resource | - | COVERED | `gcp-networksecurity-addressgroups-setiampolicy-address-group-self-grant`, `gcp-networksecurity-authorizationpolicies-setiampolicy-authorization-policy-self-grant`, `gcp-networksecurity-authzpolicies-setiampolicy-authz-policy-self-grant`, `gcp-networksecurity-clienttlspolicies-setiampolicy-client-tls-policy-self-grant`, `gcp-networksecurity-servertlspolicies-setiampolicy-server-tls-policy-self-grant` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-networkservices-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---network-services-traffic-director--cloud-service-mesh-privesc` | # GCP - Network Services (Traffic Director / Cloud Service Mesh) Privesc | - | STRUCTURAL | page title / intro / references |
| `#network-services` | ## Network Services | - | EXCLUDED | X: Page intro |
| `#network-services-networkservicesgoogleapiscom` | ## Network Services (`networkservices.googleapis.com`) | networkservices.googleapis.com | EXCLUDED | X: Page intro |
| `#networkserviceshttproutescreate--networkserviceshttproutesupdate--mesh-traffic-hijack` | ### `networkservices.httpRoutes.create` / `networkservices.httpRoutes.update` — mesh traffic hijack | networkservices.httpRoutes.create, networkservices.httpRoutes.update | EXCLUDED | X: Mesh traffic hijack |
| `#networkservicesendpointpoliciescreate--update--strip-mtls--loosen-authz-on-victim-sidecars` | ### `networkservices.endpointPolicies.create` / `.update` — strip mTLS / loosen authz on victim sidecars | networkservices.endpointPolicies.create | EXCLUDED | X: Strip mTLS on sidecars |
| `#meshconfigprojectsinit--mesh-control-plane-bootstrap-persistence` | ### `meshconfig.projects.init` — mesh control-plane bootstrap (persistence) | meshconfig.projects.init | EXCLUDED | X: Mesh bootstrap |
| `#networkserviceslbtrafficextensions--wasmplugins--service-extensions-data-path-traffic-interception` | ### `networkservices.lbTrafficExtensions.*` / `wasmPlugins.*` — Service Extensions data-path traffic interception | - | EXCLUDED | X: Service Extensions traffic/WASM interception |
| `#networkservicesauthzextensions--service-extensions-authorization-callout-hijack-auth-bypass--request-context-exfil` | ### `networkservices.authzExtensions.*` — Service Extensions authorization-callout hijack (auth bypass + request-context exfil) | - | EXCLUDED | X: authzExtensions callout hijack |
| `#networkservicesgoogletaggatewaypoliciescreate--update--first-party-javascript-injection-on-site-visitors-client-side-supply-chain` | ### `networkservices.googleTagGatewayPolicies.create` / `.update` — first-party JavaScript injection on site visitors (client-side supply-chain) | networkservices.googleTagGatewayPolicies.create | EXCLUDED | X: googleTagGatewayPolicies JavaScript injection |
| `#roles` | ## Roles | - | EXCLUDED | X: Roles |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-orgpolicy-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---orgpolicy-privesc` | # GCP - Orgpolicy Privesc | - | STRUCTURAL | page title / intro / references |
| `#iam-principals--org-policies` | ## IAM, Principals & Org Policies | - | EXCLUDED | X: Page intro (IAM, Principals & Org Policies) |
| `#orgpolicy` | ## orgpolicy | - | EXCLUDED | X: Page intro |
| `#orgpolicypolicyset` | ### `orgpolicy.policy.set` | orgpolicy.policy.set | NON-PRIVESC | gcp-v3-33-orgpolicy-policy-set-lifts-org-policy-constraints (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#orgpolicypolicyset-iamserviceaccountsactas` | ### `orgpolicy.policy.set`, `iam.serviceAccounts.actAs` | orgpolicy.policy.set, iam.serviceAccounts.actAs | EXCLUDED | gcp-v3-34-disable-cross-project-sa-usage-constraint-plus-actas (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#orgpolicypoliciescreate--orgpolicypoliciesupdate-v2-api--disable-guardrails-at-project-scope` | ### `orgpolicy.policies.create` / `orgpolicy.policies.update` (v2 API) — disable guardrails at project scope | orgpolicy.policies.create, orgpolicy.policies.update | NON-PRIVESC | gcp-v3-35-org-policy-v2-policies-create-update-delete (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#orgpolicycustomconstraintscreate--update--author-org-wide-custom-constraints-org-scope` | ### `orgpolicy.customConstraints.create` / `.update` — author org-wide custom constraints (org scope) | orgpolicy.customConstraints.create | EXCLUDED | X: Custom constraints |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-osconfig-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---os-config-privilege-escalation` | # GCP - OS Config Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#os-config` | ## OS Config | - | EXCLUDED | X: Page intro |
| `#osconfigpatchjobsexec-or-patch-deployment-write---execute-a-privileged-patch-step` | ### `osconfig.patchJobs.exec` or patch-deployment write - execute a privileged patch step | osconfig.patchJobs.exec | COVERED | `gcp-osconfig-patchjobs-exec` |
| `#osconfigospolicyassignmentscreate-or-update---execute-an-inline-privileged-os-policy` | ### `osconfig.osPolicyAssignments.create` or `.update` - execute an inline privileged OS policy | osconfig.osPolicyAssignments.create | COVERED | `gcp-osconfig-ospolicyassignments-create` |
| `#legacy-guest-policy-write---run-an-inline-software-recipe-script` | ### Legacy guest-policy write - run an inline software-recipe script | osconfig.guestPolicies.create, osconfig.guestPolicies.update | COVERED | `gcp-osconfig-guestpolicies-recipe` |
| `#osconfigpolicyorchestratorscreate-or-update---propagate-a-privileged-policy-across-projects-and-zones` | ### `osconfig.policyOrchestrators.create` or `.update` - propagate a privileged policy across projects and zones | osconfig.policyOrchestrators.create | COVERED | `gcp-osconfig-policyorchestrators` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-pam-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---privileged-access-manager-pam-privilege-escalation` | # GCP - Privileged Access Manager (PAM) Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#privileged-access-manager-pam` | ## Privileged Access Manager (PAM) | - | EXCLUDED | X: Page intro |
| `#privileged-access-manager` | ## Privileged Access Manager | - | EXCLUDED | X: PAM overview |
| `#activate-a-stronger-role-through-an-existing-entitlement` | ### Activate a stronger role through an existing entitlement | - | EXCLUDED | gcp-pam-entitlement-request-grant Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-parallelstore-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---parallelstore-privilege-escalation` | # GCP - Parallelstore Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#parallelstore` | ## Parallelstore | - | EXCLUDED | X: Page intro |
| `#parallelstore-parallelstoregoogleapiscom` | ## Parallelstore (`parallelstore.googleapis.com`) | parallelstore.googleapis.com | EXCLUDED | X: Page intro |
| `#read-a-cloud-storage-bucket-through-the-parallelstore-service-agent` | ### Read a Cloud Storage bucket through the Parallelstore service agent | - | EXCLUDED | X: Parallelstore service-agent bucket read |
| `#reclassified-operations` | ## Reclassified operations | - | EXCLUDED | X: Reclassified operations |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-private-catalog-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---service-catalog-privesc` | # GCP - Service Catalog Privesc | - | STRUCTURAL | page title / intro / references |
| `#private-catalog` | ## Private Catalog | - | EXCLUDED | X: Page intro |
| `#service-catalog-formerly-private-catalog` | ## Service Catalog (formerly Private Catalog) | - | EXCLUDED | X: Service Catalog intro |
| `#cloudprivatecatalogproducerproductsupdate--poison-an-existing-deployable-solution-version` | ### `cloudprivatecatalogproducer.products.update` — poison an existing deployable solution version | cloudprivatecatalogproducer.products.update | COVERED | `gcp-privatecatalog-product-version-poison` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-pubsub-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---pubsub-privesc` | # GCP - Pub/Sub Privesc | - | STRUCTURAL | page title / intro / references |
| `#pubsub` | ## Pub/Sub | - | EXCLUDED | X: Page intro |
| `#pubsubtopicssetiampolicy--pubsubsubscriptionssetiampolicy--self-grant-control-of-one-resource` | ### `pubsub.topics.setIamPolicy` / `pubsub.subscriptions.setIamPolicy` — self-grant control of one resource | pubsub.topics.setIamPolicy, pubsub.subscriptions.setIamPolicy | COVERED | `gcp-pubsub-topics-setiampolicy-topic-self-grant`, `gcp-pubsub-subscriptions-setiampolicy-subscription-self-grant` |
| `#pubsubsubscriptionscreate--pubsubsubscriptionsupdate--iamserviceaccountsactas--obtain-oidc-tokens-as-a-service-account` | ### `pubsub.subscriptions.create` / `pubsub.subscriptions.update` + `iam.serviceAccounts.actAs` — obtain OIDC tokens as a service account | pubsub.subscriptions.create, pubsub.subscriptions.update, iam.serviceAccounts.actAs | EXCLUDED | X: Authenticated push subscription OIDC token |
| `#pubsubsubscriptionscreate--pubsubsubscriptionsupdate--write-through-a-more-privileged-export-identity` | ### `pubsub.subscriptions.create` / `pubsub.subscriptions.update` — write through a more privileged export identity | pubsub.subscriptions.create, pubsub.subscriptions.update | EXCLUDED | X: Export subscription write through a privileged delivery identity |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-resourcemanager-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---resource-manager-privilege-escalation` | # GCP - Resource Manager Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#iam-principals--org-policies` | ## IAM, Principals & Org Policies | - | EXCLUDED | X: Page intro (Resource Manager) |
| `#organizationsfoldersprojectssetiampolicy--self-grant-on-a-hierarchy-node` | ### `organizations/folders/projects.setIamPolicy` — self-grant on a hierarchy node | resourcemanager.organizations.setIamPolicy, resourcemanager.folders.setIamPolicy, resourcemanager.projects.setIamPolicy | COVERED | `gcp-resourcemanager-organizations-setiampolicy`, `gcp-resourcemanager-folders-setiampolicy`, `gcp-resourcemanager-projects-setiampolicy` |
| `#createtagbinding--deletetagbinding--flip-tag-gated-security-conditions` | ### `*.createTagBinding` / `*.deleteTagBinding` — flip tag-gated security conditions | - | EXCLUDED | gcp-v3-32-createtagbinding-deletetagbinding-condition-flip (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#tagkeystagvaluessetiampolicy--self-grant-use-of-a-privileged-tag` | ### `tagKeys/tagValues.setIamPolicy` — self-grant use of a privileged tag | - | EXCLUDED | X: Self-grant resourcemanager.tagValueBindings.create on a tag key |
| `#projectsdeletepolicybinding--projectsupdatepolicybinding--escape-a-pab` | ### `projects.deletePolicyBinding` / `projects.updatePolicyBinding` — escape a PAB | projects.deletePolicyBinding, projects.updatePolicyBinding | EXCLUDED | gcp-v3-31-projects-deletepolicybinding-updatepolicybinding-pab-escap (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#projectsmove--foldersmove--change-inherited-security-controls` | ### `projects.move` / `folders.move` — change inherited security controls | projects.move, folders.move | EXCLUDED | gcp-v3-30-projects-move-folders-move-into-a-parent-where-the-source (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-run-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---run-privesc` | # GCP - Run Privesc | - | STRUCTURAL | page title / intro / references |
| `#cloud-run` | ## Cloud Run | - | EXCLUDED | X: Page intro |
| `#runservicescreate--iamserviceaccountsactas-runroutesinvoke` | ### `run.services.create` , `iam.serviceAccounts.actAs`, **`run.routes.invoke`** | run.services.create, iam.serviceAccounts.actAs, run.routes.invoke | COVERED | `gcp-run-services-create-actas` |
| `#runservicesupdate--iamserviceaccountsactas` | ### `run.services.update` , `iam.serviceAccounts.actAs` | run.services.update, iam.serviceAccounts.actAs | COVERED | `gcp-run-services-update-actas`<br>`gcp-run-instances-create-update-actas` |
| `#build-time-code-execution-as-the-build-service-account-via---source` | ### Build-time code execution as the **build service account** via `--source` | - | EXCLUDED | X: Build-time code execution as the build SA via run deploy --source |
| `#public-exposure-without-an-allusers-binding----no-invoker-iam-check-drs-bypass` | ### Public exposure without an `allUsers` binding — `--no-invoker-iam-check` (DRS bypass) | - | EXCLUDED | X: Public exposure via invoker IAM check disable |
| `#plaintext-environment-disclosure-with-cloud-run-read-permissions` | ### Plaintext environment disclosure with Cloud Run read permissions | - | EXCLUDED | X: Plaintext env disclosure via run get/list |
| `#runservicessetiampolicy` | ### `run.services.setIamPolicy` | run.services.setIamPolicy | COVERED | `gcp-run-services-setiampolicy-actas` |
| `#runjobscreate-runjobsrun-iamserviceaccountsactasrunjobsget` | ### `run.jobs.create`, `run.jobs.run`, `iam.serviceaccounts.actAs`,(`run.jobs.get`) | run.jobs.create, run.jobs.run, iam.serviceaccounts.actAs, run.jobs.get | COVERED | `gcp-run-jobs-create-run-actas` |
| `#runjobsupdaterunjobsruniamserviceaccountsactasrunjobsget` | ### `run.jobs.update`,`run.jobs.run`,`iam.serviceaccounts.actAs`,(`run.jobs.get`) | run.jobs.update, run.jobs.run, iam.serviceaccounts.actAs, run.jobs.get | COVERED | `gcp-run-jobs-update-run-actas` |
| `#runjobssetiampolicy` | ### `run.jobs.setIamPolicy` | run.jobs.setIamPolicy | COVERED | `gcp-run-jobs-setiampolicy` |
| `#runjobsrun-alone-on-a-pre-existing-job--run-as-its-pinned-sa` | ### `run.jobs.run` **alone** on a pre-existing job = run-as its pinned SA | run.jobs.run | EXCLUDED | X: run.jobs.run alone on an existing job |
| `#runjobsrun-runjobsrunwithoverrides-runjobsget` | ### `run.jobs.run`, `run.jobs.runWithOverrides`, (`run.jobs.get`) | run.jobs.run, run.jobs.runWithOverrides, run.jobs.get | COVERED | `gcp-run-jobs-runwithoverrides` |
| `#runworkerpoolscreate--update-iamserviceaccountsactas--a-third-run-as-sa-resource` | ### `run.workerpools.create` / `.update`, `iam.serviceAccounts.actAs` — a THIRD run-as-SA resource | run.workerpools.create, iam.serviceAccounts.actAs | COVERED | `gcp-run-workerpools-create-update-actas`<br>`gcp-run-workerpools-setiampolicy-actas` |
| `#cloud-run-instance-ssh--runsshread--runsshroot-exec-inside-a-running-container-as-its-sa-no-actas` | ### Cloud Run instance SSH — `run.*.sshRead` / `run.*.sshRoot` (exec inside a running container as its SA, no `actAs`) | run.services.sshRoot, run.services.sshRead, run.jobs.sshRoot, run.jobs.sshRead, run.workerpools.sshRoot, run.workerpools.sshRead | COVERED | `gcp-run-ssh-into-running-instance`<br>`gcp-run-instances-ssh` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-runtimeconfig-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---cloud-runtime-configurator-privilege-escalation` | # GCP - Cloud Runtime Configurator Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#runtime-configurator` | ## Runtime Configurator | - | EXCLUDED | X: Page intro |
| `#cloud-runtime-configurator-runtimeconfiggoogleapiscom` | ## Cloud Runtime Configurator (`runtimeconfig.googleapis.com`) | runtimeconfig.googleapis.com | EXCLUDED | X: Runtime Configurator intro |
| `#runtimeconfigconfigssetiampolicy--self-grant-administration-of-one-config` | ### `runtimeconfig.configs.setIamPolicy` — self-grant administration of one config | runtimeconfig.configs.setIamPolicy | COVERED | `gcp-runtimeconfig-configs-setiampolicy-config-self-grant` |
| `#why-the-other-runtime-config-permissions-are-not-separate-privilege-escalations` | ## Why the other Runtime Config permissions are not separate privilege escalations | - | EXCLUDED | X: Other Runtime Config permissions |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-secretmanager-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---secretmanager-privesc` | # GCP - Secretmanager Privesc | - | STRUCTURAL | page title / intro / references |
| `#secret-manager` | ## Secret Manager | - | EXCLUDED | X: Page intro |
| `#secretmanager` | ## secretmanager | - | EXCLUDED | X: Page intro |
| `#escalation-through-a-recovered-secret` | ### Escalation through a recovered secret | - | EXCLUDED | X: Escalation through a recovered secret |
| `#secretmanagersecretssetiampolicy` | ### `secretmanager.secrets.setIamPolicy` | secretmanager.secrets.setIamPolicy | COVERED | `gcp-secretmanager-secrets-setiampolicy-secret-self-grant` |
| `#secretmanagersecretsenablemanagedrotation--reset-a-cloud-sql-users-password-through-the-secret-identity` | ### `secretmanager.secrets.enableManagedRotation` — reset a Cloud SQL user's password through the secret identity | secretmanager.secrets.enableManagedRotation | COVERED | `gcp-secretmanager-managed-rotation-exact-cloudsql-user` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-secure-source-manager-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---secure-source-manager-privesc` | # GCP - Secure Source Manager Privesc | - | STRUCTURAL | page title / intro / references |
| `#secure-source-manager` | ## Secure Source Manager | - | EXCLUDED | X: Section intro |
| `#securesourcemanagerinstancessetiampolicy--repositoriessetiampolicy--iam-self-grant-to-readpoison-source` | ### `securesourcemanager.instances.setIamPolicy` / `repositories.setIamPolicy` — IAM self-grant to read/poison source | securesourcemanager.instances.setIamPolicy, repositories.setIamPolicy | COVERED | `gcp-securesourcemanager-setiampolicy` |
| `#branch-protection--pr-review-bypass--slip-code-past-review` | ### Branch-protection / PR-review bypass — slip code past review | - | EXCLUDED | X: Branch protection / PR review bypass |
| `#malicious-webhooks--event-exfiltration--authenticated-calls--persistence` | ### Malicious webhooks — event exfiltration / authenticated calls / persistence | - | EXCLUDED | X: Malicious webhooks / service-account-authenticated delivery |
| `#cicd-supply-chain-code-execution` | ### CI/CD supply-chain code execution | securesourcemanager.repositories.push | COVERED | `gcp-securesourcemanager-push-cicd` |
| `#securesourcemanagersshkeyscreateany--implant-an-ssh-key-on-a-service-accounts-git-identity-pushfetch-as-the-sa` | ### `securesourcemanager.sshkeys.createAny` — implant an SSH key on a service account's git identity (push/fetch as the SA) | securesourcemanager.sshkeys.createAny | EXCLUDED | X: sshkeys.createAny on a service account's git identity |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-security-command-center-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---security-command-center-privesc` | # GCP - Security Command Center Privesc | - | STRUCTURAL | page title / intro / references |
| `#security-command-center` | ## Security Command Center | - | EXCLUDED | X: Page intro |
| `#securitycentersourcessetiampolicy--self-grant-finding-control-on-one-organization-source` | ### `securitycenter.sources.setIamPolicy` — self-grant finding control on one organization source | securitycenter.sources.setIamPolicy | EXCLUDED | X: Self-grant securitycenter.findings.update on a source |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-service-management-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---service-management-privesc` | # GCP - Service Management Privesc | - | STRUCTURAL | page title / intro / references |
| `#service-usage-and-service-management` | ## Service Usage and Service Management | - | EXCLUDED | X: Page intro |
| `#servicemanagement` | ## servicemanagement | - | EXCLUDED | X: Page intro |
| `#servicemanagementservicessetiampolicy--self-grant-on-a-managed-service` | ### `servicemanagement.services.setIamPolicy` — self-grant on a managed service | servicemanagement.services.setIamPolicy | EXCLUDED | X: Self-grant servicemanagement.services.check on a managed service |
| `#servicemanagementservicesupdate--config-rollout-authentication-injection` | ### `servicemanagement.services.update` — config-rollout authentication injection | servicemanagement.services.update | EXCLUDED | X: Endpoints auth injection |
| `#servicemanagementservicesdelete--full-managed-service-takedown-endpoints--api-gateway-dos` | ### `servicemanagement.services.delete` — full managed-service takedown (Endpoints / API Gateway DoS) | servicemanagement.services.delete | EXCLUDED | X: servicemanagement.services.delete |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-serviceusage-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---service-usage-privilege-escalation` | # GCP - Service Usage Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#service-usage` | ## Service Usage | - | EXCLUDED | X: Page intro (Service Usage) |
| `#service-usage-serviceusagegoogleapiscom` | ## Service Usage (`serviceusage.googleapis.com`) | serviceusage.googleapis.com | EXCLUDED | X: Service Usage overview |
| `#reclassified-historical-claims` | ## Reclassified historical claims | - | EXCLUDED | X: Reclassified historical claims (services.enable/use/disable, quotas, consumerpolicy, MCP policies, API keys) |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-sourcerepos-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---cloud-source-repositories-privilege-escalation` | # GCP - Cloud Source Repositories Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#source-repositories` | ## Source Repositories | - | EXCLUDED | X: Section intro |
| `#privilege-escalation-techniques` | ## Privilege Escalation Techniques | - | EXCLUDED | X: Privilege Escalation Techniques (section heading) |
| `#sourcereposupdate--poison-source-consumed-by-a-privileged-cloud-build-trigger` | ### `source.repos.update` — Poison Source Consumed by a Privileged Cloud Build Trigger | source.repos.update | COVERED | `gcp-sourcerepos-update-build-trigger` |
| `#sourcerepossetiampolicy--self-grant-repository-write-access` | ### `source.repos.setIamPolicy` — Self-Grant Repository Write Access | source.repos.setIamPolicy | COVERED | `gcp-sourcerepos-setiampolicy` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-spanner-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---spanner-privesc` | # GCP - Spanner Privesc | - | STRUCTURAL | page title / intro / references |
| `#spanner` | ## Spanner | - | EXCLUDED | X: Page intro |
| `#spannerdatabasessetiampolicy--spannerinstancessetiampolicy--grant-database-access` | ### `spanner.databases.setIamPolicy` / `spanner.instances.setIamPolicy` — grant database access | spanner.databases.setIamPolicy, spanner.instances.setIamPolicy | COVERED | `gcp-spanner-databases-setiampolicy-database-self-grant`, `gcp-spanner-instances-setiampolicy-instance-self-grant` |
| `#spannerbackupscopy--spannerbackupsrestoredatabase--recover-a-database-in-an-attacker-readable-instance` | ### `spanner.backups.copy` / `spanner.backups.restoreDatabase` — recover a database in an attacker-readable instance | spanner.backups.copy, spanner.backups.restoreDatabase | EXCLUDED | X: Spanner backup copy/restore into attacker-readable instance |
| `#spannerdatabasesupdateddl--expand-a-fine-grained-database-role` | ### `spanner.databases.updateDdl` — expand a fine-grained database role | spanner.databases.updateDdl | EXCLUDED | X: Genuine database-scoped permission grant, inactive pending typed FGAC role/object/SQL-privilege and before/after evidence. |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-storage-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---storage-privesc` | # GCP - Storage Privesc | - | STRUCTURAL | page title / intro / references |
| `#cloud-storage` | ## Cloud Storage | - | EXCLUDED | X: Page intro (Cloud Storage) |
| `#storage` | ## Storage | - | EXCLUDED | X: Page intro |
| `#storagebucketssetiampolicy--storagemanagedfolderssetiampolicy--resource-scoped-self-grant` | ### `storage.buckets.setIamPolicy` / `storage.managedFolders.setIamPolicy` — resource-scoped self-grant | storage.buckets.setIamPolicy, storage.managedFolders.setIamPolicy | COVERED | `gcp-storage-buckets-setiampolicy-composer`<br>`gcp-storage-buckets-setiampolicy-code-consumers` |
| `#storagehmackeyscreate--mint-a-cloud-storage-credential-for-another-service-account` | ### `storage.hmacKeys.create` — mint a Cloud Storage credential for another service account | storage.hmacKeys.create | COVERED | `gcp-storage-hmackeys-create` |
| `#storageobjectscreate--inject-a-cloud-composer-dag` | ### `storage.objects.create` — inject a Cloud Composer DAG | storage.objects.create | EXCLUDED | X: storage.objects.create Composer DAG injection |
| `#storageobjectscreate--storageobjectsdelete--poison-an-unpinned-cloud-build-storagesource` | ### `storage.objects.create` + `storage.objects.delete` — poison an unpinned Cloud Build `StorageSource` | storage.objects.create, storage.objects.delete | COVERED | `gcp-storage-cloudbuild-unpinned-storagesource-poison` |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-vertex-ai-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---vertex-ai-privesc` | # GCP - Vertex AI Privesc | - | STRUCTURAL | page title / intro / references |
| `#vertex-ai` | ## Vertex AI | - | EXCLUDED | X: Section intro |
| `#aiplatformcustomjobscreate--iamserviceaccountsactas` | ### `aiplatform.customJobs.create` + `iam.serviceAccounts.actAs` | aiplatform.customJobs.create, iam.serviceAccounts.actAs | COVERED | `gcp-vertex-customjobs-create-actas` |
| `#omit-serviceaccount-to-run-custom-training-as-the-custom-code-service-agent` | ### Omit `serviceAccount` to run custom training as the Custom Code Service Agent | aiplatform.customJobs.create, aiplatform.hyperparameterTuningJobs.create, aiplatform.trainingPipelines.create | COVERED | `gcp-vertex-customjob-custom-code-agent` |
| `#deploy-an-attacker-controlled-model-to-an-endpoint-as-a-target-service-account` | ### Deploy an attacker-controlled model to an endpoint as a target service account | aiplatform.models.upload, aiplatform.endpoints.deploy, iam.serviceAccounts.actAs | COVERED | `gcp-vertex-models-upload-endpoint-deploy-actas` |
| `#aiplatformbatchpredictionjobscreate--iamserviceaccountsactas` | ### `aiplatform.batchPredictionJobs.create` + `iam.serviceAccounts.actAs` | aiplatform.batchPredictionJobs.create, iam.serviceAccounts.actAs | COVERED | `gcp-vertex-batchprediction-create-actas` |
| `#aiplatformpipelinejobscreate--iamserviceaccountsactas` | ### `aiplatform.pipelineJobs.create` + `iam.serviceAccounts.actAs` | aiplatform.pipelineJobs.create, iam.serviceAccounts.actAs | COVERED | `gcp-vertex-pipelinejobs-create-actas` |
| `#aiplatformhyperparametertuningjobscreate--iamserviceaccountsactas` | ### `aiplatform.hyperparameterTuningJobs.create` + `iam.serviceAccounts.actAs` | aiplatform.hyperparameterTuningJobs.create, iam.serviceAccounts.actAs | COVERED | `gcp-vertex-hptuningjobs-create-actas` |
| `#aiplatformreasoningenginescreate--iamserviceaccountsactas` | ### `aiplatform.reasoningEngines.create` + `iam.serviceAccounts.actAs` | aiplatform.reasoningEngines.create, iam.serviceAccounts.actAs | COVERED | `gcp-vertex-reasoningengines-create-actas` |
| `#omit-agent-engine-specserviceaccount-to-run-as-the-reasoning-engine-service-agent` | ### Omit Agent Engine `spec.serviceAccount` to run as the Reasoning Engine Service Agent | spec.serviceAccount | COVERED | `gcp-vertex-reasoningengines-create-default-agent` |
| `#aiplatformnotebookexecutionjobscreate--iamserviceaccountsactas` | ### `aiplatform.notebookExecutionJobs.create` + `iam.serviceAccounts.actAs` | aiplatform.notebookExecutionJobs.create, iam.serviceAccounts.actAs | COVERED | `gcp-vertex-notebookexecutionjobs-create-actas` |
| `#create-a-workbench-instance-with-a-target-service-account` | ### Create a Workbench instance with a target service account | notebooks.instances.create, iam.serviceAccounts.actAs | COVERED | `gcp-vertex-workbench-instances-create-actas` |
| `#notebooksinstancesupdate--notebooksinstancesreset-on-an-existing-workbench-instance` | ### `notebooks.instances.update` + `notebooks.instances.reset` on an existing Workbench instance | notebooks.instances.update, notebooks.instances.reset | COVERED | `gcp-vertex-workbench-instance-update-or-setiampolicy` |
| `#notebooksinstancessetiampolicy-to-self-grant-updatereset-then-inject-a-startup-script` | ### `notebooks.instances.setIamPolicy` to self-grant update/reset, then inject a startup script | notebooks.instances.setIamPolicy | EXCLUDED | X: notebooks.instances.setIamPolicy self-grant then startup script |
| `#excluded-from-this-privilege-escalation-page` | ## Excluded from this privilege-escalation page | - | EXCLUDED | X: Excluded from this page (model/dataset export-import, Feature Store/Vector Search/metadata/RAG, tuningJobs, Deployment Resource Pools, Persistent Resources) |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-vm-migration-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---vm-migration-privesc` | # GCP - VM Migration Privesc | - | STRUCTURAL | page title / intro / references |
| `#vm-migration` | ## VM Migration | - | EXCLUDED | X: Page intro (VM Migration) |
| `#migrate-to-virtual-machines` | ## Migrate to Virtual Machines | - | EXCLUDED | X: Migrate to Virtual Machines overview |
| `#vmmigrationmigratingvmsupdate--vmmigrationclonejobscreate--execute-startup-metadata-as-the-target-vm-identity` | ### `vmmigration.migratingVms.update` + `vmmigration.cloneJobs.create` — execute startup metadata as the target VM identity | vmmigration.migratingVms.update, vmmigration.cloneJobs.create | COVERED | `gcp-vmmigration-migratingvm-metadata-clone` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-vmwareengine-gcve-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---vmware-engine-gcve-privilege-escalation` | # GCP - VMware Engine (GCVE) Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#vmware-engine-gcve` | ## VMware Engine (GCVE) | - | EXCLUDED | X: Page intro (VMware Engine) |
| `#vmware-engine` | ## VMware Engine | - | EXCLUDED | X: VMware Engine authorization planes overview |
| `#vmwareengineprivatecloudsshowvcentercredentials--shownsxcredentials--cross-into-the-vmware-management-plane` | ### `vmwareengine.privateClouds.showVcenterCredentials` / `.showNsxCredentials` — cross into the VMware management plane | vmwareengine.privateClouds.showVcenterCredentials | COVERED | `gcp-vmwareengine-show-vcenter-credentials-external-principal`, `gcp-vmwareengine-show-nsx-credentials-external-principal` |
| `#vmwareengineprivatecloudssetiampolicy--grant-a-credential-reading-role-on-one-private-cloud` | ### `vmwareengine.privateClouds.setIamPolicy` — grant a credential-reading role on one private cloud | vmwareengine.privateClouds.setIamPolicy | COVERED | `gcp-vmwareengine-privateclouds-setiampolicy-private-cloud-self-grant` |
| `#references` | ## References | - | STRUCTURAL | page title / intro / references |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-workflows-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---workflows-privilege-escalation` | # GCP - Workflows Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#workflows` | ## Workflows | - | EXCLUDED | X: Page intro |
| `#workflowsworkflowscreate--iamserviceaccountsactas--workflowsexecutionscreate--deploy-code-under-a-service-account` | ### `workflows.workflows.create` + `iam.serviceAccounts.actAs` + `workflows.executions.create` — deploy code under a service account | workflows.workflows.create, iam.serviceAccounts.actAs, workflows.executions.create | COVERED | `gcp-workflows-create-actas-execute` |
| `#workflowsexecutionscreate--invoke-an-existing-privileged-workflow` | ### `workflows.executions.create` — invoke an existing privileged workflow | workflows.executions.create | EXCLUDED | X: workflows.executions.create on an existing privileged workflow<br>`gcp-workflow-input-effect-2` — conditional verified exact-target authority. |
| `#workflowsworkflowsupdate--replace-code-while-retaining-the-attached-identity` | ### `workflows.workflows.update` — replace code while retaining the attached identity | workflows.workflows.update | COVERED | `gcp-workflows-update-actas`, `gcp-workflows-update-source-retain-sa`<br>`gcp-workflows-update-source-await-execution` |
| `#workflowscallbackssend--inject-data-into-a-paused-privileged-execution` | ### `workflows.callbacks.send` — inject data into a paused privileged execution | workflows.callbacks.send | EXCLUDED | X: workflows.callbacks.send into a paused execution<br>`gcp-workflow-input-effect-3` — conditional verified exact-target authority. |
| `#references` | ## References | - | EXCLUDED | X: References section |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-workload-identity-federation-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp---workload-identity-federation-privilege-escalation` | # GCP - Workload Identity Federation Privilege Escalation | - | STRUCTURAL | page title / intro / references |
| `#workload--workforce-identity-federation` | ## Workload & Workforce Identity Federation | - | EXCLUDED | X: Page intro (Workload & Workforce Identity Federation) |
| `#workload-identity-federation` | ## Workload Identity Federation | - | EXCLUDED | X: Workload Identity Federation (section heading) |
| `#workloadidentitypoolproviderscreate--add-trust-to-an-already-authorized-pool` | ### `workloadIdentityPoolProviders.create` — add trust to an already-authorized pool | workloadIdentityPoolProviders.create | COVERED | `gcp-wif-provider-create` |
| `#workloadidentitypoolprovidersupdate--take-over-an-authorized-provider` | ### `workloadIdentityPoolProviders.update` — take over an authorized provider | workloadIdentityPoolProviders.update | COVERED | `gcp-wif-provider-update` |
| `#poolprovider-update--undelete--restore-a-residual-trust-path` | ### Pool/provider `update` / `undelete` — restore a residual trust path | iam.googleapis.com/workloadIdentityPoolProviders.undelete, iam.googleapis.com/workloadIdentityPools.update, iam.googleapis.com/workloadIdentityPools.undelete | COVERED | `gcp-wif-pool-provider-restore` |
| `#workforce-identity-federation` | ## Workforce Identity Federation | - | EXCLUDED | X: Workforce Identity Federation (section heading) |
| `#workforce-provider-control-and-trust-restoration--hijack-an-authorized-pool` | ### Workforce provider control and trust restoration — hijack an authorized pool | iam.googleapis.com/workforcePoolProviders.create, iam.googleapis.com/workforcePoolProviders.update, iam.googleapis.com/workforcePoolProviders.undelete, iam.googleapis.com/workforcePools.update, iam.googleapis.com/workforcePools.undelete | COVERED | `gcp-wif-workforce-provider-control` |
| `#scim-provisioning-token--inject-a-workforce-identity-into-a-privileged-group` | ### SCIM provisioning token — inject a workforce identity into a privileged group | - | EXCLUDED | X: SCIM provisioning token group injection |
| `#managed-workload-identities` | ## Managed workload identities | - | EXCLUDED | X: Managed workload identities (section heading) |
| `#workloadidentitypoolmanagedidentitiessetattestationrules--enroll-a-controlled-workload` | ### `workloadIdentityPoolManagedIdentities.setAttestationRules` — enroll a controlled workload | workloadIdentityPoolManagedIdentities.setAttestationRules | EXCLUDED | X: workloadIdentityPoolManagedIdentities.setAttestationRules |
| `#references` | ## References | - | EXCLUDED | X: References section |

## Other GCP pages (privesc-relevant headings; structural headings condensed per page)

### `src/pentesting-cloud/gcp-security/README.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 18 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp-pentesting`, `#basic-information`, `#labs-to-learn`, `#gcp-pentesterred-team-methodology`, `#basic-enumeration`, `#ssrf`, `#whoami`, `#org-enumeration`, `#principals--iam-enumeration`, `#services-enumeration`, `#privilege-escalation-post-exploitation--persistence`, `#publicly-exposed-services`, `#gcp--workspace-pivoting`, `#automatic-tools`, `#gcloud-config--debug`, `#capture-gcloud-gsutil-network`, `#oauth-token-configure-in-gcloud`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-basic-information/README.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#projects-migration` | ## **Projects Migration** | - | NON-PRIVESC | project move, not identity |
| (structural) | 18 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---basic-information`, `#resource-hierarchy`, `#organization-policies`, `#common-use-cases`, `#default-organization-policies`, `#iam-roles`, `#principal-access-boundary-pab-policies`, `#create--assign-apply-a-pab`, `#enumerate`, `#remove`, `#users`, `#groups`, `#default-password-policy`, `#service-accounts`, `#keys--tokens`, `#access-scopes`, `#terraform-iam-policies-bindings-and-memberships`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-basic-information/gcp-federation-abuse.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gcp` | ### GCP | none on victim (attacker GitHub/OIDC identity matching principalSet .../* or unpinned attribute; no attribute condition) | EXCLUDED | gcp-v3-45-abuse-an-over-broad-existing-workload-workforce-identity-f (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---federation-abuse`, `#oidc---github-actions-abuse`, `#github`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-cross-project-attacks/README.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cross-project-attacks`, `#the-authorization-model`, `#attack-families`, `#initial-reconnaissance`, `#common-end-to-end-chains`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-cross-project-attacks/detection-and-hardening.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cross-project-detection--hardening`, `#build-the-cross-project-trust-graph`, `#cloud-audit-logs-hunting`, `#preventive-org-policies`, `#structural-controls`, `#incident-response`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-cross-project-attacks/historical-cross-project-vulnerabilities.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#service-account-impersonation-and-confused-deputy-privesc` | ## Service-account impersonation and confused-deputy privesc | ConfusedFunction: cloudfunctions.functions.create/update (no actAs); also GCPloit/Deployment Manager/Bad.Build/ConfusedComposer/ModeLeak/ConfigConfusion | EXCLUDED | X: Historical confused-deputy vulnerabilities (ConfusedFunction, Bad.Build, ConfusedComposer, ...) |
| `#gcp--google-workspace-crossings` | ## GCP → Google Workspace crossings | iam.serviceAccountKeys.create on DWD SA (DeleFriend) | COVERED | `gcp-workspace-dwd-key-create` |
| `#managed-service-tenant--host-escapes` | ## Managed-service tenant / host escapes | - | NON-PRIVESC | patched tenant escapes (historical) |
| `#patched-2026-managed-service-vulnerabilities` | ## Patched 2026 managed-service vulnerabilities | - | NON-PRIVESC | patched vendor bugs |
| `#federation-and-metadata-server-abuse` | ## Federation and metadata-server abuse | none on victim (attacker GitHub/OIDC identity matching principalSet .../* or unpinned attribute; no attribute condition) | EXCLUDED | gcp-v3-46-abuse-an-over-broad-existing-workload-workforce-identity-f (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#authorization-bypass-and-shadow-resources` | ## Authorization bypass and shadow resources | - | NON-PRIVESC | patched authz bugs, shadow resources<br>`gcp-kcc-k8s-rbac-iam-member` — conditional verified exact-target authority. |
| `#vpc-service-controls-documented-limitations-not-a-disclosed-bypass` | ## VPC Service Controls: documented limitations, not a disclosed bypass | - | NON-PRIVESC | VPC-SC limitation, data |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---historical-cross-project-vulnerabilities`, `#retesting-historical-claims`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-cross-project-attacks/iam-and-service-account-impersonation-attacks.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#inheritance-one-binding-grants-across-every-child-project` | ## Inheritance: one binding grants across every child project | resourcemanager.organizations/folders/projects.setIamPolicy | COVERED | `gcp-resourcemanager-organizations-setiampolicy`, `gcp-resourcemanager-folders-setiampolicy`, `gcp-resourcemanager-projects-setiampolicy` |
| `#service-account-impersonation--the-crown-jewel` | ## Service-account impersonation — the crown jewel | iam.serviceAccounts.getAccessToken / signJwt / signBlob / implicitDelegation (getOpenIdToken) | COVERED | `gcp-iam-serviceaccounts-getaccesstoken`, `gcp-iam-serviceaccounts-signjwt`, `gcp-iam-serviceaccounts-signblob`, `gcp-iam-serviceaccounts-implicitdelegation` |
| `#actas-and-cross-project-attachment` | ### actAs and cross-project attachment | iam.serviceAccounts.actAs + compute.instances.create (or other runtime create) | EXCLUDED | X: Cross-project service-account attachment overview |
| `#service-account-keys--durable-cross-project-persistence` | ## Service-account keys — durable cross-project persistence | iam.serviceAccountKeys.create | COVERED | `gcp-iam-serviceaccountkeys-create` |
| `#setiampolicy-backdoors-and-public--cross-domain-bindings` | ## setIamPolicy backdoors and public / cross-domain bindings | resourcemanager.projects.setIamPolicy / iam.serviceAccounts.setIamPolicy | EXCLUDED | X: Cross-domain IAM policy self-grant overview |
| `#domain-restricted-sharing-and-its-gaps` | ### Domain Restricted Sharing and its gaps | - | NON-PRIVESC | org policy gaps explainer |
| `#workload--workforce-identity-federation-confused-deputy` | ## Workload / Workforce Identity Federation confused deputy | none on victim (attacker GitHub/OIDC identity matching principalSet .../* or unpinned attribute; no attribute condition) | EXCLUDED | gcp-v3-47-abuse-an-over-broad-existing-workload-workforce-identity-f (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#domain-wide-delegation--pivot-into-google-workspace` | ## Domain-wide delegation — pivot into Google Workspace | iam.serviceAccountKeys.create (or signJwt) on DWD-enabled SA | COVERED | `gcp-workspace-dwd-key-create`, `gcp-workspace-dwd-keyless-signjwt` |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---iam--service-account-impersonation-attacks`, `#enumeration`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-cross-project-attacks/organization-and-central-project-pivots.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#organization-and-folder-iam-admin` | ## Organization and folder IAM admin | resourcemanager.organizations.setIamPolicy / resourcemanager.folders.setIamPolicy | COVERED | `gcp-resourcemanager-organizations-setiampolicy`, `gcp-resourcemanager-folders-setiampolicy` |
| `#cicd-and-terraform-deployer-service-accounts` | ## CI/CD and Terraform deployer service accounts | cloudbuild.builds.create / config.deployments.create + actAs (pointer) | COVERED | `gcp-cloudbuild-builds-create-custom-sa-actas`, `gcp-inframanager-deployments-create-actas` |
| `#cross-project-visibility-and-exfiltration` | ## Cross-project visibility and exfiltration | - | NON-PRIVESC | data exfiltration |
| `#vpc-service-controls-perimeters` | ## VPC Service Controls perimeters | - | NON-PRIVESC | perimeter/network control |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---organization--central-project-pivots`, `#other-central-services`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-cross-project-attacks/resource-sharing-and-confused-deputy-attacks.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cross-service-confused-deputies-default-service-accounts` | ## Cross-service confused deputies (default service accounts) | cloudbuild.builds.create (default identity) | COVERED | `gcp-cloudbuild-builds-create-default-identity` |
| `#cross-project-resource-sharing-service-matrix` | ## Cross-project resource-sharing service matrix | storage.hmacKeys.create; artifactregistry write on shared repo | COVERED | `gcp-storage-hmackeys-create`, `gcp-artifactregistry-upload-artifacts` |
| `#notable-subtleties` | ### Notable subtleties | artifactregistry repo write / storage write to shared code | COVERED | `gcp-artifactregistry-upload-artifacts`, `gcp-storage-cloudbuild-unpinned-storagesource-poison`<br>gcp-pubsub-push-oidc-endpoint — conditional verified exact-target authority. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#shared-vpc-and-networking` | ## Shared VPC and networking | - | NON-PRIVESC | network-only pivot |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---resource-sharing--confused-deputy-attacks`, `#enumeration`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-permissions-for-a-pentest.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---permissions-for-a-pentest`, `#individual-tools-permissions`, `#purplepanda`, `#scoutsuite`, `#cloudsploit`, `#cartography`, `#starbase`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/README.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---persistence`, `#gcp`, `#persistence-categories`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-alloydb-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#plant-a-built-in-alloydbsuperuser-with-an-attacker-known-password` | ### Plant a built-in `alloydbsuperuser` with an attacker-known password | - | NON-PRIVESC | DB-native credential, not GCP principal |
| `#create-a-postgresql-native-backdoor-below-the-alloydb-api-inventory` | ### Create a PostgreSQL-native backdoor below the AlloyDB API inventory | - | NON-PRIVESC | DB-native backdoor user |
| `#keep-an-external-connection-path-open-for-a-standing-database-credential` | ### Keep an external connection path open for a standing database credential | - | NON-PRIVESC | network path to database |
| `#enroll-a-controlled-iam-principal-and-assign-a-durable-database-role` | ### Enroll a controlled IAM principal and assign a durable database role | - | NON-PRIVESC | database role for own principal |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---alloydb-persistence`, `#alloydb`, `#reusable-credentials`, `#standing-access-grants`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-api-keys-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#apikeyskeyscreate--apikeyskeysgetkeystring` | ### `apikeys.keys.create` (+ `apikeys.keys.getKeyString`) | - | NON-PRIVESC | project API key, no principal |
| `#apikeyskeysundelete--revive-a-key-the-defender-already-deleted` | ### `apikeys.keys.undelete` — revive a key the defender already deleted | - | NON-PRIVESC | revives own API key |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---api-keys-persistence`, `#api-keys`, `#reusable-credentials`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-apigee-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#add-a-standing-environment-iam-binding` | ## Add a standing environment IAM binding | - | NON-PRIVESC | environment role only; privesc twin _excluded |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---apigee-environment-iam-persistence`, `#apigee`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-app-engine-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#modify-code` | ### Modify code | appengine.versions.create (+appengine.applications.get, staging bucket write) + iam.serviceAccounts.actAs | COVERED | `gcp-appengine-versions-create-actas` |
| `#older-version-persistence` | ### Older-version persistence | appengine.versions.create/update (+actAs) | COVERED | `gcp-appengine-versions-create-actas` |
| `#cron-based-persistence-cronyaml` | ## Cron-based persistence (`cron.yaml`) | cron.yaml | EXCLUDED | X: Cron-based persistence (cron.yaml) |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---app-engine-persistence`, `#app-engine`, `#code-and-artifact-backdoors`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-artifact-registry-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#dependency-confusion` | ### Dependency Confusion | artifactregistry.repositories.update | COVERED | `gcp-artifactregistry-repositories-update-dependency-confusion` |
| `#remote-repository-pointing-at-an-attacker-controlled-upstream-url` | ### Remote repository pointing at an attacker-controlled upstream URL | artifactregistry.repositories.create (+repositories.update to wire into virtual repo) | COVERED | `gcp-artifactregistry-repositories-update-dependency-confusion`<br>gcp-create-attacker-upstream-remote-repository-consumed-directly — conditional verified exact-target authority. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#upstream-credential-tamper--disclosure---remote-username----remote-password-secret-version` | #### Upstream **credential** tamper + disclosure (`--remote-username` / `--remote-password-secret-version`) | artifactregistry.repositories.update (+secretmanager.versions.add/access for the credential secret) | COVERED | `gcp-artifactregistry-repositories-update-dependency-confusion` |
| `#squat-the-legacy-gcrio-namespace-as-a-permanent-backdoor---artifactregistryrepositoriescreate` | ### Squat the legacy `gcr.io` namespace as a permanent backdoor - `artifactregistry.repositories.create` | gcr.io, artifactregistry.repositories.create | COVERED | `gcp-artifactregistry-gcrio-namespace-squat` |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---artifact-registry-persistence`, `#artifact-registry`, `#code-and-artifact-backdoors`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-bare-metal-solution-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#project-level-ssh-key-backdoor-baremetalsolutionsshkeyscreate` | ## Project-level SSH key backdoor (`baremetalsolution.sshKeys.create`) | - | NON-PRIVESC | host access, no GCP identity |
| `#serial-console-left-enabled-baremetalsolutioninstancesenableinteractiveserialconsole` | ### Serial console left enabled (`baremetalsolution.instances.enableInteractiveSerialConsole`) | - | NON-PRIVESC | host console access only |
| `#standing-nfs-allowlist-entry-baremetalsolutionnfssharesupdate` | ### Standing NFS allowlist entry (`baremetalsolution.nfsshares.update`) | - | NON-PRIVESC | NFS data access |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---bare-metal-solution-bms-persistence`, `#bare-metal-solution-bms`, `#standing-access-grants`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-beyondcorp-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#retain-service-level-access-with-gateway-and-application-iam-bindings` | ## Retain service-level access with gateway and application IAM bindings | - | NON-PRIVESC | app access for own identity |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---beyondcorp-persistence`, `#beyondcorp`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-biglake-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#resource-level-iam-binding-for-a-controlled-principal` | ## Resource-level IAM binding for a controlled principal | - | NON-PRIVESC | data access binding |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---biglake--lakehouse-persistence`, `#biglake--lakehouse`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-bigquery-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#authorized-view-or-dataset--persistent-indirect-read-path` | ### Authorized view or dataset — persistent indirect read path | - | NON-PRIVESC | data read path |
| `#bigquerydatasetsupdate--bigquerydatasetssetiampolicy--persistent-dataset-acl-grant` | ### `bigquery.datasets.update` / `bigquery.datasets.setIamPolicy` — persistent dataset ACL grant | - | NON-PRIVESC | dataset data access |
| `#continuous-query-bound-to-a-service-account--bounded-real-time-exfiltration` | ## Continuous query bound to a service account — bounded real-time exfiltration | bigquery.jobs.create + iam.serviceAccounts.actAs (continuous query --connection_property=service_account) | COVERED | `gcp-bigquery-continuous-query-actas` |
| `#scheduled-query-bound-to-a-service-account--recurring-sql-persistence` | ## Scheduled query bound to a service account — recurring SQL persistence | bigquery.transfers.update + bigquery.datasets.get (or bigquery.jobs.create + bigquery.transfers.get + bigquery.datasets.get) + iam.serviceAccounts.actAs | COVERED | `gcp-bigquery-transfers-scheduled-query-actas` |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---bigquery-persistence`, `#bigquery`, `#standing-access-grants`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-bigtable-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#dedicated-attacker-app-profile` | ## Dedicated attacker App Profile | - | NON-PRIVESC | data-plane routing only |
| `#lock-replication-behind-your-own-cmek` | ## Lock replication behind your own CMEK | - | NON-PRIVESC | anti-remediation / data control |
| `#maintain-your-own-replica-cluster` | ### Maintain your own replica cluster | - | NON-PRIVESC | data replica exfil |
| `#durable-change-stream-wiretap-bigtabletablesupdate` | ### Durable change-stream wiretap (`bigtable.tables.update`) | - | NON-PRIVESC | data exfil stream |
| `#silent-rolling-automated-backups-bigtabletablesupdate` | ### Silent rolling automated backups (`bigtable.tables.update`) | - | NON-PRIVESC | data backup copy |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---bigtable-persistence`, `#bigtable`, `#continuous-data-export`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-certificate-authority-service-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#privatecacertificateauthoritiescreate--attacker-controlled-signing-key--retain-a-trusted-subordinate-ca-credential` | ### `privateca.certificateAuthorities.create` + attacker-controlled signing key — retain a trusted subordinate CA credential | - | NON-PRIVESC | PKI trust, no GCP IAM identity |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---certificate-authority-service-persistence`, `#certificate-authority-service`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cloud-asset-inventory-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloudassetfeedscreate--asset-feed-to-an-attacker-controlled-pubsub-topic` | ### `cloudasset.feeds.create` — asset feed to an attacker-controlled Pub/Sub topic | - | NON-PRIVESC | recon feed exfil |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-asset-inventory-persistence`, `#cloud-asset-inventory`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cloud-deploy-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#clouddeployrolloutsrollback--re-arm-a-backdoor-release-on-demand` | ## `clouddeploy.rollouts.rollback` — re-arm a backdoor release on demand | - | NON-PRIVESC | re-arms own prior release |
| `#clouddeployreleasesabandon--foreclose-the-rollback-remediation-path` | ## `clouddeploy.releases.abandon` — foreclose the rollback remediation path | - | NON-PRIVESC | anti-remediation |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-deploy-persistence`, `#cloud-deploy`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cloud-domains-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#domainsregistrationssetiampolicy--registration-scoped-iam-persistence` | ## `domains.registrations.setIamPolicy` — registration-scoped IAM persistence | - | NON-PRIVESC | domain registration control only |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-domains-persistence`, `#cloud-domains`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cloud-functions-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#backdoor-the-source-or-dependencies` | ## Backdoor the source or dependencies | cloudfunctions.functions.update + cloudfunctions.functions.sourceCodeSet + cloudfunctions.functions.get + iam.serviceAccounts.actAs | COVERED | `gcp-cloudfunctions-update-sourcecodeset-actas` |
| `#use-an-event-trigger` | ## Use an event trigger | - | NON-PRIVESC | trigger for own backdoor |
| `#expose-an-http-backdoor` | ## Expose an HTTP backdoor | - | NON-PRIVESC | public invoker exposure |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-functions-persistence`, `#cloud-functions`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cloud-identity-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#open-an-iam-bound-groups-join-policy--durable-self-service-re-entry` | ## Open an IAM-bound group's join policy — durable self-service re-entry | - | EXCLUDED | gcp-v3-48-open-an-iam-bound-google-group-to-later-self-join-by-a-con (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-identity-persistence`, `#cloud-identity`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cloud-run-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#backdoored-revision` | ### Backdoored Revision | run.services.update (+run.services.get) + iam.serviceAccounts.actAs | COVERED | `gcp-run-services-update-actas` |
| `#backdoored-service-or-job` | ### Backdoored Service or Job | run.jobs.update/create + run.jobs.run + iam.serviceAccounts.actAs (or run.services.create) | COVERED | `gcp-run-jobs-update-run-actas`, `gcp-run-jobs-create-run-actas`, `gcp-run-services-create-actas` |
| `#event-driven-re-invocation--eventarc--pubsub-push-to-a-backdoored-run-service` | ## Event-driven re-invocation — EventArc / Pub/Sub push to a backdoored Run service | - | NON-PRIVESC | re-trigger; OIDC invoker token only |
| `#publicly-accessible-service` | ## Publicly Accessible Service | - | NON-PRIVESC | public exposure |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-run-persistence`, `#cloud-run`, `#code-and-artifact-backdoors`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cloud-scheduler-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#recurring-oidc-beacon---a-renewable-service-account-credential-feed` | ## Recurring OIDC beacon - a renewable service-account credential feed | cloudscheduler.jobs.create + iam.serviceAccounts.actAs | COVERED | `gcp-cloudscheduler-jobs-create-actas` |
| `#recurring-oauth-job---scheduled-re-grant--self-healing-backdoor` | ## Recurring OAuth job - scheduled re-grant / self-healing backdoor | cloudscheduler.jobs.create + iam.serviceAccounts.actAs | COVERED | `gcp-cloudscheduler-jobs-create-actas` |
| `#hijack-an-existing-job-instead-of-creating-one` | ### Hijack an existing job instead of creating one | cloudscheduler.jobs.update + iam.serviceAccounts.actAs | COVERED | `gcp-cloudscheduler-jobs-update-actas` |
| `#pubsub-and-app-engine-jobs---identity-free-dormant-triggers` | ### Pub/Sub and App Engine jobs - identity-free dormant triggers | - | NON-PRIVESC | identity-free trigger |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-scheduler-persistence`, `#cloud-scheduler`, `#triggered-execution`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cloud-shell-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#persistent-home-directory` | ## Persistent home directory | - | NON-PRIVESC | own Cloud Shell home |
| `#backdoor-bashrc` | ### Backdoor <code>.bashrc</code> | - | NON-PRIVESC | own foothold persistence |
| `#backdoor-customize_environment` | ### Backdoor <code>.customize_environment</code> | - | NON-PRIVESC | own foothold persistence |
| `#authorization-and-tokens` | #### Authorization and tokens | - | NON-PRIVESC | own user tokens |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-shell-persistence`, `#cloud-shell`, `#code-and-artifact-backdoors`, `#how-the-ssh-connection-is-established`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cloud-sql-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#expose-a-database-and-whitelist-your-client-ip` | ## Expose a database and whitelist your client IP | - | NON-PRIVESC | network exposure of DB |
| `#create-a-user-or-rotate-a-password` | ### Create a user or rotate a password | - | NON-PRIVESC | DB-native credential |
| `#cloudsqlsslcertscreate--mint-a-durable-client-certificate` | ### `cloudsql.sslCerts.create` — mint a durable client certificate | - | NON-PRIVESC | DB client cert |
| `#sql-server-contained-database-authentication--hidden-portable-db-user` | ### SQL Server `contained database authentication` — hidden, portable DB user | - | NON-PRIVESC | DB-native user |
| `#in-engine-scheduled-task-cloudsqlenable_pg_cron--mysql-event_scheduler--self-triggering-db-persistence` | ## In-engine scheduled task (`cloudsql.enable_pg_cron` / MySQL `event_scheduler`) — self-triggering DB persistence | - | NON-PRIVESC | in-DB scheduled task |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-sql-persistence`, `#cloud-sql`, `#reusable-credentials`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cloud-tasks-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloudtaskstaskscreate---override-queue-retry-limits-per-task` | ### `cloudtasks.tasks.create` - override queue retry limits per task | cloudtasks.tasks.create | EXCLUDED | X: cloudtasks.tasks.create - override queue retry limits per task |
| `#attacker-owned-queue-as-a-private-dispatch-channel` | ### Attacker-owned queue as a private dispatch channel | cloudtasks.queues.create + cloudtasks.tasks.create + iam.serviceAccounts.actAs | COVERED | `gcp-cloudtasks-tasks-create-actas` |
| `#dormant-time-bomb-task---up-to-30-days-of-delayed-execution` | ### Dormant time-bomb task - up to 30 days of delayed execution | cloudtasks.tasks.create + iam.serviceAccounts.actAs | COVERED | `gcp-cloudtasks-tasks-create-actas` |
| `#queue-urioverride---passive-capture-of-every-task-the-application-enqueues` | ## Queue `uriOverride` - passive capture of every task the application enqueues | cloudtasks.queues.update (no actAs) | EXCLUDED | X: Queue uriOverride passive capture of application tasks |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-tasks-persistence`, `#cloud-tasks`, `#triggered-execution`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cluster-director-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#hypercomputeclusterclustersupdate--iamserviceaccountsactas--persist-a-login-fleet-startup-hook` | ## `hypercomputecluster.clusters.update` + `iam.serviceAccounts.actAs` — persist a login-fleet startup hook | hypercomputecluster.clusters.update, iam.serviceAccounts.actAs | EXCLUDED | X: hypercomputecluster.clusters.update + iam.serviceAccounts.actAs — persist a login-fleet startup hook |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cluster-director-persistence`, `#cluster-director`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-compute-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#persist-with-instance-or-project-startup-script-metadata` | ### Persist with instance or project startup-script metadata | compute.instances.setMetadata (page: no actAs for instance scope) or compute.projects.setCommonInstanceMetadata (+iam.serviceAccounts.actAs) | COVERED | `gcp-compute-instances-setmetadata-existing-vm`, `gcp-compute-projects-setcommoninstancemetadata` |
| `#poison-a-consumed-custom-image-family` | ### Poison a consumed custom-image family | compute.images.create + compute.disks.useReadOnly (source disk) | COVERED | `gcp-compute-images-create-family-poison` (NS-3, implemented in schema v1.1) |
| `#persist-through-an-existing-managed-instance-group-template` | ### Persist through an existing Managed Instance Group template | compute.instanceGroupManagers.update + compute.instanceTemplates.create (+ compute.instanceTemplates.useReadOnly, actAs) | COVERED | `gcp-compute-instancegroupmanagers-update-template` |
| `#persist-with-a-recurring-vm-manager-patch-deployment` | ## Persist with a recurring VM Manager patch deployment | osconfig.patchDeployments.create | COVERED | `gcp-osconfig-patchjobs-exec` |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---compute-persistence`, `#compute`, `#code-and-artifact-backdoors`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-config-controller-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#config-sync-pointed-at-an-attacker-controlled-git-source` | ### Config Sync pointed at an attacker-controlled Git source | container.thirdPartyObjects.create/update (RootSync/RepoSync on Config Controller cluster) | COVERED | `gcp-configcontroller-kcc-resource-write` |
| `#self-healing-iam-backdoor-iampolicymember-reconciled-by-kcc` | ### Self-healing IAM backdoor (`IAMPolicyMember` reconciled by KCC) | container.thirdPartyObjects.create (IAMPolicyMember) | COVERED | `gcp-configcontroller-kcc-resource-write` |
| `#durable-instance-iam-binding-krmapihostingkrmapihostssetiampolicy` | ## Durable instance IAM binding (`krmapihosting.krmApiHosts.setIamPolicy`) | krmapihosting.krmApiHosts.setIamPolicy | EXCLUDED | `gcp-configcontroller-krmapihosts-setiampolicy` — declared principal gain unproven |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---config-controller-persistence`, `#config-controller`, `#self-healing-and-protected-footholds`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-contact-center-insights-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#standing-analysis-rule--continuous-auto-analysis-of-new-conversations-analysisrulescreate` | ## Standing analysis rule → continuous auto-analysis of new conversations (`analysisRules.create`) | - | NON-PRIVESC | data processing/exfil |
| `#standing-redaction-disable-via-settingsupdate--durable-raw-pii-capture` | ## Standing redaction-disable via `settings.update` — durable raw-PII capture | - | NON-PRIVESC | data exposure |
| `#authorized-view-iam-binding-for-a-controlled-principal-authorizedviewssetiampolicy` | ## Authorized-view IAM binding for a controlled principal (`authorizedViews.setIamPolicy`) | - | NON-PRIVESC | data view access |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---contact-center-insights-persistence`, `#contact-center-insights`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-container-analysis-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#attacker-controlled-attestor-and-signing-key-trusted-by-policy` | ### Attacker-controlled attestor and signing key trusted by policy | - | NON-PRIVESC | BinAuthz trust, admission bypass |
| `#note-level-iam-binding-for-a-controlled-principal` | ### Note-level IAM binding for a controlled principal | - | NON-PRIVESC | note metadata access |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---container-analysis-persistence`, `#container-analysis`, `#standing-access-grants`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-cx-agent-studio-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cesagentsupdate--cestoolsupdate--implant-persistent-agent-behavior` | ### `ces.agents.update` / `ces.tools.update` — implant persistent agent behavior | - | NON-PRIVESC | app-level agent behavior |
| `#cesappversionscreate--cesdeploymentsupdate--pin-a-backdoored-immutable-version` | ### `ces.appVersions.create` + `ces.deployments.update` — pin a backdoored immutable version | - | NON-PRIVESC | app-level backdoored version |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cx-agent-studio-persistence`, `#cx-agent-studio`, `#code-and-artifact-backdoors`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-data-fusion-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#malicious-artifact--plugin-planted-in-the-namespace-datafusionartifactscreate` | ## Malicious artifact / plugin planted in the namespace (`datafusion.artifacts.create`) | datafusion.artifacts.create | COVERED | `gcp-datafusion-artifacts-create-plugin-poison` |
| `#attacker-controlled-connection--secure-store-key-redirect` | ## Attacker-controlled connection / secure-store key redirect | - | NON-PRIVESC | data redirection |
| `#instancenamespace-iam-binding-for-a-controlled-principal-datafusioninstancessetiampolicy` | ## Instance/namespace IAM binding for a controlled principal (`datafusion.instances.setIamPolicy`) | datafusion.instances.setIamPolicy | EXCLUDED | X: Instance/namespace IAM binding for a controlled principal (datafusion.instances.setIamPolicy) |
| `#scheduled-backdoor-pipeline-pinned-to-a-privileged-runtime-sa` | ## Scheduled backdoor pipeline pinned to a privileged runtime SA | datafusion pipeline deploy/schedule (datafusion.instances.get, pipelines create/execute) + datafusion.namespaces.setServiceAccount + iam.serviceAccounts.actAs | EXCLUDED | `gcp-datafusion-namespace-setserviceaccount-actas` — declared principal gain unproven |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---data-fusion-persistence`, `#data-fusion`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-dataflow-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#invisible-persistence-in-built-container` | ### Invisible persistence in built container | cloudbuild.builds.create (image build) + dataflow.jobs.create + iam.serviceAccounts.actAs | COVERED | `gcp-cloudbuild-builds-create-default-identity`, `gcp-dataflow-jobs-create-actas` |
| `#long-running-streaming-job--artifact-less-sa-bound-running-compute-persistence` | ### Long-running streaming job — artifact-less, SA-bound running-compute persistence | dataflow.jobs.create + iam.serviceAccounts.actAs | COVERED | `gcp-dataflow-jobs-create-actas` |
| `#datapipelinespipelinescreate--recurring-dataflow-run-as-sa-via-a-scheduled-data-pipeline-cron-persistence` | ## `datapipelines.pipelines.create` — recurring Dataflow run-as-SA via a scheduled Data Pipeline (cron persistence) | datapipelines.pipelines.create | COVERED | `gcp-dataflow-datapipelines-create-actas` |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dataflow-persistence`, `#dataflow`, `#code-and-artifact-backdoors`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-dataproc-metastore-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#retain-access-with-a-service-iam-binding` | ## Retain access with a service IAM binding | - | NON-PRIVESC | metadata access binding |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dataproc-metastore-persistence`, `#dataproc-metastore`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-datastream-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#standing-exfil-stream-as-a-durable-exfiltration-channel` | ### Standing exfil stream as a durable exfiltration channel | - | NON-PRIVESC | data exfil |
| `#repoint-an-existing-legitimate-stream-to-an-attacker-destination` | ### Repoint an existing legitimate stream to an attacker destination | - | NON-PRIVESC | data exfil |
| `#durable-network-reach-via-reusable-private-connections--routes` | ## Durable network reach via reusable private connections / routes | - | NON-PRIVESC | network-only pivot |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---datastream-persistence`, `#datastream`, `#continuous-data-export`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-discovery-engine-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#rag--grounding-poisoning--inject-documents-an-llm-will-surface` | ### RAG / grounding poisoning — inject documents an LLM will surface | - | NON-PRIVESC | content poisoning |
| `#website--target-site-indexing` | ### Website / target-site indexing | - | NON-PRIVESC | content poisoning |
| `#resource-level-iam-grant--retain-access-to-an-app-or-corpus` | ## Resource-level IAM grant — retain access to an app or corpus | - | NON-PRIVESC | data access binding |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---discovery-engine-persistence`, `#discovery-engine`, `#code-and-artifact-backdoors`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-dlp-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#dlpjobtriggerscreate--recurring-sensitive-value-collection` | ## `dlp.jobTriggers.create` — recurring sensitive-value collection | - | NON-PRIVESC | data collection |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---sensitive-data-protection-dlp-persistence`, `#sensitive-data-protection-dlp`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-document-ai-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#malicious-default-processor-version--durable-poisoned-pipeline` | ## Malicious default processor version — durable poisoned pipeline | - | NON-PRIVESC | integrity / output poisoning |
| `#standing-cross-project-service-agent-trust--re-entrant-modeldata-exfil` | ## Standing cross-project service-agent trust — re-entrant model/data exfil | - | NON-PRIVESC | own service agent; data exfil |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---document-ai-persistence`, `#document-ai`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-essential-contacts-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#essentialcontactscontactscreate` | ### `essentialcontacts.contacts.create` | - | NON-PRIVESC | notification interception |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---essential-contacts-persistence`, `#essential-contacts`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-eventarc-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#eventarcpipelinescreate--recurring-oauth-token-delivery-as-an-identity-level-backdoor` | ## `eventarc.pipelines.create` — recurring OAuth-token delivery as an identity-level backdoor | eventarc.pipelines.create | EXCLUDED | X: eventarc.pipelines.create — recurring OAuth-token delivery as an identity-level backdoor |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---eventarc-persistence`, `#eventarc`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-filestore-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#give-broader-access-and-privileges-over-a-mount` | ## Give broader access and privileges over a mount | - | NON-PRIVESC | NFS data access |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---filestore-persistence`, `#filestore`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-firebase-app-hosting-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#backdoor-rollout--traffic-split--durable-code-execution-in-a-live-app` | ### Backdoor rollout / traffic split — durable code execution in a live app | firebaseapphosting.builds.create + firebaseapphosting.rollouts.create (+traffic.update) | COVERED | `gcp-firebaseapphosting-build-rollout-existing-backend` |
| `#backend-hijack--repoint-source-or-runtime-identity` | ### Backend hijack — repoint source or runtime identity | firebaseapphosting.backends.update (+iam.serviceAccounts.actAs for a new SA) | COVERED | `gcp-firebaseapphosting-backends-update-actas`, `gcp-firebaseapphosting-backends-update-source` |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---firebase-app-hosting-persistence`, `#firebase-app-hosting`, `#code-and-artifact-backdoors`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-firebase-data-connect-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#backdoor-connector--a-permissive-operation-that-leaks-the-whole-database` | ### Backdoor connector — a permissive operation that leaks the whole database | - | NON-PRIVESC | data exposure |
| `#schema-tampering--durable-data-layer-backdoor-in-postgresql` | ### Schema tampering — durable data-layer backdoor in PostgreSQL | - | NON-PRIVESC | data-layer backdoor |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---firebase-data-connect-persistence`, `#firebase-data-connect`, `#code-and-artifact-backdoors`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-firestore-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#datastoreusercreds--mint-db-native-credentials-iam-independent-persistence--data-plane-exfil` | ### `datastore.userCreds.*` — mint DB-native credentials (IAM-independent persistence / data-plane exfil) | - | NON-PRIVESC | DB-native credentials |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---firestore-persistence`, `#firestore`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-healthcare-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#healthcarefhirstoresupdate--stream-future-fhir-versions-to-bigquery` | ### `healthcare.fhirStores.update` — stream future FHIR versions to BigQuery | - | NON-PRIVESC | data exfil |
| `#healthcarefhirstoresupdate--publish-future-full-fhir-resources-to-pubsub` | ### `healthcare.fhirStores.update` — publish future full FHIR resources to Pub/Sub | - | NON-PRIVESC | data exfil |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-healthcare-persistence`, `#cloud-healthcare`, `#continuous-data-export`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-iam-deny-policies-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#principal-access-boundary-pab-lockout--a-less-watched-sibling-of-deny-policies` | ### Principal Access Boundary (PAB) lockout — a less-watched sibling of deny policies | - | NON-PRIVESC | lockout / DoS |
| `#iamdenypoliciescreate` | ### `iam.denypolicies.create` | - | NON-PRIVESC | lockout / anti-remediation |
| `#angle-1--lockout-persistence-plant-a-restrictive-pab-on-responders` | ### Angle 1 — lockout persistence (plant a restrictive PAB on responders) | - | NON-PRIVESC | responder lockout |
| `#tag-keyed-deny-rules-can-be-evaded-by-moving-a-tag` | ### Tag-keyed deny rules can be evaded by moving a tag | - | NON-PRIVESC | defense evasion of deny |
| `#angle-2--guardrail-removal-privesc-enabler-deleterelax-a-pab-blocking-you` | ### Angle 2 — guardrail-removal privesc-enabler (delete/relax a PAB blocking you) | - | NON-PRIVESC | restores own suppressed allows |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---iam-deny-policies-persistence`, `#iam-deny-policies`, `#self-healing-and-protected-footholds`, `#persistent-defense-evasion`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-iam-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#iamserviceaccountsundelete---reactivate-a-deleted-privileged-identity` | ### `iam.serviceAccounts.undelete` - Reactivate a deleted privileged identity | iam.serviceAccounts.undelete | EXCLUDED | X: Undelete a deleted privileged service account |
| `#resourcemanagersetiampolicy---plant-a-durable-hierarchy-binding` | ### `resourcemanager.*.setIamPolicy` - Plant a durable hierarchy binding | resourcemanager.{projects,folders,organizations}.setIamPolicy | EXCLUDED | X: resourcemanager.*.setIamPolicy - Plant a durable hierarchy binding |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---iam-persistence`, `#iam`, `#standing-access-grants`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-iap-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#durable-iap-resource-iam-binding-to-a-controlled-identity` | ## Durable IAP resource-IAM binding to a controlled identity | - | NON-PRIVESC | tunnel/web access for own SA |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---iap-persistence`, `#iap`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-liens-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#resourcemanagerprojectscreatelien` | ### `resourcemanager.projects.createLien` | - | NON-PRIVESC | anti-remediation |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---liens-persistence`, `#liens`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-logging-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#loggingsinkscreate` | ## `logging.sinks.create` | - | NON-PRIVESC | log exfil |
| `#continuous-log-exfiltration-to-an-attacker-destination` | ### Continuous log exfiltration to an attacker destination | - | NON-PRIVESC | log exfil |
| `#loggingsinksupdate--durable-blinding-of-_default-exclusion-or-disable` | ## `logging.sinks.update` — durable blinding of `_Default` (exclusion or disable) | - | NON-PRIVESC | logging evasion |
| `#loggingbucketsupdate---locked--anti-remediation-retention-floor` | ## `logging.buckets.update --locked` — anti-remediation retention floor | - | NON-PRIVESC | logging evasion / anti-forensics |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---logging-persistence`, `#logging`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-looker-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#in-app-api3-admin-credential--hidden-admin-user` | ### In-app API3 admin credential / hidden admin user | - | NON-PRIVESC | Looker app identity, not GCP |
| `#embed-sso-secret-backdoor` | ### Embed SSO secret backdoor | - | NON-PRIVESC | Looker app access |
| `#project-level-iam-binding-of-roleslookeradmin-to-a-controlled-principal` | ## Project-level IAM binding of `roles/looker.admin` to a controlled principal | - | NON-PRIVESC | own re-entry; generic setIamPolicy |
| `#scheduled-content-delivery--broadened-allowed-email-domains--recurring-operator-driven-exfil` | ## Scheduled content delivery / broadened allowed-email-domains — recurring operator-driven exfil | - | NON-PRIVESC | data exfil |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---looker-persistence`, `#looker`, `#reusable-credentials`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-managed-flink-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#managedflinkjobscreate--long-running-streaming-job-foothold` | ### `managedflink.jobs.create` — long-running streaming-job foothold | managedflink.jobs.create | EXCLUDED | X: managedflink.jobs.create — long-running streaming-job foothold |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---managed-flink-persistence`, `#managed-flink`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-managed-kafka-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#durable-kafka-connect-connector-as-a-standing-tap-managedkafkaconnectorscreate` | ## Durable Kafka Connect connector as a standing tap (`managedkafka.connectors.create`) | - | NON-PRIVESC | data exfil/injection |
| `#attacker-created-topic-as-a-covert-channel--dead-drop-managedkafkatopicscreate` | ## Attacker-created topic as a covert channel / dead-drop (`managedkafka.topics.create`) | - | NON-PRIVESC | covert channel |
| `#kafka-acl-granting-a-controlled-principal-durable-topic-access-managedkafkaaclscreate--updateentries` | ### Kafka ACL granting a controlled principal durable topic access (`managedkafka.acls.create` / `updateEntries`) | - | NON-PRIVESC | data-plane access |
| `#project-level-rolesmanagedkafkaclient-grant-to-a-controlled-identity` | ### Project-level `roles/managedkafka.client` grant to a controlled identity | - | NON-PRIVESC | own re-entry, data role |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---managed-kafka-persistence`, `#managed-kafka`, `#standing-access-grants`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-monitoring-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#alert-policy--attacker-channel-as-a-defender-activity-feed---monitoringalertpoliciescreate--monitoringnotificationchannelscreate` | ### Alert policy + attacker channel as a defender-activity feed - `monitoring.alertPolicies.create` + `monitoring.notificationChannels.create` | - | NON-PRIVESC | recon tripwire |
| `#hijacking-the-existing-alert-delivery-path---monitoringnotificationchannelsupdate` | ### Hijacking the existing alert delivery path - `monitoring.notificationChannels.update` | - | NON-PRIVESC | alert interception |
| `#long-lived-snooze-as-durable-blindness---monitoringsnoozescreate--update` | ## Long-lived snooze as durable blindness - `monitoring.snoozes.create` / `.update` | - | NON-PRIVESC | alerting evasion |
| `#uptime-check-as-a-recurring-outbound-channel---monitoringuptimecheckconfigscreate` | ## Uptime check as a recurring outbound channel - `monitoring.uptimeCheckConfigs.create` | - | NON-PRIVESC | egress channel |
| `#scheduled-service-agent-oidc-token-harvesting---monitoringuptimecheckconfigscreate--an-endpoint-you-control` | ## Scheduled service-agent OIDC token harvesting - `monitoring.uptimeCheckConfigs.create` + an endpoint you control | - | NON-PRIVESC | audience-bound OIDC only (excluded class)<br>`gcp-s08-10-receive-monitoring-service-agent-oidc-tokens` — conditional verified exact-target authority. |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---monitoring-persistence`, `#monitoring`, `#continuous-data-export`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-netapp-volumes-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cross-region--cross-project-replication-mirror-to-an-attacker-project` | ### Cross-region / cross-project replication mirror to an attacker project | - | NON-PRIVESC | data exfil |
| `#scheduled-backup-policy--attacker-controlled-backup-vault` | ### Scheduled backup policy → attacker-controlled backup vault | - | NON-PRIVESC | data exfil |
| `#standing-permissive-export-policy-rule--durable-credential-less-nfssmb-tap` | ## Standing permissive export-policy rule — durable credential-less NFS/SMB tap | - | NON-PRIVESC | NFS data access |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---netapp-volumes-persistence`, `#netapp-volumes`, `#continuous-data-export`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-non-svc-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#authenticated-user-tokens` | ### Authenticated User Tokens | - | EXCLUDED | gcp-v3-05-steal-another-google-user-s-locally-stored-gcloud-access-o (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#service-accounts` | ### Service Accounts | - | EXCLUDED | gcp-v3-06-steal-a-service-account-private-key-or-access-token-from-a (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#metadata` | ### Metadata | - | EXCLUDED | gcp-v3-07-fetch-an-attached-service-account-s-token-after-gaining-gu (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---token-persistence`, `#iam`, `#reusable-credentials`, `#auth-flow`, `#oauth-scopes`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-oracle-database-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#goldengate-replication-to-an-attacker-target--continuous-cdc-exfil` | ## GoldenGate replication to an attacker target — continuous CDC exfil | - | NON-PRIVESC | data exfil |
| `#standing-wallet--backdoor-db-user` | ## Standing wallet / backdoor DB user | - | NON-PRIVESC | DB-native credential |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---oracle-databasegoogle-cloud-persistence`, `#oracle-databasegoogle-cloud`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-pam-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#no-approval-self-eligible-entitlement--durable-laundered-re-entry` | ### No-approval self-eligible entitlement → durable, laundered re-entry | - | NON-PRIVESC | needs existing grant ability (anti-delegation) |
| `#broaden-or-hijack-an-existing-entitlement-entitlementsupdate--entitlementssetiampolicy` | ### Broaden or hijack an existing entitlement (`entitlements.update` / `entitlements.setIamPolicy`) | - | NON-PRIVESC | re-entry; anti-delegation per page |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---privileged-access-manager-pam-persistence`, `#privileged-access-manager-pam`, `#standing-access-grants`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-private-catalog-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#durable-poisoned-product-in-an-associated-catalog` | ### Durable poisoned product in an associated catalog | cloudprivatecatalogproducer.products.update (product/version write in associated catalog) | COVERED | `gcp-privatecatalog-product-version-poison`<br>gcp-s08-16-associate-poisoned-catalog-with-additional-consumer-hie — conditional verified exact-target authority. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---private-catalog-persistence`, `#private-catalog`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-pub-sub-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#retain-access-through-a-resource-iam-binding` | ## Retain access through a resource IAM binding | - | NON-PRIVESC | topic/subscription data access |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---pubsub-resource-iam-persistence`, `#pubsub`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-resource-iam-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#keep-access-with-a-resource-iam-binding` | ## Keep access with a resource IAM binding | - | NON-PRIVESC | resource-bounded roles (AD/DNS/BinAuthz) |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---resource-iam-persistence`, `#iam`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-secret-manager-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#rotation-misuse` | ## Rotation misuse | - | NON-PRIVESC | rotation suppression / exfil |
| `#delayed-destroy-ttl-as-an-incident-response-defeat` | ## Delayed-destroy TTL as an incident-response defeat | - | NON-PRIVESC | anti-remediation |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---secret-manager-persistence`, `#secret-manager`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-security-command-center-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#standing-mute-config--an-evergreen-suppression-rule` | ### Standing mute config — an evergreen suppression rule | - | NON-PRIVESC | detection evasion |
| `#persistently-disabled-detectors--modules` | ### Persistently disabled detectors / modules | - | NON-PRIVESC | detection evasion |
| `#dead-custom-detection-module` | ### Dead custom detection module | - | NON-PRIVESC | detection evasion |
| `#repointed--deleted-export-pipeline` | ### Repointed / deleted export pipeline | - | NON-PRIVESC | detection evasion |
| `#vmruntime-opt-out-as-standing-blind-spot` | ### VM/runtime opt-out as standing blind spot | - | NON-PRIVESC | detection evasion |
| `#security-posture-tamper--revert-preventive-guardrails-silently-securitypostureposturedeployments` | ### Security Posture tamper — revert **preventive** guardrails, silently (`securityposture.postureDeployments.*`) | - | NON-PRIVESC | guardrail removal |
| `#self-grant-on-a-source-durable-finding-control` | ## Self-grant on a source (durable finding control) | - | NON-PRIVESC | finding control only |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---security-command-center-persistence`, `#security-command-center`, `#persistent-defense-evasion`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-service-directory-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#servicedirectorynamespacesservicessetiampolicy--resource-scoped-iam-persistence` | ## `servicedirectory.namespaces/services.setIamPolicy` — resource-scoped IAM persistence | - | NON-PRIVESC | service registry access |
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---service-directory-persistence`, `#service-directory`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-spanner-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#standing-change-stream-as-an-ongoing-cdc-exfil-channel` | ## Standing change stream as an ongoing CDC exfil channel | - | NON-PRIVESC | data exfil |
| `#standing-data-role-grant-to-a-throwaway-principal-setiampolicy-backdoor` | ### Standing data-role grant to a throwaway principal (setIamPolicy backdoor) | - | NON-PRIVESC | data access binding |
| `#fine-grained-access-database-role-backdoor-updateddl` | ### Fine-grained-access database-role backdoor (updateDdl) | - | NON-PRIVESC | data access backdoor |
| `#long-retention-backup--backup-schedule-as-a-delayed-restore-copy` | ## Long-retention backup / backup schedule as a delayed-restore copy | - | NON-PRIVESC | data copy |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---spanner-persistence`, `#spanner`, `#standing-access-grants`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-storage-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#storagehmackeyscreate` | ## `storage.hmacKeys.create` | storage.hmacKeys.create | EXCLUDED | X: storage.hmacKeys.create |
| `#storagebucketsupdate--pubsub-object-notification-exfil--monitoring-channel` | ## `storage.buckets.update` — Pub/Sub object-notification exfil & monitoring channel | - | NON-PRIVESC | metadata exfil channel |
| `#give-public-access` | ### Give Public Access | - | NON-PRIVESC | public data exposure |
| `#storagebucketsupdate--default-object-acl-poisoning-auto-expose-future-objects` | ### `storage.buckets.update` — default-object-ACL poisoning (auto-expose future objects) | - | NON-PRIVESC | data exposure |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---storage-persistence`, `#storage`, `#standing-access-grants`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-vm-migration-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vm-migration-persistence`, `#vm-migration`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-vmwareengine-gcve-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#resetvcentercredentials--resetnsxcredentials--rotate-to-a-credential-only-the-attacker-holds` | ### `resetVcenterCredentials` / `resetNsxCredentials` — rotate to a credential only the attacker holds | - | NON-PRIVESC | VMware identity, not GCP (excluded) |
| `#durable-vcenter-local-accounts--sso-identity-source--custom-roles` | ### Durable vCenter local accounts / SSO identity source / custom roles | - | NON-PRIVESC | in-appliance identity |
| `#internet-facing-management-access-rule-as-a-durable-ingress-backdoor` | ### Internet-facing management access rule as a durable ingress backdoor | - | NON-PRIVESC | network ingress |
| `#privatecloudssetiampolicy--durable-iam-binding-for-a-controlled-principal` | ### `privateClouds.setIamPolicy` — durable IAM binding for a controlled principal | - | NON-PRIVESC | vCenter creds only; twin _excluded |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vmware-engine-gcve-persistence`, `#vmware-engine-gcve`, `#reusable-credentials`, `#standing-access-grants`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-vpc-service-controls-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#standing-egressingress-rule-as-a-sanctioned-exfil-channel` | ### Standing egress/ingress rule as a sanctioned exfil channel | - | NON-PRIVESC | exfil boundary tamper |
| `#standing-permissive-access-level-attacker-context-whitelisted` | ### Standing permissive access level (attacker context whitelisted) | - | NON-PRIVESC | context-access guardrail tamper |
| `#perimeter-parked-in-dry-run--a-wall-that-never-blocks` | ## Perimeter parked in dry-run — a wall that never blocks | - | NON-PRIVESC | guardrail disable |
| `#gcpuseraccessbindingscreateupdate--90-day-workforce-looker-sessions` | ## `gcpUserAccessBindings.create/update` — 90-day Workforce Looker sessions | - | NON-PRIVESC | session lifetime extension |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vpc-service-controls-persistence`, `#vpc-service-controls`, `#standing-access-grants`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-workflows-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#backdoor-workflow-bound-to-a-privileged-service-account` | ### Backdoor workflow bound to a privileged service account | workflows.workflows.create + workflows.executions.create + iam.serviceAccounts.actAs | COVERED | `gcp-workflows-create-actas-execute`<br>gcp-workflows-existing-parameterized-invoke — conditional verified exact-target authority. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#source-only-update---keep-a-privileged-identity-after-actas-is-revoked` | ### Source-only update - keep a privileged identity after `actAs` is revoked | workflows.workflows.update + workflows.executions.create (no actAs) | EXCLUDED | X: Source-only update - keep a privileged identity after actAs is revoked |
| `#scheduler-triggered-workflow---unattended-re-execution` | ### Scheduler-triggered workflow - unattended re-execution | cloudscheduler.jobs.create + iam.serviceAccounts.actAs on an SA with workflows.executions.create | COVERED | `gcp-cloudscheduler-jobs-create-actas` |
| `#long-lived-callback-endpoint---a-waiting-execution-as-a-trigger` | ### Long-lived callback endpoint - a waiting execution as a trigger | workflows.workflows.create/update + workflows.executions.create (+actAs for new SA); later workflows.callbacks.send | COVERED | `gcp-workflows-create-actas-execute`, `gcp-workflows-update-source-retain-sa`<br>gcp-workflows-parameterized-callback — conditional verified exact-target authority. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---workflows-persistence`, `#workflows`, `#code-and-artifact-backdoors`, `#triggered-execution`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-persistence/gcp-workload-identity-federation-persistence.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#workforce-pool-and-provider--org-level-human-identity-backdoor` | ### Workforce pool and provider — org-level human-identity backdoor | iam.googleapis.com/workforcePools.create + iam.googleapis.com/workforcePoolProviders.create + resourcemanager.{projects,folders,organizations}.setIamPolicy | COVERED | `gcp-wif-workforce-provider-control`, `gcp-resourcemanager-projects-setiampolicy` |
| `#iamgoogleapiscomworkloadidentitypoolscreate--workloadidentitypoolproviderscreate--external-backdoor` | ### `iam.googleapis.com/workloadIdentityPools.create` + `workloadIdentityPoolProviders.create` — external backdoor | workloadIdentityPoolProviders.create | EXCLUDED | X: New workload identity pool and provider backdoor |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---workload-identity-federation-persistence`, `#workload-identity-federation`, `#standing-access-grants`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/README.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---post-exploitation`, `#credential-access`, `#data-export`, `#traffic-interception--redirection`, `#data-tampering`, `#security-control-bypass`, `#telemetry-tampering`, `#dosbreak` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-access-approval-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#accessapprovalsettingsupdate--accessapprovalsettingsdelete` | ### `accessapproval.settings.update` / `accessapproval.settings.delete` | - | NON-PRIVESC | approval control evasion only |
| `#accessapprovalrequestsapprove--dismiss--invalidate--rubber-stamp-or-kill-approval-requests` | ### `accessapproval.requests.approve` / `.dismiss` / `.invalidate` — rubber-stamp or kill approval requests | - | NON-PRIVESC | approves Google staff access |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---access-approval-post-exploitation`, `#access-approval`, `#security-control-bypass`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-advisory-notifications-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#advisorynotificationsnotificationslist--read-full-security-and-privacy-notices` | ### `advisorynotifications.notifications.list` — read full security and privacy notices | - | NON-PRIVESC | notice data read |
| `#advisorynotificationssettingsupdate--disable-organization-sensitive-actions-delivery` | ### `advisorynotifications.settings.update` — disable organization Sensitive Actions delivery | - | NON-PRIVESC | notification telemetry tampering |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---advisory-notifications-post-exploitation`, `#advisory-notifications`, `#data-export`, `#telemetry-tampering`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-alloydb-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#alloydbuserscreate--update--plant-a-built-in-database-administrator-credential` | ### `alloydb.users.create` / `.update` — plant a built-in database administrator credential | - | NON-PRIVESC | DB credential, no IAM gain |
| `#create-an-iam-database-user-with-an-explicit-database-role` | ### Create an IAM database user with an explicit database role | - | NON-PRIVESC | database-level privilege only |
| `#alloydbinstancesexecutesql--query-through-the-data-api-without-a-database-network-path` | ### `alloydb.instances.executeSql*` — query through the Data API without a database network path | - | NON-PRIVESC | database data read |
| `#alloydbclustersexport--export-database-data-to-an-attacker-controlled-bucket` | ### `alloydb.clusters.export` — export database data to an attacker-controlled bucket | - | NON-PRIVESC | data export |
| `#alloydbclustersrestore--restore-a-cross-project-backup-into-a-controlled-project` | ### `alloydb.clusters.restore` — restore a cross-project backup into a controlled project | - | NON-PRIVESC | data copy to attacker project |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---alloydb-post-exploitation`, `#alloydb`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-api-gateway-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#apigatewayapiconfigscreate--actas--steal-an-sas-oidc-identity-token` | ### `apigateway.apiconfigs.create` (+ `actAs`) — steal an SA's OIDC identity token | apigateway.apiconfigs.create | EXCLUDED | X: API Gateway backend-auth SA OIDC ID token theft |
| `#auth-bypass-by-redefining-security-in-the-openapi-spec` | ### Auth-bypass by redefining `security` in the OpenAPI spec | - | NON-PRIVESC | exposes backend unauthenticated |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---api-gateway-post-exploitation`, `#api-gateway`, `#credential-access`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-apigee-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#historical--unpatched-hybrid-cve-2025-13292-gatewaytoheaven` | ### Historical / unpatched Hybrid: CVE-2025-13292 (`GatewayToHeaven`) | - | EXCLUDED | gcp-v3-01-unpatched-apigee-hybrid-metadata-and-analytics-worker-cred (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---apigee-post-exploitation`, `#apigee`, `#related-authenticated-techniques`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-app-engine-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#read-secrets-and-deployment-locations-from-version-configuration` | ### Read secrets and deployment locations from version configuration | - | NON-PRIVESC | config/secret read<br>`gcp-appengine-version-env-credential` — conditional verified exact-target authority. |
| `#read-application-logs-with-logginglogentrieslist` | ### Read application logs with `logging.logEntries.list` | - | NON-PRIVESC | log data read<br>`gcp-appengine-log-credential` — conditional verified exact-target authority. |
| `#read-source-code` | ### Read Source Code | - | NON-PRIVESC | source code read<br>`gcp-appengine-source-credential` — conditional verified exact-target authority. |
| `#read-or-poison-app-engine-memcache-data` | ### Read or poison App Engine Memcache data | - | NON-PRIVESC | cache data read/tamper<br>`gcp-appengine-memcache-session` — conditional verified exact-target authority. |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---app-engine-post-exploitation`, `#app-engine`, `#credential-access`, `#data-export`, `#data-tampering`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-app-lifecycle-manager-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#saasservicemgmtflagsupdate--revisionreleaserollout-creation--change-application-behavior-without-deploying-code` | ### `saasservicemgmt.flags.update` + revision/release/rollout creation — change application behavior without deploying code | - | NON-PRIVESC | app-defined behavior, not IAM |
| `#saasservicemgmtflagreleasescreate--rolloutscreate--republish-a-known-older-flag-revision` | ### `saasservicemgmt.flagReleases.create` + `rollouts.create` — republish a known older flag revision | - | NON-PRIVESC | app-defined behavior, not IAM |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---app-lifecycle-manager-post-exploitation`, `#app-lifecycle-manager`, `#data-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-application-design-center-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#rolesdesigncenterviewer--read-objects-from-known-cloud-storage-buckets` | ### `roles/designcenter.viewer` — read objects from known Cloud Storage buckets | - | NON-PRIVESC | bucket object read<br>`gcp-designcenter-bucket-credential` — conditional verified exact-target authority. |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---application-design-center-post-exploitation`, `#application-design-center`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-artifact-registry-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#artifactregistryrepositoriesdownloadartifacts--inspect-stored-artifacts-for-sensitive-data` | ### `artifactregistry.repositories.downloadArtifacts` — inspect stored artifacts for sensitive data | - | NON-PRIVESC | artifact data read<br>`gcp-artifactregistry-download-credential` — conditional verified exact-target authority. |
| `#artifactregistryrepositoriesexportartifacts--copy-an-artifact-to-cloud-storage` | ### `artifactregistry.repositories.exportArtifacts` — copy an artifact to Cloud Storage | - | NON-PRIVESC | artifact export<br>`gcp-artifactregistry-export-credential` — conditional verified exact-target authority. |
| `#artifactregistryattachmentscreate--add-untrusted-metadata-to-an-artifact` | ### `artifactregistry.attachments.create` — add untrusted metadata to an artifact | - | NON-PRIVESC | supply-chain metadata tamper |
| `#artifactregistryrepositoriessetiampolicy--expose-a-repository-publicly` | ### `artifactregistry.repositories.setIamPolicy` — expose a repository publicly | - | NON-PRIVESC | public exposure (self-grant is gcp-artifactregistry-repositories-setiampolicy) |
| `#disable-artifact-registry-platform-logs` | ### Disable Artifact Registry platform logs | - | NON-PRIVESC | telemetry tampering |
| `#artifactregistryrepositoriesupdate--disable-automatic-vulnerability-scanning` | ### `artifactregistry.repositories.update` — disable automatic vulnerability scanning | - | NON-PRIVESC | security control disable |
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---artifact-registry-post-exploitation`, `#artifact-registry`, `#data-export`, `#data-tampering`, `#security-control-bypass`, `#telemetry-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-backup-and-dr-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#backup-and-restore-gke-secrets-into-an-attacker-accessible-cluster` | ### Backup and restore GKE Secrets into an attacker-accessible cluster | - | EXCLUDED | gcp-v3-02-copy-source-cluster-credential-secrets-with-backup-for-gke (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#continuously-capture-labelled-compute-resources-with-auto-protection` | ### Continuously capture labelled Compute resources with auto-protection | - | NON-PRIVESC | data capture<br>`gcp-backupdr-autoprotection-disk-credential` — conditional verified exact-target authority. |
| `#restore-a-vaulted-compute-engine-backup-into-a-controlled-project` | ### Restore a vaulted Compute Engine backup into a controlled project | - | EXCLUDED | data export to controlled project<br>`gcp-backupdr-restore-compute-vm-as-chosen-sa` — restore proves data recovery, not usable chosen-SA authority<br>gcp-backupdr-restored-disk-credential — conditional verified exact-target authority. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---backup-and-dr-post-exploitation`, `#backup-and-dr`, `#credential-access`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-bare-metal-solution-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#baremetalsolutionnfssharesupdate--expose-an-nfs-export-to-a-reachable-client` | ### `baremetalsolution.nfsshares.update` — expose an NFS export to a reachable client | - | NON-PRIVESC | data exposure |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---bare-metal-solution-post-exploitation`, `#bare-metal-solution`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-beyondcorp-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#inventory-private-web-routes-gateway-identities-and-access-policies` | ### Inventory private web routes, gateway identities, and access policies | - | NON-PRIVESC | recon |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---beyondcorp-post-exploitation`, `#beyondcorp--chrome-enterprise-premium`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-biglake-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#biglaketablesgetdata--obtain-table-scoped-cloud-storage-credentials` | ### `biglake.tables.getData` — obtain table-scoped Cloud Storage credentials | - | NON-PRIVESC | prefix-scoped storage data token |
| `#biglaketablesupdatedata--update--write-objects-and-commit-a-malicious-iceberg-snapshot` | ### `biglake.tables.updateData` + `.update` — write objects and commit a malicious Iceberg snapshot | - | NON-PRIVESC | data tampering |
| `#biglaketablesupdate--repoint-a-biglake-metastore-classic-table-location` | ### `biglake.tables.update` — repoint a BigLake metastore (classic) table location | - | NON-PRIVESC | data integrity tampering |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---biglake-post-exploitation`, `#biglake--lakehouse`, `#credential-access`, `#data-tampering`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-bigquery-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#bigqueryjobslistall--jobslist-jobsget--read-every-principals-sql-silently` | ### `bigquery.jobs.listAll` (+ `jobs.list`, `jobs.get`) — read every principal's SQL, silently | - | NON-PRIVESC | query/data read<br>`gcp-bigquery-job-sql-credential` — conditional verified exact-target authority. |
| `#bigquerytablesgetdata--paginate-an-entire-table-without-running-a-query` | ### `bigquery.tables.getData` — paginate an entire table without running a query | - | NON-PRIVESC | table data read |
| `#bigqueryconnectionsuse--query-cloud-sql-through-stored-connection-credentials` | ### `bigquery.connections.use` — query Cloud SQL through stored connection credentials | - | NON-PRIVESC | data read via stored creds |
| `#bigquery-sql-injection-through-an-application-identity--disclose-reachable-data` | ### BigQuery SQL injection through an application identity — disclose reachable data | - | NON-PRIVESC | data read via app |
| `#bigquerytablesexport--export-data--bulk-exfiltration-to-attacker-controlled-storage` | ### `bigquery.tables.export` / `EXPORT DATA` — bulk exfiltration to attacker-controlled storage | - | NON-PRIVESC | data export |
| `#bigquerymodelsexport--mlweights--exfiltrate-trained-bqml-models` | ### `bigquery.models.export` / `ML.WEIGHTS` — exfiltrate trained BQML models | - | NON-PRIVESC | model export |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---bigquery-post-exploitation`, `#bigquery`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-bigtable-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#read-base-table-rows` | ### Read base-table rows | - | NON-PRIVESC | data read |
| `#read-data-exposed-through-a-scoped-view` | ### Read data exposed through a scoped view | - | NON-PRIVESC | data read |
| `#undelete-a-recently-deleted-table` | ### Undelete a recently deleted table | - | NON-PRIVESC | data recovery/read |
| `#restore-a-backup-into-a-new-table-or-project` | ### Restore a backup into a new table or project | - | NON-PRIVESC | data copy |
| `#tamper-with-or-destroy-row-data` | ### Tamper with or destroy row data | - | NON-PRIVESC | data tamper/DoS |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---bigtable-post-exploitation`, `#bigtable`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-binary-authorization-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#binaryauthorizationpolicyupdate-plus-workload-deployment--relax-admission-and-obtain-a-workload-foothold` | ### `binaryauthorization.policy.update` plus workload deployment — relax admission and obtain a workload foothold | binaryauthorization.policy.update | EXCLUDED | X: binaryauthorization.policy.update plus workload deployment — relax admission and obtain a workload foothold |
| `#binaryauthorizationattestorsupdate-plus-artifact-analysis-occurrence-creation--inject-a-signing-key-and-obtain-a-workload-foothold` | ### `binaryauthorization.attestors.update` plus Artifact Analysis occurrence creation — inject a signing key and obtain a workload foothold | binaryauthorization.attestors.update | EXCLUDED | X: binaryauthorization.attestors.update plus Artifact Analysis occurrence creation — inject a signing key and obtain a workload footh |
| `#gke-breakglass-label-plus-pod-creation--bypass-admission-and-obtain-a-pod-foothold` | ### GKE breakglass label plus Pod creation — bypass admission and obtain a Pod foothold | Kubernetes RBAC pods create (container.pods.create) | COVERED | `gcp-container-pod-template-node-sa` |
| `#cloud-run---breakglass-plus-service-deployment--bypass-admission-and-obtain-a-revision-foothold` | ### Cloud Run `--breakglass` plus service deployment — bypass admission and obtain a revision foothold | run.services.get + run.services.update + run.operations.get + artifactregistry.repositories.downloadArtifacts + iam.serviceAccounts.actAs | COVERED | `gcp-run-services-update-actas` |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---binary-authorization-post-exploitation`, `#binary-authorization`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-certificate-manager-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#publiccaexternalaccountkeyscreate--register-a-persistent-off-platform-acme-account` | #### `publicca.externalAccountKeys.create` — register a persistent off-platform ACME account | - | NON-PRIVESC | external ACME account persistence |
| `#certificatemanagertrustconfigsupdate--inject-an-mtls-client-identity` | ### `certificatemanager.trustconfigs.update` — inject an mTLS client identity | - | NON-PRIVESC | app mTLS bypass, no IAM |
| `#certificatemanagercertmapentriesupdate--substitute-a-live-hostname-certificate` | ### `certificatemanager.certmapentries.update` — substitute a live hostname certificate | - | NON-PRIVESC | TLS impersonation/DoS |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---certificate-manager-post-exploitation`, `#certificate-manager`, `#public-ca-publiccagoogleapiscom`, `#security-control-bypass`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-asset-inventory-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#analyzeiampolicylongrunning--expanded-iam-graph-to-a-chosen-destination` | ### `AnalyzeIamPolicyLongrunning` — expanded IAM graph to a chosen destination | - | NON-PRIVESC | bulk IAM metadata export |
| `#exportassets--one-shot-bulk-export-to-an-attacker-controlled-bucket--dataset` | ### `ExportAssets` — one-shot bulk export to an attacker-controlled bucket / dataset | - | NON-PRIVESC | bulk asset metadata export |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-asset-inventory-post-exploitation`, `#cloud-asset-inventory`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-build-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#read-stored-build-output` | ### Read stored build output | - | NON-PRIVESC | build output read<br>`gcp-cloudbuild-log-credential` — conditional verified exact-target authority. |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-build-post-exploitation`, `#cloud-build`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-deploy-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#clouddeployreleasesget--list--plaintext-deploy-params--execution-sa-disclosure-viewer-only` | ### `clouddeploy.releases.get` / `.list` — plaintext deploy-params + execution-SA disclosure (viewer-only) | - | NON-PRIVESC | secret/SA disclosure read |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-deploy-post-exploitation`, `#cloud-deploy`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-dns-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#modify-a-public-zone-to-redirect-traffic-mail-or-domain-validation` | #### Modify a public zone to redirect traffic, mail, or domain validation | dns.changes.create + dns.resourceRecordSets.create/update (dns.managedZones.get) | COVERED | `gcp-workspace-cloud-dns-admin-recovery` |
| `#attach-an-outbound-server-policy-to-redirect-vpc-wide-dns` | #### Attach an outbound server policy to redirect VPC-wide DNS | - | NON-PRIVESC | network traffic redirection |
| `#add-a-response-policy-rule-for-a-targeted-dns-override` | #### Add a response-policy rule for a targeted DNS override | - | NON-PRIVESC | network traffic redirection |
| `#create-a-forwarding-or-peering-zone` | #### Create a forwarding or peering zone | - | NON-PRIVESC | network traffic redirection |
| `#shadow-internal-names-with-a-private-authoritative-zone-or-private-zone-record` | ### Shadow internal names with a private authoritative zone or private-zone record | - | NON-PRIVESC | network traffic redirection |
| `#enable-dns-query-surveillance-or-disable-query-logging` | ### Enable DNS query surveillance or disable query logging | - | NON-PRIVESC | telemetry tampering |
| `#disable-dnssec-while-the-parent-ds-record-remains` | ### Disable DNSSEC while the parent DS record remains | - | NON-PRIVESC | DNS DoS |
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-dns-post-exploitation`, `#dns`, `#scope-boundaries`, `#traffic-interception--redirection`, `#dns-tampering-techniques`, `#telemetry-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-domains-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#domainsregistrationsconfiguremanagement--obtain-the-transfer-credential-and-transfer-the-domain` | ### `domains.registrations.configureManagement` — obtain the transfer credential and transfer the domain | - | COVERED | domain transfer/takeover off-platform<br>`gcp-domains-configuremanagement-transfer-workspace-admin-recovery` |
| `#domainsregistrationsconfiguredns--redirect-authoritative-dns` | ### `domains.registrations.configureDns` — redirect authoritative DNS | domains.registrations.configureDns | COVERED | `gcp-domains-configuredns-workspace-admin-recovery` (NS-2, implemented in schema v1.1) |
| `#domainsregistrationsconfigurecontact--expose-registrant-data-or-alter-transfer-contacts` | ### `domains.registrations.configureContact` — expose registrant data or alter transfer contacts | - | NON-PRIVESC | registrant data/contact tamper |
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-domains-post-exploitation`, `#cloud-domains`, `#credential-access`, `#traffic-interception--redirection`, `#data-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-functions-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#read-managed-source-bucket-objects-directly` | ### Read managed source-bucket objects directly | - | NON-PRIVESC | source code read |
| `#cloudfunctionsfunctionssourcecodeget--request-a-signed-source-download-url` | ### `cloudfunctions.functions.sourceCodeGet` — request a signed source-download URL | - | NON-PRIVESC | source code read |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-run-functions-post-exploitation`, `#cloud-functions`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-quotas-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloudquotasquotasget--map-capacity-dimensions-and-quota-request-history` | ### `cloudquotas.quotas.get` — map capacity, dimensions and quota-request history | - | NON-PRIVESC | recon |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-quotas-post-exploitation`, `#cloud-quotas`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-run-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#access-the-images` | ### Access the images | - | NON-PRIVESC | image data read |
| `#runlocationsexportimage--export-a-cached-private-image-without-source-registry-access` | ### `run.locations.exportImage` — export a cached private image without source-registry access | - | NON-PRIVESC | image export |
| `#modify--redeploy-the-image` | ### Modify & redeploy the image | run.services.update + iam.serviceAccounts.actAs | COVERED | `gcp-run-services-update-actas` |
| `#serverless-vpc-access-connector--pivot-from-serverless-into-an-internal-vpc` | ### Serverless VPC Access connector — pivot from serverless into an internal VPC | - | NON-PRIVESC | network pivot (deploy is gcp-run-services-*-actas) |
| `#delete-cloud-run-services-jobs-or-revisions` | ### Delete Cloud Run services, jobs or revisions | - | NON-PRIVESC | DoS |
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-run-post-exploitation`, `#cloud-run`, `#data-export`, `#data-tampering`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-scheduler-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloudschedulerjobsget-or-list--cloudschedulerjobsfullview--silent-secret-harvesting` | ### (`cloudscheduler.jobs.get` or `.list`) + `cloudscheduler.jobs.fullView` — silent secret harvesting | - | NON-PRIVESC | secret read |
| `#cloudschedulerjobsrun---replay-privileged-jobs-on-demand` | ### `cloudscheduler.jobs.run` - replay privileged jobs on demand | - | NON-PRIVESC | replays fixed job, no new identity |
| `#cloudschedulerjobsupdate---payloadtarget-tampering-on-a-trusted-job` | ### `cloudscheduler.jobs.update` - payload/target tampering on a trusted job | cloudscheduler.jobs.update | EXCLUDED | X: cloudscheduler.jobs.update - payload/target tampering on a trusted job |
| `#cloudschedulerjobspause--cloudschedulerjobsdelete---disruption` | ### `cloudscheduler.jobs.pause` / `cloudscheduler.jobs.delete` - disruption | - | NON-PRIVESC | DoS |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-scheduler-post-exploitation`, `#cloud-scheduler`, `#credential-access`, `#data-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-shell-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#recover-the-authorized-users-session-access-token` | ### Recover the authorized user's session access token | - | NON-PRIVESC | needs prior session foothold |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-shell-post-exploitation`, `#cloud-shell`, `#excluded-low-value-or-historical-behaviors`, `#credential-access`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-sql-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#export-sql-server-login-password-hashes-with-sp_help_revlogin` | ### Export SQL Server login password hashes with `sp_help_revlogin` | - | EXCLUDED | gcp-v3-03-recover-another-cloud-sql-login-by-exporting-and-cracking (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#execute-sql-through-the-data-api--cloudsqlinstancesexecutesql` | ### Execute SQL through the Data API — `cloudsql.instances.executeSql` | - | NON-PRIVESC | database data read |
| `#copy-current-or-historical-data-to-another-instance--clone-replica-or-restore` | ### Copy current or historical data to another instance — clone, replica, or restore | - | NON-PRIVESC | data copy |
| `#export-database-contents-through-the-instance-service-account--cloudsqlinstancesexport` | ### Export database contents through the instance service account — `cloudsql.instances.export` | - | NON-PRIVESC | data export |
| `#import-an-attacker-controlled-database-dump--cloudsqlinstancesimport` | ### Import an attacker-controlled database dump — `cloudsql.instances.import` | - | NON-PRIVESC | data tampering |
| `#weaken-transport-security-or-invalidate-client-certificates--cloudsqlinstancesupdate-cloudsqlinstancesresetsslconfig` | ### Weaken transport security or invalidate client certificates — `cloudsql.instances.update`, `cloudsql.instances.resetSslConfig` | - | NON-PRIVESC | transport security bypass |
| `#open-an-iam-authenticated-session-through-the-cloud-sql-auth-proxy` | ### Open an IAM-authenticated session through the Cloud SQL Auth Proxy | - | NON-PRIVESC | uses own identity |
| `#suppress-postgresql-engine-logging--cloudsqlinstancesupdate` | ### Suppress PostgreSQL engine logging — `cloudsql.instances.update` | - | NON-PRIVESC | telemetry tampering |
| `#destroy-data-or-weaken-recovery--delete-databases-backups-or-instances` | ### Destroy data or weaken recovery — delete databases, backups, or instances | - | NON-PRIVESC | DoS/deletion |
| `#disrupt-instance-availability--update-restart-failover-or-stop-a-replica` | ### Disrupt instance availability — update, restart, failover, or stop a replica | - | NON-PRIVESC | DoS |
| (structural) | 9 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-sql-post-exploitation`, `#cloud-sql`, `#credential-access`, `#data-export`, `#data-tampering`, `#security-control-bypass`, `#telemetry-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-support-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloudsupporttechcaseslist--get--mine-support-cases-and-incident-artifacts` | ### `cloudsupport.techCases.list` / `.get` — mine support cases and incident artifacts | - | NON-PRIVESC | support case data read |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-support-post-exploitation`, `#cloud-support`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cloud-tasks-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloudtaskstasksget--cloudtaskstaskslist--cloudtaskstasksfullview---harvest-secrets-from-queued-work` | ### `cloudtasks.tasks.get` \| `cloudtasks.tasks.list` (+ `cloudtasks.tasks.fullView`) - harvest secrets from queued work | - | NON-PRIVESC | secret read |
| `#cloudtaskstasksrun---replay-queued-work-on-demand` | ### `cloudtasks.tasks.run` - replay queued work on demand | - | NON-PRIVESC | replays existing tasks (X:excluded Run existing tasks) |
| `#cloudtaskstasksdelete---selectively-or-batch-delete-queued-work` | ### `cloudtasks.tasks.delete` - selectively or batch-delete queued work | - | NON-PRIVESC | DoS |
| `#cloudtasksqueuespurge--pause--delete---destroy-or-stall-queued-business-work` | ### `cloudtasks.queues.purge` / `.pause` / `.delete` - destroy or stall queued business work | - | NON-PRIVESC | DoS |
| `#cloudtasksqueuesupdate---retryrate-tampering-and-stealth-traffic-capture` | ### `cloudtasks.queues.update` - retry/rate tampering and stealth traffic capture | cloudtasks.queues.update | EXCLUDED | X: Queue retry/rate tampering and uriOverride traffic capture |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-tasks-post-exploitation`, `#cloud-tasks`, `#credential-access`, `#data-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-compliance-manager-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloudsecuritycomplianceframeworkdeploymentsdelete--cloudcontroldeploymentsdelete--update--tear-down-or-weaken-enforced-controls` | ### `cloudsecuritycompliance.frameworkDeployments.delete` / `cloudControlDeployments.delete` / `.update` — tear down or weaken enforced controls | - | NON-PRIVESC | security control teardown |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---compliance-manager-post-exploitation`, `#compliance-manager`, `#security-control-bypass`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-composer-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#export-dags-data-and-plugins` | ### Export DAGs, data, and plugins | - | NON-PRIVESC | DAG/data read |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---composer-post-exploitation`, `#composer`, `#data-export`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-compute-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#read-literal-configuration-from-compute-metadata` | ### Read literal configuration from Compute metadata | - | NON-PRIVESC | metadata secret read |
| `#computeinstancesgetguestattributes--read-guest-attributes-ssh-host-keys--bootstrap-secrets-without-ssh` | ### `compute.instances.getGuestAttributes` — read guest attributes (SSH host keys / bootstrap secrets) without SSH | - | NON-PRIVESC | guest attribute read |
| `#read-serial-console-output---computeinstancesgetserialportoutput` | ### Read serial-console output - `compute.instances.getSerialPortOutput` | - | NON-PRIVESC | serial output read |
| `#export--inspect-images-locally` | ### Export & Inspect Images locally | - | NON-PRIVESC | image data export |
| `#export--inspect-snapshots--disks-locally` | ### Export & Inspect Snapshots & Disks locally | - | NON-PRIVESC | disk data export |
| `#recover-deleted-standard-snapshots-before-expiry` | ### Recover deleted standard snapshots before expiry | - | NON-PRIVESC | data recovery/read |
| `#inspect-an-image-creating-a-vm` | ### Inspect an Image creating a VM | - | NON-PRIVESC | image data access |
| `#inspect-a-snapshotdisk-attaching-it-to-a-vm` | ### Inspect a Snapshot/Disk attaching it to a VM | - | NON-PRIVESC | disk data access |
| `#computesnapshotssetiampolicy--computeimagessetiampolicy--resource-level-exfil-share` | ### `compute.snapshots.setIamPolicy` / `compute.images.setIamPolicy` — resource-level exfil share | - | NON-PRIVESC | data exfil share |
| `#computepacketmirroringscreate--traffic-interception-by-passive-packet-mirroring` | ### `compute.packetMirrorings.create` — traffic interception by passive packet mirroring | - | NON-PRIVESC | traffic interception |
| `#computeroutescreate--next-hop-instance-route-hijack-active-in-path-mitm` | ### `compute.routes.create` — next-hop-instance route hijack (active in-path MITM) | - | NON-PRIVESC | network MITM |
| `#computeroutersupdate--bgp-advertised-route-tampering-dynamic-route-hijack--blackhole` | ### `compute.routers.update` — BGP advertised-route tampering (dynamic-route hijack / blackhole) | - | NON-PRIVESC | network hijack/DoS |
| `#computeurlmapsupdate--load-balancer-backend-hijack` | ### `compute.urlMaps.update` — load-balancer backend hijack | - | NON-PRIVESC | traffic redirection |
| `#computebackendbucketsupdate--computebackendservicesupdate--cloud-cdn-cache-poisoning--response-tamper` | ### `compute.backendBuckets.update` / `compute.backendServices.update` — Cloud CDN cache poisoning & response tamper | - | NON-PRIVESC | response tampering |
| `#computebackendbucketsaddsignedurlkey--computebackendservicesaddsignedurlkey--inject-a-cloud-cdn-signed-urlcookie-signing-key-access-control-bypass` | ### `compute.backendBuckets.addSignedUrlKey` / `compute.backendServices.addSignedUrlKey` — inject a Cloud CDN signed-URL/cookie signing key (access-control bypass) | - | NON-PRIVESC | CDN content access bypass |
| `#computeinstancesaddaccessconfig--expose-an-internal---no-address-vm-to-the-internet` | ### `compute.instances.addAccessConfig` — expose an internal (`--no-address`) VM to the internet | - | NON-PRIVESC | network exposure |
| `#computerouterscreate--computeroutersupdate--cloud-nat-outbound-egress-for-isolated-vms-stealthy-exfil--c2` | ### `compute.routers.create` + `compute.routers.update` — Cloud NAT outbound egress for isolated VMs (stealthy exfil / C2) | - | NON-PRIVESC | network egress |
| `#computeroutersupdate--private-nat-trusted-source-impersonation-ncchybrid-allowlist-bypass` | ### `compute.routers.update` — Private NAT trusted-source impersonation (NCC/hybrid allowlist bypass) | - | NON-PRIVESC | network allowlist bypass |
| `#computeinstancesupdatenetworkinterface--claim-unused-alias-ips-in-a-trusted-secondary-range` | ### `compute.instances.updateNetworkInterface` — claim unused alias IPs in a trusted secondary range | - | NON-PRIVESC | network allowlist bypass |
| `#computeinstancessetmetadata--computeprojectssetcommoninstancemetadata--interactive-serial-console-access-firewall--iap-bypass` | ### `compute.instances.setMetadata` / `compute.projects.setCommonInstanceMetadata` — interactive serial-console access (firewall / IAP bypass) | - | NON-PRIVESC | reachability; needs existing OS credential |
| `#computeinstancesupdateshieldedinstanceconfig--disable-secure-boot--integrity-monitoring-anti-forensics` | ### `compute.instances.updateShieldedInstanceConfig` — disable Secure Boot / Integrity Monitoring (anti-forensics) | - | NON-PRIVESC | anti-forensics |
| `#computesecuritypoliciesupdate--cloud-armor-wafdeny-bypass` | ### `compute.securityPolicies.update` — Cloud Armor WAF/deny bypass | - | NON-PRIVESC | WAF bypass |
| `#computesubnetworksupdate--disable-vpc-flow-logs-anti-forensics` | ### `compute.subnetworks.update` — disable VPC Flow Logs (anti-forensics) | - | NON-PRIVESC | telemetry tampering |
| `#networkmanagementvpcflowlogsconfigsdelete--update--disable-central-vpc-flow-logs-anti-forensics-separate-api` | ### `networkmanagement.vpcflowlogsconfigs.delete` / `.update` — disable *central* VPC Flow Logs (anti-forensics, separate API) | - | NON-PRIVESC | telemetry tampering |
| `#computeroutersupdate--disable-cloud-nat-logging-egress-monitoring-blind-spot` | ### `compute.routers.update` — disable Cloud NAT logging (egress-monitoring blind spot) | - | NON-PRIVESC | telemetry tampering |
| (structural) | 11 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---compute-post-exploitation`, `#compute`, `#credential-access`, `#data-export`, `#convenient-cli`, `#fallback-when-cli-discovery-is-denied`, `#traffic-interception--redirection`, `#data-tampering`, `#security-control-bypass`, `#telemetry-tampering`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-config-controller-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#kubernetes-secret-read--recover-credentials-supplied-to-or-generated-by-config-connector-and-config-sync` | ### Kubernetes Secret read — recover credentials supplied to or generated by Config Connector and Config Sync | - | NON-PRIVESC | existing secret read (KCC SA-key variant is X:excluded) |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---config-controller-post-exploitation`, `#config-controller--config-connector-kcc`, `#credential-access`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-contact-center-insights-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#read-stored-transcripts-and-analysis-results` | ### Read stored transcripts and analysis results | - | NON-PRIVESC | transcript data read |
| `#reuse-the-insights-service-agent-to-read-supported-cloud-storage-conversation-files` | ### Reuse the Insights service agent to read supported Cloud Storage conversation files | - | NON-PRIVESC | service-agent data read |
| `#export-the-corpus-to-a-cross-project-bigquery-table` | ### Export the corpus to a cross-project BigQuery table | - | NON-PRIVESC | data export |
| `#mint-bearer-urls-for-raw-conversation-audio` | ### Mint bearer URLs for raw conversation audio | - | NON-PRIVESC | audio data read |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---contact-center-insights-post-exploitation`, `#contact-center-ai-insights`, `#excluded-techniques`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-container-analysis-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#containeranalysisoccurrenceslist--get--recover-software-supply-chain-metadata` | ### `containeranalysis.occurrences.list` / `.get` — recover software-supply-chain metadata | - | NON-PRIVESC | supply-chain metadata read |
| `#occurrencescreate--notesattachoccurrence--a-registered-signing-key--authorize-a-chosen-digest` | ### `occurrences.create` + `notes.attachOccurrence` + a registered signing key — authorize a chosen digest | - | NON-PRIVESC | admission bypass only; deploy separate |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---container-analysis-post-exploitation`, `#container-analysis--artifact-analysis`, `#data-export`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-cx-agent-studio-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cesconversationslistget--harvest-transcripts-and-tool-traces` | ### `ces.conversations.list/get` — harvest transcripts and tool traces | - | NON-PRIVESC | transcript data read |
| `#cesguardrailsupdatedelete--weaken-application-safety-controls` | ### `ces.guardrails.update/delete` — weaken application safety controls | - | NON-PRIVESC | app safety control bypass |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cx-agent-studio-post-exploitation`, `#cx-agent-studio`, `#data-export`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-data-fusion-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#datafusionsecurekeysgetsecret--read-a-namespace-secure-store-value` | ### `datafusion.secureKeys.getSecret` — read a namespace secure-store value | - | NON-PRIVESC | stored secret read |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---data-fusion-post-exploitation`, `#data-fusion`, `#credential-access`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-database-center-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#databasecenterlist--mine-the-database-fleet-and-its-weaknesses` | ### `databasecenter.*.list` — mine the database fleet and its weaknesses | - | NON-PRIVESC | recon |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---database-center-post-exploitation`, `#database-center`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-database-insights-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#databaseinsightsfetchquery--mine-sql-workload-and-schema-intelligence` | ### `databaseinsights.*.fetch/query` — mine SQL workload and schema intelligence | - | NON-PRIVESC | recon |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---database-insights-post-exploitation`, `#database-insights`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-dataflow-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#no-separate-dataflow-post-exploitation-primitive-is-retained` | ### No separate Dataflow post-exploitation primitive is retained | - | NON-PRIVESC | points to dataflow privesc page |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dataflow-post-exploitation`, `#dataflow`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-dataproc-metastore-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#query-the-backend-catalog-with-sql` | ### Query the backend catalog with SQL | - | NON-PRIVESC | catalog metadata read |
| `#export-the-metadata-catalog-to-cloud-storage` | ### Export the metadata catalog to Cloud Storage | - | NON-PRIVESC | catalog metadata export |
| `#overwrite-the-catalog-through-import-or-restore` | ### Overwrite the catalog through import or restore | - | NON-PRIVESC | catalog data tampering |
| `#repoint-a-database-table-or-partition-location` | ### Repoint a database, table, or partition location | - | NON-PRIVESC | catalog data tampering |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dataproc-metastore-post-exploitation`, `#dataproc-metastore`, `#data-export`, `#data-tampering`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-dataproc-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#dataprocclustersjobsbatchessessionslistget--harvest-workload-identities-code-and-execution-metadata` | ### `dataproc.{clusters,jobs,batches,sessions}.list/get` — harvest workload identities, code and execution metadata | - | NON-PRIVESC | config/metadata read |
| `#suppress-in-vm-logging-and-monitoring-via---properties` | ### Suppress in-VM logging and monitoring via `--properties` | - | NON-PRIVESC | telemetry tampering (create+actAs is gcp-dataproc-*) |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dataproc-post-exploitation`, `#dataproc`, `#data-export`, `#telemetry-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-datastream-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#datastreamconnectionprofilesdiscover--live-source-db-schema-recon-read-only-role-reaches-it` | #### `datastream.connectionProfiles.discover` — live source-DB schema recon (read-only role reaches it) | - | NON-PRIVESC | recon |
| `#datastreamobjectsstartbackfilljob--copy-selected-source-rows-through-an-existing-stream` | #### `datastream.objects.startBackfillJob` — copy selected source rows through an existing stream | - | NON-PRIVESC | data copy |
| `#datastreamstreamspause--resume--delete--disrupt-or-stop-replication` | ### `datastream.streams.pause` / `.resume` / `.delete` — disrupt or stop replication | - | NON-PRIVESC | DoS |
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---datastream-post-exploitation`, `#datastream`, `#data-export`, `#active-source-reconnaissance`, `#targeted-historical-data-copy`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-deployment-manager-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#deploymentmanagermanifestsget--discovery-permissions--recover-configuration-and-unredacted-credentials` | ### `deploymentmanager.manifests.get` (+ discovery permissions) — recover configuration and unredacted credentials | - | NON-PRIVESC | manifest secret read<br>`gcp-pa-s03-1-deploymentmanager` — conditional verified exact-target authority. |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---deployment-manager-post-exploitation`, `#deployment-manager`, `#credential-access`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-developer-connect-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#developerconnectusersfetchaccesstoken---recover-the-callers-own-linked-oauth-token` | ### `developerconnect.users.fetchAccessToken` - recover the caller's own linked OAuth token | - | NON-PRIVESC | caller's own OAuth token |
| `#developerconnectgitrepositorylinksfetchreadtoken---export-a-linked-repository-read-credential` | ### `developerconnect.gitRepositoryLinks.fetchReadToken` - export a linked repository read credential | - | NON-PRIVESC | repo read credential |
| `#developerconnectgitrepositorylinksfetchreadwritetoken---export-a-provider-write-credential` | ### `developerconnect.gitRepositoryLinks.fetchReadWriteToken` - export a provider write credential | developerconnect.gitRepositoryLinks.fetchReadWriteToken | EXCLUDED | X: developerconnect.gitRepositoryLinks.fetchReadWriteToken - export a provider write credential |
| `#use-an-enabled-system-git-proxy-to-read-or-modify-a-linked-repository` | ### Use an enabled system Git proxy to read or modify a linked repository | developerconnect.gitRepositoryLinks.gitProxyRead + developerconnect.gitRepositoryLinks.gitProxyWrite (roles/developerconnect.gitProxyUser; also in Developer Con | COVERED | `gcp-developerconnect-readwrite-token-pipeline-poison` |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---developer-connect-post-exploitation`, `#developer-connect`, `#credential-access`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-dialogflow-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#dialogflowwebhooksupdate--redirect-retained-external-authentication-material` | ### `dialogflow.webhooks.update` — redirect retained external authentication material | - | NON-PRIVESC | external credential capture, no GCP SA<br>`gcp-pa-s03-4-dialogflow` — conditional verified exact-target authority. |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dialogflow-cx-post-exploitation`, `#dialogflow-cx`, `#traffic-interception--redirection`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-discovery-engine-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#discoveryengineservingconfigssearch--read-a-periodic-bigquery-copy-whose-imported-acls-are-not-enforced` | ### `discoveryengine.servingConfigs.search` — Read a Periodic BigQuery Copy Whose Imported ACLs Are Not Enforced | - | NON-PRIVESC | indexed data read |
| `#data-plane-read--search--grounded-answers-leak-indexed-content-rolesdiscoveryengineviewer` | ### Data-plane read — search & grounded answers leak indexed content (`roles/discoveryengine.viewer`) | - | NON-PRIVESC | indexed data read |
| `#documentsimport--gcs--bigquery-confused-deputy-read-any-datastore--exfil` | ### `documents:import` — GCS / BigQuery confused-deputy (read-any-datastore → exfil) | - | NON-PRIVESC | service-agent confused-deputy data read |
| `#availability--dos` | ### Availability / DoS | - | NON-PRIVESC | DoS |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---gemini-enterprise--discovery-engine-post-exploitation`, `#vertex-ai-search-discovery-engine`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-dlp-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#read-jobs-templates-triggers-and-data-profiles--map-sensitive-data` | ### Read jobs, templates, triggers, and data profiles — map sensitive data | - | NON-PRIVESC | recon |
| `#dlpdeidentifytemplatesget--reuse-a-reversible-template-to-reverse-tokens` | ### `dlp.deidentifyTemplates.get` — reuse a reversible template to reverse tokens | - | NON-PRIVESC | data re-identification |
| `#dlpjobscreate--read-through-the-dlp-service-agent-and-export-quoted-findings` | ### `dlp.jobs.create` — read through the DLP service agent and export quoted findings | - | NON-PRIVESC | service-agent confused-deputy data read |
| `#dlpcontentpoliciesupdate--turn-gemini-enterprise-sensitive-content-gates-into-allow-rules` | #### `dlp.contentPolicies.update` — turn Gemini Enterprise sensitive-content gates into allow rules | - | NON-PRIVESC | security control bypass |
| `#dlpdeidentifytemplatesupdate--make-a-shared-transform-pass-sensitive-values-through` | #### `dlp.deidentifyTemplates.update` — make a shared transform pass sensitive values through | - | NON-PRIVESC | data masking bypass |
| `#dlpinspecttemplatesupdate--blind-template-driven-inspection` | ### `dlp.inspectTemplates.update` — blind template-driven inspection | - | NON-PRIVESC | detection evasion |
| (structural) | 9 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---sensitive-data-protection-dlp-post-exploitation`, `#sensitive-data-protection-dlp`, `#rejected-as-a-standalone-technique`, `#data-export`, `#security-control-bypass`, `#configuration-tampering`, `#telemetry-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-document-ai-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#documentaidatasetslistdocuments--documentaidatasetsgetdocuments---extract-stored-dataset-documents` | ### `documentai.datasets.listDocuments` + `documentai.datasets.getDocuments` - extract stored dataset documents | - | NON-PRIVESC | document data read |
| `#documentaiprocessorversionscreate---copy-a-trusted-source-processor-version-cross-project` | ### `documentai.processorVersions.create` - copy a trusted source processor version cross-project | - | NON-PRIVESC | model copy via standing trust |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---document-ai-post-exploitation`, `#document-ai`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-eventarc-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#eventarctriggersupdate--redirect-an-existing-standard-event-stream` | ### `eventarc.triggers.update` — redirect an existing Standard event stream | - | NON-PRIVESC | event data redirection |
| `#eventarcenrollmentsupdate--redirect-or-broaden-an-advanced-bus-subscription` | ### `eventarc.enrollments.update` — redirect or broaden an Advanced bus subscription | - | NON-PRIVESC | event data redirection |
| `#eventarctriggerscreate--copy-future-event-payloads-to-an-attacker-controlled-destination` | ### `eventarc.triggers.create` — copy future event payloads to an attacker-controlled destination | - | NON-PRIVESC | event data exfil |
| `#eventarcmessagebusespublish--channelspublish--channelconnectionspublish--inject-attacker-chosen-events` | ### `eventarc.messageBuses.publish` / `channels.publish` / `channelConnections.publish` — inject attacker-chosen events | - | NON-PRIVESC | event injection, app-dependent |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---eventarc-post-exploitation`, `#eventarc`, `#traffic-interception--redirection`, `#data-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-filestore-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#mount-a-reachable-filestore-share` | ### Mount a reachable Filestore share | - | NON-PRIVESC | data read/exfil |
| `#clone-a-share-through-a-standard-backup` | ### Clone a share through a standard backup | - | NON-PRIVESC | data read/exfil |
| `#widen-nfs-export-access---fileinstancesupdate` | ### Widen NFS export access - `file.instances.update` | - | NON-PRIVESC | NFS export widening (data exposure) |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---filestore-post-exploitation`, `#filestore`, `#data-export`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-firebase-data-connect-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#connectorsimpersonatequery--impersonatemutation--run-operations-as-any-end-user` | ### `connectors.impersonateQuery` / `.impersonateMutation` — run operations as any end-user | - | NON-PRIVESC | app end-user impersonation, not GCP principal |
| `#servicesexecutegraphql--admin-graphql--full-data-readwrite-bypassing-auth` | ### `services.executeGraphql` — admin GraphQL → full data read/write, bypassing `@auth` | - | NON-PRIVESC | DB data read/write |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---firebase-data-connect-post-exploitation`, `#firebase-data-connect`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-firestore-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#datastoredatabasesexport--bulk-data-exfiltration-incl-cross-project-confused-deputy` | ### `datastore.databases.export` — bulk data exfiltration (incl. cross-project confused deputy) | - | NON-PRIVESC | data read/exfil |
| `#datastoredatabasesclone--pitr-snapshot-clone-into-an-attacker-controlled-database-acl-bypass-exfil` | ### `datastore.databases.clone` — PITR-snapshot clone into an attacker-controlled database (ACL-bypass exfil) | - | NON-PRIVESC | data read/exfil |
| `#datastoredatabasesimport--data-tampering--privileged-entity-injection` | ### `datastore.databases.import` — data tampering / privileged-entity injection | - | NON-PRIVESC | data/config tampering |
| `#datastoreentitiesgetlist--firestore-security-rules-are-bypassed-by-any-iam-principal` | ### `datastore.entities.get`/`list` — Firestore **security rules are bypassed** by any IAM principal | - | NON-PRIVESC | data read bypassing rules |
| `#datastoredatabasesdelete--irreversible-database-dos` | ### `datastore.databases.delete` — irreversible database DoS | - | NON-PRIVESC | DoS/destruction |
| `#datastoredatabasesupdate--disable-delete-protection--pitr-defense-evasion-precursor` | ### `datastore.databases.update` — disable delete-protection / PITR (defense-evasion precursor) | - | NON-PRIVESC | defense evasion / DoS precursor |
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---firestore-post-exploitation`, `#firestore`, `#data-export`, `#data-tampering`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-gemini-cloud-assist-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#geminicloudassistinvestigationsrevisionsgetlist--harvest-troubleshooting-evidence-and-history` | ### `geminicloudassist.investigations/revisions.get/list` — harvest troubleshooting evidence and history | - | NON-PRIVESC | data read/exfil |
| `#rolesgeminicloudassistuser--read-objects-from-known-cloud-storage-buckets` | ### `roles/geminicloudassist.user` — read objects from known Cloud Storage buckets | - | NON-PRIVESC | data read/exfil |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---gemini-cloud-assist-post-exploitation`, `#gemini-cloud-assist`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-gke-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#pull-an-accessible-container-image-for-local-inspection` | ### Pull an accessible container image for local inspection | - | NON-PRIVESC | image data read |
| `#containerclustersupdate--disable-gke-loggingmonitoring-components-anti-forensics` | ### `container.clusters.update` — disable GKE logging/monitoring components (anti-forensics) | - | NON-PRIVESC | logging/defense evasion |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---gke-post-exploitation`, `#google-kubernetes-engine-gke`, `#data-export`, `#telemetry-tampering`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-google-secops-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#chronicleeventsudmsearch--chronicleeventssearchrawlogs--search-accessible-telemetry-for-secrets-and-topology` | ### `chronicle.events.udmSearch` / `chronicle.events.searchRawLogs` — search accessible telemetry for secrets and topology | - | NON-PRIVESC | credential/secret disclosure (data) |
| `#chroniclereferencelistsupdate--chronicledatatablerowscreate--poison-rule-lookup-data` | ### `chronicle.referenceLists.update` / `chronicle.dataTableRows.create` — poison rule lookup data | - | NON-PRIVESC | data/config tampering |
| `#chroniclecasesclose--close-active-soar-cases-as-not-malicious` | ### `chronicle.cases.close` — close active SOAR cases as not malicious | - | NON-PRIVESC | logging/defense evasion |
| `#chroniclefeedsdisable--archive-a-feed-and-stop-its-ingestion` | ### `chronicle.feeds.disable` — archive a feed and stop its ingestion | - | NON-PRIVESC | logging/defense evasion |
| `#chronicleruledeploymentsupdate--stop-a-rule-or-stop-promoting-its-detections-to-alerts` | ### `chronicle.ruleDeployments.update` — stop a rule or stop promoting its detections to alerts | - | NON-PRIVESC | logging/defense evasion |
| `#chroniclerulesupdate--introduce-an-exclusion-into-detection-logic` | ### `chronicle.rules.update` — introduce an exclusion into detection logic | - | NON-PRIVESC | logging/defense evasion |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---google-secops-chronicle-post-exploitation`, `#google-secops-chronicle`, `#credential-access`, `#data-tampering`, `#telemetry-tampering`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-healthcare-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#read-or-alter-fhir-resources-through-the-fhir-rest-api` | ### Read or alter FHIR resources through the FHIR REST API | - | NON-PRIVESC | data read/exfil |
| `#export-a-complete-or-targeted-store-through-the-healthcare-service-agent` | ### Export a complete or targeted store through the Healthcare service agent | - | NON-PRIVESC | data read/exfil |
| `#healthcaredatasetsdeidentify--stage-a-transformed-copy-without-source-record-read-permissions` | ### `healthcare.datasets.deidentify` — stage a transformed copy without source record-read permissions | - | NON-PRIVESC | data read/exfil |
| `#read-or-inject-hl7v2-clinical-messages` | ### Read or inject HL7v2 clinical messages | - | NON-PRIVESC | data/config tampering |
| `#read-or-inject-dicom-instances-through-dicomweb` | ### Read or inject DICOM instances through DICOMweb | - | NON-PRIVESC | data/config tampering |
| `#bulk-import-attacker-controlled-fhir-dicom-or-hl7v2-data` | ### Bulk-import attacker-controlled FHIR, DICOM, or HL7v2 data | - | NON-PRIVESC | data/config tampering |
| `#healthcarefhirstoresupdate--disable-fhir-consent-enforcement` | ### `healthcare.fhirStores.update` — disable FHIR consent enforcement | - | NON-PRIVESC | control weakening / defense evasion |
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-healthcare-post-exploitation`, `#cloud-healthcare-api`, `#data-export`, `#data-tampering`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-iam-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---iam-post-exploitation`, `#iam`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-ids-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#network-security-integration--attacker-controlled-traffic-inspection` | ### Network Security Integration — attacker-controlled traffic inspection | - | NON-PRIVESC | network traffic interception only |
| `#route-selected-vpc-flows-through-an-attacker-controlled-intercept-service` | #### Route selected VPC flows through an attacker-controlled intercept service | - | NON-PRIVESC | network/traffic interception only |
| `#mirror-selected-vpc-traffic-to-an-attacker-controlled-collector-through-nsi` | #### Mirror selected VPC traffic to an attacker-controlled collector through NSI | - | NON-PRIVESC | network/traffic interception only |
| `#override-ngfw-threat-actions-to-allow` | ### Override NGFW threat actions to `ALLOW` | - | NON-PRIVESC | control weakening / defense evasion |
| `#add-cloud-ids-threat-exceptions-to-suppress-selected-signatures` | ### Add Cloud IDS threat exceptions to suppress selected signatures | - | NON-PRIVESC | logging/defense evasion |
| `#exclude-an-attacker-used-vpc-from-dns-threat-detection` | ### Exclude an attacker-used VPC from DNS Threat Detection | - | NON-PRIVESC | logging/defense evasion |
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-ids-and-network-inspection-post-exploitation`, `#cloud-ids`, `#traffic-interception--redirection`, `#security-control-bypass`, `#telemetry-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-integration-connectors-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#rolesconnectorsinvoker--rolesconnectorslistener--use-a-connections-stored-credentials` | ### `roles/connectors.invoker` / `roles/connectors.listener` — use a connection's stored credentials | - | NON-PRIVESC | backend creds used for data, no GCP principal |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---integration-connectors-post-exploitation`, `#integration-connectors`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-kms-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloudkmscryptokeyversionsusetoverify` | ### `cloudkms.cryptoKeyVersions.useToVerify` | - | NON-PRIVESC | verify oracle / recon |
| `#cloudkmscryptokeyversionsusetodecapsulate--post-quantum-kem-decrypt-oracle` | ### `cloudkms.cryptoKeyVersions.useToDecapsulate` — post-quantum KEM decrypt oracle | - | NON-PRIVESC | decrypt oracle (data) |
| `#cloudkmscryptokeyversionsrestore` | ### `cloudkms.cryptoKeyVersions.restore` | - | NON-PRIVESC | key restore (data/recovery) |
| `#cloudkmscryptokeyversionsusetoencrypt--cloudkmscryptokeyversionsusetoencryptviadelegation` | ### `cloudkms.cryptoKeyVersions.useToEncrypt` \| `cloudkms.cryptoKeyVersions.useToEncryptViaDelegation` | - | NON-PRIVESC | ciphertext forgery (data) |
| `#cloudkmscryptokeyversionsusetosign` | ### `cloudkms.cryptoKeyVersions.useToSign` | - | NON-PRIVESC | signature forgery (relying-party integrity) |
| `#signature--jwt--oidc-forgery-with-only-usetosign` | #### Signature / JWT / OIDC forgery with only `useToSign` | - | EXCLUDED | gcp-v3-43-kms-usetosign-on-a-key-that-backs-a-trusted-jwt-oidc-issue (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#usetosign-on-mac--hmac-keys--forge-hmacs` | #### `useToSign` on MAC / HMAC keys — forge HMACs | - | EXCLUDED | gcp-v3-04-forge-an-application-session-or-api-identity-with-a-kms-ma (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#cloudkmscryptokeyversionsdestroy` | ### `cloudkms.cryptoKeyVersions.destroy` | - | NON-PRIVESC | DoS/destruction |
| `#kms-ransomware` | ### KMS Ransomware | - | NON-PRIVESC | ransomware / DoS |
| `#here-are-the-steps-to-import-a-new-version-and-disabledelete-the-older-data` | #### Here are the steps to import a new version and disable/delete the older data: | - | NON-PRIVESC | ransomware procedure (DoS) |
| `#cloudkmscryptokeyversionsupdate` | ### `cloudkms.cryptoKeyVersions.update` | - | NON-PRIVESC | key disable DoS |
| `#cloudkmscryptokeysupdate--key-access-justifications-zero-access-reasons-lockout-silent-to-version-monitoring-dos` | ### `cloudkms.cryptoKeys.update` — Key Access Justifications "zero access reasons" lockout (silent-to-version-monitoring DoS) | - | NON-PRIVESC | DoS/destruction |
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---kms-post-exploitation`, `#kms`, `#credential-access`, `#data-export`, `#data-tampering`, `#dosbreak`, `#cloud-storage--cmek-permission-model`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-live-stream-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#livestreamchannelsget--recover-an-rtmp-distribution-stream-key` | ### `livestream.channels.get` — recover an RTMP distribution stream key | - | NON-PRIVESC | third-party stream key (data) |
| `#livestreamassetscreate--livestreameventscreate--re-host-service-agent-readable-media` | ### `livestream.assets.create` + `livestream.events.create` — re-host service-agent-readable media | - | NON-PRIVESC | data read/exfil |
| `#livestreaminputsget--inject-content-through-a-disclosed-input-uri` | ### `livestream.inputs.get` — inject content through a disclosed input URI | - | NON-PRIVESC | media content injection |
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---live-stream-post-exploitation`, `#live-stream`, `#credential-access`, `#data-export`, `#data-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-logging-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#read-log-entries--logginglogentrieslist-and-loggingviewsaccess` | ### Read log entries — `logging.logEntries.list` and `logging.views.access` | - | NON-PRIVESC | data read/exfil |
| `#copy-historical-logs-to-cloud-storage--loggingbucketscopylogentries` | ### Copy historical logs to Cloud Storage — `logging.buckets.copyLogEntries` | - | NON-PRIVESC | data read/exfil |
| `#create-a-linked-bigquery-dataset--logginglinkscreate` | ### Create a linked BigQuery dataset — `logging.links.create` | - | NON-PRIVESC | data read/exfil |
| `#change-access-to-a-log-view--loggingviewssetiampolicy` | ### Change access to a log view — `logging.views.setIamPolicy` | - | NON-PRIVESC | grants log-view read only |
| `#exempt-a-principal-from-data-access-audit-logs` | ### Exempt a principal from Data Access audit logs | - | NON-PRIVESC | audit-log evasion (perms already privesc-modeled by gcp-resourcemanager-*-setiampolicy) |
| `#forge-log-entries--logginglogentriescreate` | ### Forge log entries — `logging.logEntries.create` | - | NON-PRIVESC | logging/defense evasion |
| `#blind-a-custom-log-view--loggingviewsupdate` | ### Blind a custom log view — `logging.views.update` | - | NON-PRIVESC | logging/defense evasion |
| `#change-a-log-based-metric--logginglogmetricsupdate` | ### Change a log-based metric — `logging.logMetrics.update` | - | NON-PRIVESC | logging/defense evasion |
| `#poison-defaults-for-future-projects-and-folders--loggingsettingsupdate` | ### Poison defaults for future projects and folders — `logging.settings.update` | - | NON-PRIVESC | logging/defense evasion |
| `#delete-a-log-from-_default--logginglogsdelete` | ### Delete a log from `_Default` — `logging.logs.delete` | - | NON-PRIVESC | logging/defense evasion |
| `#delete-a-log-bucket--loggingbucketsdelete` | ### Delete a log bucket — `logging.buckets.delete` | - | NON-PRIVESC | logging/defense evasion |
| `#delete-a-linked-bigquery-dataset--logginglinksdelete` | ### Delete a linked BigQuery dataset — `logging.links.delete` | - | NON-PRIVESC | logging/defense evasion |
| `#delete-a-custom-log-view--loggingviewsdelete` | ### Delete a custom log view — `logging.views.delete` | - | NON-PRIVESC | logging/defense evasion |
| `#delete-a-log-based-metric--logginglogmetricsdelete` | ### Delete a log-based metric — `logging.logMetrics.delete` | - | NON-PRIVESC | logging/defense evasion |
| `#delete-a-log-sink--loggingsinksdelete` | ### Delete a log sink — `logging.sinks.delete` | - | NON-PRIVESC | logging/defense evasion |
| `#alter-retention-lock-fields-or-cmek--loggingbucketsupdate` | ### Alter retention, lock, fields, or CMEK — `logging.buckets.update` | - | NON-PRIVESC | logging/defense evasion |
| `#disable-exclude-or-redirect-routing--loggingsinksupdate-and-loggingexclusions` | ### Disable, exclude, or redirect routing — `logging.sinks.update` and `logging.exclusions.*` | - | NON-PRIVESC | logging/defense evasion |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---logging-post-exploitation`, `#logging`, `#data-export`, `#security-control-bypass`, `#telemetry-tampering`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-looker-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#sql-runner--issue-raw-sql-through-an-allowed-connection` | ### SQL Runner — issue raw SQL through an allowed connection | - | NON-PRIVESC | data read/exfil |
| `#lookerinstancesexport--export-instance-data-to-controlled-storage-and-kms-resources` | ### `looker.instances.export` — export instance data to controlled Storage and KMS resources | - | NON-PRIVESC | data read/exfil |
| `#looker-application-queries-and-downloads--exfiltrate-authorized-model-and-saved-content-data` | ### Looker application queries and downloads — exfiltrate authorized model and saved-content data | - | NON-PRIVESC | data read/exfil |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---looker-post-exploitation`, `#looker`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-managed-flink-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#managedflinkjobscreate--execute-an-attacker-jarpython-job-as-the-workload-identity` | ### `managedflink.jobs.create` — execute an attacker JAR/Python job as the workload identity | managedflink.jobs.create | EXCLUDED | `gcp-managedflink-jobs-create-actas` — no verified caller-to-workload-identity gain |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---managed-flink-post-exploitation`, `#managed-flink`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-managed-kafka-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#managedkafkaclustersconnect-plus-kafka-read-acls---consume-topic-data` | ### `managedkafka.clusters.connect` plus Kafka `READ` ACLs - consume topic data | - | NON-PRIVESC | data read/exfil |
| `#managedkafkaconnectorscreate--update---stream-a-topic-to-an-attacker-controlled-sink` | ### `managedkafka.connectors.create` / `.update` - stream a topic to an attacker-controlled sink | - | NON-PRIVESC | network/traffic interception only |
| `#managedkafkaclustersconnect-plus-kafka-write-acls---inject-records` | ### `managedkafka.clusters.connect` plus Kafka `WRITE` ACLs - inject records | - | NON-PRIVESC | data/config tampering |
| `#managedkafkatopicsupdate--delete-or-broker-topic-acls---expire-or-destroy-topic-data` | ### `managedkafka.topics.update` / `.delete` or broker topic ACLs - expire or destroy topic data | - | NON-PRIVESC | DoS/destruction |
| `#managedkafkaconsumergroupsupdate--delete---rewind-skip-or-erase-committed-offsets` | ### `managedkafka.consumerGroups.update` / `.delete` - rewind, skip, or erase committed offsets | - | NON-PRIVESC | DoS/destruction |
| `#managedkafkasubjectsdelete--versionsdelete---disrupt-schema-registry-clients` | ### `managedkafka.subjects.delete` / `versions.delete` - disrupt Schema Registry clients | - | NON-PRIVESC | DoS/destruction |
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---managed-kafka-post-exploitation`, `#managed-kafka`, `#data-export`, `#traffic-interception--redirection`, `#data-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-managed-microsoft-ad-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#managedidentitiesdomainsresetpassword--obtain-the-delegated-administrator-credential` | ### `managedidentities.domains.resetpassword` — obtain the delegated administrator credential | managedidentities.domains.resetpassword | EXCLUDED | X: Reset the Managed Microsoft AD delegated administrator password |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---managed-microsoft-ad-post-exploitation`, `#managed-microsoft-ad`, `#credential-access`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-memorystore-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#redis-auth-credential-disclosure---redisinstancesgetauthstring` | ### Redis AUTH credential disclosure - `redis.instances.getAuthString` | - | NON-PRIVESC | credential/secret disclosure (data) |
| `#redis-cluster--data-plane-takeover-via-managed-token-auth-users---redisclustersconnect` | ### Redis Cluster — data-plane takeover via managed token-auth users - `redis.clusters.connect` | - | NON-PRIVESC | Redis data-plane access only |
| `#data-exfiltration-via-rdb-export---redisinstancesexport` | ### Data exfiltration via RDB export - `redis.instances.export` | - | NON-PRIVESC | data read/exfil |
| `#redis-cluster--second-rdb-to-gcs-exfil-path-via-backup--export` | ### Redis Cluster — second RDB-to-GCS exfil path via backup → export | - | NON-PRIVESC | data read/exfil |
| `#redis-clusterinstance-dos--acl-tamper` | ### Redis Cluster/instance DoS & ACL tamper | - | NON-PRIVESC | DoS/destruction |
| `#config-tamper--its-limits---redisinstancesupdate` | ### Config tamper & its limits - `redis.instances.update` | - | NON-PRIVESC | DoS/destruction |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---memorystore-post-exploitation`, `#memorystore`, `#credential-access`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-model-armor-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#modelarmorfloorsettingsupdate--disable-orgfolderproject-wide-llm-safety-enforcement` | ### `modelarmor.floorSettings.update` — disable org/folder/project-wide LLM safety enforcement | - | NON-PRIVESC | control weakening / defense evasion |
| `#modelarmortemplatesupdate--install-catch-all-exclusions-that-return-no_match_found` | ### `modelarmor.templates.update` — install catch-all exclusions that return `NO_MATCH_FOUND` | - | NON-PRIVESC | control weakening / defense evasion |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---model-armor-post-exploitation`, `#model-armor`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-monitoring-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#monitoringtimeserieslist--monitoringmetricdescriptorslist--telemetry-reconnaissance` | ### `monitoring.timeSeries.list` / `monitoring.metricDescriptors.list` — telemetry reconnaissance | - | NON-PRIVESC | telemetry recon |
| `#monitoringalertslistget--mine-current-and-historical-policy-violations` | ### `monitoring.alerts.list/get` — mine current and historical policy violations | - | NON-PRIVESC | data read/exfil |
| `#monitoringtimeseriescreate--forge-user-defined-telemetry` | ### `monitoring.timeSeries.create` — forge user-defined telemetry | - | NON-PRIVESC | logging/defense evasion |
| `#monitoringuptimecheckconfigsupdate--weaken-content-and-status-validation` | ### `monitoring.uptimeCheckConfigs.update` — weaken content and status validation | - | NON-PRIVESC | logging/defense evasion |
| `#monitoringmetricdescriptorsdelete--disable-a-user-defined-metric` | ### `monitoring.metricDescriptors.delete` — disable a user-defined metric | - | NON-PRIVESC | logging/defense evasion |
| `#monitoringdashboardsupdate--delete--visual-blinding` | ### `monitoring.dashboards.update` / `.delete` — visual blinding | - | NON-PRIVESC | logging/defense evasion |
| `#monitoringnotificationchannelsupdate--delete--stop-alert-delivery` | ### `monitoring.notificationChannels.update` / `.delete` — stop alert delivery | - | NON-PRIVESC | logging/defense evasion |
| `#monitoringalertpoliciesupdate--delete--disable-or-remove-detections` | ### `monitoring.alertPolicies.update` / `.delete` — disable or remove detections | - | NON-PRIVESC | logging/defense evasion |
| `#monitoringslosupdate--delete--weaken-slo-and-burn-rate-monitoring` | ### `monitoring.slos.update` / `.delete` — weaken SLO and burn-rate monitoring | - | NON-PRIVESC | logging/defense evasion |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---monitoring-post-exploitation`, `#monitoring`, `#data-export`, `#telemetry-tampering`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-netapp-volumes-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#netappvolumescreate--clone-data-from-a-snapshot-or-backup` | ### `netapp.volumes.create` — clone data from a snapshot or backup | - | NON-PRIVESC | data read/exfil |
| `#netappontap--use-the-filtered-ontap-management-proxy` | ### `netapp.ontap.*` — use the filtered ONTAP management proxy | - | NON-PRIVESC | data/config tampering |
| `#netappvolumesupdate--expose-an-nfs-volume-to-an-attacker-controlled-client-range` | ### `netapp.volumes.update` — expose an NFS volume to an attacker-controlled client range | - | NON-PRIVESC | control weakening / defense evasion |
| `#netappvolumesdelete--snapshotsdelete--backupsdelete--destroy-data-and-recovery-points` | ### `netapp.volumes.delete` / `snapshots.delete` / `backups.delete` — destroy data and recovery points | - | NON-PRIVESC | DoS/destruction |
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---netapp-volumes-post-exploitation`, `#netapp-volumes`, `#data-export`, `#data-tampering`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-network-intelligence-center-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#networkmanagementconnectivitytestslistgetcreatererun--recover-or-generate-internal-path-traces` | ### `networkmanagement.connectivitytests.list/get/create/rerun` — recover or generate internal path traces | - | NON-PRIVESC | network recon |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---network-intelligence-center-post-exploitation`, `#network-intelligence-center`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-observability-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloudtracetraceslistget-or-observabilityviewsaccess--mine-trace-spans-for-credentials-and-internal-architecture` | ### `cloudtrace.traces.list/get` or `observability.views.access` — mine trace spans for credentials and internal architecture | - | NON-PRIVESC | credential/secret disclosure (data) |
| `#observabilitylinkscreate--bigquery-read-permissions--expose-trace-storage-through-bigquery-iam` | ### `observability.links.create` + BigQuery read permissions — expose trace storage through BigQuery IAM | - | NON-PRIVESC | data read/exfil |
| `#errorreportinggroupslist--errorreportingerroreventslist--mine-stack-traces-and-request-context` | ### `errorreporting.groups.list` / `errorreporting.errorEvents.list` — mine stack traces and request context | - | NON-PRIVESC | data read/exfil |
| `#errorreportingerroreventscreate-or-cloudtracetracespatch--inject-misleading-telemetry` | ### `errorreporting.errorEvents.create` or `cloudtrace.traces.patch` — inject misleading telemetry | - | NON-PRIVESC | logging/defense evasion |
| `#error-reporting-group-mutation-and-event-deletion--suppress-or-erase-error-evidence` | ### Error Reporting group mutation and event deletion — suppress or erase error evidence | - | NON-PRIVESC | logging/defense evasion |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---observability-post-exploitation`, `#observability`, `#credential-access`, `#data-export`, `#telemetry-tampering`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-oracle-database-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#oracledatabaseautonomousdatabasesgeneratewallet--pull-the-connection-wallet--full-db-access` | ### `oracledatabase.autonomousDatabases.generateWallet` — pull the connection wallet → full DB access | - | NON-PRIVESC | credential/secret disclosure (data) |
| `#oracledatabaseautonomousdatabasesclone--restore--offline-copy-exfil` | ### `oracledatabase.autonomousDatabases.clone` / `.restore` — offline copy exfil | - | NON-PRIVESC | data read/exfil |
| `#availability-tampering--failover--switchover--stop--delete` | ### Availability tampering — `failover` / `switchover` / `stop` / `delete` | - | NON-PRIVESC | DoS/destruction |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---oracle-databasegoogle-cloud-post-exploitation`, `#oracle-databasegoogle-cloud`, `#credential-access`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-pam-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#entitlement--grant-enumeration--jit-privilege-escalation-graph` | ### Entitlement & grant enumeration → JIT privilege-escalation graph | - | NON-PRIVESC | recon of PAM entitlements |
| `#revoke-active-grants-anti-ir--targeted-dos` | ### Revoke active grants (anti-IR / targeted DoS) | - | NON-PRIVESC | anti-IR DoS |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---privileged-access-manager-pam-post-exploitation`, `#privileged-access-manager-pam`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-parameter-manager-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#parameterversionsrender--read-secret-manager-secrets-you-dont-have-access-to` | ### `parameterVersions.render` — read Secret Manager secrets you don't have access to | - | NON-PRIVESC | secret read via parameter identity (confused deputy; borderline if secrets hold SA keys) |
| `#parameter-poisoning--inject-configsecret-refs-consumed-by-workloads` | ### Parameter poisoning — inject config/secret-refs consumed by workloads | - | NON-PRIVESC | config tampering |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---parameter-manager-post-exploitation`, `#parameter-manager`, `#credential-access`, `#data-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-personalized-service-health-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#servicehealtheventslist--infer-productlocation-usage-and-monitor-defensive-outages` | ### `servicehealth.events.list` — infer product/location usage and monitor defensive outages | - | NON-PRIVESC | recon |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---personalized-service-health-post-exploitation`, `#personalized-service-health`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-policy-troubleshooter-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#iamtroubleshoot--map-permission-paths-without-exercising-the-target-api` | ### `iam:troubleshoot` — map permission paths without exercising the target API | - | NON-PRIVESC | IAM recon |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---policy-troubleshooter-post-exploitation`, `#policy-troubleshooter`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-pub-sub-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#bigquery-export-subscription-exfil-sink---pubsubsubscriptionscreate--pubsubtopicsattachsubscription` | ### BigQuery export subscription exfil sink - `pubsub.subscriptions.create` + `pubsub.topics.attachSubscription` | - | NON-PRIVESC | data read/exfil |
| `#pubsubsubscriptionsupdate--reuse-a-stored-custom-writer-without-caller-actas` | ### `pubsub.subscriptions.update` — reuse a stored custom writer without caller `actAs` | - | NON-PRIVESC | confused-deputy writes as stored writer SA (message delivery only, no SA code/token; borderline) |
| `#retarget-a-bigquery-subscription` | #### Retarget a BigQuery subscription | - | NON-PRIVESC | data poisoning via stored writer |
| `#retarget-a-cloud-storage-subscription` | #### Retarget a Cloud Storage subscription | - | NON-PRIVESC | message redirection via stored writer |
| `#cloud-storage-subscription-bucket-name-hijack---storagebucketsdelete` | ### Cloud Storage subscription bucket-name hijack - `storage.buckets.delete` | - | NON-PRIVESC | bucket-name hijack exfil |
| `#pubsubsubscriptionsupdate` | ### `pubsub.subscriptions.update` | - | NON-PRIVESC | message redirection/DoS (new OIDC SA = OIDC-only, excluded) |
| `#pubsubsubscriptionscreatepubsubtopicsattachsubscription--pubsubsubscriptionsconsume` | ### **`pubsub.subscriptions.create,`**`pubsub.topics.attachSubscription` , (`pubsub.subscriptions.consume`) | - | NON-PRIVESC | message siphon (data) |
| `#pubsubtopicspublish` | ### `pubsub.topics.publish` | - | NON-PRIVESC | message injection into consumers |
| `#pubsubtopicsupdate` | ### `pubsub.topics.update` | - | NON-PRIVESC | topic config DoS |
| `#pubsubtopicscreate--pubsubtopicsupdate--import-topic-cloud-storage-ingestion-message-injection` | ### `pubsub.topics.create` / `pubsub.topics.update` — import-topic (Cloud Storage ingestion) message injection | - | NON-PRIVESC | message injection into consumers |
| `#pubsubsnapshotscreate-pubsubsnapshotsseek` | ### `pubsub.snapshots.create`, `pubsub.snapshots.seek` | - | NON-PRIVESC | message replay (data) |
| `#pubsubtopicsdetachsubscription` | ### `pubsub.topics.detachSubscription` | - | NON-PRIVESC | DoS/destruction |
| `#pubsubtopicsdelete` | ### `pubsub.topics.delete` | - | NON-PRIVESC | DoS/destruction |
| `#pubsubsubscriptionsdelete` | ### `pubsub.subscriptions.delete` | - | NON-PRIVESC | DoS/destruction |
| `#pubsubschemasattach-pubsubtopicsupdatepubsubschemascreate` | ### `pubsub.schemas.attach`, `pubsub.topics.update`,(`pubsub.schemas.create`) | - | NON-PRIVESC | DoS/destruction |
| `#pubsubsubscriptionsconsume--destroy-a-backlog-with-seek---time-silent-by-default` | ### `pubsub.subscriptions.consume` — destroy a backlog with `seek --time` (silent by default) | - | NON-PRIVESC | DoS/destruction |
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---pubsub-post-exploitation`, `#pubsub`, `#data-export`, `#traffic-interception--redirection`, `#data-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-recaptcha-enterprise-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#recaptchaenterprisekeysretrievelegacysecretkey--retrieve-the-legacy-verifier-secret` | ### `recaptchaenterprise.keys.retrievelegacysecretkey` — retrieve the legacy verifier secret | - | NON-PRIVESC | app verifier secret (data) |
| `#relatedaccountgroupslist--relatedaccountgroupmembershipslist--map-related-victim-accounts` | ### `relatedaccountgroups.list` + `relatedaccountgroupmemberships.list` — map related victim accounts | - | NON-PRIVESC | recon of app accounts |
| `#recaptchaenterpriseassessmentsannotate--submit-false-fraud-model-feedback` | ### `recaptchaenterprise.assessments.annotate` — submit false fraud-model feedback | - | NON-PRIVESC | data/config tampering |
| `#recaptchaenterprisekeysupdate--recaptchaenterprisepoliciesupdate--weaken-key-and-challenge-enforcement` | ### `recaptchaenterprise.keys.update` / `recaptchaenterprise.policies.update` — weaken key and challenge enforcement | - | NON-PRIVESC | control weakening / defense evasion |
| `#recaptchaenterprisekeysupdate--pin-valid-assessments-from-an-ip-to-score-09` | ### `recaptchaenterprise.keys.update` — pin valid assessments from an IP to score `0.9` | - | NON-PRIVESC | control weakening / defense evasion |
| `#recaptchaenterprisefirewallpoliciescreate--update--return-an-attacker-favorable-firewall-action` | ### `recaptchaenterprise.firewallpolicies.create` / `.update` — return an attacker-favorable firewall action | - | NON-PRIVESC | control weakening / defense evasion |
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---recaptcha-enterprise-post-exploitation`, `#recaptcha-enterprise`, `#credential-access`, `#data-export`, `#data-tampering`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-recommender-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#recommender-reads--mine-precomputed-privilege-and-attack-path-intelligence` | ### Recommender reads — mine precomputed privilege and attack-path intelligence | - | NON-PRIVESC | IAM recon |
| `#recommenderrecommendationsupdate--insightsupdate--suppress-or-freeze-findings` | ### `recommender.*Recommendations.update` / `*Insights.update` — suppress or freeze findings | - | NON-PRIVESC | logging/defense evasion |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---recommender-post-exploitation`, `#recommender`, `#data-export`, `#telemetry-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-runtimeconfig-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#runtimeconfigvariablesget--list--recover-stored-variable-values` | ### `runtimeconfig.variables.get` (+ `.list`) — recover stored variable values | - | NON-PRIVESC | config/secret read |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-runtime-configurator-post-exploitation`, `#runtime-configurator`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-secretmanager-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#secretmanagerversionsaccess` | ### `secretmanager.versions.access` | - | NON-PRIVESC | secret read (data; may hold creds) |
| `#secretmanagerversionsadd` | ### `secretmanager.versions.add` | - | NON-PRIVESC | secret value injection |
| `#secretmanagersecretsupdate` | ### `secretmanager.secrets.update` | - | NON-PRIVESC | secret lifecycle tampering |
| `#version-alias-repointing--secretmanagersecretsupdate-secretmanagersecretsget` | ### Version alias repointing — `secretmanager.secrets.update` (`secretmanager.secrets.get`) | - | NON-PRIVESC | secret alias substitution |
| `#secretmanagerversionsdestroy` | ### `secretmanager.versions.destroy` | - | NON-PRIVESC | DoS/destruction |
| `#secretmanagerversionsdisable` | ### `secretmanager.versions.disable` | - | NON-PRIVESC | DoS/destruction |
| `#secretmanagersecretsdelete` | ### `secretmanager.secrets.delete` | - | NON-PRIVESC | DoS/destruction |
| `#secretmanagersecretsupdate--regional-secret-cmek-hijack-remote-kill-switch` | ### `secretmanager.secrets.update` — regional-secret CMEK hijack (remote kill-switch) | - | NON-PRIVESC | CMEK kill-switch DoS |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---secretmanager-post-exploitation`, `#secret-manager`, `#credential-access`, `#data-tampering`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-secure-source-manager-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#repositoriesfetch--read-apis--harvest-private-source-and-unmerged-review-intelligence` | ### `repositories.fetch` + read APIs — harvest private source and unmerged review intelligence | - | NON-PRIVESC | source code read |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---secure-source-manager-post-exploitation`, `#secure-source-manager`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-security-command-center-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#create-or-change-a-mute-rule` | ### Create or change a mute rule | - | NON-PRIVESC | logging/defense evasion |
| `#mute-individual-findings-or-bulk-mute-matches` | ### Mute individual findings or bulk-mute matches | - | NON-PRIVESC | logging/defense evasion |
| `#mark-a-finding-inactive` | ### Mark a finding inactive | - | NON-PRIVESC | logging/defense evasion |
| `#execute-on-a-documented-unsupported-runtime-surface` | ### Execute on a documented unsupported runtime surface | - | NON-PRIVESC | detector coverage evasion |
| `#disable-a-detection-service-or-module` | ### Disable a detection service or module | - | NON-PRIVESC | logging/defense evasion |
| `#delete-or-alter-a-pubsub-notification-configuration` | ### Delete or alter a Pub/Sub notification configuration | - | NON-PRIVESC | logging/defense evasion |
| `#delete-or-alter-a-bigquery-continuous-export` | ### Delete or alter a BigQuery continuous export | - | NON-PRIVESC | logging/defense evasion |
| `#delete-an-etd-or-sha-custom-module` | ### Delete an ETD or SHA custom module | - | NON-PRIVESC | logging/defense evasion |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---security-command-center-post-exploitation`, `#security-command-center`, `#telemetry-tampering`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-service-directory-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#servicedirectoryendpointscreateupdate--poison-service-discovery` | ### `servicedirectory.endpoints.create/update` — poison service discovery | - | NON-PRIVESC | service-discovery traffic redirection |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---service-directory-post-exploitation`, `#service-directory`, `#traffic-interception--redirection`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-source-repositories-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#sourcereposget--clone-private-source-and-inspect-all-reachable-history` | ### `source.repos.get` — clone private source and inspect all reachable history | - | NON-PRIVESC | source code read |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-source-repositories-post-exploitation`, `#source-repositories`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-spanner-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#read-or-modify-database-rows` | ### Read or modify database rows | - | NON-PRIVESC | DB data read/write |
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---spanner-post-exploitation`, `#spanner`, `#data-export`, `#spannerdatabasesselect`, `#spannerdatabasesread`, `#spannerdatabaseswrite`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-storage-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#storage-insights-inventory-report-to-a-chosen-bucket` | ### Storage Insights inventory report to a chosen bucket | - | NON-PRIVESC | inventory metadata exfil |
| `#global-bucket-name-takeover-of-upstream-writers` | ### Global bucket name takeover of upstream writers | - | NON-PRIVESC | bucket-name hijack exfil |
| `#storagebucketsrestore` | ### `storage.buckets.restore` | - | NON-PRIVESC | bucket recovery/destination re-establish |
| `#signed-urls--credential-free-exfil--covert-write-iamserviceaccountssignblob` | ### Signed URLs — credential-free exfil & covert write (`iam.serviceAccounts.signBlob`) | iam.serviceAccounts.signBlob | EXCLUDED | X: Signed URLs — credential-free exfil & covert write (iam.serviceAccounts.signBlob) |
| `#give-public-access` | ### Give Public Access | - | NON-PRIVESC | public data exposure |
| `#storageobjectsdelete` | ### `storage.objects.delete` | - | NON-PRIVESC | DoS/destruction |
| `#storagebucketsdelete-storageobjectsdelete--storageobjectslist` | ### `storage.buckets.delete`, `storage.objects.delete` & `storage.objects.list` | - | NON-PRIVESC | DoS/destruction |
| `#storagebucketsupdate--irreversible-retention-lock-denial--ransomware--anti-forensics` | ### `storage.buckets.update` — irreversible retention lock (denial / ransomware / anti-forensics) | - | NON-PRIVESC | DoS/destruction |
| `#storagebatchoperationsjobscreate--serverless-bulk-delete--re-encrypt--hold-strip-mass-dos--ransomware` | ### `storagebatchoperations.jobs.create` — serverless bulk delete / re-encrypt / hold-strip (mass DoS & ransomware) | - | NON-PRIVESC | DoS/destruction |
| `#deactivate-hmac-keys` | ### Deactivate HMAC Keys | - | NON-PRIVESC | HMAC key DoS |
| `#storagebucketssetipfilter--storagebucketsupdate` | ### `storage.buckets.setIpFilter` & `storage.buckets.update` | - | NON-PRIVESC | DoS/destruction |
| `#storagebucketsupdate--default-cmek-repoint-ransom-of-future-writes` | ### `storage.buckets.update` — default-CMEK repoint (ransom of future writes) | - | NON-PRIVESC | DoS/destruction |
| `#storageobjectssetretention--object-holds--per-object-un-deletable-lock` | ### `storage.objects.setRetention` / object holds — per-object un-deletable lock | - | NON-PRIVESC | DoS/destruction |
| `#storagebucketsupdate--disable-soft-delete--versioning-anti-forensics-multiplier` | ### `storage.buckets.update` — disable soft-delete & versioning (anti-forensics multiplier) | - | NON-PRIVESC | DoS/destruction |
| `#storagebucketsupdate--lifecycle-rule-as-deferred-deniable-mass-deletion` | ### `storage.buckets.update` — lifecycle rule as deferred, deniable mass-deletion | - | NON-PRIVESC | DoS/destruction |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---storage-post-exploitation`, `#cloud-storage`, `#data-export`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-storage-transfer-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#storagetransferjobsupdate--run--repoint-an-authorized-job` | ### `storagetransfer.jobs.update` + `run` — repoint an authorized job | - | NON-PRIVESC | data exfil via transfer agent |
| `#storagetransferjobscreate--run--copy-agent-readable-data-to-an-attacker-sink` | ### `storagetransfer.jobs.create` + `run` — copy agent-readable data to an attacker sink | - | NON-PRIVESC | data exfil via transfer agent |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---storage-transfer-post-exploitation`, `#storage-transfer`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-transcoder-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#transcoderjobscreate--re-host-media-readable-by-the-service-agent` | ### `transcoder.jobs.create` — re-host media readable by the service agent | - | NON-PRIVESC | media exfil via service agent |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---transcoder-post-exploitation`, `#transcoder`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-unified-maintenance-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#maintenanceresourcemaintenanceslist--enumerate-resources-and-maintenance-windows` | ### `maintenance.resourceMaintenances.list` — enumerate resources and maintenance windows | - | NON-PRIVESC | resource recon |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---unified-maintenance-post-exploitation`, `#unified-maintenance`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-vertex-ai-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#read-workload-specifications-inline-secrets-identities-and-artifact-locations` | ### Read workload specifications, inline secrets, identities, and artifact locations | - | NON-PRIVESC | spec/secret read, SA recon |
| `#use-rag-engine-as-a-service-agent-read-and-retrieve-deputy` | ### Use RAG Engine as a service-agent read-and-retrieve deputy | - | NON-PRIVESC | data read via RAG service agent |
| `#read-online-feature-values-and-embedding-neighbors` | ### Read online feature values and embedding neighbors | - | NON-PRIVESC | data read/exfil |
| `#export-an-exportable-model-or-dataset-to-controlled-cloud-storage` | ### Export an exportable model or dataset to controlled Cloud Storage | - | NON-PRIVESC | data read/exfil |
| `#weaken-or-delete-semantic-governance-tool-guardrails` | ### Weaken or delete Semantic Governance tool guardrails | - | NON-PRIVESC | agent guardrail defense evasion |
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vertex-ai-post-exploitation`, `#vertex-ai`, `#credential-access`, `#data-export`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-vm-migration-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#vmmigrationmigratingvmscreate--vmmigrationmigratingvmsupdate--migrate-an-aws-unattached-volume` | ### `vmmigration.migratingVms.create` + `vmmigration.migratingVms.update` — migrate an AWS unattached volume | - | NON-PRIVESC | disk data exfil |
| `#vmmigrationimageimportscreate--make-the-service-agent-read-a-disk-image-from-cloud-storage` | ### `vmmigration.imageImports.create` — make the service agent read a disk image from Cloud Storage | - | NON-PRIVESC | disk image read via agent |
| `#vmmigrationclonejobscreate--materialize-a-replicated-vm-and-read-its-snapshot` | ### `vmmigration.cloneJobs.create` — materialize a replicated VM and read its snapshot | - | NON-PRIVESC | replica disk data read (exec-as-VM-SA variant already gcp-vmmigration-migratingvm-metadata-clone) |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vm-migration-post-exploitation`, `#vm-migration`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-vmwareengine-gcve-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#clone-a-workload-vm-for-offline-data-access-through-vcenter` | ### Clone a workload VM for offline data access through vCenter | - | NON-PRIVESC | vCenter disk data (non-GCP identity) |
| `#use-nsx-enterprise-admin-to-bypass-segmentation-or-intercept-traffic` | ### Use NSX Enterprise Admin to bypass segmentation or intercept traffic | - | NON-PRIVESC | NSX network segmentation bypass |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vmware-engine-gcve-post-exploitation`, `#vmware-engine-gcve`, `#data-export`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-vpc-network-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#network-pivots-and-interception` | ### Network pivots and interception | - | NON-PRIVESC | network-only pivot |
| `#abusing-vpc-peering-as-a-network-pivot-primitive` | #### Abusing VPC peering as a network-pivot primitive | - | NON-PRIVESC | network-only pivot |
| `#network-connectivity-center-ncc-hubspoke--pivot-without-peering` | #### Network Connectivity Center (NCC) hub/spoke — pivot without peering | - | NON-PRIVESC | network-only pivot |
| `#networkconnectivitypolicybasedroutescreate--steer-matching-traffic-to-an-attacker-controlled-next-hop` | #### `networkconnectivity.policyBasedRoutes.create` — steer matching traffic to an attacker-controlled next hop | - | NON-PRIVESC | traffic redirection |
| `#cloud-vpn--ha-vpn--tunnel-bridge-bgp-hijack--the-psk-disclosure-myth` | ### Cloud VPN / HA VPN — tunnel bridge, BGP hijack & the PSK-disclosure myth | - | NON-PRIVESC | network bridge/BGP hijack |
| `#firewall-rule-tampering-as-a-standalone-primitive` | ### Firewall-rule tampering as a standalone primitive | - | NON-PRIVESC | network exposure |
| `#private-service-connect-psc--cross-vpc-reach--attacker-published-services` | ### Private Service Connect (PSC) — cross-VPC reach & attacker-published services | - | NON-PRIVESC | network reach/impersonated endpoint |
| `#networkconnectivityinternalrangescreate--vpc-ipam-squat--subnet-allocation-dos` | ### `networkconnectivity.internalRanges.create` — VPC IPAM squat / subnet-allocation DoS | - | NON-PRIVESC | DoS/destruction |
| `#service-networking--private-services-access-psa-connection-abuse` | ### Service Networking — Private Services Access (PSA) connection abuse | - | NON-PRIVESC | PSA network DoS/route leak |
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vpc-and-networking-post-exploitation`, `#vpc-and-networking`, `#audit-visibility`, `#traffic-interception--redirection`, `#security-control-bypass`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-vpc-service-controls-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vpc-service-controls-post-exploitation`, `#vpc-service-controls`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-web-security-scanner-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#create-and-run-a-custom-scan-to-map-a-projects-public-application` | ### Create and run a custom scan to map a project's public application | - | NON-PRIVESC | app vulnerability recon |
| `#read-existing-scan-configuration-findings-and-crawled-urls` | ### Read existing scan configuration, findings, and crawled URLs | - | NON-PRIVESC | scan results recon |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---web-security-scanner-post-exploitation`, `#web-security-scanner`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-workflows-post-exploitation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#workflowsworkflowsget--recover-workflow-source-and-its-execution-identity` | ### `workflows.workflows.get` — recover workflow source and its execution identity | - | NON-PRIVESC | source/secret read, SA recon |
| `#read-execution-arguments-results-and-detailed-step-variables` | ### Read execution arguments, results and detailed step variables | - | NON-PRIVESC | execution data read |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---workflows-post-exploitation`, `#workflows`, `#data-export`, `#dosbreak`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/README.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---services`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-access-approval-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---access-approval-enum`, `#access-approval-accessapprovalgoogleapiscom`, `#enumeration`, `#relevant-permissions--roles`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-advisory-notifications-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---advisory-notifications-enum`, `#advisory-notifications-advisorynotificationsgoogleapiscom`, `#enumeration`, `#logging-boundary`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-agent-identity-auth-manager-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---agent-identity-auth-manager-enum`, `#agent-identity-auth-manager`, `#inventory`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-agent-registry-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---agent-registry-enum`, `#agent-registry-agentregistrygoogleapiscom`, `#enumerate-locations-and-registry-resources`, `#interesting-fields`, `#roles-and-audit-visibility`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-ai-platform-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---ai-platform-enum`, `#ai-platform-legacy`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-alloydb-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---alloydb-enum`, `#alloydb-for-postgresql`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-analytics-hub-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---analytics-hub-enum`, `#basic-information`, `#enumeration`, `#privilege-escalation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-api-gateway-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#relevant-permissions` | ### Relevant permissions | apigateway.apis.create + apigateway.apiconfigs.create + apigateway.gateways.create + iam.serviceAccounts.actAs (roles/editor) | EXCLUDED | X: API Gateway backend-auth SA (enumeration page) |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---api-gateway-enum`, `#api-gateway`, `#enumeration`, `#post-exploitation--privesc`, `#unauthenticated-access`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-api-keys-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---api-keys-enum`, `#basic-information`, `#restrictions`, `#enumeration`, `#privilege-escalation--post-exploitation`, `#unauthenticated-enum`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-apigee-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 14 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---apigee-enum`, `#basic-information`, `#enumerate-organizations-and-environments`, `#enumerate-proxies-revisions-and-deployments`, `#enumerate-shared-flows-flow-hooks-and-backends`, `#enumerate-secrets-credentials-and-tls-material`, `#enumerate-trace-masks-and-resource-iam`, `#logs`, `#attack-techniques`, `#privilege-escalation`, `#post-exploitation`, `#unauthenticated-access`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-app-engine-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 13 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---app-engine-enum`, `#basic-information`, `#firewall`, `#sa`, `#storage`, `#containers`, `#urls--regions`, `#enumeration`, `#privilege-escalation`, `#unauthenticated-enum`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-app-hub-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#serviceprojectattachmentsdetach--delete--application-map-tamper-metadata-dos` | #### `serviceProjectAttachments.detach` / `.delete` — application-map tamper (metadata DoS) | - | NON-PRIVESC | metadata DoS |
| `#apphubapplicationssetiampolicy--self-grant-weak` | #### `apphub.applications.setIamPolicy` — self-grant (weak) | - | NON-PRIVESC | App Hub metadata only |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---app-hub-enum`, `#app-hub`, `#apphubdiscoveredserviceslist--discoveredworkloadslist--cross-project-topology-recon-primary-value`, `#interesting-permissions`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-app-lifecycle-manager-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---app-lifecycle-manager-enum`, `#app-lifecycle-manager-saasservicemgmtgoogleapiscom`, `#enumeration`, `#remote-mcp-server`, `#interesting-permissions`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-app-topology-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---app-topology-enum`, `#app-topology-apptopologygoogleapiscom`, `#enumerate-domains-and-schemas`, `#generate-targeted-topology-graphs`, `#remote-mcp-transport`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-application-design-center-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---application-design-center-enum`, `#application-design-center-designcentergoogleapiscom`, `#enumeration`, `#remote-mcp-server`, `#predefined-role-hazards`, `#audit-footprint`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-application-integration-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---application-integration-enum`, `#application-integration`, `#inventory`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-artifact-registry-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 13 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---artifact-registry-enum`, `#basic-information`, `#formats-and-modes`, `#encryption`, `#cleanup-policies`, `#vulnerability-scanning`, `#enumeration`, `#privilege-escalation`, `#unauthenticated-access`, `#post-exploitation`, `#persistence`, `#container-analysis--artifact-analysis-vuln-scanning--attestation-metadata`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-backup-and-dr-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---backup-and-dr-enum`, `#enumerate-vault-backed-protection`, `#enumerate-auto-protection-policies-preview`, `#what-to-review`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-bare-metal-solution-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---bare-metal-solution-enum`, `#bare-metal-solution-bms`, `#enumeration-read-only--rolesbaremetalsolutionviewer`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-batch-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---batch-enum`, `#basic-information`, `#service-account`, `#enumeration`, `#privilege-escalation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-beyondcorp-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 10 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---beyondcorp--chrome-enterprise-premium-enum`, `#secure-gateway-beyondcorpgoogleapiscom`, `#identity-and-network-boundaries`, `#enumeration`, `#logging-boundaries`, `#privilege-escalation`, `#post-exploitation`, `#persistence`, `#identity-aware-proxy`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-biglake-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---biglake--lakehouse-enum`, `#biglake--lakehouse`, `#enumerate-cloud-storage-biglake-tables-and-connections`, `#enumerate-current-iceberg-rest-catalogs`, `#enumerate-biglake-metastore-classic`, `#relevant-lakehouse-roles`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-bigquery-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 13 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---bigquery-enum`, `#basic-information`, `#encryption`, `#expiration`, `#external-sources`, `#dataset-acls`, `#table-rows-control-access`, `#columns-access-control`, `#enumeration`, `#privilege-escalation--post-exploitation`, `#persistence`, `#unauthenticated-access`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-bigtable-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---bigtable-enum`, `#bigtable`, `#hierarchy`, `#privilege-escalation`, `#post-exploitation`, `#persistence`, `#unauthenticated-access`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-binary-authorization-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---binary-authorization-enum`, `#binary-authorization-binaryauthorizationgoogleapiscom`, `#enumeration`, `#relevant-permissions--roles`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-certificate-authority-service-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---certificate-authority-service-enum`, `#basic-information`, `#enumeration`, `#privilege-escalation`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-certificate-manager-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---certificate-manager-enum`, `#certificate-manager`, `#enumeration`, `#relevant-permissions`, `#logging`, `#post-exploitation--privesc`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-billing-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-billing-enum`, `#cloud-billing-cloudbillinggoogleapiscom`, `#core-enumeration`, `#cloud-billing-remote-mcp-transport-preview`, `#privilege-escalation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-build-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#sa-permissions` | ### SA Permissions | no GCP perm; attacker opens external PR / pushes to monitored repo where trigger comment control = Not required | EXCLUDED | NS-5 REJECTED as a privesc edge: CSPM check (external SCM contributor, no principal source) (_excluded) |
| `#pr-approvals` | ### PR Approvals | no GCP perm; attacker opens external PR / pushes to monitored repo where trigger comment control = Not required | EXCLUDED | NS-5 REJECTED as a privesc edge: CSPM check (external SCM contributor, no principal source) (_excluded) |
| (structural) | 13 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-build-enum`, `#basic-information`, `#events`, `#execution`, `#approvals`, `#connections--repositories`, `#connect-a-repository`, `#storage`, `#enumeration`, `#privilege-escalation`, `#unauthenticated-access`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-cli-execution-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-cli-execution-enum`, `#cloud-cli-execution-cloudcligoogleapiscom`, `#enumerate-the-exposed-tools`, `#execute-google-cloud-cli-commands-remotely`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-deploy-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-deploy-enum`, `#basic-information`, `#enumeration`, `#privilege-escalation`, `#post-exploitation-and-persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-domains-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-domains-enum`, `#basic-information`, `#enumerate-registrations-and-takeover-relevant-settings`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-endpoints-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-endpoints-enum`, `#enumerate-resources`, `#what-to-review`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-functions-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 13 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-functions-enum`, `#cloud-functions`, `#storage`, `#artifact-registry`, `#sa`, `#triggers-url--authentication`, `#inside-the-cloud-function`, `#enumeration`, `#privilege-escalation`, `#unauthenticated-access`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-identity-and-google-groups-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-identity-and-google-groups-enum`, `#enumerate-resources`, `#what-to-review`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-ids-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-ids-enum`, `#cloud-ids-idsgoogleapiscom`, `#enumeration`, `#relevant-permissions--roles`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-quotas-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-quotas-enum`, `#basic-information`, `#enumeration`, `#remote-mcp-server`, `#audit-footprint`, `#post-exploitation`, `#privilege-escalation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-run-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 13 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-run-enum`, `#cloud-run`, `#services-and-jobs`, `#cloud-run-service`, `#relevant-details`, `#enumeration`, `#cloud-run-jobs`, `#enumeration-1`, `#privilege-escalation`, `#unauthenticated-access`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-scheduler-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-scheduler-enum`, `#basic-information`, `#service-accounts`, `#enumeration`, `#privilege-escalation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-shell-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-shell-enum`, `#basic-information`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-sql-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 12 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-sql-enum`, `#basic-information`, `#password`, `#zone-availability`, `#encryption`, `#connections`, `#data-protection`, `#enumeration`, `#unauthenticated-enum`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-support-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-support-enum`, `#cloud-customer-care-cloudsupportgoogleapiscom`, `#rest-enumeration`, `#remote-mcp-enumeration`, `#audit-boundary`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-tasks-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 10 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-tasks-enum`, `#basic-information`, `#enumeration`, `#visibility-during-enumeration`, `#attack-techniques`, `#privilege-escalation`, `#post-exploitation`, `#persistence`, `#unauthenticated-access`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cloud-workstations-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-workstations-enum`, `#basic-information`, `#enumeration`, `#permission-filtered-unlogged-discovery`, `#logging-and-detection`, `#attack-techniques`, `#privilege-escalation-and-persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cluster-director-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cluster-director-enum`, `#cluster-director-hypercomputeclustergoogleapiscom`, `#enumeration`, `#interesting-permissions`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-compliance-manager-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---compliance-manager-enum`, `#enumerate-resources`, `#what-to-review`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-composer-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---composer-enum`, `#basic-information`, `#enumeration`, `#privesc`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-compute-instances-enum/README.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 22 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---compute-enum`, `#gcp-vpc--networking`, `#enumeration`, `#compute-instances`, `#enumeration-1`, `#privilege-escalation`, `#unauthenticated-enum`, `#post-exploitation`, `#persistence`, `#serial-console-logs`, `#startup-scripts-output`, `#os-configuration-manager`, `#enumeration-2`, `#images`, `#machine-images-and-custom-images`, `#enumeration-3`, `#privilege-escalation-1`, `#custom-instance-templates`, `#snapshots`, `#enumeration-4`, `#privilege-escalation-2`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-compute-instances-enum/gcp-compute-instance.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 12 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---compute-instances`, `#basic-information`, `#confidential-vm`, `#disk--disk-encryption`, `#deploy-container`, `#service-account`, `#firewall`, `#networking`, `#extra-security`, `#vm-access`, `#metadata`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-compute-instances-enum/gcp-vpc-and-networking.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 11 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vpc--networking`, `#gcp-compute-networking-in-a-nutshell`, `#vpc-subnetworks--firewalls-in-gcp`, `#subnetworks`, `#firewalls`, `#hierarchical-firewall-policies`, `#firewall-rules-evaluation`, `#vpc-network-peering`, `#enumerate-vpc-connectivity-and-exposure`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-config-controller-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---config-controller--config-connector-kcc-enum`, `#config-controller-krmapihostinggoogleapiscom`, `#enumeration`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-config-delivery-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---config-delivery-enum`, `#enumerate-resources`, `#what-to-review`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-contact-center-insights-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---contact-center-ai-insights-enum`, `#basic-information`, `#enumeration`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-container-analysis-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 9 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---container-analysis--artifact-analysis-enum`, `#container-analysis-containeranalysisgoogleapiscom`, `#enumeration`, `#important-authorization-boundaries`, `#privilege-escalation`, `#post-exploitation`, `#persistence`, `#binary-authorization`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-containers-gke-and-composer-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#external-user-authentication-and-standard-node-access` | ### External user authentication and Standard node access | compute.instances.osLogin/osAdminLogin on nodes | COVERED | `gcp-compute-instances-oslogin` |
| (structural) | 10 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---containers--gke-enum`, `#containers`, `#privesc`, `#node-pools`, `#kubernetes`, `#current-gke-identity-and-metadata-checks`, `#credentials-outside-workload-identity`, `#autopilot-privileged-workload-allowlists`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-cx-agent-studio-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cx-agent-studio-enum`, `#basic-information`, `#enumeration`, `#remote-mcp-server`, `#audit-footprint`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-data-fusion-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 10 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---data-fusion-enum`, `#cloud-data-fusion`, `#control-plane-enumeration`, `#data-plane-enumeration`, `#access-model-notes`, `#current-predefined-role-highlights`, `#privilege-escalation`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-database-center-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---database-center-enum`, `#basic-information`, `#enumeration`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-database-insights-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---database-insights-enum`, `#basic-information`, `#enumeration`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-database-migration-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---database-migration-service-enum`, `#enumerate-resources`, `#what-to-review`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-dataflow-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 11 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dataflow-enum`, `#basic-information`, `#components`, `#batch-vs-streaming-jobs`, `#enumeration`, `#job-enumeration`, `#template-and-bucket-enumeration`, `#privilege-escalation`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-dataform-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dataform-enum`, `#basic-information`, `#enumeration`, `#privesc-and-post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-dataplex-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dataplex-enum`, `#basic-information`, `#enumeration`, `#universal-catalog-metadata--schema-exfil-cross-project-recon`, `#data-lineage--map-upstream-sources-transformations-and-downstream-blast-radius`, `#privesc-and-post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-dataproc-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 12 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dataproc-enum`, `#basic-information`, `#components`, `#enumeration`, `#cluster-enumeration`, `#job-enumeration`, `#serverless-batch-and-session-enumeration`, `#remote-mcp-server`, `#audit-footprint`, `#post-exploitation`, `#privesc`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-dataproc-metastore-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dataproc-metastore-enum`, `#dataproc-metastore`, `#enumeration`, `#relevant-permissions`, `#privesc`, `#persistence`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-datastream-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 12 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---datastream-enum`, `#basic-information`, `#enumerate-regions-and-static-ips`, `#enumerate-connection-profiles`, `#enumerate-streams-and-replicated-objects`, `#enumerate-private-connections-and-routes`, `#visibility-during-enumeration`, `#attack-techniques`, `#privilege-escalation`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-deployment-manager-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---deployment-manager-enum`, `#enumerate-resources`, `#what-to-review`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-developer-connect-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---developer-connect-enum`, `#developer-connect`, `#enumerate-connections-and-linked-repositories`, `#enumerate-account-connectors-and-users`, `#enumerate-insights-and-deployment-events`, `#critical-iam-and-identity-boundaries`, `#offensive-follow-up`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-dialogflow-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dialogflow-cx-enum`, `#enumerate-agents-and-webhooks`, `#what-to-review`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-dns-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---dns-enum`, `#gcp---cloud-dns`, `#unauthenticated-access`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-document-ai-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---document-ai-enum`, `#document-ai-documentaigoogleapiscom`, `#enumeration`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-essential-contacts-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---essential-contacts-enum`, `#enumerate-resources`, `#what-to-review`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-eventarc-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---eventarc-enum`, `#eventarc`, `#enumeration`, `#relevant-permissions`, `#post-exploitation--privesc`, `#privilege-escalation-and-persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-filestore-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 9 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---filestore-enum`, `#basic-information`, `#connections`, `#backups`, `#encryption`, `#enumeration`, `#security-boundaries-and-permissions`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-app-hosting-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---firebase-app-hosting-enum`, `#firebase-app-hosting-firebaseapphostinggoogleapiscom`, `#enumeration`, `#relevant-permissions`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-data-connect-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---firebase-data-connect-enum`, `#firebase-data-connect-firebasedataconnectgoogleapiscom`, `#enumeration`, `#relevant-permissions`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-firebase-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---firebase-enum`, `#firebase`, `#unauthenticated-enum`, `#authenticated-enum`, `#access-info-with-app-id-and-api-key`, `#privilege-escalation`, `#unauthenticated-access`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-firestore-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---firestore-enum`, `#cloud-firestore`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-gemini-cloud-assist-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---gemini-cloud-assist-enum`, `#basic-information`, `#investigations`, `#remote-mcp-server`, `#broad-predefined-role-warning`, `#audit-footprint`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-google-secops-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---google-secops-chronicle-enum`, `#google-secops-chroniclegoogleapiscom`, `#enumeration`, `#relevant-permissions--roles`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-healthcare-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-healthcare-api-enum`, `#cloud-healthcare-api`, `#enumerate-datasets-and-modality-stores`, `#inspect-store-configuration-and-external-destinations`, `#enumerate-datasetstore-iam-without-flattening-conditions`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-iam-and-org-policies-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#default-permissions` | ### Default Permissions | - | NON-PRIVESC | owner of own new project |
| `#iam-remote-mcp-transport` | ### IAM remote MCP transport | iam.roles.update via MCP transport | COVERED | `gcp-iam-roles-update-own-custom-role` |
| `#organization-policy-remote-mcp-transport` | ### Organization Policy remote MCP transport | - | NON-PRIVESC | orgpolicy (catalog-excluded) |
| (structural) | 24 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---iam-principals--org-policies-enum`, `#service-accounts`, `#enumeration`, `#users--groups`, `#enumeration-1`, `#related-group-attacks`, `#resource-manager-project-search-mcp`, `#iam`, `#set-iam-policy-vs-add-iam-policy-binding`, `#enumeration-2`, `#cloudasset-iam-enumeration`, `#policy-analyzer-remote-mcp-transport`, `#iam-recommender--policy-insights--precomputed-privesc-target-map`, `#policy-analyzer--sa-usage-insights--dormant-privileged-sa--unused-key-oracle`, `#policy-troubleshooter--blind-can-x-do-y-probing`, `#cloud-asset-export-query-move-analysis-and-feeds`, `#testiampermissions-enumeration`, `#privesc`, `#unauthenticated-enum`, `#post-exploitation`, `#persistence`, `#org-policies`, `#privesc-1`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-iap-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---iap-enum`, `#basic-information`, `#enumeration`, `#privesc-and-post-exploitation`, `#unauthenticated-access`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-identity-federation-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 11 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---workload--workforce-identity-federation-enum`, `#basic-information`, `#enumerate-workload-identity-pools-and-providers`, `#enumerate-workforce-pools-and-providers`, `#enumerate-workforce-oauth-clients`, `#enumerate-managed-workload-identities`, `#logging-and-detection`, `#attack-techniques`, `#privilege-escalation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-infra-manager-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---infra-manager-enum`, `#infrastructure-manager`, `#enumeration`, `#relevant-permissions`, `#post-exploitation--privesc`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-integration-connectors-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 11 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---integration-connectors-enum`, `#basic-information`, `#enumerate-connections`, `#enumerate-available-actions-entities-and-events`, `#enumerate-network-and-custom-connector-resources`, `#visibility-during-enumeration`, `#attack-techniques`, `#privilege-escalation`, `#post-exploitation`, `#application-integration-credential-access`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-kms-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 13 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---kms-enum`, `#kms`, `#key-protection-level`, `#key-purposes`, `#rotation-period--scheduled-for-destruction-period`, `#primary-version`, `#cmek-permission-model`, `#enumeration`, `#basic-roles-and-kms-correcting-the-editorowner-exclude-kms-belief`, `#autokey-autokeyconfig--keyhandles`, `#privilege-escalation`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-liens-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---resource-manager-liens-enum`, `#enumerate-resources`, `#what-to-review`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-live-stream-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---live-stream-enum`, `#basic-information`, `#enumeration`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-logging-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 10 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---logging-enum`, `#basic-information`, `#logs-flow`, `#configurations-supported-by-gcp-logging`, `#list-buckets`, `#list-logs-only-logs-that-contain-log-entries-are-listed`, `#get-log-metrics`, `#get-log-sinks`, `#get-log-views`, `#list-linked-bigquery-datasets` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-looker-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---looker-enum`, `#basic-information`, `#enumeration`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-looker-studio-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---looker-studio-enum`, `#enumerate-resources`, `#what-to-review`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-lustre-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---managed-lustre-enum`, `#enumerate-resources`, `#what-to-review`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-managed-flink-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#relevant-permissions` | ### Relevant permissions | managedflink.jobs.create (into existing deployment) | EXCLUDED | `gcp-managedflink-jobs-create-actas` — no verified caller-to-workload-identity gain |
| `#persistence` | ## Persistence | - | NON-PRIVESC | persistence pointer |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---managed-flink-enum`, `#bigquery-engine-for-apache-flink-managedflinkgoogleapiscom`, `#enumeration`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-managed-kafka-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---managed-kafka-enum`, `#managed-service-for-apache-kafka`, `#enumerate-clusters-topics-consumer-groups-and-acls-read-only`, `#role--permission-map`, `#enumerate-kafka-connect-resources-read-only`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-managed-microsoft-ad-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#relevant-permissions--roles` | ### Relevant permissions / roles | - | NON-PRIVESC | AD account, not cloud identity |
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---managed-microsoft-ad-enum`, `#managed-service-for-microsoft-active-directory-managedidentitiesgoogleapiscom`, `#enumeration`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-memorystore-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 3 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---memorystore-enum`, `#memorystore`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-migration-center-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#migrationcenterassetsgetlist--cross-cloud-estate-recon-highest-value` | ### `migrationcenter.assets.get`/`.list` — cross-cloud estate recon (highest value) | - | NON-PRIVESC | cross-cloud recon |
| `#interesting-permissions-write--rolesmigrationcenteradmin-basic-editorowner` | ### Interesting permissions (write — `roles/migrationcenter.admin`, basic `editor`/`owner`) | migrationcenter.discoveryClients.create + iam.serviceAccounts.actAs | EXCLUDED | X: Migration Center discovery client bound to a service account |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---migration-center-enum`, `#migration-center`, `#enumeration-read-only--rolesmigrationcenterviewer`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-model-armor-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---model-armor-enum`, `#enumerate-resources`, `#what-to-review`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-monitoring-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 10 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---monitoring-enum`, `#basic-information`, `#policies`, `#dashboards`, `#channels`, `#snoozers`, `#enumeration`, `#remote-mcp-server`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-netapp-volumes-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---netapp-volumes-enum`, `#basic-information`, `#enumeration`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-network-intelligence-center-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---network-intelligence-center-enum`, `#basic-information`, `#connectivity-tests`, `#remote-mcp-server`, `#other-network-management-resources`, `#audit-footprint`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-network-services-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 11 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---network-services-enum`, `#basic-information`, `#enumerate-meshes-gateways-and-routes`, `#enumerate-service-extensions`, `#enumerate-agent-gateways`, `#enumerate-cloud-multicast`, `#visibility-during-enumeration`, `#attack-techniques`, `#traffic-redirection-policy-downgrade-and-service-extensions`, `#referenced-network-security-policies`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-observability-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---observability-enum`, `#google-cloud-observability-observabilitygoogleapiscom`, `#enumeration`, `#interesting-permissions`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-oracle-database-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---oracle-databasegoogle-cloud-enum`, `#oracle-databasegoogle-cloud-oracledatabasegoogleapiscom`, `#enumeration`, `#relevant-permissions`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-os-config-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---os-config-enum`, `#basic-information`, `#enumerate-project-features-patching-policies-and-reports`, `#enumerate-policy-orchestrators-at-every-possible-parent`, `#permission-and-identity-boundaries`, `#privilege-escalation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-pam-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---privileged-access-manager-pam-enum`, `#privileged-access-manager-privilegedaccessmanagergoogleapiscom`, `#onboarding`, `#enumeration`, `#relevant-permissions--roles`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-parallelstore-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---parallelstore-enum`, `#enumerate-resources`, `#what-to-review`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-parameter-manager-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---parameter-manager-enum`, `#parameter-manager-parametermanagergoogleapiscom`, `#enumeration`, `#relevant-permissions`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-personalized-service-health-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---personalized-service-health-enum`, `#basic-information`, `#enumeration`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-policy-troubleshooter-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---policy-troubleshooter-enum`, `#policy-troubleshooter-policytroubleshootergoogleapiscom`, `#enumeration`, `#relevant-permissions-and-roles`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-private-catalog-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---private-catalog-enum`, `#private-catalog-cloudprivatecataloggoogleapiscom--cloudprivatecatalogproducergoogleapiscom`, `#enumeration`, `#relevant-permissions--roles`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-pub-sub.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 9 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---pubsub-enum`, `#pubsub`, `#snapshots--schemas`, `#enumeration`, `#privilege-escalation--post-exploitation`, `#persistence`, `#unauthenticated-access`, `#pubsub-lite`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-recaptcha-enterprise-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---recaptcha-enterprise-enum`, `#recaptcha-enterprise-recaptchaenterprisegoogleapiscom`, `#enumeration`, `#relevant-permissions--roles`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-recommender-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---recommender-enum`, `#basic-information`, `#enumeration`, `#remote-mcp-server`, `#audit-footprint`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-runtimeconfig-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---runtime-configurator-enum`, `#enumerate-resources`, `#what-to-review`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-secrets-manager-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 9 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---secrets-manager-enum`, `#secret-manager`, `#enumeration`, `#privilege-escalation`, `#post-exploitation`, `#persistence`, `#unauthenticated-access`, `#rotation-misuse`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-secure-source-manager-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#remote-mcp-attack-surface` | ### Remote MCP attack surface | securesourcemanager.repositories.push, securesourcemanager.repositories.setIamPolicy, securesourcemanager.instances.setIamPolicy | COVERED | `gcp-securesourcemanager-push-cicd`, `gcp-securesourcemanager-setiampolicy` |
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---secure-source-manager-enum`, `#secure-source-manager`, `#enumeration`, `#relevant-permissions`, `#post-exploitation--privesc`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-security-command-center-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 13 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---security-command-center-enum`, `#security-command-center-securitycentergoogleapiscom--securitycentermanagementgoogleapiscom`, `#tiers-decide-what-exists-at-all`, `#the-console-surface`, `#built-in-detection-services-the-authoritative-list`, `#detector-data-sources-the-blind-spot-map`, `#findings-sources-mute-configs-and-exports`, `#relevant-permissions--roles`, `#other-security-console-entries-with-no-dedicated-page`, `#privilege-escalation`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-sensitive-data-protection-dlp-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---sensitive-data-protection-dlp-enum`, `#sensitive-data-protection--dlp-dlpgoogleapiscom`, `#enumeration`, `#relevant-permissions--roles`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-service-directory-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---service-directory-enum`, `#basic-information`, `#enumerate-namespaces-services-endpoints-and-resolved-answers`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-service-usage-and-service-management-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---service-usage-and-service-management-enum`, `#enumerate-resources`, `#what-to-review`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-source-repositories-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 9 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---source-repositories-enum`, `#basic-information`, `#offsec-information`, `#open-in-cloud-shell`, `#enumeration`, `#privilege-escalation--post-exploitation`, `#unauthenticated-enum`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-spanner-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---spanner-enum`, `#cloud-spanner`, `#privilege-escalation-and-persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-stackdriver-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---stackdriver-enum`, `#cloud-logging`, `#what-may-be-exposed`, `#iam-checks`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-storage-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 16 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---storage-enum`, `#storage`, `#storage-types`, `#access-control`, `#versioning`, `#retention-policy`, `#encryption`, `#public-access`, `#hmac-keys`, `#enumeration`, `#privilege-escalation`, `#unauthenticated-enum`, `#storage-insights---inventory-reports-recon`, `#post-exploitation`, `#persistence`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-storage-transfer-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---storage-transfer-enum`, `#basic-information`, `#enumeration`, `#privilege-escalation--post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-telemetry-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---telemetry-api-enum`, `#telemetry-otlp-api-telemetrygoogleapiscom`, `#permissions-and-roles`, `#test-log-ingestion-safely`, `#offensive-implications`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-trace-profiler-error-reporting-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 10 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---trace-profiler--error-reporting-enum`, `#basic-information`, `#enumeration`, `#cloud-trace--leaked-urls--params--tokens`, `#cloud-trace-remote-mcp-server`, `#error-reporting--stack-traces--exception-messages`, `#error-reporting-remote-mcp-server`, `#cloud-profiler--code--deployment-structure`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-transcoder-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---transcoder-enum`, `#basic-information`, `#enumeration`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-unified-maintenance-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---unified-maintenance-enum`, `#basic-information`, `#enumeration`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-vertex-ai-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 27 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vertex-ai-enum`, `#vertex-ai`, `#agent-engine--reasoning-engine`, `#key-components`, `#models`, `#endpoints`, `#custom-jobs`, `#hyperparameter-tuning-jobs`, `#model-garden`, `#tensorboards`, `#service-accounts--permissions`, `#data-storage`, `#encryption`, `#networking`, `#enumeration`, `#model-information-gathering`, `#endpoint-details`, `#custom-job-information`, `#access-control`, `#storage-and-artifacts`, `#model-garden-1`, `#feature-store--vector-search-data-plane-read-surfaces`, `#rag-engine-resources-and-service-identity`, `#semantic-governance-policies-and-enforcement-chain`, `#privilege-escalation`, `#post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-vertex-ai-search-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 7 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vertex-ai-search-discovery-engine-enum`, `#vertex-ai-search--agent-builder-discoveryenginegoogleapiscom`, `#enumeration`, `#resource-level-iam`, `#role--permission-map`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-vm-migration-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vm-migration-enum`, `#migrate-to-virtual-machines`, `#enumeration`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-vmwareengine-gcve-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 5 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vmware-engine-gcve-enum`, `#vmware-engine`, `#enumerate-private-clouds-clusters-and-network-exposure`, `#related-offensive-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-vpc-service-controls-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---vpc-service-controls-enum`, `#vpc-service-controls-accesscontextmanagergoogleapiscom`, `#enumeration`, `#privilege-escalation`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-web-security-scanner-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---web-security-scanner-enum`, `#web-security-scanner-websecurityscannergoogleapiscom`, `#enumeration`, `#scanner-as-recon-the-practical-primitive`, `#hardening--negative-results-do-not-chase-these`, `#relevant-permissions--roles`, `#attack-techniques`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-workflows-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 6 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---workflows-enum`, `#basic-information`, `#encryption`, `#enumeration`, `#privesc-and-post-exploitation`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-workspace-addons-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---google-workspace-add-ons-enum`, `#google-workspace-add-ons`, `#inventory`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-to-workspace-pivoting/README.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#from-gcp-to-gws` | ## **From GCP to GWS** | - | EXCLUDED | X: Section intro |
| `#agent-identity-auth-manager-credentials` | ### Agent Identity auth-manager credentials | - | EXCLUDED | X: Agent Identity pointer |
| `#application-integration-credential-access` | ### Application Integration credential access | - | EXCLUDED | X: Application Integration pointer |
| `#workspace-http-add-on-deployment-takeover` | ### Workspace HTTP Add-on Deployment Takeover | - | EXCLUDED | X: Add-on takeover pointer |
| `#domain-wide-delegation-basics` | ### **Domain Wide Delegation basics** | - | EXCLUDED | X: DWD basics |
| `#compromise-existing-delegation` | ### Compromise existing delegation | as on page heading (Compromise existing delegation) | COVERED | `gcp-workspace-dwd-key-create` |
| `#keyless-dwd-abuse-with-signjwt-or-signblob` | #### Keyless DWD abuse with `signJwt` or `signBlob` | as on page heading (Keyless DWD abuse with `signJwt` or `signBlob`) | COVERED | `gcp-workspace-dwd-keyless-signjwt` |
| `#direct-service-account-workspace-resources-without-dwd` | #### Direct service-account Workspace resources without DWD | - | EXCLUDED | X: SA-owned Workspace resources without DWD |
| `#gcp-generate-delegation-token` | #### [GCP Generate Delegation Token](https://github.com/carlospolop/gcp_gen_delegation_token) | - | EXCLUDED | X: Delegation token tool |
| `#delepwn` | #### [**DelePwn**](https://github.com/n0tspam/delepwn) | - | EXCLUDED | X: DelePwn tool |
| `#delefriend` | #### [**DeleFriend**](https://github.com/axon-git/DeleFriend) | - | EXCLUDED | X: DeleFriend tool |
| `#gitlabs-python-script` | #### [Gitlab's Python script](https://gitlab.com/gitlab-com/gl-security/security-operations/redteam/redteam-public/pocs/gcp_misc/-/blob/master/gcp_delegation.py) | - | EXCLUDED | X: GitLab script |
| `#create-a-new-delegation-persistence` | ### Create a new delegation (Persistence) | - | EXCLUDED | X: Create a new delegation |
| `#cross-organizational-delegation` | #### Cross-Organizational delegation | - | EXCLUDED | X: Cross-organization delegation |
| `#creating-a-project-to-enumerate-workspace` | ### Creating a Project to enumerate Workspace | - | EXCLUDED | X: Create project to enumerate Workspace |
| `#cloud-dns-to-workspace-administrator-recovery` | ### Cloud DNS to Workspace administrator recovery | as on page heading (Cloud DNS to Workspace administrator recovery) | COVERED | `gcp-workspace-cloud-dns-admin-recovery` |
| `#abusing-gcloud-credentials` | ### Abusing Gcloud credentials | - | EXCLUDED | X: Abusing gcloud credentials |
| `#from-gws-to-gcp` | ## From GWS to GCP | - | EXCLUDED | X: Section intro |
| `#workspace-super-administrator-to-gcp-organization-administrator` | ### Workspace super administrator to GCP Organization Administrator | as on page heading (Workspace super administrator to GCP Organization Administrator) | EXCLUDED | gcp-workspace-super-admin-org-admin Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#access-privileged-gcp-users` | ### Access privileged GCP users | Workspace admin (reset passwords) | EXCLUDED | gcp-v3-44-workspace-admin-resets-a-tenant-user-s-password-or-adds-it (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#google-groups-privilege-escalation` | ### Google Groups Privilege Escalation | group self-join | EXCLUDED | gcp-groups-self-join-open-group (NS-1, implemented in schema v1.1) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#references` | ## References | - | EXCLUDED | X: References section |
| (structural) | 1 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp--workspace-pivoting` |

### `src/pentesting-cloud/gcp-security/gcp-to-workspace-pivoting/gcp-agent-identity-auth-manager-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#agent-identity-auth-manager` | ## Agent Identity auth manager | - | EXCLUDED | X: Page intro |
| `#read-only-enumeration-and-no-list-fallback` | ## Read-only enumeration and no-list fallback | - | EXCLUDED | X: Enumeration |
| `#agentidentityauthprovidersretrievecredentials` | ## `agentidentity.authProviders.retrieveCredentials` | agentidentity.authProviders.retrieveCredentials | COVERED | `gcp-agentidentity-retrieve-credentials` |
| `#conditional-gcp-to-workspace-pivot` | ### Conditional GCP to Workspace pivot | - | EXCLUDED | X: Conditional pivot explanation |
| `#agentidentityauthprovidersupdate-token-endpoint-interception` | ## `agentidentity.authProviders.update` token-endpoint interception | agentidentity.authProviders.update | COVERED | `gcp-agentidentity-update-token-url` |
| `#references` | ## References | - | EXCLUDED | X: References section |
| (structural) | 1 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---agent-identity-auth-manager-credential-access` |

### `src/pentesting-cloud/gcp-security/gcp-to-workspace-pivoting/gcp-application-integration-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#application-integration` | ## Application Integration | - | EXCLUDED | X: Page intro |
| `#read-only-enumeration-and-no-list-fallback` | ## Read-only enumeration and no-list fallback | - | EXCLUDED | X: Enumeration |
| `#integrationsauthconfigsget--retrieve-decrypted-credentials` | ## `integrations.authConfigs.get` — retrieve decrypted credentials | integrations.authConfigs.get | NEEDS-SCHEMA | gcp-appintegration-authconfigs-get-decrypted Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#integrationsintegrationsinvoke--invoke-a-credentialed-workflow` | ## `integrations.integrations.invoke` — invoke a credentialed workflow | integrations.integrations.invoke | EXCLUDED | X: Invoke existing integration<br>`gcp-integration-invoke-input-effect-12` — conditional verified exact-target authority. |
| `#http-connector-credential-forwarding` | ### HTTP connector credential forwarding | - | EXCLUDED | X: HTTP connector credential forwarding<br>`gcp-integration-invoke-input-effect-13` — conditional verified exact-target authority. |
| `#runasserviceaccount--author--publish-an-integration-that-runs-as-an-arbitrary-sa` | ## `runAsServiceAccount` — author + publish an integration that runs as an arbitrary SA | as on page heading (`runAsServiceAccount` — author + publish an integration that runs as an arbitrary SA) | COVERED | `gcp-appintegration-runas-sa-actas` |
| `#references` | ## References | - | EXCLUDED | X: References section |
| (structural) | 1 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---application-integration-credential-access` |

### `src/pentesting-cloud/gcp-security/gcp-to-workspace-pivoting/gcp-understanding-domain-wide-delegation.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#understanding-domain-wide-delegation` | ## **Understanding Domain-Wide Delegation** | - | EXCLUDED | X: DWD explainer |
| `#domain-wide-delegation-under-the-hood` | ### **Domain-Wide Delegation: Under the Hood** | - | EXCLUDED | X: DWD internals |
| `#references` | ## References | - | EXCLUDED | X: References section |
| (structural) | 1 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---understanding-domain-wide-delegation` |

### `src/pentesting-cloud/gcp-security/gcp-to-workspace-pivoting/gcp-workspace-addons-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#google-workspace-add-ons` | ## Google Workspace add-ons | - | EXCLUDED | X: Page intro (Google Workspace add-ons) |
| `#gsuiteaddonsdeploymentsupdate` | ## `gsuiteaddons.deployments.update` | gsuiteaddons.deployments.update | COVERED | `gcp-workspace-addons-deployment-update` |
| `#preconditions` | ### Preconditions | - | EXCLUDED | X: Preconditions |
| `#enumerate-safely` | ### Enumerate safely | - | EXCLUDED | X: Enumeration |
| `#authorized-lab-proof` | ### Authorized-lab proof | - | EXCLUDED | X: Lab proof |
| `#references` | ### References | - | EXCLUDED | X: References section |
| (structural) | 1 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---workspace-add-on-deployment-takeover` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/README.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 12 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---unauthenticated-enum--access`, `#gcp`, `#technique-categories`, `#resource-bruteforce-or-takeover`, `#public-resource-name-discovery`, `#public-resources-brute-force`, `#buckets-firebase-apps--cloud-functions`, `#potential-credential-leaks`, `#google-api-keys`, `#bearer-identity-tokens`, `#service-account-private-keys`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-api-gateway-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#api-gateway` | ## API Gateway | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#publicly-shared-data` | ## Publicly shared data | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#anonymous-mcp-toolslist--enumerate-operations-and-input-schemas` | ### Anonymous MCP `tools/list` — enumerate operations and input schemas | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#anonymous-invocation-and-modification` | ## Anonymous invocation and modification | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#probe-routes-with-no-authentication-configured` | ### Probe routes with no authentication configured | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#discover-public-gateway-hostnames` | ## Discover public gateway hostnames | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---api-gateway-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-api-keys-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#api-keys` | ## API Keys | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#public-reconnaissance` | ## Public reconnaissance | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#project-identifiers-in-public-client-configuration` | ### Project identifiers in public client configuration | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#potential-credential-leaks` | ## Potential credential leaks | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#google-api-keys` | ### Google API keys | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#service-account-private-keys` | ### Service-account private keys | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#object-authorization-for-key-authenticated-applications` | ## Object authorization for key-authenticated applications | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---api-keys-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-apigee-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#apigee` | ## Apigee | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#anonymous-invocation-and-modification` | ## Anonymous invocation and modification | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#probe-proxies-missing-an-auth-policy` | ### Probe proxies missing an auth policy | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#self-registration-and-guest-access` | ## Self-registration and guest access | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#developer-portal-self-service-key-registration` | ### Developer-portal self-service key registration | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#resource-bruteforce-or-takeover` | ## Resource bruteforce or takeover | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#discover-public-api-proxies` | ### Discover public API proxies | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---apigee-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-app-engine-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#app-engine` | ## App Engine | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#resource-bruteforce-or-takeover` | ## Resource bruteforce or takeover | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#brute-force-subdomains` | ### Brute Force Subdomains | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---app-engine-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-artifact-registry-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#artifact-registry` | ## Artifact Registry | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#publicly-shared-data` | ## Publicly shared data | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#anonymous-pull-from-a-public-repository` | ### Anonymous pull from a public repository | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#dependency-confusion` | ## Dependency Confusion | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---artifact-registry-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-bigquery-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#bigquery` | ## BigQuery | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#publicly-shared-data` | ## Publicly shared data | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#dataset-shared-with-allauthenticatedusers--read-from-an-unrelated-account` | ### Dataset shared with `allAuthenticatedUsers` — read from an unrelated account | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---bigquery-unauthenticated-enum-and-external-access`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-bigtable-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#bigtable-and-spanner` | ## Bigtable and Spanner | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#publicly-shared-data` | ## Publicly shared data | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#cloud-spanner--fine-grained-access-control-compound-misconfig` | ### Cloud Spanner — fine-grained access control (compound misconfig) | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#tables-granted-bigtabletablesreadrows-to-allusers--allauthenticatedusers` | ### Tables granted `bigtable.tables.readRows` to `allUsers` / `allAuthenticatedUsers` | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---bigtable-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-cloud-build-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloud-build` | ## Cloud Build | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#cloudbuildyml` | ### cloudbuild.yml | no GCP perm; attacker opens external PR / pushes to monitored repo where trigger comment control = Not required | EXCLUDED | NS-5 REJECTED as a privesc edge: CSPM check (external SCM contributor, no principal source) (_excluded) |
| `#pr-approvals` | ### PR Approvals | no GCP perm; attacker opens external PR / pushes to monitored repo where trigger comment control = Not required | EXCLUDED | NS-5 REJECTED as a privesc edge: CSPM check (external SCM contributor, no principal source) (_excluded) |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-build-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-cloud-endpoints-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloud-endpoints` | ## Cloud Endpoints | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#anonymous-invocation-and-modification` | ## Anonymous invocation and modification | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#probe-routes-with-no-security-requirement` | ### Probe routes with no security requirement | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#resource-bruteforce-or-takeover` | ## Resource bruteforce or takeover | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#discover-endpoints-hostnames` | ### Discover Endpoints hostnames | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-endpoints-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-cloud-functions-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloud-functions` | ## Cloud Functions | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#anonymous-invocation-and-modification` | ## Anonymous invocation and modification | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#public-function-invocation` | ### Public function invocation | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#resource-bruteforce-or-takeover` | ## Resource bruteforce or takeover | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#brute-force-urls` | ### Brute Force URls | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#authorized-inventory-audit-of-public-invocation` | ## Authorized inventory audit of public invocation | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-functions-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-cloud-run-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloud-run` | ## Cloud Run | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#anonymous-invocation-and-modification` | ## Anonymous invocation and modification | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#public-cloud-run-invocation` | ### Public Cloud Run invocation | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#resource-bruteforce-or-takeover` | ## Resource bruteforce or takeover | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#claim-a-released-cloudrun-custom-url` | ### Claim a released `*.cloud.run` custom URL | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#authorized-inventory-audit-of-public-invocation` | ## Authorized inventory audit of public invocation | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-run-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-cloud-sql-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloud-sql` | ## Cloud SQL | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#brute-force` | ## Brute Force | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-sql-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-cloud-tasks-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloud-tasks-and-cloud-scheduler` | ## Cloud Tasks and Cloud Scheduler | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#cloud-scheduler--forced-job-run` | ## Cloud Scheduler — forced job run | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#queues-granted-cloudtaskstaskscreate-to-allusers--allauthenticatedusers` | ## Queues granted `cloudtasks.tasks.create` to `allUsers` / `allAuthenticatedUsers` | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-tasks-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-compute-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#compute` | ## Compute | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#ssrf---server-side-request-forgery` | ## SSRF - Server Side Request Forgery | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#vulnerable-exposed-services` | ## Vulnerable exposed services | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---compute-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-dns-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#cloud-dns` | ## Cloud DNS | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#dangling-records-and-ownership-checks` | ## Dangling records and ownership checks | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#public-dns-asset-discovery` | ## Public DNS asset discovery | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---cloud-dns-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-firebase-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#firebase` | ## Firebase | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#public-reconnaissance` | ## Public reconnaissance | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#public-project-configuration` | ### Public project configuration | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#publicly-shared-data` | ## Publicly shared data | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#data-exposed-by-permissive-rules` | ### Data exposed by permissive rules | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#anonymous-invocation-and-modification` | ## Anonymous invocation and modification | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#writes-exposed-by-permissive-rules` | ### Writes exposed by permissive rules | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#potential-credential-leaks` | ## Potential credential leaks | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#google-api-keys` | ### Google API keys | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#self-registration-and-guest-access` | ## Self-registration and guest access | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#anonymous-sign-up--bypass-if-requestauth--null-rules` | ### Anonymous sign-up → bypass `if request.auth != null` rules | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---firebase-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-gke-kubelet-unauthenticated-access.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#gke--kubernetes` | ## GKE / Kubernetes | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#publicly-shared-data` | ## Publicly shared data | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#historical-kubelet-read-only-metadata` | ### Historical kubelet read-only metadata | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---historical-kubelet-read-only-api-exposure`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-google-groups-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#google-groups` | ## Google Groups | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#read-a-publicly-visible-group-archive` | ### Read a publicly visible group archive | - | NON-PRIVESC | public data read |
| `#join-a-publicly-open-iam-bound-group-without-victim-tenant-access` | ### Join a publicly open IAM-bound group without victim-tenant access | none (group open to join) | NEEDS-SCHEMA | gcp-groups-self-join-open-group (NS-1, implemented in schema v1.1) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| (structural) | 4 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---google-groups-unauthenticated-enum-and-access`, `#publicly-shared-data`, `#self-registration-and-guest-access`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-healthcare-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#healthcare-api` | ## Healthcare API | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#publicly-shared-data` | ## Publicly shared data | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#read-phi-from-a-store-shared-with-allauthenticatedusers` | ### Read PHI from a store shared with `allAuthenticatedUsers` | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---healthcare-api-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-iam-principals-and-org-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#iam-and-organizations` | ## IAM and Organizations | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#public-reconnaissance` | ## Public reconnaissance | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#is-domain-used-in-workspace` | ### Is domain used in Workspace? | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#service-account-response-hints` | ### Service-account response hints | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#authenticated-principal-validation` | ## Authenticated principal validation | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---iam-principals--org-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-iap-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#iap` | ## IAP | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#authentication-and-access-control-bypass` | ## Authentication and access-control bypass | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#allusers--rolesiaphttpsresourceaccessor-bypass` | ### `allUsers` → `roles/iap.httpsResourceAccessor` bypass | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---iap-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-looker-studio-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#looker-studio` | ## Looker Studio | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#publicly-shared-data` | ## Publicly shared data | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#public-link-report-data-exposure` | ### Public-link report data exposure | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---looker-studio-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-pub-sub-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#pubsub` | ## Pub/Sub | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#publicly-shared-data` | ## Publicly shared data | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#subscriptions-shared-with-external-identities` | ### Subscriptions shared with external identities | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#external-authenticated-publishing` | ## External authenticated publishing | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---pubsub-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-secret-manager-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#secret-manager` | ## Secret Manager | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#publicly-shared-data` | ## Publicly shared data | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#read-a-secret-shared-with-allusers--allauthenticatedusers` | ### Read a secret shared with `allUsers` / `allAuthenticatedUsers` | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---secret-manager-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-source-repositories-unauthenticated-enum.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#source-repositories` | ## Source Repositories | - | NON-PRIVESC | unauthenticated exposure/recon/data |
| `#compromise-external-repository` | ### Compromise External Repository | no GCP perm; write to external upstream repo mirrored/triggering builds | EXCLUDED | NS-5 REJECTED as a privesc edge: CSPM check (external SCM contributor, no principal source) (_excluded) |
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---source-repositories-unauthenticated-enum`, `#references` |

### `src/pentesting-cloud/gcp-security/gcp-unauthenticated-enum-and-access/gcp-storage-unauthenticated-enum/README.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 8 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp---storage-unauthenticated-enum`, `#storage`, `#publicly-shared-data`, `#public-object-reads-and-listings`, `#resource-bruteforce-or-takeover`, `#public-bucket-brute-force`, `#search-open-buckets-in-current-account`, `#references` |

### `src/pentesting-cloud/gcp-security/permission-risk-categorizations.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| (structural) | 2 title/intro/enumeration/pointer headings | - | STRUCTURAL | `#gcp-permissions-categories`, `#canonical-yaml` |


## GCP v3 challenge additions

These sections require exact reviewed evidence; missing facts remain UNKNOWN.

### `src/pentesting-cloud/workspace-security/gws-admin-privesc.md`

| `#grant-yourselfan-account-a-privileged-admin-role` | Assign a stronger Workspace administrator role to a controlled account | exact source/target proof | EXCLUDED | gcp-v3-08-assign-a-stronger-workspace-administrator-role-to-a-contro (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-admin-persistence.md`

| `#domain-wide-delegation-grant-to-an-attacker-service-account` | Authorize an attacker-controlled service-account OAuth client for Workspace domain-wide delegation | exact source/target proof | EXCLUDED | gcp-v3-09-authorize-an-attacker-controlled-service-account-oauth-cli (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-admin-persistence.md`

| `#marketplace-app-domain-install--oauth-app-trusted-allow-listing` | Install or trust an attacker OAuth app across a Workspace domain | exact source/target proof | EXCLUDED | gcp-v3-10-install-or-trust-an-attacker-oauth-app-across-a-workspace (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-admin-persistence.md`

| `#sso--saml-sign-in-profile-tampering` | Point Workspace SSO at an attacker-controlled identity provider | exact source/target proof | EXCLUDED | gcp-v3-11-point-workspace-sso-at-an-attacker-controlled-identity-pro (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-google-platforms-phishing/gws-app-scripts.md`

| `#shared-document-script-ownership` | Modify a bound Apps Script that later runs under its owner’s authorization | exact source/target proof | EXCLUDED | gcp-v3-12-modify-a-bound-apps-script-that-later-runs-under-its-owner (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-workspace-sync-attacks-gcpw-gcds-gps-directory-sync-with-ad-and-entraid/gcds-google-cloud-directory-sync.md`

| `#gcds---disk-tokens--ad-credentials` | Recover GCDS administrator OAuth and directory credentials from host configuration | exact source/target proof | EXCLUDED | gcp-v3-13-recover-gcds-administrator-oauth-and-directory-credentials (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-workspace-sync-attacks-gcpw-gcds-gps-directory-sync-with-ad-and-entraid/gcpw-google-credential-provider-for-windows.md`

| `#gcpw---registry-refresh-tokens` | Recover another GCPW user’s Google refresh token or password | exact source/target proof | EXCLUDED | gcp-v3-14-recover-another-gcpw-user-s-google-refresh-token-or-passwo (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-workspace-sync-attacks-gcpw-gcds-gps-directory-sync-with-ad-and-entraid/gcpw-google-credential-provider-for-windows.md`

| `#gcpw---mitm` | Intercept a GCPW user’s Google authorization response during sign-in | exact source/target proof | EXCLUDED | gcp-v3-15-intercept-a-gcpw-user-s-google-authorization-response-duri (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-workspace-sync-attacks-gcpw-gcds-gps-directory-sync-with-ad-and-entraid/gps-google-password-sync.md`

| `#gps---dumping-password-and-token-from-disk` | Recover Password Sync administrator OAuth or AD credentials from its host | exact source/target proof | EXCLUDED | gcp-v3-16-recover-password-sync-administrator-oauth-or-ad-credential (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-workspace-sync-attacks-gcpw-gcds-gps-directory-sync-with-ad-and-entraid/gws-admin-directory-sync.md`

| `#attacking-groups` | Join a GCP IAM-bound Workspace group by changing its synchronized external-directory group | exact source/target proof | EXCLUDED | gcp-v3-17-join-a-gcp-iam-bound-workspace-group-by-changing-its-synch (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-admin-privesc.md`

| `#create-a-new-super-admin` | Create a second Google Workspace Super Admin | exact source/target proof | EXCLUDED | gcp-v3-18-create-a-second-google-workspace-super-admin (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-google-platforms-phishing/gws-app-scripts.md`

| `#abusing-shared-with-me-documents` | Edit a shared Apps Script that still has another user’s installable trigger | exact source/target proof | EXCLUDED | gcp-v3-19-edit-a-shared-apps-script-that-still-has-another-user-s-in (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-workspace-sync-attacks-gcpw-gcds-gps-directory-sync-with-ad-and-entraid/gcds-google-cloud-directory-sync.md`

| `#gcds---dumping-tokens-from-memory` | Extract GCDS OAuth or AD credentials from process memory | exact source/target proof | EXCLUDED | gcp-v3-20-extract-gcds-oauth-or-ad-credentials-from-process-memory (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-workspace-sync-attacks-gcpw-gcds-gps-directory-sync-with-ad-and-entraid/gcpw-google-credential-provider-for-windows.md`

| `#gcpw---disk-refresh-tokens` | Recover Chrome profile refresh tokens on a GCPW workstation | exact source/target proof | EXCLUDED | gcp-v3-21-recover-chrome-profile-refresh-tokens-on-a-gcpw-workstatio (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-workspace-sync-attacks-gcpw-gcds-gps-directory-sync-with-ad-and-entraid/gcpw-google-credential-provider-for-windows.md`

| `#gcpw---dumping-tokens-from-processes-memory` | Recover Google tokens from browser process memory on a GCPW workstation | exact source/target proof | EXCLUDED | gcp-v3-22-recover-google-tokens-from-browser-process-memory-on-a-gcp (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-workspace-sync-attacks-gcpw-gcds-gps-directory-sync-with-ad-and-entraid/gcpw-google-credential-provider-for-windows.md`

| `#gcpw---recovering-clear-text-password` | Recover a GCPW account password from the Windows LSA secret | exact source/target proof | EXCLUDED | gcp-v3-23-recover-a-gcpw-account-password-from-the-windows-lsa-secre (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-workspace-sync-attacks-gcpw-gcds-gps-directory-sync-with-ad-and-entraid/gps-google-password-sync.md`

| `#gps---dumping-tokens-from-memory` | Extract Password Sync OAuth or AD credentials from process memory | exact source/target proof | EXCLUDED | gcp-v3-24-extract-password-sync-oauth-or-ad-credentials-from-process (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-google-platforms-phishing/README.md`

| `#app-password-phishing` | Phish a Workspace user into issuing and disclosing an app password | exact source/target proof | EXCLUDED | gcp-v3-25-phish-a-workspace-user-into-issuing-and-disclosing-an-app (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-google-platforms-phishing/README.md`

| `#oauth-apps-phishing` | Obtain delegated user tokens through consent to an attacker OAuth app | exact source/target proof | EXCLUDED | gcp-v3-26-obtain-delegated-user-tokens-through-consent-to-an-attacke (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-google-platforms-phishing/README.md`

| `#manual-authorization-response-relay` | Relay a victim’s OAuth authorization code or callback URL | exact source/target proof | EXCLUDED | gcp-v3-27-relay-a-victim-s-oauth-authorization-code-or-callback-url (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-google-platforms-phishing/gws-app-scripts.md`

| `#leak-token` | Exfiltrate an Apps Script OAuth token after victim authorization | exact source/target proof | EXCLUDED | gcp-v3-28-exfiltrate-an-apps-script-oauth-token-after-victim-authori (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-workspace-sync-attacks-gcpw-gcds-gps-directory-sync-with-ad-and-entraid/gcpw-google-credential-provider-for-windows.md`

| `#gcpw---get-tokens` | Recover another user’s GCPW refresh token or stored Google password | exact source/target proof | EXCLUDED | gcp-v3-29-recover-another-user-s-gcpw-refresh-token-or-stored-google (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-application-design-center-enum.md`

| `#remote-mcp-server` | Deploy caller-controlled infrastructure as a selected service account through Application Design Center | exact source/target proof | EXCLUDED | gcp-v3-49-deploy-caller-controlled-infrastructure-as-a-selected-serv (exact evidence; conditional) Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |


## Additive v4 reviewed mappings (HackTricks Cloud 4913b6d88ced9972f72ccdd708d21641725a6fb5)

The totals above describe the historical heading sweep. The following rows bind newly admitted conditional entries to their authored source anchors; the original rows remain intact.

### `src/pentesting-cloud/gcp-security/gcp-basic-information/README.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#service-accounts` | Read attached VM SA token from metadata after host access | EXCLUDED | gcp-compromised-vm-metadata-sa-token — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-cross-project-attacks/historical-cross-project-vulnerabilities.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#managed-service-tenant--host-escapes` | Unauthenticated Dataproc YARN UI submits job as cluster identity | EXCLUDED | gcp-dataproc-yarn-unauthenticated-job — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#federation-and-metadata-server-abuse` | Compromised pod reads node SA token or legacy kube-env from metadata | EXCLUDED | gcp-gke-pod-node-metadata-token — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-cross-project-attacks/iam-and-service-account-impersonation-attacks.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#service-account-impersonation--the-crown-jewel` | Mint OIDC ID token to invoke protected endpoint as SA | EXCLUDED | gcp-sa-getopenidtoken-protected-endpoint — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-bigquery-post-exploitation.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#bigquerytablesgetdata--paginate-an-entire-table-without-running-a-query` | Read BigQuery table rows | COVERED | `gcp-bigquery-table-row-credential` — conditional exact-target evidence; authored source revision `0b36331`. |

### `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-bigtable-post-exploitation.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#read-base-table-rows` | Read Bigtable base-table rows | COVERED | `gcp-bigtable-row-credential` — conditional exact-target evidence; authored source revision `0b36331`. |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-container-privesc.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#containerpodsattach` | Use attach to control an interactive process in a running pod | EXCLUDED | gcp-container-pods-attach-running-ksa — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#workload-and-pod-create--update-permissions` | Reach the KSA of an existing pod by changing its container image | COVERED | `gcp-container-pods-update-running-ksa` — conditional exact-target evidence; authored source revision `0b36331`. |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-private-catalog-privesc.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#cloudprivatecatalogproducerproductsupdate--poison-an-existing-deployable-solution-version` | Poison a Terraform solution deployed by a consumer | EXCLUDED | gcp-privatecatalog-terraform-version-poison — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-run-privesc.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#plaintext-environment-disclosure-with-cloud-run-read-permissions` | Plaintext credential theft | EXCLUDED | gcp-run-literal-sa-key-disclosure — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-secretmanager-privesc.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#secretmanagersecretssetiampolicy` | Secret IAM self-grant to credential theft | COVERED | `gcp-secretmanager-secrets-setiampolicy-secret-self-grant` |
| `#escalation-through-a-recovered-secret` | Stored credential theft | EXCLUDED | gcp-secretmanager-versions-access-sa-key — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-parameter-manager-enum.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#relevant-permissions` | Render a template version to recover a stronger credential | EXCLUDED | gcp-parametermanager-template-render-credential — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#relevant-permissions` | Render a parameter version to recover a stronger credential | EXCLUDED | gcp-parametermanager-version-render-credential — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |
| `#relevant-permissions` | Insert a secret reference and render it through Parameter Manager identity | EXCLUDED | gcp-parametermanager-write-reference-render-credential — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-secure-source-manager-enum.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#relevant-permissions` | Clone a repository containing a stronger cloud credential | EXCLUDED | gcp-securesourcemanager-fetch-committed-credential — conditional exact-target evidence; authored source revision `0b36331`.<br>gcp-securesourcemanager-hook-oidc-token — conditional verified exact-target authority. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-sensitive-data-protection-dlp-enum.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#enumeration` | Read quoted credentials from DLP job findings of a GCP service account | EXCLUDED | gcp-dlp-job-quote-sa-credential — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-storage-enum.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#enumeration` | Read credential from Storage object or older generation of a GCP service account | EXCLUDED | gcp-storage-object-sa-credential — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-vertex-ai-enum.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#custom-job-information` | Read inline credentials in custom-job environment of a GCP service account | EXCLUDED | gcp-vertex-customjob-env-sa-credential — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-workflows-enum.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#enumeration` | Read credential from workflow execution arguments or results of a GCP service account | EXCLUDED | gcp-workflows-execution-sa-credential — conditional exact-target evidence; authored source revision `0b36331`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-admin-privesc.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#account-takeover-reset-password--strip-2-step-verification` | Take over a Workspace user with password reset and 2SV control | EXCLUDED | gcp-workspace-admin-password-reset-2sv-takeover — conditional exact-target evidence; authored source revision `unspecified`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/workspace-security/gws-workspace-sync-attacks-gcpw-gcds-gps-directory-sync-with-ad-and-entraid/gws-admin-directory-sync.md`

| Anchor | Heading | Status | Mapping / review |
|---|---|---|---|
| `#attacking-users` | Claim a newly synced Workspace user through its activation mailbox | EXCLUDED | gcp-workspace-directory-sync-activation-mailbox — conditional exact-target evidence; authored source revision `unspecified`. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |


### `src/pentesting-cloud/gcp-security/gcp-basic-information/README.md`
| `#remove` | gcp-pab-delete-unblock-allow | NON-PRIVESC | gcp-pab-delete-unblock-allow — conditional exact-target evidence required. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

### `src/pentesting-cloud/gcp-security/gcp-services/gcp-deployment-manager-enum.md`
| `#what-to-review` | gcp-deploymentmanager-manifest-credential | EXCLUDED | gcp-deploymentmanager-manifest-credential — conditional exact-target evidence required. Review 2026-10-16: plain-text IDs above are excluded from the active catalog. |

## 2026-10-16 principal-to-principal review

The historical `COVERED` rows above record prior catalog decisions. The current active catalog is the YAML under `peaso/privesc/catalog/gcp`, checked against the exact-principal and additional-effective-permission rule. It contains 169 active entries after this review. We excluded 22 terminal or saved-action effects, 71 entries with no declared source permission/action, and 19 entries that rely on untyped challenge evidence for a concrete principal gain. Entries with a concrete source action and a specific service-to-principal relationship remain defined even where current inventory cannot resolve the target; the graph must suppress memberless unknown nodes. Those exclusions are recorded with individual reasons in `_excluded.yaml`. Every remaining active entry has a nonempty `requires` action and cites an existing heading under `gcp-privilege-escalation/` in the [HackTricks Cloud PR #472](https://github.com/HackTricks-wiki/hacktricks-cloud/pull/472) worktree. Of the 34 new headings, the subset backed by current exact target evidence remains active; the others document conditional hypotheses but are excluded from automated paths until typed proof or attachment collection is implemented.

Seven unambiguous terminal techniques were moved from privilege-escalation sections to post-exploitation sections in that PR. Their old headings remain as link stubs so historical anchors still resolve:

| Technique | Destination |
|---|---|
| BeyondCorp gateway repointing | `gcp-post-exploitation/gcp-beyondcorp-post-exploitation.md` |
| BigQuery data-policy and taxonomy change | `gcp-post-exploitation/gcp-bigquery-post-exploitation.md` |
| BigQuery row-access-policy change | `gcp-post-exploitation/gcp-bigquery-post-exploitation.md` |
| Bigtable authorized-view widening | `gcp-post-exploitation/gcp-bigtable-post-exploitation.md` |
| Workflows existing-execution invocation | `gcp-post-exploitation/gcp-workflows-post-exploitation.md` |
| Workflows paused-execution callback | `gcp-post-exploitation/gcp-workflows-post-exploitation.md` |
| Dataform existing saved-workflow invocation | `gcp-post-exploitation/gcp-dataform-post-exploitation.md` |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-logging-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#change-access-to-a-log-view--loggingviewssetiampolicy` | ### Self-grant logging.views.access on a log view | logging.views.setIamPolicy | COVERED | `gcp-logging-views-setiampolicy-self-grant` |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloud-domains-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#domainsregistrationssetiampolicy--registration-scoped-iam-persistence` | ### Self-grant domains.registrations.configureDns on a domain registration | domains.registrations.setIamPolicy | COVERED | `gcp-domains-registrations-setiampolicy-self-grant` |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-service-directory-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#servicedirectorynamespacesservicessetiampolicy--resource-scoped-iam-persistence` | ### Self-grant servicedirectory.services.update on a service | servicedirectory.services.setIamPolicy | COVERED | `gcp-servicedirectory-services-setiampolicy-self-grant` |
| `#servicedirectorynamespacesservicessetiampolicy--resource-scoped-iam-persistence` | ### Self-grant servicedirectory.services.create on a namespace | servicedirectory.namespaces.setIamPolicy | COVERED | `gcp-servicedirectory-namespaces-setiampolicy-self-grant` |

### `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-contact-center-insights-privesc.md`

| anchor | heading | permissions | status | mapping |
|---|---|---|---|---|
| `#authorized-view-iam-self-grant-authorizedviewssetiampolicy` | ## Authorized-view IAM self-grant (`authorizedViews.setIamPolicy`) | contactcenterinsights.authorizedViews.setIamPolicy | COVERED | `gcp-contactcenterinsights-authorizedviews-setiampolicy-self-grant` |

## Current CSPM catalog reconciliation (HackTricks Cloud `4fab4d35d179f490e5c0c6343ab7ef690b4a6f45`)

The heading sweep above records its historical source revision. The rows below record changes to the current automatic catalog. RETIRED entries remain documented in the source and exclusion catalog; they do not run as automatic checks.

| Technique ID | Source | Current disposition | Reason |
| --- | --- | --- | --- |
| `gcp-artifactregistry-repositories-setiampolicy-repository-self-grant` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-artifact-registry-privesc.md#artifactregistryrepositoriessetiampolicy--self-grant-control-of-a-repository` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-bigtable-instances-setiampolicy-instance-admin-self-grant` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-bigtable-privesc.md#bigtableinstancessetiampolicy--self-grant-across-one-instance` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-cloudbuild-builds-create-cross-project-actas` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloudbuild-privesc.md#cloudbuildbuildscreate--execute-build-steps-as-a-build-service-account` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-configcontroller-kcc-service-account-key` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-config-controller-privesc.md#kcc-iamserviceaccountkey-plus-secret-read--mint-a-long-lived-key-for-a-more-privileged-service-account` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-networkconnectivity-hubs-setiampolicy-group-use-self-grant` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-connectivity-center-privesc.md#resource-iam-self-grants` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-resourcemanager-organizations-setiampolicy-deny-admin` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-resourcemanager-privesc.md#organizationsfoldersprojectssetiampolicy--self-grant-on-a-hierarchy-node` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-resourcemanager-organizations-setiampolicy-role-admin` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-resourcemanager-privesc.md#organizationsfoldersprojectssetiampolicy--self-grant-on-a-hierarchy-node` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-resourcemanager-projects-setiampolicy-project-delete` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-resourcemanager-privesc.md#organizationsfoldersprojectssetiampolicy--self-grant-on-a-hierarchy-node` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-resourcemanager-projects-setiampolicy-sa-token` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-resourcemanager-privesc.md#organizationsfoldersprojectssetiampolicy--self-grant-on-a-hierarchy-node` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-run-instances-create-update-cross-project-actas` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-run-privesc.md#runservicesupdate--iamserviceaccountsactas` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-run-jobs-create-run-cross-project-actas` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-run-privesc.md#runjobscreate-runjobsrun-iamserviceaccountsactasrunjobsget` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-run-services-create-cross-project-actas` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-run-privesc.md#runservicescreate--iamserviceaccountsactas-runroutesinvoke` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-storage-managedfolders-setiampolicy-composer` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-storage-privesc.md#storagebucketssetiampolicy--storagemanagedfolderssetiampolicy--resource-scoped-self-grant` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-storage-managedfolders-setiampolicy-dataproc-init` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-storage-privesc.md#storagebucketssetiampolicy--storagemanagedfolderssetiampolicy--resource-scoped-self-grant` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-workflows-create-cross-project-actas` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-workflows-privesc.md#workflowsworkflowscreate--iamserviceaccountsactas--workflowsexecutionscreate--deploy-code-under-a-service-account` | ACTIVE | Reviewed source-bound automatic path. |
| `gcp-artifactregistry-repositories-update-dependency-confusion` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-artifact-registry-privesc.md#dependency-confusion` | RETIRED | The target uses uncollected artifact_consumer attachment inventory; repository update permission alone cannot establish package resolution, a publishable upstream, and a later consumer install. The prior reviewed source exclusion marks dependency confusion manual-only. |
| `gcp-artifactregistry-tags-update` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-artifact-registry-privesc.md#artifactregistrytagsupdate--repoint-a-mutable-tag-to-another-stored-version` | RETIRED | The target uses uncollected artifact_consumer attachment inventory, so it cannot bind a mutable tag, alternate package version, and workload that later pulls it. The prior reviewed source exclusion marks this exact tag-repoint path manual-only. |
| `gcp-biglake-connection-table-bounded-storage-read` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-biglake-privesc.md#bigquerytablescreate--bigqueryconnectionsdelegate--create-a-table-that-reads-as-the-connection-service-account` | RETIRED | Manual-only: the exact connection, table, object, and source denial followed by an allowed read require a reviewed before/after proof that the collector does not produce. |
| `gcp-bigquery-authorized-dataset-existing-view-bounded-table-access` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-bigquery-privesc.md#dataset-acl-write--authorized-view-or-dataset-as-an-indirect-read-path` | RETIRED | Manual-only: the existing view, authorized dataset, protected table, prior denial, and later allowed query require a reviewed before/after proof that the collector does not produce. |
| `gcp-bigquery-authorized-routine-bounded-table-access` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-bigquery-privesc.md#dataset-acl-write--authorize-a-routine-as-an-indirect-access-path` | RETIRED | Manual-only: exact callable routine, dataset authorization, prior denial, and later allowed table result require a reviewed before/after proof that the collector does not produce. |
| `gcp-bigquery-authorized-view-bounded-table-access` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-bigquery-privesc.md#dataset-acl-write--authorized-view-or-dataset-as-an-indirect-read-path` | RETIRED | Manual-only: exact view, dataset authorization, prior denial, and later allowed table result require a reviewed before/after proof that the collector does not produce. |
| `gcp-bigquery-remote-function-bounded-cloudrun-invoke` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-bigquery-privesc.md#bigqueryroutinescreate--bigqueryconnectionsdelegateuse--invoke-cloud-run-through-a-remote-function` | RETIRED | Manual-only: exact connection, routine, endpoint, prior denial, and later allowed invocation require a reviewed before/after proof that the collector does not produce. |
| `gcp-bigquery-table-row-credential` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-bigquery-privesc.md#verified-service-account-private-key-in-table-rows` | RETIRED | Manual-only: a normal inventory does not read table rows or verify a reusable private key, exact service-account subject, and successful authentication. |
| `gcp-bigtable-row-credential` | `src/pentesting-cloud/gcp-security/gcp-post-exploitation/gcp-bigtable-post-exploitation.md#read-base-table-rows` | RETIRED | Manual-only: a normal inventory does not read Bigtable cells or verify a reusable private key, exact service-account subject, and successful authentication. |
| `gcp-bms-direct-initial-secret-exact-server-user` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-bare-metal-solution-privesc.md#retrieve-a-still-valid-initial-server-password` | RETIRED | Manual-only: the exact password must still work for the named BMS server user and allow a new OS action; a normal inventory cannot perform that login proof. |
| `gcp-cloudfunctions-setiampolicy-actas` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-cloudfunctions-privesc.md#cloudfunctionsfunctionsupdate--source-upload--replace-an-existing-privileged-function` | RETIRED | Google Cloud Functions documentation says only execution permissions are allowed at the per-function IAM level, so function setIamPolicy cannot self-grant update or sourceCodeSet. The old reviewed exclusion records this path as invalid; project-level deployment grants are covered by separate active techniques. |
| `gcp-composer-environments-executeairflowcommand` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-composer-privesc.md#composerenvironmentsexecuteairflowcommand--retrieve-airflow-secrets-or-run-available-dag-code` | RETIRED | Manual-only: the recorded permission and environment identity do not establish a supported Airflow CLI path or an existing DAG or connection that provides code execution or a usable credential. |
| `gcp-compute-images-create-family-poison` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-compute-privesc/README.md#poison-a-consumed-custom-image-family` | RETIRED | Manual-only: a family reference in an instance template does not show that a workload consumes it, the source image is controlled, or a later VM boots that image. |
| `gcp-dataproc-staging-object-plant` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-dataproc-privesc.md#dataprocclustersget--config-leak-sa--scopes--buckets--metadata--properties--staging-bucket-poison` | RETIRED | Manual-only: bucket write access cannot establish an unused exact object name, a later job reference, and execution by the cluster service account; these facts are not collected. |
| `gcp-firebaseapphosting-backends-update-source` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-firebase-app-hosting-privesc.md#backend-hijack--repoint-source-or-runtime-identity` | RETIRED | Manual-only path. Backend update permission and an existing backend do not prove control of an accepted replacement GitHub repository, the live branch, automatic rollout settings, path filters, or a later build. Keep the technique documented in HackTricks Cloud; exclude it from CSPM execution and the UI. Exact build-and-rollout paths remain active. |
| `gcp-firebaseauth-configs-update-exact-idp-principal` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-firebase-privesc.md#firebaseauthconfigsupdate--hijack-identity-platform-blocking-functions` | RETIRED | Manual-only path. Configuration update permission does not prove an attacker-controlled deployed blocking function, enabled forwarding for the actual IdP credential, a later supported federated sign-in, token capture, or new IdP access. Keep the technique documented in HackTricks Cloud; exclude it from CSPM execution and the UI. |
| `gcp-firebaseauth-users-update-exact-user-credential` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-firebase-privesc.md#firebaseauthusersupdate--take-over-an-application-user-or-set-privileged-custom-claims` | RETIRED | Manual-only path. User-update permission does not prove an exact usable account, accepted password change, sign-in as that user, or an application action newly allowed to the caller. Keep the technique documented in HackTricks Cloud; exclude it from CSPM execution and the UI. |
| `gcp-runtimeconfig-configs-setiampolicy-config-self-grant` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-runtimeconfig-privesc.md#runtimeconfigconfigssetiampolicy--self-grant-administration-of-one-config` | RETIRED | Manual-only path. The scanner collects neither an exact runtimeconfig resource with its IAM policy nor the grantable role and effective before/after permission. The only current path uses externally reviewed mutation evidence, so a normal CSPM scan cannot establish this self-grant. Keep the HackTricks Cloud technique documented; exclude it from CSPM execution and the UI. |
| `gcp-saasservicemgmt-release-unit-actuation` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-app-lifecycle-manager-privesc.md#saasservicemgmtreleasescreate--unitoperationscreate--rolloutscreate--apply-attacker-terraform-as-an-actuation-service-account` | RETIRED | Manual-only path. The scanner does not collect existing Units, their actuation service accounts, compatible release and rollout topology, or a resulting actuation. IAM permissions alone cannot establish a specific service-account authority gain. Keep the HackTricks Cloud procedure documented; exclude it from CSPM execution and the UI. |
| `gcp-secretmanager-managed-rotation-exact-cloudsql-user` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-secretmanager-privesc.md#secretmanagersecretsenablemanagedrotation--reset-a-cloud-sql-users-password-through-the-secret-identity` | RETIRED | Manual-only path. The scanner does not run password rotation, verify the exact Cloud SQL user and secret identity, or authenticate with a new password to prove a newly allowed database action. The current path depends on externally reviewed login evidence. Keep the HackTricks Cloud technique documented; exclude it from CSPM execution and the UI. |
| `gcp-securesourcemanager-push-cicd` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-secure-source-manager-privesc.md#cicd-supply-chain-code-execution` | RETIRED | Manual-only path. The collector has no Secure Source Manager repository or repository-controlled triggers file inventory, so it cannot join a writable ref to an automatic build and its exact service account. Keep the technique in HackTricks Cloud; exclude it from CSPM execution and the UI. |
| `gcp-securesourcemanager-setiampolicy` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-secure-source-manager-privesc.md#securesourcemanagerinstancessetiampolicy--repositoriessetiampolicy--iam-self-grant-to-readpoison-source` | RETIRED | Manual-only path. IAM self-grant alone cannot establish a linked automatic build; the collector lacks the repository, branch, triggers file and build-service-account join. Keep the technique in HackTricks Cloud; exclude it from CSPM execution and the UI. |
| `gcp-servicedirectory-namespaces-setiampolicy-self-grant` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-service-directory-privesc.md#servicedirectorynamespacesservicessetiampolicy--resource-scoped-iam-persistence` | RETIRED | Manual-only path. The scanner collects neither an exact servicedirectory resource with its IAM policy nor the grantable role and effective before/after permission. The only current path uses externally reviewed mutation evidence, so a normal CSPM scan cannot establish this self-grant. Keep the HackTricks Cloud technique documented; exclude it from CSPM execution and the UI. |
| `gcp-servicedirectory-services-setiampolicy-self-grant` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-service-directory-privesc.md#servicedirectorynamespacesservicessetiampolicy--resource-scoped-iam-persistence` | RETIRED | Manual-only path. The scanner collects neither an exact servicedirectory resource with its IAM policy nor the grantable role and effective before/after permission. The only current path uses externally reviewed mutation evidence, so a normal CSPM scan cannot establish this self-grant. Keep the HackTricks Cloud technique documented; exclude it from CSPM execution and the UI. |
| `gcp-spanner-databases-setiampolicy-database-self-grant` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-spanner-privesc.md#spannerdatabasessetiampolicy--spannerinstancessetiampolicy--grant-database-access` | RETIRED | Manual-only path. The scanner collects neither an exact spanner resource with its IAM policy nor the grantable role and effective before/after permission. The only current path uses externally reviewed mutation evidence, so a normal CSPM scan cannot establish this self-grant. Keep the HackTricks Cloud technique documented; exclude it from CSPM execution and the UI. |
| `gcp-spanner-instances-setiampolicy-instance-self-grant` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-spanner-privesc.md#spannerdatabasessetiampolicy--spannerinstancessetiampolicy--grant-database-access` | RETIRED | Manual-only path. The scanner collects neither an exact spanner resource with its IAM policy nor the grantable role and effective before/after permission. The only current path uses externally reviewed mutation evidence, so a normal CSPM scan cannot establish this self-grant. Keep the HackTricks Cloud technique documented; exclude it from CSPM execution and the UI. |
| `gcp-workspace-addons-deployment-update` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-workspace-addons-privesc.md#gsuiteaddonsdeploymentsupdate` | RETIRED | Manual-only path. The collector does not inventory the exact installed HTTP deployment, its consenting users and scopes, or a later invocation of the changed endpoint. Deployment-update permission alone cannot establish a Workspace user authority edge. Keep the technique in HackTricks Cloud; exclude it from CSPM execution and the UI. |
| `gcp-workspace-cloud-dns-admin-recovery` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-workspace-privesc.md#cloud-dns-to-workspace-administrator-recovery` | RETIRED | Manual-only path. The collector does not establish that a writable public Cloud DNS zone is actually delegated for the Workspace tenant's primary domain or that administrator recovery accepts the challenge. A lookalike or private zone must not create a Workspace administrator edge. Keep the technique in HackTricks Cloud; exclude it from CSPM execution and the UI. |
| `gcp-workspace-dwd-key-create` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-workspace-privesc.md#compromise-existing-delegation` | RETIRED | Manual-only path. A key creation grant cannot establish that the exact service account has a Workspace domain-wide-delegation grant, that a subject and scope are accepted, or that the created key yields a delegated token. Keep the technique in HackTricks Cloud; exclude it from CSPM execution and the UI. |
| `gcp-workspace-dwd-keyless-signjwt` | `src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-workspace-privesc.md#keyless-dwd-abuse-with-signjwt-or-signblob` | RETIRED | Manual-only path. GCP IAM can establish signJwt or signBlob permission, but the collector cannot read the Workspace tenant's domain-wide-delegation client grant, approved scopes, or a successful delegated token exchange. Keep the technique in HackTricks Cloud; exclude it from CSPM execution and the UI. |
