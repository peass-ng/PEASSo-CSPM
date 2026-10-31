# Permissions

PEASO CSPM only needs **read** access. It never needs permission to create, change or delete
cloud resources, and it never needs APIs that return secret values. This page lists the access
each provider needs and the authentication methods each mode supports.

When access is missing, the affected checks report `DENIED` or `UNKNOWN`. They never turn into
`PASS`. The connector **access check** in the web app (`POST /api/connectors/check-access`) tells
you which reads work before you start a scan.

## AWS

### Recommended role

Use the CloudFormation template `infra/aws/customer-role.json`. It creates one IAM role,
`HackTricksCspmReadOnly-<StackName>`, with:

- A trust policy that only allows `sts:AssumeRole` from the scanner's collector role
  (`CollectorRoleArn` parameter) and only with the matching `sts:ExternalId` (`ExternalId`
  parameter, which must start with `hacktricks-cspm-` and be at least 32 characters).
- A maximum session length of one hour.
- The AWS managed policies `ReadOnlyAccess` and `SecurityAudit`.
- Eight customer managed policies (`CspmConfigurationReadOnly1` to `8`) that add the extra
  `List*`, `Describe*`, `Get*`, `Batch*`, `View*`, `Search*` and `Lookup*` actions the
  collectors use for services the managed policies miss.

A few actions in those policies are not strictly reads but are needed to produce report data:
`iam:GenerateCredentialReport`, `iam:GenerateServiceLastAccessedDetails` and
`iam:SimulatePrincipalPolicy` (all of which only compute data about IAM), and `apigateway:GET`.
The template does not grant secret-value APIs such as `secretsmanager:GetSecretValue`.

The hosted deployment serves this template from its own domain, and the web app generates the
External ID for you.

### Auth methods

| Mode | Methods |
| --- | --- |
| Local (CLI or local server) | `default`, `profile`, `sso`, `access_keys`, `assume_role`, `web_identity`, `container`, `instance` |
| Hosted | `access_keys`, `assume_role` |

Hosted rules for `assume_role`:

- The server generates the External ID (prefix `hacktricks-cspm-`).
- At most 50 role targets per connector and role chains of at most 10 hops.
- Roles in the platform's own AWS accounts are rejected.

### Account scope

Scopes are explicit. Each scope is an account ID or `account/region`. The scanner never reads
other accounts on its own: cross-account collection needs explicit `assume_roles` entries in the
auth object or an `organization_role_name` option.

### Access Analyzer

The AWS collector does not create or call IAM Access Analyzer analyzers. Access Analyzer data
is only used when it is already present in saved scan results. You do not need
`IAMAccessAnalyzerFullAccess` or any other Access Analyzer write permission.

## Google Cloud

### Roles

Grant these roles to the scanning identity on each project (or on the folder/organization for
many projects):

| Role | Why |
| --- | --- |
| `roles/viewer` | Read most resource configuration |
| `roles/iam.securityReviewer` | Read IAM policies on all resources |
| `roles/cloudasset.viewer` | Cloud Asset Inventory searches |
| `roles/serviceusage.serviceUsageConsumer` | Use the quota project for API calls |
| `roles/logging.privateLogViewer` | Read audit and data-access logs (activity and detection) |
| `roles/securitycenter.findingsViewer` | Read Security Command Center findings |
| `roles/recommender.viewer` | Read IAM recommender insights |

For impersonation, the caller also needs `roles/iam.serviceAccountTokenCreator` on the target
service account. For workload identity federation, the external principal needs
`roles/iam.workloadIdentityUser`.

### Auth methods

| Mode | Methods |
| --- | --- |
| Local | `adc`, `gcloud`, `service-account`, `external-account`, `metadata`, `impersonation`, `token` |
| Hosted | `token`, `service-account`, `external-account`, and `platform-service-account` when the deployment enables it |

Hosted GCP connectors must list exact project IDs. The `platform-service-account` method uses a
deployment-owned service account whose key is read from `PEASO_GCP_PLATFORM_SA_SECRET_ARN`; the
customer grants the read roles above to that service account.

## Azure

### Azure RBAC roles

Assign at subscription scope (or management group for many subscriptions):

| Role | Role definition ID |
| --- | --- |
| Reader | `acdd72a7-3385-48ef-bd42-f606fba81ae7` |
| Security Reader | `39bc4728-0917-49c7-9d2c-d95423bc2eb4` |
| Key Vault Reader (optional, Key Vault metadata) | `21090545-7ca7-4776-b22c-e363652d74d2` |

### Microsoft Graph application permissions

For Entra ID checks, grant these application permissions and give admin consent:
`Directory.Read.All`, `Policy.Read.All`, `AuditLog.Read.All`, `Reports.Read.All`,
`RoleManagement.Read.Directory`, `Organization.Read.All`.

Optional, for PIM for Groups and access-package checks: `PrivilegedAccess.Read.AzureADGroup`,
`RoleManagementPolicy.Read.AzureADGroup` and `EntitlementManagement.Read.All`. Without them those
inventories are reported as denied.

### Auth methods

| Mode | Methods |
| --- | --- |
| Local | `auto`, `az-cli`, `client-secret`, `client-cert`, `managed-identity`, `workload-identity`, `device-code`, `token` |
| Hosted | `token`, `client-secret`, `client-cert`, `workload-identity` |

The `token` method accepts separate tokens per audience (`arm_token`, `graph_token`,
`vault_token`, `storage_token`, `logs_token`) so you can grant only the surfaces you want read.

## Kubernetes

### RBAC

Bind the scanning identity to:

1. The built-in `view` ClusterRole.
2. A small extra ClusterRole (for example `hacktricks-cspm-scan-rbac-read`) with `get`, `list`
   and `watch` on: `namespaces`, `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings`,
   `nodes`, `persistentvolumes`, `storageclasses`, `validatingwebhookconfigurations` and
   `mutatingwebhookconfigurations`. The `view` role does not include these.

Listing `secrets` is optional. If you grant it, the scanning identity can see Secret values even
though the collector discards them; only grant it if you accept that.

### Auth methods

| Mode | Methods |
| --- | --- |
| Local | `kubeconfig`, `context`, `in-cluster`, `token`, `client-cert`, `inline` |
| Hosted | `inline`, `token`, `client-cert`; the API server must be a public HTTPS endpoint |

## Optional content scans

Secret scanning of content (function packages, logs, notebooks, build files, container images
and similar) and image CVE scanning are off unless you select specific targets. Each selected
surface needs its own extra read permission, for example `pods/log` in Kubernetes or pull access
to a container registry. These scans are described in [secrets-and-images.md](secrets-and-images.md).

## What is never needed

- Any write, create, update, delete, tag or attach permission.
- Secret value APIs (for example Secrets Manager `GetSecretValue`, Key Vault secret get, Secret
  Manager `versions.access`) for the core scan.
- Permission to create Access Analyzer analyzers or any other cloud-side scanning resource.

## Best practices

- Use a dedicated identity only for scanning, and nothing else.
- Prefer short-lived credentials: role assumption with External ID, federation or impersonation over static keys.
- Grant the minimum set above and use the connector access check to confirm it.
- Leave Kubernetes `secrets` access and optional content-scan permissions off unless you need them.
- Scope the identity to exactly the accounts, projects or subscriptions you plan to scan.
