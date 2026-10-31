import type { Provider } from "./types";

export type AuthGuide = {
  access: string;
  permissions: string;
  permissionIds?: string[];
  optionalSetup?: { title: string; description: string; commands: { label: string; value: string }[] };
  url: string;
  link: string;
  commands: { label: string; value: string }[];
  accessCommandCount: number;
};

export const awsPolicyArns = [
  "arn:aws:iam::aws:policy/ReadOnlyAccess",
  "arn:aws:iam::aws:policy/SecurityAudit",
];
const awsPolicyList = awsPolicyArns.join(" ");
const awsPermissions = "ReadOnlyAccess or SecurityAudit, or verified equivalent baseline inventory permissions, are required. We recommend both read policies for broad inventory and security configuration coverage. Optional exact secret-content checks need separate per-surface reads; see docs/permissions.md. Access is read-only: the scan never creates, changes or deletes IAM Access Analyzer analyzers, so no Access Analyzer write permission such as IAMAccessAnalyzerFullAccess is needed.";
export const awsHostedPermissions = "Deploy the customer role template from Onboarding in each target account. It creates the role, External ID trust, collector-specific read policies, ReadOnlyAccess and SecurityAudit. All grants are read-only; the scan never creates or deletes IAM Access Analyzer analyzers. Its metadata grants do not cover every optional exact secret-content check; see docs/permissions.md and preserve any separately deployed read grants when updating the role.";
const awsRoleGrant = { label: "AWS CLI: attach policies to role", value: [
  "ROLE_NAME='REPLACE_WITH_SCANNING_ROLE_NAME'",
  "for POLICY_ARN in " + awsPolicyList + "; do",
  '  aws iam attach-role-policy --role-name "$ROLE_NAME" --policy-arn "$POLICY_ARN"',
  "done",
].join("\n") };
const awsCreateUser = { label: "AWS CLI: create scanning user and access key", value: [
  "USER_NAME='hacktricks-cspm-scan'",
  'aws iam create-user --user-name "$USER_NAME"',
  'aws iam create-access-key --user-name "$USER_NAME"',
].join("\n") };
const awsUserGrant = { label: "AWS CLI: attach policies to scanning user", value: [
  "USER_NAME='hacktricks-cspm-scan'",
  "for POLICY_ARN in " + awsPolicyList + "; do",
  '  aws iam attach-user-policy --user-name "$USER_NAME" --policy-arn "$POLICY_ARN"',
  "done",
].join("\n") };
const awsSsoGrant = { label: "AWS CLI: attach policies to IAM Identity Center permission set", value: [
  "INSTANCE_ARN='REPLACE_WITH_SSO_INSTANCE_ARN'",
  "PERMISSION_SET_ARN='REPLACE_WITH_PERMISSION_SET_ARN'",
  "for POLICY_ARN in " + awsPolicyList + "; do",
  '  aws sso-admin attach-managed-policy-to-permission-set --instance-arn "$INSTANCE_ARN" --permission-set-arn "$PERMISSION_SET_ARN" --managed-policy-arn "$POLICY_ARN"',
  "done",
  'aws sso-admin provision-permission-set --instance-arn "$INSTANCE_ARN" --permission-set-arn "$PERMISSION_SET_ARN" --target-type ALL_PROVISIONED_ACCOUNTS',
].join("\n") };
const awsDefaultAccess = { label: "AWS CLI: verify the selected server identity", value: "aws sts get-caller-identity" };
const awsAssumeAccess = { label: "AWS CLI: create target role trusting your source identity", value: [
  "SOURCE_PRINCIPAL_ARN='REPLACE_WITH_SOURCE_IAM_ROLE_OR_USER_ARN'",
  "ROLE_NAME='hacktricks-cspm-scan-target'",
  'printf \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"%s"},"Action":"sts:AssumeRole"}]}\' "$SOURCE_PRINCIPAL_ARN" > hacktricks-cspm-target-trust.json',
  'aws iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document file://hacktricks-cspm-target-trust.json',
  'aws iam get-role --role-name "$ROLE_NAME" --query Role.Arn --output text',
].join("\n") };
const awsSourceAssumeGrant = { label: "AWS CLI: allow source role to assume target", value: [
  "SOURCE_ROLE_NAME='REPLACE_WITH_SOURCE_ROLE_NAME'",
  "TARGET_ROLE_ARN='REPLACE_WITH_TARGET_ROLE_ARN'",
  'printf \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"%s"}]}\' "$TARGET_ROLE_ARN" > hacktricks-cspm-source-assume.json',
  'aws iam put-role-policy --role-name "$SOURCE_ROLE_NAME" --policy-name HackTricksCspmAssumeTarget --policy-document file://hacktricks-cspm-source-assume.json',
].join("\n") };
const awsWebIdentityAccess = { label: "AWS CLI: create web identity role", value: [
  "OIDC_PROVIDER_ARN='arn:aws:iam::REPLACE_WITH_ACCOUNT_ID:oidc-provider/REPLACE_WITH_ISSUER_HOST_AND_PATH'",
  "OIDC_SUBJECT='REPLACE_WITH_SUBJECT'",
  "ROLE_NAME='hacktricks-cspm-web-identity'",
  'ISSUER="${OIDC_PROVIDER_ARN#*oidc-provider/}"',
  'printf \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Federated":"%s"},"Action":"sts:AssumeRoleWithWebIdentity","Condition":{"StringEquals":{"%s:sub":"%s","%s:aud":"sts.amazonaws.com"}}}]}\' "$OIDC_PROVIDER_ARN" "$ISSUER" "$OIDC_SUBJECT" "$ISSUER" > hacktricks-cspm-web-trust.json',
  'aws iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document file://hacktricks-cspm-web-trust.json',
].join("\n") };
const awsContainerAccess = { label: "AWS CLI: create ECS task role", value: [
  "ROLE_NAME='hacktricks-cspm-ecs-scan'",
  'printf \'%s\' \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}\' > hacktricks-cspm-ecs-trust.json',
  'aws iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document file://hacktricks-cspm-ecs-trust.json',
  'aws iam get-role --role-name "$ROLE_NAME" --query Role.Arn --output text',
  "# Set this ARN as taskRoleArn in the HackTricks CSPM ECS task definition.",
].join("\n") };
const awsInstanceAccess = { label: "AWS CLI: create EC2 instance profile", value: [
  "ROLE_NAME='hacktricks-cspm-ec2-scan'",
  'printf \'%s\' \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}\' > hacktricks-cspm-ec2-trust.json',
  'aws iam create-role --role-name "$ROLE_NAME" --assume-role-policy-document file://hacktricks-cspm-ec2-trust.json',
  'aws iam create-instance-profile --instance-profile-name "$ROLE_NAME"',
  'aws iam add-role-to-instance-profile --instance-profile-name "$ROLE_NAME" --role-name "$ROLE_NAME"',
  "# Associate this instance profile with the HackTricks CSPM EC2 host.",
].join("\n") };

export const gcpRoles = [
  "roles/viewer", "roles/iam.securityReviewer", "roles/cloudasset.viewer",
  "roles/serviceusage.serviceUsageConsumer", "roles/logging.privateLogViewer",
  "roles/securitycenter.findingsViewer",
  "roles/recommender.viewer",
];
const gcpPermissions = "Grant these seven project roles to the scanning identity. Optional selected content needs separate bucket/repository/service grants in the resource-owning project; see docs/permissions.md. A workload service agent is a different principal from the scanner. Private Logs Viewer already includes Logs Viewer and permits Data Access log reads.";
const gcpGrant = (principal = "serviceAccount:REPLACE_WITH_SCANNING_SA_EMAIL") => ({
  label: "gcloud CLI: grant project roles",
  value: [
    "PROJECT_ID='REPLACE_WITH_CUSTOMER_PROJECT_ID'",
    "PRINCIPAL='" + principal + "'",
    "for ROLE in " + gcpRoles.join(" ") + "; do",
    '  gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="$PRINCIPAL" --role="$ROLE" --quiet',
    "done",
  ].join("\n"),
});
const gcpImpersonationGrant = { label: "gcloud CLI: allow source to impersonate target", value: [
  "TARGET_SA='REPLACE_WITH_TARGET_SA_EMAIL'",
  "SOURCE_PRINCIPAL='user:REPLACE_WITH_SOURCE_EMAIL'",
  'gcloud iam service-accounts add-iam-policy-binding "$TARGET_SA" --member="$SOURCE_PRINCIPAL" --role=roles/iam.serviceAccountTokenCreator',
].join("\n") };
const gcpCreateSaKey = { label: "gcloud CLI: create service account and JSON key", value: [
  "IDENTITY_PROJECT='REPLACE_WITH_IDENTITY_PROJECT_ID'",
  'gcloud iam service-accounts create hacktricks-cspm-scan --project="$IDENTITY_PROJECT"',
  'gcloud iam service-accounts keys create ./hacktricks-cspm-scan.json --iam-account="hacktricks-cspm-scan@$IDENTITY_PROJECT.iam.gserviceaccount.com"',
].join("\n") };
const gcpCreateTargetSa = { label: "gcloud CLI: create impersonation target", value: [
  "IDENTITY_PROJECT='REPLACE_WITH_IDENTITY_PROJECT_ID'",
  'gcloud iam service-accounts create hacktricks-cspm-scan --project="$IDENTITY_PROJECT"',
  'gcloud iam service-accounts describe "hacktricks-cspm-scan@$IDENTITY_PROJECT.iam.gserviceaccount.com"',
].join("\n") };
const gcpExternalAccess = { label: "gcloud CLI: create workload identity pool and OIDC provider", value: [
  "IDENTITY_PROJECT='REPLACE_WITH_IDENTITY_PROJECT_ID'",
  "POOL='hacktricks-cspm-scan'",
  "PROVIDER='hacktricks-cspm-oidc'",
  "ISSUER_URI='https://REPLACE_WITH_OIDC_ISSUER'",
  'gcloud iam workload-identity-pools create "$POOL" --project="$IDENTITY_PROJECT" --location=global --display-name="HackTricks CSPM scan"',
  'gcloud iam workload-identity-pools providers create-oidc "$PROVIDER" --project="$IDENTITY_PROJECT" --location=global --workload-identity-pool="$POOL" --issuer-uri="$ISSUER_URI" --attribute-mapping="google.subject=assertion.sub"',
  "PROJECT_NUMBER='REPLACE_WITH_IDENTITY_PROJECT_NUMBER'",
  "TARGET_SA='REPLACE_WITH_TARGET_SA_EMAIL'",
  "TOKEN_FILE='REPLACE_WITH_OIDC_TOKEN_FILE'",
  'gcloud iam workload-identity-pools create-cred-config "projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL/providers/$PROVIDER" --service-account="$TARGET_SA" --credential-source-file="$TOKEN_FILE" --output-file=hacktricks-cspm-external-account.json',
].join("\n") };
const gcpExternalGrant = { label: "gcloud CLI: trust external subject for service account impersonation", value: [
  "PROJECT_NUMBER='REPLACE_WITH_IDENTITY_PROJECT_NUMBER'",
  "POOL='hacktricks-cspm-scan'",
  "SUBJECT='REPLACE_WITH_OIDC_SUBJECT'",
  "TARGET_SA='REPLACE_WITH_TARGET_SA_EMAIL'",
  'gcloud iam service-accounts add-iam-policy-binding "$TARGET_SA" --member="principal://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL/subject/$SUBJECT" --role=roles/iam.workloadIdentityUser',
].join("\n") };
const gcpMetadataAccess = { label: "gcloud CLI: attach scanning service account to VM", value: [
  "IDENTITY_PROJECT='REPLACE_WITH_IDENTITY_PROJECT_ID'",
  "VM_NAME='REPLACE_WITH_SCANNING_VM_NAME'",
  "ZONE='REPLACE_WITH_SCANNING_VM_ZONE'",
  'gcloud iam service-accounts create hacktricks-cspm-scan --project="$IDENTITY_PROJECT"',
  'gcloud compute instances set-service-account "$VM_NAME" --zone="$ZONE" --service-account="hacktricks-cspm-scan@$IDENTITY_PROJECT.iam.gserviceaccount.com" --scopes=https://www.googleapis.com/auth/cloud-platform',
].join("\n") };

const azurePermissions = "Assign Reader and Security Reader on each subscription. Optional selected content needs separate site config/list, registry pull, storage data, workspace or service-specific reads; see docs/permissions.md. Key Vault Reader is only for metadata inside RBAC-enabled vaults. For directory inventory, app credentials also need Microsoft Graph application permissions Directory.Read.All, Policy.Read.All, AuditLog.Read.All, Reports.Read.All, RoleManagement.Read.Directory, and Organization.Read.All with admin consent.";
const azureRoleIds = [
  "Reader · acdd72a7-3385-48ef-bd42-f606fba81ae7",
  "Security Reader · 39bc4728-0917-49c7-9d2c-d95423bc2eb4",
  "Key Vault Reader (optional) · 21090545-7ca7-4776-b22c-e363652d74d2",
];
const azureAppGrant = { label: "Azure CLI: grant subscription roles to app or managed identity", value: [
  "SUBSCRIPTION_ID='REPLACE_WITH_SUBSCRIPTION_ID'",
  "PRINCIPAL_OBJECT_ID='REPLACE_WITH_SERVICE_PRINCIPAL_OBJECT_ID'",
  "for ROLE_ID in acdd72a7-3385-48ef-bd42-f606fba81ae7 39bc4728-0917-49c7-9d2c-d95423bc2eb4; do",
  '  az role assignment create --assignee-object-id "$PRINCIPAL_OBJECT_ID" --assignee-principal-type ServicePrincipal --role "$ROLE_ID" --scope "/subscriptions/$SUBSCRIPTION_ID"',
  "done",
].join("\n") };
const azureUserGrant = { label: "Azure CLI: grant subscription roles to signed-in user", value: [
  "SUBSCRIPTION_ID='REPLACE_WITH_SUBSCRIPTION_ID'",
  'USER_OBJECT_ID="$(az ad signed-in-user show --query id -o tsv)"',
  "for ROLE_ID in acdd72a7-3385-48ef-bd42-f606fba81ae7 39bc4728-0917-49c7-9d2c-d95423bc2eb4; do",
  '  az role assignment create --assignee-object-id "$USER_OBJECT_ID" --assignee-principal-type User --role "$ROLE_ID" --scope "/subscriptions/$SUBSCRIPTION_ID"',
  "done",
].join("\n") };
const azureVaultGrant = { label: "Azure CLI: grant optional Key Vault metadata access", value: [
  "VAULT_ID='/subscriptions/REPLACE_WITH_SUBSCRIPTION_ID/resourceGroups/REPLACE_WITH_RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/REPLACE_WITH_VAULT_NAME'",
  "PRINCIPAL_OBJECT_ID='REPLACE_WITH_SCANNING_PRINCIPAL_OBJECT_ID'",
  'az role assignment create --assignee-object-id "$PRINCIPAL_OBJECT_ID" --assignee-principal-type ServicePrincipal --role 21090545-7ca7-4776-b22c-e363652d74d2 --scope "$VAULT_ID"',
].join("\n") };
const azureVaultUserGrant = { label: "Azure CLI: grant signed-in user optional Key Vault metadata access", value: [
  "VAULT_ID='/subscriptions/REPLACE_WITH_SUBSCRIPTION_ID/resourceGroups/REPLACE_WITH_RESOURCE_GROUP/providers/Microsoft.KeyVault/vaults/REPLACE_WITH_VAULT_NAME'",
  'USER_OBJECT_ID="$(az ad signed-in-user show --query id -o tsv)"',
  'az role assignment create --assignee-object-id "$USER_OBJECT_ID" --assignee-principal-type User --role 21090545-7ca7-4776-b22c-e363652d74d2 --scope "$VAULT_ID"',
].join("\n") };
const azureGraphGrant = { label: "Azure CLI: grant Microsoft Graph app permissions", value: [
  "APP_ID='REPLACE_WITH_APP_CLIENT_ID'",
  "GRAPH_APP_ID='00000003-0000-0000-c000-000000000000'",
  "for PERMISSION in Directory.Read.All Policy.Read.All AuditLog.Read.All Reports.Read.All RoleManagement.Read.Directory Organization.Read.All; do",
  '  PERMISSION_ID="$(az ad sp show --id "$GRAPH_APP_ID" --query "appRoles[?value==\u0027$PERMISSION\u0027].id | [0]" -o tsv)"',
  '  az ad app permission add --id "$APP_ID" --api "$GRAPH_APP_ID" --api-permissions "$PERMISSION_ID=Role"',
  "done",
  'az ad app permission admin-consent --id "$APP_ID"',
].join("\n") };
const azureManagedIdentityGraphGrant = { label: "Azure CLI: grant Microsoft Graph roles to managed identity", value: [
  "MI_OBJECT_ID='REPLACE_WITH_MANAGED_IDENTITY_OBJECT_ID'",
  "GRAPH_APP_ID='00000003-0000-0000-c000-000000000000'",
  'GRAPH_SP_ID="$(az ad sp show --id "$GRAPH_APP_ID" --query id -o tsv)"',
  "for PERMISSION in Directory.Read.All Policy.Read.All AuditLog.Read.All Reports.Read.All RoleManagement.Read.Directory Organization.Read.All; do",
  '  PERMISSION_ID="$(az ad sp show --id "$GRAPH_APP_ID" --query "appRoles[?value==\u0027$PERMISSION\u0027].id | [0]" -o tsv)"',
  '  BODY="$(printf \'{"principalId":"%s","resourceId":"%s","appRoleId":"%s"}\' "$MI_OBJECT_ID" "$GRAPH_SP_ID" "$PERMISSION_ID")"',
  '  az rest --method POST --url "https://graph.microsoft.com/v1.0/servicePrincipals/$MI_OBJECT_ID/appRoleAssignments" --body "$BODY"',
  "done",
].join("\n") };
const azureCreateSp = { label: "Azure CLI: create scanning service principal", value: [
  "az ad sp create-for-rbac --name hacktricks-cspm-scan",
  "# Save the appId, password, and tenant from the output; the password is shown once.",
  "APP_ID='REPLACE_WITH_RETURNED_APP_ID'",
  'az ad sp show --id "$APP_ID" --query id -o tsv',
  "# Use that object ID in the subscription role grant command.",
].join("\n") };
const azureCreateCertApp = { label: "Azure CLI: register app and certificate", value: [
  'APP_ID="$(az ad app create --display-name hacktricks-cspm-scan --query appId -o tsv)"',
  'az ad sp create --id "$APP_ID"',
  'openssl req -x509 -newkey rsa:3072 -nodes -keyout hacktricks-cspm-scan.key -out hacktricks-cspm-scan.crt -days 365 -subj "/CN=hacktricks-cspm-scan"',
  'az ad app credential reset --id "$APP_ID" --cert @hacktricks-cspm-scan.crt --append',
  'cat hacktricks-cspm-scan.key hacktricks-cspm-scan.crt > hacktricks-cspm-scan.pem',
  'az ad sp show --id "$APP_ID" --query id -o tsv',
  "# Put hacktricks-cspm-scan.pem on the HackTricks CSPM server or paste it into the inline certificate field.",
].join("\n") };
const azureFederationAccess = { label: "Azure CLI: register OIDC trust for scanning app", value: [
  'APP_ID="$(az ad app create --display-name hacktricks-cspm-scan --query appId -o tsv)"',
  'az ad sp create --id "$APP_ID"',
  "ISSUER_URI='https://REPLACE_WITH_OIDC_ISSUER'",
  "SUBJECT='REPLACE_WITH_OIDC_SUBJECT'",
  'printf \'{"name":"hacktricks-cspm-scan","issuer":"%s","subject":"%s","audiences":["api://AzureADTokenExchange"]}\' "$ISSUER_URI" "$SUBJECT" > hacktricks-cspm-federated.json',
  'az ad app federated-credential create --id "$APP_ID" --parameters hacktricks-cspm-federated.json',
  'az ad sp show --id "$APP_ID" --query id -o tsv',
  "# Supply a current OIDC assertion with this issuer, subject and audience.",
].join("\n") };
const azureManagedIdentityAccess = { label: "Azure CLI: enable VM managed identity", value: [
  "RESOURCE_GROUP='REPLACE_WITH_SCANNING_VM_RESOURCE_GROUP'",
  "VM_NAME='REPLACE_WITH_SCANNING_VM_NAME'",
  'az vm identity assign --resource-group "$RESOURCE_GROUP" --name "$VM_NAME"',
  'az vm show --resource-group "$RESOURCE_GROUP" --name "$VM_NAME" --query identity.principalId -o tsv',
].join("\n") };

const k8sPermissions = "Bind the identity to the built-in view ClusterRole and the extra read-only cluster inventory role shown below. These cover common workload, network, RBAC, node, storage and admission metadata checks; optional custom resources need their own list grants. Optional exact content targets can use namespace-scoped get/resourceNames Roles; Pod logs need pods/log get and private images need separate registry pull authorization. See docs/secret-content-permissions.md. Secret metadata inventory additionally needs list on Secrets; that permission exposes secret values to the identity even though the collector discards them.";
const k8sCreateServiceAccount = { label: "kubectl: create scanning service account", value: [
  "NAMESPACE='REPLACE_WITH_NAMESPACE'",
  "SERVICE_ACCOUNT='hacktricks-cspm-scan'",
  'kubectl -n "$NAMESPACE" create serviceaccount "$SERVICE_ACCOUNT"',
].join("\n") };
const k8sServiceAccountGrant = { label: "kubectl: bind service account to view role", value: [
  "NAMESPACE='REPLACE_WITH_NAMESPACE'",
  "SERVICE_ACCOUNT='hacktricks-cspm-scan'",
  'kubectl create clusterrolebinding hacktricks-cspm-scan-view --clusterrole=view --serviceaccount="$NAMESPACE:$SERVICE_ACCOUNT"',
].join("\n") };
const k8sUserGrant = { label: "kubectl: bind user or certificate common name to read roles", value: [
  "K8S_USERNAME='REPLACE_WITH_KUBECONFIG_USER_OR_CERTIFICATE_CN'",
  'kubectl create clusterrolebinding hacktricks-cspm-scan-view --clusterrole=view --user="$K8S_USERNAME"',
].join("\n") };
const k8sExtraSaGrant = { label: "kubectl: allow service account to read cluster metadata", value: [
  "NAMESPACE='REPLACE_WITH_NAMESPACE'",
  "SERVICE_ACCOUNT='hacktricks-cspm-scan'",
  "kubectl create clusterrole hacktricks-cspm-scan-rbac-read --verb=get,list,watch --resource=namespaces,roles,rolebindings,clusterroles,clusterrolebindings,nodes,persistentvolumes,storageclasses,validatingwebhookconfigurations,mutatingwebhookconfigurations",
  'kubectl create clusterrolebinding hacktricks-cspm-scan-rbac-read --clusterrole=hacktricks-cspm-scan-rbac-read --serviceaccount="$NAMESPACE:$SERVICE_ACCOUNT"',
].join("\n") };
const k8sExtraUserGrant = { label: "kubectl: allow user to read cluster metadata", value: [
  "K8S_USERNAME='REPLACE_WITH_KUBECONFIG_USER_OR_CERTIFICATE_CN'",
  "kubectl create clusterrole hacktricks-cspm-scan-rbac-read --verb=get,list,watch --resource=namespaces,roles,rolebindings,clusterroles,clusterrolebindings,nodes,persistentvolumes,storageclasses,validatingwebhookconfigurations,mutatingwebhookconfigurations",
  'kubectl create clusterrolebinding hacktricks-cspm-scan-rbac-read --clusterrole=hacktricks-cspm-scan-rbac-read --user="$K8S_USERNAME"',
].join("\n") };
const k8sSecretGrant = { label: "kubectl: optional Secret inventory permission", value: [
  "NAMESPACE='REPLACE_WITH_NAMESPACE'",
  "SERVICE_ACCOUNT='hacktricks-cspm-scan'",
  "kubectl create clusterrole hacktricks-cspm-scan-secret-list --verb=list --resource=secrets",
  'kubectl create clusterrolebinding hacktricks-cspm-scan-secret-list --clusterrole=hacktricks-cspm-scan-secret-list --serviceaccount="$NAMESPACE:$SERVICE_ACCOUNT"',
].join("\n") };
const k8sSecretUserGrant = { label: "kubectl: optional Secret inventory permission for user", value: [
  "K8S_USERNAME='REPLACE_WITH_KUBECONFIG_USER_OR_CERTIFICATE_CN'",
  "kubectl create clusterrole hacktricks-cspm-scan-secret-list --verb=list --resource=secrets",
  'kubectl create clusterrolebinding hacktricks-cspm-scan-secret-list --clusterrole=hacktricks-cspm-scan-secret-list --user="$K8S_USERNAME"',
].join("\n") };
const k8sKubeconfigAccess = { label: "kubectl: create dedicated service-account kubeconfig", value: [
  "NAMESPACE='default'",
  "SERVICE_ACCOUNT='hacktricks-cspm-scan'",
  'kubectl -n "$NAMESPACE" create serviceaccount "$SERVICE_ACCOUNT"',
  'kubectl -n "$NAMESPACE" create token "$SERVICE_ACCOUNT" --duration=2h > hacktricks-cspm-scan.token',
  'SERVER="$(kubectl config view --minify -o jsonpath=\'{.clusters[0].cluster.server}\')"',
  'kubectl config view --raw --minify -o jsonpath=\'{.clusters[0].cluster.certificate-authority-data}\' | base64 --decode > hacktricks-cspm-cluster-ca.crt',
  'kubectl --kubeconfig=hacktricks-cspm-scan.kubeconfig config set-cluster hacktricks-cspm-target --server="$SERVER" --certificate-authority=hacktricks-cspm-cluster-ca.crt --embed-certs=true',
  'kubectl --kubeconfig=hacktricks-cspm-scan.kubeconfig config set-credentials hacktricks-cspm-scan --token="$(cat hacktricks-cspm-scan.token)"',
  'kubectl --kubeconfig=hacktricks-cspm-scan.kubeconfig config set-context hacktricks-cspm-target --cluster=hacktricks-cspm-target --user=hacktricks-cspm-scan',
  'kubectl --kubeconfig=hacktricks-cspm-scan.kubeconfig config use-context hacktricks-cspm-target',
].join("\n") };
const k8sCertAccess = { label: "kubectl: request and approve a scanning client certificate", value: [
  "USERNAME='hacktricks-cspm-scan'",
  'openssl req -new -newkey rsa:3072 -nodes -keyout hacktricks-cspm-scan.key -out hacktricks-cspm-scan.csr -subj "/CN=$USERNAME"',
  'CSR_BASE64="$(base64 < hacktricks-cspm-scan.csr | tr -d "\\n")"',
  "cat > hacktricks-cspm-scan-csr.yaml <<EOF",
  'apiVersion: certificates.k8s.io/v1',
  'kind: CertificateSigningRequest',
  'metadata: {name: hacktricks-cspm-scan}',
  'spec:',
  '  request: $CSR_BASE64',
  '  signerName: kubernetes.io/kube-apiserver-client',
  '  usages: [client auth]',
  "EOF",
  'kubectl apply -f hacktricks-cspm-scan-csr.yaml',
  'kubectl certificate approve hacktricks-cspm-scan',
  'kubectl get csr hacktricks-cspm-scan -o jsonpath=\'{.status.certificate}\' | base64 --decode > hacktricks-cspm-scan.crt',
].join("\n") };
const aws = (access: string, url: string, commands = [awsRoleGrant], accessCommandCount = 0): AuthGuide => ({ access, permissions: awsPermissions, permissionIds: awsPolicyArns, url, link: "AWS setup guide", commands, accessCommandCount });
const gcp = (access: string, url: string, commands = [gcpGrant()], accessCommandCount = 0): AuthGuide => ({ access, permissions: gcpPermissions, permissionIds: gcpRoles, url, link: "Google Cloud setup guide", commands, accessCommandCount });
const azure = (access: string, url: string, commands = [azureAppGrant, azureVaultGrant, azureGraphGrant], accessCommandCount = 0): AuthGuide => ({ access, permissions: azurePermissions, permissionIds: azureRoleIds, url, link: "Microsoft setup guide", commands, accessCommandCount });
const k8s = (access: string, url: string, commands = [k8sCreateServiceAccount, k8sServiceAccountGrant, k8sExtraSaGrant, k8sSecretGrant], accessCommandCount = 0): AuthGuide => ({ access, permissions: k8sPermissions, url, link: "Kubernetes setup guide", commands, accessCommandCount });

export const authGuides: Record<Provider, Record<string, AuthGuide>> = {
  aws: {
    default: aws("Configure an AWS profile, environment variables, or an attached workload role on the HackTricks CSPM server. The default credential chain selects it automatically.", "https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-authentication.html", [awsDefaultAccess, awsRoleGrant], 1),
    profile: aws("Run aws configure --profile NAME, or create a named role profile in the server's AWS config, then enter NAME here.", "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html", [{ label: "AWS CLI: configure named profile", value: "aws configure --profile hacktricks-cspm-scan" }, awsRoleGrant], 1),
    sso: aws("Run aws configure sso on the server, choose an account and permission set, then run aws sso login --profile NAME and enter NAME here.", "https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html", [{ label: "AWS CLI: configure and sign in with SSO", value: "aws configure sso --profile hacktricks-cspm-scan\naws sso login --profile hacktricks-cspm-scan" }, awsSsoGrant], 1),
    access_keys: aws("Create an access key for a dedicated IAM scanning user, or obtain temporary STS credentials. Enter the session token when one was issued.", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html", [awsCreateUser, awsUserGrant], 1),
    assume_role: aws("Create a target role in each account with a trust policy naming the HackTricks CSPM server's source IAM principal. The source role also needs sts:AssumeRole on each target ARN. Enter each role ARN below.", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user_externalid.html", [awsAssumeAccess, awsRoleGrant, awsSourceAssumeGrant], 1),
    web_identity: aws("Register your OIDC provider in IAM, then create a role limited to its issuer, exact subject and sts.amazonaws.com audience. Provide AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE to the HackTricks CSPM server.", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html", [awsWebIdentityAccess, awsRoleGrant], 1),
    container: aws("Create an ECS task role and set its ARN as taskRoleArn on the task definition running HackTricks CSPM. The SDK gets temporary credentials from task metadata.", "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html", [awsContainerAccess, awsRoleGrant], 1),
    instance: aws("Create an EC2 role and instance profile, then associate that profile with the HackTricks CSPM host.", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html", [awsInstanceAccess, awsRoleGrant], 1),
  },
  gcp: {
    adc: gcp("On the HackTricks CSPM server, run gcloud auth application-default login for a local user, or attach a service account to the workload. ADC selects the available source.", "https://cloud.google.com/docs/authentication/application-default-credentials", [{ label: "gcloud CLI: create local ADC", value: "gcloud auth application-default login" }, gcpGrant("user:REPLACE_WITH_SIGNED_IN_EMAIL")], 1),
    gcloud: gcp("Run gcloud auth login on the HackTricks CSPM server and select the account to use. Enter its email here if several accounts are signed in.", "https://cloud.google.com/sdk/gcloud/reference/auth/login", [{ label: "gcloud CLI: sign in", value: "gcloud auth login" }, gcpGrant("user:REPLACE_WITH_SIGNED_IN_EMAIL")], 1),
    "platform-service-account": gcp("Grant the HackTricks service account access to each selected project and add this connector’s approval label. Enter exact project IDs; shared-account discovery is disabled.", "https://cloud.google.com/resource-manager/docs/creating-managing-labels", [gcpGrant("serviceAccount:SERVICE_ACCOUNT_FROM_CONNECTOR_SETUP")]),
    "service-account": gcp("Create a dedicated service account and JSON key in Google Cloud IAM, then upload the key here. Keep the key private and rotate it when needed.", "https://cloud.google.com/iam/docs/keys-create-delete", [gcpCreateSaKey, gcpGrant("serviceAccount:hacktricks-cspm-scan@REPLACE_WITH_IDENTITY_PROJECT_ID.iam.gserviceaccount.com")], 1),
    impersonation: gcp("Create a target service account and configure ADC or an attached source identity on the server. Grant the source Service Account Token Creator on the target; grant project read roles to the target.", "https://cloud.google.com/docs/authentication/use-service-account-impersonation", [gcpCreateTargetSa, gcpImpersonationGrant, gcpGrant("serviceAccount:REPLACE_WITH_TARGET_SA_EMAIL")], 1),
    "external-account": gcp("Create a target service account, workload identity pool, OIDC provider and credential configuration on the HackTricks CSPM server. The subject token must match the exact subject granted on the target service account.", "https://cloud.google.com/iam/docs/workload-identity-federation", [gcpCreateTargetSa, gcpExternalAccess, gcpExternalGrant, gcpGrant("serviceAccount:REPLACE_WITH_TARGET_SA_EMAIL")], 2),
    metadata: gcp("Attach a dedicated service account to the VM running HackTricks CSPM. For another workload type, set its service account in that workload's deployment configuration.", "https://cloud.google.com/docs/authentication/set-up-adc-attached-service-account", [gcpMetadataAccess, gcpGrant("serviceAccount:hacktricks-cspm-scan@REPLACE_WITH_IDENTITY_PROJECT_ID.iam.gserviceaccount.com")], 1),
    token: gcp("Generate a short-lived OAuth access token for an identity with project read permissions, for example with gcloud auth print-access-token. Replace it when it expires.", "https://cloud.google.com/sdk/gcloud/reference/auth/print-access-token", [{ label: "gcloud CLI: print temporary access token", value: "gcloud auth print-access-token" }, gcpGrant("user:REPLACE_WITH_TOKEN_OWNER_EMAIL")], 1),
  },
  azure: {
    "client-cert-inline": azure("Register an Entra app, upload the public certificate, then paste the combined private key and certificate PEM here. Keep the private key out of the app registration.", "https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials", [azureCreateCertApp, azureAppGrant, azureVaultGrant, azureGraphGrant], 1),
    "workload-identity-inline": azure("Register an Entra app and an exact federated issuer and subject. Paste a current OIDC assertion with api://AzureADTokenExchange as its audience.", "https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation", [azureFederationAccess, azureAppGrant, azureVaultGrant, azureGraphGrant], 1),
    "az-cli": azure("Run az login on the HackTricks CSPM server and select the tenant and subscription with az account set. The collector uses that CLI session.", "https://learn.microsoft.com/en-us/cli/azure/authenticate-azure-cli-interactively", [{ label: "Azure CLI: sign in and choose subscription", value: "az login\naz account set --subscription REPLACE_WITH_SUBSCRIPTION_ID" }, azureUserGrant, azureVaultUserGrant], 1),
    "client-secret": azure("Register an Entra app, create a client secret under Certificates & secrets, and enter its tenant ID, application ID, and secret value here.", "https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app", [azureCreateSp, azureAppGrant, azureVaultGrant, azureGraphGrant], 1),
    "client-cert": azure("Register an Entra app, upload its public certificate, and place the combined private key and certificate PEM on the HackTricks CSPM server; enter its path here.", "https://learn.microsoft.com/en-us/entra/identity-platform/certificate-credentials", [azureCreateCertApp, azureAppGrant, azureVaultGrant, azureGraphGrant], 1),
    "managed-identity": azure("Enable a system-assigned managed identity on the HackTricks CSPM VM or equivalent workload, then grant its object ID subscription and Graph read roles.", "https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/assign-app-role-managed-identity-azure-cli", [azureManagedIdentityAccess, azureAppGrant, azureVaultGrant, azureManagedIdentityGraphGrant], 1),
    "workload-identity": azure("Add a federated credential to an Entra app and mount a matching OIDC token file on the HackTricks CSPM server; enter its path here.", "https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation", [azureFederationAccess, azureAppGrant, azureVaultGrant, azureGraphGrant], 1),
    token: azure("Use az account get-access-token to obtain an ARM token and, if needed, a separate Microsoft Graph token. Paste both before they expire.", "https://learn.microsoft.com/en-us/cli/azure/account", [{ label: "Azure CLI: obtain ARM and Graph tokens", value: "az account get-access-token --resource-type arm --query accessToken -o tsv\naz account get-access-token --resource-type ms-graph --query accessToken -o tsv" }, azureUserGrant, azureVaultUserGrant], 1),
    default: azure("Configure Azure CLI, managed identity, or environment credentials on the HackTricks CSPM server. The Azure default credential chain selects the available source.", "https://learn.microsoft.com/en-us/python/api/azure-identity/azure.identity.defaultazurecredential", [{ label: "Azure CLI: verify default local identity", value: "az login\naz account set --subscription REPLACE_WITH_SUBSCRIPTION_ID\naz account show --query id -o tsv" }, azureUserGrant, azureVaultUserGrant, azureAppGrant, azureVaultGrant, azureGraphGrant], 1),
  },
  k8s: {
    "kubeconfig-inline": k8s("Create a dedicated service-account kubeconfig with the target API server, embedded CA and token. Paste its YAML here. Exec helpers, auth-provider plugins, proxy settings and references to credential files are rejected. Rotate its short-lived token before expiration.", "https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/", [k8sKubeconfigAccess, k8sServiceAccountGrant, k8sExtraSaGrant, k8sSecretGrant], 1),
    "certificate-inline": k8s("Request a client certificate signed by the cluster CA. A cluster administrator must approve the CSR. Paste the resulting certificate and private key here.", "https://kubernetes.io/docs/reference/access-authn-authz/authentication/", [k8sCertAccess, k8sUserGrant, k8sExtraUserGrant, k8sSecretUserGrant], 1),
    kubeconfig: k8s("Create a dedicated service-account kubeconfig with embedded credentials, place it on the HackTricks CSPM server, and enter its path and context. The file is parsed as data only: exec helpers, auth-provider plugins, proxies and external credential files are rejected. Rotate its token before expiration.", "https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/", [k8sKubeconfigAccess, k8sServiceAccountGrant, k8sExtraSaGrant, k8sSecretGrant], 1),
    in_cluster: k8s("Run HackTricks CSPM in the cluster with a dedicated service account set on its Pod. The mounted token supplies authentication.", "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/", [k8sCreateServiceAccount, k8sServiceAccountGrant, k8sExtraSaGrant, k8sSecretGrant], 1),
    token: k8s("Create a dedicated service account and issue a short-lived token with kubectl create token SERVICE_ACCOUNT. Enter the API server URL, token, and CA.", "https://kubernetes.io/docs/reference/kubectl/generated/kubectl_create/kubectl_create_token/", [k8sCreateServiceAccount, { label: "kubectl: issue short-lived token", value: "NAMESPACE='REPLACE_WITH_NAMESPACE'\nkubectl -n \"$NAMESPACE\" create token hacktricks-cspm-scan" }, k8sServiceAccountGrant, k8sExtraSaGrant, k8sSecretGrant], 2),
    certificate: k8s("Request a client certificate signed by the cluster CA, then place the certificate and key on the HackTricks CSPM server. A cluster administrator must approve the CSR.", "https://kubernetes.io/docs/reference/access-authn-authz/authentication/", [k8sCertAccess, k8sUserGrant, k8sExtraUserGrant, k8sSecretUserGrant], 1),
  },
};
