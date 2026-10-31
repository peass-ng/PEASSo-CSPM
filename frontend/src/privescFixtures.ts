// Fixture privilege-escalation map for the explicit demo mode. Shapes follow
// docs/privesc.md exactly. Illustrative data only: no cloud was assessed.
import type {
  Finding,
  PrivescConfidence,
  PrivescEdge,
  PrivescEvidenceRef,
  PrivescGraph,
  PrivescNode,
} from "./types";
import {
  broadReach,
  principalCard,
  PrivescIndex,
  reachAdmin,
  shortestPaths,
} from "./privescQueries";

type Technique = {
  title: string;
  service: string;
  severity: string;
  source: string;
  summary: string;
  mitigation: string;
  requires: Record<string, unknown>[];
  conditions?: { id: string; description: string }[];
};
const HT = "src/pentesting-cloud";
const techniques: Record<string, Technique> = {
  "aws-ec2-passrole-runinstances": {
    title: "Launch an EC2 instance with a passed instance profile",
    service: "ec2",
    severity: "high",
    source: `${HT}/aws-security/aws-privilege-escalation/aws-ec2-privesc/README.md#iampassrole-ec2runinstances`,
    summary:
      "The source can obtain the credentials of any role it may pass to a new instance.",
    mitigation:
      "Restrict iam:PassRole Resource to specific roles and add an iam:PassedToService condition.",
    requires: [
      { action: "iam:PassRole", resource: "{target.arn}" },
      { action: "ec2:RunInstances", resource: "*" },
    ],
    conditions: [
      {
        id: "passrole_condition_key",
        description:
          "iam:PassedToService / iam:AssociatedResourceArn conditions may restrict this",
      },
    ],
  },
  "aws-sts-assumerole": {
    title: "Assume a role whose trust policy allows the source",
    service: "sts",
    severity: "high",
    source: `${HT}/aws-security/aws-privilege-escalation/aws-sts-privesc/README.md#stsassumerole`,
    summary: "The source can obtain the target role's session credentials.",
    mitigation:
      "Limit role trust policies to the exact principals that need them and require an external ID or MFA.",
    requires: [{ action: "sts:AssumeRole", resource: "{target.arn}" }],
  },
  "aws-lambda-passrole-createfunction": {
    title: "Create a Lambda function with a passed execution role",
    service: "lambda",
    severity: "high",
    source: `${HT}/aws-security/aws-privilege-escalation/aws-lambda-privesc/README.md#iampassrole-lambdacreatefunction-lambdainvokefunction`,
    summary: "The source can run code with any execution role it may pass.",
    mitigation:
      "Scope iam:PassRole to dedicated Lambda roles and restrict lambda:CreateFunction.",
    requires: [
      { action: "iam:PassRole", resource: "{target.arn}" },
      { action: "lambda:CreateFunction", resource: "*" },
      { action: "lambda:InvokeFunction", resource: "*" },
    ],
  },
  "aws-lambda-updatefunctioncode": {
    title: "Update the code of a Lambda function running as the target role",
    service: "lambda",
    severity: "high",
    source: `${HT}/aws-security/aws-privilege-escalation/aws-lambda-privesc/README.md#lambdaupdatefunctioncode`,
    summary: "The source can execute with the function's execution role.",
    mitigation:
      "Restrict lambda:UpdateFunctionCode to deployment pipelines and sign code.",
    requires: [
      { action: "lambda:UpdateFunctionCode", resource: "{target.function_arn}" },
    ],
  },
  "aws-iam-attach-role-policy": {
    title: "Attach a managed policy to a role the source controls",
    service: "iam",
    severity: "critical",
    source: `${HT}/aws-security/aws-privilege-escalation/aws-iam-privesc/README.md#iamattachuserpolicy-iamattachgrouppolicy-iamattachrolepolicy`,
    summary: "The source can grant itself AdministratorAccess.",
    mitigation:
      "Deny iam:Attach*Policy outside of break-glass roles and use permission boundaries.",
    requires: [{ action: "iam:AttachRolePolicy", resource: "{source.arn}" }],
  },
  "aws-iam-create-policy-version": {
    title: "Create a new default version of an attached policy",
    service: "iam",
    severity: "critical",
    source: `${HT}/aws-security/aws-privilege-escalation/aws-iam-privesc/README.md#iamcreatepolicyversion`,
    summary: "The source can rewrite its own policy to grant full access.",
    mitigation:
      "Remove iam:CreatePolicyVersion from non-administrators; alert on SetAsDefault.",
    requires: [
      { action: "iam:CreatePolicyVersion", resource: "{source.policy_arn}" },
    ],
  },
  "aws-glue-passrole-createjob": {
    title: "Create a Glue job with a passed role",
    service: "glue",
    severity: "medium",
    source: `${HT}/aws-security/aws-privilege-escalation/aws-glue-privesc.md#iampassrole-gluecreatejob-gluestartjobrun`,
    summary: "The source can run a job as a role trusting Glue.",
    mitigation: "Restrict iam:PassRole for glue.amazonaws.com roles.",
    requires: [
      { action: "iam:PassRole", resource: "{target.arn}" },
      { action: "glue:CreateJob", resource: "*" },
    ],
  },
  "aws-codebuild-passrole": {
    title: "Start a CodeBuild project with a passed service role",
    service: "codebuild",
    severity: "medium",
    source: `${HT}/aws-security/aws-privilege-escalation/aws-codebuild-privesc/README.md#iampassrole-codebuildcreateproject`,
    summary: "The source can run a build as a role trusting CodeBuild.",
    mitigation: "Scope codebuild:CreateProject and iam:PassRole.",
    requires: [
      { action: "iam:PassRole", resource: "{target.arn}" },
      { action: "codebuild:CreateProject", resource: "*" },
    ],
  },
  "aws-batch-submitjob-existing-definition": {
    title: "Submit a job using an existing job definition with a job role",
    service: "batch",
    severity: "high",
    source: `${HT}/aws-security/aws-privilege-escalation/aws-batch-privesc/README.md`,
    summary: "The source can submit a Batch job whose definition runs as a job role, gaining that role's credentials.",
    mitigation: "Scope batch:SubmitJob to specific job definitions and queues; keep job roles least-privileged.",
    requires: [{ action: "batch:SubmitJob", resource: "*" }],
    conditions: [{ id: "batch_attachment_not_collected", description: "Batch job definitions and their job roles were not collected." }],
  },
  "gcp-iam-sa-token-creator": {
    title: "Mint access tokens for a service account",
    service: "iam",
    severity: "high",
    source: `${HT}/gcp-security/gcp-privilege-escalation/gcp-iam-privesc.md#iamserviceaccountsgetaccesstoken`,
    summary: "The source can act as the target service account.",
    mitigation:
      "Grant roles/iam.serviceAccountTokenCreator only on specific service accounts.",
    requires: [
      {
        permission: "iam.serviceAccounts.getAccessToken",
        resource: "{target.email}",
      },
    ],
  },
  "gcp-iam-sa-key-create": {
    title: "Create a key for a service account",
    service: "iam",
    severity: "high",
    source: `${HT}/gcp-security/gcp-privilege-escalation/gcp-iam-privesc.md#iamserviceaccountkeyscreate`,
    summary: "The source can obtain long-lived credentials for the target.",
    mitigation:
      "Enforce iam.disableServiceAccountKeyCreation and remove key admin grants.",
    requires: [
      { permission: "iam.serviceAccountKeys.create", resource: "{target.email}" },
    ],
  },
  "gcp-compute-instances-create-actas": {
    title: "Create a VM running as a service account",
    service: "compute",
    severity: "high",
    source: `${HT}/gcp-security/gcp-privilege-escalation/gcp-compute-privesc/README.md#computeinstancescreate`,
    summary:
      "The source can obtain the token of a service account it may attach.",
    mitigation:
      "Limit iam.serviceAccounts.actAs to the service accounts a workload needs.",
    requires: [
      { permission: "compute.instances.create", resource: "{project}" },
      { permission: "iam.serviceAccounts.actAs", resource: "{target.email}" },
    ],
    conditions: [
      {
        id: "binding_condition",
        description: "An IAM condition on the binding may restrict this",
      },
    ],
  },
  "gcp-cloudfunctions-create-actas": {
    title: "Deploy a Cloud Function running as a service account",
    service: "cloudfunctions",
    severity: "high",
    source: `${HT}/gcp-security/gcp-privilege-escalation/gcp-cloudfunctions-privesc.md#cloudfunctionsfunctionscreate`,
    summary: "The source can execute as the function's service account.",
    mitigation: "Restrict actAs and cloudfunctions.functions.create.",
    requires: [
      { permission: "cloudfunctions.functions.create", resource: "{project}" },
      { permission: "iam.serviceAccounts.actAs", resource: "{target.email}" },
    ],
  },
  "gcp-resourcemanager-setiampolicy": {
    title: "Change the IAM policy of a project",
    service: "resourcemanager",
    severity: "critical",
    source: `${HT}/gcp-security/gcp-privilege-escalation/gcp-resourcemanager-privesc.md#resourcemanagerprojectssetiampolicy`,
    summary: "The source can grant itself Owner on the project.",
    mitigation:
      "Remove setIamPolicy from basic roles; use custom least-privilege roles.",
    requires: [
      {
        permission: "resourcemanager.projects.setIamPolicy",
        resource: "{target.scope}",
      },
    ],
  },
  "azure-automation-runbook-identity": {
    title: "Run an Automation runbook with its managed identity",
    service: "automation",
    severity: "high",
    source: `${HT}/azure-security/az-privilege-escalation/az-automation-accounts-privesc.md`,
    summary: "The source can execute as the automation account identity.",
    mitigation:
      "Restrict runbook write/publish and scope the managed identity role.",
    requires: [
      {
        action: "Microsoft.Automation/automationAccounts/runbooks/write",
        scope: "{target.scope}",
      },
      {
        action: "Microsoft.Automation/automationAccounts/jobs/write",
        scope: "{target.scope}",
      },
    ],
  },
  "azure-entra-app-add-credential": {
    title: "Add a credential to an application",
    service: "entra",
    severity: "high",
    source: `${HT}/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#applications`,
    summary: "The source can authenticate as the application's service principal.",
    mitigation:
      "Limit application owners and Application Administrator assignments.",
    requires: [
      {
        entra_permission:
          "microsoft.directory/applications/credentials/update",
      },
    ],
  },
  "azure-entra-role-assign": {
    title: "Assign an Entra directory role",
    service: "entra",
    severity: "critical",
    source: `${HT}/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#privileged-role-administrator`,
    summary: "The source can assign itself Global Administrator.",
    mitigation:
      "Require PIM approval for Privileged Role Administrator and monitor role assignments.",
    requires: [
      {
        entra_permission:
          "microsoft.directory/roleAssignments/allProperties/allTasks",
      },
    ],
    conditions: [
      {
        id: "restricted_admin_unit",
        description: "Restricted administrative units may prevent this",
      },
    ],
  },
  "azure-rbac-roleassignment-write": {
    title: "Create an Azure role assignment",
    service: "authorization",
    severity: "critical",
    source: `${HT}/azure-security/az-privilege-escalation/az-authorization-privesc.md#microsoftauthorizationroleassignmentswrite`,
    summary: "The source can grant itself Owner on the scope.",
    mitigation:
      "Restrict roleAssignments/write with ABAC conditions on assignable roles.",
    requires: [
      {
        action: "Microsoft.Authorization/roleAssignments/write",
        scope: "{target.scope}",
      },
    ],
  },
  "azure-sp-add-secret": {
    title: "Add a secret to a service principal",
    service: "entra",
    severity: "high",
    source: `${HT}/azure-security/az-privilege-escalation/az-entraid-privesc/README.md#service-principals`,
    summary: "The source can authenticate as the service principal.",
    mitigation: "Remove ownership of service principals from regular users.",
    requires: [
      {
        entra_permission:
          "microsoft.directory/servicePrincipals/credentials/update",
      },
    ],
  },
  "k8s-pods-create": {
    title: "Create a pod that mounts a service account token",
    service: "pods",
    severity: "high",
    source: `${HT}/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/README.md#pod-creation-steal-token`,
    summary: "The source can obtain the token of any service account in the namespace.",
    mitigation:
      "Restrict pods/create and enforce Pod Security admission in privileged namespaces.",
    requires: [
      { verb: "create", resource: "pods", namespace: "{target.namespace}" },
    ],
  },
  "k8s-pods-exec": {
    title: "Exec into a running pod",
    service: "pods",
    severity: "high",
    source: `${HT}/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/README.md#pods-exec`,
    summary: "The source can act with the pod's service account token.",
    mitigation: "Remove pods/exec from non-operator roles.",
    requires: [
      {
        verb: "create",
        resource: "pods",
        subresource: "exec",
        namespace: "{target.namespace}",
      },
    ],
  },
  "k8s-escalate-bind": {
    title: "Bind or escalate cluster roles",
    service: "rbac",
    severity: "critical",
    source: `${HT}/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/README.md#escalate`,
    summary: "The source can bind cluster-admin to itself.",
    mitigation: "Remove the bind and escalate verbs from non-admin roles.",
    requires: [
      { verb: "bind", resource: "clusterroles", api_group: "rbac.authorization.k8s.io" },
    ],
  },
  "k8s-serviceaccounts-token-create": {
    title: "Create a token for a service account",
    service: "serviceaccounts",
    severity: "high",
    source: `${HT}/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/README.md#create-token`,
    summary: "The source can act as the target service account.",
    mitigation: "Restrict serviceaccounts/token create.",
    requires: [
      {
        verb: "create",
        resource: "serviceaccounts",
        subresource: "token",
        namespace: "{target.namespace}",
      },
    ],
  },
  "k8s-secrets-get": {
    title: "Read service account token secrets",
    service: "secrets",
    severity: "medium",
    source: `${HT}/kubernetes-security/abusing-roles-clusterroles-in-kubernetes/README.md#listing-secrets`,
    summary: "The source can read legacy token secrets in the namespace.",
    mitigation: "Avoid legacy token secrets and restrict secrets/get.",
    requires: [
      { verb: "get", resource: "secrets", namespace: "{target.namespace}" },
    ],
  },
  "k8s-cloud-identity": {
    title: "Use the cloud identity federated to a service account",
    service: "workload-identity",
    severity: "high",
    source: `${HT}/kubernetes-security/kubernetes-pivoting-to-clouds.md`,
    summary: "The source can obtain the cloud role federated to the service account.",
    mitigation: "Scope IRSA trust policies to a single namespace and service account.",
    requires: [{ annotation: "eks.amazonaws.com/role-arn" }],
  },
  "admin-equivalent": {
    title: "Already administers the target scope",
    service: "iam",
    severity: "critical",
    source: "",
    summary: "The source holds an administrator-equivalent grant on the scope.",
    mitigation: "Confirm the administrative grant is intended and protected by MFA.",
    requires: [],
  },
};

const AWS = "111111111111";
const aws = (path: string) => `arn:aws:iam::${AWS}:${path}`;
const node = (
  id: string,
  label: string,
  type: string,
  provider: string,
  scope: string,
  kind = "principal",
  attrs: Record<string, unknown> = {},
): PrivescNode => ({ id, label, type, provider, scope, kind, attrs });

const ec2Members = [
  aws("role/ec2-app-role"),
  ...Array.from({ length: 11 }, (_, i) => aws(`role/ec2-web-${i}`)),
];
const kubeSystemMembers = [
  "k8s:prod-eks:sa:kube-system:clusterrole-aggregation-controller",
  ...[
    "coredns",
    "kube-proxy",
    "aws-node",
    "ebs-csi-controller",
    "metrics-server",
    "replicaset-controller",
    "deployment-controller",
    "job-controller",
    "namespace-controller",
    "node-controller",
    "pv-protection-controller",
    "endpoint-controller",
    "cronjob-controller",
    "daemon-set-controller",
    "statefulset-controller",
    "ttl-controller",
    "generic-garbage-collector",
  ].map((n) => `k8s:prod-eks:sa:kube-system:${n}`),
];
const sample = (members: string[], type: string, provider: string, scope: string) =>
  members.slice(0, 5).map((id) =>
    node(id, id.split(/[/:]/).pop() || id, type, provider, scope),
  );

const nodes: PrivescNode[] = [
  // AWS
  node(aws("user/alice"), "alice", "aws_user", "aws", AWS, "principal", { arn: aws("user/alice"), account: AWS, name: "alice" }),
  node(aws("user/bob-ci"), "bob-ci", "aws_user", "aws", AWS, "principal", { arn: aws("user/bob-ci"), account: AWS, name: "bob-ci" }),
  node(aws("user/carol"), "carol", "aws_user", "aws", AWS, "principal", { arn: aws("user/carol"), account: AWS, name: "carol" }),
  node(aws("user/dave-intern"), "dave-intern", "aws_user", "aws", AWS, "principal", { arn: aws("user/dave-intern"), account: AWS, name: "dave-intern" }),
  node(aws("role/ec2-app-role"), "ec2-app-role", "aws_role", "aws", AWS, "principal", { arn: aws("role/ec2-app-role"), account: AWS, name: "ec2-app-role" }),
  node(aws("role/lambda-exec-role"), "lambda-exec-role", "aws_role", "aws", AWS, "principal", { arn: aws("role/lambda-exec-role"), account: AWS, name: "lambda-exec-role" }),
  node(aws("role/OrganizationAdmin"), "OrganizationAdmin", "aws_role", "aws", AWS, "principal", { arn: aws("role/OrganizationAdmin"), account: AWS, name: "OrganizationAdmin" }),
  node(aws("role/data-pipeline-role"), "data-pipeline-role", "aws_role", "aws", AWS, "principal", { arn: aws("role/data-pipeline-role"), account: AWS, name: "data-pipeline-role" }),
  node(aws("role/ci-build-role"), "ci-build-role", "aws_role", "aws", AWS, "principal", { arn: aws("role/ci-build-role"), account: AWS, name: "ci-build-role" }),
  {
    id: `agg:aws_role:8aa5e4f516:${AWS}:conditional`,
    kind: "aggregate",
    type: "aws_role",
    provider: "aws",
    scope: AWS,
    label: `Roles trusting ec2.amazonaws.com with an instance profile in ${AWS}`,
    underlying_count: ec2Members.length,
    members: ec2Members,
    member_sample: sample(ec2Members, "aws_role", "aws", AWS),
    confidence: "conditional",
    candidate_set: "aws_role:8aa5e4f516",
    subset: false,
  },
  node(`aws_account_admin:${AWS}`, `Account ${AWS} administrator`, "aws_account_admin", "aws", AWS, "entity", { admin: true, account: AWS }),
  // GCP
  node("user:erin@acme.example", "erin@acme.example", "gcp_user", "gcp", "projects/acme-prod", "principal", { email: "erin@acme.example" }),
  node("user:frank@acme.example", "frank@acme.example", "gcp_user", "gcp", "projects/acme-prod", "principal", { email: "frank@acme.example" }),
  node("user:gina@acme.example", "gina@acme.example", "gcp_user", "gcp", "projects/acme-data", "principal", { email: "gina@acme.example" }),
  node("serviceAccount:deploy@acme-prod.iam.gserviceaccount.com", "deploy@acme-prod", "gcp_service_account", "gcp", "projects/acme-prod", "principal", { email: "deploy@acme-prod.iam.gserviceaccount.com" }),
  node("serviceAccount:terraform@acme-prod.iam.gserviceaccount.com", "terraform@acme-prod", "gcp_service_account", "gcp", "projects/acme-prod", "principal", { email: "terraform@acme-prod.iam.gserviceaccount.com" }),
  node("serviceAccount:123-compute@developer.gserviceaccount.com", "Compute default SA", "gcp_service_account", "gcp", "projects/acme-prod", "principal", { email: "123-compute@developer.gserviceaccount.com" }),
  node("serviceAccount:ml-runner@acme-data.iam.gserviceaccount.com", "ml-runner@acme-data", "gcp_service_account", "gcp", "projects/acme-data", "principal", { email: "ml-runner@acme-data.iam.gserviceaccount.com" }),
  node("gcp_scope_owner:projects/acme-prod", "Owner of projects/acme-prod", "gcp_scope_owner", "gcp", "projects/acme-prod", "entity", { admin: true }),
  node("gcp_scope_owner:organizations/4242", "Owner of organizations/4242", "gcp_scope_owner", "gcp", "organizations/4242", "entity", { admin: true }),
  // Azure
  node("8b1c0e9a-grace", "grace@contoso.example", "azure_user", "azure", "/subscriptions/sub-prod", "principal", { upn: "grace@contoso.example" }),
  node("2d4f6a1c-heidi", "heidi@contoso.example", "azure_user", "azure", "/subscriptions/sub-prod", "principal", { upn: "heidi@contoso.example" }),
  node("7e7e7e7e-ivan", "ivan@contoso.example", "azure_user", "azure", "/subscriptions/sub-prod", "principal", { upn: "ivan@contoso.example" }),
  node("5a5a5a5a-ci-sp", "ci-pipeline-sp", "azure_service_principal", "azure", "/subscriptions/sub-prod", "principal", { app_id: "0000-ci" }),
  node("9c9c9c9c-app-sp", "billing-app-sp", "azure_service_principal", "azure", "/subscriptions/sub-prod", "principal", { app_id: "0000-billing" }),
  node("3f3f3f3f-automation-mi", "automation-mi", "azure_managed_identity", "azure", "/subscriptions/sub-prod/resourcegroups/rg-ops", "principal", { assigned: "system" }),
  node("azure_scope_owner:/subscriptions/sub-prod", "Owner of subscription sub-prod", "azure_scope_owner", "azure", "/subscriptions/sub-prod", "entity", { admin: true }),
  node("azure_scope_owner:/subscriptions/sub-prod/resourcegroups/rg-app", "Owner of rg-app", "azure_scope_owner", "azure", "/subscriptions/sub-prod/resourcegroups/rg-app", "entity", { admin: true }),
  node("entra_role:62e90394-69f5-4237-9190-012177145e10", "Global Administrator", "entra_role", "azure", "tenant", "entity", { admin: true, template_id: "62e90394-69f5-4237-9190-012177145e10" }),
  // Kubernetes
  node("k8s:prod-eks:user:jenkins", "jenkins", "k8s_user", "k8s", "prod-eks", "principal", { cluster: "prod-eks" }),
  node("k8s:prod-eks:user:oncall", "oncall", "k8s_user", "k8s", "prod-eks", "principal", { cluster: "prod-eks" }),
  node("k8s:prod-eks:sa:ci:deployer", "ci/deployer", "k8s_service_account", "k8s", "prod-eks/ci", "principal", { cluster: "prod-eks", namespace: "ci", annotation: `eks.amazonaws.com/role-arn=${aws("role/data-pipeline-role")}` }),
  node("k8s:prod-eks:sa:monitoring:prometheus", "monitoring/prometheus", "k8s_service_account", "k8s", "prod-eks/monitoring", "principal", { cluster: "prod-eks", namespace: "monitoring" }),
  node("k8s:prod-eks:sa:default:default", "default/default", "k8s_service_account", "k8s", "prod-eks/default", "principal", { cluster: "prod-eks", namespace: "default" }),
  node("k8s:prod-eks:sa:kube-system:clusterrole-aggregation-controller", "kube-system/clusterrole-aggregation-controller", "k8s_service_account", "k8s", "prod-eks/kube-system", "principal", { cluster: "prod-eks", namespace: "kube-system" }),
  {
    id: "agg:k8s_service_account:4f1e2d9b07:prod-eks/kube-system:derived",
    kind: "aggregate",
    type: "k8s_service_account",
    provider: "k8s",
    scope: "prod-eks/kube-system",
    label: "Service accounts in prod-eks/kube-system",
    underlying_count: kubeSystemMembers.length,
    members: kubeSystemMembers,
    member_sample: sample(kubeSystemMembers, "k8s_service_account", "k8s", "prod-eks/kube-system"),
    confidence: "derived",
    candidate_set: "k8s_service_account:4f1e2d9b07",
    subset: false,
  },
  node("k8s_cluster_admin:prod-eks", "prod-eks cluster-admin", "k8s_cluster_admin", "k8s", "prod-eks", "entity", { admin: true }),
  {
    id: `unresolved:aws_role:298a174944:${AWS}`,
    kind: "aggregate",
    type: "aws_role",
    provider: "aws",
    scope: AWS,
    label: `Unresolved: Job roles of Batch job definitions covered by batch:SubmitJob in ${AWS}`,
    underlying_count: 0,
    members: [],
    member_sample: [],
    confidence: "unknown",
    candidate_set: "aws_role:298a174944",
    subset: false,
    unresolved: true,
    unresolved_reason: "batch_attachment_not_collected",
    facts_needed: "facts not in snapshot: batch_attachment_not_collected",
  },
];

const ref = {
  aws: (who: string, policy: string, statement = 0): PrivescEvidenceRef => ({
    policy: `${who}#inline/${policy}`,
    policy_name: policy,
    policy_type: "inline",
    statement,
    sid: null,
    effect: "Allow",
  }),
  gcp: (role: string, policy = "projects/acme-prod", condition: string | null = null): PrivescEvidenceRef => ({
    policy,
    role,
    binding: `${role}@${policy}`,
    condition,
  }),
  azure: (role: string, scope: string, via = "direct"): PrivescEvidenceRef => ({
    assignment: `${scope}/providers/Microsoft.Authorization/roleAssignments/${role.toLowerCase().replace(/\W+/g, "-")}`,
    role,
    scope,
    via,
  }),
  k8s: (binding: string, role: string, namespace: string | null): PrivescEvidenceRef => ({
    binding,
    role,
    namespace,
  }),
};
const K8S_ADMIN = "k8s_cluster_admin:prod-eks";
const edgeSpecs: [string, string, string[], PrivescConfidence, PrivescEvidenceRef[]][] = [
  [aws("user/alice"), `agg:aws_role:8aa5e4f516:${AWS}:conditional`, ["aws-ec2-passrole-runinstances"], "conditional", [ref.aws(aws("user/alice"), "alice-dev")]],
  [aws("role/ec2-app-role"), aws("role/OrganizationAdmin"), ["aws-sts-assumerole"], "derived", [ref.aws(aws("role/ec2-app-role"), "assume-admin")]],
  [aws("role/OrganizationAdmin"), `aws_account_admin:${AWS}`, ["admin-equivalent"], "derived", [{ policy: "arn:aws:iam::aws:policy/AdministratorAccess", policy_name: "AdministratorAccess", policy_type: "managed", statement: 0, sid: null, effect: "Allow" }]],
  [aws("user/bob-ci"), aws("role/lambda-exec-role"), ["aws-lambda-passrole-createfunction", "aws-lambda-updatefunctioncode"], "derived", [ref.aws(aws("user/bob-ci"), "ci-deploy"), ref.aws(aws("user/bob-ci"), "ci-deploy", 1)]],
  [aws("role/lambda-exec-role"), `aws_account_admin:${AWS}`, ["aws-iam-attach-role-policy"], "derived", [ref.aws(aws("role/lambda-exec-role"), "lambda-iam")]],
  [aws("user/carol"), `aws_account_admin:${AWS}`, ["aws-iam-create-policy-version"], "conditional", [{ policy: `arn:aws:iam::${AWS}:policy/analyst`, policy_name: "analyst", policy_type: "managed", statement: 2, sid: "PolicyOps", effect: "Allow" }]],
  [aws("user/dave-intern"), aws("role/data-pipeline-role"), ["aws-glue-passrole-createjob"], "conditional", [ref.aws(aws("user/dave-intern"), "intern-sandbox")]],
  [aws("role/data-pipeline-role"), aws("role/ci-build-role"), ["aws-codebuild-passrole"], "derived", [ref.aws(aws("role/data-pipeline-role"), "pipeline")]],
  [aws("role/ci-build-role"), aws("role/lambda-exec-role"), ["aws-lambda-updatefunctioncode"], "derived", [ref.aws(aws("role/ci-build-role"), "build")]],
  ["user:erin@acme.example", "serviceAccount:deploy@acme-prod.iam.gserviceaccount.com", ["gcp-iam-sa-token-creator"], "derived", [ref.gcp("roles/iam.serviceAccountTokenCreator", "projects/acme-prod/serviceAccounts/deploy")]],
  ["serviceAccount:deploy@acme-prod.iam.gserviceaccount.com", "serviceAccount:terraform@acme-prod.iam.gserviceaccount.com", ["gcp-iam-sa-key-create"], "derived", [ref.gcp("roles/iam.serviceAccountKeyAdmin")]],
  ["serviceAccount:terraform@acme-prod.iam.gserviceaccount.com", "gcp_scope_owner:organizations/4242", ["admin-equivalent"], "derived", [ref.gcp("roles/owner", "organizations/4242")]],
  ["user:frank@acme.example", "serviceAccount:123-compute@developer.gserviceaccount.com", ["gcp-compute-instances-create-actas"], "conditional", [ref.gcp("roles/compute.instanceAdmin.v1", "projects/acme-prod", "request.time < timestamp('2027-01-01T00:00:00Z')")]],
  ["user:frank@acme.example", "serviceAccount:ml-runner@acme-data.iam.gserviceaccount.com", ["gcp-cloudfunctions-create-actas"], "derived", [ref.gcp("roles/cloudfunctions.developer", "projects/acme-data")]],
  ["serviceAccount:123-compute@developer.gserviceaccount.com", "gcp_scope_owner:projects/acme-prod", ["gcp-resourcemanager-setiampolicy"], "conditional", [ref.gcp("roles/editor")]],
  ["user:gina@acme.example", "serviceAccount:ml-runner@acme-data.iam.gserviceaccount.com", ["gcp-iam-sa-token-creator"], "unknown", [ref.gcp("roles/iam.workloadIdentityUser", "projects/acme-data")]],
  ["8b1c0e9a-grace", "3f3f3f3f-automation-mi", ["azure-automation-runbook-identity"], "derived", [ref.azure("Automation Contributor", "/subscriptions/sub-prod/resourcegroups/rg-ops")]],
  ["3f3f3f3f-automation-mi", "azure_scope_owner:/subscriptions/sub-prod", ["admin-equivalent"], "derived", [ref.azure("Owner", "/subscriptions/sub-prod")]],
  ["2d4f6a1c-heidi", "9c9c9c9c-app-sp", ["azure-entra-app-add-credential"], "derived", [ref.azure("Application Administrator", "/", "directory_role")]],
  ["9c9c9c9c-app-sp", "entra_role:62e90394-69f5-4237-9190-012177145e10", ["azure-entra-role-assign"], "conditional", [ref.azure("Privileged Role Administrator", "/", "directory_role")]],
  ["7e7e7e7e-ivan", "5a5a5a5a-ci-sp", ["azure-sp-add-secret"], "unknown", [ref.azure("Owner (service principal)", "/", "ownership")]],
  ["5a5a5a5a-ci-sp", "azure_scope_owner:/subscriptions/sub-prod/resourcegroups/rg-app", ["azure-rbac-roleassignment-write"], "derived", [ref.azure("User Access Administrator", "/subscriptions/sub-prod/resourcegroups/rg-app", "group:platform-ops")]],
  ["k8s:prod-eks:user:jenkins", "k8s:prod-eks:sa:ci:deployer", ["k8s-serviceaccounts-token-create"], "derived", [ref.k8s("ci/jenkins-tokens", "Role/token-minter", "ci")]],
  ["k8s:prod-eks:sa:ci:deployer", "agg:k8s_service_account:4f1e2d9b07:prod-eks/kube-system:derived", ["k8s-pods-create", "k8s-pods-exec"], "derived", [ref.k8s("deployer-kube-system", "ClusterRole/workload-admin", "kube-system")]],
  ["k8s:prod-eks:sa:kube-system:clusterrole-aggregation-controller", K8S_ADMIN, ["k8s-escalate-bind"], "derived", [ref.k8s("system:controller:clusterrole-aggregation-controller", "ClusterRole/system:controller:clusterrole-aggregation-controller", null)]],
  ["k8s:prod-eks:sa:ci:deployer", aws("role/data-pipeline-role"), ["k8s-cloud-identity"], "unknown", [ref.k8s("irsa-annotation", "ServiceAccount/deployer", "ci")]],
  [aws("user/dave-intern"), `unresolved:aws_role:298a174944:${AWS}`, ["aws-batch-submitjob-existing-definition"], "unknown", [ref.aws(aws("user/dave-intern"), "intern-sandbox", 1)]],
  [aws("user/bob-ci"), `unresolved:aws_role:298a174944:${AWS}`, ["aws-batch-submitjob-existing-definition"], "unknown", [ref.aws(aws("user/bob-ci"), "ci-deploy", 2)]],
  ["k8s:prod-eks:user:oncall", "k8s:prod-eks:sa:monitoring:prometheus", ["k8s-pods-exec"], "derived", [ref.k8s("monitoring/oncall-debug", "Role/debugger", "monitoring")]],
  ["k8s:prod-eks:sa:monitoring:prometheus", "k8s:prod-eks:sa:default:default", ["k8s-secrets-get"], "conditional", [ref.k8s("prometheus-read", "ClusterRole/prometheus", null)]],
];

const providerOf = new Map(nodes.map((n) => [n.id, n]));
const findings: Finding[] = [];
const edges: PrivescEdge[] = edgeSpecs.map(([source, target, techs, confidence, refs], i) => {
  const src = providerOf.get(source)!;
  const tgt = providerOf.get(target)!;
  const ids = techs.map((t) => `privesc:${t}:${source}`);
  techs.forEach((t, j) => {
    const tech = techniques[t];
    if (findings.some((f) => f.id === ids[j])) return;
    findings.push({
      id: ids[j],
      category: "privesc",
      check_id: t,
      title: tech.title,
      provider: String(src.provider),
      service: tech.service,
      resource_id: source,
      scope: String(src.scope),
      severity: tech.severity,
      status: confidence === "unknown" ? "UNKNOWN" : "FAIL",
      frameworks: ["HackTricks Cloud Best Practices"],
      remediation: tech.mitigation,
      ...(t === "aws-ec2-passrole-runinstances" ? { remediation_details: {
        summary: "Remove the unnecessary iam:PassRole grant or constrain it to approved execution roles and a supported service condition.",
        steps: [
          "Inspect the supplied granting_statements reference and the inline policy attached to its user; identify legitimate launch operations.",
          "Review a replacement document that removes unused iam:PassRole or limits its Resource to approved role ARNs and, where supported, iam:PassedToService.",
          "Update only the granting inline policy through its owner, then test ordinary launches and rerun the finding.",
        ],
        cli: [
          { label: "Inspect the referenced inline user policy", shell: "bash", code: "aws iam get-user-policy --user-name <USER_NAME> --policy-name <POLICY_NAME>" },
          { label: "Apply a separately reviewed policy document", shell: "bash", code: "aws iam put-user-policy --user-name <USER_NAME> --policy-name <POLICY_NAME> --policy-document file://reviewed-policy.json" },
        ],
        iac: { label: "Update the owned policy declaration", language: "text", code: "Edit the granting inline user policy in its Terraform or CloudFormation owner; review the plan before applying it." },
        caveats: ["This demo finding has conditional confidence and does not prove an executable path.", "The fixture reference is illustrative; it does not supply a safe replacement policy or real AWS target."],
        references: [
          { title: "AWS PassRole guidance", url: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html" },
          { title: "AWS CLI inline user policy update", url: "https://docs.aws.amazon.com/cli/latest/reference/iam/put-user-policy.html" },
        ],
      }} : {}),
      evidence: {
        technique: {
          id: t,
          title: tech.title,
          source: tech.source || null,
          source_revision: tech.source ? "a53b46392c" : null,
          summary: tech.summary,
          requires: tech.requires,
        },
        source: src,
        targets: [
          {
            id: tgt.id,
            label: tgt.label,
            type: tgt.type,
            kind: tgt.kind,
            scope: tgt.scope,
            ...(tgt.kind === "aggregate"
              ? { underlying_count: tgt.underlying_count }
              : {}),
          },
        ],
        target_count:
          tgt.kind === "aggregate" ? Number(tgt.underlying_count || 0) : 1,
        granting_statements: refs,
        ...(t === "aws-iam-attach-role-policy" ? {
          granting_permissions: [{ permission: "iam:AttachRolePolicy", grant: refs[0] }],
        } : {}),
        conditions:
          confidence === "conditional"
            ? [src.provider === "aws" ? "scp_not_evaluated" : "condition_present"]
            : confidence === "unknown"
              ? ["facts_missing"]
              : [],
        confidence,
        ...(tech.conditions ? { technique_conditions: tech.conditions } : {}),
      },
    });
  });
  return {
    id: `e:${(0xfb963a15ef00 + i * 7919).toString(16)}`,
    source,
    target,
    techniques: techs,
    confidence,
    evidence_refs: refs,
    findings: ids,
  };
});

export const privescGraph: PrivescGraph = { nodes, edges };
export const privescFindings = findings;
const index = new PrivescIndex(privescGraph);

/** Fixture routes for the privesc endpoints; undefined when not a privesc path. */
export function privescDemoRequest(raw: string): unknown {
  const [path, query = ""] = raw.split("?");
  const params = new URLSearchParams(query);
  const depth = Number(params.get("max_depth") || 6);
  if (path.endsWith("/graphs/privesc")) return privescGraph;
  if (path.endsWith("/privesc/admins"))
    return reachAdmin(index, depth, params.get("include_unknown") !== "false");
  if (path.endsWith("/privesc/paths")) {
    const from = params.get("from") || params.get("source") || "";
    const to = params.get("to") || params.get("target") || undefined;
    return shortestPaths(index, from, to, depth, Number(params.get("limit") || 10), params.get("include_unknown") !== "false");
  }
  if (path.endsWith("/privesc/broad"))
    return broadReach(index, Number(params.get("min_targets") || 10));
  const principal = path.match(/\/privesc\/principals\/(.+)$/);
  if (principal)
    return principalCard(index, decodeURIComponent(principal[1]), findings);
  const finding = path.match(/\/findings\/(privesc%3A.+|privesc:.+)$/);
  if (finding) {
    const id = decodeURIComponent(finding[1]);
    return findings.find((f) => f.id === id);
  }
  if (path.endsWith("/findings") && params.get("categories") === "privesc")
    return { items: findings, total: findings.length, next_offset: null };
  return undefined;
}
