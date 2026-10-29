export type Provider = "aws" | "gcp" | "azure" | "k8s";
export type Category =
  | "hardening"
  | "exposure"
  | "least_privilege"
  | "iam_graph"
  | "network"
  | "privesc"
  | "monitoring"
  | "encryption"
  | "compliance"
  | "logging"
  | "identity"
  | "recovery"
  | "vulnerability"
  | "threat_detection"
  | "secure_development"
  | "backup"
  | "supply_chain"
  | "malware"
  | "asset_management"
  | "patch_management";
export type Connector = {
  content_scan_checks?: { leaks: string[]; images: string[] };
  scheduling?: { allowed: boolean; reason: string };
  id: string;
  name: string;
  provider: Provider;
  auth?: Record<string, unknown>;
  auth_mode?: string;
  scopes: string[];
  options?: Record<string, unknown>;
  input_mode?: string;
  onboarding?: {
    external_id: string;
    collector_role_arn: string;
    target_role_arns: string[];
    template_url: string;
    quick_create_template_url?: string | null;
  };
  gcp_onboarding?: {
    service_account_email: string;
    project_label_key: string;
    project_label_value: string;
  };
  status?: string;
  created_at?: string;
};
export type Finding = {
  secret_evidence?: {
    status: string; message?: string; complete?: boolean; next_offset?: number | null; total_locations?: number;
    matches: { fingerprint: string; value: string; detectors: { engine: string; rule: string }[];
      locations: { resource_id?: string; scope?: string; path: string | null; line: number | null;
        field?: string; image_digest?: string; layer?: string; source?: string; location_kind?: string; detector_input_path?: string }[] }[];
  };
  scanner_status?: string;
  ai_review?: { verdict: string; reason: string };
  finding_type?: string;
  secret_fingerprint?: string;
  linked_check_ids?: string[];
  evidence_summary_format?: "natural-language-v2";
  id: string;
  category: string;
  check_id: string;
  title: string;
  provider: string;
  service: string;
  resource_id: string;
  resource_name?: string;
  native_resource_id?: string;
  framework_ids?: string[];
  automated?: boolean;
  scope: string;
  severity: string;
  status: string;
  frameworks: string[];
  evidence: unknown;
  evidence_summary?: string;
  guidance_refresh?: {
    version: string;
    status: "current_text" | "historical_definition";
    basis: "matching_archived_criteria" | "criteria_unavailable" | "criteria_changed" | "corrected_evaluator_unbound";
    allow_summary: boolean;
    message?: string;
  };
  remediation: unknown;
  remediation_details?: RemediationDetails;
  description?: string;
  evaluated?: string[];
  pass_when?: string;
  fail_when?: string;
  not_applicable_when?: string;
  rationale?: string;
  grouped?: boolean;
  member_count?: number;
  status_counts?: Record<string, number>;
  affected_asset_count?: number;
  affected_regions?: string[];
  affected_scopes?: string[];
  affected_accounts?: string[];
  member_filters?: Record<string, string | string[]>;
};
export type FindingGroupMember = {
  id: string;
  scope: string;
  account?: string;
  region?: string;
  asset: string;
  resource_id?: string;
  resource_name?: string;
  native_resource_id?: string;
  status: string;
  severity: string;
  evidence_summary?: string;
};
export type FindingGroupDetail = Finding & {
  members: FindingGroupMember[];
  members_total: number;
  members_next_offset?: number | null;
  next_offset?: number | null;
};
export type RemediationDetails = {
  summary: string;
  steps: string[];
  cli: { label: string; shell?: string; code: string }[];
  iac?: { label: string; code: string; language?: string } | string;
  caveats?: string[];
  references: { title: string; url: string }[];
};
export type GraphNode = {
  id: string;
  label?: string;
  name?: string;
  type?: string;
  kind?: string;
  service?: string;
  scope?: string;
  provider?: string;
  [key: string]: unknown;
};
export type GraphEdge = {
  id?: string;
  source: string;
  target: string;
  label?: string;
  type?: string;
  evidence?: unknown;
  [key: string]: unknown;
};
export type Graph = {
  nodes: GraphNode[];
  edges: GraphEdge[];
  // Set by /graphs/{kind}/expand (server-side aggregate expansion).
  expanded?: string;
  member_count?: number;
  truncated?: boolean;
  edges_truncated?: boolean;
  omitted_edges?: number;
  omitted_underlying_edges?: number;
  omitted_boundary_nodes?: number;
  projection?: {
    collapsed?: boolean;
    node_count?: number;
    edge_count?: number;
    expansion?: string;
    [key: string]: unknown;
  };
};
export type Report = {
  schema_version: string;
  snapshot_id: string;
  provider: string;
  scopes: string[];
  created_at: string;
  resources: unknown[];
  findings: Finding[];
  coverage: unknown;
  stats: Record<string, unknown>;
  publication?: { state: "partial" | "final"; phase?: string; sequence?: number; ai_stages?: Record<string, number>; completed_collections?: number; sections?: Record<string, { status: "complete" | "running" | "not_selected"; data_revision: number }> };
  graphs: { network: Graph; iam: Graph; privesc?: PrivescGraph };
};
export type Scan = {
  id: string;
  updated_at?: string;
  timeline?: { status: string; at: string }[];
  display_name?: string;
  connector_name?: string;
  connector_id: string;
  status: string;
  result_available?: boolean;
  resumable?: boolean;
  ai_enabled?: boolean;
  ai_network_enabled?: boolean;
  ai_priorities_enabled?: boolean;
  error_code?: string;
  created_at: string;
  categories: string[];
  error?: string;
  report?: Report;
  progress?: number;
  progress_details?: { phase?: string; provider?: string; completed?: number; total?: number | null; resources?: number; at?: string };
  input_mode?: string;
};
export type ScheduleRule = {
  frequency: "daily" | "weekly" | "monthly";
  time: string;
  weekdays?: number[];
  day_of_month?: number;
};
export type Schedule = {
  last_error?: string | null;
  ai_enabled?: boolean;
  ai_priorities_enabled?: boolean;
  ai_network_enabled?: boolean;
  id: string;
  name?: string;
  connector_id: string;
  categories: string[];
  frameworks?: string[];
  interval_hours?: number;
  rules?: ScheduleRule[];
  timezone?: string;
  checks?: string[];
  content_checks?: string[];
  leaks_enabled?: boolean;
  images_enabled?: boolean;
  enabled: boolean;
  next_run_at?: string;
};
export type Catalog = {
  checks?: Array<Record<string, unknown>>;
  framework_versions?: Array<Record<string, unknown>>;
  upstream_coverage?: Record<string, unknown>;
  frameworks?: unknown[];
  providers?: unknown;
  auth_modes?: unknown;
  [key: string]: unknown;
};
export type Me = {
  email?: string;
  name?: string;
  mode?: string;
  quota?: unknown;
  identity?: Record<string, string>;
  [key: string]: unknown;
};
export type Workspace = {
  id: string;
  name: string;
  owner?: string;
  role: "read" | "write" | "admin";
  personal?: boolean;
};
export const categories: { id: Category; label: string }[] = [
  { id: "hardening", label: "Hardening" },
  { id: "exposure", label: "Exposure" },
  { id: "least_privilege", label: "Least privilege" },
  { id: "iam_graph", label: "IAM relationships" },
  { id: "network", label: "Network map" },
  { id: "privesc", label: "Privilege escalation" },
  { id: "monitoring", label: "Monitoring" },
  { id: "encryption", label: "Encryption" },
  { id: "compliance", label: "Compliance" },
  { id: "logging", label: "Logging" },
  { id: "identity", label: "Identity" },
  { id: "recovery", label: "Recovery" },
  { id: "vulnerability", label: "Vulnerabilities" },
  { id: "threat_detection", label: "Threat detection" },
  { id: "secure_development", label: "Secure development" },
  { id: "backup", label: "Backups" },
  { id: "supply_chain", label: "Supply chain" },
  { id: "malware", label: "Malware" },
  { id: "asset_management", label: "Asset management" },
  { id: "patch_management", label: "Patch management" },
];
export const providers: { id: Provider; name: string; detail: string }[] = [
  { id: "aws", name: "Amazon Web Services", detail: "Accounts & regions" },
  { id: "gcp", name: "Google Cloud", detail: "Projects & organizations" },
  { id: "azure", name: "Microsoft Azure", detail: "Tenants & subscriptions" },
  { id: "k8s", name: "Kubernetes", detail: "Clusters & namespaces" },
];

export type PrivescConfidence = "derived" | "conditional" | "unknown";
export type PrivescNodeKind = "principal" | "entity" | "aggregate";
export type PrivescNode = {
  exposures?: import("./PrincipalExposure").PrincipalExposure[];
  exposed_member_count?: number;
  id: string;
  label?: string;
  type?: string;
  provider?: string;
  scope?: string;
  kind?: PrivescNodeKind | string;
  attrs?: Record<string, unknown>;
  underlying_count?: number | null;
  members?: string[];
  member_sample?: PrivescNode[];
  confidence?: PrivescConfidence;
  candidate_set?: string;
  subset?: boolean;
  /** Placeholder for a target set the evaluator could not resolve from the snapshot. */
  unresolved?: boolean;
  unresolved_reason?: string;
  facts_needed?: string;
};
export type PrivescEvidenceRef = Record<string, unknown>;
export type PrivescEdge = {
  id: string;
  source: string;
  target: string;
  techniques: string[];
  confidence: PrivescConfidence;
  evidence_refs?: PrivescEvidenceRef[];
  findings?: string[];
  technique_details?: { id: string; evidence_refs?: PrivescEvidenceRef[]; conditions?: string[]; finding?: string; severity?: string; base_severity?: string; granting_permissions?: { permission: string; grant: PrivescEvidenceRef; evaluated_resource?: string; requirement?: Record<string, unknown> }[] }[];
  via_aggregate?: string;
};
export type PrivescGraph = {
  nodes: PrivescNode[];
  edges: PrivescEdge[];
  truncated?: boolean;
  total_nodes?: number;
  total_edges?: number;
  projection?: string;
};
export type PrivescAdminResult = {
  principal: string;
  label?: string;
  type?: string | null;
  admin: string;
  admin_label?: string | null;
  distance: number;
  confidence: PrivescConfidence;
  next?: string | null;
};
export type PrivescPathStep = {
  from: string;
  to: string;
  via: "edge" | "membership";
  techniques: string[];
  confidence: PrivescConfidence;
  edge?: string | null;
};
export type PrivescPath = {
  source: string;
  target: string;
  length: number;
  confidence: PrivescConfidence;
  steps: PrivescPathStep[];
};
export type PrivescBroadResult = {
  principal: string;
  label?: string;
  reached: number;
  admin: boolean;
  aggregates: string[];
};
export type PrivescTechniqueEvidence = {
  id?: string;
  title?: string;
  source?: string | null;
  source_revision?: string | null;
  summary?: string | null;
  requires?: unknown;
};
export type PrivescFindingEvidence = {
  technique?: PrivescTechniqueEvidence;
  source?: PrivescNode;
  targets?: PrivescNode[];
  target_count?: number;
  granting_statements?: PrivescEvidenceRef[];
  granting_permissions?: { permission: string; grant: PrivescEvidenceRef; evaluated_resource?: string; requirement?: Record<string, unknown> }[];
  conditions?: string[];
  confidence?: PrivescConfidence;
  technique_conditions?: { id: string; description?: string }[];
  blockers_not_evaluated?: string[];
  blocker_verdicts?: string[];
  reason?: string;
  facts_needed?: string;
  required_permissions?: unknown;
};
export type PrivescPrincipalCard = {
  principal: PrivescNode;
  outgoing: PrivescEdge[];
  incoming: PrivescEdge[];
  techniques: string[];
  granting: PrivescEvidenceRef[];
  member_of_aggregates: string[];
  may_act_as: string[];
  is_admin: boolean;
  findings?: Finding[];
  technique_details?: Record<string, { required_permissions?: {
    all_of?: string[];
    any_of?: string[][];
    leaves?: string[];
  } }>;
  outgoing_total?: number;
  incoming_total?: number;
};
