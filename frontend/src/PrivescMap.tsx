import { ExposureBadges, ExposureDetails } from "./PrincipalExposure";
import { memo, useCallback, useEffect, useId, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
} from "@xyflow/react";
import type { Edge, Node, NodeChange, NodeProps, ReactFlowInstance } from "@xyflow/react";
import { sharedElk } from "./elkWorker";
import type { ELK as ElkInstance, ElkNode } from "elkjs";
import {
  ArrowRight,
  Crown,
  ExternalLink,
  Filter,
  Focus,
  Layers,
  Minimize2,
  CircleHelp,
  PanelLeftClose,
  PanelLeftOpen,
  Radar,
  Route,
  Search,
  ShieldAlert,
  UserRound,
  X,
} from "lucide-react";
import {
  ApiError,
  listOf,
  privescApi,
  useApi,
  usePrivescAdmins,
  usePrivescBroad,
  usePrivescGraph,
  usePrivescPaths,
  usePrivescPrincipal,
} from "./api";
import { PrivescIndex, principalCard } from "./privescQueries";
import type {
  Finding,
  PrivescConfidence,
  PrivescEdge,
  PrivescEvidenceRef,
  PrivescFindingEvidence,
  PrivescNode,
  PrivescPath,
} from "./types";
import { Badge, EvidenceFields, humanError, Inspector, Panel, ProviderIcon, State } from "./ui";
import { Remediation } from "./Remediation";
import { authLink } from "./authLinks";
import { explainPrivescCondition } from "./privescCondition";
import "@xyflow/react/dist/style.css";

const INITIAL_CAP = 150,
  CAP_STEP = 150,
  // Hard ceiling for "Show more": beyond this ELK layout and DOM size stop
  // being interactive, so the user must narrow with search, focus or filters.
  HARD_CAP = 900,
  MEMBER_CAP = 40,
  FOCUS_DEPTH = 2,
  VIRTUALIZE_AT = 100;
// Node card geometry (shared by ELK, React Flow and the minimap).
const NODE_W = 300,
  AGG_W = 330,
  NODE_H = 78;
// Below this zoom node labels stop being legible, so the initial view anchors
// on the admin targets instead of fitting the whole (possibly huge) map.
const READABLE_ZOOM = 0.62,
  ANCHOR_ZOOM = 0.72;
const nodeWidth = (n: { kind?: string }) => (n.kind === "aggregate" ? AGG_W : NODE_W);
const SIDEBAR_KEY = "hacktricks-cspm.privesc.sidebar";
const SEV_RANK: Record<string, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};
const SEV_COLOR: Record<string, string> = {
  critical: "#ff6b85",
  high: "#f7a75c",
  medium: "#e8d27a",
  low: "#7fb6ff",
  info: "#7f97a8",
};
const CONF_DASH: Record<string, string | undefined> = {
  derived: undefined,
  conditional: "7 5",
  unknown: "2 5",
};
const PROVIDERS = ["aws", "gcp", "azure", "k8s"];
const PROVIDER_NAME: Record<string, string> = {
  aws: "AWS",
  gcp: "GCP",
  azure: "Azure",
  k8s: "K8s",
  entra: "Entra",
};

type VNode = PrivescNode & { synthetic?: boolean };
type VEdge = {
  id: string;
  source: string;
  target: string;
  techniques: string[];
  confidence: PrivescConfidence;
  severity: string;
  membership?: boolean;
};
type Highlight = { nodes: Set<string>; edges: Set<string>; label: string };
function displayedStepEdge(step: PrivescPath["steps"][number], index: PrivescIndex) {
  if (step.via === "edge" && step.edge) return step.edge;
  const group = index.nodes.get(step.to)?.type === "principal_group";
  const aggregate = group ? step.to : step.from;
  return `m:${aggregate}->${group ? step.from : step.to}`;
}
type Card =
  | { type: "principal"; id: string }
  | { type: "edge"; id: string }
  | { type: "unresolved"; id: string };
// Above this many unresolved placeholders they start hidden (they only carry unknown edges).
const UNRESOLVED_AUTO_HIDE = 20;
export const isUnresolved = (n?: PrivescNode) =>
  !!n && (n.unresolved === true || n.id.startsWith("unresolved:") || n.id.startsWith("unknown:"));
type QueryKind = "admins" | "path" | "broad" | "from";
type PeFlowNode = Node<
  {
    node: VNode;
    admin: boolean;
    expanded: boolean;
    highlighted: boolean;
    dimmed: boolean;
    focused: boolean;
    onFocus: () => void;
    onPaths: () => void;
  },
  "pe"
>;

export function hacktricksUrl(source?: string | null) {
  if (!source) return undefined;
  const [path, hash] = source.split("#");
  const page = path.replace(/^src\//, "").replace(/(?:^|\/)README\.md$/, "/").replace(/\.md$/, ".html");
  return `https://cloud.hacktricks.wiki/en/${page}${hash ? `#${hash}` : ""}`;
}
export function humanType(type?: string | null) {
  if (!type) return "Principal";
  const [head, ...rest] = type.split("_");
  const name = PROVIDER_NAME[head];
  return name
    ? `${name} ${rest.join(" ")}`.trim()
    : type.replaceAll("_", " ");
}
const shortId = (id: string) => id.split(/[/:]/).filter(Boolean).pop() || id;
const unresolvedTitle = (n: PrivescNode) =>
  (n.label || n.candidate_set || n.id).replace(/^Unresolved:\s*/i, "");
// Read-only collection the analyser would need to resolve an "<x>_attachment_not_collected" set.
const AWS_COLLECT: Record<string, string> = {
  batch: "batch:DescribeJobDefinitions, batch:DescribeJobQueues",
  cloudformation: "cloudformation:ListStacks, cloudformation:DescribeStacks",
  glue: "glue:GetJobs, glue:GetDevEndpoints",
  sagemaker: "sagemaker:ListNotebookInstances, sagemaker:DescribeNotebookInstance",
  codebuild: "codebuild:ListProjects, codebuild:BatchGetProjects",
  codepipeline: "codepipeline:ListPipelines, codepipeline:GetPipeline",
  ecs: "ecs:ListClusters, ecs:ListServices, ecs:DescribeServices, ecs:DescribeTaskDefinition",
  ecs_task: "ecs:ListTasks, ecs:DescribeTasks, ecs:DescribeTaskDefinition",
  elasticbeanstalk_environment: "elasticbeanstalk:DescribeEnvironments, elasticbeanstalk:DescribeConfigurationSettings",
  emr_cluster: "elasticmapreduce:ListClusters, elasticmapreduce:DescribeCluster",
  rds_db_instance: "rds:DescribeDBInstances",
  redshift_cluster: "redshift:DescribeClusters",
  redshift_serverless_workgroup: "redshift-serverless:ListWorkgroups, redshift-serverless:ListNamespaces",
  stepfunctions: "states:ListStateMachines, states:DescribeStateMachine",
};
export function unresolvedAdvice(n: PrivescNode): { missing: string; collect: string } {
  const reason = n.unresolved_reason || "";
  const facts = (n.facts_needed || "").replace(/^facts not in snapshot:\s*/i, "");
  const attach = /^(.+)_attachment_not_collected$/.exec(reason);
  if (attach) {
    const svc = attach[1];
    const actions = n.provider === "aws" ? AWS_COLLECT[svc] : undefined;
    return {
      missing: `The snapshot has no ${humanType(svc)} resources with their attached execution roles, so the roles this technique would hand over cannot be listed.`,
      collect: actions
        ? `Grant the collector read access (${actions}) and rescan with the privesc category.`
        : `Collect ${humanType(svc)} resources and their attached roles, then rescan with the privesc category.`,
    };
  }
  if (/_not_evaluated$/.test(reason))
    return {
      missing: `The evaluator could not resolve this target selector from the snapshot${facts ? `; it needs ${facts}` : ""}.`,
      collect: facts
        ? `Collect ${facts} and rescan. Until then, review the inbound principals and their exact permission and target prerequisites manually.`
        : "Review the inbound principals and their exact permission and target prerequisites manually.",
    };
  return {
    missing: facts ? `Facts not in the snapshot: ${facts}.` : "Facts needed to resolve the targets were not collected.",
    collect: "Widen collection for the resources named above and rescan with the privesc category.",
  };
}
const nodeLabel = (n?: PrivescNode, id = "") =>
  n?.label || (n ? shortId(n.id) : shortId(id));
const plural = (n: number, word: string) =>
  `${n} ${word}${n === 1 ? "" : "s"}`;

export function formatRef(ref: PrivescEvidenceRef): string {
  const v = (k: string) => {
    const value = ref[k];
    return value == null ? "" :
      typeof value === "string" || typeof value === "number" || typeof value === "boolean"
        ? String(value)
        : "structured field";
  };
  if ("policy_name" in ref || "policy_type" in ref)
    return `${v("policy_type") || "policy"} policy ${v("policy_name") || v("policy")} · statement ${v("statement") || "0"}${v("sid") ? ` (${v("sid")})` : ""} · ${v("effect") || "Allow"}`;
  if ("assignment" in ref)
    return `${v("role")} at ${v("scope") || "/"}${v("via") ? ` · via ${v("via")}` : ""}`;
  if ("binding" in ref && "namespace" in ref)
    return `${v("binding")} → ${v("role")}${v("namespace") ? ` in ${v("namespace")}` : " (cluster-wide)"}`;
  if ("role" in ref)
    return `${v("role")} on ${v("policy") || v("binding")}${v("condition") ? ` · condition: ${v("condition")}` : ""}`;
  const fields = Object.entries(ref).map(([key, value]) => {
    const label = key.replaceAll("_", " ");
    if (value == null) return `${label}: not supplied`;
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean")
      return `${label}: ${value}`;
    return `${label}: structured fields supplied`;
  });
  return fields.length ? fields.join(" · ") : "Reference fields were not supplied";
}

function grantSource(ref: PrivescEvidenceRef): string | undefined {
  if (typeof ref.policy === "string" && ref.policy.startsWith("arn:aws:")) return ref.policy;
  const value = ref.role || ref.role_definition || ref.role_definition_id ||
    ref.binding || ref.assignment || ref.app_role_assignment || ref.policy;
  return typeof value === "string" && value ? value : undefined;
}

const PeNodeView = memo(function PeNodeView({ data }: NodeProps<PeFlowNode>) {
  const n = data.node;
  const unresolved = isUnresolved(n);
  const aggregate = n.kind === "aggregate" && !unresolved;
  const count = aggregate ? n.underlying_count : undefined;
  const subtitle = unresolved
    ? `Unresolved · facts missing · ${n.scope || "unscoped"}`
    : aggregate
    ? `${count == null ? "Unknown" : count} ${n.type === "principal_group" ? "possible sources" : "members"} · ${data.expanded ? "collapse" : "expand"}`
    : n.kind === "entity"
      ? data.admin
        ? `Admin scope · ${n.scope || humanType(n.type)}`
        : humanType(n.type)
      : `${humanType(n.type)} · ${n.scope || "unscoped"}`;
  return (
    <div
      className={[
        "pe-node",
        `pe-kind-${n.kind || "principal"}`,
        `pe-prov-${n.provider || "generic"}`,
        data.admin ? "pe-admin" : "",
        data.expanded ? "is-expanded" : "",
        data.highlighted ? "is-hl" : "",
        data.dimmed ? "is-dim" : "",
        data.focused ? "is-focus" : "",
        n.confidence === "unknown" ? "is-unknown" : "",
        unresolved ? "pe-unresolved" : "",
      ].join(" ")}
      title={unresolved ? `${n.id}\n${n.facts_needed || n.unresolved_reason || ""}` : n.id}
    >
      <Handle type="target" position={Position.Left} />
      <span className="pe-node-icon">
        {unresolved ? (
          <CircleHelp size={20} aria-label="Unresolved" />
        ) : data.admin ? (
          <Crown size={18} />
        ) : (
          <ProviderIcon provider={String(n.provider || "generic")} size={22} />
        )}
      </span>
      <span className="pe-node-text">
        <strong>
          {unresolved ? (
            <>
              <em className="pe-unresolved-tag">Unresolved</em>
              {unresolvedTitle(n)}
            </>
          ) : (
            nodeLabel(n)
          )}
        </strong>
        <span>{n.exposures?.length ? "Exposed entry point · " : ""}{subtitle}</span>
      </span>
      {!unresolved && !aggregate && (
        <span className="pe-node-actions" role="group" aria-label={`Actions for ${nodeLabel(n)}`}>
          <button
            type="button"
            className="pe-node-action nodrag nopan"
            aria-label={`Focus neighbourhood of ${nodeLabel(n)}`}
            title="Focus neighbourhood"
            onClick={(event) => {
              event.stopPropagation();
              data.onFocus();
            }}
          >
            <Focus size={15} aria-hidden="true" />
          </button>
          <button
            type="button"
            className="pe-node-action nodrag nopan"
            aria-label={`Paths from ${nodeLabel(n)}`}
            title="Paths from this principal"
            onClick={(event) => {
              event.stopPropagation();
              data.onPaths();
            }}
          >
            <Route size={15} aria-hidden="true" />
          </button>
        </span>
      )}
      {aggregate && (
        <span className="pe-node-count" aria-label={`${count ?? "unknown"} members`}>
          {count ?? "?"}
        </span>
      )}
      <Handle type="source" position={Position.Right} />
    </div>
  );
});
const nodeTypes = { pe: PeNodeView };

export function PrivescMap({
  scanId,
  demo,
  categories,
  onNavigate,
}: {
  scanId: string;
  demo: boolean;
  categories?: string[];
  onNavigate?: (page: string) => void;
}) {
  const graphQ = usePrivescGraph(scanId, demo);
  const findingsQ = useApi<{ items: Finding[] }>(
    privescApi.findings(scanId),
    demo,
    !!scanId && !!graphQ.data?.nodes?.length,
  );
  const graph = useMemo(
    () => ({
      nodes: graphQ.data?.nodes || [],
      edges: graphQ.data?.edges || [],
    }),
    [graphQ.data],
  );
  const index = useMemo(() => new PrivescIndex(graph), [graph]);
  const findingList = useMemo(() => listOf(findingsQ.data), [findingsQ.data]);
  const findingSeverity = useMemo(() => new Map(findingList.map(f => [f.id, String(f.severity || "").toLowerCase()])), [findingList]);
  const edgeSeverity = useCallback(
    (e: PrivescEdge) => {
      // Priority belongs to this source and finding, not every use of a technique.
      const levels = [...(e.technique_details || []).map(d => findingSeverity.get(d.finding || "") || d.severity || ""),
        ...(e.findings || []).map(id => findingSeverity.get(id) || "")].filter(Boolean);
      return levels.sort((a, b) => (SEV_RANK[b] ?? 0) - (SEV_RANK[a] ?? 0))[0]
        || (index.isAdmin(e.target) ? "critical" : "high");
    },
    [findingSeverity, index],
  );

  const [provider, setProvider] = useState(""),
    [minSeverity, setMinSeverity] = useState(""),
    [confidence, setConfidence] = useState(""),
    [exposedOnly, setExposedOnly] = useState(false),
    [hideUnknown, setHideUnknown] = useState(true),
    // null = automatic (hidden when there are many placeholders).
    [unresolvedChoice, setUnresolvedChoice] = useState<boolean | null>(null),
    [expanded, setExpanded] = useState<Set<string>>(() => new Set()),
    [focus, setFocus] = useState(""),
    [highlight, setHighlight] = useState<Highlight | null>(null),
    [selected, setSelected] = useState(""),
    [card, setCard] = useState<Card | null>(null),
    [query, setQuery] = useState<QueryKind | null>(null),
    [cap, setCap] = useState(INITIAL_CAP);
  const [hoveredRelation, setHoveredRelation] = useState("");
  const [hoveredNode, setHoveredNode] = useState("");
  const [positions, setPositions] = useState<Record<string, { x: number; y: number }>>({});
  const positionsRef = useRef(positions);
  const onNodesChange = useCallback((changes: NodeChange<PeFlowNode>[]) => {
    const moves = changes.filter((change) => change.type === "position" && change.position);
    if (!moves.length) return;
    const next = { ...positionsRef.current };
    for (const move of moves) {
      if (move.type === "position" && move.position) next[move.id] = move.position;
    }
    positionsRef.current = next;
    setPositions(next);
  }, []);
  const displayedPaths = useRef<{ query: QueryKind | null; paths: PrivescPath[] } | null>(null);

  useEffect(() => {
    setExpanded(new Set());
    setFocus("");
    setHighlight(null);
    setHoveredRelation("");
    setHoveredNode("");
    positionsRef.current = {};
    setPositions({});
    setSelected("");
    setCard(null);
    setQuery(null);
    setCap(INITIAL_CAP);
    setUnresolvedChoice(null);
    displayedPaths.current = null;
  }, [scanId, demo]);
  const unresolvedStats = useMemo(() => {
    const ids = new Set(graph.nodes.filter(isUnresolved).map((n) => n.id));
    let edges = 0;
    for (const e of graph.edges) if (ids.has(e.target) || ids.has(e.source)) edges++;
    return { nodes: ids.size, edges };
  }, [graph]);
  const showUnresolved =
    !hideUnknown && (unresolvedChoice ?? unresolvedStats.nodes <= UNRESOLVED_AUTO_HIDE);

  const visible = useMemo(() => {
    const hlNodes = highlight?.nodes || new Set<string>();
    const passNode = (n?: PrivescNode) =>
      !!n &&
      (!provider || n.provider === provider) &&
      (showUnresolved || !isUnresolved(n) || hlNodes.has(n.id)) &&
      !(
        hideUnknown &&
        (n.id.startsWith("unknown:") ||
          (n.kind === "aggregate" && n.confidence === "unknown"))
      );
    const edges: VEdge[] = [];
    const ids = new Set<string>();
    for (const e of graph.edges) {
      if (exposedOnly && !index.nodes.get(e.source)?.exposures?.length && !index.nodes.get(e.source)?.exposed_member_count) continue;
      if (!passNode(index.nodes.get(e.source))) continue;
      if (!passNode(index.nodes.get(e.target))) continue;
      if (hideUnknown && e.confidence === "unknown") continue;
      if (confidence && e.confidence !== confidence) continue;
      const severity = edgeSeverity(e);
      if (minSeverity && (SEV_RANK[severity] ?? 0) < SEV_RANK[minSeverity])
        continue;
      edges.push({
        id: e.id,
        source: e.source,
        target: e.target,
        techniques: e.techniques,
        confidence: e.confidence,
        severity,
      });
      ids.add(e.source);
      ids.add(e.target);
    }
    const extra = new Map<string, VNode>();
    for (const aggId of expanded) {
      const agg = index.nodes.get(aggId);
      if (!agg || !ids.has(aggId)) continue;
      const all = agg.members || [];
      const members = new Set(all.slice(0, MEMBER_CAP));
      for (const m of all) if (hlNodes.has(m) || m === focus) members.add(m);
      const group = agg.type === "principal_group";
      for (const m of members) {
        const node: VNode = index.nodes.get(m) ||
          agg.member_sample?.find((s) => s.id === m) || {
            id: m,
            label: shortId(m),
            type: group ? "principal" : agg.type,
            provider: agg.provider,
            scope: agg.scope,
            kind: "principal",
            synthetic: true,
          };
        if (!passNode(node)) continue;
        if (!index.nodes.has(m)) extra.set(m, node);
        ids.add(m);
        edges.push({
          id: `m:${aggId}->${m}`,
          source: group ? m : aggId,
          target: group ? aggId : m,
          techniques: [],
          confidence: agg.confidence || "derived",
          severity: "info",
          membership: true,
        });
      }
    }
    let keep = ids;
    if (focus && ids.has(focus)) {
      const adj = new Map<string, string[]>();
      for (const e of edges) {
        (adj.get(e.source) || adj.set(e.source, []).get(e.source)!).push(
          e.target,
        );
        (adj.get(e.target) || adj.set(e.target, []).get(e.target)!).push(
          e.source,
        );
      }
      keep = new Set([focus]);
      let frontier = [focus];
      for (let d = 0; d < FOCUS_DEPTH; d++) {
        const next: string[] = [];
        for (const id of frontier)
          for (const n of adj.get(id) || [])
            if (!keep.has(n)) {
              keep.add(n);
              next.push(n);
            }
        frontier = next;
      }
      for (const id of hlNodes) if (ids.has(id)) keep.add(id);
    }
    const total = keep.size;
    if (keep.size > cap) {
      const degree = new Map<string, number>();
      for (const e of edges) {
        degree.set(e.source, (degree.get(e.source) || 0) + 1);
        degree.set(e.target, (degree.get(e.target) || 0) + 1);
      }
      const score = (id: string) =>
        (hlNodes.has(id) ? 1e6 : 0) +
        (id === focus ? 1e6 : 0) +
        (index.isAdmin(id) ? 1e5 : 0) +
        (degree.get(id) || 0);
      keep = new Set([...keep].sort((a, b) => score(b) - score(a)).slice(0, cap));
    }
    const nodes = [...keep].map((id) => index.nodes.get(id) || extra.get(id)!);
    return {
      nodes,
      edges: edges.filter((e) => keep.has(e.source) && keep.has(e.target)),
      total,
      hidden: total - nodes.length,
    };
  }, [
    graph,
    index,
    provider,
    hideUnknown,
    showUnresolved,
    confidence,
    minSeverity,
    exposedOnly,
    edgeSeverity,
    expanded,
    focus,
    highlight,
    cap,
  ]);

  // ELK layout in a web worker, keyed by the visible structure only so that
  // highlighting and selection never re-run the layout.
  const layoutKey = useMemo(
    () =>
      visible.nodes.map((n) => n.id).join("|") +
      "#" +
      visible.edges.map((e) => e.id).join("|"),
    [visible],
  );
  const elk = useRef<ElkInstance | null>(null);
  const flow = useRef<ReactFlowInstance<PeFlowNode, Edge> | null>(null);
  const [layout, setLayout] = useState<{
    key: string;
    nodes: VNode[];
    edges: VEdge[];
    pos: Record<string, { x: number; y: number }>;
  } | null>(null);
  const [layingOut, setLayingOut] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(() => {
    try {
      return localStorage.getItem(SIDEBAR_KEY) !== "closed";
    } catch {
      return true;
    }
  });
  const toggleSidebar = useCallback(() => {
    setSidebarOpen((open) => {
      try {
        localStorage.setItem(SIDEBAR_KEY, open ? "closed" : "open");
      } catch {
        /* per-viewer convenience only */
      }
      return !open;
    });
  }, []);
  const [layoutError, setLayoutError] = useState("");
  useEffect(() => {
    elk.current = sharedElk();
    return () => {
      elk.current = null;
    };
  }, []);
  const visibleRef = useRef(visible);
  visibleRef.current = visible;
  useEffect(() => {
    const snapshot = visibleRef.current;
    if (!snapshot.nodes.length) {
      setLayout({ key: layoutKey, nodes: [], edges: [], pos: {} });
      return;
    }
    let active = true;
    setLayingOut(true);
    setLayoutError("");
    const input: ElkNode = {
      id: "root",
      layoutOptions: {
        "elk.algorithm": "layered",
        "elk.direction": "RIGHT",
        "elk.spacing.nodeNode": "36",
        "elk.layered.spacing.nodeNodeBetweenLayers": "260",
        "elk.layered.spacing.edgeNodeBetweenLayers": "60",
        // One layering for every component so all admin targets share the last column.
        "elk.separateConnectedComponents": "false",
        "elk.spacing.componentComponent": "80",
        "elk.layered.nodePlacement.strategy": "BRANDES_KOEPF",
        "elk.layered.crossingMinimization.strategy": "LAYER_SWEEP",
        "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
        "elk.aspectRatio": "1.8",
      },
      children: snapshot.nodes.map((n) => ({
        id: n.id,
        width: nodeWidth(n),
        height: NODE_H,
        // Admin targets always close the left-to-right escalation flow.
        ...(index.isAdmin(n.id) || (n.kind === "entity" && n.attrs?.admin === true)
          ? { layoutOptions: { "elk.layered.layering.layerConstraint": "LAST" } }
          : {}),
      })),
      edges: snapshot.edges.map((e) => ({
        id: e.id,
        sources: [e.source],
        targets: [e.target],
      })),
    };
    (elk.current || sharedElk())
      .layout(input)
      .then((result) => {
        if (!active) return;
        const pos: Record<string, { x: number; y: number }> = {};
        for (const c of result.children || [])
          pos[c.id] = { x: c.x || 0, y: c.y || 0 };
        setLayout({
          key: layoutKey,
          nodes: snapshot.nodes,
          edges: snapshot.edges,
          pos,
        });
        setLayingOut(false);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setLayoutError(
          error instanceof Error ? error.message : "Graph layout failed",
        );
        setLayingOut(false);
      });
    return () => {
      active = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [layoutKey]);

  const hl = highlight;
  const hoverPaths = useMemo(() => {
    const incoming = new Map<string, VEdge[]>(), outgoing = new Map<string, VEdge[]>();
    for (const edge of layout?.edges || []) {
      if (!incoming.has(edge.target)) incoming.set(edge.target, []);
      if (!outgoing.has(edge.source)) outgoing.set(edge.source, []);
      incoming.get(edge.target)!.push(edge);
      outgoing.get(edge.source)!.push(edge);
    }
    return { incoming, outgoing };
  }, [layout]);
  // Hover is temporary: it must not change the query, graph layout or viewport.
  const renderHighlight = useMemo(() => {
    if (hoveredNode && layout?.nodes.some(node => node.id === hoveredNode)) {
      const nodes = new Set([hoveredNode]), edges = new Set<string>();
      // Keep directions separate: an ancestor's unrelated branches are not paths through this node.
      for (const direction of ["incoming", "outgoing"] as const) {
        const visited = new Set([hoveredNode]), pending = [hoveredNode];
        while (pending.length) {
          const current = pending.pop()!;
          for (const edge of hoverPaths[direction].get(current) || []) {
            edges.add(edge.id);
            const next = direction === "incoming" ? edge.source : edge.target;
            nodes.add(next);
            if (!visited.has(next)) {
              visited.add(next);
              pending.push(next);
            }
          }
        }
      }
      return { nodes, edges };
    }
    const edge = layout?.edges.find((item) => item.id === hoveredRelation);
    return edge
      ? { nodes: new Set([edge.source, edge.target]), edges: new Set([edge.id]) }
      : hl ? { nodes: hl.nodes, edges: hl.edges } : null;
  }, [layout, hoverPaths, hoveredNode, hoveredRelation, hl]);
  const focusOn = useCallback((id: string) => {
    setFocus(id);
    setSelected(id);
    setHighlight(null);
    const parents = index.memberOfTarget.get(id) || [];
    if (!index.out.has(id) && !index.inc.has(id) && parents.length)
      setExpanded((prev) => new Set([...prev, parents[0]]));
  }, [index]);
  const pathsFrom = useCallback((id: string) => {
    setSelected(id);
    setQuery("from");
    setSidebarOpen(true);
    try {
      localStorage.setItem(SIDEBAR_KEY, "open");
    } catch {
      // The sidebar still opens when local storage is unavailable.
    }
    setCard(null);
  }, []);
  const flowNodes = useMemo<PeFlowNode[]>(
    () =>
      (layout?.nodes || []).map((n) => ({
        id: n.id,
        type: "pe",
        // Crossing arrows must not intercept node hover or clicks.
        zIndex: 20,
        position: positions[n.id] || layout!.pos[n.id] || { x: 0, y: 0 },
        width: nodeWidth(n),
        height: NODE_H,
        selected: card?.type === "principal" && card.id === n.id,
        data: {
          node: n,
          admin: index.isAdmin(n.id) || (n.kind === "entity" && n.attrs?.admin === true),
          expanded: expanded.has(n.id),
          highlighted: !!renderHighlight?.nodes.has(n.id),
          dimmed: !!renderHighlight && !renderHighlight.nodes.has(n.id),
          focused: focus === n.id || selected === n.id,
          onFocus: () => {
            focusOn(n.id);
            setCard(null);
          },
          onPaths: () => pathsFrom(n.id),
        },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
      })),
    [layout, positions, index, expanded, renderHighlight, focus, selected, card, focusOn, pathsFrom],
  );
  const flowEdges = useMemo<Edge[]>(
    () =>
      (layout?.edges || []).map((e) => {
        const on = !!renderHighlight?.edges.has(e.id);
        const dim = !!renderHighlight && !on;
        const color = e.membership ? "#6f8796" : SEV_COLOR[e.severity] || SEV_COLOR.high;
        const n = e.techniques.length;
        return {
          id: e.id,
          source: e.source,
          target: e.target,
          type: "default",
          interactionWidth: 24,
          className: [
            "pe-edge",
            `sev-${e.severity}`,
            `conf-${e.confidence}`,
            e.membership ? "pe-membership" : "",
            on ? "is-hl" : "",
            dim ? "is-dim" : "",
          ].join(" "),
          label: e.membership
            ? undefined
            : `${plural(n, "technique")}${e.confidence === "derived" ? "" : ` · ${e.confidence}`}`,
          labelStyle: { fill: color, fontSize: 11.5, fontWeight: 600 },
          labelBgStyle: { fill: "#0b1624", fillOpacity: 0.92 },
          labelBgPadding: [7, 4] as [number, number],
          labelBgBorderRadius: 4,
          style: {
            stroke: color,
            strokeWidth: on ? 3.2 : e.membership ? 1.1 : 1.7,
            strokeDasharray: e.membership ? "3 4" : CONF_DASH[e.confidence],
            opacity: dim ? 0.16 : 1,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            color,
            width: 15,
            height: 15,
          },
          zIndex: on ? 10 : 0,
          focusable: !e.membership,
          ariaLabel: e.membership
            ? `${nodeLabel(index.nodes.get(e.source), e.source)} member ${nodeLabel(index.nodes.get(e.target), e.target)}`
            : `${nodeLabel(index.nodes.get(e.source), e.source)} to ${nodeLabel(index.nodes.get(e.target), e.target)}: ${e.techniques.join(", ")}`,
        };
      }),
    [layout, renderHighlight, index],
  );

  const canvasRef = useRef<HTMLDivElement | null>(null);
  // Readable initial viewport: fit when the whole map stays legible, otherwise
  // anchor the admin targets near the right edge at a readable zoom.
  const readableView = useCallback(
    (ids?: string[]) => {
      const inst = flow.current,
        el = canvasRef.current;
      if (!inst || !el || !layout) return;
      const w = el.clientWidth || 800,
        h = el.clientHeight || 600;
      const box = (list: VNode[]) => {
        let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
        for (const n of list) {
          const p = positionsRef.current[n.id] || layout.pos[n.id];
          if (!p) continue;
          x0 = Math.min(x0, p.x);
          y0 = Math.min(y0, p.y);
          x1 = Math.max(x1, p.x + nodeWidth(n));
          y1 = Math.max(y1, p.y + NODE_H);
        }
        return { x0, y0, x1, y1, ok: x0 !== Infinity };
      };
      const pad = 0.1;
      const fitZoom = (b: ReturnType<typeof box>) =>
        Math.min(
          (w * (1 - 2 * pad)) / Math.max(1, b.x1 - b.x0),
          (h * (1 - 2 * pad)) / Math.max(1, b.y1 - b.y0),
        );
      const subset = ids?.length
        ? layout.nodes.filter((n) => ids.includes(n.id))
        : layout.nodes;
      const all = box(subset);
      if (!all.ok) return;
      const z = fitZoom(all);
      if (z >= READABLE_ZOOM) {
        const zoom = Math.min(z, 1.15);
        void inst.setViewport(
          {
            zoom,
            x: w / 2 - ((all.x0 + all.x1) / 2) * zoom,
            y: h / 2 - ((all.y0 + all.y1) / 2) * zoom,
          },
          { duration: 0 },
        );
        return;
      }
      if (ids?.length && subset.length <= 12) {
        // A traced path reads from its source: left-align it at a readable zoom.
        const zoom = Math.max(READABLE_ZOOM, Math.min(ANCHOR_ZOOM, z));
        const tall = (all.y1 - all.y0) * zoom > h * 0.84;
        void inst.setViewport(
          {
            zoom,
            x: w * 0.05 - all.x0 * zoom,
            y: tall ? h * 0.08 - all.y0 * zoom : h / 2 - ((all.y0 + all.y1) / 2) * zoom,
          },
          { duration: 0 },
        );
        return;
      }
      // Too large to read when fitted: anchor where the paths end (admin
      // targets, or the right-most nodes of the subset) at a readable zoom.
      const admins = subset.filter(
        (n) => index.isAdmin(n.id) || (n.kind === "entity" && n.attrs?.admin === true),
      );
      const right = all.x1;
      const anchorNodes = admins.length
        ? admins
        : subset.filter((n) => ((positionsRef.current[n.id] || layout.pos[n.id])?.x ?? -Infinity) + nodeWidth(n) >= right - 1);
      const a = box(anchorNodes);
      const zoom = Math.max(READABLE_ZOOM, Math.min(ANCHOR_ZOOM, fitZoom(a)));
      const tall = (a.y1 - a.y0) * zoom > h * 0.8;
      void inst.setViewport(
        {
          zoom,
          x: w * 0.9 - a.x1 * zoom,
          // A tall admin column starts at its top; a compact cluster is centred.
          y: tall ? h * 0.08 - a.y0 * zoom : h / 2 - ((a.y0 + a.y1) / 2) * zoom,
        },
        { duration: 0 },
      );
    },
    [layout, index],
  );
  // Expanding/collapsing an aggregate keeps it centred instead of re-anchoring.
  const keepInView = useRef("");
  useEffect(() => {
    if (!layout || layingOut || !flow.current) return;
    const targets = hl ? [...hl.nodes].filter((id) => layout.pos[id]) : [];
    const kept = keepInView.current;
    keepInView.current = "";
    const id = requestAnimationFrame(() => {
      const p = kept && !targets.length ? positionsRef.current[kept] || layout.pos[kept] : undefined;
      if (p && flow.current) {
        void flow.current.setCenter(p.x + AGG_W / 2, p.y + NODE_H / 2, {
          zoom: Math.max(READABLE_ZOOM, flow.current.getZoom()),
          duration: 0,
        });
        return;
      }
      readableView(targets);
    });
    return () => cancelAnimationFrame(id);
  }, [layout, layingOut, hl, readableView, sidebarOpen]);

  const toggleExpand = useCallback((id: string) => {
    keepInView.current = id;
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);
  const highlightPaths = useCallback(
    (paths: PrivescPath[], label: string) => {
      displayedPaths.current = { query, paths };
      const nodes = new Set<string>(),
        edges = new Set<string>(),
        aggs: string[] = [];
      for (const p of paths)
        for (const s of p.steps) {
          nodes.add(s.from);
          nodes.add(s.to);
          edges.add(displayedStepEdge(s, index));
          if (s.via !== "edge" || !s.edge) {
            const fromNode = index.nodes.get(s.from);
            const group = index.nodes.get(s.to)?.type === "principal_group";
            const agg = group ? s.to : s.from;
            if (fromNode?.kind === "aggregate" || group) aggs.push(agg);
          }
        }
      if (aggs.length)
        setExpanded((prev) => new Set([...prev, ...aggs]));
      setFocus("");
      setHighlight(nodes.size ? { nodes, edges, label } : null);
    },
    [index, query],
  );
  const highlightSet = useCallback(
    (nodes: Set<string>, edges: Set<string>, label: string) => {
      displayedPaths.current = null;
      setFocus("");
      setHighlight(nodes.size ? { nodes, edges, label } : null);
    },
    [],
  );
  const openPrincipal = useCallback((id: string) => {
    setSelected(id);
    setCard({ type: "principal", id });
  }, []);
  const counts = useMemo(() => {
    let principals = 0,
      aggregates = 0,
      admins = 0;
    for (const n of graph.nodes) {
      if (isUnresolved(n)) continue;
      if (n.kind === "aggregate") aggregates++;
      else if (n.kind === "principal") principals++;
      if (index.isAdmin(n.id)) admins++;
    }
    return { principals, aggregates, admins };
  }, [graph, index]);
  const pickable = useMemo(
    () => graph.nodes.filter((n) => n.type !== "principal_group"),
    [graph],
  );
  const filtered = !!(provider || minSeverity || confidence || hideUnknown || exposedOnly);

  if (!scanId) return <State empty title="Select a scan to explore the map" />;
  if (graphQ.isPending) return <State loading />;
  const missing =
    graphQ.error instanceof ApiError &&
    [404, 422].includes(graphQ.error.status);
  if (graphQ.error instanceof ApiError && graphQ.error.status === 401)
    return (
      <Panel className="pe-empty">
        <div className="state" role="alert">
          <ShieldAlert />
          <h3>Authentication is required to view this map</h3>
          <p>Sign in to your workspace or add a valid API token in Settings, then retry.</p>
          <div className="button-row">
            <a className="button primary" href={authLink("login")}>Sign in at Tools</a>
            <button className="button" onClick={() => onNavigate?.("Settings")}>
              Open authentication settings
            </button>
          </div>
        </div>
      </Panel>
    );
  if (graphQ.error && !missing)
    return (
      <State error={graphQ.error} onRetry={() => void graphQ.refetch()} />
    );
  if (missing || !graph.nodes.length)
    return (
      <PrivescEmpty
        ran={!!categories?.includes("privesc")}
        onNavigate={onNavigate}
      />
    );

  return (
    <>
      <div className="section-top pe-top">
        <p>
          Catalog-driven escalation paths between identities · defensive
          attack-path review.
        </p>
        <span className="count-pill">
          {counts.principals} principals · {counts.aggregates} aggregates ·{" "}
          {counts.admins} admin scopes · {graph.edges.length} escalation edges
          {unresolvedStats.nodes > 0 && ` · ${unresolvedStats.nodes} unresolved`}
        </span>
      </div>
      <div className="notice">
        <ShieldAlert size={18} />
        <p>
          Edges show modelled escalation paths from observed permissions and
          collected facts. A solid edge is derived from evaluated evidence; a
          dashed edge is conditional on the prerequisites shown in its
          inspector. A dotted edge needs facts the snapshot did not collect.
          Select an edge to see the exact condition or missing evidence.
          Nothing was executed against your cloud.
        </p>
      </div>
      {graphQ.data?.truncated && (
        <div className="notice">
          <Layers size={18} />
          <p>
            The API truncated this graph to whole edges (
            {graphQ.data.total_nodes} nodes, {graphQ.data.total_edges} edges in
            the report). {graphQ.data.projection}
          </p>
        </div>
      )}
      <Panel className="graph-panel pe-panel">
        <div className="graph-toolbar pe-toolbar">
          <NodePicker
            label="Search principals"
            placeholder="Find a principal, role or scope…"
            icon={<Search size={16} />}
            options={pickable}
            value=""
            onChange={(id) => focusOn(id)}
            clearOnPick
          />
          <div className="pe-filters" role="group" aria-label="Map filters">
            <Filter size={15} aria-hidden />
            <select
              aria-label="Provider filter"
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
            >
              <option value="">All providers</option>
              {PROVIDERS.map((p) => (
                <option key={p} value={p}>
                  {PROVIDER_NAME[p]}
                </option>
              ))}
            </select>
            <select
              aria-label="Severity filter"
              value={minSeverity}
              onChange={(e) => setMinSeverity(e.target.value)}
            >
              <option value="">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High and above</option>
              <option value="medium">Medium and above</option>
            </select>
            <select
              aria-label="Confidence filter"
              value={confidence}
              onChange={(e) => setConfidence(e.target.value)}
            >
              <option value="">All confidence</option>
              <option value="derived">Derived</option>
              <option value="conditional">Conditional</option>
              <option value="unknown">Unknown</option>
            </select>
            <label className="pe-check">
              <input type="checkbox" checked={exposedOnly} onChange={e => setExposedOnly(e.target.checked)} />
              Exposed sources only
            </label>
            <label className="pe-check">
              <input
                type="checkbox"
                checked={hideUnknown}
                onChange={(e) => setHideUnknown(e.target.checked)}
              />
              Hide unknown
            </label>
            {unresolvedStats.nodes > 0 && (
              <label className="pe-check" title="Placeholders for target sets the snapshot could not resolve">
                <input
                  type="checkbox"
                  checked={showUnresolved}
                  disabled={hideUnknown}
                  onChange={(e) => setUnresolvedChoice(e.target.checked)}
                />
                Show unresolved ({unresolvedStats.nodes})
              </label>
            )}
          </div>
        </div>
        <div className="graph-breadcrumb pe-status">
          {focus ? (
            <span className="pe-chip">
              <Focus size={12} /> Neighbourhood of{" "}
              <strong>{nodeLabel(index.nodes.get(focus), focus)}</strong> ·{" "}
              {FOCUS_DEPTH} hops
              <button
                className="icon-button pe-chip-close"
                aria-label="Clear focus"
                onClick={() => setFocus("")}
              >
                <X size={12} />
              </button>
            </span>
          ) : (
            <span>All escalation paths</span>
          )}
          {highlight && (
            <span className="pe-chip hl">
              <Route size={12} /> {highlight.label}
              <button
                className="icon-button pe-chip-close"
                aria-label="Clear highlight"
                onClick={() => setHighlight(null)}
              >
                <X size={12} />
              </button>
            </span>
          )}
          <span className="push-right" />
          {expanded.size > 0 && (
            <button
              className="text-button"
              onClick={() => setExpanded(new Set())}
            >
              <Minimize2 size={13} /> Collapse aggregates
            </button>
          )}
          <button
            className="text-button"
            onClick={() =>
              readableView(
                highlight ? [...highlight.nodes].filter((id) => layout?.pos[id]) : [],
              )
            }
          >
            <Crown size={13} /> Admin view
          </button>
          <button
            className="text-button"
            onClick={() => void flow.current?.fitView({ padding: 0.12 })}
          >
            <Focus size={13} /> Fit view
          </button>
        </div>
        <div className={`pe-layout${sidebarOpen ? "" : " is-collapsed"}`}>
          {sidebarOpen && (
          <QuerySidebar
            scanId={scanId}
            demo={demo}
            query={query}
            setQuery={setQuery}
            index={index}
            pickable={pickable}
            selected={selected}
            setSelected={setSelected}
            highlightPaths={highlightPaths}
            highlightSet={highlightSet}
            openPrincipal={openPrincipal}
          />
          )}
          <div
            className="graph-canvas pe-canvas"
            aria-label="Privilege escalation map"
            onPointerLeave={() => { setHoveredNode(""); setHoveredRelation(""); }}
            ref={canvasRef}
          >
            <button
              className="pe-sidebar-toggle"
              aria-expanded={sidebarOpen}
              aria-label={sidebarOpen ? "Hide query sidebar" : "Show query sidebar"}
              title={sidebarOpen ? "Hide queries (full-width map)" : "Show queries"}
              onClick={() => toggleSidebar()}
            >
              {sidebarOpen ? <PanelLeftClose size={16} /> : <PanelLeftOpen size={16} />}
              <span>{sidebarOpen ? "Hide queries" : "Queries"}</span>
            </button>
            {layoutError ? (
              <State error={new Error(layoutError)} />
            ) : (
              <>
                <ReactFlow
                  nodes={flowNodes}
                  edges={flowEdges}
                  nodeTypes={nodeTypes}
                  onInit={(instance) => {
                    flow.current = instance;
                  }}
                  nodesDraggable
                  nodeDragThreshold={4}
                  onNodesChange={onNodesChange}
                  onEdgeMouseEnter={(_, edge) => { setHoveredNode(""); setHoveredRelation(edge.id); }}
                  onEdgeMouseLeave={() => setHoveredRelation("")}
                  onNodeMouseEnter={(_, node) => { setHoveredRelation(""); setHoveredNode(node.id); }}
                  onNodeMouseLeave={() => setHoveredNode("")}
                  onNodeDragStart={() => { setHoveredRelation(""); setHoveredNode(""); }}
                  nodesConnectable={false}
                  edgesReconnectable={false}
                  deleteKeyCode={null}
                  // Virtualise only large maps; small ones keep every node in the DOM.
                  onlyRenderVisibleElements={flowNodes.length > VIRTUALIZE_AT}
                  minZoom={0.05}
                  maxZoom={2}
                  onNodeClick={(_, n) => {
                    setHoveredNode("");
                    setHoveredRelation("");
                    const node = (n as PeFlowNode).data.node;
                    if (isUnresolved(node)) setCard({ type: "unresolved", id: node.id });
                    else if (node.kind === "aggregate") toggleExpand(node.id);
                    else openPrincipal(node.id);
                  }}
                  onEdgeClick={(_, e) => {
                    setHoveredRelation("");
                    const current = displayedPaths.current;
                    const path = current?.query === query
                      ? current.paths.find((item) => item.steps.some(
                          (step) => displayedStepEdge(step, index) === e.id,
                        ))
                      : undefined;
                    if (path)
                      highlightPaths([path], `${path.confidence} path · ${path.steps.length} hops`);
                    if (!e.id.startsWith("m:"))
                      setCard({ type: "edge", id: e.id });
                  }}
                  colorMode="dark"
                >
                  <Background color="rgba(166,227,212,.09)" gap={22} size={1} />
                  <Controls showInteractive={false} />
                  <MiniMap
                    pannable
                    zoomable
                    ariaLabel="Map overview"
                    nodeColor={(n) => {
                      const d = (n as PeFlowNode).data;
                      if (d.admin) return "#ff6b85";
                      if (isUnresolved(d.node)) return "#6b7785";
                      if (d.node.kind === "aggregate") return "#b59cff";
                      return (
                        {
                          aws: "#f7a75c",
                          gcp: "#7fb6ff",
                          azure: "#5ad1ff",
                          k8s: "#8ef0c8",
                        }[String(d.node.provider)] || "#8fa3b5"
                      );
                    }}
                    nodeStrokeWidth={0}
                    maskColor="rgba(5, 12, 22, 0.72)"
                    style={{ background: "#0b1624" }}
                  />
                </ReactFlow>
                {layingOut && (
                  <div className="graph-loading" role="status">
                    Laying out escalation paths…
                  </div>
                )}
                {!layingOut && layout && !layout.nodes.length && (
                  <div className="graph-empty">
                    <State
                      empty
                      title={
                        filtered
                          ? "No escalation edges match these filters"
                          : "No escalation edges to display"
                      }
                    />
                  </div>
                )}
              </>
            )}
          </div>
        </div>
        <div className="graph-footer">
          <span>
            {visible.nodes.length} visible nodes · {visible.edges.length}{" "}
            visible edges
            {visible.hidden > 0 &&
              ` · ${visible.hidden} nodes hidden by the render cap`}
          </span>
          <Legend />
          {visible.hidden > 0 && cap < HARD_CAP && (
            <button
              className="button pe-show-more"
              disabled={layingOut}
              onClick={() => setCap(Math.min(HARD_CAP, cap + CAP_STEP))}
            >
              {layingOut
                ? "Laying out…"
                : `Show ${Math.min(CAP_STEP, visible.hidden, HARD_CAP - cap)} more nodes`}
            </button>
          )}
          {visible.hidden > 0 && cap >= HARD_CAP && (
            <span className="pe-hard-cap" role="status">
              Render limit of {HARD_CAP} nodes reached
            </span>
          )}
        </div>
        {!showUnresolved && unresolvedStats.nodes > 0 && (
          <p className="notice small pe-cap-notice pe-unresolved-notice">
            <CircleHelp size={14} /> {plural(unresolvedStats.nodes, "unresolved target set")}{" "}
            ({plural(unresolvedStats.edges, "unknown edge")}) hidden: the snapshot lacks the facts to
            resolve them.{" "}
            {!hideUnknown && (
              <button className="text-button inline" onClick={() => setUnresolvedChoice(true)}>
                Show them
              </button>
            )}
          </p>
        )}
        {visible.hidden > 0 && (
          <p className="notice small pe-cap-notice">
            Large map: the view renders the {cap} most connected nodes (admin
            scopes and highlighted paths first). Search, focus a neighbourhood,
            run a query or filter by provider to narrow it.
          </p>
        )}
      </Panel>
      {card?.type === "principal" && (
        <PrincipalCard
          key={card.id}
          scanId={scanId}
          demo={demo}
          id={card.id}
          index={index}
          findings={findingList}
          severity={edgeSeverity}
          onClose={() => setCard(null)}
          onEdge={(id) => setCard({ type: "edge", id })}
          onPrincipal={openPrincipal}
        />
      )}
      {card?.type === "unresolved" && (
        <UnresolvedCard
          key={card.id}
          id={card.id}
          index={index}
          onClose={() => setCard(null)}
          onEdge={(id) => setCard({ type: "edge", id })}
          onPrincipal={openPrincipal}
        />
      )}
      {card?.type === "edge" && (
        <EdgeCard
          key={card.id}
          scanId={scanId}
          demo={demo}
          id={card.id}
          index={index}
          findings={findingList}
          severity={edgeSeverity}
          onClose={() => setCard(null)}
          onPrincipal={openPrincipal}
        />
      )}
    </>
  );
}

function UnresolvedCard({
  id,
  index,
  onClose,
  onEdge,
  onPrincipal,
}: {
  id: string;
  index: PrivescIndex;
  onClose: () => void;
  onEdge: (id: string) => void;
  onPrincipal: (id: string) => void;
}) {
  const node = index.nodes.get(id);
  if (!node) return null;
  const inbound = index.inc.get(id) || [];
  const advice = unresolvedAdvice(node);
  const techniques = [...new Set(inbound.flatMap((e) => e.techniques))];
  const SHOW = 40;
  return (
    <Inspector title="Unresolved target set" onClose={onClose}>
      <div className="pe-card-head">
        <span className="pe-node-icon pe-unresolved-icon">
          <CircleHelp size={22} />
        </span>
        <div>
          <h3>{unresolvedTitle(node)}</h3>
          <code className="pe-id">{node.id}</code>
        </div>
      </div>
      <div className="inspector-badges pe-badges">
        <Badge value="unknown" />
        <ExposureBadges exposures={node.exposures} />
        <Badge value={humanType(node.type)} />
        {node.scope && <Badge value={node.scope} />}
      </div>
      <p className="pe-query-summary">
        A placeholder, not a principal: these principals hold the permissions a
        technique needs, but the snapshot lacks the facts that say which identities
        the technique would reach. Every edge into it is <strong>unknown</strong>,
        never proven.
      </p>
      <h3>Missing facts</h3>
      <dl className="pe-dl">
        <div className="pe-dl-row">
          <dt>Reason</dt>
          <dd><code>{node.unresolved_reason || "not reported"}</code></dd>
        </div>
        {node.facts_needed && (
          <div className="pe-dl-row">
            <dt>Facts needed</dt>
            <dd>{node.facts_needed}</dd>
          </div>
        )}
      </dl>
      <p>{advice.missing}</p>
      <h3>What to collect</h3>
      <p>{advice.collect}</p>
      {techniques.length > 0 && (
        <>
          <h3>Techniques · {techniques.length}</h3>
          <p className="pe-ref">{techniques.join(" · ")}</p>
        </>
      )}
      <h3>Principals pointing here · {inbound.length}</h3>
      {inbound.slice(0, SHOW).map((e) => (
        <div key={e.id} className="pe-edge-row inbound">
          <div className="pe-edge-row-head">
            <span>
              ←{" "}
              <button className="text-button inline" onClick={() => onPrincipal(e.source)}>
                {nodeLabel(index.nodes.get(e.source), e.source)}
              </button>
            </span>
            <Badge value={e.confidence} />
          </div>
          <button className="text-button" onClick={() => onEdge(e.id)}>
            View technique details <ArrowRight size={13} />
          </button>
        </div>
      ))}
      {inbound.length > SHOW && (
        <p className="muted small-text">…and {inbound.length - SHOW} more.</p>
      )}
    </Inspector>
  );
}

function PrivescEmpty({
  ran,
  onNavigate,
}: {
  ran: boolean;
  onNavigate?: (page: string) => void;
}) {
  return (
    <Panel className="pe-empty">
      <div className="state">
        <Radar />
        <h3>
          {ran
            ? "No privilege-escalation paths in this scan"
            : "This scan has no privilege-escalation data"}
        </h3>
        <p>
          {ran
            ? "The privesc analysis ran but drew no escalation edges. Check coverage: denied or missing collections make edges unknown rather than absent, and missing evidence does not mean identities are safe."
            : "The privilege-escalation category was not run for this assessment. Run a new scan with the Privilege escalation (privesc) category selected to build the map."}
        </p>
        {onNavigate && (
          <button className="button primary" onClick={() => onNavigate("Scans")}>
            Rescan with privesc
            <ArrowRight size={16} />
          </button>
        )}
      </div>
    </Panel>
  );
}

function Legend() {
  return (
    <div className="pe-legend" aria-label="Map legend">
      {["critical", "high", "medium", "low"].map((s) => (
        <span key={s}>
          <i style={{ background: SEV_COLOR[s] }} />
          {s}
        </span>
      ))}
      <span>
        <svg width="22" height="6" aria-hidden>
          <line x1="0" y1="3" x2="22" y2="3" stroke="#b9cad6" strokeWidth="2" />
        </svg>
        derived
      </span>
      <span>
        <svg width="22" height="6" aria-hidden>
          <line x1="0" y1="3" x2="22" y2="3" stroke="#b9cad6" strokeWidth="2" strokeDasharray="7 5" />
        </svg>
        conditional
      </span>
      <span>
        <svg width="22" height="6" aria-hidden>
          <line x1="0" y1="3" x2="22" y2="3" stroke="#b9cad6" strokeWidth="2" strokeDasharray="2 5" />
        </svg>
        unknown
      </span>
    </div>
  );
}

function NodePicker({
  label,
  placeholder,
  options,
  value,
  onChange,
  icon,
  clearOnPick,
}: {
  label: string;
  placeholder?: string;
  options: PrivescNode[];
  value: string;
  onChange: (id: string) => void;
  icon?: ReactNode;
  clearOnPick?: boolean;
}) {
  const listId = useId();
  const current = options.find((o) => o.id === value);
  const [text, setText] = useState(current ? nodeLabel(current) : "");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  useEffect(() => {
    if (!clearOnPick) setText(current ? nodeLabel(current) : "");
  }, [value]); // eslint-disable-line react-hooks/exhaustive-deps
  const matches = useMemo(() => {
    const q = text.trim().toLowerCase();
    const out: PrivescNode[] = [];
    for (const o of options) {
      if (
        !q ||
        `${o.label || ""} ${o.id} ${o.type || ""} ${o.scope || ""}`
          .toLowerCase()
          .includes(q)
      )
        out.push(o);
      if (out.length >= 8) break;
    }
    return out;
  }, [text, options]);
  function pick(o: PrivescNode) {
    onChange(o.id);
    setText(clearOnPick ? "" : nodeLabel(o));
    setOpen(false);
  }
  return (
    <div className={`pe-picker ${icon ? "search-field" : ""}`}>
      {icon}
      <input
        role="combobox"
        aria-label={label}
        aria-expanded={open && matches.length > 0}
        aria-controls={listId}
        aria-autocomplete="list"
        placeholder={placeholder || label}
        value={text}
        onChange={(e) => {
          setText(e.target.value);
          setOpen(true);
          setActive(0);
        }}
        onFocus={() => setOpen(true)}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setActive((a) => Math.min(a + 1, matches.length - 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActive((a) => Math.max(a - 1, 0));
          } else if (e.key === "Enter" && matches[active]) {
            e.preventDefault();
            pick(matches[active]);
          } else if (e.key === "Escape") setOpen(false);
        }}
      />
      {open && matches.length > 0 && (
        <ul className="pe-options" role="listbox" id={listId} aria-label={label}>
          {matches.map((o, i) => (
            <li
              key={o.id}
              role="option"
              aria-selected={i === active}
              onMouseDown={(e) => {
                e.preventDefault();
                pick(o);
              }}
            >
              <ProviderIcon provider={String(o.provider || "generic")} size={16} />
              <span>{nodeLabel(o)}</span>
              <small>{o.kind === "aggregate" ? "aggregate" : humanType(o.type)}</small>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

type SidebarProps = {
  scanId: string;
  demo: boolean;
  query: QueryKind | null;
  setQuery: (q: QueryKind | null) => void;
  index: PrivescIndex;
  pickable: PrivescNode[];
  selected: string;
  setSelected: (id: string) => void;
  highlightPaths: (paths: PrivescPath[], label: string) => void;
  highlightSet: (nodes: Set<string>, edges: Set<string>, label: string) => void;
  openPrincipal: (id: string) => void;
};
const QUERIES: { id: QueryKind; label: string; icon: typeof Crown }[] = [
  { id: "admins", label: "Who can reach admin", icon: Crown },
  { id: "path", label: "Shortest path", icon: Route },
  { id: "broad", label: "Techniques reaching everyone/broad", icon: Radar },
  { id: "from", label: "Paths from selected principal", icon: UserRound },
];
function QuerySidebar(props: SidebarProps) {
  const { query, setQuery } = props;
  return (
    <aside className="pe-sidebar" aria-label="Escalation queries">
      <div className="eyebrow">QUERIES</div>
      <div className="pe-query-buttons">
        {QUERIES.map((q) => (
          <button
            key={q.id}
            className="pe-query-button"
            aria-pressed={query === q.id}
            onClick={() => setQuery(query === q.id ? null : q.id)}
          >
            <q.icon size={15} />
            {q.label}
          </button>
        ))}
      </div>
      <div className="pe-query-body">
        {!query && (
          <p className="muted small-text">
            Run a query to highlight escalation paths. Click a principal for
            its card, an edge for the technique, and an aggregate to expand
            it.
          </p>
        )}
        {query === "admins" && <AdminsQuery {...props} />}
        {query === "path" && <PathQuery {...props} />}
        {query === "broad" && <BroadQuery {...props} />}
        {query === "from" && <FromQuery {...props} />}
      </div>
    </aside>
  );
}

function PathList({
  paths,
  index,
  onPick,
  active,
}: {
  paths: PrivescPath[];
  index: PrivescIndex;
  onPick: (i: number) => void;
  active: number;
}) {
  return (
    <ol className="pe-paths">
      {paths.map((p, i) => (
        <li key={i}>
          <button
            className={`pe-result ${active === i ? "active" : ""}`}
            onClick={() => onPick(i)}
          >
            <span className="pe-result-title">
              {nodeLabel(index.nodes.get(p.target), p.target)}
            </span>
            <span className="pe-steps">
              {p.steps.map((s, j) => (
                <span key={j}>
                  {j === 0 && nodeLabel(index.nodes.get(s.from), s.from)}
                  <em>
                    {s.via === "membership" ? " ∈ " : ` —${s.techniques.length}→ `}
                  </em>
                  {nodeLabel(index.nodes.get(s.to), s.to)}
                </span>
              ))}
            </span>
            <span className="pe-result-meta">
              {plural(p.length, "hop")} <Badge value={p.confidence} />
            </span>
          </button>
        </li>
      ))}
    </ol>
  );
}

function AdminsQuery({ scanId, demo, index, highlightPaths, highlightSet }: SidebarProps) {
  const all = usePrivescAdmins(scanId, demo, true, true);
  // The API's known-only query includes both derived and conditional edges.
  // Keep unknown-only reach separate; neither group is labelled proven.
  const potentialQ = usePrivescAdmins(scanId, demo, true, false);
  const q = potentialQ.isPending || potentialQ.error ? potentialQ : all;
  const potential = useMemo(() => listOf(potentialQ.data), [potentialQ.data]);
  const unknownRows = useMemo(() => {
    const ok = new Set(potential.map((r) => r.principal));
    return listOf(all.data).filter((r) => !ok.has(r.principal));
  }, [all.data, potential]);
  const rows = useMemo(() => [...potential, ...unknownRows], [potential, unknownRows]);
  const [pick, setPick] = useState<{ from: string; to: string; knownOnly: boolean } | null>(null);
  // Exclude unknown shortcuts when tracing a derived or conditional row.
  const paths = usePrivescPaths(scanId, demo, pick?.from || "", pick?.to || "", 6, !pick?.knownOnly);
  useEffect(() => {
    if (!rows.length) return;
    const nodes = new Set<string>(),
      edges = new Set<string>();
    for (const r of rows) {
      nodes.add(r.principal);
      nodes.add(r.admin);
      if (r.next) {
        nodes.add(r.next);
        const e = index.out.get(r.principal)?.find((x) => x.target === r.next);
        if (e) edges.add(e.id);
      }
    }
    highlightSet(
      nodes,
      edges,
      `${potential.length} potential · ${unknownRows.length} unknown reach admin`,
    );
  }, [rows]); // eslint-disable-line react-hooks/exhaustive-deps
  const pathRows = useMemo(() => listOf(paths.data), [paths.data]);
  useEffect(() => {
    if (pathRows.length && pick)
      highlightPaths(
        pathRows.slice(0, 1),
        `Path ${nodeLabel(index.nodes.get(pick.from), pick.from)} → ${nodeLabel(index.nodes.get(pick.to), pick.to)}`,
      );
  }, [pathRows]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <QueryState q={q} empty={!rows.length} emptyText="No principal reaches an admin-equivalent scope within 6 hops.">
      <p className="pe-query-summary">
        {plural(potential.length, "principal")} have a derived or conditional
        path to an admin-equivalent scope; {unknownRows.length} more have only
        unknown paths with missing facts. Select one to trace its path.
      </p>
      {([
        ["potential", "Potential paths", "Hops are derived or conditional; inspect each condition before treating a path as usable.", potential],
        ["unknown", "Unknown paths", "At least one hop depends on facts the snapshot did not collect.", unknownRows],
      ] as const).map(([kind, title, hint, list]) => (
        <section key={kind} className={`pe-admin-group pe-admin-${kind}`}>
          <h4 className="pe-group-title">
            {title} · {list.length}
          </h4>
          <p className="muted small-text">{hint}</p>
          {list.length === 0 ? (
            <p className="muted small-text">None.</p>
          ) : (
      <ul className="pe-results" aria-label={kind === "potential" ? "Principals with potential admin paths" : "Principals reaching admin over unknown edges"}>
        {list.map((r) => (
          <li key={`${r.principal}-${r.admin}`}>
            <button
              className={`pe-result ${pick?.from === r.principal ? "active" : ""}`}
              onClick={() => setPick({ from: r.principal, to: r.admin, knownOnly: kind === "potential" })}
            >
              <span className="pe-result-title">
                {r.label || nodeLabel(index.nodes.get(r.principal), r.principal)}
              </span>
              <span className="pe-result-sub">
                → {r.admin_label || nodeLabel(index.nodes.get(r.admin), r.admin)}
              </span>
              <span className="pe-result-meta">
                {plural(r.distance, "hop")} <Badge value={r.confidence} />
              </span>
            </button>
            {pick?.from === r.principal && pathRows.length > 0 && (
              <PathList paths={pathRows.slice(0, 1)} index={index} active={0} onPick={() => undefined} />
            )}
          </li>
        ))}
      </ul>
          )}
        </section>
      ))}
    </QueryState>
  );
}

function PathQuery({ scanId, demo, index, pickable, highlightPaths }: SidebarProps) {
  const [from, setFrom] = useState(""),
    [to, setTo] = useState(""),
    [req, setReq] = useState<{ from: string; to: string } | null>(null),
    [active, setActive] = useState(0);
  const q = usePrivescPaths(scanId, demo, req?.from || "", req?.to || "");
  const rows = useMemo(() => listOf(q.data), [q.data]);
  useEffect(() => {
    if (rows.length && req) {
      setActive(0);
      highlightPaths(
        rows.slice(0, 1),
        `Shortest path ${nodeLabel(index.nodes.get(req.from), req.from)} → ${nodeLabel(index.nodes.get(req.to), req.to)}`,
      );
    }
  }, [rows]); // eslint-disable-line react-hooks/exhaustive-deps
  return (
    <form
      className="pe-path-form"
      onSubmit={(e) => {
        e.preventDefault();
        if (from && to) setReq({ from, to });
      }}
    >
      <label className="pe-field-label">From</label>
      <NodePicker label="Path source" placeholder="Search source principal…" options={pickable} value={from} onChange={setFrom} />
      <label className="pe-field-label">To</label>
      <NodePicker label="Path target" placeholder="Search target principal or scope…" options={pickable} value={to} onChange={setTo} />
      <button className="button primary" type="submit" disabled={!from || !to}>
        <Route size={15} /> Find shortest path
      </button>
      {req && (
        <QueryState q={q} empty={!rows.length} emptyText="No escalation path within 6 hops between these nodes.">
          <PathList
            paths={rows}
            index={index}
            active={active}
            onPick={(i) => {
              setActive(i);
              highlightPaths([rows[i]], `Path ${i + 1} of ${rows.length}`);
            }}
          />
        </QueryState>
      )}
    </form>
  );
}

function BroadQuery({ scanId, demo, index, highlightSet, openPrincipal }: SidebarProps) {
  const q = usePrivescBroad(scanId, demo, true, 10);
  const rows = useMemo(() => listOf(q.data), [q.data]);
  const [active, setActive] = useState("");
  function show(principal: string, aggregates: string[]) {
    setActive(principal);
    const nodes = new Set<string>([principal]),
      edges = new Set<string>();
    for (const e of index.out.get(principal) || []) {
      nodes.add(e.target);
      edges.add(e.id);
    }
    for (const a of aggregates) nodes.add(a);
    highlightSet(nodes, edges, `Broad reach of ${nodeLabel(index.nodes.get(principal), principal)}`);
  }
  return (
    <QueryState q={q} empty={!rows.length} emptyText="No principal reaches an admin scope or 10+ principals directly.">
      <p className="pe-query-summary">
        Principals whose direct techniques reach an admin scope or at least 10
        principals.
      </p>
      <ul className="pe-results" aria-label="Broad reach">
        {rows.map((r) => (
          <li key={r.principal}>
            <button
              className={`pe-result ${active === r.principal ? "active" : ""}`}
              onClick={() => show(r.principal, r.aggregates)}
              onDoubleClick={() => openPrincipal(r.principal)}
            >
              <span className="pe-result-title">
                {r.label || nodeLabel(index.nodes.get(r.principal), r.principal)}
              </span>
              <span className="pe-result-sub">
                Reaches {plural(r.reached, "target")}
                {r.aggregates.length ? ` · ${plural(r.aggregates.length, "aggregate")}` : ""}
              </span>
              <span className="pe-result-meta">
                {r.admin && <Badge value="critical" />}
                {r.admin ? "admin" : ""}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </QueryState>
  );
}

function FromQuery({ scanId, demo, index, pickable, selected, setSelected, highlightPaths, highlightSet }: SidebarProps) {
  const q = usePrivescPaths(scanId, demo, selected);
  const rows = useMemo(() => listOf(q.data), [q.data]);
  const [active, setActive] = useState(-1);
  useEffect(() => {
    if (!selected || !q.data) return;
    setActive(-1);
    if (rows.length)
      highlightPaths(rows, `Paths from ${nodeLabel(index.nodes.get(selected), selected)}`);
    else {
      const nodes = new Set<string>([selected]),
        edges = new Set<string>();
      for (const e of index.out.get(selected) || []) {
        nodes.add(e.target);
        edges.add(e.id);
      }
      highlightSet(nodes, edges, `Direct edges from ${nodeLabel(index.nodes.get(selected), selected)}`);
    }
  }, [q.data, selected]); // eslint-disable-line react-hooks/exhaustive-deps
  const direct = index.out.get(selected) || [];
  return (
    <div className="pe-path-form">
      <label className="pe-field-label">Principal</label>
      <NodePicker label="Selected principal" placeholder="Click a node or search…" options={pickable} value={selected} onChange={setSelected} />
      {!selected ? (
        <p className="muted small-text">Click a principal on the map or search for one.</p>
      ) : (
        <QueryState q={q} empty={false}>
          <p className="pe-query-summary">
            {rows.length
              ? `${plural(rows.length, "path")} to admin-equivalent scopes.`
              : `No path to an admin scope within 6 hops. ${plural(direct.length, "direct escalation edge")}.`}
          </p>
          <PathList
            paths={rows}
            index={index}
            active={active}
            onPick={(i) => {
              setActive(i);
              highlightPaths([rows[i]], `Path ${i + 1} from ${nodeLabel(index.nodes.get(selected), selected)}`);
            }}
          />
        </QueryState>
      )}
    </div>
  );
}

function QueryState({
  q,
  empty,
  emptyText,
  children,
}: {
  q: { isPending: boolean; isFetching?: boolean; error: unknown; refetch: () => unknown };
  empty: boolean;
  emptyText?: string;
  children: ReactNode;
}) {
  if (q.isPending) return <p className="muted small-text" role="status">Running query…</p>;
  if (q.error)
    return (
      <div className="pe-query-error" role="alert">
        {humanError(q.error)}
        <button className="text-button" onClick={() => void q.refetch()}>
          Retry
        </button>
      </div>
    );
  if (empty) return <p className="muted small-text">{emptyText}</p>;
  return <>{children}</>;
}

function findingFor(
  technique: string,
  source: string,
  ...lists: (Finding[] | undefined)[]
) {
  const id = `privesc:${technique}:${source}`;
  for (const list of lists) {
    const hit =
      list?.find((f) => f.id === id) ||
      list?.find((f) => f.check_id === technique && f.resource_id === source);
    if (hit) return hit;
  }
  return undefined;
}
const text = (v: unknown) =>
  v == null ? "Not supplied" :
    typeof v === "string" || typeof v === "number" || typeof v === "boolean"
      ? String(v)
      : Array.isArray(v) && v.every((item) => ["string", "number", "boolean"].includes(typeof item))
        ? v.map(String).join(", ")
        : "Structured fields supplied";

function PrincipalCard({
  scanId,
  demo,
  id,
  index,
  findings,
  severity,
  onClose,
  onEdge,
  onPrincipal,
}: {
  scanId: string;
  demo: boolean;
  id: string;
  index: PrivescIndex;
  findings: Finding[];
  severity: (edge: PrivescEdge) => string;
  onClose: () => void;
  onEdge: (id: string) => void;
  onPrincipal: (id: string) => void;
}) {
  const q = usePrivescPrincipal(scanId, demo, id);
  const local = useMemo(() => principalCard(index, id), [index, id]);
  const card = q.data || local;
  const node = { ...local.principal, ...(card.principal || {}) };
  const admin = index.isAdmin(id);
  const label = (nid: string) => nodeLabel(index.nodes.get(nid), nid);
  const attrs = Object.entries(node.attrs || {});
  return (
    <Inspector title="Principal" onClose={onClose}>
      <div className="pe-card-head">
        <ProviderIcon provider={String(node.provider || "generic")} size={34} />
        <div>
          <h3>{nodeLabel(node)}</h3>
          <code className="pe-id">{node.id}</code>
        </div>
      </div>
      <div className="inspector-badges pe-badges">
        <ExposureBadges exposures={node.exposures} />
        <Badge value={humanType(node.type)} />
        <Badge value={String(node.kind || "principal")} />
        {(admin || card.is_admin) && <Badge value="critical" />}
        {(admin || card.is_admin) && (
          <span className="pe-admin-tag">
            <Crown size={12} /> {admin ? "Admin scope" : "Reaches admin directly"}
          </span>
        )}
      </div>
      <ExposureDetails exposures={node.exposures} />
      {!!node.exposed_member_count && <p>{node.exposed_member_count} members have an external or internet workload entry point. Expand members to review evidence.</p>}
      {q.isPending && <p className="muted small-text">Loading the principal card…</p>}
      <details className="pe-identity">
        <summary>Identity</summary>
        <dl className="pe-dl">
          <dt>Provider</dt>
          <dd>{PROVIDER_NAME[String(node.provider)] || String(node.provider || "—")}</dd>
          <dt>Type</dt>
          <dd>{humanType(node.type)}</dd>
          <dt>Scope</dt>
          <dd>{node.scope || "—"}</dd>
          {attrs.map(([k, v]) => (
            <div key={k} className="pe-dl-row">
              <dt>{k.replaceAll("_", " ")}</dt>
              <dd>{typeof v === "object" && v !== null ? <EvidenceFields data={v} /> : text(v)}</dd>
            </div>
          ))}
        </dl>
      </details>
      {(card.member_of_aggregates?.length > 0 || card.may_act_as?.length > 0) && (
        <>
          <h3>Membership</h3>
          {card.member_of_aggregates.map((a) => (
            <p key={a} className="pe-membership-line">
              Member of <strong>{label(a)}</strong>: every edge into it reaches this principal.
            </p>
          ))}
          {card.may_act_as.map((a) => (
            <p key={a} className="pe-membership-line">
              May act through <strong>{label(a)}</strong> (facts missing, unknown confidence).
            </p>
          ))}
        </>
      )}
      <h3>
        Outgoing escalation · {card.outgoing_total ?? card.outgoing.length}
      </h3>
      {!card.outgoing.length && (
        <p className="muted small-text">No escalation edges start at this node.</p>
      )}
      {card.outgoing.map((e) => (
        <div key={e.id} className="pe-edge-row pe-outgoing-row">
          {e.techniques.map((t) => {
            const f = findingFor(t, e.source, card.findings, findings);
            const tech = ((f?.evidence || {}) as PrivescFindingEvidence).technique;
            const title = f?.title || tech?.title;
            const explanation = tech?.summary || f?.description || f?.evidence_summary;
            return (
              <div key={t} className="pe-outgoing-technique">
                <div className="pe-outgoing-title">
                  {title && <strong>{title}</strong>}
                  <Badge value={String(f?.severity || severity(e))} />
                </div>
                {explanation && <p>{explanation}</p>}
              </div>
            );
          })}
          <div className="pe-outgoing-footer">
            <span className="pe-outgoing-target">
              <span className="pe-k">Escalates to</span>
              <button className="text-button inline" onClick={() => onPrincipal(e.target)}>{label(e.target)}</button>
              {e.confidence !== "derived" && <Badge value={e.confidence} />}
            </span>
            <button className="text-button" onClick={() => onEdge(e.id)}>
              View technique details <ArrowRight size={13} />
            </button>
          </div>
        </div>
      ))}
      <h3>Inbound · {card.incoming_total ?? card.incoming.length}</h3>
      {!card.incoming.length && (
        <p className="muted small-text">No principal escalates into this node.</p>
      )}
      {card.incoming.map((e, i) => (
        <div key={`${e.id}-${i}`} className="pe-edge-row inbound">
          <div className="pe-edge-row-head">
            <span>
              ← <button className="text-button inline" onClick={() => onPrincipal(e.source)}>{label(e.source)}</button>
              {e.via_aggregate && <small> via {label(e.via_aggregate)}</small>}
            </span>
            <Badge value={e.confidence} />
          </div>
          <p className="pe-ref">{e.techniques.map((t) => findingFor(t, e.source, findings)?.title || t).join(" · ")}</p>
          <button className="text-button" onClick={() => onEdge(e.id)}>
            View technique details <ArrowRight size={13} />
          </button>
        </div>
      ))}
    </Inspector>
  );
}

function EdgeCard({
  scanId,
  demo,
  id,
  index,
  findings,
  severity,
  onClose,
  onPrincipal,
}: {
  scanId: string;
  demo: boolean;
  id: string;
  index: PrivescIndex;
  findings: Finding[];
  severity: (e: PrivescEdge) => string;
  onClose: () => void;
  onPrincipal: (id: string) => void;
}) {
  const edge = useMemo(() => {
    for (const list of index.out.values()) {
      const hit = list.find((e) => e.id === id);
      if (hit) return hit;
    }
    return undefined;
  }, [index, id]);
  const sourceQ = usePrivescPrincipal(scanId, demo, edge?.source || "");
  if (!edge)
    return (
      <Inspector title="Escalation technique" onClose={onClose}>
        <p>This edge is no longer in the map.</p>
      </Inspector>
    );
  const label = (nid: string) => nodeLabel(index.nodes.get(nid), nid);
  const target = index.nodes.get(edge.target);
  return (
    <Inspector title="Escalation technique" onClose={onClose}>
      <div className="pe-edge-title">
        <button className="text-button inline" onClick={() => onPrincipal(edge.source)}>
          {label(edge.source)}
        </button>
        <ArrowRight size={15} />
        <button className="text-button inline" onClick={() => onPrincipal(edge.target)}>
          {label(edge.target)}
        </button>
      </div>
      <div className="inspector-badges pe-badges">
        <Badge value={severity(edge)} />
        <Badge value={edge.confidence} />
        {target?.kind === "aggregate" && (
          <span className="pe-admin-tag">
            <Layers size={12} /> reaches {target.underlying_count ?? "unknown"} members
          </span>
        )}
      </div>
      {edge.techniques.map((t, i) => (
        <TechniqueSection
          key={t}
          scanId={scanId}
          demo={demo}
          technique={t}
          findingId={edge.technique_details?.find(detail => detail.id === t)?.finding || findingFor(t, edge.source, findings)?.id || edge.findings?.[i] || `privesc:${t}:${edge.source}`}
          summary={findingFor(t, edge.source, findings)}
          edgeGrants={edge.technique_details?.find((detail) => detail.id === t)?.granting_permissions}
          edgeRefs={edge.technique_details?.find(detail => detail.id === t)?.evidence_refs || edge.evidence_refs}
          edgeConfidence={edge.confidence}
          catalogRequired={sourceQ.data?.technique_details?.[t]?.required_permissions}
        />
      ))}
    </Inspector>
  );
}


function PermissionGrantDetails({ grant }: { grant: PrivescEvidenceRef }) {
  const statement = grant.statement_document as Record<string, unknown> | undefined;
  const list = (value: unknown) => Array.isArray(value) ? value.map(String).join(", ") : String(value ?? "");
  return <div className="pe-grant-details">
    {(grant.policy_name || grant.policy_type) ? <p>{formatRef(grant)}</p> : null}
    {statement && <>
      <p><strong>{statement.NotAction ? "NotAction" : "Action"}:</strong> <code>{list(statement.NotAction ?? statement.Action)}</code></p>
      <p><strong>{statement.NotResource ? "NotResource" : "Resource"}:</strong> <code>{list(statement.NotResource ?? statement.Resource)}</code></p>
      {statement.Condition ? <div><strong>Statement conditions</strong><pre>{JSON.stringify(statement.Condition, null, 2)}</pre></div> : null}
    </>}
    {grant.scope ? <p><strong>Assignment scope:</strong> <code>{String(grant.scope)}</code></p> : null}
    {grant.via ? <p><strong>Granted through:</strong> <code>{String(grant.via)}</code></p> : null}
    {grant.assignment ? <p><strong>Role assignment:</strong> <code>{String(grant.assignment)}</code></p> : null}
    {grant.directory_role_assignment ? <p><strong>Directory role assignment:</strong> <code>{String(grant.directory_role_assignment)}</code></p> : null}
    {grant.directory_scope ? <p><strong>Directory scope:</strong> <code>{String(grant.directory_scope)}</code></p> : null}
    {grant.matched_role_permissions ? <p><strong>Matching role permissions:</strong> <code>{list(grant.matched_role_permissions)}</code></p> : null}
    {grant.policy && !statement && !grant.policy_name ? <p><strong>Policy scope:</strong> <code>{String(grant.policy)}</code></p> : null}
    {grant.expression ? <p><strong>Binding condition:</strong> <code>{String(grant.expression)}</code></p> : null}
    {grant.condition && !statement && !grant.expression ? <div><strong>Grant condition</strong><pre>{JSON.stringify(grant.condition, null, 2)}</pre></div> : null}
    {grant.role_permissions ? <div><strong>Role definition permissions</strong><pre>{JSON.stringify(grant.role_permissions, null, 2)}</pre></div> : null}
    {grant.rule ? <div><strong>Matched RBAC rule</strong><pre>{JSON.stringify(grant.rule, null, 2)}</pre></div> : null}
  </div>;
}

function TechniqueSection({
  scanId,
  demo,
  technique,
  findingId,
  summary,
  edgeGrants,
  edgeRefs,
  edgeConfidence,
  catalogRequired,
}: {
  scanId: string;
  demo: boolean;
  technique: string;
  findingId: string;
  summary?: Finding;
  edgeGrants?: { permission: string; grant: PrivescEvidenceRef; evaluated_resource?: string }[];
  edgeRefs?: PrivescEvidenceRef[];
  edgeConfidence?: PrivescFindingEvidence["confidence"];
  catalogRequired?: { all_of?: string[]; any_of?: string[][]; leaves?: string[] };
}) {
  const q = useApi<Finding>(
    privescApi.finding(scanId, findingId),
    demo,
    !!scanId && !!findingId,
  );
  const finding = q.data || summary;
  const ev = { granting_statements: edgeRefs, confidence: edgeConfidence, ...(finding?.evidence || {}) } as PrivescFindingEvidence;
  const tech = ev.technique || {};
  const requires = tech.requires ?? ev.required_permissions;
  const href = hacktricksUrl(tech.source);
  const grants = [...new Map((ev.granting_permissions?.length ? ev.granting_permissions : edgeGrants || [])
    .filter((item) => item.permission)
    .map((item) => [`${item.permission}\n${item.evaluated_resource || ""}\n${JSON.stringify(item.grant)}`, item])).values()];
  const required = [...new Set(grants.map((item) => item.permission))];
  const legacySources = [...new Set((ev.granting_statements || [])
    .map(grantSource).filter((source): source is string => !!source))];
  const conditions = [
    ...(ev.conditions || []).map((code) => explainPrivescCondition(code)),
    ...(ev.technique_conditions || []).map((c) => explainPrivescCondition(c.id, c.description)),
    ...(ev.blockers_not_evaluated || []).map((blocker) =>
      `${explainPrivescCondition(blocker)} This blocker was not evaluated.`),
    ...(ev.blocker_verdicts || []).map((verdict) => explainPrivescCondition(verdict)),
  ].filter((value, index, values) => values.indexOf(value) === index);
  return (
    <section className="pe-technique" aria-label={`Technique ${technique}`}>
      <div className="pe-technique-head">
        <h3>{finding?.title || tech.title || (technique === "admin-equivalent" ? "Already administers the target scope" : technique)}</h3>
        {finding?.severity && <Badge value={String(finding.severity)} />}
      </div>
      <code className="pe-id">{technique}</code>
      {q.isPending && !summary && (
        <p className="muted small-text">Loading technique evidence…</p>
      )}
      {(tech.summary || finding?.description || finding?.evidence_summary) &&
        <p>{tech.summary || finding?.description || finding?.evidence_summary}</p>}
      {q.error && <p className="muted small-text">Full finding evidence could not be loaded. <button className="text-button inline" onClick={() => void q.refetch()}>Retry evidence</button></p>}
      {ev.confidence === "conditional" && (
        <p className="pe-path-explanation">
          Conditional path: the permissions and target are modelled. The
          prerequisites and possible blockers listed below still need verification.
        </p>
      )}
      {ev.confidence === "unknown" && (
        <p className="pe-path-explanation">
          Unknown path: the snapshot cannot establish the target or a required
          prerequisite. {ev.facts_needed || "Inspect the missing facts below before treating this path as usable."}
        </p>
      )}
      {technique === "admin-equivalent" && (
        <p>{ev.confidence === "conditional"
          ? "The recorded grant may provide administrative control if its conditions and guardrails permit. The exact matched grant is shown below."
          : "The recorded grant provides administrative control on this scope. The exact matched grant is shown below."}</p>
      )}
      {typeof ev.target_count === "number" && (
        <p className="muted small-text">Reaches {plural(ev.target_count, "underlying target")}.</p>
      )}
      <h4>Required permissions</h4>
      {technique === "admin-equivalent" ? (
        required.length ? <ul className="pe-perms">{required.map(permission => <li key={permission}><code>{permission}</code></li>)}</ul>
          : <p className="muted small-text">This stored assessment does not record the exact administrative permission match. Run a new assessment to capture it.</p>
      ) : Array.isArray(requires) && requires.length ? (
        <ul className="pe-perms">
          {requires.map((r, i) => (
            <li key={i}>
              {typeof r === "object" && r
                ? <EvidenceFields data={r} />
                : text(r)}
            </li>
          ))}
        </ul>
      ) : catalogRequired?.all_of?.length || catalogRequired?.any_of?.length ? (
        <ul className="pe-perms">
          {(catalogRequired.all_of || []).map((permission, i) => <li key={`all-${i}`}>{permission}</li>)}
          {!!catalogRequired.any_of?.length &&
            <li>One of: {catalogRequired.any_of.map((group) => group.join(" and ")).join("; or ")}</li>}
        </ul>
      ) : required.length ? (
        <ul className="pe-perms">
          {required.map((permission) => <li key={permission}><code>{permission}</code></li>)}
        </ul>
      ) : (
        <p className="muted small-text">
          {technique === "admin-equivalent"
            ? "This stored assessment does not record the exact administrative permission match. Run a new assessment to capture it."
            : "The exact required permissions were not recorded in this assessment. Review its source evidence or run a new assessment."}
        </p>
      )}
      <h4>Granting permissions</h4>
      {grants.length ? (
        <ul className="pe-grants">
          {grants.map((item) => (
            <li key={`${item.permission}\n${item.evaluated_resource || ""}\n${JSON.stringify(item.grant)}`}>
              <code>{item.permission}</code>
              <span>{grantSource(item.grant) || "Grant source not recorded"}</span>
              {item.evaluated_resource && <p><strong>Evaluated resource:</strong> <code>{item.evaluated_resource}</code></p>}
              <PermissionGrantDetails grant={item.grant} />
            </li>
          ))}
        </ul>
      ) : legacySources.length ? (
        <>
          <p className="muted small-text">This report records the grant sources without a permission-by-permission match.</p>
          <ul className="pe-grants">{(ev.granting_statements || []).map((grant, index) => <li key={index}><span>{grantSource(grant) || formatRef(grant)}</span><PermissionGrantDetails grant={grant} /></li>)}</ul>
        </>
      ) : (
        <p className="muted small-text">No granting policy or role was recorded.</p>
      )}
      <h4>Mitigation</h4>
      <Remediation legacy={finding?.remediation || "Remove the granting permission or scope it to the intended resources."} details={finding?.remediation_details} />
      {conditions.length > 0 && (
        <>
          <h4>Conditions and blockers</h4>
          <ul className="pe-conditions">
            {conditions.map((condition, i) => (
              <li key={i}>{condition}</li>
            ))}
          </ul>
        </>
      )}
      {href && (
        <a className="button pe-source" href={href} target="_blank" rel="noopener noreferrer">
          HackTricks Cloud source <ExternalLink size={13} />
        </a>
      )}
      {tech.source_revision && <p className="muted small-text">Catalog revision {tech.source_revision}</p>}
    </section>
  );
}

