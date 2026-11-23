import { TableDownload } from "./TableDownload";
import { useEffect, useMemo, useRef, useState } from "react";
import {
  Background,
  BaseEdge,
  Controls,
  Handle,
  Position,
  ReactFlow,
} from "@xyflow/react";
import type {
  Edge,
  EdgeProps,
  Node,
  NodeProps,
  ReactFlowInstance,
} from "@xyflow/react";
import { sharedElk } from "./elkWorker";
import type { ElkEdgeSection, ElkNode, ELK as ElkInstance } from "elkjs";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  ArrowLeft,
  Search,
  Layers,
  Table2,
  Network,
  Focus,
} from "lucide-react";
import { useApi } from "./api";
import { ConnectionAssessment } from "./ConnectionAssessment";
import type { Graph, GraphEdge, GraphNode } from "./types";
import { Evidence, humanError, Inspector, Panel, ProviderIcon, State } from "./ui";
import { namePrefix, projectView, structuralIndex } from "./graphProjection";
import type { GroupLevel, ProjectedNode } from "./graphProjection";
import "@xyflow/react/dist/style.css";
const MAX_NODES = 120,
  MAX_EDGES = 400,
  // Edge labels collide once many edges converge; show them on selection only.
  EDGE_LABELS_AT = 24,
  // Inspector lists are not virtualised; keep huge groups responsive.
  INSPECT_EDGES = 200,
  INSPECT_MEMBERS = 50,
  VIRTUALIZE_AT = 100;
type MapNode = Node<
  { label: string; provider: string; subtitle: string; group?: boolean },
  "asset"
>;
type RoutedEdge = Edge<
  {
    sections: ElkEdgeSection[];
    label: string;
    count: number;
    showLabel: boolean;
  },
  "routed"
>;
function AssetNode({ data }: NodeProps<MapNode>) {
  return (
    <div className={`map-node ${data.group ? "map-group" : ""}`}>
      <Handle type="target" position={Position.Left} />
      <ProviderIcon provider={data.provider} size={24} />
      <div>
        <strong>{data.label}</strong>
        <span>{data.subtitle}</span>
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}
function Routed({ id, data, selected }: EdgeProps<RoutedEdge>) {
  return (
    <>
      {data?.sections.map((s, index) => {
        const points = [s.startPoint, ...(s.bendPoints || []), s.endPoint];
        const path = points
          .map((p, i) => `${i ? "L" : "M"} ${p.x} ${p.y}`)
          .join(" ");
        const midpoint = points[Math.floor(points.length / 2)];
        return (
          <g key={index}>
            <BaseEdge
              id={`${id}-${index}`}
              path={path}
              style={{
                stroke: selected ? "#c4ffee" : "#659ba8",
                strokeWidth: selected ? 3 : 1.6,
              }}
            />
            {index === 0 && (data.showLabel || selected) && (
              <text
                x={midpoint.x - 8}
                y={midpoint.y - 9}
                textAnchor="end"
                style={{ fill: "#a5c5ce", fontSize: 9, pointerEvents: "none" }}
              >
                {data.count > 1 ? `${data.label} ×${data.count}` : data.label}
              </text>
            )}
          </g>
        );
      })}
    </>
  );
}
const nodeTypes = { asset: AssetNode },
  edgeTypes = { routed: Routed };
const emptyGraph: Graph = { nodes: [], edges: [] };
export function GraphView({
  scanId,
  kind,
  demo,
}: {
  scanId: string;
  kind: "iam" | "network";
  demo: boolean;
}) {
  const [connection, setConnection] = useState<{
    source?: string;
    destination?: string;
  }>();
  const [sourceSelection, setSourceSelection] = useState("");
  const [completeEvidence, setCompleteEvidence] = useState(false);
  // Server-side expansion of one projected aggregate (bounded subgraph of its
  // members plus stubs), instead of downloading the complete graph.
  const [expandNode, setExpandNode] = useState<{ id: string; label: string }>();
  const query = useApi<Graph>(
    `/scans/${encodeURIComponent(scanId)}/graphs/${kind}${
      completeEvidence
        ? ""
        : expandNode
          ? `/expand?node=${encodeURIComponent(expandNode.id)}`
          : "?max_nodes=500"
    }`,
    demo,
    !!scanId,
  );
  const graph = query.data || emptyGraph;
  const [search, setSearch] = useState(""),
    [mode, setMode] = useState<"map" | "table">("map"),
    [level, setLevel] = useState<GroupLevel>("scope"),
    [scope, setScope] = useState(""),
    [service, setService] = useState(""),
    [network, setNetwork] = useState(""),
    [subnet, setSubnet] = useState(""),
    [prefix, setPrefix] = useState(""),
    [risk, setRisk] = useState("");
  const [inspect, setInspect] = useState<ProjectedNode | GraphEdge>(),
    [nodes, setNodes] = useState<MapNode[]>([]),
    [edges, setEdges] = useState<RoutedEdge[]>([]),
    [layoutError, setLayoutError] = useState(""),
    [layingOut, setLayingOut] = useState(false),
    [page, setPage] = useState(0);
  const elk = useRef<ElkInstance | null>(null),
    flow = useRef<ReactFlowInstance<MapNode, RoutedEdge> | null>(null),
    fitted = useRef(false);
  useEffect(() => {
    elk.current = sharedElk();
    return () => {
      elk.current = null;
    };
  }, []);
  useEffect(() => {
    setCompleteEvidence(false);
    setExpandNode(undefined);
    setScope("");
    setService("");
    setNetwork("");
    setSubnet("");
    setPrefix("");
    setRisk("");
    setLevel("scope");
    setSearch("");
    setPage(0);
    fitted.current = false;
  }, [scanId, kind]);
  const structural = useMemo(() => structuralIndex(graph), [graph]);
  const matching = useMemo(() => {
    const riskMatches = new Set(
      graph.nodes
        .filter(
          (n) =>
            !risk ||
            (Array.isArray(n.risk_annotations) &&
              n.risk_annotations.some(
                (a) =>
                  typeof a === "object" &&
                  a !== null &&
                  "type" in a &&
                  a.type === risk,
              )),
        )
        .map((n) => n.id),
    );
    const primaryRiskMatches = new Set(riskMatches);
    if (risk)
      for (const e of graph.edges) {
        if (
          primaryRiskMatches.has(e.source) ||
          primaryRiskMatches.has(e.target)
        ) {
          riskMatches.add(e.source);
          riskMatches.add(e.target);
        }
      }
    const selected = graph.nodes.filter(
      (n) =>
        (!scope || String(n.scope || "Unscoped") === scope) &&
        (!service ||
          String(n.service || n.type || n.kind || "Other") === service) &&
        (!network ||
          (structural.network(n)?.id ||
            `unassigned:${n.scope || "Unscoped"}`) === network) &&
        (!subnet ||
          (structural.subnet(n)?.id ||
            `unassigned:${n.scope || "Unscoped"}`) === subnet) &&
        (!prefix || namePrefix(n) === prefix) &&
        (!risk || riskMatches.has(n.id)) &&
        `${n.label || n.name || n.id} ${n.type || ""} ${n.service || ""} ${n.scope || ""}`
          .toLowerCase()
          .includes(search.toLowerCase()),
    );
    // Inside a subnet, security groups and route tables live at VPC level;
    // pull the ones protecting/routing the subnet's members in as context so
    // the firewall rules are visible next to the machines and interfaces.
    if (!subnet || subnet.startsWith("unassigned:")) return selected;
    const ids = new Set(selected.map((n) => n.id));
    const extra = new Set<string>();
    for (const e of graph.edges) {
      if (e.type === "protected_by" && ids.has(e.source)) extra.add(e.target);
      else if (e.type === "route_association" && ids.has(e.target))
        extra.add(e.source);
    }
    for (const id of ids) extra.delete(id);
    if (!extra.size) return selected;
    return selected.concat(graph.nodes.filter((n) => extra.has(n.id)));
  }, [graph, structural, scope, service, network, subnet, prefix, search, risk]);
  const view = useMemo(
    () =>
      projectView(
        graph,
        matching,
        level,
        page,
        MAX_NODES,
        MAX_EDGES,
        structural,
        !!network,
      ),
    [graph, matching, level, page, structural, network],
  );
  useEffect(() => {
    let active = true;
    setLayingOut(true);
    setLayoutError("");
    const input: ElkNode = {
      id: "root",
      layoutOptions: {
        "elk.algorithm": "layered",
        "elk.direction": "RIGHT",
        "elk.edgeRouting": "ORTHOGONAL",
        "elk.spacing.nodeNode": "45",
        "elk.layered.spacing.nodeNodeBetweenLayers": "110",
        // Dense group-level views otherwise become one very long row that
        // fits at an unreadable zoom; wrap layers to a screen-like aspect.
        ...(view.nodes.length > 12
          ? {
              "elk.aspectRatio": "1.8",
              "elk.layered.wrapping.strategy": "MULTI_EDGE",
            }
          : {}),
        "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
      },
      children: view.nodes.map((n) => ({ id: n.id, width: 240, height: 74 })),
      edges: view.edges.map((e) => ({
        id: String(e.id),
        sources: [e.source],
        targets: [e.target],
      })),
    };
    (elk.current || sharedElk())
      .layout(input)
      .then((result) => {
        if (!active) return;
        const nodeById = new Map(view.nodes.map((x) => [x.id, x]));
        const edgeById = new Map(view.edges.map((x) => [String(x.id), x]));
        const showLabel = view.edges.length <= EDGE_LABELS_AT;
        setNodes(
          (result.children || []).map((n) => {
            const original = nodeById.get(n.id)!;
            const internal =
              original.internal_edges?.reduce(
                (total, e) => total + Number(e.underlying_count || 1),
                0,
              ) || 0;
            return {
              id: n.id,
              type: "asset",
              position: { x: n.x || 0, y: n.y || 0 },
              data: {
                label: String(original.label || original.name || original.id),
                provider: String(original.provider || "generic"),
                subtitle: original.group
                  ? `${original.underlying_count} assets · ${internal} internal relations`
                  : String(
                      original.service || original.type || "Observed asset",
                    ),
                group: !!original.group,
              },
              sourcePosition: Position.Right,
              targetPosition: Position.Left,
            };
          }),
        );
        setEdges(
          (result.edges || []).map((e) => {
            const original = edgeById.get(e.id)!;
            return {
              id: e.id,
              source: original.source,
              target: original.target,
              type: "routed",
              data: {
                sections: e.sections || [],
                label: String(
                  original.label || original.type || "Observed relationship",
                ),
                count: Number(original.underlying_count || 1),
                showLabel,
              },
              ariaLabel: String(
                original.label || original.type || "Observed relationship",
              ),
            };
          }),
        );
        setLayingOut(false);
      })
      .catch((error) => {
        if (active) {
          setLayoutError(
            error instanceof Error ? error.message : "Graph layout failed",
          );
          setLayingOut(false);
        }
      });
    return () => {
      active = false;
    };
  }, [view]);
  useEffect(() => {
    if (!layingOut && nodes.length && !fitted.current && flow.current) {
      // Keep the first view legible on tall/wide layouts; "Fit view" still
      // shows everything.
      requestAnimationFrame(() => {
        void flow.current?.fitView({ padding: 0.2, minZoom: 0.45 });
      });
      fitted.current = true;
    }
  }, [nodes, layingOut]);
  function endpointResource(
    node: ProjectedNode | GraphEdge,
  ): string | undefined {
    if ("source" in node) return undefined;
    if (typeof node.resource_id === "string" && !node.aggregate)
      return node.resource_id;
    if (typeof node.group_key === "string") {
      const root = graph.nodes.find((n) => n.id === node.group_key);
      if (typeof root?.resource_id === "string") return root.resource_id;
    }
    return undefined;
  }
  function reset() {
    fitted.current = false;
    setLevel("scope");
    setScope("");
    setService("");
    setNetwork("");
    setSubnet("");
    setPrefix("");
    setPage(0);
  }
  // Leaf level: very large groups are split by name prefix first so the next
  // view stays meaningful instead of paging through thousands of assets.
  function leaf(n: ProjectedNode): GroupLevel {
    return level !== "prefix" && (n.member_ids?.length || 0) > MAX_NODES
      ? "prefix"
      : "assets";
  }
  // Collapse back to the level a breadcrumb crumb represents.
  function collapseTo(crumb: "scope" | "network" | "subnet" | "service") {
    const split = !!prefix || level === "prefix";
    fitted.current = false;
    setPrefix("");
    setPage(0);
    setInspect(undefined);
    if (crumb === "scope") {
      setNetwork("");
      setSubnet("");
      setService("");
      setLevel(kind === "network" ? "network" : "service");
    } else if (crumb === "network") {
      setSubnet("");
      setLevel(
        graph.nodes.find((x) => x.id === network)?.type === "namespace"
          ? "assets"
          : "subnet",
      );
    } else {
      setLevel(split ? "prefix" : "assets");
    }
  }
  function expand(n: ProjectedNode) {
    if (!n.group) return;
    const key = String(n.group_key);
    fitted.current = false;
    if (level === "prefix") {
      setPrefix(key);
      setLevel("assets");
    } else if (level === "scope") {
      setScope(key);
      setLevel(kind === "network" ? "network" : "service");
    } else if (level === "network") {
      setNetwork(key);
      setLevel(
        graph.nodes.find((x) => x.id === key)?.type === "namespace"
          ? "assets"
          : "subnet",
      );
    } else if (level === "subnet") {
      setSubnet(key);
      setLevel(leaf(n));
    } else {
      setService(key);
      setLevel(leaf(n));
    }
    setPage(0);
    setInspect(undefined);
  }
  const scroll = useRef<HTMLDivElement>(null);
  const clickTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const virtual = useVirtualizer({
    count: matching.length,
    getScrollElement: () => scroll.current,
    estimateSize: () => 66,
    overscan: 10,
  });
  const projection = graph.projection;
  const collapsed = projection?.collapsed;
  const displayLimited = graph.truncated || graph.edges_truncated;
  const omittedRelationships = graph.omitted_underlying_edges ?? Number(projection?.omitted_underlying_edges || 0);
  return (
    <>
      <div className="section-top">
        <p>
          {kind === "iam"
            ? "Declared access and trust · defensive IAM review."
            : "Explore structural inventory and conditional rule candidates."}
        </p>
        <span className="count-pill">
          {projection?.node_count ?? graph.nodes.length} assets ·{" "}
          {projection?.edge_count ?? graph.edges.length} relationships
        </span>
      </div>
      <div className="notice">
        <Layers size={18} />
        <p>
          {kind === "iam"
            ? "This map shows permissions found in the scan. Conditions may affect actual access."
            : "This map shows resources linked in the scan. Open a connection to see what was found."}
        </p>
      </div>
      {displayLimited && (
        <div className="notice" role="status">
          <p>
            This view is limited to keep the map responsive.
            {omittedRelationships > 0 ? ` ${omittedRelationships.toLocaleString()} relationships are outside this view.` : " Additional relationships may be outside this view."}
            {" "}Their absence from the canvas does not establish that access is blocked. Expand a group or load the complete graph to review the remaining evidence.
          </p>
          {!completeEvidence && (
            <button className="button" onClick={() => setCompleteEvidence(true)}>
              Load complete graph evidence
            </button>
          )}
        </div>
      )}
      {expandNode && !completeEvidence && (
        <div className="notice">
          <p>
            Showing the members of {expandNode.label}
            {typeof graph.member_count === "number"
              ? ` (${graph.member_count} members)`
              : ""}
            ; nodes outside it are folded into stubs.
          </p>
          <button
            className="button"
            onClick={() => {
              setExpandNode(undefined);
              setSearch("");
              reset();
            }}
          >
            Back to projection
          </button>
        </div>
      )}
      {collapsed && !expandNode && (
        <div className="notice">
          <p>
            Grouped overview. Expand a group to inspect its members and connections.
            Evidence excerpts may be sampled; the complete graph retains the underlying records.
          </p>
          {!displayLimited && (
            <button className="button" onClick={() => setCompleteEvidence(true)}>
              Load complete graph evidence
            </button>
          )}
        </div>
      )}
      <Panel className={mode === "table" ? "graph-panel graph-table-panel" : "graph-panel"}>
        <div className={mode === "table" ? "graph-toolbar table-toolbar" : "graph-toolbar"}>
          {kind === "network" && (
            <button
              className="button"
              disabled={demo || !scanId}
              onClick={() => setConnection({ source: sourceSelection })}
            >
              Assess configuration path
            </button>
          )}
          <div className="search-field">
            <Search size={17} />
            <input
              aria-label="Search graph"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(0);
              }}
              placeholder="Find an asset, service or scope…"
            />
          </div>
          {kind === "iam" && (
            <select
              className="risk-select"
              aria-label="IAM risk filter"
              value={risk}
              onChange={(e) => {
                setRisk(e.target.value);
                setPage(0);
              }}
            >
              <option value="">All declared relationships</option>
              <option value="high_risk_grant">High-risk grants</option>
              <option value="external_trust">External trust</option>
              <option value="inactive_identity">Inactive identities</option>
            </select>
          )}
          <div className="segmented">
            <button
              aria-pressed={mode === "map"}
              onClick={() => setMode("map")}
            >
              <Network size={16} />
              Map
            </button>
            <button
              aria-pressed={mode === "table"}
              onClick={() => setMode("table")}
            >
              <Table2 size={16} />
              Table
            </button>
          </div>
          {mode === "table" && <TableDownload table="asset-table" label="asset table" rows={matching.map(node => ({
            id: node.id, label: node.label || node.name || node.id, provider: node.provider || "generic",
            service: node.service || node.type || "Asset", scope: node.scope || "Unscoped",
          }))} />}
        </div>
        <div className="graph-breadcrumb">
          <button className="text-button" onClick={reset}>
            All scopes
          </button>
          {(
            [
              ["scope", scope],
              ["network", network],
              ["subnet", subnet],
              ["service", service],
            ] as const
          )
            .filter(([, value]) => value)
            .map(([crumb, value]) => (
              <span key={crumb}>
                /{" "}
                <button
                  className="text-button crumb"
                  onClick={() => collapseTo(crumb)}
                >
                  {String(
                    graph.nodes.find((n) => n.id === value)?.label || value,
                  )}
                </button>
              </span>
            ))}
          {prefix && <span>/ {prefix}…</span>}
          {level !== "assets" && (
            <button
              className="text-button push-right"
              onClick={() => {
                fitted.current = false;
                setLevel("assets");
                setPage(0);
              }}
            >
              Show assets
            </button>
          )}
          {level !== "scope" && (
            <button className="text-button" onClick={reset}>
              <ArrowLeft size={13} />
              Overview
            </button>
          )}
          <button
            className="text-button"
            onClick={() => void flow.current?.fitView({ padding: 0.2 })}
          >
            <Focus size={13} />
            Fit view
          </button>
        </div>
        {!scanId ? (
          <State empty title="Select a scan to explore the map" />
        ) : (
          <State
            loading={query.isPending}
            error={query.error}
            onRetry={() => void query.refetch()}
            empty={!!query.data && !graph.nodes.length}
            title="No graph evidence collected"
          >
            <>
              {mode === "map" ? (
                <div
                  className="graph-canvas"
                  aria-label={`${kind} relationship map`}
                >
                  {layoutError ? (
                    <State error={new Error(layoutError)} />
                  ) : (
                    <>
                      <ReactFlow
                        nodes={nodes}
                        edges={edges}
                        nodeTypes={nodeTypes}
                        edgeTypes={edgeTypes}
                        onInit={(instance) => {
                          flow.current = instance;
                        }}
                        nodesDraggable={false}
                        nodesConnectable={false}
                        edgesReconnectable={false}
                        deleteKeyCode={null}
                        minZoom={0.1}
                        maxZoom={2}
                        onNodeClick={(_, n) => {
                          // Deferred so a double-click can expand a group
                          // without the inspector covering the canvas first.
                          if (clickTimer.current)
                            clearTimeout(clickTimer.current);
                          clickTimer.current = setTimeout(() => {
                            clickTimer.current = undefined;
                            setInspect(view.nodes.find((x) => x.id === n.id));
                          }, 220);
                        }}
                        onNodeDoubleClick={(_, n) => {
                          if (clickTimer.current)
                            clearTimeout(clickTimer.current);
                          clickTimer.current = undefined;
                          const target = view.nodes.find((x) => x.id === n.id);
                          if (target?.group) expand(target);
                          else setInspect(target);
                        }}
                        zoomOnDoubleClick={false}
                        onlyRenderVisibleElements={nodes.length > VIRTUALIZE_AT}
                        onEdgeClick={(_, e) =>
                          setInspect(view.edges.find((x) => x.id === e.id))
                        }
                        colorMode="dark"
                      >
                        <Background color="#233747" gap={24} />
                        <Controls showInteractive={false} />
                      </ReactFlow>
                      {layingOut && (
                        <div className="graph-loading" role="status">
                          Routing evidence relationships…
                        </div>
                      )}
                      {!layingOut && !view.nodes.length && (
                        <div className="graph-empty">
                          <State empty title="No matching assets" />
                        </div>
                      )}
                    </>
                  )}
                </div>
              ) : (<>
                <div
                  className="graph-table"
                  ref={scroll}
                  role="region"
                  tabIndex={0}
                  aria-label="Graph asset table"
                >
                  <div
                    style={{
                      height: virtual.getTotalSize(),
                      position: "relative",
                    }}
                  >
                    {virtual.getVirtualItems().map((v) => {
                      const n = matching[v.index];
                      return (
                        <button
                          className="graph-table-row"
                          key={n.id}
                          style={{
                            position: "absolute",
                            top: v.start,
                            height: v.size,
                            width: "100%",
                          }}
                          onClick={() => setInspect(n)}
                        >
                          <ProviderIcon
                            provider={String(n.provider || "generic")}
                            size={24}
                          />
                          <strong>{n.label || n.name || n.id}</strong>
                          <span>{n.service || n.type || "Asset"}</span>
                          <span>{n.scope || "Unscoped"}</span>
                        </button>
                      );
                    })}
                  </div>
                  {!matching.length && (
                    <State empty title="No matching assets" />
                  )}
                </div>
              </>)}
              <div className="graph-footer">
                <span>
                  {mode === "map"
                    ? `${view.nodes.length} visible nodes · ${view.edges.length} visible edge groups`
                    : `${matching.length} matching assets`}{" "}
                  · {view.internalCount} internal relationships retained ·{" "}
                  {view.outsideCount} relationships outside filters
                </span>
                {mode === "map" && view.total > MAX_NODES && (
                  <div>
                    <button
                      className="button"
                      disabled={!page}
                      onClick={() => setPage(page - 1)}
                    >
                      Previous
                    </button>
                    <span>
                      {" "}
                      Page {page + 1} of{" "}
                      {Math.ceil(view.total / MAX_NODES)}{" "}
                    </span>
                    <button
                      className="button"
                      disabled={(page + 1) * MAX_NODES >= view.total}
                      onClick={() => setPage(page + 1)}
                    >
                      Next
                    </button>
                  </div>
                )}
              </div>
              {mode === "map" &&
                (view.total > MAX_NODES || view.edgeTotal > MAX_EDGES) && (
                  <p className="notice small">
                    Visible view limited to {MAX_NODES} nodes and {MAX_EDGES}{" "}
                    edge groups. Narrow the scope, search or use the complete
                    supplied asset table.
                  </p>
                )}
            </>
          </State>
        )}
      </Panel>
      {connection && (
        <ConnectionAssessment
          scanId={scanId}
          nodes={graph.nodes}
          source={connection.source}
          destination={connection.destination}
          onClose={() => setConnection(undefined)}
        />
      )}
      {inspect && (
        <Inspector
          title={
            "source" in inspect
              ? "Relationship evidence"
              : inspect.group
                ? "Group evidence"
                : "Asset evidence"
          }
          onClose={() => setInspect(undefined)}
        >
          <h3>
            {String(
              inspect.label ||
                inspect.name ||
                inspect.id ||
                inspect.type ||
                "Observed relationship",
            )}
          </h3>
          {!!inspect.group && (
            <button
              className="button primary"
              onClick={() => expand(inspect as ProjectedNode)}
            >
              Explore group
            </button>
          )}
          {!!inspect.aggregate && collapsed && !demo && !expandNode && (
            <button
              className="button primary"
              onClick={() => {
                setExpandNode({
                  id: String(inspect.id),
                  label: String(inspect.label || inspect.id),
                });
                reset();
                setSearch("");
                setInspect(undefined);
              }}
            >
              Expand on the server
            </button>
          )}
          {!!inspect.aggregate && collapsed && (
            <button
              className="button"
              onClick={() => {
                setCompleteEvidence(true);
                setInspect(undefined);
              }}
            >
              Load underlying graph evidence
            </button>
          )}
          {kind === "network" &&
            !("source" in inspect) &&
            endpointResource(inspect) && (
              <div className="button-row">
                <button
                  className="button"
                  disabled={demo}
                  onClick={() => {
                    const source = endpointResource(inspect);
                    setSourceSelection(source || "");
                    setInspect(undefined);
                    setConnection({ source });
                  }}
                >
                  Assess from this resource
                </button>
                {sourceSelection && (
                  <button
                    className="button"
                    disabled={demo}
                    onClick={() => {
                      setConnection({
                        source: sourceSelection,
                        destination: endpointResource(inspect),
                      });
                      setInspect(undefined);
                    }}
                  >
                    Assess to this resource
                  </button>
                )}
              </div>
            )}
          <Evidence data={inspectionSummary(inspect)} />
          <CompleteGrants scanId={scanId} demo={demo} value={inspect} />
          {"underlying_edges" in inspect &&
            Array.isArray(inspect.underlying_edges) && (
              <>
                <h3>
                  Underlying evidence · {String(inspect.underlying_count)}{" "}
                  relationships
                </h3>
                {inspect.underlying_edges.slice(0, INSPECT_EDGES).map((e, i) => (
                  <button
                    key={i}
                    className="relationship-row"
                    onClick={() => setInspect(e)}
                  >
                    {e.source} → {e.target}
                    <span>{e.label || e.type || "Observed relationship"}</span>
                  </button>
                ))}
              </>
            )}
          {!("source" in inspect) && (
            <>
              <h3>
                {inspect.group ? "Internal relationships" : "Related evidence"}
              </h3>
              {(() => {
                const related = inspect.group
                  ? (inspect as ProjectedNode).internal_edges || []
                  : graph.edges.filter(
                      (e) => e.source === inspect.id || e.target === inspect.id,
                    );
                return related.length > INSPECT_EDGES ? (
                  <p className="muted small">
                    Showing {INSPECT_EDGES} of {related.length} relationships.
                    Explore the group to see the rest in context.
                  </p>
                ) : null;
              })()}
              {(inspect.group
                ? (inspect as ProjectedNode).internal_edges || []
                : graph.edges.filter(
                    (e) => e.source === inspect.id || e.target === inspect.id,
                  )
              )
                .slice(0, INSPECT_EDGES)
                .map((e, i) => (
                <button
                  key={i}
                  className="relationship-row"
                  onClick={() => setInspect(e)}
                >
                  {e.source} → {e.target}
                  <span>
                    {e.label || e.type || "Observed relationship"} ·{" "}
                    {Number(e.underlying_count || 1)} evidence records
                  </span>
                </button>
              ))}
            </>
          )}
        </Inspector>
      )}
    </>
  );
}

type GrantCard = {
  grant_count?: number;
  source_grants_truncated?: boolean;
  detail_ref?: { resource_ref?: string };
};
// IAM cards carry a bounded grant sample; the complete severity-annotated grant
// list for card.detail_ref is fetched only on request.
function CompleteGrants({
  scanId,
  demo,
  value,
}: {
  scanId: string;
  demo: boolean;
  value: ProjectedNode | GraphEdge;
}) {
  const card = (value as { card?: GrantCard }).card;
  const ref = card?.source_grants_truncated
    ? card.detail_ref?.resource_ref
    : undefined;
  const [open, setOpen] = useState(false);
  const detail = useApi<{ grant_count?: number; grants?: unknown[] }>(
    `/scans/${encodeURIComponent(scanId)}/graphs/iam/grants/` +
      encodeURIComponent(ref || ""),
    demo,
    open && !!ref && !!scanId,
  );
  useEffect(() => setOpen(false), [ref]);
  if (!ref) return null;
  if (!open)
    return (
      <button
        className="button"
        disabled={demo || !scanId}
        onClick={() => setOpen(true)}
      >
        Load all {Number(card?.grant_count || 0)} declared grants
      </button>
    );
  if (detail.isLoading)
    return <p className="muted small">Loading declared grants…</p>;
  if (detail.error) return <p className="muted small">{humanError(detail.error)}</p>;
  return (
    <>
      <h3>
        All declared grants ·{" "}
        {Number(detail.data?.grant_count ?? card?.grant_count ?? 0)}
      </h3>
      <Evidence data={detail.data?.grants ?? detail.data} />
    </>
  );
}

function inspectionSummary(value: ProjectedNode | GraphEdge) {
  const { internal_edges, underlying_edges, ...metadata } = value;
  const members = (metadata as ProjectedNode).member_ids;
  if (Array.isArray(members) && members.length > INSPECT_MEMBERS)
    Object.assign(metadata, {
      member_ids: members.slice(0, INSPECT_MEMBERS),
      member_count: members.length,
      member_ids_truncated: true,
    });
  const relationSummary = (edges: unknown) =>
    Array.isArray(edges)
      ? edges.slice(0, INSPECT_EDGES).map((e) => ({
          id: e.id,
          source: e.source,
          target: e.target,
          type: e.type,
          count: e.underlying_count || 1,
          evidence_available: true,
        }))
      : undefined;
  return {
    ...metadata,
    ...(internal_edges
      ? { internal_relationships: relationSummary(internal_edges) }
      : {}),
    ...(underlying_edges
      ? { underlying_relationships: relationSummary(underlying_edges) }
      : {}),
  };
}
