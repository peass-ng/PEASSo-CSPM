import { TableDownload, collectCursorTableRows } from "./TableDownload";
import { useEffect, useMemo, useRef, useState } from "react";
import { Background, BaseEdge, Controls, getSmoothStepPath, Handle, MarkerType, Position, ReactFlow } from "@xyflow/react";
import type { Edge, EdgeProps, Node, NodeProps, ReactFlowInstance } from "@xyflow/react";
import type { ElkEdgeSection, ElkNode } from "elkjs";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Boxes, ChevronDown, ChevronRight, Cloud, Disc3, Flame, Focus, GitFork, Globe2, HardDrive, Layers, LockKeyhole, Network, Route, Search, Server, Shield, ShieldAlert, ShieldCheck, Table2, Waypoints } from "lucide-react";
import { json, request, useApi } from "./api";
import { ConnectionAssessment } from "./ConnectionAssessment";
import type { ConfigurationDecision } from "./ConnectionAssessment";
import { sharedElk } from "./elkWorker";
import type { Graph, GraphEdge, GraphNode } from "./types";
import { Evidence, EvidenceFields, Inspector, Panel, State, visibleEvidence } from "./ui";
import { cidrs, kind, label, nativeDetails, networkModel, networkView, observed, providerNames, ruleRows, serviceTypes } from "./networkPresentation";
import type { Group, VisibleEdge, VisibleItem } from "./networkPresentation";
import "@xyflow/react/dist/style.css";

const emptyGraph: Graph = { nodes: [], edges: [] };
type NativeEdgeRecord = {
  id: string; type?: string; layer?: string; confidence?: string;
  source?: { id?: string; label?: string; native_id?: string; type?: string };
  target?: { id?: string; label?: string; native_id?: string; type?: string };
  evidence_refs?: unknown; evidence_status?: string;
};
type NativeEdgePage = { items: NativeEdgeRecord[]; total: number; next_cursor?: string | null; group_id?: string; snapshot_id?: string };
const icons: Record<string, typeof Network> = {
  vpc: Network, vnet: Network, network: Network, cluster: Boxes, subnet: Layers, subnetwork: Layers, namespace: Boxes,
  security_group: Shield, network_acl: ShieldAlert, network_firewall: Flame, network_firewall_policy: ShieldCheck, network_firewall_rule_group: Shield,
  nsg: ShieldCheck, firewall: Flame, firewall_policy: ShieldCheck, networkpolicy: ShieldAlert,
  route: Route, route_table: Route, transit_gateway_route_table: Route, router: Route,
  internet_gateway: Globe2, nat_gateway: Globe2, transit_gateway: Globe2, transit_gateway_attachment: GitFork, transit_gateway_vpc_attachment: GitFork, vpn_gateway: LockKeyhole, virtual_network_gateway: LockKeyhole, vpn_connection: LockKeyhole, vpn_tunnel: LockKeyhole, ec2_client_vpn_endpoint: LockKeyhole,
  load_balancer: Waypoints, classic_load_balancer: Waypoints, loadbalancer: Waypoints, application_gateway: Waypoints, forwarding_rule: Waypoints,
  vpc_peering: GitFork, vnet_peering: GitFork, peering: GitFork,
  vpc_endpoint: Waypoints, vpc_endpoint_service: Waypoints, ec2_instance_connect_endpoint: Waypoints, private_endpoint: Waypoints,
  elastic_ip: Globe2, ec2_eip: Globe2, address: Globe2, url_map: Route, backend_bucket: Cloud, health_check: ShieldCheck,
  network_interface: Disc3, nic: Disc3, instance: Server, vm: Server, rds_instance: Server, rds_cluster: Server, lambda_function: Cloud, eks_cluster: Boxes, gke_cluster: Boxes, pod: Boxes, service: Cloud,
  ecs_cluster: Boxes, ecs_service: Boxes, ecs_task: Boxes, ecs_task_set: Boxes, ecs_container_instance: Server,
  efs_file_system: HardDrive, efs_mount_target: Disc3, cloudfront_distribution: Globe2, cloudfront_vpc_origin: Waypoints,
  service_attachment: Waypoints, network_endpoint_group: Waypoints, network_attachment: Disc3, vpc_access_connector: GitFork,
  private_link_service: Waypoints, persistentvolume: HardDrive, persistentvolumeclaim: HardDrive,
  cloudrun_service: Cloud, cloudrun_job: Boxes, function: Cloud, filestore_instance: HardDrive, redis_instance: Server,
};
type N = Node<{ item: VisibleItem; expanded: boolean; internalResults?: ConfigurationDecision[]; onInspectInternal?: (results: ConfigurationDecision[]) => void }, "networkAsset">;
type E = Edge<{ count: number; type: string; uncertain: boolean; grouped?: boolean; color?: string; sections: ElkEdgeSection[]; rooted: boolean; showLabel: boolean }, "networkLink">;
function Asset({ data }: NodeProps<N>) {
  const { item } = data;
  const Icon = icons[item.kind] || HardDrive;
  const isGroup = item.id.startsWith("network:") || item.id.startsWith("area:");
  return <div className={`network-node ${isGroup ? "network-compound" : ""} ${item.id.startsWith("network:") ? "network-root" : ""}`} style={{ width: item.width, height: item.height }} data-kind={item.kind} data-hidden={item.hidden} title={`${item.title} · ${item.subtitle}`}>
    <Handle type="target" position={Position.Left} />
    <button type="button" className="network-node-heading" aria-expanded={isGroup ? data.expanded : undefined} aria-label={`${isGroup ? "Open" : "Inspect"} ${item.title}`}><Icon size={16} aria-label={`${item.kind.replaceAll("_", " ")} icon`} /><span className="network-node-label"><strong>{Array.from(item.title).slice(0,10).join("")}</strong></span>{isGroup && (data.expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />)}</button>
    {isGroup && (data.internalResults?.length ? <button type="button" className="network-node-meta network-node-internal" onClick={event=>{event.stopPropagation();data.onInspectInternal?.(data.internalResults!);}}>{data.internalResults.length.toLocaleString()} assessed internal pairs · inspect</button>
      : null)}
    <Handle type="source" position={Position.Right} />
  </div>;
}
function NetworkLink({ id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerStart, markerEnd, data, selected }: EdgeProps<E>) {
  const [fallback, fallbackX, fallbackY] = getSmoothStepPath({ sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, borderRadius: 8 });
  const sections = data?.rooted ? data.sections : undefined;
  const paths = sections?.length ? sections.map(section => [section.startPoint, ...(section.bendPoints || []), section.endPoint].map((point,index) => `${index ? "L" : "M"} ${point.x} ${point.y}`).join(" ")) : [fallback];
  const first = sections?.[0];
  const labelX = first ? (first.startPoint.x+first.endPoint.x)/2 : fallbackX;
  const labelY = first ? (first.startPoint.y+first.endPoint.y)/2 : fallbackY;
  return <g data-route={sections?.length ? "elk" : "flow"} data-relationship={data?.type}>{paths.map((path,index) => <BaseEdge key={index} id={`${id}:${index}`} path={path} markerStart={markerStart} markerEnd={markerEnd} interactionWidth={12} style={{ stroke:data?.color || (data?.uncertain ? "#dbb778" : "#809ca8"), strokeDasharray:data?.uncertain ? "5 4" : data?.grouped ? "3 3" : undefined, strokeWidth:selected ? 4 : Math.min(3.5, 2 + Math.log2(data?.count || 1)) }} />)}{(data?.showLabel || selected) && <text x={labelX} y={labelY-8} textAnchor="middle" className="network-edge-label">{data?.type}{data && data.count>1 ? ` ×${data.count}` : ""}</text>}</g>;
}
const nodeTypes = { networkAsset: Asset };
const edgeTypes = { networkLink: NetworkLink };
const flowEndpointTypes: Record<string, string[]> = { aws:["instance","network_interface"], azure:["vm","nic"], gcp:["instance","network_interface"], k8s:["pod"] };
function stringify(value: unknown) { return value === undefined || value === null || value === "" ? "Unknown" : String(value); }
function addressFamilyLabel(value: unknown) { return value === "ipv4" ? "IPv4" : value === "ipv6" ? "IPv6" : "Unknown family"; }
function relationshipLabel(value: unknown) { return stringify(value).replaceAll("_", " "); }
function decisionReason(result: ConfigurationDecision) {
  const rows = result.decision === "unknown" ? result.unresolved_dependencies :
    result.decision === "blocked" ? [...(Array.isArray(result.routes) ? result.routes : []),
      ...(Array.isArray(result.policy_decisions) ? result.policy_decisions : [])].filter(row => row?.decision === "blocked") : [];
  const first = Array.isArray(rows) ? rows.find(row => row && typeof row === "object" && typeof row.message === "string") : undefined;
  return first && typeof first.message === "string" ? first.message : undefined;
}
function assessmentSummary(results: ConfigurationDecision[]) {
  const counts = {allowed:0,blocked:0,unknown:0};
  for (const result of results) counts[result.decision] += 1;
  const decisions = (Object.keys(counts) as Array<keyof typeof counts>).filter(decision => counts[decision] > 0);
  return {
    decision: decisions.length === 1 ? decisions[0] : "mixed",
    label: decisions.length === 1 ? decisions[0] : decisions.map(decision => `${counts[decision]} ${decision}`).join(" · "),
  };
}
function validatedAssessmentResults(
  response: { snapshot_id?: string; results?: ConfigurationDecision[] } | undefined,
  provider: string,
  expectedPairs: Set<string>,
  expectedQuery: { protocol: string; sourcePort?: number; destinationPort: number; addressFamily: string },
): ConfigurationDecision[] | undefined {
  if (!response || typeof response.snapshot_id !== "string" || !response.snapshot_id ||
      !Array.isArray(response.results) || response.results.length !== expectedPairs.size) return undefined;
  const seen = new Set<string>();
  for (const result of response.results) {
    if (!result || typeof result !== "object" || result.provider !== provider ||
        result.snapshot_id !== response.snapshot_id || result.modeled_configuration !== true ||
        result.new_flow_only !== true || !["allowed", "blocked", "unknown"].includes(result.decision)) return undefined;
    const query = result.query;
    if (!query || typeof query !== "object") return undefined;
    const fields = query as Record<string, unknown>;
    const pair = JSON.stringify([fields.source_resource_id, fields.destination_resource_id]);
    if (!expectedPairs.has(pair) || seen.has(pair) || fields.protocol !== expectedQuery.protocol ||
        (fields.source_port ?? undefined) !== expectedQuery.sourcePort ||
        fields.destination_port !== expectedQuery.destinationPort ||
        fields.address_family !== expectedQuery.addressFamily) return undefined;
    seen.add(pair);
  }
  return response.results;
}
function isStoredEdgeId(value: unknown): value is string { return typeof value === "string" && /^analysis:[a-f0-9]{24}$/.test(value); }
function mergeGraphs(base: Graph, extra?: Graph): Graph {
  if (!extra) return base;
  const nodes = new Map(base.nodes.map(n => [n.id,n]));
  const loadedNodes = new Set<string>();
  for (const n of extra.nodes) {
    if (!n.stub && !n.aggregate) loadedNodes.add(n.id);
    if (!n.stub || !nodes.has(n.id) || nodes.get(n.id)?.stub) nodes.set(n.id,n);
  }
  const edges = new Map(base.edges.map((e,i) => [String(e.id || i),e]));
  const loadedEdges = new Set<string>();
  for (const [i,e] of extra.edges.entries()) {
    if (!e.aggregate) loadedEdges.add(String(e.id || `extra:${i}`));
    edges.set(String(e.id || `extra:${i}`),e);
  }
  for (const [id,n] of nodes) if (n.aggregate && Array.isArray(n.node_refs)) {
    const refs = n.node_refs.map(String).filter(ref => !loadedNodes.has(ref));
    if (!refs.length) nodes.delete(id);
    else if (refs.length < n.node_refs.length) nodes.set(id,{...n,node_refs:refs,underlying_count:refs.length,label:`${kind(n)} (${refs.length} still grouped)`});
  }
  for (const [id,e] of edges) if (e.aggregate && Array.isArray(e.edge_refs)) {
    const refs = e.edge_refs.map(String).filter(ref => !loadedEdges.has(ref));
    if (!refs.length) edges.delete(id);
    else if (refs.length < e.edge_refs.length) edges.set(id,{...e,edge_refs:refs,underlying_count:refs.length});
  }
  const kept = new Set(nodes.keys());
  return { ...base, nodes: [...nodes.values()], edges: [...edges.values()].filter(e => kept.has(e.source) && kept.has(e.target)) };
}
function ResourceDetail({ n, graph }: { n: GraphNode; graph: Graph }) {
  const [page, setPage] = useState(0);
  const refs = useMemo(() => graph.edges.flatMap((edge, index) => edge.source === n.id || edge.target === n.id ? [index] : []), [graph, n.id]);
  const byId = useMemo(() => new Map(graph.nodes.map(node => [node.id, node])), [graph]);
  const represented = refs.reduce((sum, index) => sum + Number(graph.edges[index].underlying_count || 1), 0);
  const loaded = refs.reduce((sum, index) => sum + (graph.edges[index].aggregate ? 0 : 1), 0);
  const unresolved = Math.max(0, represented - loaded);
  const pageSize = 100;
  const lastPage = Math.max(0, Math.ceil(refs.length / pageSize) - 1);
  const currentPage = Math.min(page, lastPage);
  const first = currentPage * pageSize;
  const last = Math.min(refs.length, first + pageSize);
  useEffect(() => setPage(0), [n.id]);
  return <>
    <details className="network-resource-details"><summary>Resource details</summary>
      <dl className="network-facts">{nativeDetails(n).filter(x => x.name !== "Name" && x.name !== "Type").map((x,index) => <div key={`${x.name}:${index}`}><dt>{x.name}</dt><dd>{x.value}</dd></div>)}</dl>
    </details>
    {!observed(n) && <p className="notice">Referenced resource was not collected in this scope. Its configuration and attachment are unknown.</p>}
    <h3>Loaded attachment records · {refs.length}</h3>
    <p>{represented.toLocaleString()} represented attachment{represented===1?"":"s"} · {loaded.toLocaleString()} loaded individual record{loaded===1?"":"s"} · {unresolved.toLocaleString()} underlying record{unresolved===1?"":"s"} not loaded.</p>
    {refs.length ? <><TableDownload table="network-attachments" label="loaded attachment records"
      rows={refs.map(index => {
        const edge = graph.edges[index];
        const other = byId.get(edge.source === n.id ? edge.target : edge.source);
        return { id: edge.id, relationship: relationshipLabel(edge.type || edge.label),
          other_endpoint: other ? label(other) : "Unresolved endpoint",
          evidence_type: edge.layer === "modeled_rule" ? "Rule candidate; reachability unknown"
            : edge.aggregate ? "Projected summary; underlying facts may be unloaded" : "Supplied reference",
          supplied_fields: visibleEvidence(edge.evidence ?? null) };
      })} />
      <div className="network-rule-scroll" role="region" aria-label="Loaded attachment records" tabIndex={0}>
      <table className="network-rules"><thead><tr><th>Relationship</th><th>Other endpoint</th><th>Evidence type</th><th>Supplied fields</th></tr></thead>
        <tbody>{refs.slice(first,last).map((index) => { const e = graph.edges[index]; const other = byId.get(e.source === n.id ? e.target : e.source); return <tr key={e.id || index}><td>{relationshipLabel(e.type || e.label)}</td><td>{other ? label(other) : "Unresolved endpoint"}</td><td>{e.layer === "modeled_rule" ? "Rule candidate; reachability unknown" : e.aggregate ? "Projected summary; underlying facts may be unloaded" : "Supplied reference"}</td><td>{e.evidence ? <details><summary>View supplied fields</summary><EvidenceFields data={e.evidence} /></details> : "No fields supplied"}</td></tr>; })}</tbody>
      </table></div><div className="network-rule-pages"><span>Attachment records {first+1}–{last} of {refs.length}{refs.length>pageSize ? " · additional loaded records on later pages" : ""}</span>{refs.length>pageSize && <div><button type="button" disabled={currentPage===0} onClick={() => setPage(currentPage-1)}>Previous attachment page</button><button type="button" disabled={currentPage===lastPage} onClick={() => setPage(currentPage+1)}>Next attachment page</button></div>}</div></> : <p className="muted">No attachment relationships were supplied in loaded graph evidence.</p>}
    {serviceTypes.has(kind(n)) && <RuleTable node={n} />}
    <details><summary>Collected technical fields</summary><Evidence data={n} /></details>
  </>;
}
const nativeEndpointLabel = (endpoint: NativeEdgeRecord["source"]) =>
  endpoint?.label || endpoint?.native_id || endpoint?.id || "Unknown endpoint";

function NativeEdgeRows({ items, loadAll }: {
  items: NativeEdgeRecord[]; loadAll?: (signal: AbortSignal) => Promise<NativeEdgeRecord[]>;
}) {
  const exportRows = async (signal: AbortSignal) => (loadAll ? await loadAll(signal) : items).map(item => ({
    id: item.id, type: item.type, relationship: relationshipLabel(item.type),
    source_label: nativeEndpointLabel(item.source), evidence_refs: visibleEvidence(item.evidence_refs),
    destination_label: nativeEndpointLabel(item.target), evidence_label: item.evidence_status ? relationshipLabel(item.evidence_status) : "Status unknown",
  }));
  return <><TableDownload table="native-network-relationships" label="native relationship details table" loadRows={exportRows} />
    <div className="network-rule-scroll" role="region" aria-label="Native relationship details" tabIndex={0}><table className="network-rules"><thead><tr><th>Relationship</th><th>Source</th><th>Destination</th><th>Evidence</th></tr></thead><tbody>{items.map(item => <tr key={item.id}>
    <td>{relationshipLabel(item.type)} · {item.id}</td>
    <td>{nativeEndpointLabel(item.source)}</td>
    <td>{nativeEndpointLabel(item.target)}</td>
    <td>{item.evidence_status ? relationshipLabel(item.evidence_status) : "Status unknown"}{item.evidence_refs != null && <details><summary>Supplied evidence references</summary><EvidenceFields data={item.evidence_refs} /></details>}</td>
  </tr>)}</tbody></table></div></>;
}
function NativeGroupRecords({ scanId, groupId }: { scanId: string; groupId: string }) {
  const [open, setOpen] = useState(false);
  const groupPath = `/scans/${encodeURIComponent(scanId)}/graphs/network/edges?group_id=${encodeURIComponent(groupId)}&limit=100`;
  const loadPage = (cursor: string, signal?: AbortSignal) =>
    request<NativeEdgePage>(cursor ? `${groupPath}&cursor=${encodeURIComponent(cursor)}` : groupPath, { signal });
  const pages = useInfiniteQuery<NativeEdgePage, Error>({
    queryKey: ["network-native-group", scanId, groupId], initialPageParam: "",
    enabled: open,
    queryFn: ({ pageParam, signal }) => loadPage(String(pageParam), signal),
    getNextPageParam: last => last.next_cursor || undefined, retry: 1,
  });
  const records = pages.data?.pages.flatMap(page => page.items) || [];
  const loaded = records.length;
  const total = pages.data?.pages[0]?.total;
  return <section><button type="button" className="text-button" onClick={() => setOpen(value => !value)} aria-expanded={open}>{open ? "Hide" : "Load"} native records for projected group {groupId}</button>
    {open && <>{pages.isPending && <p role="status">Loading native relationships…</p>}{pages.error && <p role="alert">Native relationship details could not be loaded: {pages.error.message}</p>}
      {pages.data && <><p>Native records loaded {loaded.toLocaleString()} of {Number(total ?? loaded).toLocaleString()}.</p><NativeEdgeRows items={records} loadAll={signal => collectCursorTableRows(loadPage, signal)} />{pages.hasNextPage && <button type="button" disabled={pages.isFetchingNextPage} onClick={() => void pages.fetchNextPage()}>Next native relationship page</button>}</>}</>}
  </section>;
}
function NativePageRecords({ scanId, ids }: { scanId: string; ids: string[] }) {
  const [open, setOpen] = useState(false);
  const query = useApi<NativeEdgePage>(`/scans/${encodeURIComponent(scanId)}/graphs/network/edges?${ids.map(id => `ids=${encodeURIComponent(id)}`).join("&")}`, false, open && ids.length > 0);
  if (!ids.length) return null;
  return <section><button type="button" className="text-button" onClick={() => setOpen(value => !value)} aria-expanded={open}>{open ? "Hide" : "Load"} native details for {ids.length} record{ids.length===1?"":"s"} on this page</button>
    {open && <>{query.isPending && <p role="status">Loading native relationship details…</p>}{query.error && <p role="alert">Native relationship details could not be loaded: {query.error.message}</p>}{query.data && <NativeEdgeRows items={query.data.items} />}</>}
  </section>;
}
function RelationshipDetail({ edge, graph, scanId, demo }: { edge: VisibleEdge; graph: Graph; scanId: string; demo: boolean }) {
  const [page, setPage] = useState(0);
  const pageSize = 100;
  const lastPage = Math.max(0, Math.ceil(edge.recordIndices.length / pageSize) - 1);
  const currentPage = Math.min(page, lastPage);
  const first = currentPage * pageSize;
  const last = Math.min(edge.recordIndices.length, first + pageSize);
  const byId = useMemo(() => new Map(graph.nodes.map(node => [node.id, node])), [graph]);
  useEffect(() => setPage(0), [edge.id]);
  return <section>
    <p>{edge.count.toLocaleString()} represented supplied relationship{edge.count===1?"":"s"} · {edge.availableCount.toLocaleString()} loaded individual record{edge.availableCount===1?"":"s"} · {edge.unresolvedCount.toLocaleString()} underlying record{edge.unresolvedCount===1?"":"s"} not loaded in the graph.</p>
    <p>{edge.uncertain ? "This group includes a rule candidate; reachability is unknown." : "These are supplied references, not proof of traffic flow."}</p>
    {!!edge.unresolvedCount && <p className="muted">Projected references and bounded server responses may represent facts unavailable in this loaded view. Load relevant inventory pages or the source snapshot to inspect them.</p>}
    <TableDownload table="loaded-network-relationships" label="loaded relationship records table"
      rows={edge.recordIndices.flatMap((index, position) => {
        const record = graph.edges[index];
        if (!record) return [];
        return [{ record: stringify(record.id || `Record ${position + 1}`),
          source_label: label(byId.get(record.source) || { id: record.source }),
          destination_label: label(byId.get(record.target) || { id: record.target }),
          supplied_fields: visibleEvidence(record.evidence ?? null),
          status: record.aggregate ? `Projected summary · ${Number(record.underlying_count || 1)} underlying`
            : record.layer === "modeled_rule" ? "Rule candidate" : "Loaded supplied reference" }];
      })} />
    <div className="network-rule-scroll" role="region" aria-label="Loaded relationship records" tabIndex={0}><table className="network-rules"><thead><tr><th>Record</th><th>Source</th><th>Destination</th><th>Status</th></tr></thead><tbody>
      {edge.recordIndices.slice(first,last).map((index,i) => { const record = graph.edges[index]; if (!record) return null; return <tr key={index}><td>{stringify(record.id || `Record ${first+i+1}`)}</td><td>{label(byId.get(record.source) || {id:record.source})}</td><td>{label(byId.get(record.target) || {id:record.target})}</td><td>{record.aggregate ? `Projected summary · ${Number(record.underlying_count || 1)} underlying` : record.layer === "modeled_rule" ? "Rule candidate" : "Loaded supplied reference"}</td></tr>; })}
    </tbody></table></div>
    <div className="network-rule-pages"><span>Loaded records {first+1}–{last} of {edge.recordIndices.length}</span>{edge.recordIndices.length>pageSize && <div><button type="button" disabled={currentPage===0} onClick={() => setPage(currentPage-1)}>Previous relationship page</button><button type="button" disabled={currentPage===lastPage} onClick={() => setPage(currentPage+1)}>Next relationship page</button></div>}</div>
    {edge.recordIndices.slice(first,last).map(index => { const record = graph.edges[index]; return record?.evidence ? <details key={index}><summary>Supplied fields for {stringify(record.id || `record ${index+1}`)}</summary><EvidenceFields data={record.evidence} /></details> : null; })}
    {!demo && !!scanId && <NativePageRecords key={`${edge.id}:${currentPage}`} scanId={scanId} ids={edge.recordIndices.slice(first,last).map(index => graph.edges[index]).filter(record => !record.aggregate && isStoredEdgeId(record.id)).map(record => String(record.id))} />}
    {!demo && !!scanId && edge.recordIndices.slice(first,last).map(index => graph.edges[index]).filter(record => record.aggregate && isStoredEdgeId(record.id) && Array.isArray(record.edge_refs) && !record.boundary && Number(record.underlying_count) === record.edge_refs.length).map(record => <NativeGroupRecords key={record.id} scanId={scanId} groupId={String(record.id)} />)}
  </section>;
}
function RuleTable({ node }: { node: GraphNode }) {
  const rows = ruleRows(node);
  const [page, setPage] = useState(0);
  const pageSize = 100;
  const lastPage = Math.max(0, Math.ceil(rows.length / pageSize) - 1);
  const visiblePage = Math.min(page, lastPage);
  const first = visiblePage * pageSize;
  const last = Math.min(first + pageSize, rows.length);
  useEffect(() => { setPage(0); }, [node.id, node.evidence, rows.length]);
  return <section>
    <h3>Collected rules · {rows.length}</h3>
    {node.type === "network_acl" && <p className="muted">Network ACL rules are ordered by number and stateless. These rows do not establish effective reachability.</p>}
    {rows.length ? <>
      <TableDownload table="network-rules" label="collected network rules table" rows={rows} />
      <div className="network-rule-scroll" role="region" aria-label="Collected network rules" tabIndex={0}>
        <table className="network-rules"><thead><tr>{["Rule / priority", "Direction", "Protocol", "Port", "Source", "Destination", "Action"].map(x => <th key={x}>{x}</th>)}</tr></thead>
          <tbody>{rows.slice(first, last).map((r, i) => <tr key={first + i}><td>{r.order}</td><td>{r.direction}</td><td>{r.protocol}</td><td>{r.port}</td><td>{r.source}</td><td>{r.destination}</td><td>{r.action}</td></tr>)}</tbody>
        </table>
      </div>
      <div className="network-rule-pages"><span>Rules {first + 1}–{last} of {rows.length}</span>{rows.length > pageSize && <div><button type="button" disabled={visiblePage === 0} onClick={() => setPage(Math.max(0, visiblePage - 1))}>Previous rule page</button><button type="button" disabled={visiblePage === lastPage} onClick={() => setPage(Math.min(lastPage, visiblePage + 1))}>Next rule page</button></div>}</div>
    </> : <p className="muted">No native rule rows were supplied in this graph node. Review the source snapshot for full configuration.</p>}
  </section>;
}
export function NetworkMap({ scanId, demo }: { scanId: string; demo: boolean }) {
  const [expansion, setExpansion] = useState("");
  const [inventoryEnabled, setInventoryEnabled] = useState(false);
  const base = useApi<Graph>(`/scans/${encodeURIComponent(scanId)}/graphs/network?max_nodes=500`, demo, !!scanId);
  const expanded = useApi<Graph>(`/scans/${encodeURIComponent(scanId)}/graphs/network/expand?node=${encodeURIComponent(expansion)}`, demo, !!scanId && !!expansion && !demo);
  const pages = useInfiniteQuery<Graph & { page?: number; page_count?: number }, Error>({
    queryKey:[demo ? "demo" : "live","network-inventory",scanId],
    initialPageParam:0,
    enabled:!!scanId && !demo && inventoryEnabled,
    queryFn:({pageParam})=>request<Graph & {page?:number;page_count?:number}>(`/scans/${encodeURIComponent(scanId)}/graphs/network/page?page=${Number(pageParam)}&page_size=120`),
    getNextPageParam:last=>typeof last.page_count === "number" && typeof last.page === "number" && last.page+1 < last.page_count ? last.page+1 : undefined,
    retry:1,
  });
  const graph = useMemo(() => {
    let result = mergeGraphs(base.data || emptyGraph, expanded.data);
    if (!demo && inventoryEnabled) for (const page of pages.data?.pages || []) result = mergeGraphs(result,page);
    return result;
  }, [base.data, expanded.data, pages.data, demo, inventoryEnabled]);
  const model = useMemo(() => networkModel(graph), [graph]);
  const [provider, setProvider] = useState("");
  const [networkId, setNetworkId] = useState("");
  const [areaId, setAreaId] = useState("");
  const [expandedAreas, setExpandedAreas] = useState<Set<string>>(() => new Set());
  const [search, setSearch] = useState("");
  const [mode, setMode] = useState<"map" | "table">("map");
  const [connection, setConnection] = useState(false);
  const [assessSource, setAssessSource] = useState("");
  const [assessTarget, setAssessTarget] = useState("");
  const [flowResult, setFlowResult] = useState<ConfigurationDecision>();
  const [flowInspect, setFlowInspect] = useState(false);
  const [batchSource, setBatchSource] = useState("");
  const [batchProtocol, setBatchProtocol] = useState("tcp");
  const [batchFamily, setBatchFamily] = useState("ipv4");
  const [batchPort, setBatchPort] = useState("443");
  const [batchSourcePort, setBatchSourcePort] = useState("");
  const [batchResults, setBatchResults] = useState<ConfigurationDecision[]>([]);
  const [batchPageResults, setBatchPageResults] = useState<ConfigurationDecision[]>([]);
  const [batchError, setBatchError] = useState("");
  const [batchPending, setBatchPending] = useState(false);
  const [batchTotal, setBatchTotal] = useState(0);
  const [batchOffset, setBatchOffset] = useState(0);
  const [batchInspect, setBatchInspect] = useState<ConfigurationDecision[]>();
  const [matrixInspect, setMatrixInspect] = useState<ConfigurationDecision[]>();
  const [matrixPage, setMatrixPage] = useState(0);
  const [matrixComparePage, setMatrixComparePage] = useState<number | null>(null);
  const batchRun = useRef(0);
  const [page, setPage] = useState(0);
  const [inspect, setInspect] = useState<VisibleItem | VisibleEdge>();
  const inspectedNode = inspect && "node" in inspect ? inspect.node : undefined;
  const needsNative = !!inspectedNode?.resource_id && !(inspectedNode.evidence && typeof inspectedNode.evidence === "object" && "native_resource" in inspectedNode.evidence);
  const native = useApi<Record<string, unknown>>(`/scans/${encodeURIComponent(scanId)}/resources/${encodeURIComponent(String(inspectedNode?.resource_id || ""))}`, demo, !!scanId && needsNative && !demo);
  const detailedNode = inspectedNode && native.data ? { ...inspectedNode, evidence: { ...(typeof inspectedNode.evidence === "object" ? inspectedNode.evidence : {}), native_resource: native.data } } : inspectedNode;
  const [layout, setLayout] = useState<{ nodes: N[]; edges: E[] }>({ nodes: [], edges: [] });
  const [layoutError, setLayoutError] = useState("");
  const flow = useRef<ReactFlowInstance<N,E> | null>(null);
  const tableScroll = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const refit = () => requestAnimationFrame(() => void flow.current?.fitView({ padding: 0.18, maxZoom: 1.1, duration: 0 }));
    window.addEventListener("resize", refit);
    return () => window.removeEventListener("resize", refit);
  }, []);
  useEffect(() => { batchRun.current += 1; setProvider(""); setNetworkId(""); setAreaId(""); setExpandedAreas(new Set()); setExpansion(""); setInventoryEnabled(false); setFlowResult(undefined); setBatchSource(""); setBatchResults([]); setBatchPageResults([]); setBatchError(""); setBatchPending(false); setPage(0); }, [scanId,demo]);
  const currentProvider = model.providers.includes(provider) ? provider : model.providers[0] || "";
  useEffect(() => setMatrixPage(0), [scanId, demo, currentProvider, networkId, areaId, page]);
  const flowQuery = flowResult?.query && typeof flowResult.query === "object" ? flowResult.query as Record<string, unknown> : {};
  const flowFamily = addressFamilyLabel(flowQuery.address_family);
  const sourceNode = graph.nodes.find(n => n.resource_id === flowQuery.source_resource_id && !n.stub && !n.aggregate);
  const targetNode = graph.nodes.find(n => n.resource_id === flowQuery.destination_resource_id && !n.stub && !n.aggregate);
  const batchSourceNode = graph.nodes.find(n => n.resource_id === batchSource && !n.stub && !n.aggregate);
  const batchSourceNetwork = batchSourceNode && model.owner.get(batchSourceNode.id);
  const batchSourceArea = batchSourceNode && model.area.get(batchSourceNode.id);
  const flowProviderVisible = !!sourceNode && !!targetNode && !!flowResult &&
    sourceNode.provider === currentProvider && targetNode.provider === currentProvider &&
    flowResult.provider === currentProvider;
  const batchFocusIds = batchPageResults.filter(result => result.provider === currentProvider).flatMap(result => {
    const query = result.query && typeof result.query === "object" ? result.query as Record<string, unknown> : {};
    return [query.source_resource_id, query.destination_resource_id].filter((id): id is string => typeof id === "string" && !!id);
  });
  const focusAssets = [...new Set([
    ...(flowProviderVisible ? [sourceNode?.id, targetNode?.id] : []),
    ...graph.nodes.filter(node => node.provider === currentProvider && typeof node.resource_id === "string" && batchFocusIds.includes(node.resource_id)).map(node => node.id),
  ].filter((id): id is string => !!id))];
  const focusNetworks = focusAssets.map(id => model.owner.get(id)).filter((id): id is string => !!id);
  const view = useMemo(() => networkView(model, currentProvider, networkId, areaId, search, page, focusNetworks, focusAssets, [...expandedAreas]), [model, currentProvider, networkId, areaId, search, page, focusNetworks.join("|"), focusAssets.join("|"), expandedAreas]);
  const matrixCandidates = useMemo(() => {
    const interfacesByMachine = new Map<string, Set<string>>();
    for (const edge of graph.edges) {
      if (edge.type !== "attached_interface") continue;
      const source = model.byId.get(edge.source), target = model.byId.get(edge.target);
      if (!source || !target || source.provider !== target.provider) continue;
      const machine = ["instance", "vm"].includes(kind(source)) && ["network_interface", "nic"].includes(kind(target)) ? source
        : ["instance", "vm"].includes(kind(target)) && ["network_interface", "nic"].includes(kind(source)) ? target : undefined;
      const iface = machine === source ? target : machine === target ? source : undefined;
      if (machine && iface && flowEndpointTypes[String(machine.provider)]?.includes(kind(iface)) &&
          typeof iface.resource_id === "string" && iface.resource_id !== machine.resource_id &&
          observed(machine) && !machine.stub && !machine.aggregate)
        interfacesByMachine.set(machine.id, new Set([...(interfacesByMachine.get(machine.id) || []), iface.id]));
    }
    const selectableInterface = (id: string) => {
      const node = model.byId.get(id);
      return !!node && !node.stub && !node.aggregate && observed(node);
    };
    const representedInterfaces = new Set([...interfacesByMachine.values()]
      .filter(ids => ids.size === 1 && [...ids].every(selectableInterface)).flatMap(ids => [...ids]));
    const ambiguousMachines = new Set([...interfacesByMachine.entries()]
      .filter(([,ids]) => ids.size > 1 && [...ids].every(selectableInterface)).map(([id]) => id));
    const shownNetworks = new Set(view.items.filter(item => item.id.startsWith("network:")).map(item => item.group?.id).filter((id): id is string => !!id));
    return graph.nodes.filter(node => node.provider === currentProvider && !node.stub && !node.aggregate && observed(node) && !representedInterfaces.has(node.id) && !ambiguousMachines.has(node.id) &&
      typeof node.resource_id === "string" && flowEndpointTypes[currentProvider]?.includes(kind(node)) &&
      (!networkId ? shownNetworks.has(model.owner.get(node.id) || "") : model.owner.get(node.id) === networkId) &&
      (!areaId || model.area.get(node.id) === areaId));
  }, [graph.nodes, graph.edges, currentProvider, networkId, areaId, model, view.items]);
  const matrixEndpointOrder = useMemo(() => {
    const buckets = new Map<string, GraphNode[]>();
    for (const node of matrixCandidates) {
      const key = areaId ? areaId : networkId ? model.area.get(node.id) || node.id : model.owner.get(node.id) || node.id;
      buckets.set(key, [...(buckets.get(key) || []), node]);
    }
    const queues = [...buckets.values()].map(rows => ({rows, offset:0}));
    const ordered: string[] = [], seen = new Set<string>();
    let remaining = queues.reduce((sum, queue) => sum + queue.rows.length, 0);
    while (remaining) {
      for (const queue of queues) {
        const node = queue.rows[queue.offset++];
        if (!node) continue;
        remaining -= 1;
        if (typeof node.resource_id === "string" && !seen.has(node.resource_id)) {
          seen.add(node.resource_id);
          ordered.push(node.resource_id);
        }
      }
    }
    return ordered;
  }, [matrixCandidates, areaId, networkId, model]);
  const matrixPageCount = Math.max(1, Math.ceil(matrixEndpointOrder.length / 12));
  const currentMatrixPage = Math.min(matrixPage, matrixPageCount - 1);
  useEffect(() => setMatrixComparePage(null), [scanId, demo, currentProvider, networkId, areaId, page, currentMatrixPage]);
  const matrixWindow = matrixEndpointOrder.slice(currentMatrixPage * 12, (currentMatrixPage + 1) * 12);
  const matrixEndpointIds = matrixWindow.length === 1 && currentMatrixPage > 0
    ? [matrixEndpointOrder[currentMatrixPage * 12 - 1], ...matrixWindow] : matrixWindow;
  const borrowedEndpointId = matrixWindow.length === 1 && currentMatrixPage > 0 ? matrixEndpointIds[0] : undefined;
  const compareEndpointIds = matrixComparePage === null ? []
    : matrixEndpointOrder.slice(matrixComparePage * 12, (matrixComparePage + 1) * 12)
      .filter(id => id !== borrowedEndpointId);
  const matrix = useQuery<{snapshot_id: string; results: ConfigurationDecision[]}, Error>({
    queryKey:["network-matrix",scanId,currentProvider,matrixEndpointIds],
    enabled:!demo && !!scanId && matrixEndpointIds.length >= 2,
    queryFn:()=>request(`/scans/${encodeURIComponent(scanId)}/reachability/matrix`, json({
      endpoint_resource_ids:matrixEndpointIds, protocol:"tcp", destination_port:443,
      source_port:54321, address_family:"ipv4",
    })),
    staleTime:Infinity, retry:1,
  });
  const grid = useQuery<{snapshot_id: string; results: ConfigurationDecision[]}, Error>({
    queryKey:["network-grid",scanId,currentProvider,matrixWindow,compareEndpointIds],
    enabled:!demo && !!scanId && matrixComparePage !== null && matrixComparePage !== currentMatrixPage &&
      matrixWindow.length > 0 && compareEndpointIds.length > 0,
    queryFn:()=>request(`/scans/${encodeURIComponent(scanId)}/reachability/grid`, json({
      first_endpoint_resource_ids:matrixWindow, second_endpoint_resource_ids:compareEndpointIds,
      protocol:"tcp", destination_port:443, source_port:54321, address_family:"ipv4",
    })),
    staleTime:Infinity, retry:1,
  });
  const expectedMatrixPairs = new Set(matrixEndpointIds.flatMap(source =>
    matrixEndpointIds.filter(destination => destination !== source).map(destination => JSON.stringify([source,destination]))));
  const expectedGridPairs = new Set(compareEndpointIds.flatMap(first =>
    matrixWindow.filter(second => second !== first).flatMap(second =>
      [JSON.stringify([first,second]), JSON.stringify([second,first])])));
  const previewQuery = {protocol:"tcp",sourcePort:54321,destinationPort:443,addressFamily:"ipv4"};
  const validatedMatrixResults = validatedAssessmentResults(matrix.data, currentProvider, expectedMatrixPairs, previewQuery);
  const validatedGridResults = validatedMatrixResults && grid.data?.snapshot_id === matrix.data?.snapshot_id
    ? validatedAssessmentResults(grid.data, currentProvider, expectedGridPairs, previewQuery) : undefined;
  const flowEdge = useMemo(() => {
    if (!flowResult || !flowProviderVisible || !sourceNode || !targetNode) return undefined;
    const ids = new Set(view.items.map(item => item.id));
    const representative = (node: GraphNode) => {
      if (ids.has(`asset:${node.id}`)) return `asset:${node.id}`;
      const area = model.area.get(node.id);
      if (area && ids.has(`area:${area}`)) return `area:${area}`;
      const owner = model.owner.get(node.id);
      return owner && ids.has(`network:${owner}`) ? `network:${owner}` : undefined;
    };
    const source = representative(sourceNode), target = representative(targetNode);
    if (!source || !target || source === target) return undefined;
    return { source, target, id:"assessed-flow", decision:flowResult.decision,
      grouped:!source.startsWith("asset:") || !target.startsWith("asset:"),
      type:`${label(sourceNode)} → ${label(targetNode)} · ${flowFamily} ${String(flowQuery.protocol || "tcp").toUpperCase()}/${flowQuery.source_port ? `${flowQuery.source_port}→` : ""}${String(flowQuery.destination_port || "?")} · ${flowResult.decision}` };
  }, [flowResult, flowProviderVisible, sourceNode, targetNode, view, model, flowFamily, flowQuery.protocol, flowQuery.source_port, flowQuery.destination_port]);
  const batchEdges = useMemo(() => {
    const visibleIds = new Set(view.items.map(item => item.id));
    const representative = (node: GraphNode) => {
      if (visibleIds.has(`asset:${node.id}`)) return `asset:${node.id}`;
      const area = model.area.get(node.id);
      if (area && visibleIds.has(`area:${area}`)) return `area:${area}`;
      const owner = model.owner.get(node.id);
      return owner && visibleIds.has(`network:${owner}`) ? `network:${owner}` : undefined;
    };
    const grouped = new Map<string, {id:string;source:string;target:string;results:ConfigurationDecision[]}>();
    for (const result of batchResults) {
      const query = result.query && typeof result.query === "object" ? result.query as Record<string, unknown> : {};
      const source = graph.nodes.find(node => node.resource_id === query.source_resource_id && !node.stub && !node.aggregate);
      const target = graph.nodes.find(node => node.resource_id === query.destination_resource_id && !node.stub && !node.aggregate);
      if (!source || !target || source.provider !== currentProvider) continue;
      const from = representative(source), to = representative(target);
      if (!from || !to || from === to) continue;
      const key = JSON.stringify([from,to]);
      const found = grouped.get(key);
      if (found) found.results.push(result);
      else grouped.set(key,{id:`assessed-batch:${grouped.size}`,source:from,target:to,results:[result]});
    }
    return [...grouped.values()].map(edge => {
      const query = edge.results[0].query as Record<string, unknown>;
      const summary = assessmentSummary(edge.results);
      return {...edge,decision:summary.decision,
        grouped:edge.results.length>1 || !edge.source.startsWith("asset:") || !edge.target.startsWith("asset:"),
        type:`${addressFamilyLabel(query.address_family)} ${String(query.protocol || "tcp").toUpperCase()}/${query.source_port ? `${query.source_port}→` : ""}${String(query.destination_port || "?")} · ${summary.label}`};
    });
  }, [batchResults, view.items, graph.nodes, currentProvider, model]);
  const matrixEdges = useMemo(() => {
    const visibleIds = new Set(view.items.map(item => item.id));
    const nodeByResource = new Map(graph.nodes.filter(node => node.provider === currentProvider &&
      !node.stub && !node.aggregate && observed(node) && typeof node.resource_id === "string").map(node => [node.resource_id, node]));
    const representative = (node: GraphNode) => {
      if (visibleIds.has(`asset:${node.id}`)) return `asset:${node.id}`;
      const area = model.area.get(node.id);
      if (area && visibleIds.has(`area:${area}`)) return `area:${area}`;
      const owner = model.owner.get(node.id);
      return owner && visibleIds.has(`network:${owner}`) ? `network:${owner}` : undefined;
    };
    const grouped = new Map<string, {id:string;source:string;target:string;decision:string;results:ConfigurationDecision[];type:string}>();
    const assessed = [...(validatedMatrixResults || []), ...(validatedGridResults || [])];
    for (const result of assessed) {
      const query = result.query && typeof result.query === "object" ? result.query as Record<string, unknown> : {};
      const source = nodeByResource.get(query.source_resource_id as string);
      const target = nodeByResource.get(query.destination_resource_id as string);
      if (!source || !target) continue;
      const from = representative(source), to = representative(target);
      if (!from || !to || from === to) continue;
      const key = JSON.stringify([from,to]);
      const found = grouped.get(key);
      if (found) found.results.push(result);
      else grouped.set(key,{id:`matrix:${grouped.size}`,source:from,target:to,decision:result.decision,
        results:[result],type:`IPv4 TCP/54321→443 · ${result.decision}`});
    }
    return [...grouped.values()].map(edge => {
      const summary = assessmentSummary(edge.results);
      return {...edge,decision:summary.decision,type:`IPv4 TCP/54321→443 · ${summary.label}`};
    });
  }, [validatedMatrixResults, validatedGridResults, view.items, graph.nodes, model, currentProvider]);
  const internalMatrixGroups = useMemo(() => {
    const visibleIds = new Set(view.items.map(item => item.id));
    const nodeByResource = new Map(graph.nodes.filter(node => node.provider === currentProvider &&
      !node.stub && !node.aggregate && observed(node) && typeof node.resource_id === "string").map(node => [node.resource_id, node]));
    const representative = (node: GraphNode) => {
      if (visibleIds.has(`asset:${node.id}`)) return `asset:${node.id}`;
      const area = model.area.get(node.id);
      if (area && visibleIds.has(`area:${area}`)) return `area:${area}`;
      const owner = model.owner.get(node.id);
      return owner && visibleIds.has(`network:${owner}`) ? `network:${owner}` : undefined;
    };
    const groups = new Map<string, ConfigurationDecision[]>();
    for (const result of [...(validatedMatrixResults || []), ...(validatedGridResults || [])]) {
      const query = result.query as Record<string, unknown>;
      const source = nodeByResource.get(query.source_resource_id as string);
      const target = nodeByResource.get(query.destination_resource_id as string);
      if (!source || !target) continue;
      const from = representative(source), to = representative(target);
      if (!from || from !== to || !from.startsWith("network:") && !from.startsWith("area:")) continue;
      groups.set(from, [...(groups.get(from) || []), result]);
    }
    return groups;
  }, [validatedMatrixResults, validatedGridResults, view.items, graph.nodes, model, currentProvider]);
  const sharedArea = sourceNode && targetNode && model.area.get(sourceNode.id) === model.area.get(targetNode.id)
    ? model.area.get(sourceNode.id) : undefined;
  const sharedNetwork = sourceNode && targetNode && model.owner.get(sourceNode.id) === model.owner.get(targetNode.id)
    ? model.owner.get(sourceNode.id) : undefined;
  const sameVisibleGroup = sourceNode?.id === targetNode?.id ||
    !!sharedArea && view.items.some(item => item.id === `area:${sharedArea}`) ||
    !!sharedNetwork && view.items.some(item => item.id === `network:${sharedNetwork}`);
  const flowArrowMessage = !flowResult || flowEdge ? "" : !sourceNode || !targetNode
    ? "One or both endpoints are outside the loaded map evidence. Load inventory pages or expand their resource group to draw the assessed arrow."
    : sameVisibleGroup
      ? "Both endpoints are represented by one visible group; open their subnet to see a separate arrow."
      : "The endpoints are outside the current visible page or filter. Open their network or clear the filter to draw the assessed arrow.";
  const visible = useMemo(() => new Map(view.items.map(x=>[x.id,x])), [view]);
  const virtual = useVirtualizer({ count: view.matching.length, getScrollElement: () => tableScroll.current, estimateSize: () => 62, overscan: 8 });
  useEffect(() => {
    let live = true;
    if (!view.items.length) { setLayout({ nodes: [], edges: [] }); return; }
    const items = view.items.map(item=>({...item}));
    const byId = new Map(items.map(item=>[item.id,item]));
    const links = [...view.edges, ...(flowEdge ? [flowEdge] : []), ...batchEdges, ...matrixEdges];
    const positions = new Map<string,{x:number;y:number}>();
    const localSections = new Map<string,{parentId?:string;sections:ElkEdgeSection[]}>();
    const arrange = async () => {
      // Lay out each container from the inside out so ELK can route links around
      // the actual child bounds, including expanded subnets and their endpoints.
      for (const parentId of [...items.filter(item=>item.id.startsWith("area:")).map(item=>item.id),
        ...items.filter(item=>item.id.startsWith("network:")).map(item=>item.id), "root"]) {
        const children = items.filter(item=>parentId==="root" ? !item.parentId : item.parentId===parentId);
        if (!children.length) continue;
        const childIds = new Set(children.map(item=>item.id));
        const siblingLinks = links.filter(edge=>childIds.has(edge.source) && childIds.has(edge.target));
        const directChild = (id:string) => {
          let item = byId.get(id);
          while (item?.parentId && item.parentId!==parentId) item = byId.get(item.parentId);
          return item && (parentId==="root" ? !item.parentId : item.parentId===parentId) ? item.id : undefined;
        };
        const projected = new Map<string,{id:string;sources:string[];targets:string[]}>();
        for (const edge of links) {
          const source = directChild(edge.source), target = directChild(edge.target);
          if (!source || !target || source===target || source===edge.source && target===edge.target) continue;
          const key = `${source}\u0000${target}`;
          if (!projected.has(key)) projected.set(key,{id:`layout:${parentId}:${projected.size}`,sources:[source],targets:[target]});
        }
        const input: ElkNode = {id:parentId,layoutOptions:{
          "elk.algorithm":"layered","elk.direction":"RIGHT","elk.edgeRouting":"ORTHOGONAL",
          "elk.spacing.nodeNode":"38","elk.layered.spacing.nodeNodeBetweenLayers":"78",
          "elk.padding":parentId==="root" ? "[top=20,left=20,bottom=20,right=20]" : "[top=56,left=18,bottom=20,right=18]",
        },children:children.map(item=>({id:item.id,width:item.width,height:item.height})),
        edges:[...siblingLinks.map(edge=>({id:edge.id,sources:[edge.source],targets:[edge.target]})),...projected.values()]};
        const result = await sharedElk().layout(input);
        for (const node of result.children || []) positions.set(node.id,{x:node.x || 0,y:node.y || 0});
        for (const edge of result.edges || []) if (!edge.id.startsWith("layout:")) localSections.set(edge.id,{parentId:parentId==="root" ? undefined : parentId,sections:edge.sections || []});
        const parent = byId.get(parentId);
        if (parent) {parent.width=Math.max(parent.width,result.width || 0);parent.height=Math.max(parent.height,result.height || 0);}
      }
      return items;
    };
    arrange().then(positionedItems => {
      if (!live) return;
      const positioned: N[] = [];
      const absolute = (id:string):{x:number;y:number} => {
        const item = byId.get(id);
        const pos = positions.get(id) || {x:0,y:0};
        if (!item?.parentId) return pos;
        const parent = absolute(item.parentId);
        return {x:pos.x+parent.x,y:pos.y+parent.y};
      };
      for (const item of positionedItems) {
        const pos = positions.get(item.id) || {x:0,y:0};
        positioned.push({ id:item.id, type:"networkAsset", parentId:item.parentId, extent:item.parentId ? "parent" : undefined, position:pos, zIndex:item.parentId ? 4 : 2, data:{ item, expanded: item.id === `network:${networkId}` || item.id === `area:${areaId}` || !!item.node && expandedAreas.has(item.node.id), internalResults:internalMatrixGroups.get(item.id), onInspectInternal:setMatrixInspect }, width:item.width,height:item.height,style:{ width:item.width,height:item.height }, sourcePosition:Position.Right,targetPosition:Position.Left, draggable:false });
      }
      const sections = new Map([...localSections].map(([id,route])=>{
        const origin = route.parentId ? absolute(route.parentId) : {x:0,y:0};
        const points = route.sections.map(section=>({...section,startPoint:{x:section.startPoint.x+origin.x,y:section.startPoint.y+origin.y},
          endPoint:{x:section.endPoint.x+origin.x,y:section.endPoint.y+origin.y},
          bendPoints:section.bendPoints?.map(point=>({x:point.x+origin.x,y:point.y+origin.y}))}));
        return [id,points] as const;
      }));
      const drawn: E[] = [...view.edges.map(x=>({id:x.id,source:x.source,target:x.target,type:"networkLink" as const,zIndex:3,
        ariaLabel:`${x.type}, ${x.count} supplied relationships`,data:{count:x.count,type:x.type,uncertain:x.uncertain,showLabel:x.id.startsWith("peering:"),rooted:sections.has(x.id),sections:sections.get(x.id)||[]}}))];
      if (flowEdge) {
        const color = flowEdge.decision === "allowed" ? "#6de1a7" : flowEdge.decision === "blocked" ? "#f07878" : "#dbb778";
        drawn.push({id:flowEdge.id,source:flowEdge.source,target:flowEdge.target,type:"networkLink",zIndex:7,
          markerEnd:{type:MarkerType.ArrowClosed,color,width:22,height:22},ariaLabel:flowEdge.type,
          data:{count:1,type:flowEdge.type,uncertain:flowEdge.decision==="unknown",grouped:flowEdge.grouped,color,showLabel:true,rooted:sections.has(flowEdge.id),sections:sections.get(flowEdge.id)||[]}});
      }
      for (const edge of batchEdges) {
        const color = edge.decision === "allowed" ? "#6de1a7" : edge.decision === "blocked" ? "#f07878" : edge.decision === "mixed" ? "#bca7f5" : "#dbb778";
        drawn.push({id:edge.id,source:edge.source,target:edge.target,type:"networkLink",zIndex:7,
          markerEnd:{type:MarkerType.ArrowClosed,color,width:20,height:20},ariaLabel:`${edge.type}, ${edge.results.length} assessed pairs`,
          data:{count:edge.results.length,type:edge.type,uncertain:edge.decision==="unknown" || edge.decision==="mixed",grouped:edge.grouped,color,showLabel:edge.results.length>1,rooted:sections.has(edge.id),sections:sections.get(edge.id)||[]}});
      }
      for (const edge of matrixEdges) {
        const color = edge.decision === "allowed" ? "#6de1a7" : edge.decision === "blocked" ? "#f07878" : edge.decision === "mixed" ? "#bca7f5" : "#dbb778";
        drawn.push({id:edge.id,source:edge.source,target:edge.target,type:"networkLink",zIndex:6,
          markerEnd:{type:MarkerType.ArrowClosed,color,width:18,height:18},ariaLabel:`${edge.type}, ${edge.results.length} assessed pairs`,
          data:{count:edge.results.length,type:edge.type,uncertain:edge.decision==="unknown" || edge.decision==="mixed",grouped:edge.results.length>1,color,showLabel:true,rooted:sections.has(edge.id),sections:sections.get(edge.id)||[]}});
      }
      setLayout({ nodes: positioned, edges: drawn });
      setLayoutError("");
      requestAnimationFrame(()=>void flow.current?.fitView({padding:0.18,maxZoom:1.1}));
    }).catch(error => { if (live) setLayoutError(error instanceof Error ? error.message : "Layout failed"); });
    return () => { live=false; };
  }, [view, networkId, areaId, expandedAreas, flowEdge, batchEdges, matrixEdges, internalMatrixGroups]);
  function open(item: VisibleItem) {
    if (item.id.startsWith("network:")) { setNetworkId(item.group?.id || ""); setAreaId(""); setSearch(""); setPage(0); }
    else if (item.id.startsWith("area:")) {
      const owner = item.node && model.owner.get(item.node.id);
      if (owner) setNetworkId(owner);
      if (item.aggregate && !demo) { setExpansion(item.node?.id || ""); setAreaId(""); }
      else {
        const id = item.node?.id || "";
        const collapse = areaId === id || expandedAreas.has(id);
        setExpandedAreas(previous => {
          const next = new Set(previous);
          if (collapse) next.delete(id); else next.add(id);
          return next;
        });
        if (!collapse || areaId === id) setAreaId(collapse ? "" : id);
      }
      setSearch("");
      setPage(0);
    }
    else if (item.aggregate && !demo) setExpansion(item.node?.id || "");
    else setInspect(item);
  }
  function showAssessedFlow(result: ConfigurationDecision) {
    batchRun.current += 1;
    setBatchSource("");
    setBatchResults([]);
    setBatchPageResults([]);
    setBatchPending(false);
    const query = result.query && typeof result.query === "object" ? result.query as Record<string, unknown> : {};
    const source = graph.nodes.find(n => n.resource_id === query.source_resource_id && !n.stub && !n.aggregate);
    const target = graph.nodes.find(n => n.resource_id === query.destination_resource_id && !n.stub && !n.aggregate);
    const sourceOwner = source && model.owner.get(source.id);
    const targetOwner = target && model.owner.get(target.id);
    const sourceArea = source && model.area.get(source.id);
    const targetArea = target && model.area.get(target.id);
    setFlowResult(result);
    setProvider(String(source?.provider || target?.provider || currentProvider));
    setNetworkId(sourceOwner && sourceOwner === targetOwner ? sourceOwner : "");
    setAreaId(sourceArea && sourceArea === targetArea ? sourceArea : "");
    setSearch(""); setPage(0); setMode("map"); setConnection(false);
  }
  function clearBatchAssessment() {
    batchRun.current += 1;
    setBatchResults([]);
    setBatchPageResults([]);
    setBatchPending(false);
    setBatchError("");
  }
  async function assessLoadedConnections(offset = 0, selectedSource = batchSource, reset = false) {
    const port = Number(batchPort);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      setBatchError("Destination port must be between 1 and 65535.");
      return;
    }
    const sourcePortText = batchSourcePort.trim();
    const sourcePort = sourcePortText ? Number(sourcePortText) : undefined;
    if (sourcePortText && (!Number.isInteger(sourcePort) || sourcePort! < 1 || sourcePort! > 65535)) {
      setBatchError("Source port must be between 1 and 65535.");
      return;
    }
    const source = graph.nodes.find(node => node.resource_id === selectedSource && !node.stub && !node.aggregate);
    if (!source || source.aggregate || source.stub || !flowEndpointTypes[String(source.provider)]?.includes(kind(source))) {
      setBatchError("Select a collected endpoint as the source.");
      return;
    }
    const eligible = graph.nodes.filter(node => node.id !== source.id && node.provider === source.provider &&
      typeof node.resource_id === "string" && !node.aggregate && !node.stub &&
      flowEndpointTypes[String(node.provider)]?.includes(kind(node)));
    const targets = [...new Map(eligible.map(node => [String(node.resource_id), node])).values()];
    targets.sort((a,b) => String(a.resource_id).localeCompare(String(b.resource_id)));
    if (!targets.length) {
      setBatchError("Load other endpoint resources before assessing connections.");
      return;
    }
    const pageOffset = Math.max(0, Math.min(offset, Math.floor((targets.length-1)/24)*24));
    const run = ++batchRun.current;
    setBatchTotal(targets.length);
    setBatchOffset(pageOffset);
    setBatchPending(true);
    setBatchError("");
    if (reset) setBatchResults([]);
    setBatchPageResults([]);
    setFlowResult(undefined);
    try {
      const destinationIds = targets.slice(pageOffset,pageOffset+24).map(node => String(node.resource_id));
      const response = await request<{snapshot_id: string; results: ConfigurationDecision[]}>(`/scans/${encodeURIComponent(scanId)}/reachability/batch`, json({
        source_resource_id: selectedSource, destination_resource_ids: destinationIds,
        protocol: batchProtocol, destination_port: port, address_family: batchFamily,
        ...(sourcePort !== undefined ? {source_port: sourcePort} : {}),
      }));
      if (run === batchRun.current) {
        const expectedPairs = new Set(destinationIds.map(destination => JSON.stringify([selectedSource,destination])));
        const validated = validatedAssessmentResults(response, String(source.provider), expectedPairs,
          {protocol:batchProtocol,sourcePort,destinationPort:port,addressFamily:batchFamily});
        if (!validated) {
          setBatchError("Assessment response was incomplete or did not match the selected connections.");
          return;
        }
        setBatchPageResults(validated);
        setBatchResults(previous => {
          const accumulated = new Map(previous.map(result => [String((result.query as Record<string, unknown>)?.destination_resource_id), result]));
          for (const result of validated) accumulated.set(String((result.query as Record<string, unknown>)?.destination_resource_id), result);
          return [...accumulated.values()];
        });
      }
    } catch (error) {
      if (run === batchRun.current) setBatchError(error instanceof Error ? error.message : "Connection assessment failed.");
    } finally {
      if (run === batchRun.current) setBatchPending(false);
    }
  }
  const currentGroup = model.groups.find(g=>g.id===networkId);
  const tabGroups = model.groups.filter(g=>g.provider===currentProvider);
  function openContext(n: GraphNode) {
    const area = model.area.get(n.id);
    const owner = model.owner.get(n.id);
    if (owner) setNetworkId(owner);
    if (area) {
      const areaNode = model.byId.get(area);
      if (areaNode?.aggregate && !demo) { setExpansion(areaNode.id); setAreaId(""); }
      else setAreaId(area);
    } else setAreaId("");
    setPage(0);
    setSearch("");
    setMode("map");
    setInspect(undefined);
  }
  return <>
    <div className="section-top"><p>Collected network architecture and explicit relationships from this scan.</p><span className="count-pill">{(graph.projection?.node_count ?? graph.nodes.length).toLocaleString()} resources · {(graph.projection?.edge_count ?? graph.edges.length).toLocaleString()} relationships</span></div>
    <div className="network-legend" aria-label="Network link legend"><span><i className="reference"/> Collected reference</span><span><i className="candidate"/> Candidate link</span><span><i className="allowed"/> Configuration allows</span><span><i className="blocked"/> Configuration blocks</span><span><i className="unknown"/> Configuration unknown</span><span><i className="mixed"/> Mixed assessed pairs</span></div>
    {!demo && matrixPageCount > 1 && <div className="button-row"><button type="button" className="button" disabled={currentMatrixPage===0} onClick={()=>setMatrixPage(currentMatrixPage-1)}>Previous 12 endpoints</button><button type="button" className="button" disabled={currentMatrixPage+1>=matrixPageCount} onClick={()=>setMatrixPage(currentMatrixPage+1)}>Next 12 endpoints</button><label>Compare endpoint window <select aria-label="Compare endpoint window" value={matrixComparePage===null ? "" : String(matrixComparePage)} onChange={event=>setMatrixComparePage(event.target.value==="" ? null : Number(event.target.value))}><option value="">Select another window</option>{Array.from({length:matrixPageCount},(_,index)=>index).filter(index=>index!==currentMatrixPage).map(index=><option key={index} value={index}>Window {index+1}</option>)}</select></label></div>}
    {matrixComparePage !== null && matrixComparePage !== currentMatrixPage && <p className="muted" role="status">Cross-window IPv4 TCP/54321→443: window {currentMatrixPage+1} ↔ window {matrixComparePage+1}{grid.isPending ? " · assessing…" : grid.error ? ` · failed: ${grid.error.message}` : grid.data && !validatedGridResults ? " · response incomplete or mismatched" : validatedGridResults ? ` · ${validatedGridResults.length} directed pairs evaluated` : ""}. Only the named pairs are assessed.</p>}
    {validatedGridResults && validatedGridResults.length > 0 && <details className="network-matrix-results"><summary>Cross-window assessed pairs · {validatedGridResults.length}</summary><div className="network-rule-scroll" role="region" aria-label="Cross-window assessed pairs" tabIndex={0}>{validatedGridResults.map((result,index)=>{const query=result.query as Record<string,unknown>;const source=graph.nodes.find(node=>node.resource_id===query.source_resource_id);const target=graph.nodes.find(node=>node.resource_id===query.destination_resource_id);return <button key={index} type="button" className="text-button" onClick={()=>{setMatrixInspect([result]);}}>{source?label(source):String(query.source_resource_id)} → {target?label(target):String(query.destination_resource_id)} · {result.decision.toUpperCase()}</button>;})}</div></details>}
    {!!matrixEdges.length && <details className="network-matrix-results"><summary>Automatically assessed arrow groups · {matrixEdges.length}</summary><div className="network-rule-scroll" role="region" aria-label="Automatically assessed arrow groups" tabIndex={0}>{matrixEdges.map(edge=><button key={edge.id} type="button" className="text-button" onClick={()=>setMatrixInspect(edge.results)}>{visible.get(edge.source)?.title || edge.source} → {visible.get(edge.target)?.title || edge.target} · {edge.type} · {edge.results.length} pair{edge.results.length===1?"":"s"}</button>)}</div></details>}
    {flowResult && <div className="network-flow-result" role="status"><strong>{flowFamily} {String(flowQuery.protocol || "TCP").toUpperCase()}/{flowQuery.source_port ? `${flowQuery.source_port}→` : ""}{String(flowQuery.destination_port || "?")} · {flowResult.decision.toUpperCase()}</strong><span>{sourceNode ? label(sourceNode) : String(flowQuery.source_resource_id || "Unknown source")} → {targetNode ? label(targetNode) : String(flowQuery.destination_resource_id || "Unknown destination")}</span><button type="button" onClick={()=>setFlowInspect(true)}>Details</button><button type="button" onClick={()=>setFlowResult(undefined)}>Clear path</button>{decisionReason(flowResult) && <small>{decisionReason(flowResult)}</small>}{flowArrowMessage && <small>{flowArrowMessage}</small>}{!flowEdge && (!sourceNode || !targetNode) && !demo && <button type="button" onClick={()=>{if(!inventoryEnabled)setInventoryEnabled(true);else if(pages.hasNextPage)void pages.fetchNextPage();}} disabled={inventoryEnabled && (pages.isFetchingNextPage || pages.isPending || !pages.hasNextPage)}>Load network inventory</button>}</div>}
    {batchSource && <div className="network-batch-panel" role="region" aria-label="Connections from selected resource">
      <strong>Connections from {label(graph.nodes.find(node => node.resource_id === batchSource) || {id:batchSource})}</strong>
      <div className="button-row">
        <button type="button" className="button" onClick={()=>{setProvider(String(batchSourceNode?.provider || currentProvider));setNetworkId("");setAreaId("");setSearch("");setPage(0);setMode("map");}}>Show paths between networks</button>
        {batchSourceNetwork && <button type="button" className="button" onClick={()=>{setProvider(String(batchSourceNode?.provider || currentProvider));setNetworkId(batchSourceNetwork);setAreaId("");setSearch("");setPage(0);setMode("map");}}>Show paths between {batchSourceNode?.provider === "k8s" ? "namespaces" : "subnets"}</button>}
        {batchSourceArea && batchSourceNetwork && <button type="button" className="button" onClick={()=>{setProvider(String(batchSourceNode?.provider || currentProvider));setNetworkId(batchSourceNetwork);setAreaId(batchSourceArea);setSearch("");setPage(0);setMode("map");}}>Show paths within source {batchSourceNode?.provider === "k8s" ? "namespace" : "subnet"}</button>}
      </div>
      <label>Protocol <select value={batchProtocol} disabled={batchPending} onChange={event=>{setBatchProtocol(event.target.value);clearBatchAssessment();}}><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
      <label>Address family <select value={batchFamily} disabled={batchPending} onChange={event=>{setBatchFamily(event.target.value);clearBatchAssessment();}}><option value="ipv4">IPv4</option><option value="ipv6">IPv6</option></select></label>
      <label>Destination port <input type="number" min={1} max={65535} disabled={batchPending} value={batchPort} onChange={event=>{setBatchPort(event.target.value);clearBatchAssessment();}} /></label>
      <label>Source port (optional) <input type="number" min={1} max={65535} disabled={batchPending} value={batchSourcePort} onChange={event=>{setBatchSourcePort(event.target.value);clearBatchAssessment();}} /></label>
      <button type="button" className="button primary" disabled={batchPending} onClick={()=>void assessLoadedConnections(0,batchSource,true)}>{batchPending ? "Assessing…" : "Assess loaded endpoints"}</button>
      <button type="button" className="button" onClick={()=>{batchRun.current+=1;setBatchSource("");setBatchResults([]);setBatchPageResults([]);setBatchError("");setBatchPending(false);}}>Clear connections</button>
      {batchError && <p role="alert">{batchError}</p>}
      {!!batchResults.length && <><p role="status">{batchPageResults.length ? `Loaded endpoints ${batchOffset+1}–${batchOffset+batchPageResults.length} of ${batchTotal}. ` : ""}Assessed {batchResults.length} of {batchTotal}: {batchResults.filter(result=>result.decision==="allowed").length} allowed · {batchResults.filter(result=>result.decision==="blocked").length} blocked · {batchResults.filter(result=>result.decision==="unknown").length} unknown. {batchEdges.length} visible arrow groups; arrows anchored to a network or subnet represent only their listed endpoint pairs.{batchEdges.length < batchResults.length ? " Some assessed pairs share one visible group or are off this page; open the source network or subnet to inspect them." : ""}</p>
        {batchTotal>24 && <div className="button-row"><button type="button" className="button" disabled={batchPending || batchOffset===0} onClick={()=>void assessLoadedConnections(Math.max(0,batchOffset-24))}>Previous 24 endpoints</button><button type="button" className="button" disabled={batchPending || batchOffset+24>=batchTotal} onClick={()=>void assessLoadedConnections(batchOffset+24)}>Next 24 endpoints</button></div>}
        {!!batchPageResults.length && <details><summary>Results for {batchPageResults.length} loaded endpoints on this page</summary><ul>{batchPageResults.map((result,index)=>{const query = result.query && typeof result.query === "object" ? result.query as Record<string, unknown> : {};const target = graph.nodes.find(node=>node.resource_id===query.destination_resource_id);return <li key={index}><button type="button" onClick={()=>showAssessedFlow(result)}>{target ? label(target) : String(query.destination_resource_id)} · {result.decision.toUpperCase()} · show path</button>{decisionReason(result) && <small>{decisionReason(result)}</small>}</li>;})}</ul></details>}</>}
    </div>}
    {graph.projection?.collapsed && <div className="notice" role="status"><p>Server overview groups large inventory. Open a network, expand a projected resource group, or load an inventory page for more evidence. {Number(graph.omitted_underlying_edges || graph.projection.omitted_underlying_edges || 0).toLocaleString()} relationships are outside this view.</p></div>}
    <Panel className="network-architecture">
      <div className="network-toolbar"><div className="network-provider-tabs" role="tablist" aria-label="Collected providers">{model.providers.map(p=><button key={p} role="tab" aria-selected={currentProvider===p} onClick={()=>{batchRun.current+=1;setProvider(p);setNetworkId("");setAreaId("");setFlowResult(undefined);setBatchSource("");setBatchResults([]);setBatchPageResults([]);setPage(0);}}>{providerNames[p] || p}<span>{model.groups.filter(g=>g.provider===p).reduce((sum,g)=>sum+g.count,0)}</span></button>)}</div><div className="search-field"><Search size={17}/><input aria-label="Search loaded network resources" placeholder="Search loaded names, IDs and types…" value={search} onChange={e=>{setSearch(e.target.value);setPage(0);}} /></div><div className="segmented"><button aria-pressed={mode==="map"} onClick={()=>setMode("map")}><Network size={15}/> Map</button><button aria-pressed={mode==="table"} onClick={()=>setMode("table")}><Table2 size={15}/> Table</button></div>{!demo && !!scanId && <button className="button" onClick={()=>setConnection(true)}>Assess configuration path</button>}</div>
      <div className="network-breadcrumb"><button onClick={()=>{setNetworkId("");setAreaId("");setFlowResult(undefined);setPage(0);}}>All {providerNames[currentProvider] || "provider"} networks</button>{currentGroup && <><span>/</span><button onClick={()=>{setAreaId("");setPage(0);}}>{currentGroup.title}</button></>}{areaId && <><span>/</span><strong>{label(model.byId.get(areaId) || {id:areaId})}</strong></>}<button className="network-fit" onClick={()=>void flow.current?.fitView({padding:0.18})}><Focus size={14}/> Fit</button></div>
      {currentGroup && <NetworkHeader group={currentGroup} graph={graph} scanId={scanId} demo={demo} />}
      {!scanId ? <State empty title="Select a scan to explore the network" /> : <State loading={base.isPending} error={base.error} onRetry={()=>void base.refetch()} empty={!!base.data && !model.providers.length} title="No collected network resources" emptyMessage="This assessment did not collect network resources.">{mode==="map" ? <div className="network-canvas" aria-label="Network architecture map">{layoutError ? <State error={new Error(layoutError)} /> : <ReactFlow key={`${scanId}:${currentProvider}:${networkId}:${areaId}:${page}:${layout.nodes.map(node => node.id).join("|")}:${layout.edges.map(edge => edge.id).join("|")}`} nodes={layout.nodes} edges={layout.edges} nodeTypes={nodeTypes} edgeTypes={edgeTypes} onInit={x=>{flow.current=x;requestAnimationFrame(()=>void x.fitView({padding:0.18,maxZoom:1.1,duration:0}));}} nodesDraggable={false} nodesConnectable={false} elementsSelectable onNodeClick={(_,n)=>{const item=visible.get(n.id);if(item?.id.startsWith("network:") || item?.id.startsWith("area:")) open(item);else setInspect(item);}} onEdgeClick={(_,e)=>{if(e.id==="assessed-flow") setFlowInspect(true);else if(e.id.startsWith("assessed-batch:")) setBatchInspect(batchEdges.find(x=>x.id===e.id)?.results);else if(e.id.startsWith("matrix:")) setMatrixInspect(matrixEdges.find(x=>x.id===e.id)?.results);else setInspect(view.edges.find(x=>x.id===e.id));}} minZoom={0.15} maxZoom={1.6} fitView fitViewOptions={{padding:0.18,maxZoom:1.1}} colorMode="dark"><Background color="rgba(166,227,212,.09)" gap={22} size={1}/><Controls showInteractive={false}/></ReactFlow>}{!view.items.length && <div className="network-empty">No matching resources in the loaded evidence.</div>}</div> : <div className="network-table" ref={tableScroll} role="region" aria-label="Network resource table" tabIndex={0}><div style={{height:virtual.getTotalSize(),position:"relative"}}>{virtual.getVirtualItems().map(v=>{const n=view.matching[v.index];const Icon=icons[kind(n)]||HardDrive;return <div key={n.id} className="network-table-row" style={{position:"absolute",top:v.start,height:v.size}}><button className="network-table-main" onClick={()=>setInspect({id:`asset:${n.id}`,title:label(n),subtitle:kind(n),width:194,height:62,count:Number(n.underlying_count||1),hidden:0,kind:kind(n),node:n})}><Icon size={18} aria-label={`${kind(n).replaceAll("_"," ")} icon`}/><strong>{label(n)}</strong><span>{kind(n).replaceAll("_"," ")}</span><span>{stringify(n.scope)}</span>{!observed(n)&&<em>Unresolved</em>}</button>{(model.area.has(n.id)||["subnet","subnetwork","namespace"].includes(kind(n))) && <button className="network-table-open" onClick={()=>openContext(n)}>Open {kind(n)==="namespace" ? "workload group" : "subnet"}</button>}</div>;})}</div></div>}</State>}
      <div className="network-footer"><span>{layout.nodes.length} visible nodes · {view.edges.length} visible edge groups · {view.hiddenNodes.toLocaleString()} resources folded or off page · {view.hiddenEdges.toLocaleString()} relationships internal, off page or omitted{view.visibleEdgeTotal>400 ? ` · ${view.visibleEdgeTotal-400} edge groups omitted by canvas limit` : ""}</span><div className="button-row">{view.pageCount>1 && <><button disabled={!page} onClick={()=>setPage(page-1)}>Previous {view.pageLabel}</button><span>Page {page+1} of {view.pageCount}</span><button disabled={page+1>=view.pageCount} onClick={()=>setPage(page+1)}>Next {view.pageLabel}</button></>}{!demo && <button onClick={()=>{if(!inventoryEnabled)setInventoryEnabled(true);else if(pages.hasNextPage)void pages.fetchNextPage();}} disabled={inventoryEnabled && (pages.isFetchingNextPage || pages.isPending || !pages.hasNextPage)}>{inventoryEnabled && !pages.hasNextPage && !pages.isPending ? "All inventory pages loaded" : "Load inventory page"}</button>}</div></div>
      {(expanded.isPending && expansion || inventoryEnabled && pages.isFetching) && <p role="status" className="network-load">Loading bounded network evidence…</p>}
      {(expanded.error || pages.error) && <p role="alert" className="network-load">Additional network evidence could not be loaded. The current map remains available.</p>}
    </Panel>
    {inspect && <Inspector title={"records" in inspect ? "Observed relationship" : "Network resource"} onClose={()=>setInspect(undefined)}>{"records" in inspect ? <h3>{inspect.type}</h3> : <div className="network-resource-heading"><h3>{inspect.title}</h3><span className="count-pill">{inspect.kind.replaceAll("_", " ")}</span></div>}{"records" in inspect ? <RelationshipDetail edge={view.edges.find(edge => edge.id === inspect.id) || inspect} graph={graph} scanId={scanId} demo={demo} /> : <>{inspect.group && <><p>{inspect.group.count} resources · {inspect.group.unresolvedCount} unresolved references.</p><button className="button primary" onClick={()=>{open(inspect);setInspect(undefined);}}>Open network</button></>}{inspect.id.startsWith("area:") && <button className="button primary" onClick={()=>{open(inspect);setInspect(undefined);}}>{inspect.kind==="namespace"?"Open workloads":"Open subnet"}</button>}{needsNative && native.isPending && <p role="status">Loading collected configuration…</p>}{native.error && <p role="alert">Native configuration could not be loaded; graph identifiers and attachments remain available.</p>}{inspect.node && typeof inspect.node.resource_id === "string" && flowEndpointTypes[String(inspect.node.provider)]?.includes(kind(inspect.node)) && !demo && <div className="button-row"><button className="button" onClick={()=>{setAssessSource(String(inspect.node?.resource_id));setInspect(undefined);setConnection(true);}}>Assess from this resource</button><button className="button" onClick={()=>{setAssessTarget(String(inspect.node?.resource_id));setInspect(undefined);setConnection(true);}}>Assess to this resource</button><button className="button" onClick={()=>{const selectedSource=String(inspect.node?.resource_id);batchRun.current+=1;setBatchSource(selectedSource);setBatchResults([]);setBatchPageResults([]);setBatchError("");setBatchPending(false);setInspect(undefined);void assessLoadedConnections(0,selectedSource);}}>Assess connections from this resource</button></div>}{detailedNode && <ResourceDetail key={detailedNode.id} n={detailedNode} graph={graph} />}{inspect.aggregate && !demo && <button className="button" onClick={()=>{setExpansion(inspect.node?.id||"");setInspect(undefined);}}>Expand supplied resource group</button>}</>}</Inspector>}
    {flowInspect && flowResult && <Inspector title="Assessed configuration path" onClose={()=>setFlowInspect(false)}><h3>{flowResult.decision.toUpperCase()} · {flowFamily} {String(flowQuery.protocol || "TCP").toUpperCase()}/{flowQuery.source_port ? `${flowQuery.source_port}→` : ""}{String(flowQuery.destination_port || "?")}</h3><p>{sourceNode ? label(sourceNode) : String(flowQuery.source_resource_id)} → {targetNode ? label(targetNode) : String(flowQuery.destination_resource_id)}</p><p>Configuration decision from this snapshot. Application listening and actual traffic were not measured.</p><Evidence data={{routes:flowResult.routes,policy_decisions:flowResult.policy_decisions,unresolved_dependencies:flowResult.unresolved_dependencies,evidence_refs:flowResult.evidence_refs}} /></Inspector>}
    {batchInspect && <Inspector title="Assessed configuration paths" onClose={()=>setBatchInspect(undefined)}><h3>{batchInspect.length} selected endpoint pair{batchInspect.length===1?"":"s"}</h3><p>Each result applies only to its named endpoints and ports. Application listening and actual traffic were not measured.</p>{batchInspect.map((result,index)=>{const query=result.query as Record<string,unknown>;const source=graph.nodes.find(node=>node.resource_id===query.source_resource_id);const target=graph.nodes.find(node=>node.resource_id===query.destination_resource_id);return <details key={index} open={batchInspect.length===1}><summary>{source?label(source):String(query.source_resource_id)} → {target?label(target):String(query.destination_resource_id)} · {`${addressFamilyLabel(query.address_family)} ${String(query.protocol).toUpperCase()}/${query.source_port ? `${query.source_port}→` : ""}${String(query.destination_port)}`} · {result.decision.toUpperCase()}</summary><Evidence data={{routes:result.routes,policy_decisions:result.policy_decisions,unresolved_dependencies:result.unresolved_dependencies,evidence_refs:result.evidence_refs}} /></details>;})}</Inspector>}
    {matrixInspect && <Inspector title="Automatically assessed flows" onClose={()=>setMatrixInspect(undefined)}><h3>{matrixInspect.length} directed TCP/54321→443 IPv4 pair{matrixInspect.length===1?"":"s"}</h3><p>Each result applies only to its named endpoints and ports. Application listening and actual traffic were not measured.</p>{matrixInspect.map((result,index)=>{const query=result.query as Record<string,unknown>;const source=graph.nodes.find(node=>node.resource_id===query.source_resource_id);const target=graph.nodes.find(node=>node.resource_id===query.destination_resource_id);return <details key={index}><summary>{source?label(source):String(query.source_resource_id)} → {target?label(target):String(query.destination_resource_id)} · {result.decision.toUpperCase()}</summary><Evidence data={{routes:result.routes,policy_decisions:result.policy_decisions,unresolved_dependencies:result.unresolved_dependencies,evidence_refs:result.evidence_refs}} /></details>;})}</Inspector>}
    {connection && <ConnectionAssessment scanId={scanId} nodes={graph.nodes} source={assessSource} destination={assessTarget} onClose={()=>setConnection(false)} onShowMap={showAssessedFlow} />}
  </>;
}
function NetworkHeader({group,graph,scanId,demo}:{group:Group;graph:Graph;scanId:string;demo:boolean}) {
  const root = group.root;
  const needsNative = !!root?.resource_id && !demo && !(root.evidence && typeof root.evidence === "object" && "native_resource" in root.evidence);
  const native = useApi<Record<string,unknown>>(`/scans/${encodeURIComponent(scanId)}/resources/${encodeURIComponent(String(root?.resource_id || ""))}`, demo, needsNative);
  const detailedRoot = root && native.data ? { ...root, evidence: { ...(typeof root.evidence === "object" ? root.evidence : {}), native_resource: native.data } } : root;
  const scope = String(root?.scope || group.members[0]?.scope || "Unknown");
  const location = detailedRoot ? nativeDetails(detailedRoot).filter(f=>["Account","Project","Subscription","Tenant","Region"].includes(f.name)).map(f=>`${f.name}: ${f.value}`).join(" · ") : `Collection scope: ${scope}`;
  const ownership = group.provider==="gcp" ? graph.edges.filter(e=>(e.type==="shared_vpc_host" || e.type==="shared_vpc_service_project") && [e.source,e.target].some(id=>modelScope(id,graph)===scope)) : [];
  const areaName = group.provider==="k8s"?"namespace workload groups":group.provider==="gcp"?"subnetworks":"subnets";
  return <div className="network-header"><div><span className="eyebrow">{providerNames[group.provider]} {group.provider==="gcp"?"GLOBAL / SHARED VPC CONTEXT":group.provider==="k8s"?"CLUSTER":"NETWORK"}</span><h2>{group.title}</h2><p>{group.provider==="k8s" ? `Cluster: ${group.id.startsWith("cluster:unknown:") ? "Unknown" : group.id.slice("cluster:".length)} · collection scope: ${scope}` : location}</p>{ownership.map(e=><p key={e.id}>Shared VPC {String(e.type).replaceAll("_"," ")}: {label(graph.nodes.find(n=>n.id===e.source)||{id:e.source})} → {label(graph.nodes.find(n=>n.id===e.target)||{id:e.target})}</p>)}{native.error && <p role="alert">Native network configuration could not be loaded. CIDR and other native fields remain unknown. <button className="text-button" onClick={()=>void native.refetch()}>Retry</button></p>}</div><div className="network-header-stats"><span><strong>{needsNative && native.isPending ? "Loading…" : cidrs(detailedRoot||{id:""}).join(", ")||"Unknown"}</strong> CIDR</span><span><strong>{group.areas.length}</strong> {areaName}</span><span><strong>{group.count}</strong> resources</span><span><strong>{group.observedCount} collected · {group.unresolvedCount} unresolved</strong> Coverage in supplied view</span></div></div>;
}
function modelScope(id:string,graph:Graph) { return String(graph.nodes.find(n=>n.id===id)?.scope || ""); }
