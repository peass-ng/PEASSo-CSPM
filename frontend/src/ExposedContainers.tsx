import { useState } from "react";
import { useApi } from "./api";
import { ImagesFindingsTable, type ImageFinding } from "./ImagesFindingsTable";
import { Inspector, Panel, State } from "./ui";
import { SourceFinding } from "./ReportIssue";

export type ContainerExposureRoute = {
  endpoint: string;
  port: number;
  protocol: string;
  container_port: number;
  controls: string[];
  kind: string;
  service?: string;
  rule?: string;
  finding_id: string;
};
type Container = {
  digest: string;
  workload: string;
  scope: string;
  container: string;
  counts: { critical: number; high: number };
  exposure_routes: ContainerExposureRoute[];
};

function Advisories({ source, container, onClose }: { source: string; container: Container; onClose: () => void }) {
  const [offset, setOffset] = useState(0);
  const query = useApi<{ rows: ImageFinding[]; total: number; next_offset: number | null; coverage: "COMPLETE" | "UNKNOWN" }>(
    `/scans/${encodeURIComponent(source)}/image-findings?image_digest=${encodeURIComponent(container.digest)}&offset=${offset}&limit=50`,
    false,
  );
  return <Inspector title={`Image CVEs for ${container.container}`} onClose={onClose}>
    <code>{container.digest}</code>
    <ImagesFindingsTable rows={query.data?.rows || []} total={query.data?.total}
      coverage={query.data?.coverage} loading={query.isPending} error={query.error}
      onRetry={() => void query.refetch()} />
    {offset > 0 && <button type="button" className="text-button" onClick={() => setOffset(Math.max(0, offset - 50))}>Previous CVEs</button>}
    {query.data?.next_offset != null &&
      <button type="button" className="text-button" onClick={() => setOffset(query.data!.next_offset!)}>Next CVEs</button>}
  </Inspector>;
}

export function ExposedContainers({ scanId, sources }: { scanId: string; sources: { id: string; name: string }[] }) {
  const [expanded, setExpanded] = useState(false);
  const [source, setSource] = useState(scanId);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<Container>();
  const [routeFinding, setRouteFinding] = useState<string>();
  const query = useApi<{ items: Container[]; total: number; next_offset: number | null; image_coverage: string; image_findings_present: boolean; workload_evidence_available: boolean }>(
    `/scans/${encodeURIComponent(scanId)}/exposed-containers?image_scan_id=${encodeURIComponent(source)}&offset=${offset}`,
    false, expanded,
  );
  return <Panel className="findings-panel">
    <button type="button" className="text-button" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>
      Exposed containers with CVEs{query.data?.total ? ` (${query.data.total})` : ""}
    </button>
    {expanded && <>
      <label>Image CVE assessment <select value={source} onChange={event => {
        setSource(event.target.value); setOffset(0); setSelected(undefined);
      }}>
        {sources.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
      </select></label>
      <State loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} />
      {query.data && !query.data.items.length && <p>{query.data.image_coverage === "NOT_SCANNED"
        ? "Choose an assessment that scanned container images."
        : !query.data.image_findings_present && query.data.image_coverage === "COMPLETE" ? "No Critical or High image advisories were recorded in that assessment."
        : !query.data.workload_evidence_available ? "This assessment has no matching running workload evidence."
        : "No scanned image digest was linked to a captured internet-facing container route."}</p>}
      {!!query.data?.items.length && <div className="table-scroll"><table className="findings-table">
        <thead><tr><th>Running container</th><th>Captured internet route</th><th>Package advisories</th></tr></thead>
        <tbody>{query.data.items.map(row => <tr key={JSON.stringify([row.scope, row.workload, row.container, row.digest])}>
          <td><strong>{row.container}</strong><div className="small"><code>{row.workload}</code></div>
            <div className="muted small">{row.scope}</div><div className="small"><code>{row.digest}</code></div></td>
          <td><ul className="report-evidence">{row.exposure_routes.map(route => <li key={JSON.stringify(route)}>
            <code>{route.endpoint}:{route.port}</code> · {route.protocol} → container port {route.container_port}
            {route.service && <> · <code>{route.service}</code></>}
            {!!route.controls.length && <div className="small">{route.controls.join(" · ")}</div>}
            <button type="button" className="text-button" onClick={() => setRouteFinding(route.finding_id)}>View route evidence</button>
          </li>)}</ul></td>
          <td>{row.counts.critical > 0 && <span className="badge critical">{row.counts.critical} critical</span>}
            {row.counts.high > 0 && <span className="badge high">{row.counts.high} high</span>}
            <div><button type="button" className="text-button" onClick={() => setSelected(row)}>View CVEs</button></div>
          </td>
        </tr>)}</tbody>
      </table></div>}
      {offset > 0 && <button type="button" className="text-button" onClick={() => setOffset(Math.max(0, offset - 20))}>Previous containers</button>}
      {query.data?.next_offset != null &&
        <button type="button" className="text-button" onClick={() => setOffset(query.data!.next_offset!)}>Next containers</button>}
    </>}
    {routeFinding && <SourceFinding scanId={scanId} id={routeFinding} onClose={() => setRouteFinding(undefined)} onInspect={setRouteFinding} />}
    {selected && <Advisories key={selected.digest} source={source} container={selected} onClose={() => setSelected(undefined)} />}
  </Panel>;
}
