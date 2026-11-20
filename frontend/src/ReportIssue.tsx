import { useState } from "react";
import { useQueries } from "@tanstack/react-query";
import { request, useApi } from "./api";
import { FindingInspector } from "./Findings";
import { Badge, Inspector, State } from "./ui";
import { NetworkArchitecture } from "./NetworkArchitecture";
import type { Finding } from "./types";
export type Reference = { domain: "findings" | "least_privilege" | "privesc_edges" | "actions"; id: string };
type SpecialDetail = {
  asset?: string; scope?: string; digest?: string; counts?: Record<string, number>;
  label?: string; locations?: string[]; detectors?: string[]; finding_ids: string[];
  report_id?: string; issue_id?: string;
};
type PermissionRecommendation = {
  principal: string; kind: "permission" | "service" | "role"; value: string;
  source: string; scope: string; policy?: string; replacement?: string[];
  last_accessed?: string; last_refreshed?: string; usage_window_end?: string; usage_window_days?: number;
  confidence: "provider_recommendation" | "tracked_without_observed_use";
};
export type Issue = { id: string; title: string; kind: string; severity: string; status: string; description: string; impact: string; recommendation: string; verification: string; affected_assets?: string[]; manual_affected_assets?: string[]; special_details?: SpecialDetail[]; permission_recommendations?: PermissionRecommendation[]; references: Reference[] };
export const issueKinds: Record<string, string> = { vulnerability: "Security issue", hardening: "Hardening suggestion", leaks: "Leaks", image_cves: "Image CVEs" };
export function SourceFinding({ scanId, id, onClose, onInspect }: { scanId: string; id: string; onClose: () => void; onInspect: (id: string) => void }) {
  const query = useApi<Finding>(`/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(id)}`, false);
  if (!query.data) return <Inspector title="Supporting finding" onClose={onClose}><State loading={query.isPending} error={query.error} /></Inspector>;
  return <FindingInspector finding={query.data} scanId={scanId} lazy={false} onInspectMember={finding => onInspect(finding.id)} onClose={onClose} demo={false} />;
}
function AffectedAssets({ assets, title }: { assets: string[]; title: string }) {
  const [expanded, setExpanded] = useState(false);
  return <><h3>{title}</h3><ul className="report-evidence">{(expanded ? assets : assets.slice(0, 3)).map(asset => <li key={asset}><code>{asset}</code></li>)}</ul>
    {assets.length > 3 && <button className="text-button" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>
      {expanded ? "Show fewer assets" : `Show ${assets.length - 3} more assets`}
    </button>}</>;
}

function SpecialDetails({ rows, onInspect }: {
  rows: SpecialDetail[]; onInspect?: (row: SpecialDetail) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? rows : rows.slice(0, 5);
  const images = rows[0].counts !== undefined;
  return <>
    <h4>{images ? "Severity by resource and image" : "Detected leaks and locations"}</h4>
    {images ? <div className="table-scroll"><table className="findings-table">
      <thead><tr><th>Resource and image</th><th>Critical</th><th>High</th><th>Medium</th></tr></thead>
      <tbody>{visible.map((row, index) => <tr key={index}>
        <td><code>{row.asset || row.digest || row.scope}</code>
          {!!row.scope && <div className="muted small">{row.scope}</div>}
          {!!row.digest && row.digest !== row.asset && <div className="muted small"><code>{row.digest}</code></div>}
        </td>
        {["critical", "high", "medium"].map(level => {
          const count = row.counts?.[level];
          return <td key={level} aria-label={count === 0 ? "None found" : count === undefined ? "Count unavailable" : undefined}>
            {count === 0 ? "" : count ?? "—"}
          </td>;
        })}
      </tr>)}</tbody>
    </table></div> : <ul className="report-evidence">{visible.map((row, index) => <li key={index}>
      <strong>{row.label}</strong>{!!row.detectors?.length && <> · {row.detectors.join(", ")}</>}
      <div>{row.locations?.[0] || "Location unavailable in the captured evidence"}</div>
      {onInspect && !!row.finding_ids.length && <button type="button" className="text-button" onClick={() => onInspect(row)}>View retained value and evidence</button>}
    </li>)}</ul>}
    {rows.length > 5 && <button type="button" className="text-button" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>
      {expanded ? "Show fewer entries" : `Show ${rows.length - 5} more entries`}
    </button>}
  </>;
}

function PermissionRecommendations({ items }: { items: PermissionRecommendation[] }) {
  const [limit, setLimit] = useState(5);
  return <><h4>Access to review for removal</h4>
    <p>Confirm workload and emergency access needs before changing a grant.</p>
    <div className="table-scroll"><table className="findings-table">
      <thead><tr><th>Principal and scope</th><th>Access</th><th>Usage evidence</th></tr></thead>
      <tbody>{items.slice(0, limit).map((item, index) => <tr key={index}>
        <td><code>{item.principal}</code><div className="muted small">{item.scope}</div></td>
        <td><code>{item.value}</code>{item.policy && <div className="muted small">{item.policy}</div>}
          {!!item.replacement?.length && <div>Replace with {item.replacement.join(", ")}</div>}</td>
        <td>{item.confidence === "tracked_without_observed_use" ? "No use observed for this tracked action" : "Provider recommendation"}
          <div className="muted small">{item.source}</div>
          {item.last_accessed && <div>Last accessed {item.last_accessed}</div>}
          {item.last_refreshed && <div>Refreshed {item.last_refreshed}</div>}
          {item.usage_window_days && <div>{item.usage_window_days}-day observation window</div>}
          {item.usage_window_end && <div>Report completed {item.usage_window_end}</div>}</td>
      </tr>)}</tbody>
    </table></div>
    {items.length > 5 && <button type="button" className="text-button" aria-expanded={limit > 5}
      onClick={() => setLimit(limit < items.length ? limit + 25 : 5)}>
      {limit < items.length ? `Show ${Math.min(items.length - limit, 25)} more` : "Show fewer"}
    </button>}</>;
}

export function IssueBody({ issue, onInspectDetails }: { issue: Omit<Issue, "references">; onInspectDetails?: (row: SpecialDetail) => void }) {
  return <><Badge value={issue.severity} /><p>{issue.status === "confirmed" ? "Confirmed configuration" : "Needs review"} · {issueKinds[issue.kind] || issue.kind}</p>
    <h3>Description and affected scope</h3><NetworkArchitecture label="Issue description" markdown text={issue.description} />
    {!!issue.special_details?.length && <SpecialDetails rows={issue.special_details} onInspect={onInspectDetails} />}
    {!!issue.affected_assets?.length && <AffectedAssets title="Affected assets" assets={issue.affected_assets} />}
    {!!issue.manual_affected_assets?.length && <AffectedAssets title="Agent-added affected assets" assets={issue.manual_affected_assets} />}
    <h3>Impact</h3><NetworkArchitecture label="Issue impact" markdown text={issue.impact} />
    <h3>Recommendation</h3><NetworkArchitecture label="Issue recommendation" markdown text={issue.recommendation} />
    {!!issue.permission_recommendations?.length && <PermissionRecommendations items={issue.permission_recommendations} />}
    <h3>Verification</h3><NetworkArchitecture label="Issue verification" markdown text={issue.verification} /></>;
}


function evidenceIdentifier(ref: Reference) {
  const arn = ref.id.indexOf("arn:");
  return arn >= 0 ? ref.id.slice(arn).replace(/:\d{12}$/, "") : ref.id;
}
export function SupportingEvidence({ scanId, references, onInspect, available = true }: {
  scanId: string; references: Reference[]; onInspect: (id: string) => void; available?: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? references : references.slice(0, 3);
  const batches: string[][] = [];
  for (const id of [...new Set(visible.filter(ref => ref.domain === "findings").map(ref => ref.id))]) {
    const last = batches[batches.length - 1];
    if (!last || last.length >= 20 || encodeURIComponent([...last, id].join("")).length > 4000) batches.push([id]);
    else last.push(id);
  }
  const labels = useQueries({ queries: batches.map(ids => ({
    queryKey: ["report-evidence-labels", scanId, ...ids],
    queryFn: () => request(`/scans/${encodeURIComponent(scanId)}/findings-report/evidence?${ids.map(id => `finding_id=${encodeURIComponent(id)}`).join("&")}`) as Promise<{ items: Record<string, string> }>,
    enabled: available, staleTime: Infinity, retry: false,
  })) });
  const names = Object.assign({}, ...labels.map(query => query.data?.items || {})) as Record<string, string>;
  const sections = { least_privilege: "Least Privilege", privesc_edges: "Privilege Escalation Map", actions: "Top 15 Actions" };
  return <><ul className="report-evidence">{visible.map(ref => <li key={ref.domain + ref.id}>
    {ref.domain === "findings" && available ? <button className="text-button" onClick={() => onInspect(ref.id)}>{names[ref.id] || evidenceIdentifier(ref)}</button> :
      ref.domain !== "findings" && available ? <a href={`#${encodeURIComponent(sections[ref.domain])}`}>{evidenceIdentifier(ref)}</a> : evidenceIdentifier(ref)}
  </li>)}</ul>{references.length > 3 && <button className="text-button" aria-expanded={expanded} onClick={() => setExpanded(!expanded)}>
    {expanded ? "Show fewer evidence links" : `Show ${references.length - 3} more evidence links`}
  </button>}</>;
}
