import { useState } from "react";
import { useQueries } from "@tanstack/react-query";
import { request, useApi } from "./api";
import { FindingInspector } from "./Findings";
import { Badge, Inspector, State } from "./ui";
import { NetworkArchitecture } from "./NetworkArchitecture";
import type { Finding } from "./types";
export type Reference = { domain: "findings" | "least_privilege" | "privesc_edges" | "actions"; id: string };
export type Issue = { id: string; title: string; kind: string; severity: string; status: string; description: string; impact: string; recommendation: string; verification: string; affected_assets?: string[]; manual_affected_assets?: string[]; references: Reference[] };
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

export function IssueBody({ issue }: { issue: Omit<Issue, "references"> }) {
  return <><Badge value={issue.severity} /><p>{issue.status === "confirmed" ? "Confirmed configuration" : "Needs review"} · {issueKinds[issue.kind] || issue.kind}</p>
    <h3>Description and affected scope</h3><NetworkArchitecture label="Issue description" markdown text={issue.description} />
    {!!issue.affected_assets?.length && <AffectedAssets title="Affected assets" assets={issue.affected_assets} />}
    {!!issue.manual_affected_assets?.length && <AffectedAssets title="Agent-added affected assets" assets={issue.manual_affected_assets} />}
    <h3>Impact</h3><NetworkArchitecture label="Issue impact" markdown text={issue.impact} />
    <h3>Recommendation</h3><NetworkArchitecture label="Issue recommendation" markdown text={issue.recommendation} />
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
