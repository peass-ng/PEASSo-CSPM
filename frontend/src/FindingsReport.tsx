import { useRef, useState } from "react";
import { useApi } from "./api";
import { FindingInspector } from "./Findings";
import { Badge, Inspector, Panel, State } from "./ui";
import { NetworkArchitecture } from "./NetworkArchitecture";
import type { Finding } from "./types";

type Reference = { domain: "findings" | "least_privilege" | "privesc_edges" | "actions"; id: string };
type Issue = { id: string; title: string; kind: string; severity: string; status: string; description: string; impact: string; recommendation: string; verification: string; references: Reference[] };
type Report = { status: string; summary?: string; issues: Issue[]; limitations?: string[]; exclusions?: { reference: Reference; reason: string }[]; total: number; exclusion_count?: number; source_count?: number; covered_count?: number };
const labels = { findings: "Check result", least_privilege: "Least privilege", privesc_edges: "Privilege escalation path", actions: "Top action" };
const kinds: Record<string, string> = { vulnerability: "Security issue", hardening: "Hardening suggestion", leaks: "Leaks", image_cves: "Image CVEs" };
const pages = { findings: "Hardening & Compliance", least_privilege: "Least Privilege", privesc_edges: "Privilege Escalation Map", actions: "Top 15 Actions" };
function SourceFinding({ scanId, id, onClose, onInspect }: { scanId: string; id: string; onClose: () => void; onInspect: (id: string) => void }) {
  const query = useApi<Finding>(`/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(id)}`, false);
  if (!query.data) return <Inspector title="Supporting finding" onClose={onClose}><State loading={query.isPending} error={query.error} /></Inspector>;
  return <FindingInspector finding={query.data} scanId={scanId} lazy={false} onInspectMember={finding => onInspect(finding.id)} onClose={onClose} demo={false} />;
}
export function FindingsReport({ scanId, demo }: { scanId: string; demo: boolean }) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(0);
  const [exclusionPage, setExclusionPage] = useState(0);
  const [selected, setSelected] = useState<Issue>();
  const [source, setSource] = useState<string>();
  const trigger = useRef<HTMLButtonElement | null>(null);
  const query = useApi<Report>(`/scans/${encodeURIComponent(scanId)}/findings-report?offset=${page * 25}&limit=25&search=${encodeURIComponent(search)}&severity=${severity}&exclusion_offset=${exclusionPage * 25}`, demo, !!scanId && !demo);
  if (demo) return <Panel title="Findings Report"><p>Run a scan with AI enabled to compile a findings report.</p></Panel>;
  if (!scanId) return <Panel title="Findings Report"><p>Select an assessment with results.</p></Panel>;
  if (query.isPending || query.error) return <State loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} />;
  const report = query.data;
  if (!report) return null;
  const close = () => { setSelected(undefined); requestAnimationFrame(() => trigger.current?.focus()); };
  return <div className="ai-review-view">
    <Panel title="Findings Report">
      {report.status === "in_progress" ? <p role="status">The findings report will be compiled after the scan analyses finish.</p> :
        report.status === "not_available" ? <p>This scan has no compiled report. Run a new scan with AI enabled.</p> :
        report.status === "unavailable" ? <p>The report could not be completed. The scan findings are still available.</p> : null}
      {report.summary && <NetworkArchitecture label="Report summary" text={report.summary} />}
      {!!report.limitations?.length && <details><summary>Limitations ({report.limitations.length})</summary><ul>{report.limitations.map((text, i) => <li key={i}>{text}</li>)}</ul></details>}
      {report.status === "completed" && <details><summary>Evidence coverage</summary><p>{report.covered_count} assessed evidence sources · {report.exclusion_count} documented exclusions</p></details>}
    </Panel>
    <Panel>
      <div className="filters"><input aria-label="Search report issues" placeholder="Search report issues…" value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} />
        <select aria-label="Report issue severity" value={severity} onChange={event => { setSeverity(event.target.value); setPage(0); }}><option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map(s => <option key={s}>{s}</option>)}</select>
        <span className="count-pill">{report.total} issues</span></div>
      <div className="table-scroll"><table className="findings-table"><thead><tr><th>Severity</th><th>Issue</th><th>Type</th><th>Assessment</th><th>Sources</th></tr></thead>
        <tbody>{report.issues.map(issue => <tr key={issue.id}><td><Badge value={issue.severity} /></td><td><button className="finding-title" onClick={event => { trigger.current = event.currentTarget; setSelected(issue); }}>{issue.title}</button></td><td>{kinds[issue.kind] || issue.kind}</td><td>{issue.status === "confirmed" ? "Confirmed configuration" : "Needs review"}</td><td>{issue.references.length}</td></tr>)}
          {!report.issues.length && <tr><td colSpan={5}>{report.status === "completed" ? "No issues match the selected filters." : "No compiled issues are available yet."}</td></tr>}</tbody></table></div>
      {report.total > 25 && <div className="service-page-controls"><button disabled={page === 0} onClick={() => setPage(page - 1)}>Previous page</button><span>{page * 25 + 1}–{Math.min((page + 1) * 25, report.total)} of {report.total}</span><button disabled={(page + 1) * 25 >= report.total} onClick={() => setPage(page + 1)}>Next page</button></div>}
    </Panel>
    {!!report.exclusion_count && <Panel><details><summary>Excluded observations ({report.exclusion_count})</summary><p>Each exclusion records why an observation was not raised as an issue.</p><ul>{report.exclusions?.map((row, i) => <li key={i}>{labels[row.reference.domain]} {row.reference.id}: {row.reason}</li>)}</ul><div className="service-page-controls"><button disabled={exclusionPage === 0} onClick={() => setExclusionPage(exclusionPage - 1)}>Previous exclusions</button><button disabled={(exclusionPage + 1) * 25 >= (report.exclusion_count || 0)} onClick={() => setExclusionPage(exclusionPage + 1)}>Next exclusions</button></div></details></Panel>}
    {selected && <Inspector title={selected.title} onClose={close}>
      <Badge value={selected.severity} /><p>{selected.status === "confirmed" ? "Confirmed configuration" : "Needs review"} · {kinds[selected.kind] || selected.kind}</p>
      <h3>Description and affected scope</h3><NetworkArchitecture label="Issue description" text={selected.description} />
      <h3>Impact</h3><NetworkArchitecture label="Issue impact" text={selected.impact} />
      <h3>Recommendation</h3><NetworkArchitecture label="Issue recommendation" text={selected.recommendation} />
      <h3>Verification</h3><NetworkArchitecture label="Issue verification" text={selected.verification} />
      <h3>Supporting evidence</h3><ul>{selected.references.map(ref => <li key={ref.domain + ref.id}>{ref.domain === "findings" ? <button className="text-button" onClick={() => setSource(ref.id)}>{labels[ref.domain]} {ref.id}</button> : <a href={`#${encodeURIComponent(pages[ref.domain])}`}>{labels[ref.domain]} {ref.id}</a>}</li>)}</ul>
    </Inspector>}
    {source && <SourceFinding scanId={scanId} id={source} onInspect={setSource} onClose={() => setSource(undefined)} />}
  </div>;
}
