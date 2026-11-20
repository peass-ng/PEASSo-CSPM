import { useEffect, useRef, useState } from "react";
import { request, useApi } from "./api";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge, Inspector, Panel, State } from "./ui";
import { NetworkArchitecture } from "./NetworkArchitecture";
import { CombineReportsModal, CombinedReports } from "./CombinedReports";
import { IssueBody, SourceFinding, issueKinds as kinds } from "./ReportIssue";
import type { Issue, Reference } from "./ReportIssue";

type Report = { can_launch?: boolean; generation?: string; status: string; summary?: string; issues: Issue[]; limitations?: string[]; exclusions?: { reference: Reference; reason: string }[]; total: number; exclusion_count?: number; source_count?: number; covered_count?: number };
const labels = { findings: "Check result", least_privilege: "Least privilege", privesc_edges: "Privilege escalation path", actions: "Top action" };
const pages = { findings: "Hardening & Compliance", least_privilege: "Least Privilege", privesc_edges: "Privilege Escalation Map", actions: "Top 15 Actions" };
function AssessmentReport({ scanId, demo, canLaunch = true }: { scanId: string; demo: boolean; canLaunch?: boolean }) {
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(0);
  const [exclusionPage, setExclusionPage] = useState(0);
  const [selected, setSelected] = useState<Issue>();
  const [source, setSource] = useState<string>();
  const [confirmGeneration, setConfirmGeneration] = useState(false);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const query = useApi<Report>(`/scans/${encodeURIComponent(scanId)}/findings-report?offset=${page * 25}&limit=25&search=${encodeURIComponent(search)}&severity=${severity}&exclusion_offset=${exclusionPage * 25}`, demo, !!scanId && !demo, true);
  const launch = useMutation({
    mutationFn: () => request(`/scans/${encodeURIComponent(scanId)}/findings-report`, { method: "POST" }),
    onSuccess: () => {
      setSelected(undefined); setSource(undefined); setPage(0); setExclusionPage(0);
      client.setQueriesData<Report>({ predicate: query => query.queryKey.some(part => typeof part === "string" && part.startsWith(`/scans/${encodeURIComponent(scanId)}/findings-report?`)) },
        old => old ? { ...old, status: "in_progress", issues: [], exclusions: [], total: 0, can_launch: false } : old);
      void client.invalidateQueries({ predicate: query => query.queryKey.some(part => typeof part === "string" &&
        (part.startsWith(`/scans/${encodeURIComponent(scanId)}/findings-report?`) || part.startsWith(`/scans/${encodeURIComponent(scanId)}/ai?`))) });
    },
  });
  useEffect(() => {
    void client.invalidateQueries({ predicate: query => query.queryKey.some(part => typeof part === "string" && part.startsWith(`/scans/${encodeURIComponent(scanId)}/ai?`)) });
  }, [client, scanId, query.data?.status, query.data?.generation]);
  if (demo) return <Panel title="Findings Report"><p>Run a scan with AI enabled to compile a findings report.</p></Panel>;
  if (!scanId) return <Panel title="Findings Report"><p>Select an assessment with results.</p></Panel>;
  if (query.isPending || query.error) return <State loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} />;
  const report = query.data;
  if (!report) return null;
  const close = () => { setSelected(undefined); requestAnimationFrame(() => trigger.current?.focus()); };
  return <div className="ai-review-view">
    <Panel title="Findings Report">
      <div className="button-row"><button className="button primary" disabled={!canLaunch || report.can_launch === false || launch.isPending || report.status === "in_progress"} onClick={() => setConfirmGeneration(true)}>
        {launch.isPending || report.status === "in_progress" ? "Generating report…" : report.issues.length ? "Regenerate report" : "Generate report"}
      </button><span>Generating a report replaces all current report issues.</span></div>
      {launch.error && <p role="alert">{launch.error.message}</p>}
      {report.status === "in_progress" ? <p role="status">The findings report will be compiled after the scan analyses finish.</p> :
        report.status === "not_available" ? <p>This scan has no compiled report. Run a new scan with AI enabled.</p> :
        report.status === "unavailable" ? <p>The report could not be completed. The scan findings are still available.</p> : null}
      {report.status === "partial" && <p>Pre-generated findings are available. Compilation of remaining issues is incomplete.</p>}
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
    {confirmGeneration && <Inspector title="Generate a new Findings Report?" className="combine-report-modal report-confirmation-modal" onClose={() => setConfirmGeneration(false)}>
      <p>This will delete the current compiled findings and generate a new report from this assessment. Do you want to continue?</p>
      <div className="button-row"><button className="button" onClick={() => setConfirmGeneration(false)}>Cancel</button>
        <button className="button danger" disabled={launch.isPending || !canLaunch || report.can_launch === false} onClick={() => { setConfirmGeneration(false); launch.mutate(); }}>Delete and generate</button>
      </div>
    </Inspector>}
    {selected && <Inspector title={selected.title} onClose={close}>
      <IssueBody issue={selected} />
      <h3>Supporting evidence</h3><ul>{selected.references.map(ref => <li key={ref.domain + ref.id}>{ref.domain === "findings" ? <button className="text-button" onClick={() => setSource(ref.id)}>{labels[ref.domain]} {ref.id}</button> : <a href={`#${encodeURIComponent(pages[ref.domain])}`}>{labels[ref.domain]} {ref.id}</a>}</li>)}</ul>
    </Inspector>}
    {source && <SourceFinding scanId={scanId} id={source} onInspect={setSource} onClose={() => setSource(undefined)} />}
  </div>;
}

export function FindingsReport({ scanId, demo, canLaunch = true, canCombine = true, onSelectAssessment }: {
  scanId: string; demo: boolean; canLaunch?: boolean; canCombine?: boolean; onSelectAssessment?: (id: string) => void;
}) {
  const [tab, setTab] = useState("assessment");
  const [combine, setCombine] = useState(false);
  const [combinedId, setCombinedId] = useState("");
  const [showAll, setShowAll] = useState(false);
  return <>
    <div className="button-row report-tabs"><div className="segmented" role="tablist" aria-label="Report views">
      <button role="tab" aria-selected={tab === "assessment"} onClick={() => setTab("assessment")}>Assessment report</button>
      <button role="tab" aria-selected={tab === "combined"} onClick={() => setTab("combined")}>Combined reports</button>
    </div><button className="button" disabled={demo || !canCombine} onClick={() => setCombine(true)}>Combine different reports</button></div>
    {tab === "assessment" ? <AssessmentReport scanId={scanId} demo={demo} canLaunch={canLaunch} /> : demo ? <Panel title="Combined reports"><p>Sign in to combine completed assessment reports.</p></Panel> :
      <CombinedReports key={combinedId} scanId={scanId} selectedId={combinedId} onSelect={setCombinedId} showAll={showAll} onShowAll={setShowAll} onSelectAssessment={onSelectAssessment ? id => { setTab("assessment"); onSelectAssessment(id); } : undefined} />}
    {combine && <CombineReportsModal scanId={scanId} onClose={() => setCombine(false)} onCreated={id => { setCombine(false); setCombinedId(id); setShowAll(true); setTab("combined"); }} />}
  </>;
}
