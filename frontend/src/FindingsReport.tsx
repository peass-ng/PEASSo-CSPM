import { useEffect, useRef, useState } from "react";
import { request, useApi } from "./api";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Badge, Inspector, Panel, State } from "./ui";
import { CombineReportsModal, CombinedReports } from "./CombinedReports";
import { IssueBody, SourceFinding, SupportingEvidence, issueKinds as kinds } from "./ReportIssue";
import type { Issue, Reference } from "./ReportIssue";

type Report = { can_launch?: boolean; generation?: string; run_status?: string; status: string; summary?: string; issues: Issue[]; limitations?: string[]; exclusions?: { reference: Reference; reason: string }[]; total: number; exclusion_count?: number; source_count?: number; covered_count?: number };
function AssessmentReport({ scanId, demo }: { scanId: string; demo: boolean }) {
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Issue>();
  const [source, setSource] = useState<string>();
  const trigger = useRef<HTMLButtonElement | null>(null);
  const query = useApi<Report>(`/scans/${encodeURIComponent(scanId)}/findings-report?offset=${page * 25}&limit=25&search=${encodeURIComponent(search)}&severity=${severity}`, demo, !!scanId && !demo, true);
  useEffect(() => {
    if (!query.data) return;
    setSelected(undefined); setSource(undefined);
    if (query.data.status === "in_progress") setPage(0);
    void client.invalidateQueries({ predicate: query => query.queryKey.some(part => typeof part === "string" && part.startsWith(`/scans/${encodeURIComponent(scanId)}/ai?`)) });
  }, [client, scanId, query.data?.status, query.data?.generation]);
  if (demo) return <Panel title="Findings Report"><p>Run a scan with AI enabled to compile a findings report.</p></Panel>;
  if (!scanId) return <Panel title="Findings Report"><p>Select an assessment with results.</p></Panel>;
  if (query.isPending || query.error) return <State loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} />;
  const report = query.data;
  if (!report) return null;
  const close = () => { setSelected(undefined); requestAnimationFrame(() => trigger.current?.focus()); };
  return <div className="ai-review-view">
    <Panel>
      {(report.status === "unavailable" || report.run_status === "failed") && <p role="alert">Report generation failed. Generate the report again to retry.</p>}
      <div className="filters"><input aria-label="Search report issues" placeholder="Search report issues…" value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} />
        <select aria-label="Report issue severity" value={severity} onChange={event => { setSeverity(event.target.value); setPage(0); }}><option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map(s => <option key={s}>{s}</option>)}</select>
        <span className="count-pill">{report.total} issues</span></div>
      <div className="table-scroll"><table className="findings-table"><thead><tr><th>Severity</th><th>Issue</th><th>Type</th><th>Assessment</th><th>Sources</th></tr></thead>
        <tbody>{report.issues.map(issue => <tr key={issue.id}><td><Badge value={issue.severity} /></td><td><button className="finding-title" onClick={event => { trigger.current = event.currentTarget; setSelected(issue); }}>{issue.title}</button></td><td>{kinds[issue.kind] || issue.kind}</td><td>{issue.status === "confirmed" ? "Confirmed configuration" : "Needs review"}</td><td>{issue.references.length}</td></tr>)}
          {!report.issues.length && <tr><td colSpan={5}>{report.status === "completed" ? "No issues match the selected filters." : "No compiled issues are available yet."}</td></tr>}</tbody></table></div>
      {report.total > 25 && <div className="service-page-controls"><button disabled={page === 0} onClick={() => setPage(page - 1)}>Previous page</button><span>{page * 25 + 1}–{Math.min((page + 1) * 25, report.total)} of {report.total}</span><button disabled={(page + 1) * 25 >= report.total} onClick={() => setPage(page + 1)}>Next page</button></div>}
    </Panel>
    {selected && <Inspector title={selected.title} onClose={close}>
      <IssueBody issue={selected} />
      <h3>Supporting evidence</h3><SupportingEvidence key={selected.id} scanId={scanId} references={selected.references} onInspect={setSource} />
    </Inspector>}
    {source && <SourceFinding scanId={scanId} id={source} onInspect={setSource} onClose={() => setSource(undefined)} />}
  </div>;
}

function GenerateReport({ scanId, demo, canLaunch }: { scanId: string; demo: boolean; canLaunch: boolean }) {
  const client = useQueryClient();
  const [confirmGeneration, setConfirmGeneration] = useState(false);
  const query = useApi<Report>(`/scans/${encodeURIComponent(scanId)}/findings-report?offset=0&limit=1`, demo, !!scanId && !demo, true);
  const launch = useMutation({
    mutationFn: () => request(`/scans/${encodeURIComponent(scanId)}/findings-report`, { method: "POST" }),
    onSuccess: () => {
      client.setQueriesData<Report>({ predicate: query => query.queryKey.some(part => typeof part === "string" && part.startsWith(`/scans/${encodeURIComponent(scanId)}/findings-report?`)) },
        old => old ? { ...old, run_status: "queued", can_launch: false } : old);
      void client.invalidateQueries({ predicate: query => query.queryKey.some(part => typeof part === "string" &&
        (part.startsWith(`/scans/${encodeURIComponent(scanId)}/findings-report?`) || part.startsWith(`/scans/${encodeURIComponent(scanId)}/ai?`))) });
    },
  });
  const report = query.data;
  const running = launch.isPending || report?.status === "in_progress" || report?.run_status === "queued" || report?.run_status === "running";
  const disabled = demo || !scanId || !canLaunch || !report || report.can_launch === false || running;
  const exists = report?.status === "completed" || report?.status === "partial" || !!report?.total;
  useEffect(() => { setConfirmGeneration(false); }, [scanId]);
  return <>
    <button className="button primary" disabled={disabled} aria-busy={running} onClick={() => setConfirmGeneration(true)}>
      {running ? "Generating report…" : exists ? "Regenerate report" : "Generate report"}
    </button>
    {launch.error && <span role="alert">{launch.error.message}</span>}
    {confirmGeneration && <Inspector title="Generate a new Findings Report?" className="combine-report-modal report-confirmation-modal" onClose={() => setConfirmGeneration(false)}>
      <p>{exists ? "The agent will review and update the current findings. The current report stays available until the update is complete." : "Generate a report from this assessment?"}</p>
      <div className="button-row"><button className="button" onClick={() => setConfirmGeneration(false)}>Cancel</button>
        <button className="button primary" disabled={launch.isPending || !canLaunch || report?.can_launch === false} onClick={() => { setConfirmGeneration(false); launch.mutate(); }}>{exists ? "Update report" : "Generate report"}</button>
      </div>
    </Inspector>}
  </>;
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
    </div><GenerateReport key={scanId} scanId={scanId} demo={demo} canLaunch={canLaunch} /><button className="button" disabled={demo || !canCombine} onClick={() => setCombine(true)}>Combine different reports</button></div>
    {tab === "assessment" ? <AssessmentReport key={scanId} scanId={scanId} demo={demo} /> : demo ? <Panel title="Combined reports"><p>Sign in to combine completed assessment reports.</p></Panel> :
      <CombinedReports key={combinedId} scanId={scanId} selectedId={combinedId} onSelect={setCombinedId} showAll={showAll} onShowAll={setShowAll} onSelectAssessment={onSelectAssessment ? id => { setTab("assessment"); onSelectAssessment(id); } : undefined} />}
    {combine && <CombineReportsModal scanId={scanId} onClose={() => setCombine(false)} onCreated={id => { setCombine(false); setCombinedId(id); setShowAll(true); setTab("combined"); }} />}
  </>;
}
