import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { items, json, request, useApi } from "./api";
import { Badge, Inspector, openInspectorFromRow, Panel, State } from "./ui";
import { IssueBody, SourceFinding, SupportingEvidence, issueKinds } from "./ReportIssue";
import type { Issue } from "./ReportIssue";

type Source = { scan_id: string; connector_name: string; provider: string; created_at: string; version: string };
type Candidate = Source & { status: string; issue_count: number };
type Entry = { id: string; name: string; status: string; created: number; sources: Source[] };
type CombinedReference = { report_id: string; issue_id: string; title?: string };
type CombinedIssue = Omit<Issue, "references"> & { references: CombinedReference[] };
type CombinedReport = Entry & { summary?: string; issues: CombinedIssue[]; total: number; limitations?: string[]; covered_count?: number };
const date = (value: string | number) => new Date(typeof value === "number" ? value * 1000 : value).toLocaleString();

export function CombineReportsModal({ scanId, onClose, onCreated }: {
  scanId: string; onClose: () => void; onCreated: (id: string) => void;
}) {
  const client = useQueryClient();
  const query = useApi<{ items: Candidate[] }>("/combined-reports/candidates", false);
  const [name, setName] = useState("Combined findings report");
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState(new Set(scanId ? [scanId] : []));
  const candidates = items(query.data);
  const chosen = candidates.filter(row => row.status === "completed" && selected.has(row.scan_id));
  const create = useMutation({
    mutationFn: () => request<Entry>("/combined-reports", json({ name: name.trim(),
      reports: chosen.map(row => ({ scan_id: row.scan_id, version: row.version })) })),
    onSuccess: value => {
      void client.invalidateQueries({ predicate: query => query.queryKey.some(part => typeof part === "string" && part.startsWith("/combined-reports")) });
      onCreated(value.id);
    },
  });
  return <Inspector title="Combine different reports" className="combine-report-modal" onClose={() => { if (!create.isPending) onClose(); }}>
    <p>Select 2–20 completed Findings Reports. Matching issues will be merged, preserving affected assets and links to every source issue.</p>
    <form onSubmit={event => { event.preventDefault(); if (chosen.length >= 2 && name.trim()) create.mutate(); }}>
      <label>Combined report name<input aria-label="Combined report name" value={name} maxLength={200} required onChange={event => setName(event.target.value)} /></label>
      <input aria-label="Search assessment reports" placeholder="Search connectors or assessments…" value={search} onChange={event => setSearch(event.target.value)} />
      <State loading={query.isPending} error={query.error} onRetry={() => void query.refetch()} />
      <div className="combined-report-picker">{candidates.filter(row => `${row.connector_name} ${row.provider} ${row.scan_id}`.toLowerCase().includes(search.toLowerCase())).map(row => <label key={row.scan_id} className="combined-report-option">
        <input type="checkbox" aria-label={`Select ${row.connector_name} (${date(row.created_at)})`} checked={row.status === "completed" && selected.has(row.scan_id)}
          disabled={create.isPending || row.status !== "completed" || (chosen.length >= 20 && !selected.has(row.scan_id))}
          onChange={event => setSelected(previous => { const next = new Set(previous); if (event.target.checked) next.add(row.scan_id); else next.delete(row.scan_id); return next; })} />
        <span><strong>{row.connector_name}</strong><small>{row.provider} · {date(row.created_at)}</small><small>{row.status === "completed" ? `${row.issue_count} ${row.issue_count === 1 ? "issue" : "issues"}` : `Report ${row.status.replaceAll("_", " ")} — generate a completed report first`}</small></span>
      </label>)}</div>
      {!query.isPending && !candidates.length && <p>No completed assessments are available. Generate individual Findings Reports first.</p>}
      {create.error && <p role="alert">{create.error.message}</p>}
      <div className="button-row"><button type="submit" className="button primary" disabled={chosen.length < 2 || !name.trim() || create.isPending}>{create.isPending ? "Starting combined report…" : `Combine ${chosen.length} ${chosen.length === 1 ? "report" : "reports"}`}</button><button type="button" className="button" disabled={create.isPending} onClick={onClose}>Cancel</button></div>
    </form>
  </Inspector>;
}

function FrozenSource({ combinedId, reference, onClose, onInspect, onSelectAssessment }: {
  combinedId: string; reference: CombinedReference; onClose: () => void;
  onInspect: (scan: string, id: string) => void; onSelectAssessment?: (scan: string) => void;
}) {
  const query = useApi<{ source: Source; issue: Issue; assessment_available?: boolean }>(`/combined-reports/${combinedId}/source-issue?report_id=${encodeURIComponent(reference.report_id)}&issue_id=${encodeURIComponent(reference.issue_id)}`, false);
  return <Inspector title={query.data?.issue.title || "Source report issue"} onClose={onClose}>
    {!query.data ? <State loading={query.isPending} error={query.error} /> : <>
      <p>{query.data.source.connector_name} · {date(query.data.source.created_at)}</p>
      <p>This issue is preserved from the report version used for this combination.</p>
      <IssueBody issue={query.data.issue} />
      {query.data.assessment_available === false && <p>The original assessment is no longer available. Its saved report issue is preserved here.</p>}
      {onSelectAssessment && query.data.assessment_available !== false && <button className="text-button" onClick={() => onSelectAssessment(reference.report_id)}>Open assessment report</button>}
      <h3>Original supporting evidence</h3><SupportingEvidence key={reference.report_id + reference.issue_id} scanId={reference.report_id} references={query.data.issue.references} available={query.data.assessment_available !== false} onInspect={id => onInspect(reference.report_id, id)} />
    </>}
  </Inspector>;
}

export function CombinedReports({ scanId, selectedId, onSelect, showAll, onShowAll, onSelectAssessment }: {
  scanId: string; selectedId: string; onSelect: (id: string) => void; showAll: boolean;
  onShowAll: (value: boolean) => void; onSelectAssessment?: (id: string) => void;
}) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(0);
  const [selectedIssue, setSelectedIssue] = useState<CombinedIssue>();
  const [source, setSource] = useState<CombinedReference>();
  const [evidence, setEvidence] = useState<{ scan: string; id: string }>();
  const list = useApi<{ items: Entry[] }>(`/combined-reports${!showAll && scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ""}`, false, !selectedId, true);
  const detail = useApi<CombinedReport>(`/combined-reports/${selectedId}?offset=${page * 25}&limit=25&search=${encodeURIComponent(search)}&severity=${severity}`, false, !!selectedId, true);
  const report = detail.data;
  if (!selectedId) return <Panel title="Combined reports">
    {!!scanId && <label className="checkbox"><input type="checkbox" checked={!showAll} onChange={event => onShowAll(!event.target.checked)} />Only reports including this assessment</label>}
    <State loading={list.isPending} error={list.error} onRetry={() => void list.refetch()} />
    <div className="table-scroll"><table className="findings-table"><thead><tr><th>Report</th><th>Source reports</th><th>Created</th><th>Status</th></tr></thead><tbody>{items(list.data).map(row => <tr key={row.id} className="finding-data-row" onClick={event => openInspectorFromRow(event, () => { setPage(0); setSearch(""); setSeverity(""); onSelect(row.id); })}>
      <td><button className="finding-title" onClick={() => { setPage(0); setSearch(""); setSeverity(""); onSelect(row.id); }}>{row.name}</button></td>
      <td>{row.sources.map(source => <span className="combined-source-list" key={source.scan_id}>{source.connector_name} · {date(source.created_at)}</span>)}</td><td>{date(row.created)}</td><td><Badge value={row.status} /></td>
    </tr>)}{!list.isPending && !list.error && !items(list.data).length && <tr><td colSpan={4}>No combined reports{!showAll && scanId ? " include this assessment" : " have been created"}.</td></tr>}</tbody></table></div>
  </Panel>;
  return <div className="ai-review-view">
    <button className="text-button" onClick={() => { onSelect(""); setSelectedIssue(undefined); setSource(undefined); setEvidence(undefined); }}>Back to combined reports</button>
    <State loading={detail.isPending} error={detail.error} onRetry={() => void detail.refetch()} />
    {report && <>
      <Panel title={report.name}><Badge value={report.status} /><p>Created {date(report.created)} from {report.sources.length} reports.</p>
        <ul>{report.sources.map(row => <li key={row.scan_id}>{row.connector_name} · {date(row.created_at)}</li>)}</ul>
        {["queued", "running"].includes(report.status) && <p role="status">Combining the selected report issues…</p>}
      </Panel>
      <Panel><div className="filters"><input aria-label="Search combined report issues" placeholder="Search combined report issues…" value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} /><select aria-label="Combined report issue severity" value={severity} onChange={event => { setSeverity(event.target.value); setPage(0); }}><option value="">All severities</option>{["critical", "high", "medium", "low", "info"].map(value => <option key={value}>{value}</option>)}</select><span className="count-pill">{report.total} {report.total === 1 ? "issue" : "issues"}</span></div>
        <div className="table-scroll"><table className="findings-table"><thead><tr><th>Severity</th><th>Issue</th><th>Type</th><th>Assessment</th><th>Source issues</th></tr></thead><tbody>{report.issues.map(issue => <tr key={issue.id} className="finding-data-row" onClick={event => openInspectorFromRow(event, () => setSelectedIssue(issue))}>
          <td><Badge value={issue.severity} /></td><td><button className="finding-title" onClick={() => setSelectedIssue(issue)}>{issue.title}</button></td><td>{issueKinds[issue.kind] || issue.kind}</td><td>{issue.status === "confirmed" ? "Confirmed configuration" : "Needs review"}</td><td>{issue.references.length}</td>
        </tr>)}{!report.issues.length && <tr><td colSpan={5}>{report.status === "completed" ? "No issues match the selected filters." : "No combined issues are available yet."}</td></tr>}</tbody></table></div>
        {report.total > 25 && <div className="service-page-controls"><button disabled={!page} onClick={() => setPage(page - 1)}>Previous page</button><span>{page * 25 + 1}–{Math.min((page + 1) * 25, report.total)} of {report.total}</span><button disabled={(page + 1) * 25 >= report.total} onClick={() => setPage(page + 1)}>Next page</button></div>}
      </Panel>
    </>}
    {selectedIssue && <Inspector title={selectedIssue.title} onClose={() => setSelectedIssue(undefined)}>
      <IssueBody issue={selectedIssue} /><h3>Source report issues</h3><ul>{selectedIssue.references.map(ref => <li key={ref.report_id + ref.issue_id}><button className="text-button" onClick={() => setSource(ref)}>{report?.sources.find(row => row.scan_id === ref.report_id)?.connector_name || ref.report_id} · {ref.title || ref.issue_id}</button></li>)}</ul>
    </Inspector>}
    {source && <FrozenSource combinedId={selectedId} reference={source} onClose={() => setSource(undefined)} onSelectAssessment={onSelectAssessment} onInspect={(scan, id) => setEvidence({ scan, id })} />}
    {evidence && <SourceFinding scanId={evidence.scan} id={evidence.id} onInspect={id => setEvidence({ ...evidence, id })} onClose={() => setEvidence(undefined)} />}
  </div>;
}
