import { ChevronDown } from "lucide-react";

export function ReportFilters({ combined = false, search, severity, total, onSearch, onSeverity }: {
  combined?: boolean; search: string; severity: string; total: number;
  onSearch: (value: string) => void; onSeverity: (value: string) => void;
}) {
  const label = combined ? "Search combined report issues" : "Search report issues";
  return <div className="filters report-filters">
    <input aria-label={label} placeholder={label + "…"} value={search} onChange={event => onSearch(event.target.value)} />
    <div className="report-filter-actions">
      <div className="report-severity-select">
        <select aria-label={combined ? "Combined report issue severity" : "Report issue severity"}
          value={severity} onChange={event => onSeverity(event.target.value)}>
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map(value => <option key={value}>{value}</option>)}
        </select>
        <ChevronDown aria-hidden size={14} />
      </div>
      <span className="count-pill">{total} {total === 1 ? "issue" : "issues"}</span>
    </div>
  </div>;
}
