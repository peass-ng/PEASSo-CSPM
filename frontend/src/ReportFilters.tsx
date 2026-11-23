import type { ReactNode } from "react";
import { Search } from "lucide-react";

export function ReportFilters({ combined = false, search, severity, total, onSearch, onSeverity, children }: {
  children: ReactNode;
  combined?: boolean; search: string; severity: string; total: number;
  onSearch: (value: string) => void; onSeverity: (value: string) => void;
}) {
  const label = combined ? "Search combined report issues" : "Search report issues";
  return <div className="table-toolbar report-filters">
    <label className="search-field">
      <Search size={16} aria-hidden="true" />
      <input aria-label={label} placeholder={label + "…"} value={search} onChange={event => onSearch(event.target.value)} />
    </label>
    <select aria-label={combined ? "Combined report issue severity" : "Report issue severity"}
      value={severity} onChange={event => onSeverity(event.target.value)}>
      <option value="">All severities</option>
      {["critical", "high", "medium", "low", "info"].map(value => <option key={value}>{value}</option>)}
    </select>
    <span className="count-pill" aria-live="polite">{total} {total === 1 ? "issue" : "issues"}</span>
    {children}
  </div>;
}
