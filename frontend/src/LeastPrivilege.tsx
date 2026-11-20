import { useState } from "react";
import { ChevronRight, Search, ShieldCheck } from "lucide-react";
import { useApi } from "./api";
import { Inspector, Panel, ProviderIcon, State } from "./ui";
import "./LeastPrivilege.css";
import { ExposureBadges, ExposureDetails, type PrincipalExposure } from "./PrincipalExposure";
import { Badge } from "./ui";

type Suggestion = {
  kind: "permission" | "service" | "role" | "role_review";
  value: string;
  scope: string;
  source: string;
  evidence_id?: string;
  replacement?: string[];
  last_accessed?: string;
  last_refreshed?: string;
  usage_window_end?: string;
  policy?: string;
  confidence: "provider_recommendation" | "declared_grant_only" | "tracked_without_observed_use";
};
type RiskPermission = {
  permission: string; severity: string; source: string; scope: string; resources: string[];
  conditions?: unknown; exclusions?: string[]; last_accessed?: string; usage_basis?: "permission" | "service" | "policy" | "group" | "role" | "compatible";
  days_since_last_access?: number; unused_finding?: boolean; usage_status?: "observed" | "not_observed";
  usage_window_days?: number; usage_window_end?: string; usage_source?: string;
  group_key: string; group_label: string; principal?: string; principal_id?: string;
};
type Principal = {
  id: string;
  principal: string;
  label?: string;
  scopes: string[];
  provider: string;
  recommendation_count: number;
  tracked_review_count?: number;
  severity?: string;
  base_severity?: string;
  exposures?: PrincipalExposure[];
  suggestions: Suggestion[];
  high_risk_permissions?: RiskPermission[];
  permission_definitions_missing?: string[];
  observed_at?: string;
  identity_last_used?: string;
};
type GrantGroup = { id: string; label: string; provider: string; scopes: string[]; severity: string;
  principals: Pick<Principal, "id" | "principal" | "label" | "severity">[];
  permission_count: number; recommendation_count: number; permissions?: RiskPermission[] };
type Page = {
  items: Principal[] | GrantGroup[];
  total: number;
  next_offset: number | null;
  coverage: { limitations: string[]; unused_access_analyzers?: number };
};

function hasUnusedEvidence(item: RiskPermission) { return !!item.unused_finding || item.usage_status === "not_observed"; }

function PermissionUsage({ item }: { item: RiskPermission }) {
  if (item.days_since_last_access != null) {
    const basis = item.usage_basis === "permission" ? "Action last seen"
      : item.usage_basis === "policy" ? `Policy report · ${item.usage_source?.includes("action") ? "action" : "service"} attempt`
      : item.usage_basis === "group" ? `Group report · ${item.usage_source?.includes("action") ? "action" : "service"} attempt`
      : item.usage_basis === "role" ? "Role activity"
      : item.usage_basis === "compatible" ? "Matching principal action; granting role unconfirmed"
      : "Principal service attempt";
    return <div className={`least-usage ${item.days_since_last_access > 90 ? "stale" : "recent"}`}>
      <strong>{item.days_since_last_access} {item.days_since_last_access === 1 ? "day" : "days"} ago</strong>
      <small>{basis}{item.usage_source ? ` · ${item.usage_source}` : ""}</small>
      {item.usage_status === "not_observed" && <small>Exact action not observed for this principal</small>}
      <time dateTime={item.last_accessed}>{item.last_accessed}</time>
    </div>;
  }
  if (item.usage_status) return <div className="least-usage unknown">
    <strong>{item.usage_status === "observed" ? "Use observed" : "No use observed"}{item.usage_window_days != null ? ` in ${item.usage_window_days} days` : " in the provider window"}</strong>
    <small>{item.usage_source || "Provider insight"}; no exact last-use date</small>{item.usage_window_end && <time dateTime={item.usage_window_end}>Window ended {item.usage_window_end}</time>}
  </div>;
  return <span className="least-usage unknown">{item.unused_finding ? "Unused in analyzer window · no last-use date" : "Usage not available"}</span>;
}

export function LeastPrivilege({ scanId, demo }: { scanId: string; demo: boolean }) {
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [exposure, setExposure] = useState("");
  const [sort, setSort] = useState("severity:desc");
  const [permissionSearch, setPermissionSearch] = useState("");
  const [unusedOnly, setUnusedOnly] = useState(false);
  const [groupBy, setGroupBy] = useState<"principal" | "grant">("principal");
  const [selected, setSelected] = useState<Principal>();
  const [selectedGrant, setSelectedGrant] = useState<GrantGroup>();
  const page = useApi<Page>(`/scans/${encodeURIComponent(scanId)}/least-privilege?group_by=${groupBy}&search=${encodeURIComponent(search)}${exposure ? `&exposure=${exposure}` : ""}&sort_by=${sort.split(":")[0]}&sort_order=${sort.split(":")[1]}&offset=${offset}&limit=100`, demo, !!scanId);
  const details = useApi<Principal>(`/scans/${encodeURIComponent(scanId)}/least-privilege/principals/${encodeURIComponent(selected?.id || "")}`, demo, !!scanId && !!selected);
  const grantDetails = useApi<GrantGroup>(`/scans/${encodeURIComponent(scanId)}/least-privilege/grants?key=${encodeURIComponent(selectedGrant?.id || "")}`, demo, !!scanId && !!selectedGrant);
  const detail = selected ? (details.data?.id === selected.id ? { ...selected, ...details.data } : selected) : undefined;
  const permissions = detail?.high_risk_permissions || [];
  const visiblePermissions = permissions.filter(item => (!unusedOnly || hasUnusedEvidence(item)) && [item.permission, item.source, item.scope, ...item.resources].join(" ").toLowerCase().includes(permissionSearch.trim().toLowerCase()));
  const rows = page.data?.items || [];
  const principalRows = groupBy === "principal" ? rows as Principal[] : [];
  const grantRows = groupBy === "grant" ? rows as GrantGroup[] : [];
  const grant = selectedGrant ? (grantDetails.data?.id === selectedGrant.id ? grantDetails.data : selectedGrant) : undefined;
  const grantPermissions = (grant?.permissions || []).filter(item => (!unusedOnly || hasUnusedEvidence(item)) &&
    [item.permission, item.source, item.scope, item.principal || "", ...item.resources].join(" ").toLowerCase().includes(permissionSearch.trim().toLowerCase()));
  return <div className="least-page">
    <div className="section-top">
      <p>Review high-impact permissions, usage history and identity entry points.</p>
      <span className="count-pill">{page.data?.total ?? 0} {groupBy === "principal" ? "principals" : "policies / roles"}</span>
    </div>
    <Panel className="least-panel">
      <div className="least-toolbar">
        <select aria-label="Group least privilege by" value={groupBy} onChange={event => { setGroupBy(event.target.value as "principal" | "grant"); setOffset(0); setSelected(undefined); setSelectedGrant(undefined); }}>
          <option value="principal">Group by principal</option><option value="grant">Group by {rows[0]?.provider === "aws" ? "policy" : rows[0]?.provider ? "role" : "policy / role"}</option>
        </select>
        <label className="search-field">
          <Search size={17} />
          <input aria-label="Search principals or grants" value={search} placeholder={groupBy === "principal" ? "Search principal or scope…" : "Search policy, role, principal or scope…"}
            onChange={(event) => { setSearch(event.target.value); setOffset(0); }} />
        </label>
        <select aria-label="Sort principals" value={sort} onChange={event => { setSort(event.target.value); setOffset(0); }}>
          <option value="severity:desc">Criticality: highest first</option><option value="severity:asc">Criticality: lowest first</option>
          <option value="principal:asc">Principal: A–Z</option><option value="principal:desc">Principal: Z–A</option>
          <option value="recommendations:desc">Most suggested changes</option>
        </select>
        <select aria-label="Principal exposure filter" value={exposure} onChange={event => { setExposure(event.target.value); setOffset(0); }}>
          <option value="">All entry points</option>
          <option value="external">External accounts or identities</option>
          <option value="federated">Federated identity trust</option>
          <option value="internet">Internet-facing workload</option>
          <option value="unresolved">Unresolved exposure</option>
        </select>
      </div>
      {!scanId ? <State empty title="Select a scan to review identities" /> :
        <State loading={page.isPending} error={page.error} onRetry={() => void page.refetch()}>
          {rows.length ? <div className="least-list table-scroll" tabIndex={0} role="list" aria-label={groupBy === "principal" ? "Principals with access to review" : "Policies and roles with access to review"}>
            {principalRows.map((principal) => <button type="button" role="listitem" className="least-row" key={principal.id}
              onClick={() => { setSelected(principal); setPermissionSearch(""); setUnusedOnly(false); }}>
              <span className="least-provider"><ProviderIcon provider={principal.provider} size={22} /></span>
              <span className="least-identity"><strong>{principal.label || principal.principal.split("/").pop() || principal.principal}</strong><small>{principal.principal} · {principal.scopes.length} scope{principal.scopes.length === 1 ? "" : "s"}</small></span>
              <span className={`least-row-count${principal.recommendation_count ? " recommended" : ""}`}>{principal.recommendation_count
                ? `${principal.recommendation_count} suggested changes`
                : principal.tracked_review_count ? `${principal.tracked_review_count} tracked actions to review`
                : principal.suggestions.length ? `${principal.suggestions.length} grants to review` : "Exposure to review"}</span>
              <ExposureBadges exposures={principal.exposures} />
              {principal.severity && <Badge value={principal.severity} />}
              <ChevronRight size={18} aria-hidden="true" />
            </button>)}
            {grantRows.map((item) => <button type="button" role="listitem" className="least-row" key={item.id}
              onClick={() => { setSelectedGrant(item); setPermissionSearch(""); setUnusedOnly(false); }}>
              <span className="least-provider"><ProviderIcon provider={item.provider} size={22} /></span>
              <span className="least-identity"><strong>{item.label}</strong><small>{item.id} · {item.scopes.length} scope{item.scopes.length === 1 ? "" : "s"}</small></span>
              <span className="least-row-count">{item.principals.length} principal{item.principals.length === 1 ? "" : "s"} · {item.permission_count} grants</span>
              <Badge value={item.severity} /><ChevronRight size={18} aria-hidden="true" />
            </button>)}
          </div> : <div className="least-empty"><ShieldCheck size={24} /><h3>No access grants in this selection</h3>
            <p>{search ? "Try another search." : "No high or critical grants were recorded for this selection."}</p></div>}
          {page.data && page.data.total > 100 && <div className="least-pagination">
            <button className="button" type="button" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 100))}>Previous</button>
            <span>{offset + 1}–{Math.min(offset + 100, page.data.total)} of {page.data.total}</span>
            <button className="button" type="button" disabled={page.data.next_offset == null} onClick={() => setOffset(page.data!.next_offset!)}>Next</button>
          </div>}
        </State>}
    </Panel>
    {detail && <Inspector title="Principal access review" onClose={() => setSelected(undefined)} className="least-inspector">
      <div className="least-detail">
        <div className="least-detail-identity"><div><span className="least-eyebrow">IDENTITY ACCESS</span><h2>{detail.label || detail.principal}</h2>
          <p>{detail.principal}</p></div>{detail.severity && <Badge value={detail.severity} />}</div>
        <div className="least-detail-stats"><span><strong>{details.isPending ? "…" : details.error ? "—" : permissions.length}</strong> high / critical grants</span><span><strong>{permissions.filter(p => p.severity === "critical").length}</strong> critical</span><span><strong>{detail.exposures?.length || 0}</strong> entry points</span></div>
        <ExposureDetails exposures={detail.exposures} severity={detail.severity} baseSeverity={detail.base_severity} />
        <section className="least-permissions" aria-label="High and critical permissions">
          <h3>High & critical permissions</h3>
          <p>Declared permissions, including collected policy attachments and inherited role or group grants.</p>
          {details.isPending ? <p role="status">Loading permission details…</p> : details.error ? <State error={details.error} onRetry={() => void details.refetch()} /> : <>
            <div className="least-permission-toolbar"><label className="search-field"><Search size={16} /><input aria-label="Filter high-risk permissions" placeholder="Filter permissions, policies or scopes…" value={permissionSearch} onChange={event => setPermissionSearch(event.target.value)} /></label>
              {permissions.some(hasUnusedEvidence) && <label className="least-unused-filter"><input type="checkbox" checked={unusedOnly} onChange={event => setUnusedOnly(event.target.checked)} /> Permissions without observed use</label>}</div>
            <div className="least-permissions-scroll"><table className="least-permissions-table"><thead><tr><th>Permission & granting policy</th><th>Criticality</th><th>Applies to</th><th>Last use</th></tr></thead><tbody>
              {visiblePermissions.map((item, index) => <tr key={`${item.permission}-${item.scope}-${index}`}>
                <td><code>{item.permission}</code><small>{item.source}</small>{item.conditions != null && <details><summary>Grant conditions</summary><pre>{JSON.stringify(item.conditions, null, 2)}</pre></details>}
                  {!!item.exclusions?.length && <details><summary>Exclusions</summary><p>{item.exclusions.join(", ")}</p></details>}</td>
                <td><Badge value={item.severity} /></td><td><span>{item.scope}</span>{item.resources.map(resource => <small key={resource}>{resource}</small>)}</td>
                <td><PermissionUsage item={item} /></td>
              </tr>)}
              {!visiblePermissions.length && <tr><td colSpan={4}>{permissionSearch || unusedOnly ? "No permissions match this filter." : "No high or critical permissions were resolved from the collected definitions."}</td></tr>}
            </tbody></table></div>
          </>}
          {!!detail.permission_definitions_missing?.length && <details className="least-missing"><summary>Permission definitions not collected ({detail.permission_definitions_missing.length})</summary><p>These grants are recorded, but their permission definitions are unavailable:</p><ul>{detail.permission_definitions_missing.map(role => <li key={role}>{role}</li>)}</ul></details>}
          {detail.identity_last_used && <p className="least-identity-usage">Identity activity last seen: <time dateTime={detail.identity_last_used}>{detail.identity_last_used}</time>.</p>}
        </section>
        {detail.suggestions.some(item => item.value !== "high-impact declared access") && <section className="least-recommendations"><h3>Access recommendations</h3>
          <div className="least-suggestions">{detail.suggestions.filter(item => item.value !== "high-impact declared access").map((item, index) => <article key={`${item.scope}-${item.value}-${index}`}>
            <span className="least-source">{item.source}</span><h4>{item.kind === "permission" ? `Review removing ${item.value}` : item.kind === "service" ? `Review ${item.value} service access` : item.kind === "role" ? `Remove or replace ${item.value}` : `Review ${item.value}`}</h4>
            {item.replacement?.length ? <p>Suggested replacement: {item.replacement.join(", ")}</p> : null}
            {item.policy && <p>Granting policy: <code>{item.policy}</code></p>}
            {item.usage_window_end && <p>No use observed for this tracked action in the report completed {item.usage_window_end}.</p>}
            <p>{item.scope}</p>{item.last_accessed && <p>Last accessed: {item.last_accessed}</p>}
          </article>)}</div>
        </section>}
      </div>
    </Inspector>}
    {grant && <Inspector title={grant.provider === "aws" ? "Policy access review" : "Role access review"} onClose={() => setSelectedGrant(undefined)} className="least-inspector">
      <div className="least-detail">
        <div className="least-detail-identity"><div><span className="least-eyebrow">{grant.provider === "aws" ? "POLICY ACCESS" : "ROLE ACCESS"}</span><h2>{grant.label}</h2><p>{grant.id}</p></div><Badge value={grant.severity} /></div>
        <div className="least-detail-stats"><span><strong>{grant.principals.length}</strong> principals</span><span><strong>{grant.permission_count}</strong> high / critical grants</span><span><strong>{grant.scopes.length}</strong> scopes</span></div>
        <section className="least-permissions" aria-label="Principals receiving this grant">
          <h3>Principals receiving this {grant.provider === "aws" ? "policy" : "role"}</h3>
          <ul className="least-group-principals">{grant.principals.map(item => <li key={item.id}><strong>{item.label || item.principal}</strong><small>{item.principal}</small></li>)}</ul>
        </section>
        <section className="least-permissions" aria-label="High and critical permissions">
          <h3>High & critical permissions</h3>
          {grantDetails.isPending ? <p role="status">Loading permission details…</p> : grantDetails.error ? <State error={grantDetails.error} onRetry={() => void grantDetails.refetch()} /> : <>
            <div className="least-permission-toolbar"><label className="search-field"><Search size={16} /><input aria-label="Filter grant permissions" placeholder="Filter permission, principal or scope…" value={permissionSearch} onChange={event => setPermissionSearch(event.target.value)} /></label>
              {grant.permissions?.some(hasUnusedEvidence) && <label className="least-unused-filter"><input type="checkbox" checked={unusedOnly} onChange={event => setUnusedOnly(event.target.checked)} /> Permissions without observed use</label>}</div>
            <div className="least-permissions-scroll"><table className="least-permissions-table"><thead><tr><th>Permission & principal</th><th>Criticality</th><th>Applies to</th><th>Last use</th></tr></thead><tbody>
              {grantPermissions.map((item, index) => <tr key={`${item.principal_id}-${item.permission}-${item.scope}-${index}`}>
                <td><code>{item.permission}</code><small>{item.principal}</small>{item.conditions != null && <details><summary>Grant conditions</summary><pre>{JSON.stringify(item.conditions, null, 2)}</pre></details>}</td>
                <td><Badge value={item.severity} /></td><td><span>{item.scope}</span>{item.resources.map(resource => <small key={resource}>{resource}</small>)}</td>
                <td><PermissionUsage item={item} /></td>
              </tr>)}
              {!grantPermissions.length && <tr><td colSpan={4}>No permissions match this filter.</td></tr>}
            </tbody></table></div>
          </>}
        </section>
      </div>
    </Inspector>}

  </div>;
}
