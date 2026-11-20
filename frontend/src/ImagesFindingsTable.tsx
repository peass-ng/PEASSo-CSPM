import { useMemo, useRef, useState } from "react";
import "./ImagesFindingsTable.css";
import { Inspector, openInspectorFromRow } from "./ui";

export type ImageFinding = {
  id: string;
  provider: string;
  scope: string;
  image_reference: string;
  image_digest: string;
  severity: "HIGH" | "CRITICAL";
  vulnerability_id: string;
  package: string;
  description?: string;
  references?: string[];
  installed_version: string;
  fixed_versions: string[];
  affected_assets: { resource_id: string; kind: string; namespace?: string }[];
  affected_asset_count?: number;
  assets_truncated?: boolean;
  coverage: "COMPLETE" | "UNKNOWN";
};

export type ImageAssetPage = {
  items: ImageFinding["affected_assets"];
  total: number;
  offset: number;
  next_offset: number | null;
  coverage: "COMPLETE" | "UNKNOWN";
};

export type ImagesFindingsTableProps = {
  rows: ImageFinding[];
  /** Assessment-level coverage. Omission means the image scan is unconfirmed. */
  coverage?: "COMPLETE" | "UNKNOWN" | "NOT_SCANNED";
  coverageWarning?: string;
  loading?: boolean;
  error?: string | Error | null;
  onRetry?: () => void;
  total?: number;
  hasMore?: boolean;
  loadingMore?: boolean;
  loadMoreError?: boolean;
  onLoadMore?: () => void;
  loadAssets?: (row: ImageFinding, offset: number) => Promise<ImageAssetPage>;
};

function AffectedAssets({ row, loadAssets }: {
  row: ImageFinding;
  loadAssets?: ImagesFindingsTableProps["loadAssets"];
}) {
  const [page, setPage] = useState<ImageAssetPage>();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const count = row.affected_asset_count ?? row.affected_assets.length;
  const needsFetch = row.assets_truncated || count > row.affected_assets.length;
  const assets = page?.items || row.affected_assets;
  async function fetchPage(offset: number) {
    if (!loadAssets || loading) return;
    setLoading(true);
    setError(false);
    try {
      const next = await loadAssets(row, offset);
      setPage((previous) => offset === 0 ? next : {
        ...next,
        items: [...(previous?.items || []), ...next.items],
      });
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }
  if (!count) return <span className="images-findings-secondary">No assets listed</span>;
  return <details onToggle={(event) => {
    if (event.currentTarget.open && needsFetch && !page && !loading && !error) void fetchPage(0);
  }}>
    <summary>{count} {count === 1 ? "asset" : "assets"}</summary>
    <ul>{assets.map((asset, index) => <li key={`${asset.resource_id}:${asset.kind}:${asset.namespace || ""}:${index}`}>
      <span className="images-findings-break">{asset.resource_id}</span>
      <span className="images-findings-secondary">{asset.kind}{asset.namespace ? ` · ${asset.namespace}` : ""}</span>
    </li>)}</ul>
    {loading && <span className="images-findings-secondary" role="status">Loading assets…</span>}
    {error && <span className="images-findings-secondary" role="alert">Assets could not be loaded. <button type="button" className="text-button" onClick={() => void fetchPage(page?.next_offset ?? 0)}>Retry</button></span>}
    {page?.next_offset != null && <button type="button" className="text-button" disabled={loading} onClick={() => void fetchPage(page.next_offset!)}>Load more assets</button>}
    {needsFetch && !loadAssets && <span className="images-findings-secondary">Showing {assets.length} of {count} assets</span>}
  </details>;
}

export function filterImageFindings(rows: ImageFinding[], query: string, severity: string, provider: string): ImageFinding[] {
  const needle = query.trim().toLocaleLowerCase();
  return rows.filter((row) => {
    if (severity && row.severity !== severity) return false;
    if (provider && row.provider !== provider) return false;
    if (!needle) return true;
    return [row.vulnerability_id, row.package, row.installed_version, row.image_reference,
      row.image_digest, row.scope, row.provider,
      ...row.affected_assets.flatMap((asset) => [asset.resource_id, asset.kind, asset.namespace || ""])]
      .some((value) => value.toLocaleLowerCase().includes(needle));
  });
}

type ImageGroup = { id: string; title: string; severity: "CRITICAL" | "HIGH"; rows: ImageFinding[] };
function groupFindings(rows: ImageFinding[], by: string): ImageGroup[] {
  const groups = new Map<string, ImageGroup>();
  for (const row of rows) {
    const id = by === "image" ? JSON.stringify([row.provider, row.scope, row.image_digest]) : row.vulnerability_id;
    const group = groups.get(id) || { id, title: by === "image" ? row.image_reference : row.vulnerability_id, severity: row.severity, rows: [] };
    group.rows.push(row);
    if (row.severity === "CRITICAL") group.severity = "CRITICAL";
    groups.set(id, group);
  }
  return [...groups.values()].sort((a, b) => Number(b.severity === "CRITICAL") - Number(a.severity === "CRITICAL") || a.title.localeCompare(b.title));
}
function advisoryLinks(row: ImageFinding): string[] {
  const links = (row.references || []).filter(url => /^https?:\/\//i.test(url));
  if (/^CVE-\d{4}-\d+$/i.test(row.vulnerability_id)) links.push(`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(row.vulnerability_id)}`, `https://www.cve.org/CVERecord?id=${encodeURIComponent(row.vulnerability_id)}`);
  if (/^GHSA-[a-z0-9-]+$/i.test(row.vulnerability_id)) links.push(`https://github.com/advisories/${encodeURIComponent(row.vulnerability_id)}`);
  return [...new Set(links)];
}

export function ImagesFindingsTable({ rows, coverage, coverageWarning, loading = false, error, onRetry,
  total = rows.length, hasMore = false, loadingMore = false, loadMoreError = false, onLoadMore, loadAssets }: ImagesFindingsTableProps) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("");
  const [provider, setProvider] = useState("");
  const [groupBy, setGroupBy] = useState("cve");
  const [selected, setSelected] = useState<string>();
  const trigger = useRef<HTMLButtonElement | null>(null);
  const providers = useMemo(() => [...new Set(rows.map((row) => row.provider))].sort(), [rows]);
  const visible = useMemo(() => filterImageFindings(rows, query, severity, provider), [rows, query, severity, provider]);
  const groups = useMemo(() => groupFindings(visible, groupBy), [visible, groupBy]);
  const selectedGroup = selected ? groupFindings(rows, groupBy).find(group => group.id === selected) : undefined;
  const coverageUnknown = coverage !== "COMPLETE" || rows.some((row) => row.coverage === "UNKNOWN");
  const filtered = !!(query.trim() || severity || provider);

  if (loading) return <div className="images-findings-state" role="status">Loading image findings…</div>;
  if (error) return <div className="images-findings-state" role="alert">
    <p>Image findings could not be loaded.</p>
    {onRetry && <button type="button" className="button" onClick={onRetry}>Retry</button>}
  </div>;

  return <section className="images-findings" aria-label="Images Findings">
    {coverageUnknown && <p className="images-findings-coverage" role="status">
      {coverageWarning || (coverage === "NOT_SCANNED"
        ? "Image scanning was not selected for this assessment."
        : "Image scan coverage is incomplete. Findings shown here may be missing.")}
    </p>}
    <div className="images-findings-toolbar">
      <label>Search image findings
        <input type="search" value={query} onChange={(event) => setQuery(event.target.value)}
          placeholder="CVE, package, image, asset…" />
      </label>
      <label>Group by
        <select aria-label="Group image findings by" value={groupBy} onChange={event => { setGroupBy(event.target.value); setSelected(undefined); }}>
          <option value="cve">CVE</option><option value="image">Image</option>
        </select>
      </label>
      <label>Severity
        <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">All</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option>
        </select>
      </label>
      <label>Provider
        <select value={provider} onChange={(event) => setProvider(event.target.value)}>
          <option value="">All</option>
          {providers.map((value) => <option key={value} value={value}>{value}</option>)}
        </select>
      </label>
      <span className="images-findings-count" aria-live="polite">{groups.length} groups · {visible.length} shown · {rows.length} loaded of {total} findings</span>
    </div>
    {hasMore && <p className="images-findings-loaded-note">Groups and filters currently include loaded findings only. Load remaining findings to include every image and CVE.</p>}
    {visible.length === 0 ? <p className="images-findings-state" role="status">
      {filtered ? hasMore ? "No loaded image findings match these filters." : "No image findings match these filters." : coverage === "NOT_SCANNED"
        ? "No image scan results are available." : coverageUnknown
          ? "No image findings were reported; scan coverage is incomplete."
          : "No high or critical image vulnerabilities found."}
    </p> : <div className="images-findings-scroll table-scroll" role="region" aria-label="Image CVE findings table" tabIndex={0}>
      <table className="images-findings-table">
        <caption>High and critical image vulnerabilities grouped by {groupBy === "cve" ? "CVE" : "image"}</caption>
        <thead><tr><th scope="col">Severity</th><th scope="col">{groupBy === "cve" ? "CVE" : "Image"}</th><th scope="col">{groupBy === "cve" ? "Images" : "CVEs"}</th><th scope="col">Packages</th><th scope="col">Affected assets</th></tr></thead>
        <tbody>{groups.map(group => {
          const assets = new Set(group.rows.flatMap(row => row.affected_assets.map(asset => `${row.provider}:${row.scope}:${asset.resource_id}:${asset.kind}:${asset.namespace || ""}`)));
          const incompleteAssets = group.rows.some(row => row.assets_truncated);
          return <tr key={group.id} className="finding-data-row" onClick={event => openInspectorFromRow(event, button => {
            trigger.current = button;
            setSelected(group.id);
          })}>
            <td><span className={`badge ${group.severity.toLowerCase()}`}>{group.severity}</span></td>
            <td><button className="finding-title images-findings-break" aria-haspopup="dialog" onClick={event => { trigger.current = event.currentTarget; setSelected(group.id); }}>{group.title}</button>
              {groupBy === "image" && <span className="images-findings-secondary">{group.rows[0].provider} · {group.rows[0].scope}</span>}</td>
            <td>{new Set(group.rows.map(row => groupBy === "cve" ? `${row.provider}:${row.scope}:${row.image_digest}` : row.vulnerability_id)).size}</td>
            <td>{[...new Set(group.rows.map(row => row.package))].join(", ")}</td>
            <td>{incompleteAssets ? "At least " : ""}{assets.size} {assets.size === 1 ? "asset" : "assets"}</td>
          </tr>;
        })}</tbody>
      </table>
    </div>}
    {(hasMore || loadingMore || loadMoreError) && <div className="images-findings-more">
      {loadMoreError && <span role="alert">More findings could not be loaded. </span>}
      <button type="button" className="button" disabled={loadingMore || !onLoadMore} onClick={onLoadMore}>
        {loadingMore ? "Loading more findings…" : loadMoreError ? "Retry loading more" : "Load more findings"}
      </button>
    </div>}
    {selectedGroup && <Inspector title={selectedGroup.title} onClose={() => { setSelected(undefined); requestAnimationFrame(() => trigger.current?.focus()); }}>
      <span className={`badge ${selectedGroup.severity.toLowerCase()}`}>{selectedGroup.severity}</span>
      {hasMore && <p role="status">More findings are available. Load the remaining findings to include every affected image and package.</p>}
      {selectedGroup.rows.map(row => <section key={row.id} className="image-cve-detail">
        <h3>{row.vulnerability_id} · {row.package}</h3>
        <p>{row.description || `${row.package} ${row.installed_version} is affected by ${row.vulnerability_id}.`}</p>
        <dl><dt>Installed version</dt><dd>{row.installed_version}</dd><dt>Fixed versions</dt><dd>{row.fixed_versions.join(", ") || "No fix listed"}</dd>
          <dt>Image</dt><dd className="images-findings-break">{row.image_reference}</dd><dt>Image digest</dt><dd className="images-findings-break">{row.image_digest}</dd>
          <dt>Scope</dt><dd>{row.provider} · {row.scope}</dd></dl>
        <h4>References</h4><ul>{advisoryLinks(row).map(url => <li key={url}><a href={url} target="_blank" rel="noopener noreferrer">{url}</a></li>)}</ul>
        <h4>Affected assets</h4><AffectedAssets row={row} loadAssets={loadAssets} />
      </section>)}
    </Inspector>}
  </section>;
}
