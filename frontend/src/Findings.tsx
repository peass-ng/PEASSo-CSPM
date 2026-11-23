import { TableDownload, requestTableRows, tablePagePath } from "./TableDownload";
import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
} from "@tanstack/react-table";
import { Search, SlidersHorizontal, ChevronDown, ChevronRight } from "lucide-react";
import type { Catalog, ContainerExposureRoute, Finding, Report } from "./types";
import { Badge, Evidence, Inspector, Panel, State, openInspectorFromRow } from "./ui";
import { catalogFrameworksPath, items, request, useApi } from "./api";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { explainExposureAction, explainFindingEvidence, explainInternetExposure } from "./findingExplanation";
import { explainAzureFindingEvidence } from "./azureFindingEvidence";
import { explainAzureNativeEvidenceObservation } from "./azureNativeEvidenceObservation";
import { explainGcpFindingEvidence } from "./gcpFindingEvidence";
import { explainExposureCheck } from "./exposureCheckExplanation";
import { explainObservedEvidence } from "./observedEvidenceExplanation";
import { Remediation } from "./Remediation";
import { GroupedFindingEvidence, findingGroupPath } from "./GroupedFindingEvidence";
import { FindingStatusBadge, findingStatusCounts, findingStatusOptions, matchesFindingStatus } from "./findingStatus";
import "./FindingInspector.css";
import { AccessAnalyzerUnusedEvidence } from "./AccessAnalyzerUnusedEvidence";
import { FoundSecretValues, PrivateSecretEvidence } from "./PrivateSecretEvidence";
import findingTypes from "./findingTypes.json";
const findingTypeLabel = (id?: string) => findingTypes.find(type => type.id === id)?.label || "Unclassified";
type ContainerExposureEvidence = {
  container: string;
  manifest_digest: string;
  exposure_routes: ContainerExposureRoute[];
  advisory_totals: Partial<Record<"CRITICAL" | "HIGH", number>>;
  package_advisories: { vulnerability_id: string; severity: string; package: string; installed_version: string; fixed_versions: string[] }[];
};

function ContainerExposureEvidence({ evidence }: { evidence: ContainerExposureEvidence }) {
  return <section className="finding-detail-section">
    <h3>Container and internet routes</h3>
    <p><strong>{evidence.container}</strong> · <code>{evidence.manifest_digest}</code></p>
    <ul className="report-evidence">{evidence.exposure_routes.map(route => <li key={JSON.stringify(route)}>
      <code>{route.endpoint}:{route.port}</code> · {route.protocol} → container port {route.container_port}
      {!!route.controls.length && <div className="small">{route.controls.join(" · ")}</div>}
    </li>)}</ul>
    <h3>Package advisories</h3>
    <p>{(["CRITICAL", "HIGH"] as const).filter(level => evidence.advisory_totals[level])
      .map(level => `${evidence.advisory_totals[level]} ${level.toLowerCase()}`).join(" · ")}</p>
    <ul className="report-evidence">{evidence.package_advisories.map(advisory =>
      <li key={JSON.stringify([advisory.vulnerability_id, advisory.package, advisory.installed_version])}>
        <strong>{advisory.vulnerability_id}</strong> · <code>{advisory.package} {advisory.installed_version}</code>
        {" · "}{advisory.severity.toLowerCase()}
      </li>)}</ul>
    {Object.values(evidence.advisory_totals).reduce((sum, count) => sum + count, 0) > evidence.package_advisories.length &&
      <p className="muted">Showing the first {evidence.package_advisories.length} advisories. Open the image CVE list for all advisories.</p>}
  </section>;
}
type FindingPage = {
  items: Finding[];
  total?: number;
  next_offset?: number | null;
  offset?: number;
  facets?: { services?: string[]; statuses?: string[]; frameworks?: string[] };
  service_groups?: ServiceSummary[];
  type_groups?: { finding_type: string; label: string; count: number; status_counts: Record<string, number> }[];
  status_filter_counts?: Record<string, number>;
  status_filter_total?: number;
};
type ServiceSummary = { service: string; label?: string; count: number; status_counts: Record<string, number> };
const col = createColumnHelper<Finding>();
const assetLabel = (finding: Finding) =>
  finding.grouped ? (finding.affected_asset_count ? `${finding.affected_asset_count.toLocaleString()} assets` : `${(finding.member_count || 0).toLocaleString()} observations`)
    : finding.resource_name || finding.native_resource_id || finding.resource_id;
type SortField = "severity" | "title" | "service" | "account" | "status" | "resource_id";
function accountLabel(finding: Finding): string {
  if (finding.grouped && finding.affected_accounts?.length)
    return finding.affected_accounts.length === 1 ? finding.affected_accounts[0] : `${finding.affected_accounts.length} accounts`;
  if ("account" in finding && typeof finding.account === "string" && finding.account)
    return finding.account;
  const scope = finding.scope?.trim() || "";
  const resource = finding.native_resource_id || finding.resource_id || "";
  if (finding.provider === "aws") {
    const account = scope.match(/(?:^|\/)(\d{12})(?:\/|$)/)?.[1] ||
      resource.match(/^arn:[^:]*:[^:]*:[^:]*:(\d{12}):/)?.[1];
    return account || (scope && !scope.includes("/") ? scope : "Unknown");
  }
  if (finding.provider === "gcp") {
    const project = scope.match(/(?:^|\/)projects\/([^/]+)/)?.[1] ||
      resource.match(/(?:^|\/)projects\/([^/]+)/)?.[1];
    if (project) return project;
    const owner = scope.match(/(?:^|\/)(folders|organizations)\/([^/]+)/) ||
      resource.match(/(?:^|\/)(folders|organizations)\/([^/]+)/);
    return owner ? owner[2] :
      scope && !scope.includes("/") ? scope : "Unknown";
  }
  if (finding.provider === "azure") {
    const subscription = scope.match(/(?:^|\/)subscriptions\/([^/]+)/i)?.[1] ||
      resource.match(/(?:^|\/)subscriptions\/([^/]+)/i)?.[1];
    if (subscription) return subscription;
    const tenant = scope.match(/(?:^|\/)(tenants)\/([^/]+)/i) ||
      resource.match(/(?:^|\/)(tenants)\/([^/]+)/i);
    return tenant ? tenant[2] :
      scope && !scope.includes("/") ? scope : "Unknown";
  }
  if (finding.provider === "k8s")
    return resource.match(/^k8s:\/\/([^/]+)/)?.[1] || "Unknown";
  return scope.split("/")[0] || "Unknown";
}

const SERVICE_PAGE_SIZE = 50;
function ServiceSection({ summary, groupBy, scanId, category, findingType, demo, search, severity, status, framework, sort,
  expanded, onToggle, onInspect }: {
  summary: ServiceSummary;
  groupBy: "service" | "finding_type";
  scanId: string;
  category: string;
  findingType: string;
  demo: boolean;
  search: string;
  severity: string;
  status: string;
  framework: string;
  sort?: { field: SortField; order: "asc" | "desc" };
  expanded: boolean;
  onToggle: () => void;
  onInspect: (finding: Finding) => void;
}) {
  const [offset, setOffset] = useState(0);
  const query = useQuery({
    queryKey: [demo ? "demo" : "live", "service-findings", scanId, category, findingType, search, severity,
      status, framework, groupBy, summary.service, sort, offset],
    queryFn: ({ signal }) => {
      const params = new URLSearchParams({
        limit: String(SERVICE_PAGE_SIZE), offset: String(offset), group_by: groupBy,
        aggregation: "check", [groupBy]: summary.service || ",",
      });
      for (const [key, value] of Object.entries({ categories: category, finding_type: findingType, search, severity, status, framework }))
        if (value) params.set(key, value);
      if (sort) {
        params.set("sort_by", sort.field);
        params.set("sort_order", sort.order);
      }
      return request<FindingPage>(`/scans/${encodeURIComponent(scanId)}/findings?${params}`, { signal }, demo);
    },
    enabled: expanded,
    retry: 1,
  });
  const findings = query.data ? items(query.data) : [];
  return <>
    <tr className="service-group-row"><td colSpan={6}>
      <button type="button" className="service-group-button" aria-expanded={expanded} onClick={onToggle}>
        <ChevronRight size={16} className={expanded ? "expanded" : ""} />
        <strong>{summary.label || summary.service || "Unknown service"}</strong>
        <span>{summary.count.toLocaleString()} findings</span>
        {findingStatusCounts(summary.status_counts).map(({ label, count }) =>
          <span key={label}>{count.toLocaleString()} {label.toLowerCase()}</span>)}
      </button>
    </td></tr>
    {expanded && (query.isPending || query.error) && <tr><td colSpan={6} className="service-group-message">
      {query.isPending ? "Loading findings…" : <span role="alert">This group could not be loaded. <button type="button" className="text-button" onClick={() => void query.refetch()}>Retry</button></span>}
    </td></tr>}
    {expanded && findings.map(finding => <tr key={finding.id} className="finding-data-row"
      onClick={event => openInspectorFromRow(event, () => onInspect(finding))}>
      <td><Badge value={finding.severity} /></td>
      <td><button className="finding-title" onClick={() => onInspect(finding)}>{finding.title}{!finding.grouped_by_title && <span>{finding.check_id}</span>}</button></td>
      <td><span className="service-cell" title={finding.service}>{finding.service}</span></td>
      <td><div className="asset-cell">
        <span title={assetLabel(finding)} className="truncate">{assetLabel(finding)}</span>
        {finding.resource_name && finding.native_resource_id && <span className="native-asset-id" title={finding.native_resource_id}>{finding.native_resource_id}</span>}
        {finding.resource_id?.startsWith("inventory:") && finding.scope && <span className="native-asset-id" title={finding.scope}>{finding.scope}</span>}
      </div></td>
      <td>{accountLabel(finding)}</td>
      <td><FindingStatusBadge status={finding.status} /></td>
    </tr>)}
    {expanded && query.data && summary.count > SERVICE_PAGE_SIZE && <tr><td colSpan={6}>
      <div className="service-page-controls">
        <span>{offset + 1}–{offset + findings.length} of {summary.count.toLocaleString()} findings</span>
        <button type="button" className="text-button" disabled={offset === 0 || query.isFetching}
          onClick={() => setOffset(Math.max(0, offset - SERVICE_PAGE_SIZE))}>Previous page</button>
        <button type="button" className="text-button" disabled={offset + findings.length >= summary.count || query.isFetching}
          onClick={() => setOffset(offset + SERVICE_PAGE_SIZE)}>Next page</button>
      </div>
    </td></tr>}
  </>;
}
function FrameworkPicker({ value, options, onChange }: {
  value: string; options: { value: string; label: string }[]; onChange: (value: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const container = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (!open) return;
    input.current?.focus();
    function closeOutside(event: PointerEvent) {
      if (!container.current?.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener("pointerdown", closeOutside);
    return () => document.removeEventListener("pointerdown", closeOutside);
  }, [open]);
  const choices = [{ value: "", label: "All compliance frameworks" }, ...options];
  const selected = choices.find(option => option.value === value)?.label || value;
  function choose(next: string) {
    onChange(next); setOpen(false); setSearch(""); trigger.current?.focus();
  }
  return <div className="framework-picker" ref={container} onKeyDown={event => {
    if (event.key === "Escape" && open) { event.stopPropagation(); setOpen(false); trigger.current?.focus(); }
  }}>
    <button ref={trigger} type="button" className="framework-trigger" aria-label="Compliance framework" aria-haspopup="listbox"
      aria-expanded={open} onClick={() => { setOpen(!open); setSearch(""); }}><span className="truncate">{selected}</span><ChevronDown size={15} aria-hidden="true" className={open ? "expanded" : ""} /></button>
    {open && <div className="framework-menu">
      <input ref={input} aria-label="Filter compliance frameworks" placeholder="Filter frameworks…" value={search} onChange={event => setSearch(event.target.value)} />
      <div role="listbox" aria-label="Compliance frameworks">
        {choices.filter(option => option.label.toLocaleLowerCase().includes(search.trim().toLocaleLowerCase())).map(option =>
          <button key={option.value} type="button" role="option" aria-selected={option.value === value} onClick={() => choose(option.value)}>{option.label}</button>)}
        {!choices.some(option => option.label.toLocaleLowerCase().includes(search.trim().toLocaleLowerCase())) && <p>No matching frameworks.</p>}
      </div>
    </div>}
  </div>;
}

export function Findings({
  scanId,
  category,
  findingType = "",
  demo,
}: {
  scanId: string;
  category: string;
  findingType?: string;
  demo: boolean;
}) {
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("FAIL");
  const [service, setService] = useState("");
  const [framework, setFramework] = useState("");
  const [sort, setSort] = useState<{ field: SortField; order: "asc" | "desc" }>();
  const catalog = useApi<Catalog>(catalogFrameworksPath, demo);
  const summary = useApi<Report>(
    `/scans/${encodeURIComponent(scanId)}/summary?aggregation=check`,
    demo,
    !!scanId,
  );
  const selectedChecklist = catalog.data?.framework_versions?.find(
    (row) => row.id === framework,
  );
  const [group, setGroup] = useState("service");
  const [expandedServices, setExpandedServices] = useState<Set<string>>(new Set());
  const [expandedService, setExpandedService] = useState<string>();
  const [inspect, setInspect] = useState<Finding>();
  const [debouncedSearch, setDebouncedSearch] = useState("");
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(search), 250);
    return () => clearTimeout(timer);
  }, [search]);
  const findingParams = new URLSearchParams({ group_by: group, aggregation: "check" });
  for (const [key, value] of Object.entries({
    categories: category, finding_type: findingType, search: debouncedSearch,
    severity, status, service, framework, sort_by: sort?.field, sort_order: sort?.order,
  })) if (value) findingParams.set(key, value);
  const findingsPath = `/scans/${encodeURIComponent(scanId)}/findings?${findingParams}`;
  const query = useInfiniteQuery({
    queryKey: [
      demo ? "demo" : "live",
      "findings",
      scanId,
      category,
      findingType,
      debouncedSearch,
      severity,
      status,
      service,
      framework,
      group,
      sort?.field,
      sort?.order,
    ],
    initialPageParam: 0,
    queryFn: ({ pageParam, signal }) => request<FindingPage>(tablePagePath(findingsPath, Number(pageParam), 200), { signal }, demo),
    getNextPageParam: (last) => last.next_offset ?? undefined,
    enabled: !!scanId,
    retry: 1,
  });
  const firstPage = query.data?.pages[0];
  const all = useMemo(
    () => query.data?.pages.flatMap((page) => items(page)) || [],
    [query.data],
  );
  const serverFiltered = typeof firstPage?.total === "number";
  const serviceGroups = serverFiltered
    ? group === "service" ? firstPage?.service_groups
      : group === "finding_type" ? firstPage?.type_groups?.map(row => ({ ...row, service: row.finding_type })) : undefined
    : undefined;
  const facets = firstPage?.facets;
  const statusFilterCounts = firstPage?.status_filter_counts;
  const statusFilterTotal = firstPage?.status_filter_total;
  const frameworkOptions = useMemo(
    () =>
      Array.from(
        new Set(
          [
            ...(catalog.data?.frameworks || []).map((row) =>
              typeof row === "string"
                ? row
                : row && typeof row === "object" && "name" in row
                  ? String(row.name)
                  : "",
            ),
            ...(facets?.frameworks || []),
            ...all.flatMap((finding) => finding.frameworks || []),
          ].filter(Boolean),
        ),
      ).sort(),
    [catalog.data?.frameworks, facets?.frameworks, all],
  );
  const complianceOptions = useMemo(() => Array.from(new Map([
    ...frameworkOptions.map(name => ({ value: name, label: name })),
    ...(catalog.data?.framework_versions || []).filter(row => row.provider === summary.data?.provider || row.provider === "all")
      .map(row => ({ value: String(row.id), label: String(row.name || row.id) })),
  ].map(option => [option.value, option])).values())
    .sort((left, right) => left.label.localeCompare(right.label, undefined, { sensitivity: "base", numeric: true }) || left.value.localeCompare(right.value)),
    [frameworkOptions, catalog.data?.framework_versions, summary.data?.provider]);
  const filtered = useMemo(
    () =>
      all
        .filter(
          (f) =>
            serverFiltered ||
            ((!category || f.category === category) &&
              (!findingType || f.finding_type === findingType) &&
              (!severity || f.severity === severity) &&
              matchesFindingStatus(f.status, status) &&
              (!service || f.service === service) &&
              (!framework || (selectedChecklist
                ? f.framework_ids?.includes(framework) ||
                  (!!selectedChecklist.name && f.frameworks?.includes(String(selectedChecklist.name)))
                : f.frameworks?.includes(framework))) &&
              `${f.title} ${f.resource_id} ${f.resource_name || ""} ${f.native_resource_id || ""} ${f.check_id} ${f.scope} ${JSON.stringify(f.evidence)}`
                .toLowerCase()
                .includes(search.toLowerCase())),
        )
        .sort((a, b) => {
          if (sort && !serverFiltered) {
            if (sort.field === "severity") {
              const rank: Record<string, number> = {
                critical: 0, high: 1, medium: 2, low: 3,
                info: 4, informational: 4,
              };
              const leftRank = rank[a.severity.toLowerCase()] ?? 5;
              const rightRank = rank[b.severity.toLowerCase()] ?? 5;
              const difference = leftRank - rightRank ||
                a.severity.localeCompare(b.severity);
              return difference * (sort.order === "asc" ? 1 : -1);
            }
            const left = sort.field === "account" ? accountLabel(a)
              : sort.field === "resource_id" ? assetLabel(a) : String(a[sort.field]);
            const right = sort.field === "account" ? accountLabel(b)
              : sort.field === "resource_id" ? assetLabel(b) : String(b[sort.field]);
            return left.localeCompare(right, undefined, { numeric: true }) *
              (sort.order === "asc" ? 1 : -1);
          }
          if (sort && serverFiltered) return 0;
          return (group === "finding_type" ? findingTypeLabel(a.finding_type) : String(a[group as keyof Finding])).localeCompare(
            group === "finding_type" ? findingTypeLabel(b.finding_type) : String(b[group as keyof Finding]),
          );
        }),
    [
      all,
      category,
      findingType,
      severity,
      status,
      service,
      framework,
      search,
      group,
      serverFiltered,
      selectedChecklist,
      sort,
    ],
  );
  const columns = useMemo(
    () => [
      col.accessor("severity", {
        header: "Severity",
        cell: (i) => <Badge value={i.getValue()} />,
      }),
      col.accessor("title", {
        header: "Finding / check",
        cell: (i) => (
          <button
            className="finding-title"
            onClick={() => setInspect(i.row.original)}
          >
            {i.getValue()}
            <span>{i.row.original.check_id}</span>
          </button>
        ),
      }),
      col.accessor("service", {
        header: "Service",
        cell: (i) => (
          <span className="service-cell" title={i.getValue()}>
            {i.getValue()}
          </span>
        ),
      }),
      col.accessor("resource_id", {
        header: "Asset",
        cell: (i) => (
          <div className="asset-cell">
            <span title={assetLabel(i.row.original)} className="truncate">
              {assetLabel(i.row.original)}
            </span>
            {i.row.original.resource_name &&
              i.row.original.native_resource_id && (
                <span
                  className="native-asset-id"
                  title={i.row.original.native_resource_id}
                >
                  {i.row.original.native_resource_id}
                </span>
              )}
            {/* Collection-level rows ("inventory:<type>") repeat per region;
                the scope is what tells them apart. */}
            {i.row.original.resource_id?.startsWith("inventory:") &&
              i.row.original.scope && (
                <span className="native-asset-id" title={i.row.original.scope}>
                  {i.row.original.scope}
                </span>
              )}
          </div>
        ),
      }),
      col.display({
        id: "account",
        header: "Account",
        cell: (i) => accountLabel(i.row.original),
      }),
      col.accessor("status", {
        header: "Status",
        cell: (i) => <FindingStatusBadge status={i.getValue()} />,
      }),
    ],
    [],
  );
  const table = useReactTable({
    data: filtered,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });
  const rows = table.getRowModel().rows;
  const groupedServices = group === "service" || group === "finding_type";
  const visibleRows = useMemo(() => {
    if (serviceGroups) return [];
    if (!groupedServices) return rows.map((row) => ({ kind: "finding" as const, row }));
    const services = new Map<string, typeof rows>();
    for (const row of rows) {
      const name = group === "finding_type" ? findingTypeLabel(row.original.finding_type) : row.original.service || "Unknown service";
      if (!services.has(name)) services.set(name, []);
      services.get(name)!.push(row);
    }
    return [...services].sort(([left], [right]) => left.localeCompare(right)).flatMap(([name, findings]) => [
      { kind: "service" as const, name, findings },
      ...(expandedServices.has(name) ? findings.map((row) => ({ kind: "finding" as const, row })) : []),
    ]);
  }, [rows, group, groupedServices, expandedServices, serviceGroups]);
  const sortableColumns: Record<string, SortField> = {
    severity: "severity", title: "title", service: "service",
    resource_id: "resource_id", account: "account", status: "status",
  };
  const parent = useRef<HTMLDivElement>(null);
  const virtual = useVirtualizer({
    count: visibleRows.length,
    getScrollElement: () => parent.current,
    estimateSize: (index) => visibleRows[index]?.kind === "service" ? 58 : 87,
    overscan: 8,
  });
  const lastVisible = virtual.getVirtualItems().at(-1)?.index ?? -1;
  const browsingKey = JSON.stringify([scanId, category, findingType, debouncedSearch, severity, status, service, framework, group, sort]);
  const serviceScopeKey = JSON.stringify([scanId, category, findingType, debouncedSearch, severity, status, service, framework, group]);
  useEffect(() => setExpandedServices(new Set()), [browsingKey]);
  useEffect(() => setExpandedService(undefined), [serviceScopeKey]);
  useEffect(() => {
    if (parent.current) parent.current.scrollTop = 0;
    virtual.scrollToOffset(0);
  }, [browsingKey]);
  useEffect(() => {
    if (!serverFiltered || !query.hasNextPage || query.isFetching || query.isFetchNextPageError ||
        groupedServices || all.length < 20 || lastVisible < visibleRows.length - 20) return;
    void query.fetchNextPage({ cancelRefetch: false });
  }, [serverFiltered, query.hasNextPage, query.isFetching, query.isFetchNextPageError, groupedServices, all.length, visibleRows.length, lastVisible, query.fetchNextPage]);
  return (
    <>
      <div className="section-top">
        <p>Configuration findings, grounded in collected evidence.</p>
        <span className="count-pill">
          {serviceGroups
            ? `${firstPage?.total || 0} findings across ${serviceGroups.length} ${group === "finding_type" ? "types" : "services"}`
            : `${filtered.length} / ${firstPage?.total ?? all.filter((f) => !category || f.category === category).length} findings`}
        </span>
      </div>
      {selectedChecklist && (
        <div className="notice">
          <p>
            Selected checklist: {String(selectedChecklist.name)}. Findings are filtered across the complete assessment.
          </p>
        </div>
      )}
      <Panel className="findings-panel">
        <div className="filters">
          <div className="search-field">
            <Search size={17} />
            <input
              aria-label="Search findings"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search assets, checks and metadata…"
            />
          </div>
          <label className="compact-label">
            <span className="sr-only">Severity</span>
            <select
              aria-label="Severity"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              <option value="">All severities</option>
              {["critical", "high", "medium", "low", "info"].map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
          <select
            aria-label="Status"
            value={status}
            onChange={(e) => setStatus(e.target.value)}
          >
            <option value="">All statuses{statusFilterTotal !== undefined ? ` (${statusFilterTotal.toLocaleString()})` : ""}</option>
            {findingStatusOptions.map(({ value, label }) => (
              <option key={value} value={value}>{label}{statusFilterCounts?.[value] !== undefined ? ` (${statusFilterCounts[value].toLocaleString()})` : ""}</option>
            ))}
          </select>
          <select
            aria-label="Service"
            value={service}
            onChange={(e) => setService(e.target.value)}
          >
            <option value="">All services</option>
            {Array.from(
              new Set([
                ...(facets?.services || []),
                ...all.map((f) => f.service),
              ]),
            )
              .sort()
              .map((s) => (
                <option key={s}>{s}</option>
              ))}
          </select>
        </div>
        <div className="filter-secondary">
          <SlidersHorizontal size={15} />
          <FrameworkPicker value={framework} options={complianceOptions} onChange={setFramework} />
          <button className="text-button" onClick={() => {
            setFramework("HackTricks Cloud Best Practices"); setStatus("FAIL");
          }}>Show security failed</button>
          <label>
            Group by{" "}
            <select
              aria-label="Group findings"
              value={group}
              onChange={(e) => setGroup(e.target.value)}
            >
              <option value="service">Service</option>
              <option value="check_id">Check</option>
              <option value="finding_type">Type</option>
            </select>
          </label>
          <button
            className="text-button"
            onClick={() => {
              setSearch("");
              setSeverity("");
              setStatus("FAIL");
              setService("");
              setFramework("");
            }}
          >
            Reset filters
          </button>
          <TableDownload table={findingType === "detected_leaks" ? "leaks" : `${category || "assessment"}-findings`}
            label="findings table" disabled={!scanId || query.isPending || !!query.error || search !== debouncedSearch}
            loadRows={async signal => {
              const matches = demo || !serverFiltered ? filtered :
                await requestTableRows<Finding>(findingsPath, "items", 200, signal);
              return matches.map(row => ({
                id: row.id, severity: row.severity, title: row.title, check_id: row.check_id,
                service: row.service, provider: row.provider, scope: row.scope, status: row.status,
                asset: assetLabel(row), account: accountLabel(row), resource_id: row.resource_id,
                native_resource_id: row.native_resource_id, resource_name: row.resource_name,
                finding_type: row.finding_type, finding_type_label: findingTypeLabel(row.finding_type),
                affected_asset_count: row.affected_asset_count, affected_accounts: row.affected_accounts,
                affected_regions: row.affected_regions, affected_scopes: row.affected_scopes,
                observation_count: row.member_count, status_counts: row.status_counts,
              }));
            }} />
        </div>
        {!scanId ? (
          <State empty title="Select a scan to review evidence" />
        ) : (
          <State
            loading={query.isPending}
            error={query.error && !query.data ? query.error : undefined}
            onRetry={() => void query.refetch()}
          >
            <div
              className="table-scroll"
              ref={parent}
              role="region"
              aria-label="Findings table"
              tabIndex={0}
            >
              <table className={`findings-table${serviceGroups ? " findings-table-service-overview" : ""}`}>
                <thead>
                  {table.getHeaderGroups().map((g) => (
                    <tr key={g.id}>
                      {g.headers.map((h) => (
                        <th key={h.id} aria-sort={sort?.field === sortableColumns[h.id]
                          ? sort.order === "asc" ? "ascending" : "descending"
                          : "none"}>
                          <button className="text-button" type="button" onClick={() => {
                            const field = sortableColumns[h.id];
                            setSort((current) => ({
                              field,
                              order: current?.field === field && current.order === "asc" ? "desc" : "asc",
                            }));
                          }}>
                            {flexRender(h.column.columnDef.header, h.getContext())}
                          </button>
                        </th>
                      ))}
                    </tr>
                  ))}
                </thead>
                <tbody>
                  {serviceGroups?.map(summary => <ServiceSection
                    key={`${browsingKey}-${summary.service}`} summary={summary} groupBy={group === "finding_type" ? "finding_type" : "service"} scanId={scanId} category={category} findingType={findingType}
                    demo={demo} search={debouncedSearch} severity={severity} status={status}
                    framework={framework} sort={sort} expanded={expandedService === summary.service}
                    onToggle={() => setExpandedService(current => current === summary.service ? undefined : summary.service)}
                    onInspect={setInspect}
                  />)}
                  {virtual.getVirtualItems().length > 0 && (
                    <tr aria-hidden="true">
                      <td
                        colSpan={6}
                        style={{
                          height: virtual.getVirtualItems()[0]?.start || 0,
                          padding: 0,
                        }}
                      />
                    </tr>
                  )}
                  {virtual.getVirtualItems().map((v) => {
                    const item = visibleRows[v.index];
                    if (item.kind === "service") {
                      const counts = item.findings.reduce((result, finding) => {
                        result[finding.original.status] = (result[finding.original.status] || 0) + 1;
                        return result;
                      }, {} as Record<string, number>);
                      return <tr key={`service-${item.name}`} className="service-group-row"><td colSpan={6}>
                        <button type="button" className="service-group-button" aria-expanded={expandedServices.has(item.name)}
                          onClick={() => setExpandedServices((current) => {
                            const next = new Set(current);
                            if (next.has(item.name)) next.delete(item.name); else next.add(item.name);
                            return next;
                          })}>
                          <ChevronRight size={16} className={expandedServices.has(item.name) ? "expanded" : ""} />
                          <strong>{item.name}</strong>
                          <span>{item.findings.length} findings{query.hasNextPage ? " loaded" : ""}</span>
                          {findingStatusCounts(counts).map(({ label, count }) => <span key={label}>{count} {label.toLowerCase()}</span>)}
                        </button>
                      </td></tr>;
                    }
                    const row = item.row;
                    const current = String(
                      row.original[group as keyof Finding],
                    );
                    const previous =
                      !groupedServices && v.index > 0
                        ? String(
                            rows[v.index - 1].original[group as keyof Finding],
                          )
                        : "";
                    return (
                      <tr key={row.id} className="finding-data-row" style={{ height: 87 }}
                        onClick={event => openInspectorFromRow(event, () => setInspect(row.original))}>
                        {row.getVisibleCells().map((cell, index) => (
                          <td key={cell.id}>
                            {index === 1 && !groupedServices && !sort && current !== previous && (
                              <span className="group-label">
                                {current}
                              </span>
                            )}
                            {flexRender(
                              cell.column.columnDef.cell,
                              cell.getContext(),
                            )}
                          </td>
                        ))}
                      </tr>
                    );
                  })}
                  {virtual.getVirtualItems().length > 0 && (
                    <tr aria-hidden="true">
                      <td
                        colSpan={6}
                        style={{
                          height: Math.max(
                            0,
                            virtual.getTotalSize() -
                              (virtual.getVirtualItems().at(-1)?.end || 0),
                          ),
                          padding: 0,
                        }}
                      />
                    </tr>
                  )}
                </tbody>
              </table>
              {!(serviceGroups ? serviceGroups.length : rows.length) && (
                <div className="state">
                  <Search />
                  <h3>
                    {all.length ||
                    search ||
                    severity ||
                    status ||
                    service ||
                    framework
                      ? "No findings match these filters"
                      : "No findings recorded"}
                  </h3>
                  <p>
                    {all.length ||
                    search ||
                    severity ||
                    status ||
                    service ||
                    framework
                      ? "Try another search or reset your filters."
                      : "Review scan coverage before drawing a security conclusion."}
                  </p>
                </div>
              )}
            </div>
            {serverFiltered && !serviceGroups && (
              <div className="pagination-footer">
                <span>
                  {all.length} loaded of {firstPage?.total} matching findings ·
                  {groupedServices && query.hasNextPage
                    ? " Load more to complete service groups"
                    : " Filters search the complete assessment"}
                </span>
                {query.hasNextPage && (
                  <button
                    className="button"
                    disabled={query.isFetchingNextPage}
                    onClick={() => void query.fetchNextPage({ cancelRefetch: false })}
                  >
                    {query.isFetchingNextPage
                      ? "Loading more…"
                      : "Load more findings"}
                  </button>
                )}
                {query.isFetchNextPageError && (
                  <span role="alert">
                    More results could not be loaded.{" "}
                    <button
                      className="text-button"
                      onClick={() => void query.fetchNextPage({ cancelRefetch: false })}
                    >
                      Retry
                    </button>
                  </span>
                )}
              </div>
            )}
          </State>
        )}
      </Panel>
      {inspect && (
        <FindingInspector
          finding={inspect}
          scanId={scanId}
          demo={demo}
          lazy={!demo}
          onClose={() => setInspect(undefined)}
          onInspectMember={setInspect}
        />
      )}
    </>
  );
}
// Keep the full evidence export intact; the preview omits absent collector fields.
function evidencePreview(value: unknown): unknown {
  if (value == null || value === "Not supplied") return undefined;
  if (Array.isArray(value)) return value.map(evidencePreview).filter((item) => item !== undefined);
  if (typeof value === "object") return Object.fromEntries(Object.entries(value)
    .map(([key, item]) => [key, evidencePreview(item)] as const)
    .filter(([, item]) => item !== undefined));
  return value;
}
export function FindingInspector({
  finding,
  scanId,
  demo,
  lazy,
  onClose,
  onInspectMember,
}: {
  finding: Finding;
  scanId: string;
  demo: boolean;
  lazy: boolean;
  onClose: () => void;
  onInspectMember: (finding: Finding) => void;
}) {
  const detail = useApi<Finding>(
    finding.grouped ? findingGroupPath(scanId, finding)
      : `/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(finding.id)}`,
    demo,
    lazy && !demo,
  );
  const observed = detail.data || finding;
  const combinedTitle = observed.grouped_by_title && (observed.member_count || 0) > 1;
  const internetExposure = observed.check_id === "analysis.internet_exposure";
  const allowCurrentSummary = observed.guidance_refresh?.allow_summary !== false;
  const exposure = internetExposure && allowCurrentSummary ? explainInternetExposure(observed.evidence, observed.status) : undefined;
  const observation = !allowCurrentSummary
    ? observed.evidence_summary || `Recorded result: ${observed.status}. Review the original technical evidence below.`
    : observed.evidence_summary || (internetExposure ? exposure?.summary : undefined)
      || explainAzureNativeEvidenceObservation(observed.check_id, observed.evidence, observed.status)
      || explainAzureFindingEvidence(observed.check_id, observed.evidence, observed.status)
      || explainGcpFindingEvidence(observed.check_id, observed.evidence, observed.status)
      || explainFindingEvidence(observed.evidence, observed.status, observed.check_id).replace(/^Observed evidence:\s*/i, "");
  const evidenceSummary = observed.ai_review?.reason || explainObservedEvidence(observed, observation);
  const exposureAction = internetExposure && allowCurrentSummary ? explainExposureAction(observed.evidence, observed.status) : undefined;
  const remediationDetails = exposureAction && observed.remediation_details
    ? { ...observed.remediation_details, summary: exposureAction, steps: [exposureAction] }
    : observed.remediation_details;
  const asset = assetLabel(observed);
  const scopeAsset = asset === observed.scope || asset === `scope:${observed.scope}`;
  const technicalEvidence = evidencePreview(observed.evidence);
  const hasTechnicalEvidence = technicalEvidence !== undefined &&
    (typeof technicalEvidence !== "object" || Object.keys(technicalEvidence as object).length > 0);
  const definition = <>
    <p>{internetExposure && allowCurrentSummary ? explainExposureCheck(observed.evidence) : observed.description}</p>
    {(observed.evaluated?.length || observed.pass_when || observed.fail_when || observed.not_applicable_when || observed.remediation_details?.caveats?.length) ? <details className="finding-evaluation-details">
      <summary>Evaluation details</summary>
      {Array.isArray(observed.evaluated) && observed.evaluated.length > 0 && <>
        <h4>Fields read</h4>
        <ul>{observed.evaluated.map((field, index) => <li key={`${field}-${index}`}>{field}</li>)}</ul>
      </>}
      <dl>
        {observed.pass_when && <><dt>Pass</dt><dd>{observed.pass_when}</dd></>}
        {observed.fail_when && <><dt>Fail</dt><dd>{observed.fail_when}</dd></>}
        {observed.not_applicable_when && <><dt>Not applicable</dt><dd>{observed.not_applicable_when}</dd></>}
      </dl>
      {observed.remediation_details?.caveats?.length ? <><h4>Limitations</h4><ul>{observed.remediation_details.caveats.map((caveat, index) => <li key={index}>{caveat}</li>)}</ul></> : null}
    </details> : null}
  </>;
  return (
    <Inspector title="Finding details" className="finding-inspector" onClose={onClose}>
      <div className="finding-detail">
        <header className="finding-detail-hero">
          <div className="inspector-badges">
            <Badge value={observed.severity} />
            <FindingStatusBadge status={observed.status} />
            <span className="badge service">{observed.service}</span>
          </div>
          <h3>{observed.title}</h3>
          <p className="finding-detail-location">{observed.service} · {observed.grouped ? [observed.affected_accounts?.join(", "), observed.affected_regions?.length
            ? `${observed.affected_regions.length} ${observed.affected_regions.length === 1 ? "Region" : "Regions"}`
            : observed.affected_scopes?.every(scope => scope.endsWith("/global")) ? "Global" : ""].filter(Boolean).join(" · ") || "Selected scopes" : observed.scope}</p>
          {!observed.grouped && !scopeAsset && <p className="finding-detail-asset"><span>Asset</span> <strong>{asset}</strong></p>}
        </header>
        <State loading={lazy && !demo && detail.isPending}
          error={lazy && !demo ? detail.error : undefined} onRetry={() => void detail.refetch()}>
          <section className="finding-detail-section finding-detail-observation">
            <h3>Observed evidence</h3>
            {observed.grouped ? <GroupedFindingEvidence key={observed.id + JSON.stringify(observed.member_filters)}
              finding={observed} scanId={scanId} demo={demo} onInspectMember={member =>
                onInspectMember({ ...observed, ...member, grouped: false, grouped_by_title: false,
                  check_id: member.check_id || observed.check_id, title: member.title || observed.title,
                  service: member.service || observed.service, resource_id: member.resource_id || member.asset,
                  resource_name: member.resource_name, native_resource_id: member.native_resource_id,
                  evidence: undefined, evidence_summary: member.evidence_summary })} /> : <p>{evidenceSummary}</p>}
            {!allowCurrentSummary && observed.guidance_refresh?.message && <p className="muted">{observed.guidance_refresh.message}</p>}
            {internetExposure && observed.status === "UNKNOWN" && !!exposure?.reasons.length && <ul>{exposure.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}
          </section>
          {!observed.grouped && observed.check_id === "analysis.exposed_container_cves" && !!observed.evidence &&
            <ContainerExposureEvidence evidence={observed.evidence as unknown as ContainerExposureEvidence} />}
          {!observed.grouped && <AccessAnalyzerUnusedEvidence key={observed.id} finding={observed} />}
          {observed.secret_evidence?.status === "available" ? <PrivateSecretEvidence key={observed.id} finding={observed} scanId={scanId} />
            : <>{observed.secret_evidence && <PrivateSecretEvidence key={observed.id} finding={observed} scanId={scanId} />}
              <FoundSecretValues evidence={observed.evidence} /></>}
          <section className="finding-detail-section">
            <h3>What to do</h3>
            {combinedTitle ? <p>Open an affected asset above to review its evidence and remediation.</p> :
              <Remediation legacy={exposureAction || observed.remediation} details={remediationDetails} compact />}
          </section>
          <div className="finding-detail-extras">
            {!combinedTitle && (internetExposure || observed.description || observed.evaluated?.length || observed.pass_when || observed.fail_when || observed.not_applicable_when || observed.remediation_details?.caveats?.length) ? <details>
              <summary>How this check works</summary>
              <div className="finding-detail-extra-body">{definition}</div>
            </details> : null}
            {hasTechnicalEvidence && <details>
              <summary>Technical evidence details</summary>
              <div className="finding-detail-extra-body"><Evidence data={observed.evidence} previewData={technicalEvidence} /></div>
            </details>}
            {!combinedTitle && <details>
              <summary>Identifiers &amp; frameworks</summary>
              <dl className="finding-detail-metadata">
                <dt>Check ID</dt><dd>{observed.check_id}</dd>
                <dt>Report resource ID</dt><dd>{observed.resource_id}</dd>
                {observed.native_resource_id && observed.native_resource_id !== observed.resource_id && <><dt>Native ID</dt><dd>{observed.native_resource_id}</dd></>}
                <dt>Scope</dt><dd>{observed.scope}</dd>
                <dt>Frameworks</dt><dd>{observed.frameworks?.join(" · ") || "No framework mapping"}</dd>
              </dl>
            </details>}
          </div>
        </State>
      </div>
    </Inspector>
  );
}
