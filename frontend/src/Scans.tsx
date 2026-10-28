import { useRef, useState } from "react";
import type { FormEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import {
  CalendarClock,
  Download,
  LoaderCircle,
  Play,
  Square,
  Trash2,
  Eye,
  Plus,
} from "lucide-react";
import { categories } from "./types";
import type { Catalog, Connector, Scan, Schedule } from "./types";
import { catalogFrameworksPath, downloadReport, items, json, request, useApi } from "./api";
import { Badge, date, Evidence, humanError, Inspector, Panel, State } from "./ui";
import { CoverageView } from "./Dashboard";
import { scanDuration } from "./scanDuration";
import { scanNames } from "./scanNames";
import { defaultRule, ScheduleRules, scheduleDescription, nextScheduleDate } from "./ScheduleRules";
import type { ScheduleRule } from "./types";
type FrameworkChoice = { value: string; label: string; group: "family" | "version" };
function frameworkChoices(catalog: Catalog | undefined, provider: Connector["provider"] | undefined): FrameworkChoice[] {
  if (!provider) return [];
  const versions = (catalog?.framework_versions || []).filter((row) =>
    row.provider === provider || row.provider === "all");
  const families = new Set<string>();
  for (const row of versions) {
    if (typeof row.family === "string" && row.family.trim()) families.add(row.family);
  }
  const choices: FrameworkChoice[] = [
    { value: "HackTricks Cloud Best Practices", label: "HackTricks Cloud Best Practices", group: "family" },
    ...[...families].sort((a, b) => a.localeCompare(b)).map((family) => ({
      value: family, label: `${family.replaceAll("-", " ")} · all versions`, group: "family" as const,
    })),
    ...versions.filter((row) => typeof row.id === "string").map((row) => ({
      value: String(row.id), label: `${String(row.name || row.id)} · ${String(row.status || "unknown")} · ${String(row.supported_native_checks ?? 0)} native checks`, group: "version" as const,
    })).sort((a, b) => a.label.localeCompare(b.label)),
  ];
  return choices;
}
export const terminalStatuses = [
  "completed",
  "failed",
  "cancelled",
  "timed_out",
  "queue_exhausted",
  "credentials_expired",
];
const hasResults = (scan: Scan) => scan.status === "completed" || scan.result_available === true;
const analysisIds = new Set(["exposure", "least_privilege", "iam_graph", "network", "privesc"]);
const hardeningCategories = categories.filter((category) => !analysisIds.has(category.id));
const analysisCategories = categories.filter((category) => analysisIds.has(category.id));
function ScanCategories({ selected = [] }: { selected?: string[] }) {
  const [expanded, setExpanded] = useState(false);
  const all = categories.every(category => selected.includes(category.id));
  if (all) return <div className="scan-categories"><span>All checks</span></div>;
  return <div className="scan-categories">
    {(expanded ? selected : selected.slice(0, 5)).map(category => <span key={category}>{category.replaceAll("_", " ")}</span>)}
    {selected.length > 5 && <button type="button" className="text-button" aria-expanded={expanded}
      onClick={() => setExpanded(!expanded)}>{expanded ? "Show less" : `+${selected.length - 5} more`}</button>}
  </div>;
}

export function Scans({
  demo,
  canWrite = true,
  onSelect,
}: {
  demo: boolean;
  canWrite?: boolean;
  onSelect: (scan: Scan) => void;
}) {
  const scansQuery = useApi<{ items: Scan[] }>("/scans", demo, true, true);
  const connectorsQuery = useApi<{ items: Connector[] }>("/connectors", demo);
  const schedulesQuery = useApi<{ items: Schedule[] }>("/schedules", demo);
  const frameworkCatalog = useApi<Catalog>(catalogFrameworksPath, demo, true);
  const client = useQueryClient();
  const names = scanNames(items(scansQuery.data), items(connectorsQuery.data));
  const [launch, setLaunch] = useState(false);
  const [schedule, setSchedule] = useState<Schedule | null | undefined>();
  const [inspected, setInspect] = useState<Scan>();
  // The list is polled; show the latest state of the scan whose details are open.
  const inspect = inspected && (items(scansQuery.data).find((s) => s.id === inspected.id) ?? inspected);
  const [remove, setRemove] = useState<Scan>();
  const [error, setError] = useState("");
  function refresh() {
    void client.invalidateQueries({ queryKey: [demo ? "demo" : "live"] });
  }
  const resume = useMutation({
    mutationFn: (id: string) => request<Scan>(`/scans/${encodeURIComponent(id)}/resume`, json({}), demo),
    onSuccess: value => { if (inspect?.id === value.id) setInspect(value); refresh(); },
    onError: error => setError(humanError(error)),
  });
  const cancel = useMutation({
    mutationFn: (id: string) =>
      request(`/scans/${encodeURIComponent(id)}/cancel`, json({}), demo),
    onSuccess: refresh,
    onError: (e) => setError(e.message),
  });
  const deleteScan = useMutation({
    mutationFn: (id: string) => request(`/scans/${encodeURIComponent(id)}`, { method: "DELETE" }, demo),
    onSuccess: () => { setRemove(undefined); setInspect(undefined); refresh(); },
  });
  const updateSchedule = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      request(
        `/schedules/${encodeURIComponent(id)}`,
        json({ enabled }, "PATCH"),
        demo,
      ),
    onSuccess: refresh,
    onError: (e) => setError(e.message),
  });
  const deleteSchedule = useMutation({
    mutationFn: (id: string) =>
      request(
        `/schedules/${encodeURIComponent(id)}`,
        { method: "DELETE" },
        demo,
      ),
    onSuccess: refresh,
    onError: (e) => setError(e.message),
  });
  async function download(scan: Scan, format: string) {
    try {
      setError("");
      await downloadReport(scan.id, format, demo);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Download failed");
    }
  }
  return (
    <>
      <div className="section-top">
        <p>Run an assessment. Keep every result tied to its snapshot.</p>
        <button
          className="button primary"
          disabled={demo || !canWrite}
          onClick={() => setLaunch(true)}
        >
          <Play size={16} />
          Launch scan
        </button>
      </div>
      {error && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}
      <Panel
        title="Scan history"
        kicker="ASSESSMENTS"
        action={
          <span className="count-pill">
            {items(scansQuery.data).length} scans
          </span>
        }
      >
        <State
          loading={scansQuery.isPending}
          error={scansQuery.error}
          onRetry={() => void scansQuery.refetch()}
          empty={
            !scansQuery.isPending &&
            !scansQuery.error &&
            !items(scansQuery.data).length
          }
          title="Your first scan starts here"
        />
        <div className="card-list">
          {items(scansQuery.data).map((s) => (
            <article className="scan-row" key={s.id}>
              <div
                className={`scan-symbol ${s.status === "completed" ? "done" : ""}`}
              >
                {terminalStatuses.includes(s.status) ? <Play size={16} />
                  : <LoaderCircle size={16} className="spin" aria-label="Scan in progress" />}
              </div>
              <div className="grow">
                <button
                  className="text-button scan-id"
                  onClick={() => setInspect(s)}
                >
                  {names.get(s.id)}
                </button>
                <p>
                  {[items(connectorsQuery.data).find(
                    (c) => c.id === s.connector_id,
                  )?.name, date(s.created_at), scanDuration(s)].filter(Boolean).join(" · ")}
                </p>
                {["failed", "queue_exhausted", "credentials_expired"].includes(s.status) && s.error && (
                  <p role="alert">{humanError(s.error)}</p>
                )}
                {s.progress_details && !terminalStatuses.includes(s.status) && <p className="scan-progress" aria-label="Latest scan progress">
                  {(s.progress_details.phase || "collecting").replaceAll("_", " ")}
                  {s.progress_details.completed != null && ` · ${s.progress_details.completed}${s.progress_details.total != null ? ` / ${s.progress_details.total}` : ""} completed`}
                  {s.progress_details.resources != null && ` · ${s.progress_details.resources} resources`}
                  {s.progress_details.at && <> · Last update <time dateTime={s.progress_details.at}>{date(s.progress_details.at)}</time></>}
                </p>}
                <ScanCategories selected={s.categories} />
              </div>
              <Badge value={s.status} />
              {s.input_mode && s.input_mode !== "live" && (
                <Badge value={s.input_mode} />
              )}
              <div className="scan-actions" aria-label={`Actions for ${names.get(s.id)}`}>
                {hasResults(s) && (
                  <>
                  <button className="icon-button" aria-label={s.status === "completed" ? "Open results" : "Open partial results"}
                    title={s.status === "completed" ? "Open results" : "Open partial results"} onClick={() => onSelect(s)}>
                    <Eye size={17} />
                  </button>
                  <button
                    className="icon-button"
                    aria-label={`Download JSON ${s.id}`}
                    onClick={() => void download(s, "json")}
                  >
                    <Download size={17} />
                  </button>
                </>
              )}
              {s.resumable && terminalStatuses.includes(s.status) && <button className="icon-button" aria-label="Resume scan" title="Resume scan"
                disabled={demo || !canWrite || resume.isPending} onClick={() => resume.mutate(s.id)}>
                <Play size={15} />
              </button>}
              {!terminalStatuses.includes(s.status) && (
                  <button
                    className="icon-button"
                    aria-label={`Cancel scan ${names.get(s.id)}`}
                    title="Cancel scan"
                    disabled={cancel.isPending || demo || !canWrite}
                    onClick={() => cancel.mutate(s.id)}
                  >
                    <Square size={13} />
                  </button>
                )}
                <button className="icon-button danger scan-action-delete" aria-label={`Delete scan ${names.get(s.id)}`}
                disabled={demo || !canWrite || !terminalStatuses.includes(s.status)}
                title={terminalStatuses.includes(s.status) ? "Delete scan and its evidence" : "Cancel this scan before deleting it"}
                  onClick={() => { deleteScan.reset(); setRemove(s); }}><Trash2 size={17} /></button>
              </div>
            </article>
          ))}
        </div>
      </Panel>
      <Panel
        title="Scheduled assessments"
        kicker="STAY CURRENT"
        action={
          <button
            className="button"
            disabled={demo || !canWrite}
            onClick={() => setSchedule(null)}
          >
            <Plus size={16} />
            Add schedule
          </button>
        }
      >
        <State
          loading={schedulesQuery.isPending}
          error={schedulesQuery.error}
          onRetry={() => void schedulesQuery.refetch()}
        >
          <>
            {items(schedulesQuery.data).length ? (
              items(schedulesQuery.data).map((s) => (
                <article className="scan-row" key={s.id}>
                  <div className="scan-symbol">
                    <CalendarClock size={18} />
                  </div>
                  <div className="grow">
                    <button
                      className="text-button"
                      disabled={demo || !canWrite}
                      onClick={() => setSchedule(s)}
                    >
                      {s.name ||
                        items(connectorsQuery.data).find(
                          (c) => c.id === s.connector_id,
                        )?.name ||
                        s.id}
                    </button>
                    <p>
                      {scheduleDescription(s)} · Next{" "}
                      {nextScheduleDate(s)}
                    </p>
                    {s.last_error && <p className="form-error small">{s.last_error}</p>}
                  </div>
                  <button
                    className="button"
                    disabled={demo || !canWrite || updateSchedule.isPending}
                    onClick={() =>
                      updateSchedule.mutate({ id: s.id, enabled: !s.enabled })
                    }
                  >
                    {s.enabled ? "Pause" : "Resume"}
                  </button>
                  <button
                    className="icon-button danger"
                    disabled={demo || !canWrite || deleteSchedule.isPending}
                    aria-label={`Delete schedule ${s.id}`}
                    onClick={() => deleteSchedule.mutate(s.id)}
                  >
                    <Trash2 size={17} />
                  </button>
                </article>
              ))
            ) : (
              <div className="compact-empty">
                <CalendarClock />
                <div>
                  <h3>No schedules yet</h3>
                  <p>Create a recurring scan within your account quota.</p>
                </div>
              </div>
            )}
          </>
        </State>
      </Panel>
      {remove && <Inspector title="Delete scan" onClose={() => setRemove(undefined)}>
        <p>Permanently delete “{names.get(remove.id)}” and all its stored evidence? This cannot be undone.</p>
        {deleteScan.error && <p role="alert">{humanError(deleteScan.error)}</p>}
        <button className="button danger" disabled={deleteScan.isPending} onClick={() => deleteScan.mutate(remove.id)}>
          {deleteScan.isPending ? "Deleting…" : "Delete scan"}</button>
      </Inspector>}
      {launch && (
        <LaunchForm
          demo={demo}
          connectors={items(connectorsQuery.data)}
          connectorError={connectorsQuery.error}
          catalog={{ data: frameworkCatalog.data, isPending: frameworkCatalog.isPending, error: frameworkCatalog.error }}
          onClose={() => setLaunch(false)}
        />
      )}
      {schedule !== undefined && (
        <LaunchForm
          demo={demo}
          connectors={items(connectorsQuery.data)}
          connectorError={connectorsQuery.error}
          catalog={{ data: frameworkCatalog.data, isPending: frameworkCatalog.isPending, error: frameworkCatalog.error }}
          schedule={schedule}
          onClose={() => setSchedule(undefined)}
        />
      )}
      {inspect && (
        <Inspector title="Scan details" onClose={() => setInspect(undefined)}>
          <p>{names.get(inspect.id)}</p>
          <Badge value={inspect.status} />
          {scanDuration(inspect) && <p title="Total time from launch, including queue and processing time.">{scanDuration(inspect)}</p>}
          {["failed", "credentials_expired", "timed_out"].includes(inspect.status) && inspect.error && (
            <p role="alert">{humanError(inspect.error)}</p>
          )}
          {inspect.resumable && terminalStatuses.includes(inspect.status) && <div className="scan-resume-choice">
            <p className="muted small">Continue the unfinished work with the connector’s current credentials. Saved results stay in this scan.</p>
            <button className="button primary" disabled={demo || !canWrite || resume.isPending}
              onClick={() => resume.mutate(inspect.id)}>{resume.isPending ? "Resuming…" : "Resume from saved progress"}</button>
            {resume.error && <p role="alert">{humanError(resume.error)}</p>}
          </div>}
          <h3>Recorded scan details</h3>
          <Evidence data={inspect} />
          {hasResults(inspect) && (
            <>
            <Panel title="Coverage & limitations">
              <CoverageView scanId={inspect.id} demo={demo} />
            </Panel>
            <CatalogSupport catalog={frameworkCatalog.data} loading={frameworkCatalog.isPending} error={frameworkCatalog.error} />
            <div className="button-row">
              <button
                className="button primary"
                onClick={() => {
                  onSelect(inspect);
                  setInspect(undefined);
                }}
              >
                Review findings
              </button>
              <button
                className="button"
                onClick={() => void download(inspect, "markdown")}
              >
                Download Markdown
              </button>
            </div>
            </>
          )}
        </Inspector>
      )}
    </>
  );
}

function CatalogSupport({ catalog, loading, error }: { catalog?: Catalog; loading: boolean; error: Error | null }) {
  const versions = [...new Map((catalog?.framework_versions || [])
    .filter(row => row && typeof row === "object" && typeof row.id === "string")
    .map(row => [String(row.id), row] as const)).values()]
    .map(row => ({
      id: String(row.id), name: String(row.name || row.id),
      notAssessed: Number((row.requirements_by_status as Record<string, unknown> | undefined)?.not_assessed),
    }))
    .filter(row => Number.isSafeInteger(row.notAssessed) && row.notAssessed > 0);
  return <Panel title="Catalog support (global)">
    <p className="muted small">These checklist requirements do not have an automated check yet.</p>
    {loading && <p role="status">Loading catalog support…</p>}
    {error && <p role="alert">Catalog support could not be loaded.</p>}
    {!loading && !error && (versions.length ? <details><summary>{versions.length} checklist versions with Not assessed requirements</summary><ul className="coverage-list">{versions.map(row => <li key={row.id} className="coverage-row"><strong>{row.name}</strong><span>Not assessed · {row.notAssessed.toLocaleString()} requirements</span></li>)}</ul></details> : <p className="muted">No Not assessed requirement counts are supplied by the current catalog.</p>)}
  </Panel>;
}
export function LaunchForm({
  demo,
  connectors,
  connectorError,
  catalog,
  onClose,
  schedule,
  initialConnectorId,
}: {
  demo: boolean;
  connectors: Connector[];
  connectorError: unknown;
  catalog: { data?: Catalog; isPending: boolean; error: unknown };
  onClose: () => void;
  schedule?: Schedule | null;
  initialConnectorId?: string;
}) {
  const client = useQueryClient();
  const [connector, setConnector] = useState(
    schedule?.connector_id || initialConnectorId || connectors[0]?.id || "",
  );
  const [selected, setSelected] = useState<string[]>(
    schedule?.categories || categories.map((c) => c.id),
  );
  const [aiEnabled, setAiEnabled] = useState(schedule?.ai_enabled ?? true);
  const [aiPrioritiesEnabled, setAiPrioritiesEnabled] = useState(schedule?.ai_priorities_enabled ?? true);
  const [aiNetworkEnabled, setAiNetworkEnabled] = useState(schedule?.ai_network_enabled ?? true);
  const codex = useApi<{ available: boolean; disabled?: boolean; isolation_available?: boolean }>("/ai/codex", demo);
  const aiAvailable = !demo && codex.data?.available === true;
  const [checks, setChecks] = useState(schedule?.checks?.join(", ") || "");
  const [leaksEnabled, setLeaksEnabled] = useState(schedule ? (schedule.content_checks || []).some(id => !id.includes("vulnerabil")) : true);
  const [imagesEnabled, setImagesEnabled] = useState(schedule ? (schedule.content_checks || []).some(id => id.includes("vulnerabil")) : true);
  const [frameworks, setFrameworks] = useState<string[]>(schedule?.frameworks || []);
  const [frameworkSearch, setFrameworkSearch] = useState("");
  const frameworkPicker = useRef<HTMLDetailsElement>(null);
  const selectedConnector = connectors.find((item) => item.id === connector);
  const leakChecks = selectedConnector?.content_scan_checks?.leaks || [];
  const imageChecks = selectedConnector?.content_scan_checks?.images || [];
  const contentChecks = [...(leaksEnabled ? leakChecks : []), ...(imagesEnabled ? imageChecks : [])];
  const availableFrameworks = frameworkChoices(catalog.data, selectedConnector?.provider);
  const matchingFrameworks = availableFrameworks.filter((choice) =>
    !frameworks.includes(choice.value) && `${choice.label} ${choice.value}`.toLocaleLowerCase().includes(frameworkSearch.trim().toLocaleLowerCase()));
  const [rules, setRules] = useState<ScheduleRule[]>(schedule?.rules || [defaultRule()]);
  const [scheduleTimezone, setScheduleTimezone] = useState(schedule?.timezone || Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC");
  const [error, setError] = useState("");
  const isSchedule = schedule !== undefined;
  const previousScans = useApi<{ items: Scan[] }>("/scans", demo, !isSchedule);
  const [continuePrevious, setContinuePrevious] = useState(false);
  const latest = items(previousScans.data).filter(scan => scan.connector_id === connector)
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))[0];
  const previous = latest?.resumable && terminalStatuses.includes(latest.status) ? latest : undefined;
  const resumePrevious = !isSchedule && continuePrevious && !!previous;
  const mutation = useMutation({
    mutationFn: (payload: unknown) =>
      request(
        isSchedule
          ? schedule
            ? `/schedules/${encodeURIComponent(schedule.id)}`
            : "/schedules"
          : "/scans",
        {
          ...json(payload, schedule ? "PATCH" : "POST"),
          headers: !isSchedule
            ? { "Idempotency-Key": crypto.randomUUID() }
            : {},
        },
        demo,
      ),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: [demo ? "demo" : "live"] });
      onClose();
    },
  });
  const resumeMutation = useMutation({
    mutationFn: (id: string) => request<Scan>(`/scans/${encodeURIComponent(id)}/resume`, json({}), demo),
    onSuccess: () => { void client.invalidateQueries({ queryKey: [demo ? "demo" : "live"] }); onClose(); },
  });
  function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (!connector) return setError("Choose a connector first.");
    if (resumePrevious) { resumeMutation.mutate(previous.id); return; }
    if (!selected.length && !contentChecks.length)
      return setError("Select at least one assessment category or content analysis.");
    if (isSchedule && rules.some(rule => !rule.time || (rule.frequency === "weekly" && !rule.weekdays?.length)))
      return setError("Choose a time for each rule and at least one weekday for every weekly rule.");
    const aiWorkSelected = aiPrioritiesEnabled || selected.includes("exposure") ||
      (selected.includes("network") && aiNetworkEnabled) ||
      hardeningCategories.some((category) => selected.includes(category.id));
    mutation.mutate({
      connector_id: connector,
      ai_enabled: aiAvailable && aiEnabled && aiWorkSelected,
      ai_priorities_enabled: aiPrioritiesEnabled,
      ai_network_enabled: aiNetworkEnabled,
      categories: selected,
      content_checks: contentChecks,
      leaks_enabled: leaksEnabled && leakChecks.length > 0,
      images_enabled: imagesEnabled && imageChecks.length > 0,
      checks: checks
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
      frameworks,
      ...(isSchedule
        ? { rules, timezone: scheduleTimezone, enabled: schedule?.enabled ?? true }
        : {}),
    });
  }
  return (
    <Inspector
      title={isSchedule ? "Assessment schedule" : "Launch an assessment"}
      onClose={onClose}
    >
      <form className="form" onSubmit={submit}>
        {!!connectorError && <State error={connectorError} />}
        <label>
          Connector
          <select
            aria-label="Connector"
            value={connector}
            onChange={(e) => { setConnector(e.target.value); setContinuePrevious(false); setFrameworks([]); setFrameworkSearch(""); }}
            required
          >
            <option value="">Select an environment</option>
            {connectors.map((c) => (
              <option key={c.id} value={c.id}>
                {c.name}
              </option>
            ))}
          </select>
        </label>
        {isSchedule && selectedConnector?.scheduling?.allowed === false && (
          <p className="form-error" role="alert">{selectedConnector.scheduling.reason}</p>
        )}
        {!connectors.length && (
          <p className="form-error">Add a connector before launching a scan.</p>
        )}
        {!isSchedule && previous && <fieldset className="scan-resume-choice">
          <legend>Previous scan is unfinished</legend>
          <label className="checkbox"><input type="radio" name="scan-continuation" checked={!resumePrevious}
            onChange={() => setContinuePrevious(false)} />Start a new scan from scratch</label>
          <label className="checkbox"><input type="radio" name="scan-continuation" checked={resumePrevious}
            onChange={() => setContinuePrevious(true)} />Resume the previous scan</label>
          <p className="muted small">{resumePrevious ? "Keeps the same scan and saved results. Only unfinished work runs, using the original check selection and the connector’s current credentials." : "Collects fresh evidence and creates a new scan."}</p>
        </fieldset>}
        {!resumePrevious && <>
        <label className="checkbox"><input type="checkbox" checked={aiAvailable && aiEnabled} disabled={!aiAvailable} onChange={event => setAiEnabled(event.target.checked)} />Use AI for Network analysis and prioritized actions</label>
        {!aiAvailable && <p className="muted small">{codex.isPending ? "Checking AI access…" : codex.data?.disabled ? "AI review is disabled for every scan in Settings." : codex.data?.isolation_available === false ? "AI checks are unavailable until the platform administrator configures isolated agent execution." : "Configure an AI provider, model and thinking effort in Settings to enable AI checks."}</p>}
        <section className="assessment-config-section" aria-labelledby="hardening-config-title">
          <div className="assessment-section-heading"><span>01</span><div><h3 id="hardening-config-title">Hardening &amp; Compliance</h3><p>Select the checks to run for this environment.</p></div></div>
          <fieldset>
            <legend>Check categories <span className="category-count">{hardeningCategories.filter((category) => selected.includes(category.id)).length} / {hardeningCategories.length} selected</span></legend>
            <div className="assessment-category-grid">
              {hardeningCategories.map((c) => (
                <label key={c.id} className="checkbox">
                  <input
                    type="checkbox"
                    checked={selected.includes(c.id)}
                    onChange={(e) =>
                      setSelected(
                        e.target.checked
                          ? [...selected, c.id]
                          : selected.filter((x) => x !== c.id),
                      )
                    }
                  />
                  {c.label}
                </label>
              ))}
            </div>
          </fieldset>
          <label>
            Check IDs (optional, comma separated)
            <input
              value={checks}
              onChange={(e) => setChecks(e.target.value)}
              placeholder="Empty = supported checks in selected categories"
            />
          </label>
          <details>
            <summary>Frameworks and checklist versions (optional){frameworks.length ? ` · ${frameworks.length} selected` : ""}</summary>
            <div className="form" style={{ marginTop: 12 }}>
              <p className="muted small">Choose a framework to limit the checks. Leave this empty to run all checks in the selected categories.</p>
              {frameworks.map((value, index) => <div className="framework-selection" key={`${index}-${value}`}>
                <span aria-label={`Framework ${index + 1}`}>{availableFrameworks.find((choice) => choice.value === value)?.label || `${value} · unavailable for this connector`}</span>
                <button type="button" className="text-button" aria-label={`Remove framework ${index + 1}`} onClick={() => setFrameworks(frameworks.filter((_, i) => i !== index))}>Remove</button>
              </div>)}
              <details ref={frameworkPicker} className="framework-picker" onToggle={(event) => { if (event.currentTarget.open) event.currentTarget.querySelector("input")?.focus(); }}>
                <summary>Add another framework</summary>
                <div className="framework-picker-content">
                  <label>Search frameworks and checklist versions
                    <input type="search" value={frameworkSearch} onChange={(event) => setFrameworkSearch(event.target.value)} placeholder="Search by name or version" disabled={!selectedConnector || !catalog.data} />
                  </label>
                  {!selectedConnector || !catalog.data ? <p className="muted small">{catalog.isPending ? "Loading frameworks…" : "Choose a connector to see its frameworks."}</p> :
                    matchingFrameworks.length ? <div className="framework-choice-list">
                      {(["family", "version"] as const).map((group) => {
                        const choices = matchingFrameworks.filter((choice) => choice.group === group);
                        return choices.length ? <div key={group} className="framework-choice-group">
                          <p>{group === "family" ? "Framework families" : "Exact checklist versions"}</p>
                          {choices.map((choice) => <button key={choice.value} type="button" onClick={() => {
                            setFrameworks([...frameworks, choice.value]);
                            setFrameworkSearch("");
                            frameworkPicker.current?.removeAttribute("open");
                          }}>{choice.label}</button>)}
                        </div> : null;
                      })}
                    </div> : <p className="muted small">No matching frameworks remain.</p>}
                </div>
              </details>
              {!!catalog.error && <p role="alert">Framework catalog could not be loaded. You can still launch without a framework filter.</p>}
            </div>
          </details>
        </section>
        <section className="assessment-config-section" aria-labelledby="analysis-config-title">
          <div className="assessment-section-heading"><span>02</span><div><h3 id="analysis-config-title">Other analyses</h3><p>Turn each analysis on or off for this assessment.</p></div></div>
          <div className="assessment-category-grid">
            <label className="checkbox"><input type="checkbox" checked={aiAvailable && aiEnabled && aiPrioritiesEnabled}
              disabled={!aiAvailable || !aiEnabled} onChange={(event) => setAiPrioritiesEnabled(event.target.checked)} />Top 15 Actions <small>Uses AI</small></label>
            {analysisCategories.map((category) => <label key={category.id} className="checkbox">
              <input type="checkbox" checked={selected.includes(category.id)} onChange={(event) =>
                setSelected(event.target.checked ? [...selected, category.id] : selected.filter((id) => id !== category.id))} />
              {category.id === "network" ? "Network Map" : category.id === "privesc" ? "Privilege Escalation Map" : category.label}
            </label>)}
            <label className="checkbox"><input type="checkbox" checked={leaksEnabled && !!leakChecks.length} disabled={!leakChecks.length} onChange={event => setLeaksEnabled(event.target.checked)} />Leaks <small>{leakChecks.length ? "Selected scopes and configured targets" : "Configure exact content targets in the connector"}</small></label>
            <label className="checkbox"><input type="checkbox" checked={imagesEnabled && !!imageChecks.length} disabled={!imageChecks.length} onChange={event => setImagesEnabled(event.target.checked)} />Image CVEs <small>{imageChecks.length ? "Configured image targets" : "Configure exact image targets in the connector"}</small></label>
            <label className="checkbox"><input type="checkbox" checked={aiAvailable && aiEnabled && aiNetworkEnabled && selected.includes("network")}
              disabled={!aiAvailable || !aiEnabled || !selected.includes("network")}
              onChange={(event) => setAiNetworkEnabled(event.target.checked)} />Network Architecture <small>Uses AI and Network Map</small></label>
          </div>
        </section>
        {isSchedule && (
          <>
            {schedule && !schedule.rules?.length && <p className="muted small">This schedule currently runs every {schedule.interval_hours || 168} hours. Saving replaces that interval with the calendar rules below.</p>}
            <ScheduleRules rules={rules} timezone={scheduleTimezone} onRules={setRules} onTimezone={setScheduleTimezone} />
          </>
        )}
        </>}
        {(error || (resumePrevious ? resumeMutation.error : mutation.error)) && (
          <p className="form-error" role="alert">
            {error || humanError(resumePrevious ? resumeMutation.error : mutation.error)}
          </p>
        )}
        <button
          className="button primary"
          disabled={(isSchedule && selectedConnector?.scheduling?.allowed === false) || mutation.isPending || resumeMutation.isPending || !connectors.length}
          type="submit"
        >
          {mutation.isPending || resumeMutation.isPending
            ? "Submitting…"
            : resumePrevious ? "Resume previous scan"
            : isSchedule
              ? "Save schedule"
              : "Start scan"}
        </button>
      </form>
    </Inspector>
  );
}
