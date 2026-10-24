import { Component, lazy, Suspense, useEffect, useState } from "react";
import type { ErrorInfo, ReactNode } from "react";
import {
  ChevronDown,
  Droplet,
  Container,
  AlertTriangle,
  Cloud,
  ArrowUpRight,
  Gauge,
  GraduationCap,
  HelpCircle,
  Layers,
  ListChecks,
  Network,
  ScanLine,
  Radar,
  Settings as SettingsIcon,
  Shield,
  ShieldCheck,
  Target,
  Route,
  Waypoints,
} from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { ApiError, authSessionChangedEvent, items, useApi, workspaceKey } from "./api";
import { Connectors } from "./Connectors";
import { Dashboard } from "./Dashboard";
import { Findings } from "./Findings";
import { ImagesFindings } from "./ImagesFindings";
import { LeastPrivilege } from "./LeastPrivilege";
import { AttackAnalysis } from "./AttackAnalysis";
import { Help } from "./Help";
import { authLink } from "./authLinks";
const NetworkMap = lazy(() =>
  import("./NetworkMap").then((m) => ({ default: m.NetworkMap })),
);
const PrivescMap = lazy(() =>
  import("./PrivescMap").then((m) => ({ default: m.PrivescMap })),
);
import { AiReview, NetworkAiReview } from "./AiReview";
import { Scans } from "./Scans";
import { Settings } from "./Settings";
import type { Connector, Me, Report, Scan, Workspace } from "./types";
import { Panel, State, sourceHref } from "./ui";
import { scanNames } from "./scanNames";
import { useInsightCounts } from "./InsightCounts";
function IamIcon({ size = 18 }: { size?: number }) {
  return <svg className="nav-iam-icon" width={24} height={size} viewBox="0 0 24 18"
    style={{ width: 24, flexShrink: 0 }} fill="none" aria-hidden="true">
    <rect x="0.75" y="0.75" width="22.5" height="16.5" rx="3" stroke="currentColor" strokeWidth="1.5" />
    <text x="12" y="12" textAnchor="middle" fill="currentColor" fontFamily="'IBM Plex Mono', monospace"
      fontSize="9" fontWeight="700" letterSpacing="0.3">IAM</text>
  </svg>;
}

const pages = [
  {
    label: "Dashboard",
    icon: Gauge,
    group: "WORKSPACE",
    description: "",
  },
  {
    label: "Connectors",
    icon: Cloud,
    description: "Connect your environments with confidence.",
  },
  {
    label: "Scans",
    icon: ScanLine,
    description: "Assess, monitor and revisit your cloud posture.",
  },
  { label: "Top 15 Actions", icon: ListChecks, ai: true, group: "SECURITY INSIGHTS", description: "Review the security changes to prioritize." },
  {
    label: "Hardening & Compliance",
    icon: ShieldCheck,
    description: "Review configuration controls across your cloud estate.",
  },
  {
    label: "Exposure",
    icon: Target,
    description: "Understand your observed external exposure.",
  },
  {
    label: "Least Privilege",
    icon: IamIcon,
    description: "Review identity permissions and reduce unnecessary access.",
  },
  {
    label: "Privilege Escalation Map",
    icon: Route,
    description:
      "Which identities can escalate to others or to admin · catalog-driven attack paths.",
  },
  {
    label: "Network Map",
    icon: Network,
    description: "See the connections behind your infrastructure.",
  },
  {
    label: "Network Architecture",
    icon: Waypoints,
    ai: true,
    description: "Review AI network findings and recommended connectivity changes.",
  },
  {
    label: "Leaks",
    icon: Droplet,
    description: "Inspect detected secrets and credential-related findings and their sources.",
  },
  {
    label: "Images CVEs",
    icon: Container,
    description: "Review image vulnerabilities and their scan coverage.",
  },
  {
    label: "Attack Detection",
    icon: Radar,
    group: "THREAT DETECTION",
    description: "Review suspicious actions in cloud audit logs.",
  },
  {
    label: "Settings",
    icon: SettingsIcon,
    group: "ADMINISTRATION",
    description: "Account, quota, supported scope and help.",
  },
  {
    label: "Help",
    icon: HelpCircle,
    description: "Set up access, run an assessment and interpret its evidence.",
  },
];
const pageAliases: Record<string, string> = {
  "AI Review": "Top 15 Actions", "Top 15 Recommended Actions": "Top 15 Actions",
  "Hardening Findings": "Hardening & Compliance", "Network Findings": "Network Architecture",
  "Images Findings": "Images CVEs", "Attack Analysis": "Attack Detection",
};
const normalizePage = (page: string) => pageAliases[page] || page;
export function App() {
  const [page, setPage] = useState(() => {
    const raw = decodeURIComponent(location.hash.slice(1));
    const p = normalizePage(raw);
    return pages.some((x) => x.label === p) ? p : "Dashboard";
  });
  const [demoRequested, setDemoRequested] = useState(true);
  const [selected, setSelected] = useState("");
  const [workspaceId, setWorkspaceId] = useState(() => sessionStorage.getItem(workspaceKey) || "personal");
  const [workspaceMenuOpen, setWorkspaceMenuOpen] = useState(false);
  const client = useQueryClient();
  const identity = useApi<Me>("/me", false);
  const signedIn = identity.isSuccess;
  const codex = useApi<{ available: boolean; platform_configured: boolean; configuration_error?: { message: string } | null }>("/ai/codex", false, signedIn, true);
  const aiAvailable = signedIn && (codex.data?.available === true || codex.data?.platform_configured === true);
  const workspaces = useApi<{ items: Workspace[] }>("/workspaces", false, signedIn);
  const workspaceList = items(workspaces.data);
  const activeWorkspace = workspaceList.find((item) => item.id === workspaceId);
  const canWriteWorkspace = !signedIn || workspaceId === "personal" || activeWorkspace?.role === "write" || activeWorkspace?.role === "admin";
  const demo = !identity.isPending && !signedIn && demoRequested;
  const health = useApi<{ status: string; source_url?: string }>(
    "/health",
    demo,
  );
  const connectors = useApi<{ items: Connector[] }>("/connectors", demo);
  const scans = useApi<{ items: Scan[] }>("/scans", demo, true, true);
  const available = items(scans.data);
  const hasResult = (scan: Scan) => scan.status === "completed" || scan.result_available === true;
  const names = scanNames(available, items(connectors.data));
  const scanId =
    (available.some((scan) => scan.id === selected && hasResult(scan)) ? selected : "") || available.find(hasResult)?.id || "";
  const current = available.find((s) => s.id === scanId);
  const partialResult = !!current && current.status !== "completed" && hasResult(current);
  const report = useApi<Report>(
    `/scans/${encodeURIComponent(scanId)}/summary?aggregation=check`,
    demo,
    !!scanId && !!current && hasResult(current),
    partialResult,
  );
  const insightCounts = useInsightCounts(scanId, demo, !!scanId && !!current && hasResult(current), aiAvailable, report.data);
  const publicationRevision = report.data?.publication ? `${report.data.publication.state}:${report.data.publication.sequence ?? ""}:${JSON.stringify(report.data.publication.ai_stages || {})}` : undefined;
  useEffect(() => {
    if (!scanId || publicationRevision === undefined) return;
    void client.invalidateQueries({ predicate: (query) => query.queryKey[0] === (demo ? "demo" : "live") &&
      query.queryKey.some((part) => typeof part === "string" &&
        (part === scanId || part.includes(`/scans/${scanId}/`))) });
  }, [client, demo, scanId, publicationRevision]);
  const pageInfo = pages.find((p) => p.label === page) || pages[0];
  function navigate(p: string) {
    p = normalizePage(p);
    setPage(p);
    location.hash = encodeURIComponent(p);
  }
  useEffect(() => {
    if (pages.some(item => item.label === page && item.ai) &&
        (identity.isError || codex.isError || codex.isSuccess && !aiAvailable)) navigate("Dashboard");
  }, [page, identity.isError, codex.isError, codex.isSuccess, aiAvailable]);
  function selectWorkspace(id: string) {
    sessionStorage.setItem(workspaceKey, id);
    setWorkspaceId(id);
    setWorkspaceMenuOpen(false);
    setSelected("");
    void client.resetQueries({ queryKey: ["live"] });
  }
  useEffect(() => {
    if (signedIn && workspaces.data && !activeWorkspace && workspaceId !== "personal") selectWorkspace("personal");
  }, [signedIn, workspaces.data, activeWorkspace, workspaceId]);
  useEffect(() => {
    const change = () => {
      const raw = decodeURIComponent(location.hash.slice(1));
      const p = normalizePage(raw);
      setPage(pages.some((x) => x.label === p) ? p : "Dashboard");
    };
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  }, []);
  useEffect(() => {
    const change = () => {
      setSelected("");
      setDemoRequested(true);
      sessionStorage.removeItem(workspaceKey);
      setWorkspaceId("personal");
      void client.resetQueries({ queryKey: ["live"] });
    };
    window.addEventListener(authSessionChangedEvent, change);
    return () => window.removeEventListener(authSessionChangedEvent, change);
  }, [client]);
  const unauthorized = [connectors.error, scans.error].some(
    (e) => e instanceof ApiError && e.status === 401,
  );
  function switchDemo() {
    if (signedIn || identity.isPending) return;
    setDemoRequested(!demoRequested);
    setSelected("");
  }
  const insight = [
    "Hardening & Compliance",
    "Exposure",
    "Leaks",
    "Images CVEs",
    "Top 15 Actions",
    "Network Architecture",
    "Least Privilege",
    "Privilege Escalation Map",
    "Network Map",
  ].includes(page);
  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <aside className="sidebar">
        <a
          className="brand"
          href="#Dashboard"
          onClick={() => navigate("Dashboard")}
        >
          <img src="/icons/peaso-badge.svg" alt="" width={44} height={44} />
          <div>
            PEASS'o CSPM<span>CLOUD SECURITY</span>
          </div>
        </a>
        <div className="workspace-selector">
        <button className="workspace-chip" type="button" onClick={() => signedIn ? setWorkspaceMenuOpen(!workspaceMenuOpen) : navigate("Settings")} aria-expanded={workspaceMenuOpen} aria-label="Select workspace">
          <div className="workspace-avatar">
            <Layers size={18} />
          </div>
          <div>
            <strong>{demo ? "Fixture demo" : activeWorkspace?.name || "Personal Workspace"}</strong>
            <span>{demo ? "Sample assessment" : activeWorkspace?.role ? `${activeWorkspace.role[0].toUpperCase()}${activeWorkspace.role.slice(1)} access` : "Your private workspace"}</span>
          </div>
          <ChevronDown size={14} />
        </button>
        {signedIn && workspaceMenuOpen && <div className="workspace-menu" role="menu" aria-label="Workspaces">
          {workspaceList.map((workspace) => <button key={workspace.id} type="button" role="menuitemradio" aria-checked={workspace.id === workspaceId} onClick={() => selectWorkspace(workspace.id)}>{workspace.name}<small>{workspace.role}</small></button>)}
          <button type="button" onClick={() => { setWorkspaceMenuOpen(false); navigate("Settings"); }}>Manage workspaces</button>
        </div>}
        </div>
        <a className="sidebar-training-ad" href="https://hacktricks-training.com/courses/" target="_blank" rel="noopener noreferrer" aria-label="Learn Cloud Security">
          <GraduationCap className="training-ad-icon" size={22} aria-hidden="true" />
          <span className="training-ad-kicker">HACKTRICKS TRAINING</span>
          <strong>Learn Cloud Security</strong>
          <span className="training-ad-cta">Explore courses <ArrowUpRight size={14} aria-hidden="true" /></span>
        </a>
        <nav aria-label="Primary navigation">
          {pages.filter((p) => p.label !== "Help" && (!p.ai || aiAvailable)).map((p) => (
            <div key={p.label}>
              {(p.group || (p.label === "Hardening & Compliance" && !aiAvailable)) && <div className="nav-group">{p.group || "SECURITY INSIGHTS"}</div>}
              <button
                className={`nav-item ${p.ai ? "nav-item-ai" : ""} ${page === p.label ? "active" : ""}`}
                onClick={() => navigate(p.label)}
                aria-label={p.label}
                aria-current={page === p.label ? "page" : undefined}
              >
                <p.icon size={18} />
                <span className="nav-label">{p.label}
                  {p.label === "Attack Detection" && <span className="feature-beta nav-beta">Beta</span>}
                  {p.ai && <span className="feature-ai nav-ai" aria-hidden="true">✦ AI</span>}
                </span>
                {p.label === "Settings" && codex.data?.configuration_error && <AlertTriangle size={16} role="img" aria-label="AI configuration needs attention" />}
                {Object.hasOwn(insightCounts, p.label) && <span className="nav-count" aria-label={`${p.label} total`}>
                  {insightCounts[p.label] ?? "—"}
                </span>}
              </button>
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <button className="nav-item" onClick={() => navigate("Help")}>
            <HelpCircle size={18} />
            Help & documentation
          </button>
          <div className="sidebar-version">Built by HackTricks</div>
        </div>
      </aside>
      <div className="workspace-main">
        <header className={`topbar ${!identity.isPending && !signedIn ? "logged-out" : ""}`}>
          <span className="breadcrumb">
            Workspace <span>/</span> {page}
          </span>
          <div className="topbar-actions">
            {!identity.isPending && !signedIn && <label className="demo-switch">
              <input type="checkbox" checked={demo} onChange={switchDemo} />
              <span className="switch-track" />
              Fixture demo
            </label>}
            {!identity.isPending && !signedIn && <span className={`api-status${health.error && !demo ? " offline" : ""}`}><span className="status-dot" />{demo ? "Demo data" : health.error ? "API unavailable" : "Live API"}</span>}
            {!identity.isPending && !signedIn && <div className="topbar-auth-actions">
              <a className="button" href={authLink("login")}>Log in</a>
              <a className="button primary" href={authLink("register")}>Register</a>
            </div>}
            {signedIn && <button
              className="account-button"
              aria-label={`Account settings${identity.data?.email ? ` for ${identity.data.email}` : ""}`}
              onClick={() => navigate("Settings")}
            >
              {String(identity.data?.email || identity.data?.name || identity.data?.tenant_id || "A").trim().charAt(0).toUpperCase()}
            </button>}
          </div>
        </header>
        <main id="main-content" className={page === "Network Map" ? "network-map-page" : undefined}>
          <div className="page-heading">
            <div>
              <div className="eyebrow page-kicker"><span>//</span> PEASS'o INTELLIGENCE</div>
              <h1>{page}{pageInfo.ai && <span className="feature-ai" aria-hidden="true">✦ AI</span>}{page === "Attack Detection" && <span className="feature-beta">Beta</span>}</h1>
              {pageInfo.description && <p>{pageInfo.description}</p>}
            </div>
            {(insight || page === "Dashboard") && (
              <label className="scan-picker">
                <span>Selected assessment</span>
                <select
                  aria-label="Selected assessment"
                  value={scanId}
                  onChange={(e) => setSelected(e.target.value)}
                >
                  <option value="">
                    {available.length
                      ? "Choose an assessment with results"
                      : "No assessments with results"}
                  </option>
                  {available
                    .filter(hasResult)
                    .map((s) => (
                      <option key={s.id} value={s.id}>
                        {names.get(s.id)}
                      </option>
                    ))}
                </select>
              </label>
            )}
          </div>
          {demo && (
            <div className="demo-banner" role="status">
              <ShieldCheck size={17} />
              <strong>Fixture demo</strong>
              <span>
                Illustrative data only. No cloud assessment has been run.
                Changes are disabled.
              </span>
              <button className="text-button" onClick={switchDemo}>
                Exit demo
              </button>
            </div>
          )}
          {!demo && current?.input_mode && current.input_mode !== "live" && (
            <div className="demo-banner" role="status">
              <ShieldCheck size={17} />
              <strong>
                {current.input_mode === "demo"
                  ? "Offline demo assessment"
                  : "Imported offline snapshot"}
              </strong>
              <span>
                {current.input_mode === "demo"
                  ? "Illustrative native demo snapshot; no live cloud evidence."
                  : "This assessment analyzed an imported snapshot. Collection provenance and coverage are recorded in the report."}
              </span>
            </div>
          )}
          {!demo && page === "Scans" && partialResult && (
            <div className="demo-banner" role="status">
              <ShieldCheck size={17} />
              <strong>{["failed", "timed_out", "cancelled", "queue_exhausted", "credentials_expired"].includes(current?.status || "") ? "Saved partial results" : "Assessment in progress"}</strong>
            </div>
          )}
          {unauthorized && !demo && page !== "Settings" && (
            <div className="auth-banner" role="alert">
              <Shield size={18} />
              <span>Authenticate your workspace to load private evidence.</span>
              <button className="button" onClick={() => navigate("Settings")}>
                Set up authentication
              </button>
            </div>
          )}
          {page === "Dashboard" && (
            <Dashboard
              connectors={items(connectors.data)}
              scans={available}
              report={report.data}
              scanId={scanId}
              demo={demo}
              loading={
                connectors.isPending ||
                scans.isPending ||
                (!!scanId && report.isPending)
              }
              error={connectors.error || scans.error || report.error}
              onRetry={() => {
                void connectors.refetch();
                void scans.refetch();
                if (scanId) void report.refetch();
              }}
              onNavigate={navigate}
            />
          )}
          {page === "Connectors" && <Connectors demo={demo} canWrite={canWriteWorkspace} />}
          {page === "Attack Detection" && <AttackAnalysis demo={demo} canWrite={canWriteWorkspace} onNavigate={navigate} />}
          {page === "Scans" && (
            <Scans
              demo={demo}
              canWrite={canWriteWorkspace}
              onSelect={(s) => {
                setSelected(s.id);
                navigate("Hardening & Compliance");
              }}
            />
          )}
          {["Hardening & Compliance", "Exposure", "Leaks"].includes(
            page,
          ) && (
            <>
              <State
                error={scans.error}
                loading={scans.isPending}
                onRetry={() => void scans.refetch()}
              >
                <Findings
                  key={page}
                  scanId={scanId}
                  category={page === "Hardening & Compliance" ? "hardening" : page === "Exposure" ? "exposure" : ""}
                  findingType={page === "Leaks" ? "detected_leaks" : undefined}
                  demo={demo}
                />
              </State>
            </>
          )}
          {pageInfo.ai && codex.isPending && signedIn && <State loading />}
          {page === "Images CVEs" && <ImagesFindings key={`${scanId}:${demo}`} scanId={scanId} demo={demo} />}
          {aiAvailable && page === "Top 15 Actions" && <AiReview key={scanId} scanId={scanId} demo={demo} />}
          {aiAvailable && page === "Network Architecture" && <NetworkAiReview key={scanId} scanId={scanId} demo={demo} />}
          {page === "Least Privilege" && <LeastPrivilege scanId={scanId} demo={demo} />}
          {page === "Privilege Escalation Map" && (
            scans.error instanceof ApiError && scans.error.status === 401 && !demo
              ? <Panel>
                  <div className="state" role="alert">
                    <Shield />
                    <h3>Authentication is required to view this map</h3>
                    <p>Sign in to your workspace or add a valid API token in Settings, then retry.</p>
                    <div className="button-row">
                      <a className="button primary" href={authLink("login")}>Sign in at Tools</a>
                      <button className="button" onClick={() => navigate("Settings")}>Open authentication settings</button>
                    </div>
                  </div>
                </Panel>
              : <State
                  error={scans.error}
                  loading={scans.isPending}
                  onRetry={() => void scans.refetch()}
                >
                  <Suspense fallback={<State loading />}>
                    <PrivescMap
                      scanId={scanId}
                      demo={demo}
                      categories={current?.categories}
                      onNavigate={navigate}
                    />
                  </Suspense>
                </State>
          )}
          {page === "Network Map" && (
            <State
              error={scans.error}
              loading={scans.isPending}
              onRetry={() => void scans.refetch()}
            >
              <Suspense fallback={<State loading />}>
                <NetworkMap key={`${scanId}:${demo}`} scanId={scanId} demo={demo} />
              </Suspense>
            </State>
          )}
          {page === "Settings" && <Settings demo={false} workspaceId={workspaceId} onWorkspaceCreated={selectWorkspace} />}
          {page === "Help" && <Help onNavigate={navigate} />}
          <footer className="footer">
            <span>
              <ShieldCheck size={13} />
              Evidence first. Confidence follows.
            </span>
            <span>
              <a
                href={
                  sourceHref(health.data?.source_url) ||
                  "https://github.com/peass-ng/PEASSo-CSPM"
                }
                target="_blank"
                rel="noopener noreferrer"
              >
                Source code
              </a>{" "}
              · PEASS'o CSPM · HackTricks Cloud
            </span>
          </footer>
        </main>
      </div>
    </div>
  );
}
export class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: boolean }
> {
  state = { error: false };
  static getDerivedStateFromError() {
    return { error: true };
  }
  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("UI render error", error.name, info.componentStack);
  }
  render() {
    return this.state.error ? (
      <div className="state" role="alert">
        <h1>The workspace could not be displayed</h1>
        <p>Reload the page to reconnect with your API.</p>
        <button className="button" onClick={() => location.reload()}>
          Reload workspace
        </button>
      </div>
    ) : (
      this.props.children
    );
  }
}
