import { TableDownload } from "./TableDownload";
import { useState } from "react";
import { Copy, Check, Search } from "lucide-react";
import { Panel, ProviderIcon } from "./ui";
import { authGuides } from "./authGuides";
import { authModes } from "./Connectors";
import type { Provider } from "./types";
import { apiEndpoints, concepts, sections, statuses } from "./helpContent";
import "./Help.css";

type Chapter = "Get started" | "Connectors" | "Scans" | "API reference" | "Platform guide";
const chapters: Chapter[] = ["Get started", "Connectors", "Scans", "API reference", "Platform guide"];
function Code({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return <div className="docs-code"><div><strong>{label}</strong><button className="text-button" aria-label={`Copy ${label}`} onClick={() => {
    void navigator.clipboard.writeText(value).then(() => setCopied(true)).catch(() => setCopied(false));
  }}>{copied ? <Check size={14} /> : <Copy size={14} />}{copied ? "Copied" : "Copy"}</button></div><pre><code>{value}</code></pre></div>;
}
function Definitions({ rows }: { rows: ReadonlyArray<readonly [string, string]> }) {
  return <dl className="docs-definitions">{rows.map(([term, definition]) => <div key={term}><dt>{term}</dt><dd>{definition}</dd></div>)}</dl>;
}
const providers: { id: Provider; label: string; scope: string; steps: string[] }[] = [
  { id: "aws", label: "AWS", scope: "123456789012/us-east-2", steps: [
    "Choose Assume role for hosted cross-account access, or Access keys / session token for credentials you provide. Local installations can also use profiles, SSO or an attached workload role.",
    "For hosted role access, open its setup guide in Connectors. Deploy the supplied customer-role template in each target account using that workspace’s collector role and External ID. Enter the resulting target role ARN. For temporary credentials, enter all three values, including the session token.",
    "Enter the target accounts/Regions and choose the checks. Review optional content/image permissions separately from baseline inventory permissions. Run Check access, resolve blocking issues, then save.",
  ] },
  { id: "gcp", label: "Google Cloud", scope: "projects/example-project", steps: [
    "Choose the platform service account for hosted access, or provide a service-account JSON, impersonation setup or temporary access token. Local installations can use gcloud or Application Default Credentials.",
    "For platform access, use the exact service-account email and connector approval label shown in the setup guide. Grant its listed roles and apply its approval label to every selected project. With your own identity, grant the required project reads to that identity instead.",
    "Enter explicit projects, enable the APIs required by the selected checks, and run Check access for each scope. Resolve blocked scopes and save. Short-lived tokens must remain valid through collection.",
  ] },
  { id: "azure", label: "Azure", scope: "/subscriptions/00000000-0000-0000-0000-000000000000", steps: [
    "Choose a service principal with a client secret, inline certificate, or federated assertion. Local installations also support Azure CLI and managed identity.",
    "Enter tenant and application IDs and the selected credential. Assign the roles listed in that method’s setup guide at each subscription or narrower intended scope. Microsoft Graph and data-plane checks can require separate permissions or audience-specific tokens.",
    "Enter the subscription scopes, choose checks, and run Check access. Review any additional service-specific permissions needed for the selected checks before saving.",
  ] },
  { id: "k8s", label: "Kubernetes", scope: "my-cluster/default", steps: [
    "Choose inline kubeconfig or an API server with a service-account token or client certificate. Use a dedicated read identity and a Kubernetes API endpoint reachable from the scanner.",
    "Apply the read RBAC from the selected setup guide. Include cluster-scoped reads when assessing cluster-wide controls. Supply the CA and inline credential material; hosted kubeconfigs cannot depend on local files or exec authentication helpers.",
    "Choose the cluster and namespace scope, run Check access, and save. Access to a managed cloud account does not by itself supply Kubernetes API access to its clusters.",
  ] },
];

export function Help({ onNavigate }: { onNavigate: (page: string) => void }) {
  const [chapter, setChapter] = useState<Chapter>("Get started");
  const [provider, setProvider] = useState<Provider>("aws");
  const [method, setMethod] = useState("profile");
  const [search, setSearch] = useState("");
  const chosen = providers.find(row => row.id === provider)!;
  const methods = authModes[provider];
  const selectedMethod = methods.find(row => row.id === method) || methods[0];
  const guide = authGuides[provider][selectedMethod.id];
  const base = `${window.location.origin}/api`;
  const filteredEndpoints = apiEndpoints.filter(row => row.join(" ").toLowerCase().includes(search.trim().toLowerCase()));
  const go = (page: string, label: string) => <button className="text-button" onClick={() => onNavigate(page)}>{label}</button>;
  return <div className="help-docs">
    <nav className="docs-nav" aria-label="Documentation chapters">{chapters.map(name => <button key={name} className={chapter === name ? "active" : ""} aria-current={chapter === name ? "page" : undefined} onClick={() => setChapter(name)}>{name}</button>)}</nav>
    <div className="docs-content">
      {chapter === "Get started" && <>
        <Panel title="Get started" kicker="YOUR FIRST ASSESSMENT">
          <p>Connect an environment, run an assessment, then inspect the evidence behind its findings.</p>
          <ol className="help-steps">
            <li>Open {go("Connectors", "Connectors")}, add a connector, choose a cloud and authentication method, and follow its permission setup guide.</li>
            <li>Enter the scopes to assess. Run <strong>Check access</strong>, fix blocking permission or connectivity issues, and save the connector.</li>
            <li>Open {go("Scans", "Scans")} and select <strong>Launch scan</strong>. Choose the connector, checks or frameworks, and whether to use AI. Start the scan and follow its progress.</li>
            <li>Select the completed assessment on a results page. Open a finding for its evidence, affected assets, remediation and references.</li>
          </ol>
          <p>A completed execution can still contain denied reads or missing evidence. Review coverage and result statuses alongside failures.</p>
        </Panel>
        <div className="docs-cards">{[
          ["Connectors", "Provider tutorials, scope examples, credentials, permission setup and access checks."],
          ["Scans", "Launch, monitor, schedule and troubleshoot assessments; enable optional scanners and AI."],
          ["API reference", "Create a read-only key, query findings and inventory, paginate results and download reports."],
          ["Platform guide", "Definitions of platform sections, objects, evidence, severity and result statuses."],
        ].map(([name, text]) => <button key={name} onClick={() => setChapter(name as Chapter)}><strong>{name}</strong><span>{text}</span></button>)}</div>
      </>}
      {chapter === "Connectors" && <>
        <Panel title="Create a connector" kicker="PROVIDER TUTORIALS">
          <p>A connector stores how to authenticate and which environments to assess. Provider credentials belong here; the platform API key described in API reference is a separate credential for retrieving results.</p>
          <div className="docs-providers" aria-label="Connector tutorials">{providers.map(row => <button key={row.id} aria-label={row.label} aria-pressed={provider === row.id} onClick={() => { setProvider(row.id); setMethod(authModes[row.id][0].id); }}><ProviderIcon provider={row.id} size={18} />{row.label}</button>)}</div>
          <h3>{chosen.label} connector tutorial</h3><ol className="help-steps">{chosen.steps.map(step => <li key={step}>{step}</li>)}</ol>
          <p><strong>Scope example:</strong> <code>{chosen.scope}</code>. Use your own identifiers. The form’s scope help describes the accepted format for your selected method.</p>
          {go("Connectors", provider === "aws" ? "Open AWS setup guide" : `Open ${chosen.label} connector setup`)}
          <p>The connector form prepares the workspace-specific role, External ID or project approval details. Use those displayed values when following the hosted setup instructions.</p>
        </Panel>
        <Panel title="Authentication setup reference" kicker="IDENTITY, PERMISSIONS AND COMMANDS">
          <label className="docs-select">Authentication method<select aria-label="Authentication setup method" value={selectedMethod.id} onChange={event => setMethod(event.target.value)}>{methods.map(mode => <option key={mode.id} value={mode.id}>{mode.label}{mode.localOnly ? " · local server" : ""}</option>)}</select></label>
          <p>{guide.access}</p><h3>Permissions</h3><p>{guide.permissions}</p>
          {guide.permissionIds && <ul>{guide.permissionIds.map(id => <li key={id}><code>{id}</code></li>)}</ul>}
          <details className="docs-auth-commands"><summary>Commands for this authentication method</summary><p>Replace each placeholder before running a command. These setup commands create identities or grant access; they are separate from running a read-only assessment. Hosted AWS and platform GCP setup must use the workspace-specific commands in Connectors.</p>{guide.commands.map(command => <Code key={command.label} {...command} />)}</details>
          {guide.optionalSetup && <details className="docs-auth-commands"><summary>{guide.optionalSetup.title}</summary><p>{guide.optionalSetup.description}</p>{guide.optionalSetup.commands.map(command => <Code key={command.label} {...command} />)}</details>}
          <p className="docs-setup-link"><a href={guide.url} target="_blank" rel="noopener noreferrer">{provider === "aws" && selectedMethod.id === "assume_role" ? "AWS cross-account roles and External IDs" : guide.link} ↗</a></p>
        </Panel>
      </>}
      {chapter === "Scans" && <>
        <Panel title="Run an assessment" kicker="SCAN TUTORIAL">
          <ol className="help-steps">
            <li>Save a connector after checking its access. Open {go("Scans", "Scans")} and choose <strong>Launch scan</strong>, then select the connector.</li>
            <li>Choose the target scopes, categories, individual checks or compliance frameworks offered by the form. Keep the scope within the permissions granted to the connector.</li>
            <li>Choose whether to use AI to review findings and produce prioritized actions and network architecture recommendations. AWS AI uses captured evidence only; other eligible connectors may allow targeted read-only verification. Configure an available AI provider in {go("Settings", "Settings")} first.</li>
            <li>Start the scan. Open its details to follow collection, evaluation and any enabled AI stages. Cancel from Scans when you want to stop an execution.</li>
            <li>After completion, choose that assessment at the top of the results page. Filter failures, inspect coverage gaps and open individual findings. Export JSON or Markdown from Scans, or retrieve the data through the API.</li>
          </ol>
        </Panel>
        <Panel title="Optional content and image scans" kicker="SELECT WHAT WILL BE INSPECTED">
          <p>Selecting all checks does not enable every optional content scanner. Enable content inspection or image vulnerability scanning in the connector options, name the corresponding checks, and provide the exact targets required by those checks.</p>
          <p>Content inspection uses Kingfisher and TruffleHog for selected packages, configuration, user data or other supported sources. Image vulnerability analysis uses Trivy for selected immutable images. Read the selected method’s option help for target formats and additional permissions.</p>
          <p>Review Leaks and Images CVEs for execution results. Unknown, incomplete or not scanned means the source was not fully evaluated; it does not mean that source is clean. Discovered credentials are not validated.</p>
        </Panel>
        <Panel title="Schedules and failed executions" kicker="REPEAT AND TROUBLESHOOT">
          <p>Use <strong>Add schedule</strong> in Scans to select a connector, frequency, check selection and AI setting. Keep the connector’s credentials valid for future runs; temporary tokens can expire before the next scheduled execution.</p>
          <p>If execution fails, open its history for the failing stage and message. Fix authentication, permissions, reachability or the reported limit, then launch a new scan. A new run has a new assessment ID; old results keep their recorded evidence.</p>
          <p>For a completed scan with <strong>Access denied</strong> findings, update the relevant provider permissions and run again. For <strong>Unknown</strong> results, open the evidence to identify the missing facts.</p>
        </Panel>
      </>}
      {chapter === "API reference" && <>
        <Panel title="Access your data through the API" kicker="AUTHENTICATION AND QUICKSTART">
          <p>Base URL for this installation: <code>{base}</code>. Responses are JSON unless you request a Markdown report or follow a report download URL.</p>
          <ol className="help-steps"><li>Open {go("Settings", "Settings → API keys")}, create a named key and optionally set its expiry.</li><li>Copy the secret shown once and store it in your client’s secret manager.</li><li>Send <code>Authorization: Bearer YOUR_API_KEY</code> with each API request.</li></ol>
          <p>API keys allow personal-account GET/HEAD reads. They cannot launch scans, change connectors or schedules, manage keys, retrieve saved connector credentials, or select a shared workspace. Use the signed-in application for those actions. Revoke or rotate keys in Settings.</p>
          <Code label="Authenticate and list assessments" value={`export CSPM_API='${base}'
export CSPM_API_KEY='REPLACE_WITH_YOUR_API_KEY'
curl --fail-with-body -H "Authorization: Bearer $CSPM_API_KEY" "$CSPM_API/me"
curl --fail-with-body -H "Authorization: Bearer $CSPM_API_KEY" "$CSPM_API/scans"`} />
          <Code label="Get failed findings and inventory" value={`SCAN_ID=REPLACE_WITH_SCAN_ID
curl --fail-with-body -H "Authorization: Bearer $CSPM_API_KEY" "$CSPM_API/scans/$SCAN_ID/findings?status=FAIL&sort_by=severity&sort_order=desc&offset=0&limit=100"
curl --fail-with-body -H "Authorization: Bearer $CSPM_API_KEY" "$CSPM_API/scans/$SCAN_ID/resources?offset=0&limit=100"`} />
        </Panel>
        <Panel title="Endpoints" kicker="READ API REFERENCE">
          <label className="docs-search"><Search size={17} /><input aria-label="Search API endpoints" placeholder="Filter routes, data or parameters…" value={search} onChange={event => setSearch(event.target.value)} /></label>
          <p>All routes below use <strong>GET</strong> and are relative to <code>/api</code>. Replace brace placeholders with real IDs; URL-encode IDs used as path segments.</p>
          <TableDownload table="api-routes" label="API routes table"
            rows={filteredEndpoints.map(([route, category, description]) => ({ route, category, description }))} />
          <div className="docs-api-table"><table><thead><tr><th>Route</th><th>Data and parameters</th></tr></thead><tbody>{filteredEndpoints.map(([path, group, description]) => <tr key={path}><td><span>{group}</span><code>{path}</code></td><td>{description}</td></tr>)}</tbody></table>{!filteredEndpoints.length && <p>No endpoints match this search.</p>}</div>
        </Panel>
        <Panel title="Pagination, details and downloads" kicker="WORK WITH COMPLETE RESULTS">
          <p>Findings return an <code>items</code> array and <code>total</code>. Increase <code>offset</code> by <code>limit</code> until you have read the total. Filters apply before pagination. Resource inventory also returns <code>next_offset</code>; stop when it is null.</p>
          <p>Finding lists are summaries. Request <code>/scans/&#123;scan_id&#125;/findings/&#123;finding_id&#125;</code> for complete evidence. Request individual resource details for recorded native provider facts.</p>
          <Code label="Request a JSON report" value={'curl --fail-with-body -H "Authorization: Bearer $CSPM_API_KEY" "$CSPM_API/scans/$SCAN_ID/report?format=json" -o report-response.json'} />
          <p>A local response may be the report itself. A hosted response may contain <code>download_url</code>: fetch that short-lived URL promptly in a second request, <strong>without the API Authorization header</strong>. The JSON envelope is not the report.</p>
          <Code label="Download a hosted report from its envelope" value={`python3 -c 'import json; print(json.load(open("report-response.json"))["download_url"])' > report-url.txt
curl --fail-with-body "$(cat report-url.txt)" -o report.json`} />
          <Definitions rows={[["401", "Missing, expired, revoked or invalid authentication."], ["403", "The authenticated identity cannot perform the action or access the selected workspace."], ["404", "The requested object was not found in your account or selected context."], ["409", "The requested result is unavailable in the assessment’s current state."], ["422", "A request field, selector or parameter is invalid."], ["429", "A usage or request limit was reached; inspect the response before retrying."]]} />
        </Panel>
      </>}
      {chapter === "Platform guide" && <>
        <Panel title="What each section is for" kicker="PLATFORM GUIDE"><Definitions rows={sections} /><p>AI sections appear when AI is configured. Their contents depend on an assessment having run the corresponding AI stages.</p></Panel>
        <Panel title="Objects and terminology" kicker="DEFINITIONS"><Definitions rows={concepts} /></Panel>
        <Panel title="Understand finding statuses" kicker="EVIDENCE AND COVERAGE"><Definitions rows={statuses} /><p>Execution status is separate: queued waits for a worker; running collects or evaluates; completed has finished execution; failed, cancelled and timed_out describe an execution that stopped. Credentials expired means you need to renew the connector credentials. Use Resume from saved progress in the scan details to continue the same assessment, or choose a fresh scan when launching. Check coverage and optional scanner outcomes even for completed assessments.</p></Panel>
      </>}
    </div>
  </div>;
}
