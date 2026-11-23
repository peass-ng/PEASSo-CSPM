import { useEffect, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { json, request, useApi } from "./api";
import { Panel, State, humanError } from "./ui";

type Login = { verification_url: string; user_code: string; interval: number; expires_at: number };
type Selection = { provider: string; model: string; thinking: string; credential_saved: boolean };
type Configuration = { available: boolean; disabled?: boolean; hosted: boolean; source: string | null; selection: Selection | null; codex_connected: boolean; isolation_available: boolean; configuration_error?: { message: string; at: number } | null };
const providers = [
  ["openai", "OpenAI API key"], ["codex", "Codex sign-in"],
  ["anthropic", "Anthropic API key"], ["anthropic_token", "Anthropic token"],
  ["openrouter", "OpenRouter API key"],
];

export function CodexSettings() {
  const connection = useApi<Configuration>("/ai/configuration", false, true, true);
  const client = useQueryClient();
  const initialized = useRef(false);
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  const [thinking, setThinking] = useState("");
  const [credential, setCredential] = useState("");
  const [login, setLogin] = useState<Login>();
  const [message, setMessage] = useState("");
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!connection.data || initialized.current) return;
    initialized.current = true;
    const selected = connection.data.selection;
    if (selected) { setProvider(selected.provider); setModel(selected.model); setThinking(selected.thinking); }
  }, [connection.data]);
  function refresh() { void client.invalidateQueries({ predicate: query => query.queryKey[0] === "live" && ["/ai/codex", "/ai/configuration"].includes(String(query.queryKey[2])) }); }
  const start = useMutation({ mutationFn: () => request<Login>("/ai/codex/login", json({})), onSuccess: value => { setLogin(value); setCopied(false); setMessage(""); } });
  const policy = useMutation({
    mutationFn: (disabled: boolean) => request<{ disabled: boolean }>("/ai/preferences", { ...json({ disabled }), method: "PATCH" }),
    onSuccess: value => {
      client.setQueriesData<Configuration>({ predicate: query => query.queryKey[0] === "live" && query.queryKey[2] === "/ai/configuration" }, previous => previous ? { ...previous, disabled: value.disabled, ...(value.disabled ? { available: false, configuration_error: null } : {}) } : previous);
      setMessage(value.disabled ? "AI review is disabled for every scan." : "AI review now follows each scan or schedule's selection."); refresh();
    },
  });
  const disconnect = useMutation({ mutationFn: () => request("/ai/codex", { method: "DELETE" }), onSuccess: () => { setLogin(undefined); setMessage(""); refresh(); } });
  const revalidate = useMutation({ mutationFn: () => request("/ai/configuration/validate", json({})), onSuccess: () => { setMessage("Saved AI configuration validated."); refresh(); }, onError: () => refresh() });
  const save = useMutation({
    mutationFn: () => provider ? request<Configuration>("/ai/configuration", json({ provider, model, thinking, ...(credential ? { credential } : {}) })) : request("/ai/configuration", { method: "DELETE" }),
    onSuccess: () => { setCredential(""); setMessage(provider ? "AI configuration validated and saved. All scan agents use this selection." : connection.data?.hosted ? "HackTricks AI is used." : "Custom AI configuration removed."); refresh(); },
    onError: () => refresh(),
  });
  useEffect(() => {
    if (!login) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      if (!login || stopped) return;
      if (Date.now() / 1000 >= login.expires_at) { setLogin(undefined); setMessage("Sign-in expired. Try again."); return; }
      try {
        const result = await request<{ status: string }>("/ai/codex/login/poll", json({}));
        if (stopped) return;
        if (result.status === "connected") { setLogin(undefined); setMessage("Codex connected. Choose your model and thinking effort, then validate and save."); refresh(); return; }
      } catch (error) { if (!stopped) { setMessage(humanError(error)); setLogin(undefined); } return; }
      if (!stopped) timer = setTimeout(() => void poll(), login.interval * 1000);
    }
    timer = setTimeout(() => void poll(), login.interval * 1000);
    return () => { stopped = true; clearTimeout(timer); };
  }, [login]);
  const active = connection.data;
  async function copyCode() {
    if (!login) return;
    try { await navigator.clipboard.writeText(login.user_code); setCopied(true); }
    catch { setMessage("Select and copy the sign-in code above."); }
  }
  const savedCredential = active?.selection?.provider === provider && active.selection.credential_saved;
  const ready = provider ? !!model.trim() && !!thinking && (provider === "codex" ? active?.codex_connected : !!credential || savedCredential) : active?.hosted || !!active?.selection;
  return <Panel title="AI review"><div className="ai-settings">
    <section className="ai-settings-section" aria-labelledby="ai-purpose-heading">
      <h3 id="ai-purpose-heading">What AI does</h3>
      <ul className="ai-purpose-list">
        <li><strong>Hardening &amp; compliance:</strong> rechecks failed findings against collected evidence and, where permitted, verifies cloud configuration.</li>
        <li><strong>Exposure:</strong> reviews failed exposure findings and verifies whether the recorded configuration supports them.</li>
        <li><strong>Network architecture:</strong> explains VPCs and subnets and recommends architecture and segmentation improvements.</li>
        <li><strong>Findings Report:</strong> compiles completed scan analyses into evidence-backed issues, grouping leaks and image CVEs.</li>
        <li><strong>Top 10 Actions:</strong> prioritizes security improvements and provides an action plan for each.</li>
      </ul>
      <p className="muted small">AI-enabled scans share captured evidence with the selected AI provider. AWS AI reviews use captured evidence only. Eligible GCP, Azure and Kubernetes connectors may allow targeted read-only verification; native checks still use the connector's cloud access.</p>
    </section>
    <section className="ai-settings-section" aria-labelledby="ai-configure-heading">
      <h3 id="ai-configure-heading">Configure AI</h3>
    {connection.error && <State error={connection.error} onRetry={() => void connection.refetch()} />}
    {active?.isolation_available === false && <p role="status">AI review is unavailable until isolated agent execution is configured.</p>}
    {active?.configuration_error && <p role="alert">AI is paused: {active.configuration_error.message} No AI workloads will be launched. Validate and save your settings to resume.</p>}
    {active?.configuration_error && <button className="button" disabled={revalidate.isPending} onClick={() => revalidate.mutate()}>Revalidate saved AI configuration</button>}
    {active?.hosted && <p className="muted small">HackTricks AI is the default when no personal configuration is selected. If validation fails, AI stops until you fix your settings or explicitly select and validate HackTricks AI.</p>}
    <form className="form" onSubmit={event => { event.preventDefault(); setMessage(""); save.mutate(); }}>
      <label>AI provider<select value={provider} onChange={event => { setProvider(event.target.value); setCredential(""); setModel(""); setThinking(""); setMessage(""); save.reset(); }}>
        <option value="">{active?.hosted ? "HackTricks AI (default)" : "Select an AI provider"}</option>
        {providers.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select></label>
      {provider && <>
        {provider !== "codex" && <label>{provider === "anthropic_token" ? "Anthropic token" : "API key"}<input type="password" autoComplete="new-password" value={credential} onChange={event => setCredential(event.target.value)} placeholder={savedCredential ? "Saved credential; leave blank to keep it" : "Enter your credential"} /></label>}
        {provider === "anthropic_token" && <p className="muted small">Use a Claude Code token created with claude setup-token.</p>}
        <label>Model ID<input value={model} onChange={event => setModel(event.target.value)} required maxLength={200} placeholder="Exact model ID from your provider" /></label>
        <label>Thinking effort<select value={thinking} onChange={event => setThinking(event.target.value)} required>
          <option value="">Select thinking effort</option>
          {["none", "minimal", "low", "medium", "high", "xhigh", "max"].map(value => <option key={value} value={value}>{value}</option>)}
        </select></label>
        <p className="muted small">The backend sends a small inference request to check your credential, model, thinking and tool support before saving and before each AI workload starts.</p>
      </>}
      <div className="button-row">
        <button className="button primary" type="submit" disabled={!ready || save.isPending}>{save.isPending ? "Validating…" : provider ? "Validate and save AI" : active?.hosted ? "Use HackTricks AI" : "Remove AI configuration"}</button>
        {provider === "codex" && <button className="button" type="button" disabled={start.isPending || !!login || disconnect.isPending} onClick={() => start.mutate()}>{active?.codex_connected ? "Reconnect Codex" : "Sign in with Codex"}</button>}
        {(login || active?.codex_connected && provider === "codex") && <button className="button" type="button" disabled={disconnect.isPending} onClick={() => disconnect.mutate()}>{login ? "Cancel sign-in" : "Disconnect Codex"}</button>}
      </div>
    </form>
    {login && <div role="status"><p>On your laptop, open <a href={login.verification_url} target="_blank" rel="noreferrer">Codex sign-in</a> and enter this code:</p><p><strong>{login.user_code}</strong></p><button type="button" className="button" onClick={() => void copyCode()}>{copied ? "Code copied" : "Copy sign-in code"}</button><p>Waiting for sign-in. The code expires at {new Date(login.expires_at * 1000).toLocaleTimeString()}.</p></div>}
    </section>
    <section className="ai-settings-section" aria-labelledby="ai-disable-heading">
      <h3 id="ai-disable-heading">Disable AI</h3>
      <p className="muted small">For individual runs, turn AI off in the scan or schedule. To disable it everywhere, use the switch below.</p>
    <label className="checkbox ai-disable-toggle"><input type="checkbox" aria-describedby="ai-disable-description" checked={policy.isPending ? !!policy.variables : !!active?.disabled} disabled={!active || policy.isPending} onChange={event => policy.mutate(event.target.checked)} /><span>Disable AI for every scan</span><span className="ai-disable-warning" aria-hidden="true" title="Affects every workspace">⚠</span></label>
    <p id="ai-disable-description" className="muted small">Applies to your scans in every workspace, including schedules and queued scans. Saved provider credentials are kept. Turn this off to use each scan's AI selection again.</p>
    </section>
    {message && <p role="status">{message}</p>}
    {(start.error || disconnect.error || save.error || revalidate.error || policy.error) && <p role="alert">{humanError(start.error || disconnect.error || save.error || revalidate.error || policy.error)}</p>}
  </div></Panel>;
}
