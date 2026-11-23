import { TableDownload, collectCursorTableRows } from "./TableDownload";
import { useState } from "react";
import type { FormEvent } from "react";
import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import { Clipboard, KeyRound, Plus, Trash2 } from "lucide-react";
import { json, request } from "./api";
import { humanError, Panel, State } from "./ui";

type ApiKey = {
  id: string;
  name: string;
  prefix: string;
  created_at: string;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
};
type KeyPage = { items: ApiKey[]; next_cursor: string | null };
type CreatedKey = ApiKey & { key: string };

const date = (value: string | null) => value ? new Date(value).toLocaleString() : "Never";

/** Account-scoped, read-only external keys. The one-time secret lives only in component state. */
export function ApiKeys() {
  const client = useQueryClient();
  const [name, setName] = useState("");
  const [expiry, setExpiry] = useState("");
  const [created, setCreated] = useState<CreatedKey | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [confirmId, setConfirmId] = useState("");
  const [copied, setCopied] = useState(false);
  const keyPage = (cursor: string, signal?: AbortSignal) =>
    request<KeyPage>(`/api-keys?limit=50${cursor ? `&after=${encodeURIComponent(cursor)}` : ""}`, { signal });
  const keys = useInfiniteQuery<KeyPage>({
    queryKey: ["live", "api-keys"],
    initialPageParam: "",
    queryFn: ({ pageParam, signal }) => keyPage(String(pageParam), signal),
    getNextPageParam: (page) => page.next_cursor || undefined,
    retry: 1,
  });
  const rows = keys.data?.pages.flatMap((page) => page.items) || [];

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!name.trim() || busy) return;
    setBusy(true);
    setError("");
    setCreated(null);
    try {
      const expires_at = expiry ? new Date(expiry).toISOString() : null;
      const value = await request<CreatedKey>("/api-keys", json({ name: name.trim(), expires_at }));
      setCreated(value);
      setName("");
      setExpiry("");
      setCopied(false);
      await client.invalidateQueries({ queryKey: ["live", "api-keys"] });
    } catch (cause) {
      setError(humanError(cause));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: string) {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      await request(`/api-keys/${encodeURIComponent(id)}`, { method: "DELETE" });
      setConfirmId("");
      if (created?.id === id) setCreated(null);
      await client.invalidateQueries({ queryKey: ["live", "api-keys"] });
    } catch (cause) {
      setError(humanError(cause));
    } finally {
      setBusy(false);
    }
  }

  async function copy() {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.key);
      setCopied(true);
    } catch {
      setError("Clipboard access was denied. Select and copy the key below.");
    }
  }

  return (
    <Panel title="PEASS'o CSPM API Keys" kicker="EXTERNAL READ ACCESS" action={<TableDownload table="api-key-metadata" label="API key list"
        disabled={keys.isPending || !!keys.error}
        loadRows={async signal => (await collectCursorTableRows(keyPage, signal)).map(key => ({
          id: key.id, name: key.name, prefix: key.prefix, created_at: key.created_at,
          expires_at: key.expires_at, revoked_at: key.revoked_at, last_used_at: key.last_used_at,
        }))} />}>
      <p className="muted settings-description">Create a key for external tools to read this account’s scans, findings, reports, maps, coverage, connectors, schedules, catalog and usage. Keys cannot start scans or change account data.</p>
      <form className="form" onSubmit={(event) => void create(event)}>
        <label>Key name<input aria-label="API key name" value={name} maxLength={100} onChange={(event) => setName(event.target.value)} placeholder="Reporting integration" required /></label>
        <label>Expiry (optional)<input aria-label="API key expiry" type="datetime-local" value={expiry} onChange={(event) => setExpiry(event.target.value)} /></label>
        <button className="button primary" type="submit" disabled={busy || !name.trim()}><Plus size={15} /> Create read-only key</button>
      </form>
      {error && <p className="form-error" role="alert">{error}</p>}
      {created && (
        <div className="notice" role="status">
          <h3>Copy this key now</h3>
          <p>The secret is shown only once. Store it in your external tool’s secret manager.</p>
          <input aria-label="New API key" readOnly value={created.key} onFocus={(event) => event.currentTarget.select()} />
          <div className="button-row">
            <button className="button primary" type="button" onClick={() => void copy()}><Clipboard size={15} /> {copied ? "Copied" : "Copy key"}</button>
            <button className="button" type="button" onClick={() => setCreated(null)}>Done</button>
          </div>
        </div>
      )}
      <State loading={keys.isPending} error={keys.error && !keys.data ? keys.error : undefined} onRetry={() => void keys.refetch()}>
        <div className="stack">
          {rows.length ? rows.map((key) => (
            <article className="scan-row" key={key.id}>
              <KeyRound size={18} />
              <div className="grow">
                <strong>{key.name}</strong>
                <p className="muted small">{key.prefix}… · Created {date(key.created_at)} · Expires {date(key.expires_at)} · Last used {date(key.last_used_at)}{key.revoked_at ? ` · Revoked ${date(key.revoked_at)}` : ""}</p>
                {confirmId === key.id && <p role="alert">Revoke {key.name}? External access with this key will stop immediately.</p>}
              </div>
              {!key.revoked_at && (confirmId === key.id ? <div className="button-row">
                <button className="button danger" type="button" disabled={busy} onClick={() => void revoke(key.id)}>Confirm revoke</button>
                <button className="button" type="button" onClick={() => setConfirmId("")}>Cancel</button>
              </div> : <button className="icon-button danger" type="button" aria-label={`Revoke ${key.name}`} onClick={() => setConfirmId(key.id)}><Trash2 size={16} /></button>)}
            </article>
          )) : <p className="muted">No API keys yet.</p>}
          {keys.hasNextPage && <button className="button" type="button" disabled={keys.isFetchingNextPage} onClick={() => void keys.fetchNextPage()}>Load more keys</button>}
        </div>
      </State>
    </Panel>
  );
}
