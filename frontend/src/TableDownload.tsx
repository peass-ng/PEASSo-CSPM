import { Download } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { request, workspaceKey } from "./api";
import "./TableDownload.css";

type ExportPage<T> = { rows: T[]; next?: number | null; total?: number; version?: string };

export function tablePagePath(path: string, offset: number, limit: number) {
  const [base, query] = path.split("?", 2);
  const params = new URLSearchParams(query);
  params.set("offset", String(offset));
  params.set("limit", String(limit));
  return `${base}?${params}`;
}

/** Fetch the complete matching row set, without accepting a stalled or partial page. */
export async function collectTableRows<T>(
  load: (offset: number, signal: AbortSignal) => Promise<ExportPage<T>>,
  signal: AbortSignal,
): Promise<T[]> {
  const rows: T[] = [];
  let offset = 0;
  let total: number | undefined;
  let version: string | undefined;
  const workspace = sessionStorage.getItem(workspaceKey);
  for (;;) {
    signal.throwIfAborted();
    if (sessionStorage.getItem(workspaceKey) !== workspace) throw new Error("The workspace changed during export.");
    const page = await load(offset, signal);
    if (!Array.isArray(page.rows)) throw new Error("The table did not return a row list.");
    if (offset > 0 && page.version !== version) throw new Error("The table changed during export. Retry the download.");
    version = page.version;
    if (page.total !== undefined) {
      if (total !== undefined && total !== page.total) throw new Error("The table changed during export. Retry the download.");
      total = page.total;
    }
    for (const row of page.rows) rows.push(row);
    const next = page.next === undefined && total !== undefined && rows.length < total ? offset + page.rows.length : page.next;
    if (next == null) {
      if (total !== undefined && rows.length !== total) throw new Error("Some table rows could not be retrieved.");
      return rows;
    }
    if (!Number.isSafeInteger(next) || next !== offset + page.rows.length || next <= offset)
      throw new Error("The table stopped returning more rows.");
    offset = next;
  }
}

export function collectCursorTableRows<T>(
  load: (cursor: string, signal: AbortSignal) => Promise<{ items: T[]; next_cursor?: string | null; total?: number }>,
  signal: AbortSignal,
): Promise<T[]> {
  let cursor = "";
  const seen = new Set<string>();
  return collectTableRows(async (offset, pageSignal) => {
    const page = await load(cursor, pageSignal);
    cursor = page.next_cursor || "";
    if (cursor && seen.has(cursor)) throw new Error("The table stopped returning more rows.");
    if (cursor) seen.add(cursor);
    return { rows: page.items, total: page.total, next: cursor ? offset + page.items.length : null };
  }, signal);
}

export function requestTableRows<T>(path: string, key: "items" | "rows" | "issues", limit: number,
  signal: AbortSignal, demo = false): Promise<T[]> {
  return collectTableRows(async (offset, pageSignal) => {
    const page = await request<Partial<Record<typeof key, T[]>> & {
      offset?: number; next_offset?: number | null; total?: number; generation?: string;
    }>(tablePagePath(path, offset, limit), { signal: pageSignal }, demo);
    if (page.offset !== undefined && page.offset !== offset) throw new Error("The table returned an unexpected page.");
    if (!Array.isArray(page[key])) throw new Error("The table did not return a row list.");
    return { rows: page[key], next: page.next_offset, total: page.total, version: page.generation };
  }, signal);
}

type TableDownloadProps = {
  table: string;
  label: string;
  disabled?: boolean;
} & ({ rows: readonly unknown[]; loadRows?: never } |
     { rows?: never; loadRows: (signal: AbortSignal) => Promise<readonly unknown[]> });

export function TableDownload({ table, label, disabled, rows, loadRows }: TableDownloadProps) {
  const [open, setOpen] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const job = useRef<AbortController | undefined>(undefined);
  const id = useId();
  useEffect(() => () => job.current?.abort(), []);
  useEffect(() => {
    if (!open) return;
    const dismiss = (event: PointerEvent) => {
      if (event.target instanceof Node && !root.current?.contains(event.target)) setOpen(false);
    };
    document.addEventListener("pointerdown", dismiss);
    return () => document.removeEventListener("pointerdown", dismiss);
  }, [open]);

  async function download() {
    if (job.current) return;
    const controller = new AbortController();
    const workspace = sessionStorage.getItem(workspaceKey);
    job.current = controller;
    setPending(true);
    setOpen(false);
    setError("");
    button.current?.focus();
    try {
      const exported = loadRows ? await loadRows(controller.signal) : rows || [];
      controller.signal.throwIfAborted();
      if (sessionStorage.getItem(workspaceKey) !== workspace) throw new Error("The workspace changed during export.");
      const blob = new Blob([JSON.stringify({
        schema: `hacktricks-cspm.table.${table}.v1`, table, row_count: exported.length, rows: exported,
      }, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `hacktricks-cspm-${table}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (error) {
      if (!controller.signal.aborted) setError(error instanceof Error ? error.message : "Download failed.");
    } finally {
      job.current = undefined;
      if (!controller.signal.aborted) setPending(false);
    }
  }

  return <div ref={root} className="table-download" onKeyDown={event => {
    if (event.key === "Escape" && open) {
      event.preventDefault(); event.stopPropagation(); setOpen(false); button.current?.focus();
    }
  }}>
    <button ref={button} type="button" className="icon-button" aria-label={`Download ${label}`}
      title={`Download ${label}`} aria-expanded={open} aria-controls={id}
      aria-busy={pending} disabled={disabled} onClick={() => { if (!pending) setOpen(!open); }}>
      <Download size={16} aria-hidden="true" />
    </button>
    <div className="table-download-options" id={id} hidden={!open}>
      <button type="button" className="text-button" onClick={() => void download()}>JSON</button>
    </div>
    {pending && <span role="status" className="small">Preparing JSON…</span>}
    {error && <span role="alert" className="small form-error">{error}</span>}
  </div>;
}
