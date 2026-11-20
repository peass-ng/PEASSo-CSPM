import { useEffect, useRef, useState } from "react";
import type { MouseEvent, ReactNode } from "react";
import {
  AlertCircle,
  ArrowRight,
  LoaderCircle,
  X,
  ShieldCheck,
} from "lucide-react";

export function openInspectorFromRow(
  event: MouseEvent<HTMLTableRowElement>,
  open: (trigger: HTMLButtonElement | null) => void,
) {
  if (event.defaultPrevented || event.button !== 0 || event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
  if (!(event.target instanceof Element) || event.target.closest(
    'a, button, input, select, textarea, summary, [role="button"], [role="link"], [contenteditable]:not([contenteditable="false"])',
  )) return;
  if (event.currentTarget.ownerDocument.getSelection()?.isCollapsed === false) return;
  const trigger = event.currentTarget.querySelector<HTMLButtonElement>('button.finding-title');
  trigger?.focus({ preventScroll: true });
  open(trigger);
}

export function ProviderIcon({
  provider,
  size = 28,
}: {
  provider: string;
  size?: number;
}) {
  return (
    <img
      className="provider-icon"
      src={`/icons/${["aws", "gcp", "azure", "k8s"].includes(provider) ? provider : "generic"}.svg`}
      width={size}
      height={size}
      alt={`${provider} provider`}
    />
  );
}
export function Badge({ value }: { value: string }) {
  const label = value === "queue_exhausted" ? "Queue exhausted" : value.toLowerCase().replaceAll("_", " ");
  return (
    <span
      className={`badge ${value.toLowerCase().replace(/[^a-z_]/g, "")}`}
      title={label}
    >
      {label}
    </span>
  );
}
export function State({
  loading,
  error,
  empty,
  onRetry,
  title,
  emptyMessage,
  children,
}: {
  loading?: boolean;
  error?: unknown;
  empty?: boolean;
  onRetry?: () => void;
  title?: string;
  emptyMessage?: string;
  children?: ReactNode;
}) {
  if (loading)
    return (
      <div className="state" role="status">
        <LoaderCircle className="spin" />
        <h3>Loading evidence</h3>
        <p>Requesting the latest data from your API.</p>
      </div>
    );
  if (error)
    return (
      <div className="state error" role="alert">
        <AlertCircle />
        <h3>Data could not be loaded</h3>
        <p>{humanError(error)}</p>
        {onRetry && (
          <button className="button" onClick={onRetry}>
            Try again
          </button>
        )}
      </div>
    );
  if (empty)
    return (
      <div className="state">
        <ShieldCheck />
        <h3>{title || "No evidence yet"}</h3>
        <p>
          {emptyMessage || "Connect a cloud environment and run a scan. Missing evidence does not mean a resource is secure."}
        </p>
        {children}
      </div>
    );
  return <>{children}</>;
}
export function humanError(error: unknown): string {
  const message = error instanceof Error ? error.message : typeof error === "string" ? error : "";
  if (!message) return "The API is unavailable.";
  const parsed = evidenceInput(message);
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const record = parsed as Record<string, unknown>;
    const prefix = typeof record.context === "string" ? `${record.context}: ` : "";
    for (const key of ["detail", "message", "error", "reason"]) {
      if (typeof record[key] === "string" && record[key]) return prefix + record[key];
    }
    return "The API returned structured error details. Try again or review the request.";
  }
  return typeof parsed === "string" ? parsed : "The API returned an unreadable error.";
}
export function Panel({
  title,
  kicker,
  children,
  action,
  className = "",
}: {
  title?: string;
  kicker?: string;
  children: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      {title && (
        <div className="panel-heading">
          <div>
            {kicker && <span className="eyebrow">{kicker}</span>}
            <h2>{title}</h2>
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}
export function EmptyAction({
  onClick,
  children,
}: {
  onClick: () => void;
  children: ReactNode;
}) {
  return (
    <button className="button primary" onClick={onClick}>
      {children}
      <ArrowRight size={16} />
    </button>
  );
}
export function Inspector({
  title,
  onClose,
  children,
  className,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  className?: string;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    const trigger = dialog?.ownerDocument.activeElement;
    dialog?.showModal();
    return () => {
      dialog?.close();
      if (trigger instanceof HTMLElement) requestAnimationFrame(() => {
        if (trigger.isConnected) trigger.focus({ preventScroll: true });
      });
    };
  }, []);
  return (
    <dialog ref={ref} className={`inspector${className ? ` ${className}` : ""}`} onCancel={onClose}>
      <div className="inspector-heading">
        <h2>{title}</h2>
        <button
          className="icon-button"
          aria-label="Close inspector"
          onClick={onClose}
        >
          <X />
        </button>
      </div>
      {children}
    </dialog>
  );
}
const EVIDENCE_PAGE = 20;
const EVIDENCE_DEPTH = 8;
const EVIDENCE_TEXT = 5000;
const sensitiveField = (key: string) => /(?:secret|password|private.?key|credential|access.?token|refresh.?token|session.?token|api.?key|sa_json)/i.test(key);

function evidenceLabel(key: string) {
  const names: Record<string, string> = {
    arn: "ARN", cidr: "CIDR", id: "ID", ip: "IP", vpc: "VPC",
    iam: "IAM", api: "API", url: "URL", tls: "TLS",
  };
  return key.replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/[_-]+/g, " ").split(" ")
    .map((part) => names[part.toLowerCase()] || part)
    .join(" ").replace(/^./, (letter) => letter.toUpperCase());
}

function evidenceInput(data: unknown): unknown {
  if (typeof data !== "string") return data;
  const trimmed = data.trim();
  const start = trimmed.search(/[\[{]/);
  if (start < 0) return data;
  const prefix = trimmed.slice(0, start).trim();
  if (prefix && !/^(?:HTTP\s*\d+|Request failed(?:\s*\(\d+\))?)\s*:?$/i.test(prefix)) return data;
  const candidate = trimmed.slice(start);
  // Catalog resource selectors are literal placeholders, not encoded JSON.
  if (/^\{[a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*\}$/.test(candidate)) return data;
  if (candidate.startsWith("[") && !/^[\[{"\s\d\-tfn]/.test(candidate.slice(1))) return data;
  if (/^\[[0-9a-fA-F:.]+\](?::\d+)?$/.test(candidate)) return data;
  if (trimmed.length > 1_000_000) return "Structured text is too large for inline display. Download the full evidence.";
  try {
    const parsed = JSON.parse(candidate) as unknown;
    return prefix && parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? { context: prefix.replace(/:\s*$/, ""), ...parsed } : parsed;
  } catch {
    return candidate.startsWith("{") || /^\[\s*(?:\{|\[|"|true|false|null|-?\d)/.test(candidate)
      ? "Structured text could not be parsed. Download the full evidence to inspect its original value."
      : data;
  }
}

function EvidenceField({ name, value, depth }: { name: string; value: unknown; depth: number }) {
  const hidden = sensitiveField(name);
  const content = hidden ? undefined : evidenceInput(value);
  const structured = content !== null && typeof content === "object";
  return <div className={`evidence-field${structured ? " evidence-field-structured" : ""}`}>
    <dt>{evidenceLabel(name)}</dt>
    <dd>{hidden ? "Sensitive value withheld from preview" : <EvidenceValue value={value} depth={depth} />}</dd>
  </div>;
}

function EvidenceValue({ value, depth = 0, initiallyOpen }: { value: unknown; depth?: number; initiallyOpen?: boolean }) {
  const [view, setView] = useState({ value, open: initiallyOpen ?? (depth <= 1), page: 0, deep: false });
  const current = view.value === value;
  const open = current ? view.open : initiallyOpen ?? (depth <= 1);
  const page = current ? view.page : 0;
  const deep = current && view.deep;
  const update = (change: Partial<typeof view>) => setView({ value, open, page, deep, ...change });
  const data = evidenceInput(value);
  if (data == null) return <span className="muted">Not supplied</span>;
  if (typeof data === "boolean") return <span>{data ? "Yes" : "No"}</span>;
  if (typeof data === "number") return <span>{Number.isFinite(data) ? String(data) : "Unknown number"}</span>;
  if (typeof data === "string") {
    const textPage = Math.min(page, Math.max(0, Math.ceil(data.length / EVIDENCE_TEXT) - 1));
    return <span className="evidence-value">{data.slice(textPage * EVIDENCE_TEXT, (textPage + 1) * EVIDENCE_TEXT) || "Empty value"}
      {data.length > EVIDENCE_TEXT && <span className="evidence-pager"><span>Characters {textPage * EVIDENCE_TEXT + 1}–{Math.min((textPage + 1) * EVIDENCE_TEXT, data.length)} of {data.length}</span><button type="button" disabled={textPage === 0} onClick={() => update({ page: textPage - 1 })}>Previous</button><button type="button" disabled={(textPage + 1) * EVIDENCE_TEXT >= data.length} onClick={() => update({ page: textPage + 1 })}>Next</button></span>}
    </span>;
  }
  if (depth >= EVIDENCE_DEPTH && !deep)
    return <button className="button evidence-expand" type="button" onClick={() => update({ deep: true, open: true, page: 0 })}>Show deeper supplied fields</button>;
  const childDepth = depth >= EVIDENCE_DEPTH ? 0 : depth + 1;
  if (Array.isArray(data)) {
    if (!data.length) return <span className="muted">No records supplied</span>;
    const shownPage = Math.min(page, Math.max(0, Math.ceil(data.length / EVIDENCE_PAGE) - 1));
    const start = shownPage * EVIDENCE_PAGE;
    const primitive = data.every((item) => item == null || ["string", "number", "boolean"].includes(typeof item));
    if (!open && !primitive) return <button className="button evidence-expand" type="button" onClick={() => update({ open: true })}>Show {data.length} supplied records</button>;
    return <>
      <ol className="evidence-list">
        {data.slice(start, start + EVIDENCE_PAGE).map((item, index) =>
          <li key={start + index}><span className="evidence-record-label">Record {start + index + 1}</span><EvidenceValue value={item} depth={childDepth} /></li>)}
      </ol>
      {data.length > EVIDENCE_PAGE && <div className="evidence-pager"><span>Records {start + 1}–{Math.min(start + EVIDENCE_PAGE, data.length)} of {data.length}</span><button type="button" disabled={shownPage === 0} onClick={() => update({ page: shownPage - 1 })}>Previous</button><button type="button" disabled={start + EVIDENCE_PAGE >= data.length} onClick={() => update({ page: shownPage + 1 })}>Next</button></div>}
    </>;
  }
  if (typeof data !== "object") return <span className="muted">Value unavailable</span>;
  const fields = Object.entries(data as Record<string, unknown>);
  if (!fields.length) return <span className="muted">No fields supplied</span>;
  if (!open) return <button className="button evidence-expand" type="button" onClick={() => update({ open: true })}>Show {fields.length} supplied fields</button>;
  const statements = (data as Record<string, unknown>).Statement;
  if (Array.isArray(statements) || (statements && typeof statements === "object")) {
    const rows = Array.isArray(statements) ? statements : [statements];
    const shownPage = Math.min(page, Math.max(0, Math.ceil(rows.length / EVIDENCE_PAGE) - 1));
    const start = shownPage * EVIDENCE_PAGE;
    return <div className="evidence-policy">
      <dl className="evidence-fields">{fields.filter(([key]) => key !== "Statement").map(([key, field]) =>
        <EvidenceField key={key} name={key} value={field} depth={childDepth} />)}</dl>
      <h4>Policy statements · {rows.length}</h4>
      {rows.slice(start, start + EVIDENCE_PAGE).map((row, index) =>
        <section className="evidence-policy-statement" key={start + index}>
          <h5>Statement {start + index + 1}</h5>
          <EvidenceValue value={row} depth={childDepth} initiallyOpen />
        </section>)}
      {rows.length > EVIDENCE_PAGE && <div className="evidence-pager"><span>Statements {start + 1}–{Math.min(start + EVIDENCE_PAGE, rows.length)} of {rows.length}</span><button type="button" disabled={shownPage === 0} onClick={() => update({ page: shownPage - 1 })}>Previous</button><button type="button" disabled={start + EVIDENCE_PAGE >= rows.length} onClick={() => update({ page: shownPage + 1 })}>Next</button></div>}
    </div>;
  }
  const shownPage = Math.min(page, Math.max(0, Math.ceil(fields.length / EVIDENCE_PAGE) - 1));
  const start = shownPage * EVIDENCE_PAGE;
  return <>
    <dl className="evidence-fields">
      {fields.slice(start, start + EVIDENCE_PAGE).map(([key, field]) =>
        <EvidenceField key={key} name={key} value={field} depth={childDepth} />)}
    </dl>
    {fields.length > EVIDENCE_PAGE && <div className="evidence-pager"><span>Fields {start + 1}–{Math.min(start + EVIDENCE_PAGE, fields.length)} of {fields.length}</span><button type="button" disabled={shownPage === 0} onClick={() => update({ page: shownPage - 1 })}>Previous</button><button type="button" disabled={start + EVIDENCE_PAGE >= fields.length} onClick={() => update({ page: shownPage + 1 })}>Next</button></div>}
  </>;
}

export function EvidenceFields({ data }: { data: unknown }) {
  return <div className="evidence-presented"><EvidenceValue value={data} /></div>;
}

export function Evidence({ data, previewData = data }: { data: unknown; previewData?: unknown }) {
  const full = typeof data === "string" ? data : JSON.stringify(data ?? null, null, 2);
  function download() {
    const blob = new Blob([full], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "hacktricks-cspm-evidence.json";
    a.click();
    URL.revokeObjectURL(url);
  }
  return <section className="evidence-presented">
    <EvidenceValue value={previewData} />
    <div className="button-row"><button className="button" onClick={download}>Download full evidence</button></div>
  </section>;
}
export function date(value?: string) {
  if (!value) return "Not available";
  const d = new Date(value);
  return Number.isNaN(d.getTime())
    ? "Not available"
    : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

export function sourceHref(value?: string) {
  if (!value) return undefined;
  try {
    const url = new URL(value, location.origin);
    return ["https:", "http:"].includes(url.protocol) ? url.href : undefined;
  } catch {
    return undefined;
  }
}
