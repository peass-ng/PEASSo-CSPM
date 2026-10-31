import { useQuery } from "@tanstack/react-query";
import { demoRequest } from "./fixtures";
import type {
  PrivescAdminResult,
  PrivescBroadResult,
  PrivescGraph,
  PrivescPath,
  PrivescPrincipalCard,
} from "./types";
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}
/** Lightweight framework/checklist catalog (no per-check rows or native_check_ids). */
export const catalogFrameworksPath = "/catalog/frameworks";
export const tokenKey = "hacktricks-cspm.api-token";
export const authSessionChangedEvent = "hacktricks-cspm-auth-session-changed";
export const workspaceKey = "hacktricks-cspm.workspace-id";
// Migrate tabs opened before the product rename without dropping their session.
for (const [oldKey, newKey] of [
  ["peaso.api-token", tokenKey],
  ["peaso.workspace-id", workspaceKey],
]) {
  const previousValue = sessionStorage.getItem(oldKey);
  if (previousValue !== null && sessionStorage.getItem(newKey) === null)
    sessionStorage.setItem(newKey, previousValue);
  sessionStorage.removeItem(oldKey);
}

async function authenticatedFetch(url: string, init: RequestInit = {}) {
  const token = sessionStorage.getItem(tokenKey);
  const headers = new Headers(init.headers);
  if (!headers.has("Accept")) headers.set("Accept", "application/json");
  if (init.body && !headers.has("Content-Type"))
    headers.set("Content-Type", "application/json");
  const workspaceId = sessionStorage.getItem(workspaceKey);
  if (!headers.has("X-Workspace-Id") && workspaceId && workspaceId !== "personal") headers.set("X-Workspace-Id", workspaceId);
  const addedBearer = !!token && !headers.has("Authorization");
  if (addedBearer) headers.set("Authorization", `Bearer ${token}`);
  const options: RequestInit = { ...init, credentials: "include", headers };
  let response = await fetch(url, options);
  // A rejected tab token must not mask a valid same-origin refresh session.
  // Retry reads once without that token; the server still authenticates the cookie.
  if (response.status === 401 && addedBearer &&
      (!init.method || ["GET", "HEAD"].includes(init.method.toUpperCase()))) {
    const cookieHeaders = new Headers(headers);
    cookieHeaders.delete("Authorization");
    const cookieResponse = await fetch(url, { ...options, headers: cookieHeaders });
    if (cookieResponse.ok) {
      if (sessionStorage.getItem(tokenKey) === token) {
        sessionStorage.removeItem(tokenKey);
        window.dispatchEvent(new Event(authSessionChangedEvent));
      }
    }
    response = cookieResponse;
  }
  return response;
}
export async function request<T>(
  path: string,
  init: RequestInit = {},
  demo = false,
): Promise<T> {
  if (demo) return demoRequest(path, init) as T;
  const response = await authenticatedFetch(`/api${path}`, init);
  if (!response.ok) {
    let message = `Request failed (${response.status})`;
    try {
      const data = await response.json();
      message =
        typeof data.detail === "string"
          ? data.detail
          : typeof data.error === "string"
            ? data.error
            : message;
    } catch {
      /* No evidence details or credentials in fallback */
    }
    throw new ApiError(response.status, message);
  }
  if (response.status === 204) return undefined as T;
  const data = await response.json();
  if (isDownloadEnvelope(data)) {
    const artifact = await fetchArtifact(data.download_url);
    const downloaded: unknown = await artifact.json();
    if (downloaded && typeof downloaded === "object" && !Array.isArray(downloaded)) {
      const refreshed: Record<string, unknown> = {};
      // Private matched values arrive only from the authenticated detail API,
      // never the downloaded public evidence artifact.
      if (data.secret_evidence && typeof data.secret_evidence === 'object')
        refreshed.secret_evidence = data.secret_evidence;
      // The authenticated response may refresh presentation around an immutable artifact.
      // Never merge identities, criteria, evidence, verdict or severity from this envelope.
      if (data.remediation_details && typeof data.remediation_details === "object" && !Array.isArray(data.remediation_details))
        refreshed.remediation_details = data.remediation_details;
      const presentation = data.finding_presentation;
      if (presentation && typeof presentation === "object" && !Array.isArray(presentation)) {
        const fields = presentation as Record<string, unknown>;
        for (const key of ["description", "rationale", "remediation", "remediation_details", "evidence_summary", "guidance_refresh"] as const)
          if (Object.prototype.hasOwnProperty.call(fields, key)) refreshed[key] = fields[key];
      }
      return { ...downloaded, ...refreshed } as T;
    }
    return downloaded as T;
  }
  return data as T;
}
export const json = (body: unknown, method = "POST"): RequestInit => ({
  method,
  body: JSON.stringify(body),
});
export function useApi<T>(
  path: string,
  demo: boolean,
  enabled = true,
  poll = false,
) {
  return useQuery<T>({
    queryKey: [demo ? "demo" : "live", demo ? "fixture" : sessionStorage.getItem(workspaceKey) || "personal", path],
    queryFn: () => request<T>(path, {}, demo),
    enabled,
    retry: 1,
    refetchInterval: poll ? 4000 : false,
  });
}
export function items<T>(data: { items: T[] } | undefined): T[] {
  return Array.isArray(data?.items) ? data.items : [];
}
export async function downloadReport(
  id: string,
  format: string,
  demo: boolean,
) {
  let blob: Blob;
  if (demo) {
    const report = await request<unknown>(`/scans/${id}/report`, {}, true);
    blob = new Blob(
      [
        format === "json"
          ? JSON.stringify(report, null, 2)
          : "# HackTricks CSPM fixture report\n\nExplicit demo data; not a cloud assessment.",
      ],
      { type: format === "json" ? "application/json" : "text/markdown" },
    );
  } else {
    const response = await authenticatedFetch(
      `/api/scans/${encodeURIComponent(id)}/report?format=${format}&aggregation=check`,
      {
        headers: { Accept: "application/json, text/markdown" },
      },
    );
    if (!response.ok)
      throw new ApiError(response.status, "Report download failed");
    blob = await response.blob();
    if (
      blob.size < 8192 &&
      response.headers.get("content-type")?.includes("application/json")
    ) {
      const envelope = JSON.parse(await blob.text());
      if (isDownloadEnvelope(envelope)) {
        blob = await (await fetchArtifact(envelope.download_url)).blob();
      }
    }
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `hacktricks-cspm-${id}.${format === "json" ? "json" : "md"}`;
  a.click();
  URL.revokeObjectURL(url);
}

type DownloadEnvelope = {
  secret_evidence?: unknown;
  download_url: string;
  expires_in?: number;
  format?: string;
  remediation_details?: unknown;
  finding_presentation?: unknown;
};
function isDownloadEnvelope(value: unknown): value is DownloadEnvelope {
  return (
    !!value &&
    typeof value === "object" &&
    "download_url" in value &&
    typeof value.download_url === "string"
  );
}
async function fetchArtifact(value: string) {
  const url = new URL(value, location.origin);
  if (
    !["http:", "https:"].includes(url.protocol) ||
    url.username ||
    url.password
  )
    throw new Error("Invalid artifact download URL");
  const response = await fetch(url.href, {
    credentials: "omit",
    cache: "no-store",
    referrerPolicy: "no-referrer",
    headers: {
      Accept: "application/json, text/markdown, application/octet-stream",
    },
  });
  if (!response.ok)
    throw new ApiError(
      response.status,
      "Evidence download failed. Retry to request a fresh link.",
    );
  return response;
}

// Privilege Escalation Map endpoints (docs/privesc.md).
const scanPath = (scanId: string) => `/scans/${encodeURIComponent(scanId)}`;
export const privescApi = {
  graph: (scanId: string) => `${scanPath(scanId)}/graphs/privesc`,
  admins: (scanId: string, maxDepth = 6, includeUnknown = false) =>
    `${scanPath(scanId)}/privesc/admins?max_depth=${maxDepth}&include_unknown=${includeUnknown}`,
  paths: (scanId: string, from: string, to = "", maxDepth = 6, includeUnknown = false) => {
    const params = new URLSearchParams({ from, source: from });
    if (to) {
      params.set("to", to);
      params.set("target", to);
    }
    params.set("max_depth", String(maxDepth));
    params.set("include_unknown", String(includeUnknown));
    return `${scanPath(scanId)}/privesc/paths?${params}`;
  },
  broad: (scanId: string, minTargets = 50) =>
    `${scanPath(scanId)}/privesc/broad?min_targets=${minTargets}`,
  principal: (scanId: string, principalId: string) =>
    `${scanPath(scanId)}/privesc/principals/${encodeURIComponent(principalId)}`,
  findings: (scanId: string) =>
    `${scanPath(scanId)}/findings?categories=privesc&limit=500`,
  finding: (scanId: string, findingId: string) =>
    `${scanPath(scanId)}/findings/${encodeURIComponent(findingId)}`,
};
/** Query endpoints may return a bare list or an `{items}` envelope. */
export function listOf<T>(data: T[] | { items?: T[] } | undefined): T[] {
  if (Array.isArray(data)) return data;
  return Array.isArray(data?.items) ? data.items : [];
}
export function usePrivescGraph(scanId: string, demo: boolean) {
  return useApi<PrivescGraph>(privescApi.graph(scanId), demo, !!scanId);
}
export function usePrivescAdmins(
  scanId: string,
  demo: boolean,
  enabled = true,
  includeUnknown = false,
) {
  return useApi<PrivescAdminResult[] | { items: PrivescAdminResult[] }>(
    privescApi.admins(scanId, 6, includeUnknown),
    demo,
    !!scanId && enabled,
  );
}
export function usePrivescPaths(
  scanId: string,
  demo: boolean,
  from: string,
  to = "",
  maxDepth = 6,
  includeUnknown = false,
) {
  return useApi<PrivescPath[] | { items: PrivescPath[] }>(
    privescApi.paths(scanId, from, to, maxDepth, includeUnknown),
    demo,
    !!scanId && !!from,
  );
}
export function usePrivescBroad(
  scanId: string,
  demo: boolean,
  enabled = true,
  minTargets = 50,
) {
  return useApi<PrivescBroadResult[] | { items: PrivescBroadResult[] }>(
    privescApi.broad(scanId, minTargets),
    demo,
    !!scanId && enabled,
  );
}
export function usePrivescPrincipal(
  scanId: string,
  demo: boolean,
  principalId: string,
) {
  return useApi<PrivescPrincipalCard>(
    privescApi.principal(scanId, principalId),
    demo,
    !!scanId && !!principalId,
  );
}
