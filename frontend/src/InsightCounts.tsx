import { useApi } from "./api";
import type { Report } from "./types";

type GraphCounts = { nodes?: unknown[]; edges?: unknown[]; total_nodes?: number; total_edges?: number; truncated?: boolean };
type AiCounts = { actions?: unknown[]; network?: { total?: number; findings?: unknown[] }; pending_stages?: string[] };

/** Selected-assessment totals, independent of each page's filters and pagination. */
export function useInsightCounts(scanId: string, demo: boolean, enabled: boolean, aiAvailable: boolean, report?: Report) {
  const base = `/scans/${encodeURIComponent(scanId)}`;
  const leaks = useApi<{ total: number }>(`${base}/findings?finding_type=detected_leaks&limit=1`, demo, enabled);
  const images = useApi<{ total: number; vulnerability_count?: number }>(`${base}/image-findings`, demo, enabled);
  const principals = useApi<{ total: number; recommendation_total?: number }>(`${base}/least-privilege?limit=1`, demo, enabled);
  const privesc = useApi<GraphCounts>(`${base}/graphs/privesc?max_nodes=500`, demo, enabled);
  const network = useApi<GraphCounts>(`${base}/graphs/network?max_nodes=500`, demo, enabled);
  const ai = useApi<AiCounts>(`${base}/ai?offset=0&limit=100`, demo, enabled && aiAvailable && !demo);
  const failed = report?.stats?.failed_by_category as Record<string, number> | undefined;
  const categoryCount = (category: string) => report ? failed?.[category] ??
    report.findings?.filter(f => f.category === category && f.status === "FAIL").length ?? 0 : undefined;
  const graphCount = (data: GraphCounts | undefined, kind: "nodes" | "edges") =>
    data?.[kind === "nodes" ? "total_nodes" : "total_edges"] ??
    (data?.truncated ? undefined : data?.[kind]?.length);
  return {
    // A running AI stage has no count yet; show the pending dash, not zero.
    "Top 15 Actions": ai.data?.pending_stages?.includes("priorities") && !ai.data.actions?.length ? undefined : ai.data?.actions?.length,
    "Hardening & Compliance": categoryCount("hardening"),
    "Exposure": categoryCount("exposure"),
    "Least Privilege": principals.data?.recommendation_total ?? principals.data?.total,
    "Privilege Escalation Map": graphCount(privesc.data, "edges"),
    "Network Map": graphCount(network.data, "nodes"),
    "Network Architecture": ai.data?.network?.total ?? ai.data?.network?.findings?.length,
    "Leaks": leaks.data?.total,
    "Images CVEs": images.data?.vulnerability_count ?? images.data?.total,
  } as Record<string, number | undefined>;
}
