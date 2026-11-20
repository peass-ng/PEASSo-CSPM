import { useApi } from "./api";
import { FindingInspector } from "./Findings";
import { Badge, Inspector, State } from "./ui";
import { NetworkArchitecture } from "./NetworkArchitecture";
import type { Finding } from "./types";
export type Reference = { domain: "findings" | "least_privilege" | "privesc_edges" | "actions"; id: string };
export type Issue = { id: string; title: string; kind: string; severity: string; status: string; description: string; impact: string; recommendation: string; verification: string; references: Reference[] };
export const issueKinds: Record<string, string> = { vulnerability: "Security issue", hardening: "Hardening suggestion", leaks: "Leaks", image_cves: "Image CVEs" };
export function SourceFinding({ scanId, id, onClose, onInspect }: { scanId: string; id: string; onClose: () => void; onInspect: (id: string) => void }) {
  const query = useApi<Finding>(`/scans/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(id)}`, false);
  if (!query.data) return <Inspector title="Supporting finding" onClose={onClose}><State loading={query.isPending} error={query.error} /></Inspector>;
  return <FindingInspector finding={query.data} scanId={scanId} lazy={false} onInspectMember={finding => onInspect(finding.id)} onClose={onClose} demo={false} />;
}
export function IssueBody({ issue }: { issue: Omit<Issue, "references"> }) {
  return <><Badge value={issue.severity} /><p>{issue.status === "confirmed" ? "Confirmed configuration" : "Needs review"} · {issueKinds[issue.kind] || issue.kind}</p>
    <h3>Description and affected scope</h3><NetworkArchitecture label="Issue description" text={issue.description} />
    <h3>Impact</h3><NetworkArchitecture label="Issue impact" text={issue.impact} />
    <h3>Recommendation</h3><NetworkArchitecture label="Issue recommendation" text={issue.recommendation} />
    <h3>Verification</h3><NetworkArchitecture label="Issue verification" text={issue.verification} /></>;
}

