import { TableDownload } from "./TableDownload";
import { useState } from "react";
import { BoundedPager } from "./BoundedPager";
import type { Finding } from "./types";

type Row = Record<string, unknown>;
const record = (value: unknown): Row => value !== null && typeof value === "object" && !Array.isArray(value) ? value as Row : {};
const text = (value: unknown) => typeof value === "string" ? value : "";

/** All provider-confirmed unused access, including credentials outside Least Privilege. */
export function AccessAnalyzerUnusedEvidence({ finding }: { finding: Finding }) {
  const [query, setQuery] = useState("");
  const [offset, setOffset] = useState(0);
  const evidence = record(finding.evidence);
  if (finding.check_id !== "aws.claude_a.accessanalyzer.active_without_findings" || !Array.isArray(evidence.access_analyzer_findings)) return null;
  const rows = evidence.access_analyzer_findings.flatMap((value) => {
    const issue = record(value);
    const kind = text(issue.findingType);
    if (!kind.startsWith("Unused")) return [];
    const details = record(issue.FindingDetails || issue.UnusedPermissionDetails);
    const items = Array.isArray(details.items) ? details.items : [];
    const base = { principal: text(issue.resource) || "Principal not returned", kind,
      window: typeof issue.unused_access_days === "number" ? `${issue.unused_access_days} days` : "Not returned",
      complete: ["collected", "empty"].includes(text(details.collection_status)) };
    const result = items.flatMap((item) => {
      const detail = record(item);
      const permission = record(detail.unusedPermissionDetails);
      if (kind === "UnusedPermission" && text(permission.serviceNamespace)) {
        const actions = Array.isArray(permission.actions) ? permission.actions : [];
        return actions.length ? actions.map((value) => {
          const action = record(value), name = text(action.action);
          return { ...base, access: name.includes(":") ? name : `${text(permission.serviceNamespace)}:${name}`,
            last: text(action.lastAccessed) };
        }) : [{ ...base, access: `Service: ${text(permission.serviceNamespace)}`, last: text(permission.lastAccessed) }];
      }
      const credential = record(detail.unusedIamRoleDetails || detail.unusedIamUserAccessKeyDetails || detail.unusedIamUserPasswordDetails);
      if (!Object.keys(credential).length && !Object.keys(detail).some(key => key.startsWith("unusedIam"))) return [];
      return [{ ...base, access: kind === "UnusedIAMRole" ? "Role" : kind === "UnusedIAMUserPassword" ? "Console password" : `Access key ${text(credential.accessKeyId)}`,
        last: text(credential.lastAccessed) }];
    });
    return result.length ? result : [{ ...base, access: kind, last: "", complete: false }];
  });
  if (!rows.length) return null;
  const filtered = rows.filter(row => `${row.principal} ${row.access}`.toLowerCase().includes(query.toLowerCase()));
  const visible = filtered.slice(offset, offset + 50);
  return <section className="finding-detail-section">
    <h3>Unused access</h3>
    <div className="table-toolbar">
      <input type="search" aria-label="Filter unused access" placeholder="Filter principals or permissions…" value={query}
      onChange={event => { setQuery(event.target.value); setOffset(0); }} />
      <TableDownload table="unused-access" label="unused access table" rows={filtered} />
    </div>
    <div className="table-scroll"><table>
      <thead><tr><th>Principal</th><th>Unused access</th><th>Last used</th><th>Analysis window</th></tr></thead>
      <tbody>{visible.map((row, index) => <tr key={index}>
        <td>{row.principal}</td><td>{row.access}{!row.complete && <span className="badge warning">Incomplete details</span>}</td>
        <td>{row.last || (row.complete ? "No use recorded in analysis window" : "Not returned")}</td><td>{row.window}</td>
      </tr>)}</tbody>
    </table></div>
    <BoundedPager first={filtered.length ? offset + 1 : 0} last={Math.min(offset + 50, filtered.length)} total={filtered.length}
      unit="Unused access entries" pageSize={50} loading={false} canPrevious={offset > 0} canNext={offset + 50 < filtered.length}
      onPrevious={() => setOffset(Math.max(0, offset - 50))} onNext={() => setOffset(offset + 50)} onJump={setOffset} compact />
  </section>;
}
