import { useState } from "react";
import { TableDownload, collectTableRows } from "./TableDownload";
import { request, useApi } from "./api";
import { State } from "./ui";
import { findingStatusCounts } from "./findingStatus";
import { BoundedPager } from "./BoundedPager";
import type { Finding, FindingGroupDetail, FindingGroupMember } from "./types";

const PAGE_SIZE = 50;

function additionalMemberEvidence(summary: string | undefined, groupSummary: string | undefined): string | undefined {
  const memberText = summary?.trim();
  if (!memberText) return undefined;
  const sharedText = groupSummary?.trim();
  if (!sharedText) return memberText;
  const normalize = (value: string) => value.replace(/^Observed evidence:\s*/i, "").replace(/\s+/g, " ").trim();
  const memberNormalized = normalize(memberText);
  const sharedNormalized = normalize(sharedText);
  if (sharedNormalized.includes(memberNormalized)) return undefined;
  if (memberNormalized.startsWith(sharedNormalized) && /^[\s.;:!?]/.test(memberNormalized.slice(sharedNormalized.length))) {
    const extra = memberNormalized.slice(sharedNormalized.length).replace(/^[\s.;:!?]+/, "").trim();
    return extra || undefined;
  }
  return memberText;
}

export function findingGroupPath(scanId: string, finding: Finding, offset = 0): string {
  const params = new URLSearchParams({ members_offset: String(offset), members_limit: String(PAGE_SIZE) });
  for (const [key, value] of Object.entries(finding.member_filters || {}))
    if (value !== "") params.set(key, Array.isArray(value) ? value.join(",") : value);
  return `/scans/${encodeURIComponent(scanId)}/finding-groups/${encodeURIComponent(finding.id)}?${params}`;
}

/** One check, with its original per-asset observations kept distinct and paged. */
export function GroupedFindingEvidence({ finding, scanId, demo, onInspectMember }: {
  finding: Finding;
  scanId: string;
  demo: boolean;
  onInspectMember: (member: FindingGroupMember) => void;
}) {
  const [offset, setOffset] = useState(0);
  const query = useApi<FindingGroupDetail>(findingGroupPath(scanId, finding, offset), demo);
  const detail = query.data;
  const groupSummary = detail?.evidence_summary || finding.evidence_summary;
  const members = detail?.members || [];
  const total = detail?.members_total ?? finding.member_count ?? 0;
  const counts = detail?.status_counts || finding.status_counts || {};
  const next = detail?.members_next_offset ?? detail?.next_offset;
  const canNext = typeof next === "number" || offset + members.length < total;
  return <State loading={query.isPending} error={query.error} onRetry={() => void query.refetch()}>
    <p>{groupSummary || `${total.toLocaleString()} observations are recorded for this check. Review each asset’s result below.`}</p>
    {Object.keys(counts).length > 0 && <div className="finding-group-statuses" aria-label="Results by status">
      {findingStatusCounts(counts).map(({ label, count, tone }) =>
        <span key={label}><span className={`badge ${tone}`}>{label}</span> {count.toLocaleString()}</span>)}
    </div>}
    {detail?.affected_scope_incomplete && <p>The evidence does not identify every affected resource for this check.</p>}
    <h4>Check observations</h4>
    <TableDownload table="finding-group-assets" label="check observations"
      loadRows={signal => collectTableRows(async (pageOffset, pageSignal) => {
        const page = await request<FindingGroupDetail>(findingGroupPath(scanId, finding, pageOffset), { signal: pageSignal }, demo);
        return { rows: page.members, total: page.members_total, next: page.members_next_offset ?? page.next_offset };
      }, signal)} />
    <ol className="finding-group-members" aria-label="Individual evidence observations">
      {members.map(member => {
        const additionalEvidence = additionalMemberEvidence(member.evidence_summary, groupSummary);
        return <li key={member.id}>
          <div className="finding-group-member-heading">
            <button type="button" className="text-button" onClick={() => onInspectMember(member)}>{member.resource_name || member.native_resource_id || member.asset || member.resource_id || member.id}</button>
          </div>
          <p className="finding-group-member-scope">{member.account && member.region ? `${member.account} · ${member.region}` : member.scope}</p>
          {!!member.affected_subjects?.length && <ul aria-label="Directly affected subjects">
            {member.affected_subjects.map(subject => <li key={[subject.provider, subject.scope, subject.type, subject.native_id].join("|")}>
              {subject.kind === "scope" ? `Configuration scope ${subject.scope}` : subject.native_id}
            </li>)}
          </ul>}
          {additionalEvidence && <p>{additionalEvidence}</p>}
        </li>;
      })}
    </ol>
    {total > PAGE_SIZE && <BoundedPager first={offset + 1} last={offset + members.length} total={total}
      unit="Observations" pageSize={PAGE_SIZE} loading={query.isFetching}
      canPrevious={offset > 0} canNext={canNext}
      onPrevious={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
      onNext={() => setOffset(typeof next === "number" ? next : offset + PAGE_SIZE)}
      onJump={setOffset} compact />}
  </State>;
}
