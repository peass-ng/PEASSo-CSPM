import { requestTableRows } from "./TableDownload";
import { useEffect, useState } from "react";
import { request, useApi } from "./api";
import { ImagesFindingsTable } from "./ImagesFindingsTable";
import type { ImageAssetPage, ImageFinding } from "./ImagesFindingsTable";

export type ImageFindingsReport = {
  rows: ImageFinding[];
  coverage: "NOT_SCANNED" | "UNKNOWN" | "COMPLETE";
  complete: boolean;
  truncated: boolean;
  observations: number;
  invalid_observations: number;
  invalid_vulnerabilities: number;
  /** Count per rejection reason code; `missing_observation` is a scan coverage gap. */
  invalid_reasons?: Record<string, number>;
  invalid_vulnerability_reasons?: Record<string, number>;
  total: number;
  offset: number;
  next_offset: number | null;
};

export function imageFindingsPath(scanId: string, offset = 0): string {
  const path = `/scans/${encodeURIComponent(scanId)}/image-findings`;
  return offset ? `${path}?offset=${offset}&limit=100` : path;
}

export function imageFindingAssetsPath(scanId: string, findingId: string, offset = 0): string {
  return `${imageFindingsPath(scanId)}/${encodeURIComponent(findingId)}/assets?offset=${offset}&limit=50`;
}

function countLabel(count: number, singular: string, plural: string): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

function reasonLabel(reasons: Record<string, number> | undefined): string {
  const entries = Object.entries(reasons || {})
    .filter(([reason, count]) => /^[a-z][a-z0-9_]{0,63}$/.test(reason) && Number.isInteger(count) && count > 0)
    .sort(([a], [b]) => a.localeCompare(b));
  return entries.length ? ` (${entries.map(([reason, count]) => `${reason.replace(/_/g, " ")}: ${count}`).join(", ")})` : "";
}

/** Fail closed when completion metadata is missing or contradictory. */
export function imageFindingsPresentation(report: ImageFindingsReport): {
  coverage: "NOT_SCANNED" | "UNKNOWN" | "COMPLETE";
  warning?: string;
} {
  if (report.coverage === "NOT_SCANNED" && report.rows.length === 0 && report.observations === 0 &&
    report.complete === false && report.truncated === false) return { coverage: "NOT_SCANNED" };
  const partial = [
    report.truncated ? "report truncated" : "",
    report.invalid_observations > 0 ? countLabel(report.invalid_observations, "unusable observation", "unusable observations") + reasonLabel(report.invalid_reasons) : "",
    report.invalid_vulnerabilities > 0 ? countLabel(report.invalid_vulnerabilities, "invalid vulnerability", "invalid vulnerabilities") + reasonLabel(report.invalid_vulnerability_reasons) : "",
  ].filter(Boolean);
  const complete = report.coverage === "COMPLETE" && report.complete === true && report.observations > 0 &&
    report.truncated === false && report.invalid_observations === 0 &&
    report.invalid_vulnerabilities === 0 &&
    report.rows.every((row) => row.coverage === "COMPLETE");
  if (complete) return { coverage: "COMPLETE" };
  return { coverage: "UNKNOWN", warning: partial.length
    ? `Image findings are incomplete: ${partial.join(", ")}. Results may be missing.`
    : "Image scan coverage is incomplete. Findings shown here may be missing." };
}

export function ImagesFindings({ scanId, demo }: { scanId: string; demo: boolean }) {
  return <ImagesFindingsPage key={`${scanId}:${demo}`} scanId={scanId} demo={demo} />;
}

export function mergeImageFindingPages(previous: ImageFindingsReport | undefined, page: ImageFindingsReport): ImageFindingsReport {
  if (!previous || page.offset === 0) return page;
  const rows = [...previous.rows];
  const seen = new Set(rows.map((row) => row.id));
  for (const row of page.rows) if (!seen.has(row.id)) { rows.push(row); seen.add(row.id); }
  return { ...page, rows };
}

function ImagesFindingsPage({ scanId, demo }: { scanId: string; demo: boolean }) {
  const [offset, setOffset] = useState(0);
  const [loaded, setLoaded] = useState<ImageFindingsReport>();
  const query = useApi<ImageFindingsReport>(imageFindingsPath(scanId, offset), demo, !!scanId);
  useEffect(() => {
    if (query.data) {
      setLoaded((previous) => mergeImageFindingPages(previous, query.data!));
      // The report is capped at 5,000 rows. Finish bounded pagination so grouping
      // covers the assessment, while retaining partial positives on an error.
      const next = query.data.next_offset;
      if (next != null && next > offset && next < 5000) setOffset(next);
    }
  }, [query.data, offset]);
  if (!scanId) return <p className="images-findings-state" role="status">Select a completed assessment to view image findings.</p>;
  const report = loaded || query.data;
  const presentation = report ? imageFindingsPresentation(report) : undefined;
  const nextOffset = report?.next_offset;
  const stalled = !!report && report.rows.length < report.total &&
    (nextOffset == null || nextOffset <= offset) && !query.isPending;
  const moreError = offset > 0 && !!query.error;
  return <ImagesFindingsTable
    rows={report?.rows || []}
    coverage={stalled ? "UNKNOWN" : presentation?.coverage}
    coverageWarning={stalled ? "Image findings are incomplete: more rows could not be returned." : presentation?.warning}
    loading={offset === 0 && query.isPending}
    error={offset === 0 ? query.error : null}
    onRetry={() => void query.refetch()}
    total={report?.total}
    hasMore={nextOffset != null && nextOffset > offset}
    loadingMore={offset > 0 && query.isPending}
    loadMoreError={moreError}
    onLoadMore={() => {
      if (moreError) void query.refetch();
      else if (nextOffset != null && nextOffset > offset) setOffset(nextOffset);
    }}
    loadAllRows={signal => requestTableRows<ImageFinding>(imageFindingsPath(scanId), "rows", 100, signal, demo)}
    loadAssets={(row, assetOffset, signal): Promise<ImageAssetPage> =>
      request<ImageAssetPage>(imageFindingAssetsPath(scanId, row.id, assetOffset), { signal }, demo)}
  />;
}
