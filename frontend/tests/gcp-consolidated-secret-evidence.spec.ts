import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { gcpConsolidatedSecretObservation } from "../src/gcpConsolidatedSecretEvidence";
import { selectedConfigurationContentObservation } from "../src/selectedConfigurationContentEvidence";
const read = (name: string) => JSON.parse(readFileSync(new URL(`../../tests/fixtures/public_secret_captures/${name}`, import.meta.url), "utf8"));
function* findings(value: unknown): Generator<Finding> {
  if (Array.isArray(value)) { for (const row of value) yield* findings(row); }
  else if (value && typeof value === "object") {
    if ("check_id" in value && "status" in value) yield value as Finding;
    else for (const child of Object.values(value)) yield* findings(child);
  }
}
const rows = [
  ...findings(read("workbench-source-runtime-public-findings-20261020.json")),
  ...findings(read("dataflow-batch-source-runtime-public-findings-20261020.json")),
];
for (const [index, finding] of rows.entries()) {
  test(`actual source dedup ${index}: ${finding.check_id} ${finding.status}`, () => {
    const before = structuredClone(finding), text = gcpConsolidatedSecretObservation(finding);
    if (finding.status === "FAIL") {
      expect(text).toContain("likely secret");
      expect(text).toContain("not validated");
      expect(text!.split(/\s+/).length).toBeLessThanOrEqual(35);
      expect(text!.includes("inspection is incomplete")).toBe(finding.evidence?.complete === false);
      expect(selectedConfigurationContentObservation(finding)).toBe(text);
      if ((finding.linked_check_ids?.length || 0) > 1) expect(text).toContain("Batch and Dataflow");
    } else expect(text).toBeUndefined();
    expect(finding).toEqual(before);
  });
}
for (const fault of ["fingerprint", "unknown-check", "duplicate-link", "raw-value", "empty-location", "unknown-engine", "scope", "path", "resource", "flags", "observed"]) {
  test(`unbound consolidated source facts rejected: ${fault}`, () => {
    const finding = structuredClone(rows.find(f => f.status === "FAIL" && (f.linked_check_ids?.length || 0) > 1)!);
    const e = finding.evidence as Record<string, any>, leak = e.secret_leaks[0];
    if (fault === "fingerprint") finding.secret_fingerprint = "0".repeat(64);
    else if (fault === "unknown-check") finding.linked_check_ids!.push("gcp.review.unreviewed.secret_indicators");
    else if (fault === "duplicate-link") finding.linked_check_ids!.push(finding.linked_check_ids![0]);
    else if (fault === "raw-value") leak.value = "must-not-be-rendered";
    else if (fault === "empty-location") leak.locations = [];
    else if (fault === "unknown-engine") leak.detectors[0].engine = "unreviewed";
    else if (fault === "flags") Object.assign(e, {complete: true, coverage: "incomplete"});
    else if (fault === "observed") e.observed = "No secrets were found.";
    else leak.locations[0][{scope: "scope", path: "path", resource: "resource_id"}[fault]!] = "unbound";
    expect(gcpConsolidatedSecretObservation(finding)).toBeUndefined();
  });
}
