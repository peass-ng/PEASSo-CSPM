import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { gcpCloudRunJobImageObservation, jobImageUnknown } from "../src/gcpCloudRunJobImageEvidence";
import { explainObservedEvidence } from "../src/observedEvidenceExplanation";

const fixture = JSON.parse(readFileSync(new URL("../../tests/fixtures/gcp-cloudrun-job-image-observed-20261020.json", import.meta.url), "utf8"));
const records = Object.fromEntries(fixture.records.map((r: { name: string; finding: Finding }) => [r.name, r.finding])) as Record<string, Finding>;
for (const [name, finding] of Object.entries(records)) test(`actual Job native/public typed copy ${name}`, () => {
  const before = structuredClone(finding), text = gcpCloudRunJobImageObservation(finding);
  expect(text).toContain("Cloud Run Job");
  expect(text!.match(/[.!?](?:\s|$)/g)!.length).toBeLessThanOrEqual(3);
  expect(text!.split(/\s+/).length).toBeLessThanOrEqual(55);
  expect(text).toContain("executed image");
  expect(explainObservedEvidence(finding, "unused fallback")).toBe(text);
  expect(explainObservedEvidence({ ...finding, evidence_summary_format: "natural-language-v2", evidence_summary: "old generic copy" }, "old generic copy")).toBe(text);
  expect(text!.includes("Inspection is incomplete.")).toBe(name.includes("partial"));
  expect(finding.evidence).not.toHaveProperty("parts");
  expect(finding).toEqual(before);
});

for (const fault of ["fingerprint", "linked_check", "resource", "scope", "layer", "path", "line", "raw_value", "detector", "complete", "coverage", "empty_leaks"])
  test(`Job public DTO cannot manufacture decisive copy: ${fault}`, () => {
    const f = structuredClone(records.public_fail), e = f.evidence!;
    const leak = (e.secret_leaks as { detectors: {engine: string}[]; locations: {path:string;layer:string;line:number}[]; value?:string }[])[0];
    if (fault === "fingerprint") f.secret_fingerprint = "0".repeat(64);
    else if (fault === "linked_check") f.linked_check_ids!.push("another-check");
    else if (fault === "resource") f.resource_id = "not-a-secret";
    else if (fault === "scope") f.scope = "projects/foreign";
    else if (fault === "layer") leak.locations[0].layer = "tag:latest";
    else if (fault === "path") leak.locations[0].path = "invented.txt";
    else if (fault === "line") leak.locations[0].line = -1;
    else if (fault === "raw_value") leak.value = "";
    else if (fault === "detector") leak.detectors[0].engine = "invented";
    else if (fault === "complete") e.complete = "true";
    else if (fault === "coverage") e.coverage = "incomplete";
    else e.secret_leaks = [];
    expect(gcpCloudRunJobImageObservation(f)).toBe(jobImageUnknown);
  });

for (const fault of ["image_tag", "runtime_digest", "deployed_claim", "kind", "source_path", "version", "incomplete"])
  test(`Job native copy validates actual association fields: ${fault}`, () => {
    const f = structuredClone(records.native_pass), e = f.evidence!;
    const declaration = e.job_declaration as Record<string, unknown>;
    if (fault === "image_tag") e.image_uri = "us-central1-docker.pkg.dev/review/images/app:latest";
    else if (fault === "runtime_digest") e.observed_runtime_digest = "sha256:" + "0".repeat(64);
    else if (fault === "deployed_claim") e.deployed_bytes_proven = true;
    else if (fault === "kind") declaration.kind = "Execution";
    else if (fault === "source_path") declaration.image_json_pointer = "/status/imageDigest";
    else if (fault === "version") (e.config_engines as {version:string}[])[0].version = "unknown";
    else e.complete = false;
    expect(gcpCloudRunJobImageObservation(f)).toBe(jobImageUnknown);
  });

test("actual browser renders saved native/public Job observations without inventing parts", async ({ page }) => {
  await page.goto("/", { waitUntil: "domcontentloaded" });
  const result = await page.evaluate(async rows => {
    const helperPath = "/src/gcpCloudRunJobImageEvidence.ts", explanationPath = "/src/observedEvidenceExplanation.ts";
    const helper = await import(helperPath), renderer = await import(explanationPath);
    return rows.map((f: Finding) => ({ typed: helper.gcpCloudRunJobImageObservation(f), rendered: renderer.explainObservedEvidence(f, "old generic copy") }));
  }, Object.values(records));
  for (const row of result) {
    expect(row.rendered).toBe(row.typed);
    expect(row.rendered).toContain("Cloud Run Job");
    expect(row.rendered).not.toContain("parts");
  }
});

test("unrelated findings and explicit summary opt-out remain unchanged", () => {
  expect(gcpCloudRunJobImageObservation({ ...records.native_pass, provider: "aws" })).toBeUndefined();
  expect(gcpCloudRunJobImageObservation({ ...records.native_pass, check_id: "gcp.review.other" })).toBeUndefined();
  expect(explainObservedEvidence({ ...records.native_pass, guidance_refresh: { allow_summary: false } } as Finding, "retained copy")).toBe("retained copy");
});
