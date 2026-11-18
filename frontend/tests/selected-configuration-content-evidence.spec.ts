import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";
import type { Finding } from "../src/types";
import { selectedConfigurationContentObservation } from "../src/selectedConfigurationContentEvidence";
const read = (path: string) => JSON.parse(readFileSync(new URL(`../../${path}`, import.meta.url), "utf8"));
const codebuild = read("tests/fixtures/aws-codebuild-inline-evidence-review-20261020.json");
for (const id of Object.keys(codebuild)) codebuild[id] = codebuild[id].slice(0, 3);
const fixtures = { ...codebuild, ...read("tests/fixtures/gcp-dataflow-batch-source-evidence-review-20261020.json"), ...read("tests/fixtures/gcp-workbench-source-evidence-review-20261020.json"), ...read("tests/fixtures/k8s-selected-metadata-evidence-review-20261020.json"), ...read("tests/fixtures/gcp-dataproc-source-evidence-review-20261020.json"), ...read("tests/fixtures/aws-selected-configuration-evidence-review-20261020.json"), ...read("tests/fixtures/aws-selected-s3-source-evidence-review-20261020.json"), ...read("tests/fixtures/azure-selected-secrets-evidence-review-20261020.json"), ...read("tests/fixtures/azure-selected-log-sample-evidence-review-20261020.json"), ...read("tests/fixtures/azure-selected-databricks-evidence-review-20261020.json"), ...read("tests/fixtures/azure-selected-ml-assets-evidence-review-20261020.json"), ...read("tests/fixtures/azure-selected-ml-job-evidence-review-20261020.json"), ...read("tests/fixtures/k8s-selected-log-sample-evidence-review-20261020.json"), ...read("tests/fixtures/azure-selected-declaration-evidence-review-20261020.json") };
for (const [id, branches] of Object.entries(fixtures) as [string, { status: string; evidence: unknown }[]][])
  for (const branch of branches)
    test(`${id} ${branch.status} matches current native facts`, () => {
      const finding = { check_id: id, provider: id.startsWith("aws.") ? "aws" : id.startsWith("k8s.") ? "k8s" : id.startsWith("gcp.") ? "gcp" : "azure", ...structuredClone(branch) } as Finding;
      const before = structuredClone(finding), text = selectedConfigurationContentObservation(finding);
      if (["PASS", "FAIL"].includes(branch.status)) {
        expect(text).toBeTruthy();
        expect(text!.split(/\s+/).length).toBeLessThanOrEqual(35);
        expect(selectedConfigurationContentObservation({ ...finding, status: branch.status === "PASS" ? "FAIL" : "PASS" })).toBeUndefined();
      } else expect(text).toBeUndefined();
      expect(finding).toEqual(before);
    });
for (const fault of ["incomplete", "no-detectors", "raw-secret", "unknown-detector", "missing-location", "negative-line", "duplicate-leak", "bad-coverage"])
  test(`malformed current source cannot supply decisive prose: ${fault}`, () => {
    const id = "azure.review.storage.selected_source_secret_indicators";
    const row = structuredClone(fixtures[id].find((r: { status: string }) => r.status === "FAIL"));
    if (fault === "incomplete") row.evidence.complete = false;
    else if (fault === "no-detectors") row.evidence.secret_leaks[0].detectors = [];
    else if (fault === "raw-secret") row.evidence.secret_leaks[0].value = "";
    else if (fault === "unknown-detector") row.evidence.secret_leaks[0].detectors[0].engine = "unreviewed";
    else if (fault === "missing-location") row.evidence.secret_leaks[0].locations = [{}];
    else if (fault === "negative-line") row.evidence.secret_leaks[0].locations[0].line = -1;
    else if (fault === "duplicate-leak") row.evidence.secret_leaks.push(structuredClone(row.evidence.secret_leaks[0]));
    else row.evidence.coverage = "whole-subscription";
    expect(selectedConfigurationContentObservation({ check_id: id, provider: "azure", ...row } as Finding)).toBeUndefined();
  });

test("actual incomplete metadata hit stays brief and never becomes clean", async () => {
  const { explainObservedEvidence } = await import("../src/observedEvidenceExplanation");
  const finding = read("tests/fixtures/k8s-selected-metadata-partial-evidence-review-20261020.json") as Finding;
  const before = structuredClone(finding);
  const text = selectedConfigurationContentObservation(finding);
  expect(text).toContain("inspection is incomplete");
  expect(text!.split(".").filter(Boolean)).toHaveLength(2);
  expect(explainObservedEvidence(finding, text!)).toBe(text);
  expect(finding).toEqual(before);
  expect(selectedConfigurationContentObservation({ ...finding, status: "PASS" })).toBeUndefined();
  const malformed = structuredClone(finding);
  (malformed.evidence as { secret_leaks: unknown[] }).secret_leaks = [];
  expect(selectedConfigurationContentObservation(malformed)).toBeUndefined();
});

test("actual consolidated metadata hit preserves scope without claiming clean coverage", async () => {
  const { explainObservedEvidence } = await import("../src/observedEvidenceExplanation");
  const f = read("tests/fixtures/k8s-selected-metadata-consolidated-evidence-review-20261020.json") as Finding;
  const before = structuredClone(f), text = selectedConfigurationContentObservation(f);
  expect(text).toContain("selected object labels or annotations");
  expect(text).toContain("not validated");
  expect(text).not.toContain("complete");
  expect(explainObservedEvidence(f, text!)).toBe(text);
  expect(f).toEqual(before);
  expect(selectedConfigurationContentObservation({ ...f, secret_fingerprint: "0".repeat(64) })).toBeUndefined();
});

test("Workbench actual public partial trusted hit stays visible and uncertain", () => {
  const proof = read("tests/fixtures/gcp-workbench-source-partial-evidence-review-20261020.json");
  for (const finding of proof.public_findings as Finding[]) {
    const before = structuredClone(finding), summary = selectedConfigurationContentObservation(finding);
    if (finding.status === "UNKNOWN") expect(summary).toBeUndefined();
    else {
      expect(finding.status).toBe("FAIL");
      expect(summary).toContain("Workbench referenced source");
      expect(summary).toContain("inspection is incomplete");
      const corrupted = structuredClone(finding);
      (corrupted.evidence!.secret_leaks as { locations: {scope: string}[] }[])[0].locations[0].scope = "unbound";
      expect(selectedConfigurationContentObservation(corrupted)).toBeUndefined();
    }
    expect(finding).toEqual(before);
  }
});
