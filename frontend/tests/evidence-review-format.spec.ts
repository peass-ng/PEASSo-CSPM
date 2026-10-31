import { expect, test } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import type { Finding } from "../src/types";
import { explainAzureFindingEvidence } from "../src/azureFindingEvidence";
import { explainAzureNativeEvidenceObservation } from "../src/azureNativeEvidenceObservation";
import { explainFindingEvidence } from "../src/findingExplanation";
import { explainObservedEvidence } from "../src/observedEvidenceExplanation";

const rootFile = (path: string) => fileURLToPath(new URL(`../../${path}`, import.meta.url));
const json = (path: string) => JSON.parse(readFileSync(rootFile(path), "utf8"));
// Preserve historical fixture archives; new admissions have separate native proof.
const selectedContent = json("tests/fixtures/selected-content-evidence-review-20261020.json");
const awsSelectedConfiguration = json("tests/fixtures/aws-selected-configuration-evidence-review-20261020.json");
const azureSelectedSecrets = json("tests/fixtures/azure-selected-secrets-evidence-review-20261020.json");
const azureSelectedDeclarations = json("tests/fixtures/azure-selected-declaration-evidence-review-20261020.json");
const awsSelectedS3 = json("tests/fixtures/aws-selected-s3-source-evidence-review-20261020.json");
const awsCodebuildInline = json("tests/fixtures/aws-codebuild-inline-public-summaries-20261020.json");
const awsWorkloadCommands = json("tests/fixtures/aws-workload-command-brief-native-20261020.json").browser_summaries;
const gcpJobImage = json("tests/fixtures/gcp-cloudrun-job-image-observed-20261020.json").records;
const azureSelectedLogs = json("tests/fixtures/azure-selected-log-sample-evidence-review-20261020.json");
const azureSelectedML = json("tests/fixtures/azure-selected-ml-job-evidence-review-20261020.json");
const azureSelectedDatabricks = json("tests/fixtures/azure-selected-databricks-evidence-review-20261020.json");
const azureSasPolicy = json("tests/fixtures/azure-sas-policy-evidence-review-20261020.json");
const azureSelectedMlAssets = json("tests/fixtures/azure-selected-ml-assets-evidence-review-20261020.json");
const azureFunctionDeclarations = json("tests/fixtures/azure-functions-declaration-evidence-review-20261020.json");
const azureNspQueryDeclarations = json("tests/fixtures/azure-nsp-query-declaration-evidence-review-20261020.json");
const azureConfiguredPackage = json("tests/fixtures/azure-configured-package-evidence-review-20261020.json");
const azureAI = json("tests/fixtures/azure-ai-evidence-review-20261020.json");
const azureNetworkAudit = json("tests/fixtures/azure-network-audit-evidence-review-20261020.json");
const azureAutomationACI = json("tests/fixtures/azure-automation-aci-evidence-review-20261020.json");
const azureFinalNative = json("tests/fixtures/azure-final-native-evidence-review-20261020.json");
const azureEdgeNative = json("tests/fixtures/azure-edge-native-evidence-review-20261020.json");
type Sample = { id: string; provider: string; status: string; summary: string };
type ReviewCases = Record<string, { status: string; summary: string }[]>;
const gcpK8s: { gcp: ReviewCases; gcp_aliases: string[]; k8s: ReviewCases } =
  JSON.parse(gunzipSync(readFileSync(rootFile("tests/fixtures/gcp_k8s_evidence_review.json.gz"))).toString());

function samples(): Sample[] {
  const result: Sample[] = json("tests/fixtures/shared_evidence_review.json");
  const aws = { ...JSON.parse(gunzipSync(readFileSync(rootFile("tests/fixtures/aws_evidence_review.json.gz"))).toString()), ...selectedContent.aws, ...awsSelectedConfiguration, ...awsSelectedS3, ...awsCodebuildInline, ...awsWorkloadCommands };
  for (const [id, cases] of Object.entries(aws) as [string, { status: string; summary: string }[]][])
    for (const row of cases) result.push({ id, provider: "aws", ...row });
  for (const [id, cases] of Object.entries(gcpK8s.gcp))
    for (const row of cases) result.push({ id, provider: "gcp", ...row });
  // This new admission has source-bound native/public DTOs instead of historical example strings.
  for (const record of gcpJobImage) {
    const finding = record.finding;
    result.push({ id: finding.check_id, provider: "gcp", status: finding.status,
      summary: explainObservedEvidence(finding, "No usable deciding evidence was recorded.") });
  }
  for (const [id, cases] of Object.entries(gcpK8s.k8s))
    for (const row of cases) result.push({ id, provider: "k8s", ...row });
  const azure = { ...JSON.parse(gunzipSync(readFileSync(rootFile("tests/fixtures/azure_evidence_review.json.gz"))).toString()), ...selectedContent.azure, ...azureAI, ...azureNetworkAudit, ...azureAutomationACI, ...azureFinalNative, ...azureEdgeNative, ...azureSelectedSecrets, ...azureSelectedDeclarations, ...azureSelectedLogs, ...azureSelectedML, ...azureSelectedDatabricks, ...azureSasPolicy, ...azureSelectedMlAssets, ...azureFunctionDeclarations, ...azureNspQueryDeclarations, ...azureConfiguredPackage };
  for (const [id, cases] of Object.entries(azure) as [string, { status: string; evidence: unknown }[]][]) {
    for (const row of cases) {
      const finding = { check_id: id, provider: "azure", title: id, status: row.status, evidence: row.evidence } as Finding;
      // Exercise the actual browser fallback against every native fixture,
      // including older artifacts which have no server-generated summary.
      const observation = explainAzureNativeEvidenceObservation(id, row.evidence, row.status)
        || explainAzureFindingEvidence(id, row.evidence, row.status)
        || explainFindingEvidence(row.evidence, row.status, id).replace(/^Observed evidence:\s*/i, "");
      result.push({ id, provider: "azure", status: row.status, summary: explainObservedEvidence(finding, observation) });
    }
  }
  return result;
}

test("every registered check has reviewed prose and browser fallback coverage", () => {
  const rows = samples();
  const nativeIds = {
    aws: Object.keys({ ...JSON.parse(gunzipSync(readFileSync(rootFile("tests/fixtures/aws_evidence_review.json.gz"))).toString()), ...selectedContent.aws, ...awsSelectedConfiguration, ...awsSelectedS3, ...awsCodebuildInline, ...awsWorkloadCommands }),
    gcp: Object.keys(gcpK8s.gcp).filter(id => !gcpK8s.gcp_aliases.includes(id)),
    azure: Object.keys({ ...JSON.parse(gunzipSync(readFileSync(rootFile("tests/fixtures/azure_evidence_review.json.gz"))).toString()), ...selectedContent.azure, ...azureAI, ...azureNetworkAudit, ...azureAutomationACI, ...azureFinalNative, ...azureEdgeNative, ...azureSelectedSecrets, ...azureSelectedDeclarations, ...azureSelectedLogs, ...azureSelectedML, ...azureSelectedDatabricks, ...azureSasPolicy, ...azureSelectedMlAssets, ...azureFunctionDeclarations, ...azureNspQueryDeclarations, ...azureConfiguredPackage }),
    k8s: Object.keys(gcpK8s.k8s),
  };
  for (const provider of ["aws", "gcp", "azure", "k8s"] as const) {
    const checked = rows.filter(row => row.provider === provider);
    const renderedIds = new Set(checked.map(row => row.id));
    expect(nativeIds[provider].filter(id => !renderedIds.has(id)), provider).toEqual([]);
    expect(checked.every(row => row.summary && !row.summary.includes("{\"")), provider).toBeTruthy();
  }
  writeFileSync("/tmp/all-provider-reviewed-browser-summaries.json", JSON.stringify(rows));
});

test("all recorded explanations fit within five desktop lines", async ({ page }) => {
  const rows = samples();
  // Use the actual inspector CSS and font metrics at the normal desktop width.
  await page.route("**/api/**", route => route.fulfill({ json: { items: [] } }));
  await page.goto("/#Settings");
  await page.addStyleTag({ path: rootFile("frontend/src/FindingInspector.css") });
  const overflow = await page.evaluate((cases) => {
    const dialog = document.createElement("div");
    dialog.className = "inspector finding-inspector";
    dialog.innerHTML = '<div class="finding-detail"><section class="finding-detail-section finding-detail-observation"><p></p></section></div>';
    document.body.append(dialog);
    const paragraph = dialog.querySelector("p")!;
    if (dialog.getBoundingClientRect().width < 650 || !Number.isFinite(Number.parseFloat(getComputedStyle(paragraph).lineHeight)))
      throw new Error("The real desktop inspector styles were not applied");
    const mismatches: { id: string; provider: string; lines: number; summary: string }[] = [];
    for (const row of cases) {
      paragraph.textContent = row.summary;
      const lineHeight = Number.parseFloat(getComputedStyle(paragraph).lineHeight);
      const lines = paragraph.getBoundingClientRect().height / lineHeight;
      if (lines > 5.05) mismatches.push({ ...row, lines });
    }
    dialog.remove();
    return mismatches;
  }, rows);
  writeFileSync("/tmp/evidence-explanation-line-overflow.json", JSON.stringify(overflow, null, 2));
  expect(overflow.slice(0, 12), `${overflow.length} recorded explanations exceed five desktop lines`).toEqual([]);
});
