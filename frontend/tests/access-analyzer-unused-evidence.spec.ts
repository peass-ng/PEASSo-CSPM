import { expect, test } from "@playwright/test";

test("hardening presents unused roles, credentials and permissions outside Least Privilege", async ({ page }) => {
  const common = { resource: "arn:aws:iam::123456789012:user/example", status: "ACTIVE", unused_access_days: 90 };
  const issue = (findingType: string, detail: unknown) => ({ ...common, findingType,
    FindingDetails: { collection_status: "collected", items: [detail] } });
  const finding = { id: "unused", check_id: "aws.claude_a.accessanalyzer.active_without_findings",
    title: "IAM Access Analyzer findings", provider: "aws", category: "hardening", service: "accessanalyzer",
    resource_id: "scope:123456789012/us-east-1", scope: "123456789012/us-east-1", status: "FAIL", severity: "medium",
    frameworks: [], evidence_summary: "AWS Access Analyzer reports unused roles, credentials and permissions.",
    evidence: { findings: 4, access_analyzer_findings: [
      issue("UnusedIAMRole", { unusedIamRoleDetails: {} }),
      issue("UnusedIAMUserPassword", { unusedIamUserPasswordDetails: {} }),
      issue("UnusedIAMUserAccessKey", { unusedIamUserAccessKeyDetails: { accessKeyId: "AKIAEXAMPLE0000000000" } }),
      issue("UnusedPermission", { unusedPermissionDetails: { serviceNamespace: "s3", actions: [
        { action: "GetObject", lastAccessed: "2026-07-01T00:00:00Z" }, { action: "ListBucket" }] } }),
    ] } };
  await page.route("**/api/**", async route => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan", status: "completed", categories: ["hardening"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) json = { items: [finding], total: 1 };
    if (path.endsWith("/findings/unused")) json = finding;
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByRole("button", { name: /accessanalyzer 1 finding/ }).click();
  await page.getByRole("button", { name: /IAM Access Analyzer findings/ }).click();
  const table = page.getByRole("dialog").getByRole("table");
  await expect(table.getByRole("row")).toHaveCount(6);
  await expect(table.getByRole("cell", { name: "Role", exact: true })).toBeVisible();
  await expect(table.getByRole("cell", { name: "Console password", exact: true })).toBeVisible();
  await expect(table.getByText("s3:GetObject", { exact: true })).toBeVisible();
  await expect(table.getByText("s3:ListBucket", { exact: true })).toBeVisible();
  await expect(table.getByText("90 days", { exact: true })).toHaveCount(5);
  await expect(table.getByText("No use recorded in analysis window", { exact: true })).toHaveCount(4);
  await page.getByLabel("Filter unused access").fill("s3:GetObject");
  await expect(table.getByRole("row")).toHaveCount(2);
  await expect(table.getByText("s3:GetObject", { exact: true })).toBeVisible();
});
