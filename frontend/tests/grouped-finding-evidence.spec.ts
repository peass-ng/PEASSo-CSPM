import { expect, test } from "@playwright/test";

test("one check opens paginated evidence across accounts and regions, with original asset details", async ({ page }) => {
  const group = {
    id: "check-lambda-auth", grouped: true, check_id: "aws.lambda.function_url_authentication",
    title: "Function URLs require authentication", provider: "aws", service: "lambda", category: "hardening",
    scope: "multiple", resource_id: "check:lambda-auth", status: "FAIL", severity: "high", frameworks: [],
    member_count: 51, affected_asset_count: 51, affected_regions: ["us-east-1", "eu-west-1"],
    affected_accounts: ["111122223333", "444455556666"], status_counts: { FAIL: 25, PASS: 25, UNKNOWN: 1 },
    member_filters: { categories: "hardening", service: "lambda" },
    evidence_summary: "This check has 25 failed, 25 passed and 1 undetermined observation across 51 assets.",
    remediation: "Review each function URL’s authentication and policy.",
  };
  const members = Array.from({ length: 51 }, (_, index) => ({
    id: `member-${index}`, asset: `arn:aws:lambda:${index % 2 ? "eu-west-1:444455556666" : "us-east-1:111122223333"}:function:handler-${index}`,
    scope: index % 2 ? "444455556666/eu-west-1" : "111122223333/us-east-1",
    account: index % 2 ? "444455556666" : "111122223333", region: index % 2 ? "eu-west-1" : "us-east-1",
    status: index === 50 ? "UNKNOWN" : index % 2 ? "PASS" : "FAIL", severity: "high",
    evidence_summary: index === 50 ? "The function URL authentication setting was unavailable; access remains undetermined."
      : index % 2 ? "The function URL requires AWS_IAM signed requests; caller policies still apply."
        : "The function URL declares AuthType NONE; the resource policy still determines permitted callers.",
  }));
  members[0].evidence_summary = group.evidence_summary;
  members[1].evidence_summary = `${group.evidence_summary} The function URL requires AWS_IAM signed requests.`;
  const groupRequests: URL[] = [];
  const originalRequests: string[] = [];
  let groupedListRequested = false;
  await page.route("**/api/**", async route => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", created_at: "2026-01-01" }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) {
      groupedListRequested = url.searchParams.get("aggregation") === "check";
      json = { items: [group], total: 1, next_offset: null };
    }
    if (path.endsWith("/finding-groups/check-lambda-auth")) {
      groupRequests.push(url);
      const offset = Number(url.searchParams.get("members_offset"));
      json = { ...group, members: members.slice(offset, offset + 50), members_total: members.length,
        members_next_offset: offset + 50 < members.length ? offset + 50 : null };
    }
    if (/\/findings\/[^/]+$/.test(path)) {
      originalRequests.push(path);
      const member = members.find(row => path.endsWith(`/findings/${row.id}`));
      if (member) json = { ...group, ...member, grouped: false, resource_id: member.asset,
        evidence: { reason: "function URL authentication settings unavailable" } };
    }
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByRole("button", { name: /lambda 1 finding/ }).click();
  await page.getByRole("button", { name: `${group.title} ${group.check_id}`, exact: true }).click();
  expect(groupedListRequested).toBeTruthy();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText(group.evidence_summary, { exact: true })).toBeVisible();
  const assetList = dialog.getByRole("list", { name: "Individual evidence observations" });
  await expect(assetList.locator("li")).toHaveCount(50);
  await expect(dialog.getByText(group.evidence_summary, { exact: true })).toHaveCount(1);
  await expect(assetList.locator("li").first().locator("p")).toHaveCount(1);
  await expect(assetList.locator("li").nth(1).getByText("The function URL requires AWS_IAM signed requests.", { exact: true })).toBeVisible();
  await expect(assetList.locator(".badge")).toHaveCount(0);
  await expect(dialog.getByText("111122223333 · us-east-1").first()).toBeVisible();
  await expect(dialog.getByText("444455556666 · eu-west-1").first()).toBeVisible();
  expect(originalRequests).toEqual([]);
  for (const request of groupRequests) {
    expect(request.searchParams.get("service")).toBe("lambda");
    expect(request.searchParams.get("categories")).toBe("hardening");
    expect(request.searchParams.get("members_limit")).toBe("50");
  }
  await dialog.getByRole("button", { name: "Next page", exact: true }).click();
  await expect(dialog.getByRole("list", { name: "Individual evidence observations" }).locator("li")).toHaveCount(1);
  await expect(dialog.getByText(members[50].evidence_summary, { exact: true })).toBeVisible();
  expect(groupRequests.at(-1)?.searchParams.get("members_offset")).toBe("50");
  await dialog.getByRole("button", { name: members[50].asset, exact: true }).click();
  await expect(dialog.locator(".finding-detail-asset")).toContainText(members[50].asset);
  expect(originalRequests).toEqual(["/api/scans/scan-1/findings/member-50"]);
});
