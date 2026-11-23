import { expect, test } from "@playwright/test";

test("Type groups checks across services and lazily pages a type with its filters", async ({ page }) => {
  const requests: URL[] = [];
  const check = (id: string, service: string, type: string) => ({
    id, grouped: true, check_id: id, title: `${service} encryption enabled`, service, finding_type: type,
    provider: "aws", category: "hardening", severity: "high", status: "FAIL", frameworks: [],
    scope: "111122223333/us-east-1", resource_id: id, member_count: 1, affected_asset_count: 1,
    affected_accounts: ["111122223333"], status_counts: { FAIL: 1 },
  });
  const encryption = Array.from({ length: 51 }, (_, i) => check(`encrypted-${i}`, i % 2 ? "s3" : "rds", "encryption"));
  await page.route("**/api/**", async route => {
    const url = new URL(route.request().url());
    let json: unknown = { items: [] };
    if (url.pathname.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (url.pathname.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", created_at: "2026-01-01" }] };
    if (url.pathname.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (url.pathname.endsWith("/findings")) {
      requests.push(url);
      const offset = Number(url.searchParams.get("offset") || 0);
      const limit = Number(url.searchParams.get("limit") || 200);
      const filtered = url.searchParams.get("finding_type") === "encryption";
      json = {
        items: filtered ? encryption.slice(offset, offset + limit) : [], total: filtered ? 51 : 52,
        next_offset: filtered && offset + limit < 51 ? offset + limit : null,
        service_groups: [{ service: "s3", count: 52, status_counts: { FAIL: 52 } }],
        type_groups: [
          { finding_type: "encryption", label: "Encryption", count: 51, status_counts: { FAIL: 51 } },
          { finding_type: "backups", label: "Backups & recovery", count: 1, status_counts: { PASS: 1 } },
        ],
      };
    }
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByLabel("Group findings").selectOption("finding_type");
  await expect(page.getByRole("button", { name: "Encryption 51 findings", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Backups & recovery 1 finding 1 passed", exact: true })).toBeVisible();
  await expect(page.getByText("52 findings across 2 types")).toBeVisible();
  await page.getByRole("button", { name: "Encryption 51 findings", exact: true }).click();
  await expect(page.getByText("1–50 of 51 findings")).toBeVisible();
  await expect(page.getByRole("button", { name: /s3 encryption enabled/ }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: /rds encryption enabled/ }).first()).toBeVisible();
  await page.getByRole("button", { name: "Next page", exact: true }).click();
  await expect(page.getByText("51–51 of 51 findings")).toBeVisible();
  const filteredRequests = requests.filter(url => url.searchParams.get("finding_type") === "encryption");
  expect(filteredRequests.map(url => url.searchParams.get("offset"))).toEqual(["0", "50"]);
  expect(filteredRequests.every(url => url.searchParams.get("group_by") === "finding_type" && url.searchParams.get("aggregation") === "check")).toBe(true);
  await page.getByLabel("Group findings").selectOption("check_id");
  await expect(page.getByRole("button", { name: /Encryption 51 findings/ })).toHaveCount(0);
});
