import { readFile } from "node:fs/promises";
import { expect, test, type Locator, type Page } from "@playwright/test";

async function expectSameRow(search: Locator, controls: Locator[]) {
  await expect(search).toBeVisible();
  const searchBounds = (await search.boundingBox())!;
  for (const control of controls) {
    await expect(control).toBeVisible();
    const bounds = (await control.boundingBox())!;
    expect(Math.abs((bounds.y + bounds.height / 2) - (searchBounds.y + searchBounds.height / 2))).toBeLessThan(2);
  }
}

async function downloadJson(page: Page, label: string) {
  await page.getByRole("button", { name: label, exact: true }).click();
  const [artifact] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("button", { name: "JSON", exact: true }).click(),
  ]);
  return JSON.parse(await readFile(await artifact.path(), "utf8"));
}

async function baseRoutes(page: Page) {
  await page.route("**/api/**", route => {
    const path = new URL(route.request().url()).pathname;
    return route.fulfill({ json: path === "/api/me" ? { tenant_id: "fixture" }
      : path === "/api/scans" ? { items: [{ id: "scan", status: "completed" }] }
      : path.endsWith("/summary") ? { provider: "aws", stats: {} }
      : { items: [] } });
  });
}

test("findings export includes filtered rows beyond the loaded page", async ({ page }) => {
  await baseRoutes(page);
  const matching = ["first", "second"].map(id => ({
    id, title: `Matching finding ${id}`, check_id: "example", category: "exposure", finding_type: "network",
    provider: "aws", service: "ec2", scope: "123456789012/us-east-1", severity: "medium", status: "FAIL",
    resource_id: id, native_resource_id: `native-${id}`, resource_name: `asset-${id}`, account: "123456789012",
  }));
  await page.route("**/api/scans/scan/findings?*", route => {
    const params = new URL(route.request().url()).searchParams;
    const offset = Number(params.get("offset") || 0);
    const rows = params.get("severity") === "medium" ? matching : [...matching, { ...matching[0], id: "other", severity: "high" }];
    return route.fulfill({ json: { items: rows.slice(offset, offset + 1), total: rows.length,
      next_offset: offset + 1 < rows.length ? offset + 1 : null } });
  });
  await page.goto("/#Exposure");
  await expectSameRow(page.getByRole("textbox", { name: "Search findings" }), [
    page.getByRole("combobox", { name: "Severity" }),
    page.getByRole("combobox", { name: "Status" }),
    page.getByRole("combobox", { name: "Service", exact: true }),
    page.getByRole("button", { name: "Compliance framework", exact: true }),
    page.getByRole("combobox", { name: "Group findings" }),
    page.getByRole("button", { name: "Show security failed", exact: true }),
    page.getByRole("button", { name: "Reset filters", exact: true }),
    page.getByRole("button", { name: "Download findings table", exact: true }),
  ]);
  await page.getByRole("combobox", { name: "Severity" }).selectOption("medium");
  const result = await downloadJson(page, "Download findings table");
  expect(result).toMatchObject({ schema: "hacktricks-cspm.table.exposure-findings.v1", row_count: 2 });
  expect(result.rows).toEqual(matching.map(row => expect.objectContaining({
    id: row.id, title: row.title, severity: row.severity, status: row.status, service: row.service,
    account: row.account, asset: row.resource_name, native_resource_id: row.native_resource_id,
  })));
});

test("image export includes grouped packages and every asset page", async ({ page }) => {
  await baseRoutes(page);
  const assets = ["a", "b", "c"].map(resource_id => ({ resource_id, kind: "ecs_task" }));
  const first = { id: "image-f1", provider: "aws", scope: "account", image_reference: "registry/image:1",
    image_digest: "sha256:abc", severity: "HIGH", vulnerability_id: "CVE-2026-1234", package: "openssl",
    installed_version: "1.0", fixed_versions: ["1.1"], affected_assets: assets.slice(0, 1),
    affected_asset_count: assets.length, assets_truncated: true, coverage: "COMPLETE" };
  const second = { ...first, id: "image-f2", image_digest: "sha256:def", package: "libcrypto",
    affected_assets: [], affected_asset_count: 0, assets_truncated: false };
  let requestedFullAssets = false;
  await page.route("**/api/scans/scan/image-findings**", route => {
    const url = new URL(route.request().url());
    requestedFullAssets ||= url.searchParams.get("include_assets") === "true";
    const offset = Number(url.searchParams.get("offset") || 0);
    return route.fulfill({ json: url.pathname.endsWith("/assets") ?
      { items: assets.slice(offset, offset + 2), total: assets.length, offset, next_offset: offset === 0 ? 2 : null } :
      { rows: [offset === 0 ? first : second], total: 2, offset, next_offset: offset === 0 ? 1 : null,
        coverage: "COMPLETE", complete: true, observations: 2, truncated: false,
        invalid_observations: 0, invalid_vulnerabilities: 0 } });
  });
  await page.goto("/#Images%20CVEs");
  const result = await downloadJson(page, "Download image findings table");
  expect(requestedFullAssets).toBe(true);
  expect(result).toMatchObject({ table: "image-findings-by-cve", row_count: 1 });
  expect(result.rows[0]).toMatchObject({ title: first.vulnerability_id, image_count: 2, cve_count: 1,
    packages: ["openssl", "libcrypto"], affected_asset_count: 3, advisories: [{ affected_assets: assets }, { affected_assets: [] }] });
});

test("a stalled page produces an error instead of an incomplete file", async ({ page }) => {
  await baseRoutes(page);
  await page.route("**/api/scans/scan/findings?*", route => route.fulfill({ json: {
    items: [], total: 1, next_offset: 0,
  } }));
  await page.goto("/#Exposure");
  await page.getByRole("button", { name: "Download findings table", exact: true }).click();
  await page.getByRole("button", { name: "JSON", exact: true }).click();
  await expect(page.getByRole("alert").filter({ hasText: "The table stopped returning more rows." })).toBeVisible();
});

test("report exports follow totals when pages omit the next offset", async ({ page }) => {
  await baseRoutes(page);
  await page.route("**/api/ai/codex", route => route.fulfill({ json: { available: true } }));
  await page.route("**/api/scans/scan/findings-report?*", route => {
    const offset = Number(new URL(route.request().url()).searchParams.get("offset") || 0);
    return route.fulfill({ json: { offset, status: "completed", total: 3, generation: "v1",
      issues: offset < 3 ? [{ id: `issue-${offset}`, title: `Saved issue ${offset}`, status: "confirmed",
        kind: "vulnerability", severity: "medium", references: [{ domain: "findings", id: `source-${offset}` }] }] : [],
    } });
  });
  await page.goto("/#Findings%20Report");
  const data = await downloadJson(page, "Download assessment report issues table");
  expect(data.row_count).toBe(3);
  expect(data.rows).toEqual([0, 1, 2].map(index => expect.objectContaining({
    title: `Saved issue ${index}`, assessment_label: "Confirmed configuration",
    type_label: "Security issue", source_count: 1, references: [{ domain: "findings", id: `source-${index}` }],
  })));
});

test("API key list exports all cursor pages of public metadata", async ({ page }) => {
  await baseRoutes(page);
  await page.route("**/api/health", route => route.fulfill({ json: { auth_mode: "cognito" } }));
  await page.route("**/api/api-keys?*", route => {
    const isSecond = new URL(route.request().url()).searchParams.get("after") === "page-two";
    return route.fulfill({ json: { next_cursor: isSecond ? null : "page-two",
      items: [{ id: isSecond ? "two" : "one", name: isSecond ? "Second key" : "First key",
        prefix: "fixture_", created_at: "2026-01-01", expires_at: null, revoked_at: null,
        last_used_at: null, key: "should-not-be-exported" }],
    } });
  });
  await page.goto("/#Settings");
  const data = await downloadJson(page, "Download API key list");
  expect(data.rows.map((row: { id: string }) => row.id)).toEqual(["one", "two"]);
  expect(data.rows[0]).not.toHaveProperty("key");
});

test("Findings Report downloads one PDF per report, regardless of table filters", async ({ page }) => {
  await baseRoutes(page);
  const issue = { id: "first", title: "Saved issue", status: "confirmed",
    kind: "vulnerability", severity: "medium", references: [] };
  const report = { status: "completed", total: 1, issues: [issue] };
  const combined = { ...report, id: "group", name: "Cloud estate", created: 1785258645, sources: [] };
  const requested: string[] = [];
  await page.route("**/api/ai/codex", route => route.fulfill({ json: { available: true } }));
  await page.route("**/api/scans/scan/findings-report?*", route => route.fulfill({ json: report }));
  await page.route("**/api/combined-reports?*", route => route.fulfill({ json: { items: [combined] } }));
  await page.route("**/api/combined-reports/group?*", route => route.fulfill({ json: combined }));
  await page.route("**/api/**/pdf", route => {
    requested.push(new URL(route.request().url()).pathname);
    expect(new URL(route.request().url()).search).toBe("");
    return route.fulfill({ contentType: "application/pdf", body: "%PDF-1.4\n" });
  });

  const pdfButton = page.getByRole("button", { name: "PDF", exact: true });
  async function download(id: string, label: string) {
    const menu = page.getByRole("button", { name: label, exact: true });
    await expect(menu).toHaveCount(1);
    await expect(page.getByRole("button", { name: "Download PDF", exact: true })).toHaveCount(0);
    await menu.click();
    await expect(page.getByRole("button", { name: "JSON", exact: true })).toBeVisible();
    await expect(pdfButton).toBeVisible();
    const [file] = await Promise.all([page.waitForEvent("download"), pdfButton.click()]);
    expect(file.suggestedFilename()).toBe(`peasso-cspm-${id}.pdf`);
    expect(await readFile(await file.path(), "utf8")).toBe("%PDF-1.4\n");
  }

  await page.goto("/#Findings%20Report");
  await page.getByRole("combobox", { name: "Severity" }).selectOption("high");
  const singleLabel = "Download assessment report issues table";
  await expectSameRow(page.getByRole("textbox", { name: "Search report issues" }), [
    page.getByRole("combobox", { name: "Report issue severity" }),
    page.getByRole("button", { name: singleLabel, exact: true }),
  ]);
  await download("scan", singleLabel);
  await page.getByRole("tab", { name: "Combined reports" }).click();
  await expect(pdfButton).toHaveCount(0);
  await page.getByRole("button", { name: combined.name }).click();
  const combinedLabel = "Download combined report issues table";
  await expectSameRow(page.getByRole("textbox", { name: "Search combined report issues" }), [
    page.getByRole("combobox", { name: "Combined report issue severity" }),
    page.getByRole("button", { name: combinedLabel, exact: true }),
  ]);
  await page.setViewportSize({ width: 390, height: 844 });
  await download("group", combinedLabel);
  expect(requested).toEqual(["/api/scans/scan/findings-report/pdf", "/api/combined-reports/group/pdf"]);
});
