import { expect, test } from "@playwright/test";
import { mkdirSync } from "node:fs";

test("completed scan details render bounded labeled facts and paged coverage", async ({ page }) => {
  const scan = {
    id: "scan-humanized", connector_id: "connector-one", status: "completed",
    created_at: "2026-01-01T00:00:00Z", categories: ["hardening"],
    timeline: Array.from({ length: 55 }, (_, index) => ({ status: "collecting", at: `2026-01-01T00:${String(index).padStart(2, "0")}:00Z` })),
    policy_document: { Version: "2012-10-17", Statement: [{ Effect: "Deny", Action: ["s3:DeleteObject"], Resource: ["arn:aws:s3:::example/*"], Condition: { StringEquals: { "aws:PrincipalOrgID": "o-example" } } }] },
    socket: "[2001:db8::1]:443",
    enabled: true,
    attempts: 3,
    operator_note: "A".repeat(10_010) + "END",
  };
  const shortScan = { id: "scan-short", connector_id: "connector-two", status: "completed", created_at: "2026-01-02T00:00:00Z", categories: ["hardening"],
    timeline: [{ status: "first" }, { status: "second" }, { status: "third" }] };
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/me") ? { tenant_id: "tenant", plan: "free" }
      : path.endsWith("/scans") ? { items: [scan, shortScan] }
      : path.endsWith("/coverage") ? { items: [{ level: "collection", type: "s3_bucket", status: "collected" }], total: 1, next_offset: null }
      : { items: [] };
    await route.fulfill({ json });
  });
  await page.goto("/#Scans");
  await page.locator(".scan-row .scan-id").nth(0).click();
  const inspector = page.locator("dialog.inspector");
  await expect(inspector.getByRole("heading", { name: "Scan details", exact: true })).toBeVisible();
  await expect(inspector.getByText("Connector ID")).toBeVisible();
  await expect(inspector.getByText("connector-one")).toBeVisible();
  await expect(inspector.getByText("Records 1–20 of 55")).toBeVisible();
  await inspector.getByRole("button", { name: "Next" }).first().click();
  await expect(inspector.getByText("Records 21–40 of 55")).toBeVisible();
  await expect(inspector.getByRole("heading", { name: "Coverage & limitations" })).toBeVisible();
  await expect(inspector.locator("pre.evidence")).toHaveCount(0);
  await expect(inspector.getByText('"connector_id"')).toHaveCount(0);
  await expect(inspector.getByText("Policy statements · 1")).toBeVisible();
  await expect(inspector.getByText("s3:DeleteObject")).toBeVisible();
  await expect(inspector.getByText("[2001:db8::1]:443")).toBeVisible();
  const field = (label: string) => inspector.locator('.evidence-field').filter({ has: page.locator('dt').getByText(label, { exact: true }) }).first();
  const font = (el: Element) => ({ family: getComputedStyle(el).fontFamily, size: getComputedStyle(el).fontSize });
  const reference = await field('Enabled').locator('dd').evaluate(font);
  for (const label of ['Socket', 'Enabled', 'Attempts']) {
    expect(await field(label).locator('dt').evaluate(font), label).toEqual(reference);
    expect(await field(label).locator('dd > span').first().evaluate(font), label).toEqual(reference);
  }
  const note = inspector.getByText("Operator note").locator("..");
  await note.getByRole("button", { name: "Next" }).click();
  await note.getByRole("button", { name: "Next" }).click();
  await expect(note.getByText("END", { exact: false })).toBeVisible();
  mkdirSync("evidence", { recursive: true });
  await page.screenshot({ path: "evidence/scan-details-readable-desktop.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: "evidence/scan-details-readable-mobile.png", fullPage: true });
  await page.locator(".scan-row .scan-id").nth(1).evaluate((button) => (button as HTMLButtonElement).click());
  await expect(inspector.getByText("connector-two")).toBeVisible();
  await expect(inspector.getByText("Record 3")).toBeVisible();
  await expect(inspector.getByText("Records 21–40 of 55")).toHaveCount(0);
});

test("deep fields remain readable and a failed scan error never echoes JSON or credentials", async ({ page }) => {
  const nested = { a: { b: { c: { d: { e: { f: { g: { h: { leaf: "deep observed value" } } } } } } } } };
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ json: path.endsWith("/me") ? { tenant_id: "tenant", plan: "free" }
      : path.endsWith("/scans") ? { items: [
        { id: "scan-deep", status: "completed", connector_id: "c", created_at: "2026-01-01", categories: [], nested },
        { id: "scan-failed", status: "failed", connector_id: "c", created_at: "2026-01-01", categories: [], error: 'HTTP 422: {"detail":"A <tag> could not be validated","token":"private"}' },
      ] } : { items: [], total: 0, next_offset: null } });
  });
  await page.goto("/#Scans");
  await expect(page.getByRole("alert").getByText("HTTP 422: A <tag> could not be validated")).toBeVisible();
  await expect(page.getByText('"token"')).toHaveCount(0);
  await page.locator(".scan-row .scan-id").first().click();
  const inspector = page.locator("dialog.inspector");
  for (let index = 0; index < 6; index++) await inspector.getByRole("button", { name: "Show 1 supplied fields" }).last().click();
  await inspector.getByRole("button", { name: "Show deeper supplied fields" }).click();
  await expect(inspector.getByText("deep observed value")).toBeVisible();
});

test("connector credential document is imported without a JSON preview", async ({ page }) => {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ json: path.endsWith("/me") ? { tenant_id: "tenant", plan: "free", runtime_mode: "hosted" }
      : path.endsWith("/health") ? { status: "ok", auth_mode: "cognito" } : { items: [] } });
  });
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Add connector" }).click();
  await page.getByLabel("Cloud provider").selectOption("gcp");
  await page.getByLabel("Authentication").selectOption("service-account");
  const form = page.getByRole("dialog");
  await form.locator('input[type="file"]').first().setInputFiles({
    name: "example.json", mimeType: "application/json",
    buffer: Buffer.from(JSON.stringify({ type: "service_account", client_email: "example@example.invalid", private_key: "synthetic-fixture-only" })),
  });
  await expect(form.getByText("Service account document loaded; contents are hidden.")).toBeVisible();
  await expect(form.getByText("synthetic-fixture-only")).toHaveCount(0);
  await expect(form.locator("textarea").filter({ hasText: "synthetic-fixture-only" })).toHaveCount(0);
});

test("Settings names an active temporary paid grant without displaying plan-source codes", async ({ page }) => {
  let profile = { email: "owner@example.invalid", plan: "paid", plan_source: "administrator_comped_qa", plan_expires_at: 4_102_444_800, weekly_used: 0, weekly_limit: 10 };
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ json: path.endsWith("/me") ? profile : path.endsWith("/health") ? { auth_mode: "cognito" } : { items: [], next_cursor: null } });
  });
  await page.goto("/#Settings");
  await expect(page.getByText(/Temporary paid access \(administrator grant\).*Expires/)).toBeVisible();
  await expect(page.getByText("administrator_comped_qa")).toHaveCount(0);
  profile = { ...profile, plan: "free", weekly_limit: 1 };
  await page.reload();
  await expect(page.getByText(/Temporary paid access/)).toHaveCount(0);
});

test("coverage object errors are readable fields, never object coercion", async ({ page }) => {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/me") ? { tenant_id: "tenant", plan: "free" }
      : path.endsWith("/scans") ? { items: [{ id: "scan-coverage", status: "completed", connector_id: "c", created_at: "2026-01-01", categories: ["hardening"] }] }
      : path.endsWith("/summary") ? { stats: { resource_count: 0, finding_count: 0 }, findings: [], resources: [] }
      : path.endsWith("/coverage") ? { items: [{ service: "s3", status: "denied", error: { code: "AccessDenied", detail: "<img src=x onerror=alert(1)>" } }], total: 1, next_offset: null }
      : { items: [] };
    await route.fulfill({ json });
  });
  await page.goto("/#Dashboard");
  await expect(page.getByText("AccessDenied")).toBeVisible();
  await expect(page.getByText("<img src=x onerror=alert(1)>")).toBeVisible();
  await expect(page.locator("img[src='x']")).toHaveCount(0);
  await expect(page.getByText("[object Object]")).toHaveCount(0);
});
