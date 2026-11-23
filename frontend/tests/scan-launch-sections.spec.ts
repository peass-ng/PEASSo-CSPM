import { expect, test } from "@playwright/test";

test("assessment sections control the submitted scan work", async ({ page }) => {
  let submitted: Record<string, any> | undefined;
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === "/api/scans" && route.request().method() === "POST") {
      submitted = route.request().postDataJSON();
      return route.fulfill({ status: 503, json: { detail: "Captured" } });
    }
    const body = path === "/api/health" ? { status: "ok", auth_mode: "local" }
      : path === "/api/me" ? { tenant_id: "fixture" }
      : path === "/api/ai/codex" ? { available: true }
      : path === "/api/connectors" ? { items: [{ id: "aws", name: "AWS", provider: "aws" }] }
      : path === "/api/catalog/frameworks" ? { framework_versions: [] }
      : { items: [] };
    return route.fulfill({ json: body });
  });
  await page.goto("/#Scans");
  await expect(page.getByRole("button", { name: "Launch a scan" })).toHaveCount(0);
  await page.getByRole("button", { name: "Launch scan", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("heading", { name: "Hardening & Compliance" })).toBeVisible();
  await expect(dialog.getByRole("heading", { name: "Other analyses" })).toBeVisible();
  const frameworkSummary = dialog.locator("summary").filter({ hasText: "Frameworks and checklist versions" });
  await expect(frameworkSummary).toBeVisible();
  const arrow = () => frameworkSummary.evaluate(summary => {
    const css = getComputedStyle(summary, "::after");
    return { inset: css.insetInlineEnd, transform: css.transform };
  });
  const closed = await arrow();
  expect(closed.inset).toBe("13px");
  await frameworkSummary.press("Enter");
  await expect(frameworkSummary.locator("..")).toHaveAttribute("open", "");
  const open = await arrow();
  expect(open.inset).toBe(closed.inset);
  expect(open.transform).not.toBe(closed.transform);
  await frameworkSummary.press("Enter");
  await dialog.getByRole("checkbox", { name: "Exposure", exact: true }).uncheck();
  await dialog.getByRole("checkbox", { name: "Least privilege", exact: true }).uncheck();
  await dialog.getByRole("checkbox", { name: "Network Map", exact: true }).uncheck();
  await dialog.getByRole("checkbox", { name: /Top 10 Actions/ }).uncheck();
  await expect(dialog.getByRole("checkbox", { name: /Network Architecture/ })).toBeDisabled();
  await dialog.getByRole("button", { name: "Start scan" }).click();
  await expect.poll(() => submitted !== undefined).toBe(true);
  expect(submitted?.categories).not.toContain("exposure");
  expect(submitted?.categories).not.toContain("least_privilege");
  expect(submitted?.categories).not.toContain("network");
  expect(submitted?.categories).toContain("hardening");
  expect(submitted?.ai_priorities_enabled).toBe(false);
  expect(submitted?.ai_findings_report_enabled).toBe(true);
  expect(submitted?.ai_enabled).toBe(true);
});

test("scan actions use an icon grid at the right edge", async ({ page }) => {
  await page.route("**/api/**", (route) => {
    const path = new URL(route.request().url()).pathname;
    return route.fulfill({ json: path === "/api/scans"
      ? { items: [{ id: "done", connector_id: "aws", status: "completed", categories: ["hardening"], created_at: "2026-10-22T10:00:00Z" }] }
      : path === "/api/connectors" ? { items: [{ id: "aws", name: "AWS", provider: "aws" }] }
      : { items: [] } });
  });
  await page.goto("/#Scans");
  const row = page.locator(".scan-row").first();
  await expect(row.getByRole("button", { name: "Open results" })).toBeVisible();
  await expect(row).not.toContainText("View partial");
  const columns = await row.locator(".scan-actions").evaluate((node) => getComputedStyle(node).gridTemplateColumns.split(" ").length);
  expect(columns).toBe(2);
  await expect(row.locator(".scan-actions .icon-button")).toHaveCount(3);
});
