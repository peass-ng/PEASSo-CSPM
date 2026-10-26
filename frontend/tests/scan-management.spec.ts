import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";

async function setup(page: Page, failDelete = false) {
  const calls: { path: string; body: unknown }[] = [];
  let scans = [{ id: "done", connector_id: "second", connector_name: "Production", categories: [], status: "completed", created_at: "2026-10-19T11:32:00Z" },
    { id: "active", connector_id: "first", connector_name: "Development", categories: [], status: "collecting", created_at: "2026-10-19T12:32:00Z" }];
  await page.route("**/api/**", async route => {
    const path = new URL(route.request().url()).pathname;
    const method = route.request().method();
    if (method === "DELETE") {
      calls.push({ path, body: undefined });
      if (failDelete) return route.fulfill({ status: 503, json: { detail: "Evidence cleanup unavailable; retry" } });
      if (path === "/api/workspace-data") {
        scans = [];
        return route.fulfill({ json: { remaining: false } });
      }
      scans = scans.filter(scan => path !== `/api/scans/${scan.id}`);
      return route.fulfill({ status: 204 });
    }
    if (method === "POST" && path === "/api/scans") {
      calls.push({ path, body: route.request().postDataJSON() });
      return route.fulfill({ status: 201, json: { id: "launched" } });
    }
    const json = path.endsWith("/me") ? { tenant_id: "owner", email: "owner@example.test" }
      : path.endsWith("/health") ? { status: "ok" }
      : path.endsWith("/scans") ? { items: scans }
      : path.endsWith("/connectors") ? { items: [{ id: "first", name: "Development", provider: "aws" }, { id: "second", name: "Production", provider: "aws" }] }
      : { items: [] };
    return route.fulfill({ json });
  });
  return calls;
}

test("delete requires confirmation, refreshes history, and active scans cannot be deleted", async ({ page }) => {
  const calls = await setup(page);
  await page.goto("/#Scans");
  await expect(page.getByRole("button", { name: "Production · 19.10.26", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete scan Development · 19.10.26", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Delete scan Production · 19.10.26", exact: true }).click();
  expect(calls).toHaveLength(0);
  await expect(page.getByRole("dialog")).toContainText("all its stored evidence");
  await page.getByRole("dialog").getByRole("button", { name: "Delete scan", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Production · 19.10.26", exact: true })).toHaveCount(0);
  expect(calls.map(call => call.path)).toEqual(["/api/scans/done"]);
});

test("failed cleanup retains scan and offers an error", async ({ page }) => {
  await setup(page, true);
  await page.goto("/#Scans");
  await page.getByRole("button", { name: "Delete scan Production · 19.10.26", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete scan", exact: true }).click();
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText("cleanup unavailable");
  await expect(page.locator(".scan-row")).toHaveCount(2);
});

test("connector launch opens existing assessment form with that connector selected", async ({ page }) => {
  const calls = await setup(page);
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Launch scan for Production", exact: true }).click();
  await expect(page.getByRole("dialog").getByRole("combobox").first()).toHaveValue("second");
  await page.getByRole("button", { name: "Start scan", exact: true }).click();
  await expect.poll(() => calls.length).toBe(1);
  expect(calls[0].body).toMatchObject({ connector_id: "second" });
});

test("settings clear data requires DELETE and describes its exact scope", async ({ page }) => {
  const calls = await setup(page);
  await page.goto("/#Settings");
  await page.getByRole("button", { name: "Delete workspace data", exact: true }).click();
  const confirm = page.getByRole("button", { name: "Permanently delete workspace data", exact: true });
  await expect(confirm).toBeDisabled();
  await page.getByRole("textbox", { name: "Type DELETE to confirm" }).fill("DELETE");
  await expect(confirm).toBeEnabled();
  expect(calls).toHaveLength(0);
  await confirm.click();
  await expect(page.getByText("Workspace scan data deleted.", { exact: true })).toBeVisible();
  expect(calls.map(call => call.path)).toEqual(["/api/workspace-data"]);
});


test("deleting the selected scan clears selection and does not leave dead report requests", async ({ page }) => {
  await setup(page);
  await page.goto("/#Dashboard");
  const picker = page.getByRole("combobox", { name: "Selected assessment" });
  await picker.selectOption("done");
  await expect(picker).toHaveValue("done");
  await page.getByRole("navigation").getByRole("button", { name: "Scans", exact: true }).click();
  await page.getByRole("button", { name: "Delete scan Production · 19.10.26", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Delete scan", exact: true }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.getByRole("navigation").getByRole("button", { name: "Dashboard", exact: true }).click();
  await expect(picker).toHaveValue("");
});

test("open scan details follow the polled status and offer results once the scan completes", async ({ page }) => {
  let status = "collecting";
  await page.route("**/api/**", async route => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/me") ? { tenant_id: "owner", email: "owner@example.test" }
      : path.endsWith("/health") ? { status: "ok" }
      : path.endsWith("/scans") ? { items: [{ id: "live", connector_id: "first", connector_name: "Development", categories: [], status, created_at: "2026-10-19T12:32:00Z" }] }
      : path.endsWith("/connectors") ? { items: [{ id: "first", name: "Development", provider: "aws" }] }
      : { items: [] };
    return route.fulfill({ json });
  });
  await page.goto("/#Scans");
  await page.getByRole("button", { name: "Development · 19.10.26", exact: true }).click();
  const details = page.getByRole("dialog");
  await expect(details.getByRole("button", { name: "Review findings", exact: true })).toHaveCount(0);
  status = "completed";
  await expect(details.getByRole("button", { name: "Review findings", exact: true })).toBeVisible({ timeout: 15000 });
});

test("a corrected launch form clears the previous validation message before the server answers", async ({ page }) => {
  await page.route("**/api/**", async route => {
    const path = new URL(route.request().url()).pathname;
    if (route.request().method() === "POST" && path === "/api/scans")
      return route.fulfill({ status: 429, json: { detail: "Weekly scan quota exhausted" } });
    const json = path.endsWith("/me") ? { tenant_id: "owner", email: "owner@example.test" }
      : path.endsWith("/health") ? { status: "ok" }
      : path.endsWith("/connectors") ? { items: [{ id: "first", name: "Development", provider: "aws" }] }
      : { items: [] };
    return route.fulfill({ json });
  });
  await page.goto("/#Scans");
  await page.getByRole("button", { name: "Launch scan", exact: true }).click();
  const form = page.getByRole("dialog");
  const checked = form.locator(".assessment-category-grid input[type=checkbox]:checked");
  while (await checked.count()) await checked.first().uncheck();
  await form.getByRole("button", { name: "Start scan", exact: true }).click();
  await expect(form.locator(".form-error")).toContainText("Select at least one assessment category");
  await form.locator(".assessment-category-grid input[type=checkbox]").first().check();
  await form.getByRole("button", { name: "Start scan", exact: true }).click();
  await expect(form.locator(".form-error")).toHaveText("Weekly scan quota exhausted");
});
