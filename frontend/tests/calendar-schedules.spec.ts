import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";

async function setup(page: Page, initial: Record<string, unknown>[] = []) {
  let schedules = initial;
  const writes: Record<string, unknown>[] = [];
  await page.route("**/api/**", route => route.fulfill({ json: { items: [] } }));
  await page.route("**/api/me", route => route.fulfill({ json: { tenant_id: "fixture" } }));
  await page.route("**/api/connectors", route => route.fulfill({ json: { items: [
    { id: "account", name: "Production AWS", provider: "aws", scopes: ["555566667777"] },
  ] } }));
  await page.route("**/api/schedules*", route => {
    if (route.request().method() === "POST") {
      const data = route.request().postDataJSON();
      writes.push(data);
      const saved = { ...data, id: "schedule", next_run_at: "2026-10-20T07:15:00Z" };
      schedules = [...schedules, saved];
      return route.fulfill({ status: 201, json: saved });
    }
    return route.fulfill({ json: { items: schedules } });
  });
  await page.route("**/api/schedules/*", route => {
    const data = route.request().postDataJSON();
    writes.push(data);
    schedules = schedules.map(old => ({ ...old, ...data }));
    return route.fulfill({ json: schedules[0] });
  });
  await page.goto("/#Scans");
  return writes;
}

test("daily, selected weekdays and monthly rules can be combined, saved and edited", async ({ page }) => {
  const writes = await setup(page);
  await page.getByRole("button", { name: "Add schedule", exact: true }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Interval in hours", { exact: true })).toHaveCount(0);
  await page.getByLabel("Schedule time zone", { exact: true }).selectOption("Europe/Madrid");
  await page.getByLabel("Rule 1 time", { exact: true }).fill("09:15");
  await page.getByRole("button", { name: "Add another rule", exact: true }).click();
  await page.getByLabel("Rule 2 frequency", { exact: true }).selectOption("weekly");
  const weekdays = page.getByRole("group", { name: "Rule 2 weekdays", exact: true });
  await weekdays.getByLabel("Wednesday", { exact: true }).check();
  await weekdays.getByLabel("Friday", { exact: true }).check();
  await page.getByLabel("Rule 2 time", { exact: true }).fill("18:45");
  await page.getByRole("button", { name: "Add another rule", exact: true }).click();
  await page.getByLabel("Rule 3 frequency", { exact: true }).selectOption("monthly");
  await page.getByLabel("Rule 3 day of month", { exact: true }).selectOption("31");
  await page.getByLabel("Rule 3 time", { exact: true }).fill("22:00");
  await expect(dialog).toContainText("Shorter months use their last day.");
  await page.screenshot({ path: "/tmp/calendar-schedule-rules.png", fullPage: true });
  await page.getByRole("button", { name: "Save schedule", exact: true }).click();
  await expect(dialog).toHaveCount(0);
  expect(writes[0].timezone).toBe("Europe/Madrid");
  expect(writes[0].rules).toEqual([
    { frequency: "daily", time: "09:15" },
    { frequency: "weekly", time: "18:45", weekdays: [0, 2, 4] },
    { frequency: "monthly", time: "22:00", day_of_month: 31 },
  ]);
  expect(writes[0]).not.toHaveProperty("interval_hours");
  await expect(page.getByText(/Daily at 09:15; Monday, Wednesday, Friday at 18:45; Monthly on day 31 at 22:00/)).toBeVisible();
  await page.getByRole("button", { name: "Production AWS", exact: true }).click();
  await expect(page.getByLabel("Rule 2 time", { exact: true })).toHaveValue("18:45");
  await page.getByRole("button", { name: "Remove rule 1", exact: true }).click();
  await expect(page.getByLabel("Rule 1 frequency", { exact: true })).toHaveValue("weekly");
  await page.getByRole("button", { name: "Save schedule", exact: true }).click();
  await expect.poll(() => writes.length).toBe(2);
  expect((writes[1].rules as unknown[]).length).toBe(2);
});

test("weekly rules require a selected day and switching frequency removes irrelevant fields", async ({ page }) => {
  const writes = await setup(page);
  await page.getByRole("button", { name: "Add schedule", exact: true }).click();
  await page.getByLabel("Rule 1 frequency", { exact: true }).selectOption("weekly");
  await page.getByRole("group", { name: "Rule 1 weekdays", exact: true }).getByLabel("Monday", { exact: true }).uncheck();
  await page.getByRole("button", { name: "Save schedule", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("at least one weekday");
  expect(writes.length).toBe(0);
  await page.getByLabel("Rule 1 frequency", { exact: true }).selectOption("monthly");
  await page.getByLabel("Rule 1 frequency", { exact: true }).selectOption("daily");
  await page.getByRole("button", { name: "Save schedule", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0].rules).toEqual([{ frequency: "daily", time: "09:00" }]);
});

test("legacy intervals remain visible until explicitly converted and check selectors survive editing", async ({ page }) => {
  const writes = await setup(page, [{ id: "legacy", connector_id: "account", interval_hours: 168,
    categories: ["hardening"], checks: ["aws.iam.console_mfa"], enabled: true }]);
  await expect(page.getByText(/Every 168 hours/)).toBeVisible();
  await page.getByRole("button", { name: "Production AWS", exact: true }).click();
  await expect(page.getByRole("dialog")).toContainText("Saving replaces that interval");
  await page.getByRole("button", { name: "Save schedule", exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0].checks).toEqual(["aws.iam.console_mfa"]);
  expect(writes[0].rules).toEqual([{ frequency: "daily", time: "09:00" }]);
});

test("temporary connectors stay available manually but cannot save recurring schedules", async ({ page }) => {
  const writes = await setup(page, [{ id: "paused", connector_id: "account", enabled: false,
    interval_hours: 24, last_error: "This connector uses temporary or unverified credentials." }]);
  await page.route("**/api/connectors", route => route.fulfill({ json: { items: [
    { id: "account", name: "Temporary AWS", provider: "aws", scopes: ["555566667777"],
      scheduling: { allowed: false, reason: "This connector uses temporary or unverified credentials. Run scans manually, or select renewable credentials before creating a schedule." } },
  ] } }));
  await page.reload();
  await expect(page.getByText("This connector uses temporary or unverified credentials.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Add schedule", exact: true }).click();
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText("Run scans manually");
  await expect(page.getByRole("button", { name: "Save schedule", exact: true })).toBeDisabled();
  expect(writes).toHaveLength(0);
});
