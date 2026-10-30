import { test, expect } from "@playwright/test";

for (const available of [false, true]) {
  test(`AI launch requires available AI access: ${available}`, async ({ page }) => {
    let submitted: Record<string, unknown> | undefined;
    await page.route("**/api/**", async route => {
      const path = new URL(route.request().url()).pathname;
      if (path === "/api/scans" && route.request().method() === "POST") {
        submitted = route.request().postDataJSON();
        return route.fulfill({ status: 503, json: { detail: "Submission captured" } });
      }
      const response = path === "/api/health" ? { status: "ok", auth_mode: "local" }
        : path === "/api/me" ? { tenant_id: "fixture", plan: "free", weekly_limit: 1, weekly_used: 0 }
        : path === "/api/ai/codex" ? { available, connected: available, platform_configured: false }
        : path === "/api/connectors" ? { items: [{ id: "aws", name: "AWS", provider: "aws" }] }
        : path === "/api/catalog/frameworks" ? { framework_versions: [] }
        : { items: [] };
      return route.fulfill({ json: response });
    });
    await page.goto("/#Scans");
    await page.getByRole("button", { name: "Launch scan", exact: true }).click();
    const toggle = page.getByRole("checkbox", { name: "Use AI for Network analysis and prioritized actions" });
    if (available) {
      await expect(toggle).toBeEnabled();
      await expect(toggle).toBeChecked();
    } else {
      await expect(toggle).toBeDisabled();
      await expect(toggle).not.toBeChecked();
      await expect(page.getByText("Configure an AI provider, model and thinking effort in Settings to enable AI checks.")).toBeVisible();
    }
    await page.getByRole("button", { name: "Start scan", exact: true }).click();
    await expect.poll(() => submitted?.ai_enabled).toBe(available);
  });
}
