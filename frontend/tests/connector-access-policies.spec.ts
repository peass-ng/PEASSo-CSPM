import { test, expect } from "@playwright/test";

test("missing recommended AWS policies require acknowledgement and a changed connector resets it", async ({ page }) => {
  await page.clock.install();
  await page.route("**/api/**", route => route.fulfill({ json: { items: [] } }));
  await page.route("**/api/health", route => route.fulfill({ json: { status: "ok", auth_mode: "local" } }));
  await page.route("**/api/me", route => route.fulfill({ json: { runtime_mode: "local" } }));
  let saves = 0;
  let submitted: Record<string, unknown> = {};
  await page.route("**/api/connectors", route => {
    if (route.request().method() === "POST") {
      saves++;
      submitted = route.request().postDataJSON();
      return route.fulfill({ status: 201, json: { id: "saved" } });
    }
    return route.fulfill({ json: { items: [] } });
  });
  await page.route("**/api/connectors/check-access", route => route.fulfill({ json: {
    status: "warning", check_token: "bound-warning-receipt", principals: [],
    scope_summary: { unit: "accounts", total: 1, accessible: 1, blocked: 0, warning: 1, not_checked: 0 },
    issues: ["SecurityAudit", "ReadOnlyAccess"].map(name => ({ severity: "advisory", scope: "555566667777",
      message: `Missing recommended policy arn:aws:iam::aws:policy/${name}. Some checks might fail.` })),
  } }));
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Add connector", exact: true }).click();
  await page.getByLabel("Connector name").fill("Readonly account");
  await page.getByLabel("Authentication", { exact: true }).selectOption("access_keys");
  await page.getByLabel("Access key ID", { exact: true }).fill("fixture");
  await page.getByLabel("Secret access key", { exact: true }).fill("fixture");
  await page.getByRole("button", { name: "Check access", exact: true }).click();
  const result = page.getByRole("status");
  await expect(result).toContainText("1 with recommendations");
  await expect(result).toContainText("arn:aws:iam::aws:policy/SecurityAudit");
  await expect(result).toContainText("arn:aws:iam::aws:policy/ReadOnlyAccess");
  const save = page.getByRole("button", { name: "Save connector", exact: true });
  await expect(save).toBeDisabled();
  const acknowledgement = page.getByRole("checkbox", { name: /I understand that some checks might fail/ });
  await acknowledgement.check();
  await expect(save).toBeEnabled();
  await acknowledgement.uncheck();
  await expect(save).toBeDisabled();
  await acknowledgement.check();
  await page.getByLabel("Connector name").fill("Changed account");
  await expect(acknowledgement).toHaveCount(0);
  await expect(save).toHaveCount(0);
  expect(saves).toBe(0);
  await page.clock.fastForward(10_000);
  await page.getByRole("button", { name: "Check access", exact: true }).click();
  await expect(acknowledgement).not.toBeChecked();
  await acknowledgement.check();
  await page.screenshot({ path: "/tmp/connector-access-policy-warning.png" });
  await save.click();
  await expect.poll(() => saves).toBe(1);
  expect(submitted.acknowledge_access_warnings).toBe(true);
  expect(submitted.check_token).toBe("bound-warning-receipt");
});
