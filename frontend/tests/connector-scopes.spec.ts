import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";

async function connectorForm(page: Page) {
  const submitted: Record<string, any>[] = [];
  await page.route("**/api/**", (route) => route.fulfill({ json: { items: [] } }));
  await page.route("**/api/health", (route) => route.fulfill({ json: { status: "ok", auth_mode: "cognito" } }));
  await page.route("**/api/me", (route) => route.fulfill({ json: {
    runtime_mode: "hosted", connector_auth_methods: { aws: ["access_keys", "assume_role"], gcp: ["platform-service-account", "service-account"], azure: ["client-secret"], k8s: ["inline"] },
  } }));
  await page.route("**/api/connectors/prepare", (route) => route.fulfill({ json: {
    prepared_id: "fixture", external_id: "hacktricks-cspm-ws-fixture", collector_role_arn: "arn:aws:iam::111122223333:role/HackTricks-CSPM",
    service_account_email: "cspm@example-platform-project.iam.gserviceaccount.com",
    project_label_key: "hacktricks-cspm-00000000000000000000", project_label_value: "approved",
  } }));
  await page.route("**/api/connectors/check-access", (route) => {
    submitted.push(route.request().postDataJSON());
    return route.fulfill({ json: { status: "blocked", principals: [], issues: [{ severity: "critical", scope: "210987654321", message: "Cannot assume this target role." }],
      scope_summary: { unit: "accounts", total: 2, accessible: 1, blocked: 1, warning: 0, not_checked: 0 },
      scope_results: [{ scope: "123456789012", status: "pass", principals: ["reader"], issues: [] },
        { scope: "210987654321", status: "blocked", principals: [], issues: [{ severity: "critical", scope: "210987654321", message: "Cannot assume this target role." }] }],
    } });
  });
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Add connector", exact: true }).click();
  await page.getByLabel("Connector name").fill("Scope fixture");
  return submitted;
}

test("AWS defaults and expandable JSON guidance explain fields and scope results", async ({ page }) => {
  const sent = await connectorForm(page);
  await expect(page.getByLabel("AWS account IDs to Audit (comma separated) - All by default")).toBeHidden();
  await page.getByText("Advanced configuration", { exact: true }).click();
  await expect(page.getByLabel("AWS account IDs to Audit (comma separated) - All by default")).toBeVisible();
  await expect(page.getByLabel("Regions (comma separated) - All by default")).toBeVisible();
  const font = (el: Element) => ({ family: getComputedStyle(el).fontFamily, size: getComputedStyle(el).fontSize });
  expect(await page.getByLabel('Additional collector options JSON (no credentials)', { exact: true }).evaluate(font)).toEqual(
    await page.getByLabel('Connector name', { exact: true }).evaluate(font));
  await page.getByLabel("Authentication", { exact: true }).selectOption("access_keys");
  await page.getByLabel("Access key ID", { exact: true }).fill("fixture");
  await page.getByLabel("Secret access key", { exact: true }).fill("fixture");
  await page.getByLabel("Session token (optional)", { exact: true }).fill("opaque-session-token");
  await expect(page.getByLabel(/Temporary credential expiration/)).toHaveCount(0);
  await page.getByText("Supported auth document fields", { exact: true }).click();
  await expect(page.locator(".connector-field-help").first()).toContainText("aws_session_token");
  await page.getByText("Supported collector option fields", { exact: true }).click();
  await expect(page.locator(".connector-field-help").last()).toContainText("max_pages");
  await page.getByRole("button", { name: "Check access", exact: true }).click();
  await expect.poll(() => sent.length).toBe(1);
  await expect(page.getByRole("status")).toContainText("2 accounts in scope");
  await expect(page.getByRole("list", { name: "Access results by scope" })).toContainText("210987654321");
  await expect(page.getByRole("list", { name: "Access results by scope" })).toContainText("Cannot assume this target role.");
});

test("shared GCP requires exact IDs and never offers discovery", async ({ page }) => {
  const sent = await connectorForm(page);
  await page.getByLabel("Cloud provider").selectOption("gcp");
  await page.getByLabel("Authentication", { exact: true }).selectOption("platform-service-account");
  await expect(page.getByRole("checkbox", { name: /Discover all/ })).toHaveCount(0);
  await expect(page.locator(".connector-inspector")).not.toContainText("Da acceso");
  await expect(page.locator(".connector-inspector")).not.toContainText("Introduce los");
  await page.getByText("Advanced configuration", { exact: true }).click();
  await page.getByLabel("Project IDs (comma separated)").fill("customer-project");
  await page.getByRole("button", { name: "Check access", exact: true }).click();
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0].scopes).toEqual(["customer-project"]);
  expect(sent[0].options.all_projects).toBe(false);
  expect(sent[0].auth.method).toBe("platform-service-account");
});

test("GCP discovery is available with customer credentials", async ({ page }) => {
  await connectorForm(page);
  await page.getByLabel("Cloud provider").selectOption("gcp");
  await page.getByLabel("Authentication", { exact: true }).selectOption("service-account");
  await page.getByText("Advanced configuration", { exact: true }).click();
  await expect(page.getByRole("checkbox", { name: "Discover all accessible projects" })).toBeVisible();
  await page.getByRole("checkbox", { name: "Discover all accessible projects" }).check();
  await page.getByLabel("Authentication", { exact: true }).selectOption("platform-service-account");
  await expect(page.getByRole("checkbox", { name: /Discover all/ })).toHaveCount(0);
});

test("Azure all subscriptions selection is explicit and sent to the collector", async ({ page }) => {
  const sent = await connectorForm(page);
  await page.getByLabel("Cloud provider").selectOption("azure");
  await page.getByLabel("Tenant ID", { exact: true }).fill("tenant");
  await page.getByLabel("Client ID", { exact: true }).fill("client");
  await page.getByLabel("Client secret", { exact: true }).fill("secret");
  await page.getByText("Advanced configuration", { exact: true }).click();
  await expect(page.getByLabel("Discover and analyze all accessible subscriptions")).toBeChecked();
  await expect(page.getByLabel("Subscription IDs (comma separated)")).toBeDisabled();
  await page.getByRole("button", { name: "Check access", exact: true }).click();
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0].scopes).toEqual(["*"]);
});

test("Kubernetes all namespaces selection is sent as an all-namespace scan", async ({ page }) => {
  const sent = await connectorForm(page);
  await page.getByLabel("Cloud provider").selectOption("k8s");
  await page.getByLabel("Kubeconfig YAML", { exact: true }).fill("apiVersion: v1\nkind: Config\nclusters: []\nusers: []\ncontexts: []\n");
  await page.getByText("Advanced configuration", { exact: true }).click();
  await expect(page.getByLabel("Discover and analyze all namespaces")).toBeChecked();
  await expect(page.getByLabel("Namespaces (comma separated)")).toBeDisabled();
  await page.getByRole("button", { name: "Check access", exact: true }).click();
  await expect.poll(() => sent.length).toBe(1);
  expect(sent[0].scopes).toEqual(["*"]);
});
