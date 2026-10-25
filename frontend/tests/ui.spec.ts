import { test, expect } from "@playwright/test";
import type { Page } from "@playwright/test";
import { authGuides, awsPolicyArns } from "../src/authGuides";
async function emptyApi(page: Page) {
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({
      json: path.endsWith("/connectors/check-access")
        ? { status: "pass", issues: [], principals: [{ scope: "fixture", principal: "fixture identity" }] }
        : path.endsWith("/connectors/prepare")
          ? { prepared_id: "fixture-prepared", external_id: "peaso-fixture-external-id", collector_role_arn: "arn:aws:iam::111122223333:role/HackTricks-CSPM", template_url: "https://cspm.hacktricks.wiki/aws/customer-role.json" }
        : path.endsWith("/health")
        ? { status: "ok" }
        : path.endsWith("/me")
          ? {
              tenant_id: "validation",
              plan: "free",
              weekly_limit: 1,
              weekly_used: 0,
            }
          : path.endsWith("/catalog")
            ? { checks: [], limitations: ["Native checks only"] }
            : { items: [] },
    });
  });
}
async function checkThenSave(page: Page) {
  await page.getByRole("button", { name: "Check access", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Access verified" })).toBeVisible();
  await page.getByRole("button", { name: "Save connector", exact: true }).click();
}
async function demo(page: Page) {
  await emptyApi(page);
  await page.route("**/api/me", (route) => route.fulfill({ status: 401, json: { detail: "Bearer authentication required" } }));
  await page.goto("/");
  await expect(page.getByLabel("Fixture demo", { exact: true })).toBeChecked();
  await expect(
    page.getByRole("status").filter({ hasText: "Fixture demo" }),
  ).toBeVisible();
}
async function nav(page: Page, label: string) {
  await page
    .getByRole("navigation")
    .getByRole("button", { name: label, exact: true })
    .click();
}
test("every authentication option explains access and permission setup", async ({ page }) => {
  await emptyApi(page);
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Add connector", exact: true }).click();
  for (const provider of ["aws", "gcp", "azure", "k8s"] as const) {
    await page.getByLabel("Cloud provider").selectOption(provider);
    const authentication = page.getByLabel("Authentication", { exact: true });
    const methods = await authentication.locator("option").evaluateAll((options) =>
      options.map((option) => (option as HTMLOptionElement).value));
    expect(methods.sort()).toEqual(Object.keys(authGuides[provider]).sort());
    for (const method of methods) {
      await authentication.selectOption(method);
      const guide = page.locator(".auth-setup-guide");
      await guide.locator("summary").first().click();
      await expect(guide).toContainText("Create access");
      await expect(guide).toContainText("Grant permissions");
      await expect(guide.locator("a")).toHaveAttribute("href", authGuides[provider][method].url);
      expect(authGuides[provider][method].commands.length).toBeGreaterThan(0);
      for (const [index, command] of authGuides[provider][method].commands.entries()) {
        const step = guide.locator(".auth-guide-step").nth(index < authGuides[provider][method].accessCommandCount ? 0 : 1);
        await expect(step.getByRole("button", { name: `Copy ${command.label}` })).toBeVisible();
        await expect(step.locator("pre").filter({ hasText: command.value })).toBeVisible();
      }
    }
  }
  await page.getByLabel("Cloud provider").selectOption("gcp");
  await page.getByLabel("Authentication", { exact: true }).selectOption("adc");
  const gcpGuide = page.locator(".auth-setup-guide");
  await gcpGuide.locator("summary").first().click();
  await expect(gcpGuide).toContainText("roles/logging.privateLogViewer");
  await expect(gcpGuide).not.toContainText("roles/logging.viewer");
  await page.getByLabel("Cloud provider").selectOption("aws");
  await page.getByLabel("Authentication", { exact: true }).selectOption("access_keys");
  const accessKeyGuide = page.locator(".auth-setup-guide");
  await accessKeyGuide.locator("summary").first().click();
  await expect(accessKeyGuide.locator(".auth-guide-step").first()).toContainText("aws iam create-access-key");
  await expect(accessKeyGuide.locator(".auth-guide-step").last()).toContainText("aws iam attach-user-policy");
  await expect(accessKeyGuide).not.toContainText("Copy and run");
  await page.getByLabel("Authentication", { exact: true }).selectOption("assume_role");
  const awsGuide = page.locator(".auth-setup-guide");
  await awsGuide.locator("summary").first().click();
  for (const arn of awsPolicyArns) await expect(awsGuide).toContainText(arn);
  await expect(awsGuide.locator(".auth-guide-step").nth(1).locator("pre").first()).toContainText("aws iam attach-role-policy");
  await expect(awsGuide.getByText("Optional: set up Access Analyzer findings")).toHaveCount(0);
  await expect(awsGuide).toContainText("arn:aws:iam::aws:policy/IAMAccessAnalyzerFullAccess");
  await expect(awsGuide).not.toContainText("arn:aws:iam::aws:policy/IAMAccessAnalyzerReadOnlyAccess");
});
test("connector methods start with common choices and explain environment credentials", async ({ page }) => {
  await emptyApi(page);
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Add connector", exact: true }).click();
  const authentication = page.getByLabel("Authentication", { exact: true });
  await expect(authentication.locator("option").first()).toHaveValue("default");
  await authentication.selectOption("instance");
  await expect(page.locator(".connector-inspector > .form > .notice")).toContainText("Run PEASS'o CSPM on the EC2 instance");
  await page.getByLabel("Cloud provider").selectOption("gcp");
  await expect(authentication.locator("option").first()).toHaveValue("adc");
  await authentication.selectOption("metadata");
  await expect(page.locator(".connector-inspector > .form > .notice")).toContainText("Run PEASS'o CSPM on the Google Cloud VM");
  const sizes = await page.evaluate(() => ({
    label: parseFloat(getComputedStyle(document.querySelector(".connector-inspector .form > label")!).fontSize),
    input: parseFloat(getComputedStyle(document.querySelector(".connector-inspector .form input")!).fontSize),
    provider: parseFloat(getComputedStyle(document.querySelector(".connector-inspector .provider-picker-option")!).fontSize),
  }));
  expect(sizes.label).toBeGreaterThanOrEqual(14);
  expect(sizes.input).toBeGreaterThanOrEqual(14);
  expect(sizes.provider).toBeGreaterThanOrEqual(13);
});
test("hosted connectors show the usual access method first", async ({ page }) => {
  await emptyApi(page);
  await page.route("**/api/me", (route) => route.fulfill({ json: { runtime_mode: "hosted" } }));
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Add connector", exact: true }).click();
  const authentication = page.getByLabel("Authentication", { exact: true });
  await expect(authentication).toHaveValue("assume_role");
  await page.getByLabel("Cloud provider").selectOption("gcp");
  await expect(authentication).toHaveValue("platform-service-account");
  await page.getByLabel("Cloud provider").selectOption("azure");
  await expect(authentication).toHaveValue("client-secret");
  await page.getByLabel("Cloud provider").selectOption("k8s");
  await expect(authentication).toHaveValue("kubeconfig-inline");
});
test("scan framework picker adds multiple relevant selections and clears on connector change", async ({ page }) => {
  await emptyApi(page);
  await page.route("**/api/connectors", (route) => route.fulfill({ json: { items: [
    { id: "aws-1", name: "AWS customer", provider: "aws" },
    { id: "gcp-1", name: "GCP customer", provider: "gcp" },
  ] } }));
  await page.route("**/api/catalog/frameworks", (route) => route.fulfill({ json: {
    framework_versions: [
      { id: "cis_aws", name: "CIS AWS v1", family: "CIS", provider: "aws", status: "partially_supported", supported_native_checks: 8 },
      { id: "cis_gcp", name: "CIS GCP v2", family: "CIS", provider: "gcp", status: "partially_supported", supported_native_checks: 6 },
    ],
  } }));
  let payload: Record<string, unknown> | undefined;
  await page.route("**/api/scans", (route) => {
    if (route.request().method() === "POST") {
      payload = route.request().postDataJSON() as Record<string, unknown>;
      return route.fulfill({ status: 503, json: { detail: "Test submission captured" } });
    }
    return route.fulfill({ json: { items: [] } });
  });
  await page.goto("/#Scans");
  await page.getByRole("button", { name: "Launch scan", exact: true }).click();
  const picker = page.getByText("Frameworks and checklist versions (optional)");
  await picker.click();
  const add = page.getByText("Add another framework");
  await add.click();
  const search = page.getByRole("searchbox", { name: "Search frameworks and checklist versions" });
  await search.fill("CIS AWS");
  await expect(page.getByRole("button", { name: /CIS AWS v1/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /CIS GCP v2/ })).toHaveCount(0);
  await search.fill("");
  await page.getByRole("button", { name: "CIS · all versions" }).click();
  await expect(page.getByLabel("Framework 1", { exact: true })).toContainText("CIS");
  await add.click();
  await page.getByRole("button", { name: /CIS AWS v1/ }).click();
  await expect(page.getByLabel("Framework 2", { exact: true })).toContainText("CIS AWS v1");
  await page.getByRole("button", { name: "Start scan", exact: true }).click();
  await expect(page.getByRole("alert")).toContainText("Test submission captured");
  expect(payload?.frameworks).toEqual(["CIS", "cis_aws"]);
  await page.getByLabel("Connector", { exact: true }).selectOption("gcp-1");
  await expect(page.getByLabel("Framework 1", { exact: true })).toHaveCount(0);
  await add.click();
  await expect(page.getByRole("button", { name: /CIS GCP v2/ })).toBeVisible();
  await expect(page.getByRole("button", { name: /CIS AWS v1/ })).toHaveCount(0);
});
test("authenticated workspace starts empty without demo controls", async ({
  page,
}) => {
  await emptyApi(page);
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "No scans recorded" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Coverage is not available yet" }),
  ).toBeVisible();
  await expect(page.getByLabel("Fixture demo", { exact: true })).toHaveCount(0);
  await expect(page.locator(".api-status")).toHaveCount(0);
  await expect(page.locator('link[rel="icon"]')).toHaveAttribute("href", "/icons/peaso-badge.svg");
  await expect(page.locator(".hero")).not.toContainText("Native evidence");
  await expect(page.locator(".hero")).not.toContainText("Four cloud providers");
  await page.screenshot({
    path: "evidence/live-empty-desktop.png",
    fullPage: true,
  });
  await nav(page, "Connectors");
  await expect(
    page.getByRole("button", { name: "Add connector", exact: true }),
  ).toBeEnabled();
});
test("anonymous visitors start in fixture demo with prominent account actions", async ({ page }) => {
  await emptyApi(page);
  let signedIn = false;
  let identityChecks = 0;
  await page.route("**/api/me", (route) => {
    identityChecks += 1;
    return signedIn
    ? route.fulfill({ json: { tenant_id: "signed-in", email: "user@example.test" } })
    : route.fulfill({ status: 401, json: { detail: "Bearer authentication required" } });
  });
  await page.goto("/");
  await expect(page.getByLabel("Fixture demo", { exact: true })).toBeChecked();
  await expect(page.getByRole("link", { name: "Log in", exact: true })).toHaveAttribute("href", `https://tools.hacktricks.wiki/login.html?next=${encodeURIComponent(page.url())}`);
  await expect(page.getByRole("link", { name: "Register", exact: true })).toHaveAttribute("href", `https://tools.hacktricks.wiki/register.html?next=${encodeURIComponent(page.url())}`);
  await expect(page.getByRole("status").filter({ hasText: "Fixture demo" })).toBeVisible();
  const checksBeforeSwitch = identityChecks;
  await page.getByLabel("Fixture demo", { exact: true }).uncheck();
  await expect(page.getByLabel("Fixture demo", { exact: true })).not.toBeChecked();
  await expect(page.getByRole("link", { name: "Log in", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Register", exact: true })).toBeVisible();
  expect(identityChecks).toBe(checksBeforeSwitch);
  signedIn = true;
  await page.evaluate(() => window.dispatchEvent(new Event("hacktricks-cspm-auth-session-changed")));
  await expect(page.getByLabel("Fixture demo", { exact: true })).toHaveCount(0);
  await expect(page.locator(".api-status")).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Register", exact: true })).toHaveCount(0);
});
test("account initial and Help route show actionable documentation", async ({ page }) => {
  await emptyApi(page);
  await page.route("**/api/me", (route) => route.fulfill({ json: {
    tenant_id: "signed-in", email: "maria@example.test", plan: "free",
  } }));
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Account settings for maria@example.test" })).toHaveText("M");
  await expect(page.getByText("Live API", { exact: true })).toHaveCount(0);
  await expect(page.getByText("Built by HackTricks", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Help & documentation" }).click();
  await expect(page).toHaveURL(/#Help$/);
  await expect(page.getByRole("heading", { name: "Get started" })).toBeVisible();
  await page.getByRole("navigation", { name: "Documentation chapters" }).getByRole("button", { name: "Connectors", exact: true }).click();
  await expect(page.getByRole("button", { name: "Open AWS setup guide" })).toBeVisible();
  await page.getByLabel("Authentication setup method").selectOption("assume_role");
  await expect(page.getByRole("link", { name: /AWS cross-account roles/ })).toHaveAttribute("href", /docs\.aws\.amazon\.com/);
});
test("failed scan shows its curated role refusal in history and details", async ({ page }) => {
  await emptyApi(page);
  const role = "arn:aws:iam::222222222222:role/CustomerAudit";
  const reason = `Role ${role} was refused: trust policy does not require External ID; add the sts:ExternalId condition shown in onboarding.`;
  await page.route("**/api/scans", (route) => route.fulfill({ json: { items: [{
    id: "refused-scan", connector_id: "aws-connector", status: "failed",
    created_at: "2026-10-11T00:00:00Z", categories: [], error: reason,
    error_code: "credential_access_denied",
    failure_reasons: [{ code: "external_id_not_required_by_trust", role_arn: role, message: reason }],
  }] } }));
  await page.goto("/");
  await nav(page, "Scans");
  await expect(page.getByRole("alert").filter({ hasText: reason })).toBeVisible();
  await page.getByRole("article").filter({ hasText: reason }).locator("button.scan-id").click();
  await expect(page.getByRole("dialog").getByRole("alert").filter({ hasText: reason })).toBeVisible();
  await expect(page.getByRole("dialog")).toContainText("credential_access_denied");
  await page.getByRole("dialog").getByRole("button", { name: "Show 3 supplied fields" }).click();
  await expect(page.getByRole("dialog")).toContainText("external_id_not_required_by_trust");
});
test("filter and inspect escaped evidence with compliance", async ({
  page,
}) => {
  await demo(page);
  await nav(page, "Hardening & Compliance");
  await page.getByLabel("Group findings").selectOption("check_id");
  await expect(
    page.getByRole("button", { name: "Storage encryption requires review" }),
  ).toBeVisible();
  await page.getByLabel("Severity", { exact: true }).selectOption("high");
  await expect(
    page.getByRole("button", { name: "Storage audit configuration present" }),
  ).toHaveCount(0);
  await page.getByLabel("Compliance framework", { exact: true }).click();
  await page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option", { name: "HackTricks Cloud Best Practices", exact: true }).click();
  await page.getByLabel("Search findings").fill("demo-artifacts");
  await page
    .getByRole("button", { name: "Storage encryption requires review" })
    .click();
  await expect(page.getByRole("dialog")).toContainText(
    "Missing in fixture snapshot",
  );
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.getByLabel("Search findings").fill("no-such-asset");
  await expect(
    page.getByRole("heading", { name: "No findings match these filters" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Reset filters" }).click();
  await page.screenshot({
    path: "evidence/findings-desktop.png",
    fullPage: true,
  });
});
test("network map grouping, routed edges, table search and relationship inspector", async ({
  page,
}) => {
  await demo(page);
  await nav(page, "Network Map");
  await expect(page.locator('.react-flow__node[data-id^="network:"]').first()).toBeVisible();
  await page.locator('.react-flow__node[data-id^="network:"] .network-node-heading').first().click();
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  await expect(page.locator(".react-flow__edge-path").first()).toHaveAttribute(
    "d",
    /^M /,
  );
  await page.screenshot({
    path: "evidence/network-map-desktop.png",
    fullPage: true,
  });
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await page.getByLabel("Search loaded network resources").fill("Web workload");
  await page.locator(".network-table-main", { hasText: "Web workload" }).click();
  await expect(page.getByRole("dialog")).toContainText("n3");
  await page.getByRole("button", { name: "Close inspector" }).click();
});
test("connector validation native payload and discarded credentials", async ({
  page,
}) => {
  await emptyApi(page);
  let payload: Record<string, any> = {};
  await page.route("**/api/connectors", async (route) => {
    if (route.request().method() === "POST") {
      payload = route.request().postDataJSON();
      await route.fulfill({
        status: 503,
        json: { detail: "Collector unavailable" },
      });
    } else await route.fulfill({ json: { items: [] } });
  });
  await page.goto("/#Connectors");
  await page
    .getByRole("button", { name: "Add connector", exact: true })
    .click();
  await page
    .getByLabel("Connector name", { exact: true })
    .fill("Validation AWS");
  await page
    .getByLabel("Authentication", { exact: true })
    .selectOption("access_keys");
  await page
    .getByLabel("Access key ID", { exact: true })
    .fill("synthetic-access-id");
  await page
    .getByLabel("Secret access key", { exact: true })
    .fill("synthetic-validation-secret");
  await checkThenSave(page);
  await expect(page.getByRole("alert")).toContainText("Collector unavailable");
  expect(payload.auth.method).toBe("access_keys");
  expect(payload.auth.aws_secret_access_key).toBe(
    "synthetic-validation-secret",
  );
  await expect(
    page.getByLabel("Secret access key", { exact: true }),
  ).toHaveValue("");
  expect(
    await page.evaluate(() =>
      JSON.stringify({ ...localStorage, ...sessionStorage }),
    ),
  ).not.toContain("synthetic-validation-secret");
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page
    .getByRole("button", { name: "Add connector", exact: true })
    .click();
  await page.getByLabel("Cloud provider").selectOption("gcp");
  await page
    .getByLabel("Connector name", { exact: true })
    .fill("Validation GCP");
  await page.getByRole("button", { name: "Check access" }).click();
  await expect(page.getByRole("alert")).toContainText("Enter project IDs");
});
test("anonymous fixture demo still offers local session authentication", async ({ page }) => {
  await page.route("**/api/**", (route) =>
    new URL(route.request().url()).pathname.endsWith("/health")
      ? route.fulfill({ json: { status: "ok", auth_mode: "local" } })
      : route.fulfill({
          status: 401,
          json: { detail: "Bearer authentication required" },
        }),
  );
  await page.goto("/");
  await expect(page.getByLabel("Fixture demo", { exact: true })).toBeChecked();
  await nav(page, "Settings");
  await page
    .getByLabel("API bearer token", { exact: true })
    .fill("synthetic-local-validation-token");
  await page.getByRole("button", { name: "Use token" }).click();
  // The fixture still returns 401 after token use, so the local dialog reopens.
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(
    page.getByRole("dialog").getByLabel("API bearer token", { exact: true }),
  ).toHaveValue("");
  expect(
    await page.evaluate(() => sessionStorage.getItem("hacktricks-cspm.api-token")),
  ).toBe("synthetic-local-validation-token");
  await page.getByRole("dialog").getByRole("button", { name: "Clear token" }).click();
  expect(
    await page.evaluate(() => sessionStorage.getItem("hacktricks-cspm.api-token")),
  ).toBeNull();
  await page.screenshot({
    path: "evidence/auth-error-desktop.png",
    fullPage: true,
  });
});
test("mobile layout and dialog keyboard accessibility", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await demo(page);
  await page.screenshot({
    path: "evidence/dashboard-mobile.png",
    fullPage: true,
  });
  expect(
    await page.evaluate(() => document.documentElement.scrollWidth),
  ).toBeLessThanOrEqual(390);
  await nav(page, "Hardening & Compliance");
  await page.getByLabel("Group findings").selectOption("check_id");
  await page
    .getByRole("button", { name: "Storage encryption requires review" })
    .click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await page.screenshot({
    path: "evidence/findings-mobile.png",
    fullPage: true,
  });
});
test("HTML in API names is rendered as text", async ({ page }) => {
  await emptyApi(page);
  await page.route("**/api/connectors", (route) =>
    route.fulfill({
      json: {
        items: [
          {
            id: "x",
            name: "<img src=x onerror=alert(1)>",
            provider: "aws",
            scopes: [],
            auth: { configured: true, fields: ["method"] },
          },
        ],
      },
    }),
  );
  await page.goto("/#Connectors");
  await expect(
    page.getByRole("heading", { name: "<img src=x onerror=alert(1)>" }),
  ).toBeVisible();
  await expect(page.locator(".connectors-table img")).toHaveCount(1);
  await expect(page.locator(".connectors-table img")).toHaveAttribute("src", "/icons/aws.svg");
});
test("large map bounded and complete table searchable", async ({ page }) => {
  await emptyApi(page);
  const scan = {
    id: "large",
    connector_id: "c",
    status: "completed",
    created_at: "2026-01-01",
    categories: ["network"],
  };
  await page.route("**/api/scans", (route) =>
    route.fulfill({ json: { items: [scan] } }),
  );
  await page.route("**/api/scans/large/summary", (route) =>
    route.fulfill({
      json: { resources: [], findings: [], coverage: [], graphs: {} },
    }),
  );
  await page.route("**/api/scans/large/graphs/network*", (route) =>
    route.fulfill({
      json: {
        nodes: Array.from({ length: 250 }, (_, i) => ({
          id: `n${i}`,
          label: `Asset ${i}`,
          scope: "Validation",
          provider: "aws",
          type: "instance",
        })),
        edges: [],
      },
    }),
  );
  await page.goto("/#Network%20Map");
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  expect(await page.locator(".react-flow__node").count()).toBeLessThanOrEqual(300);
  await expect(page.getByText(/resources folded or off page/)).toBeVisible();
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await page.getByLabel("Search loaded network resources").fill("Asset 249");
  await expect(page.locator(".network-table-main", { hasText:"Asset 249" })).toBeVisible();
});
test("hosted auth respects server runtime capabilities", async ({ page }) => {
  await emptyApi(page);
  await page.route("**/api/health", (r) =>
    r.fulfill({ json: { status: "ok", auth_mode: "cognito" } }),
  );
  await page.route("**/api/me", (r) =>
    r.fulfill({
      json: {
        runtime_mode: "hosted",
        connector_auth_methods: {
          aws: ["access_keys", "assume_role"],
          gcp: ["token", "service-account"],
          azure: ["token", "client-secret", "client-cert"],
          k8s: ["inline", "token", "client-cert"],
        },
      },
    }),
  );
  await page.goto("/#Connectors");
  await page
    .getByRole("button", { name: "Add connector", exact: true })
    .click();
  await expect(page.getByLabel("Authentication", { exact: true })).toHaveValue(
    "assume_role",
  );
  await expect(
    page
      .getByLabel("Authentication", { exact: true })
      .locator('option[value="profile"]'),
  ).toHaveCount(0);
  await page
    .getByLabel("Authentication", { exact: true })
    .selectOption("assume_role");
  await page.locator(".auth-setup-guide > summary").click();
  await expect(
    page.locator(".auth-setup-guide").getByText(/External ID/),
  ).toBeVisible();
  await expect(page.getByLabel("External ID", { exact: true })).toHaveCount(0);
  await page.getByLabel("Cloud provider").selectOption("k8s");
  await expect(
    page.getByLabel("Kubeconfig YAML", { exact: true }),
  ).toBeVisible();
  await expect(
    page
      .getByLabel("Authentication", { exact: true })
      .locator('option[value="in_cluster"]'),
  ).toHaveCount(0);
  await page.getByLabel("Cloud provider").selectOption("gcp");
  await expect(
    page
      .getByLabel("Authentication", { exact: true })
      .locator('option[value="adc"]'),
  ).toHaveCount(0);
});
test("AWS key form validates, deduplicates, and sends independent role targets", async ({ page }) => {
  await emptyApi(page);
  let payload: Record<string, any> | undefined;
  await page.route("**/api/connectors", async (route) => {
    if (route.request().method() === "POST") {
      payload = route.request().postDataJSON();
      await route.fulfill({ status: 503, json: { detail: "fixture endpoint" } });
    } else await route.fulfill({ json: { items: [] } });
  });
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Add connector", exact: true }).click();
  await page.getByLabel("Connector name").fill("Key fanout");
  await page.getByLabel("Authentication").selectOption("access_keys");
  await page.getByLabel("Access key ID").fill("synthetic-key");
  await page.getByLabel("Secret access key").fill("synthetic-secret");
  const roles = page.getByLabel(/Optional target roles/);
  await roles.fill("arn:aws:iam::123456789012:role/ReadOnly | external-1\narn:aws:iam::123456789012:role/ReadOnly | external-1\ninvalid");
  await page.getByRole("button", { name: "Check access" }).click();
  await expect(page.getByRole("alert")).toContainText("one valid AWS role ARN");
  expect(payload).toBeUndefined();
  await roles.fill("arn:aws:iam::123456789012:role/ReadOnly | external-1\narn:aws:iam::123456789012:role/ReadOnly | external-1");
  await page.getByText("Advanced configuration", { exact: true }).click();
  await page.getByLabel("Include source account in scan").uncheck();
  await checkThenSave(page);
  await expect(page.getByRole("alert")).toContainText("fixture endpoint");
  expect(payload?.auth.assume_roles).toEqual([{ role_arn: "arn:aws:iam::123456789012:role/ReadOnly", external_id: "external-1" }]);
  expect(payload?.auth.role_chain).toBeUndefined();
  expect(payload?.options.include_source_account).toBe(false);
});
test("hosted role form and onboarding show trust, copy, and CloudFormation", async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"]);
  await emptyApi(page);
  await page.route("**/api/health", (route) => route.fulfill({ json: { status: "ok", auth_mode: "cognito" } }));
  await page.route("**/api/me", (route) => route.fulfill({ json: { runtime_mode: "hosted", connector_auth_methods: { aws: ["access_keys", "assume_role"] } } }));
  const role = "arn:aws:iam::123456789012:role/ReadOnly";
  let payload: Record<string, any> | undefined;
  let created = false;
  let publicReady = true;
  await page.route("**/api/connectors", async (route) => {
    if (route.request().method() === "POST") {
      payload = route.request().postDataJSON();
      created = true;
      await route.fulfill({ status: 201, json: { id: "c1" } });
    } else await route.fulfill({ json: { items: created ? [{ id: "c1", name: "Hosted role", provider: "aws", scopes: [], auth_mode: "assume_role", onboarding: { external_id: "peaso-fixture-external-id", collector_role_arn: "arn:aws:iam::111122223333:role/HackTricks-CSPM", target_role_arns: [role], template_url: "https://cspm.hacktricks.wiki/aws/customer-role.json", quick_create_template_url: publicReady ? "https://hacktricks-cspm-templates-111122223333.s3.us-east-1.amazonaws.com/customer-role.json" : null } }] : [] } });
  });
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Add connector", exact: true }).click();
  await page.getByLabel("Connector name").fill("Hosted role");
  await page.getByLabel("Authentication").selectOption("assume_role");
  await expect(page.getByLabel("Authentication").locator('option[value="assume_role"]')).toHaveText("HackTricks CSPM IAM role");
  await page.locator(".auth-setup-guide > summary").click();
  await expect(page.locator(".auth-setup-guide")).toContainText("aws cloudformation create-stack");
  await expect(page.locator(".auth-setup-guide")).toContainText("customer-role.json");
  await expect(page.locator(".auth-setup-guide")).toContainText("peaso-fixture-external-id");
  await expect(page.locator(".auth-setup-guide").getByText("arn:aws:iam::aws:policy/ReadOnlyAccess")).toHaveCount(0);
  await page.locator(".auth-setup-guide > summary").click();
  await page.getByLabel(/Target role ARNs/).fill(role);
  await checkThenSave(page);
  await expect(page.getByRole("button", { name: "Onboarding" })).toBeVisible();
  expect(payload?.auth.assume_roles).toEqual([{ role_arn: role }]);
  expect(payload?.auth.external_id).toBeUndefined();
  await page.getByRole("button", { name: "Onboarding" }).click();
  await page.getByRole("button", { name: "Copy ExternalID" }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe("peaso-fixture-external-id");
  await expect(page.getByText("Required condition")).toBeVisible();
  await expect(page.getByText("External ID must equal the value shown above.")).toBeVisible();
  await page.getByRole("button", { name: "Copy or download trust policy" }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toContain('"sts:ExternalId"');
  const trust = JSON.parse(await page.evaluate(() => navigator.clipboard.readText()));
  expect(trust.Statement).toEqual([{
    Effect: "Allow", Principal: { AWS: "arn:aws:iam::111122223333:role/HackTricks-CSPM" },
    Action: "sts:AssumeRole",
    Condition: { StringEquals: { "sts:ExternalId": "peaso-fixture-external-id" } },
  }]);
  await expect(page.getByRole("link", { name: "Create role with CloudFormation" })).toHaveAttribute("href", /#\/stacks\/create\/review\?templateURL=https%3A%2F%2Fhacktricks-cspm-templates-111122223333\.s3\.us-east-1\.amazonaws\.com%2Fcustomer-role\.json.*param_ExternalId=peaso-fixture-external-id/);
  await expect(page.getByRole("link", { name: "Download CloudFormation template" })).toHaveAttribute("href", "https://cspm.hacktricks.wiki/aws/customer-role.json");
  await expect(page.getByRole("button", { name: "Copy AWS CLI fallback" })).toBeVisible();
  publicReady = false;
  await page.reload();
  await page.getByRole("button", { name: "Onboarding" }).click();
  await expect(page.getByRole("link", { name: "Create role with CloudFormation" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Download CloudFormation template" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy AWS CLI fallback" })).toBeVisible();
});
test("access check blocks critical gaps, permits advisories, and rechecks after ten seconds", async ({ page }) => {
  await page.clock.install();
  await emptyApi(page);
  let checks = 0;
  let saved = false;
  await page.route("**/api/connectors/check-access", (route) => {
    checks += 1;
    return route.fulfill({ json: checks === 1
      ? { status: "blocked", principals: [], issues: [{ severity: "critical", scope: "account", message: "iam:ListRoles denied" }] }
      : { status: "warning", principals: [{ scope: "account", principal: "arn:aws:iam::123456789012:user/scan" }], issues: [{ severity: "advisory", scope: "account", message: "Access Analyzer unavailable" }] } });
  });
  await page.route("**/api/connectors", (route) => {
    if (route.request().method() === "POST") {
      saved = true;
      return route.fulfill({ status: 201, json: { id: "saved" } });
    }
    return route.fulfill({ json: { items: [] } });
  });
  await page.goto("/#Connectors");
  await page.getByRole("button", { name: "Add connector", exact: true }).click();
  await page.getByLabel("Connector name").fill("Checked");
  await page.getByLabel("Authentication").selectOption("access_keys");
  await page.getByLabel("Access key ID").fill("key");
  await page.getByLabel("Secret access key").fill("secret");
  await page.getByRole("button", { name: "Check access", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Access check blocked saving" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save connector" })).toHaveCount(0);
  await page.clock.fastForward(10_000);
  await page.getByRole("button", { name: "Check access", exact: true }).click();
  await expect(page.getByRole("status").filter({ hasText: "Access works with recommendations" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save connector" })).toBeDisabled();
  await page.getByRole("checkbox", { name: /I understand that some checks might fail/ }).check();
  await page.getByRole("button", { name: "Save connector" }).click();
  expect(saved).toBe(true);
});
test("collapsed relationships retain every supplied evidence record", async ({
  page,
}) => {
  await emptyApi(page);
  await page.route("**/api/scans", (r) =>
    r.fulfill({
      json: {
        items: [
          {
            id: "lossless",
            status: "completed",
            categories: ["network"],
            created_at: "2026-01-01",
          },
        ],
      },
    }),
  );
  await page.route("**/api/scans/lossless/summary", (r) =>
    r.fulfill({ json: { resources: [], findings: [], coverage: [] } }),
  );
  await page.route("**/api/scans/lossless/graphs/network*", (r) =>
    r.fulfill({
      json: {
        nodes: [
          {
            id: "v",
            label: "VPC native",
            type: "vpc",
            scope: "account",
            provider: "aws",
          },
          {
            id: "s",
            label: "Subnet native",
            type: "subnet",
            scope: "account",
            provider: "aws",
            parent_id: "v",
          },
          {
            id: "a",
            label: "Workload native",
            type: "instance",
            scope: "account",
            provider: "aws",
            parent_id: "s",
          },
        ],
        edges: [
          {
            id: "e1",
            source: "s",
            target: "v",
            type: "associated_with",
            evidence: { record: "first" },
          },
          {
            id: "e2",
            source: "a",
            target: "s",
            type: "associated_with",
            evidence: { record: "second" },
          },
        ],
      },
    }),
  );
  await page.goto("/#Network%20Map");
  await expect(page.getByText(/relationships internal, off page or omitted/)).toBeVisible();
  await page.locator('.react-flow__node[data-id="network:v"] .network-node-heading').click();
  await expect(page.locator('.react-flow__node[data-id="area:s"]')).toBeVisible();
  await page.locator('.react-flow__node[data-id="area:s"] .network-node-heading').click();
  await expect(page.locator('.react-flow__node[data-id="asset:a"]')).toBeVisible();
  await page.screenshot({
    path: "evidence/network-hierarchy.png",
    fullPage: true,
  });
});
test("pagination filters complete dataset and loads evidence lazily", async ({
  page,
}) => {
  await emptyApi(page);
  const finding = (id: string) => ({
    id,
    category: "hardening",
    check_id: "native.check",
    title: id,
    provider: "azure",
    service: "storage",
    resource_id: "asset",
    scope: "subscription",
    severity: "high",
    status: "FAIL",
    frameworks: ["HackTricks Cloud Best Practices"],
    detail_available: true,
  });
  await page.route("**/api/scans", (r) =>
    r.fulfill({
      json: {
        items: [
          {
            id: "paged",
            status: "completed",
            categories: ["hardening"],
            created_at: "2026-01-01",
          },
        ],
      },
    }),
  );
  await page.route("**/api/scans/paged/summary", (r) =>
    r.fulfill({ json: { resources: [], findings: [], coverage: [] } }),
  );
  await page.route("**/api/scans/paged/findings?*", (r) => {
    const params = new URL(r.request().url()).searchParams;
    const offset = Number(params.get("offset"));
    const searched = params.get("search");
    return r.fulfill({
      json: {
        items: searched
          ? [finding("Beyond first page")]
          : Array.from({ length: 200 }, (_, i) =>
              finding(`Finding ${offset + i}`),
            ),
        total: searched ? 1 : 1201,
        offset,
        next_offset: searched
          ? null
          : offset + 200 < 1201
            ? offset + 200
            : null,
        facets: {
          services: ["storage"],
          statuses: ["FAIL"],
          frameworks: ["HackTricks Cloud Best Practices"],
        },
      },
    });
  });
  let detailRequests = 0;
  await page.route("**/api/scans/paged/findings/*", (r) => {
    detailRequests++;
    return r.fulfill({
      json: {
        ...finding("Beyond first page"),
        evidence: { source: "Complete lazy evidence" },
      },
    });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByLabel("Group findings").selectOption("check_id");
  await expect(
    page.getByText("200 loaded of 1201 matching findings", { exact: false }),
  ).toBeVisible();
  expect(detailRequests).toBe(0);
  await page.getByRole("button", { name: "Load more findings" }).click();
  await expect(
    page.getByText("400 loaded of 1201 matching findings", { exact: false }),
  ).toBeVisible();
  await page.getByLabel("Search findings").fill("Beyond first page");
  await expect(
    page.getByRole("button", { name: "Beyond first page native.check" }),
  ).toBeVisible();
  await page
    .getByRole("button", { name: "Beyond first page native.check" })
    .click();
  await expect(page.getByRole("dialog")).toContainText(
    "Complete lazy evidence",
  );
  expect(detailRequests).toBe(1);
});
test("signed artifact requests omit API bearer token and cookies", async ({
  page,
}) => {
  await emptyApi(page);
  await page.addInitScript(() =>
    sessionStorage.setItem(
      "peaso.api-token",
      "synthetic-token-for-artifact-test",
    ),
  );
  await page.route("**/api/scans", (r) =>
    r.fulfill({
      json: {
        items: [
          {
            id: "signed",
            status: "completed",
            categories: ["network"],
            created_at: "2026-01-01",
          },
        ],
      },
    }),
  );
  await page.route("**/api/scans/signed/summary", (r) =>
    r.fulfill({ json: { resources: [], findings: [], coverage: [] } }),
  );
  await page.route("**/api/scans/signed/graphs/network*", (r) =>
    r.fulfill({
      json: {
        download_url:
          "https://artifact.validation.test/private?signature=synthetic",
        expires_in: 300,
        format: "json",
      },
    }),
  );
  let headers: Record<string, string> = {};
  await page.route("https://artifact.validation.test/**", async (r) => {
    headers = await r.request().allHeaders();
    await r.fulfill({
      headers: { "Access-Control-Allow-Origin": "*" },
      json: {
        nodes: [
          {
            id: "one",
            label: "Signed artifact node",
            scope: "safe",
            provider: "azure",
          },
        ],
        edges: [],
      },
    });
  });
  await page.goto("/#Network%20Map");
  await page.getByRole("button", { name: "Table", exact: true }).click();
  await expect(
    page.getByRole("region", { name: "Network resource table" }).getByText("Signed artifact node", { exact: true }),
  ).toBeVisible();
  expect(headers.authorization).toBeUndefined();
  expect(headers.cookie).toBeUndefined();
  expect(headers.referer).toBeUndefined();
  expect(
    await page.evaluate(() =>
      JSON.stringify({ ...localStorage, ...sessionStorage }),
    ),
  ).not.toContain("signature=synthetic");
});
test("selected configuration query is explicit and unknown remains visible", async ({
  page,
}) => {
  await emptyApi(page);
  await page.route("**/api/scans", (r) =>
    r.fulfill({
      json: {
        items: [
          {
            id: "flow",
            status: "completed",
            categories: ["network"],
            created_at: "2026-01-01",
          },
        ],
      },
    }),
  );
  await page.route("**/api/scans/flow/summary", (r) =>
    r.fulfill({
      json: { stats: { resource_count: 2, finding_count: 0 }, coverage: [] },
    }),
  );
  await page.route("**/api/scans/flow/graphs/network*", (r) =>
    r.fulfill({
      json: {
        nodes: [
          {
            id: "node-source",
            resource_id: "global-source",
            label: "Source workload",
            type: "instance",
            scope: "account",
            provider: "aws",
          },
          {
            id: "node-target",
            resource_id: "global-target",
            label: "Target workload",
            type: "instance",
            scope: "account",
            provider: "aws",
          },
        ],
        edges: [],
      },
    }),
  );
  let calls = 0;
  let body: Record<string, unknown> = {};
  await page.route("**/api/scans/flow/reachability", (r) => {
    calls++;
    body = r.request().postDataJSON();
    return r.fulfill({
      json: {
        decision: "unknown",
        provider: "aws",
        snapshot_id: "owned-snapshot",
        query: body,
        application_listening: "unknown",
        routes: [],
        policy_decisions: [],
        translations: [],
        unresolved_dependencies: [
          {
            code: "source_port_required",
            message: "Source port required for stateless return evaluation",
          },
        ],
        evidence_refs: [],
        modeled_configuration: true,
        new_flow_only: true,
      },
    });
  });
  await page.goto("/#Network%20Map");
  await page
    .getByRole("button", { name: "Assess configuration path", exact: true })
    .click();
  expect(calls).toBe(0);
  await page.getByLabel("Source resource ID").fill("global-source");
  await page.getByLabel("Destination resource ID").fill("global-target");
  await page
    .getByRole("button", { name: "Assess configuration", exact: true })
    .click();
  await expect(page.getByRole("dialog")).toContainText("source_port_required");
  expect(body.source_resource_id).toBe("global-source");
  expect(body.destination_resource_id).toBe("global-target");
  expect(body.source_port).toBeUndefined();
  expect(body.protocol).toBe("tcp");
  expect(calls).toBe(1);
  await page.screenshot({
    path: "evidence/configuration-path-dialog.png",
    fullPage: true,
  });
});
test("clearing API authentication removes cached private connector data", async ({
  page,
}) => {
  await page.addInitScript(() =>
    sessionStorage.setItem(
      "peaso.api-token",
      "synthetic-private-session-token",
    ),
  );
  await emptyApi(page);
  await page.route("**/api/health", (route) => route.fulfill({ json: { status: "ok", auth_mode: "local" } }));
  await page.route("**/api/connectors", (r) =>
    r.request().headers().authorization
      ? r.fulfill({
          json: {
            items: [
              {
                id: "private",
                name: "Private environment from previous session",
                provider: "aws",
                scopes: [],
              },
            ],
          },
        })
      : r.fulfill({
          status: 401,
          json: { detail: "Bearer authentication required" },
        }),
  );
  await page.goto("/#Connectors");
  await expect(
    page.getByRole("heading", {
      name: "Private environment from previous session",
    }),
  ).toBeVisible();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Settings", exact: true })
    .click();
  await page.getByRole("button", { name: "Manage local API token" }).click();
  await page.getByRole("button", { name: "Clear token", exact: true }).click();
  expect(await page.evaluate(() => sessionStorage.getItem("peaso.api-token"))).toBeNull();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Connectors", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "Data could not be loaded" }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", {
      name: "Private environment from previous session",
    }),
  ).toHaveCount(0);
});
test("human asset labels preserve routing IDs and exact checklist filtering", async ({
  page,
}) => {
  await emptyApi(page);
  await page.route("**/api/scans", (r) =>
    r.fulfill({
      json: {
        items: [
          {
            id: "labels",
            status: "completed",
            categories: ["hardening"],
            created_at: "2026-01-01",
          },
        ],
      },
    }),
  );
  await page.route("**/api/scans/labels/summary**", (r) =>
    r.fulfill({
      json: { provider: "aws", stats: { resource_count: 1, finding_count: 1 } },
    }),
  );
  await page.route("**/api/catalog**", (r) =>
    r.fulfill({
      json: {
        checks: [],
        framework_versions: [
          {
            id: "cis_aws_1.5",
            provider: "aws",
            name: "CIS AWS Foundations v1.5",
            status: "partial",
            supported_native_checks: 1,
            pending_source_checks: 12,
            native_check_ids: ["native.check"],
          },
        ],
      },
    }),
  );
  const finding = {
    id: "finding-route",
    category: "hardening",
    check_id: "native.check",
    title: "Review production asset",
    provider: "aws",
    service: "ec2",
    resource_id: "sha256:global-route-id",
    resource_name: "Production <web>",
    native_resource_id: "i-native",
    scope: "owned-account",
    severity: "high",
    status: "FAIL",
    frameworks: ["CIS"],
  };
  let selected = "";
  await page.route("**/api/scans/labels/findings?*", (r) => {
    selected = new URL(r.request().url()).searchParams.get("framework") || "";
    return r.fulfill({
      json: {
        items: [finding],
        total: 1,
        next_offset: null,
        facets: { frameworks: ["CIS"], services: ["ec2"], statuses: ["FAIL"] },
      },
    });
  });
  await page.route("**/api/scans/labels/findings/finding-route", (r) =>
    r.fulfill({
      json: {
        ...finding,
        evidence: { source: "Captured configuration" },
        remediation: "Owner review",
      },
    }),
  );
  await page.goto("/#Hardening%20Findings");
  await page.getByLabel("Group findings").selectOption("check_id");
  await expect(page.locator(".asset-cell")).toContainText("Production <web>");
  await page.getByLabel("Compliance framework", { exact: true }).click();
  await page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option", { name: "CIS AWS Foundations v1.5", exact: true }).click();
  await expect.poll(() => selected).toBe("cis_aws_1.5");
  await expect(
    page.getByText(
      "Selected checklist: CIS AWS Foundations v1.5. Findings are filtered across the complete assessment.",
    ),
  ).toBeVisible();
  await expect(page.getByText(/pending source checks/)).toHaveCount(0);
  await page
    .getByRole("button", { name: "Review production asset native.check" })
    .click();
  await expect(page.getByRole("dialog")).toContainText("i-native");
  await expect(page.getByRole("dialog")).toContainText(
    "sha256:global-route-id",
  );
  expect(await page.locator(".asset-cell img").count()).toBe(0);
});

test('Help documents API authentication, filterable routes and complete report downloads', async ({ page, context }) => {
  await emptyApi(page);
  await page.goto('/#Help');
  await page.getByRole('navigation', { name: 'Documentation chapters' }).getByRole('button', { name: 'API reference', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Access your data through the API' })).toBeVisible();
  await expect(page.getByText('API keys allow personal-account GET/HEAD reads.', { exact: false })).toBeVisible();
  await expect(page.locator('.docs-code').first()).toContainText('Authorization: Bearer $CSPM_API_KEY');
  await expect(page.locator('.docs-api-table tbody tr')).toHaveCount(28);
  await page.getByRole('textbox', { name: 'Search API endpoints' }).fill('/findings');
  await expect(page.locator('.docs-api-table tbody tr')).toHaveCount(2);
  await expect(page.locator('.docs-api-table')).toContainText('/scans/{scan_id}/findings/{finding_id}');
  await page.getByRole('textbox', { name: 'Search API endpoints' }).fill('no-such-endpoint');
  await expect(page.getByText('No endpoints match this search.')).toBeVisible();
  await page.getByRole('textbox', { name: 'Search API endpoints' }).clear();
  await expect(page.getByText('without the API Authorization header', { exact: true })).toBeVisible();
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await page.getByRole('button', { name: 'Copy Authenticate and list assessments' }).click();
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toContain('$CSPM_API/scans');
  await page.screenshot({ path: '/tmp/cspm-help-api.png' });
});

test('Help provides every provider tutorial, scan guidance and platform definitions on mobile', async ({ page }) => {
  await emptyApi(page);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/#Help');
  const chapters = page.getByRole('navigation', { name: 'Documentation chapters' });
  await chapters.getByRole('button', { name: 'Connectors', exact: true }).click();
  for (const name of ['AWS', 'Google Cloud', 'Azure', 'Kubernetes']) {
    await page.getByRole('button', { name, exact: true }).click();
    await expect(page.getByRole('heading', { name: `${name} connector tutorial`, exact: true })).toBeVisible();
    const methods = page.getByRole('combobox', { name: 'Authentication setup method' });
    const values = await methods.locator('option').evaluateAll(options => options.map(option => (option as HTMLOptionElement).value));
    for (const value of values) {
      await methods.selectOption(value);
      await expect(page.getByRole('heading', { name: 'Permissions', exact: true })).toBeVisible();
    }
  }
  await chapters.getByRole('button', { name: 'Scans', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Run an assessment' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Optional content and image scans' })).toBeVisible();
  await chapters.getByRole('button', { name: 'Platform guide', exact: true }).click();
  for (const name of ['What each section is for', 'Objects and terminology', 'Understand finding statuses'])
    await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
  for (const term of ['Connector', 'Scope', 'Principal', 'Coverage', 'Privilege-escalation path', 'Access denied / DENIED', 'Manual / MANUAL'])
    await expect(page.locator('dt').filter({ hasText: term }).first()).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(391);
  await page.screenshot({ path: '/tmp/cspm-help-mobile.png' });
});


test('Hardening navigation badge counts failures instead of all findings', async ({ page }) => {
  await emptyApi(page);
  let failures = 37;
  await page.route('**/api/scans', route => route.fulfill({json: {items: [{id: 'badge-scan', status: 'completed'}]}}));
  await page.route('**/api/scans/badge-scan/summary?*', route => route.fulfill({json: {
    provider: 'aws', stats: {by_category: {hardening: 965}, failed_by_category: {hardening: failures}}, findings: [], resources: [], graphs: {}, coverage: [],
  }}));
  await page.goto('/#Help');
  const badge = page.getByRole('navigation', {name: 'Primary navigation'}).getByRole('button', {name: 'Hardening & Compliance', exact: true}).locator('.nav-count');
  await expect(badge).toHaveText('37');
  failures = 0;
  await page.reload();
  await expect(badge).toHaveText('0');
});
