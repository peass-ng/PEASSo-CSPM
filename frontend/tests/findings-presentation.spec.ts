import { expect, test } from "@playwright/test";
import { explainFindingEvidence } from "../src/findingExplanation";

test("service overview lists every service and pages one expanded service", async ({ page }) => {
  const findings = Array.from({ length: 80 }, (_, index) => ({
    id: `finding-${index}`, category: "hardening", provider: "aws", scope: "123456789012/us-east-1",
    service: index < 20 ? "iam" : "s3", status: index < 20 ? "PASS" : "FAIL",
    check_id: `check-${index}`, title: `Finding ${index}`, severity: "medium",
    resource_id: `resource-${index}`, frameworks: [],
  }));
  const requests: URL[] = [];
  await page.route("**/api/**", async route => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", created_at: "2026-01-01", categories: ["hardening"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) {
      requests.push(url);
      const service = url.searchParams.get("service");
      const offset = Number(url.searchParams.get("offset"));
      const selected = service ? findings.filter(finding => finding.service === service) : findings;
      const limit = service ? 50 : 1;
      json = { items: selected.slice(offset, offset + limit), total: selected.length,
        next_offset: offset + limit < selected.length ? offset + limit : null,
        service_groups: service ? [] : [
          { service: "iam", count: 20, status_counts: { PASS: 20 } },
          { service: "s3", count: 60, status_counts: { FAIL: 60 } },
        ] };
    }
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  await expect(page.getByText("80 findings across 2 services")).toBeVisible();
  await expect(page.locator(".service-group-button")).toHaveCount(2);
  await expect(page.locator(".finding-title")).toHaveCount(0);
  expect(requests.length).toBeGreaterThanOrEqual(1);
  expect(requests.every(url => url.searchParams.get("service") === null)).toBe(true);
  await page.getByRole("button", { name: /s3 60 findings/ }).click();
  await expect(page.locator(".finding-title")).toHaveCount(50);
  expect(requests.at(-1)?.searchParams.get("service")).toBe("s3");
  expect(requests.at(-1)?.searchParams.get("limit")).toBe("50");
  await page.getByRole("button", { name: "Next page" }).click();
  await expect(page.locator(".finding-title")).toHaveCount(10);
  expect(requests.at(-1)?.searchParams.get("offset")).toBe("50");
  await page.getByRole("button", { name: "Previous page" }).click();
  await expect(page.locator(".finding-title")).toHaveCount(50);
  await page.getByRole("columnheader", { name: "Status" }).getByRole("button").click();
  await expect(page.getByRole("button", { name: /s3 60 findings/ })).toHaveAttribute("aria-expanded", "true");
  await expect.poll(() => requests.at(-1)?.searchParams.get("sort_by")).toBe("status");
  await page.getByRole("button", { name: /iam 20 findings/ }).click();
  await expect(page.locator(".finding-title")).toHaveCount(20);
  expect(requests.at(-1)?.searchParams.get("service")).toBe("iam");
  for (const width of [1440, 390]) {
    await page.setViewportSize({ width, height: 844 });
    const selects = page.locator(".scan-picker select, .filters select, .filter-secondary select");
    expect(await selects.count()).toBeGreaterThanOrEqual(4);
    for (const select of await selects.all()) {
      await expect(select).toHaveCSS("appearance", "none");
      await expect(select).toHaveCSS("background-position", "calc(100% - 10px) 50%");
      await expect(select).toHaveCSS("padding-inline-end", "28px");
    }
    const workspace = page.getByRole("button", { name: "Select workspace" });
    const rightInset = await workspace.evaluate(button =>
      button.getBoundingClientRect().right - button.querySelector("svg.lucide-chevron-down")!.getBoundingClientRect().right,
    );
    expect(rightInset).toBeGreaterThanOrEqual(10);
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  }
});

test("Hardening groups findings by service and keeps Check as the flat view", async ({ page }) => {
  const findings = [
    { id: "iam-one", service: "iam", check_id: "check-1", title: "IAM check one", status: "FAIL" },
    { id: "iam-two", service: "iam", check_id: "check-2", title: "IAM check two", status: "PASS" },
    { id: "s3-one", service: "s3", check_id: "check-3", title: "S3 check", status: "DENIED" },
  ].map(finding => ({ ...finding, category: "hardening", provider: "aws", scope: "123456789012/us-east-1",
    resource_id: finding.id, severity: "medium", frameworks: [] }));
  await page.route("**/api/**", async route => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/me") ? { tenant_id: "test", plan: "free" }
      : path.endsWith("/scans") ? { items: [{ id: "scan-1", status: "completed", created_at: "2026-01-01", categories: ["hardening"] }] }
      : path.endsWith("/summary") ? { provider: "aws", resources: [], findings: [], coverage: [], stats: {} }
      : path.endsWith("/findings") ? { items: findings, total: findings.length, next_offset: null }
      : { items: [] };
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  const group = page.getByRole("combobox", { name: "Group findings" });
  await expect(group.locator("option")).toHaveText(["Service", "Check", "Type"]);
  await expect(page.locator(".service-group-button")).toHaveCount(2);
  await expect(page.locator(".finding-title")).toHaveCount(0);
  await page.getByRole("button", { name: /iam 2 findings/ }).click();
  await expect(page.locator(".finding-title")).toHaveText([/IAM check one/, /IAM check two/]);
  await expect(page.getByRole("button", { name: /s3 1 findings/ })).toBeVisible();
  await group.selectOption("check_id");
  await expect(page.locator(".service-group-button")).toHaveCount(0);
  await expect(page.locator(".finding-title")).toHaveCount(3);
  await group.selectOption("service");
  await expect(page.locator(".service-group-button")).toHaveCount(2);
});

test("finding statuses group equivalent results while preserving access denied", async ({ page }) => {
  const statuses = ["FAIL", "PASS", "UNKNOWN", "DENIED", "MANUAL", "NOT_APPLICABLE", "EMPTY"];
  const findings = statuses.map((status, index) => ({
    id: `status-${index}`, category: "hardening", provider: "aws", scope: "123456789012/us-east-1",
    severity: "medium", service: "iam", resource_id: `resource-${index}`,
    check_id: `check-${index}`, title: `Finding ${index}`, status, frameworks: [],
  }));
  const requestedStatuses: string[] = [];
  await page.route("**/api/**", async route => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", created_at: "2026-01-01", categories: ["hardening"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) {
      const selected = url.searchParams.get("status") || "";
      if (url.searchParams.get("aggregation") === "check") requestedStatuses.push(selected);
      const matching = selected ? findings.filter(finding => selected.split(",").includes(finding.status)) : findings;
      json = { items: matching, total: matching.length, next_offset: null,
        status_filter_total: findings.length,
        status_filter_counts: { FAIL: 1, PASS: 1, "UNKNOWN,MANUAL": 2,
          DENIED: 1, "NOT_APPLICABLE,EMPTY": 2 } };
    }
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByLabel("Group findings").selectOption("check_id");
  const status = page.getByRole("combobox", { name: "Status", exact: true });
  await expect(status.locator("option")).toHaveText(["All statuses (7)", "Failed (1)", "Passed (1)", "Needs review (2)", "Access denied (1)", "Not applicable (2)"]);
  await expect(status).toHaveValue("FAIL");
  await expect(page.locator(".findings-table tbody .finding-title")).toHaveCount(1);
  expect(requestedStatuses[0]).toBe("FAIL");
  await status.selectOption("");
  await expect(page.locator(".findings-table tbody .finding-title")).toHaveCount(7);
  await status.selectOption({ value: "UNKNOWN,MANUAL" });
  await expect(status.locator("option")).toHaveText(["All statuses (7)", "Failed (1)", "Passed (1)", "Needs review (2)", "Access denied (1)", "Not applicable (2)"]);
  await expect(page.locator(".findings-table tbody .finding-title")).toHaveCount(2);
  await expect(page.locator(".findings-table tbody .badge.review")).toHaveCount(2);
  expect(requestedStatuses.at(-1)).toBe("UNKNOWN,MANUAL");
  await status.selectOption({ value: "DENIED" });
  await expect(page.locator(".findings-table tbody .finding-title")).toHaveCount(1);
  await expect(page.locator(".findings-table tbody .badge.access_denied")).toHaveText(["Access denied"]);
  expect(requestedStatuses.at(-1)).toBe("DENIED");
  await status.selectOption({ value: "NOT_APPLICABLE,EMPTY" });
  await expect(page.locator(".findings-table tbody .finding-title")).toHaveCount(2);
  await expect(page.locator(".findings-table tbody .badge.not_applicable")).toHaveCount(2);
  expect(requestedStatuses.at(-1)).toBe("NOT_APPLICABLE,EMPTY");
  await page.getByRole("button", { name: "Reset filters", exact: true }).click();
  await expect(status).toHaveValue("FAIL");
  await status.selectOption("PASS");
  await page.getByRole("navigation").getByRole("button", { name: "Exposure", exact: true }).click();
  await expect(status).toHaveValue("FAIL");
  await status.selectOption("PASS");
  await page.getByRole("navigation").getByRole("button", { name: "Hardening & Compliance", exact: true }).click();
  await expect(status).toHaveValue("FAIL");
});

test("nested federated trust evidence keeps full-width values", async ({ page }) => {
  const finding = {
    id: "federated-trust", category: "hardening", provider: "aws", scope: "555566667777/us-east-2",
    severity: "high", service: "iam", resource_id: "role/example", check_id: "fixture.federated_trust",
    title: "Federated trust review", status: "FAIL", frameworks: [],
    evidence: { federated_trusts: [{
      statement: "AssumeRolePolicyDocument.Statement[0]",
      federated_principal: "arn:aws:iam::555566667777:oidc-provider/cognito-idp.us-east-2.amazonaws.com/us-east-2_zCc4BSZAu",
      issuer: "cognito-idp.us-east-2.amazonaws.com/us-east-2_zCc4BSZAu",
      multi_tenant_issuer: false,
      conditions: { StringEquals: {
        "cognito-idp.us-east-2.amazonaws.com/us-east-2_zCc4BSZAu:aud": "37huinnh8v40psb29l72r812ff",
      }, "ForAnyValue:StringLike": {
        "cognito-idp.us-east-2.amazonaws.com/us-east-2_zCc4BSZAu:cognito:groups": "madmin-operators",
      } },
      problems: [{ reason: "Review trust condition" }],
    }] },
  };
  await page.route("**/api/**", async route => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/me") ? { tenant_id: "test", plan: "free" }
      : path.endsWith("/scans") ? { items: [{ id: "scan-1", status: "completed", created_at: "2026-01-01", categories: ["hardening"] }] }
      : path.endsWith("/summary") ? { provider: "aws", resources: [], findings: [], coverage: [], stats: {} }
      : path.endsWith("/findings") ? { items: [finding], total: 1, next_offset: null }
      : path.endsWith("/findings/federated-trust") ? finding : { items: [] };
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByRole("button", { name: /iam 1 findings/ }).click();
  await page.getByRole("button", { name: /Federated trust review/ }).click();
  const dialog = page.getByRole("dialog");
  const evidence = dialog.locator('details:has(> summary:text-is("Technical evidence details"))');
  await evidence.locator("summary").click();
  await evidence.getByRole("button", { name: "Show 6 supplied fields" }).click();
  await evidence.locator('.evidence-field:has(> dt:text-is("Conditions")) > dd > button').click();
  await evidence.locator('.evidence-field:has(> dt:text-is("String Equals")) > dd > button').click();
  const aud = evidence.getByText("37huinnh8v40psb29l72r812ff", { exact: true });
  await expect(aud).toBeVisible();
  const valueWidth = () => aud.evaluate(element => element.closest("dd")!.getBoundingClientRect().width);
  expect(await valueWidth()).toBeGreaterThan(250);
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await valueWidth()).toBeGreaterThan(160);
  expect(await dialog.evaluate(element => element.scrollWidth - element.clientWidth)).toBeLessThanOrEqual(1);
});

test("Exposure groups findings by expandable service and explains the public path", async ({ page }) => {
  const base = {
    category: "exposure", provider: "aws", scope: "123456789012/eu-west-1",
    severity: "high", status: "FAIL", frameworks: ["HackTricks Cloud Best Practices"],
    check_id: "analysis.internet_exposure", title: "Internet access to tcp/22 at 54.1.2.3",
  };
  const findings = [
    { ...base, id: "exposed-1", service: "ec2", resource_id: "hash-1", resource_name: "DifferentAuths", native_resource_id: "i-123" },
    { ...base, id: "exposed-2", service: "ec2", resource_id: "hash-2", resource_name: "Other host" },
    { ...base, id: "exposed-3", service: "rds", resource_id: "hash-3", resource_name: "Database" },
  ];
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", connector_id: "c", created_at: "2026-01-01", categories: ["exposure"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) {
      const offset = Number(new URL(route.request().url()).searchParams.get("offset"));
      json = offset === 0
        ? { items: findings.slice(0, 2), total: findings.length, next_offset: 2 }
        : { items: findings.slice(2), total: findings.length, next_offset: null };
    }
    if (path.endsWith("/findings/exposed-1")) json = { ...findings[0],
      description: "Generic cross-provider check definition", evaluated: ["generic field list"],
      evidence: { exposed_ports: ["tcp/22"], public_addresses: ["54.1.2.3"], path: [
        { layer: "security_group", decision: "allow", reason: "0.0.0.0/0 permits TCP 22" },
        { layer: "route", decision: "allow", reason: "internet gateway route" },
      ] }, remediation: "Narrow the public path.", remediation_details: {
        summary: "Old verbose general remediation.",
        steps: ["Read exposure_kind, exposed_ports and every path layer before finding the owner."],
        cli: [], references: [{ title: "AWS public access", url: "https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html" }],
      },
    };
    await route.fulfill({ json });
  });
  await page.goto("/#Exposure");
  await expect(page.getByRole("button", { name: /Exposed containers with CVEs/ })).toHaveCount(0);
  await page.getByRole("button", { name: "Load more findings" }).click();
  await expect(page.locator(".service-group-button")).toHaveCount(2);
  await expect(page.locator(".finding-title")).toHaveCount(0);
  await page.getByRole("button", { name: /ec2 2 findings/ }).click();
  await expect(page.locator(".finding-title")).toHaveCount(2);
  await page.getByRole("button", { name: /Internet access to tcp\/22.*analysis.internet_exposure/ }).first().click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("DifferentAuths", { exact: true }).first()).toBeVisible();
  await expect(dialog.getByText("Internet access to tcp/22 at 54.1.2.3 is allowed.")).toBeVisible();
  await expect(dialog.getByText("security_group: 0.0.0.0/0 permits TCP 22")).toHaveCount(0);
  await expect(dialog.getByText("Generic cross-provider check definition")).toBeHidden();
  await expect(dialog.locator(".remediation-actions > li")).toHaveText(["Consider whether this endpoint needs internet access; restrict unnecessary source networks or ports."]);
  await expect(dialog.getByText("Old verbose general remediation.")).toHaveCount(0);
  await expect(dialog.getByRole("link", { name: "AWS public access" })).toBeVisible();
  await expect(page.getByLabel("Exact finding checklist version")).toHaveCount(0);
});

test("nested observed scalar facts are concise without claiming an insecure state", async ({ page }) => {
  const finding = {
    id: "observed-empty-key", category: "hardening", check_id: "aws.cb.sqs.cmk_encryption",
    title: "Review queue encryption key", provider: "aws", service: "sqs",
    resource_id: "queue-1", scope: "123456789012/us-east-1", severity: "medium",
    status: "FAIL", frameworks: ["HackTricks Cloud Best Practices"],
  };
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", connector_id: "c", created_at: "2026-01-01" }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) json = { items: [finding], total: 1, next_offset: null };
    if (path.endsWith("/findings/observed-empty-key")) json = {
      ...finding, evidence: { Attributes: { KmsMasterKeyId: "" }, Config: {
        enabled: false, endpoint: "[2001:db8::1]:443", rule_count: 0, api_key: "private-synthetic-value",
      } },
    };
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByLabel("Group findings").selectOption("check_id");
  await page.getByRole("button", { name: "Review queue encryption key aws.cb.sqs.cmk_encryption" }).click();
  const dialog = page.getByRole("dialog");
  const observed = dialog.getByRole("heading", { name: "Observed evidence" }).locator("xpath=following-sibling::p[1]");
  await expect(observed).toContainText("KMS Master Key ID is empty in the supplied snapshot");
  await expect(observed).toContainText("enabled is false");
  await expect(observed).toContainText("[2001:db8::1]:443");
  await expect(observed).not.toContainText("private-synthetic-value");
  await expect(observed).not.toContainText("unencrypted");
  await expect(dialog.locator("pre.evidence")).toHaveCount(0);
  await dialog.getByText("Technical evidence details").click();
  await expect(dialog.getByText("Sensitive value withheld from preview")).toBeVisible();
});

test("encoded policy and array evidence stay factual without JSON in the summary", async ({ page }) => {
  const finding = {
    id: "encoded-policy", category: "hardening", check_id: "aws.cb.sqs.cmk_encryption",
    title: "Inspect supplied policy", provider: "aws", service: "sqs",
    resource_id: "queue-encoded", scope: "123456789012/us-east-1", severity: "medium",
    status: "UNKNOWN", frameworks: ["HackTricks Cloud Best Practices"],
  };
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", connector_id: "c", created_at: "2026-01-01" }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) json = { items: [finding], total: 1, next_offset: null };
    if (path.endsWith("/findings/encoded-policy")) json = {
      ...finding,
      evidence: { Attributes: {
        Policy: JSON.stringify({ Version: "2012-10-17", Statement: [] }),
        Config: JSON.stringify([{ enabled: true }, { enabled: false }]),
      } },
    };
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByLabel("Group findings").selectOption("check_id");
  await page.getByRole("button", { name: "Inspect supplied policy aws.cb.sqs.cmk_encryption" }).click();
  const observed = page.getByRole("dialog").getByRole("heading", { name: "Observed evidence" }).locator("xpath=following-sibling::p[1]");
  await expect(observed).toContainText("Policy Version is 2012-10-17");
  await expect(observed).toContainText("Config contains 2 supplied records");
  await expect(observed).not.toContainText("{\"");
  await expect(observed).not.toContainText("[{\"");
  await expect(observed).not.toContainText("unencrypted");
});

test("sensitive-only and malformed structured evidence have bounded neutral summaries", () => {
  const withheld = explainFindingEvidence({ api_key: "private-synthetic-value", Credentials: { Password: "private-synthetic-value" } }, "UNKNOWN");
  expect(withheld).toContain("no concise non-sensitive values");
  expect(withheld).not.toContain("private-synthetic-value");
  const malformed = explainFindingEvidence({ Policy: "{malformed-json}" }, "UNKNOWN");
  expect(malformed).toContain("could not be summarized");
  expect(malformed).not.toContain("{malformed-json}");
  expect(explainFindingEvidence({ Address: "[2001:db8::1]:443" }, "UNKNOWN")).toContain("[2001:db8::1]:443");
  const bounded = explainFindingEvidence({ Ports: Array.from({ length: 5000 }, (_, index) => index) }, "UNKNOWN");
  expect(bounded).toContain("0, 1, 2; 4997 more supplied");
  expect(bounded.length).toBeLessThan(180);
});

test("signed large finding shows reviewed remediation without forwarding bearer or cookies", async ({ page }) => {
  const finding = {
    id: "signed-large", category: "hardening", check_id: "aws.gap.vpc.sg_world_any_common_ports",
    title: "Broad ingress", provider: "aws", service: "ec2", resource_id: "resource-1",
    native_resource_id: "sg-12345678", scope: "123456789012/us-east-1", severity: "high",
    status: "FAIL", frameworks: [], remediation: "Legacy review",
    description: "Reads declared security group ingress for a public source on the flagged port.",
    evaluated: ["IpPermissions[].IpRanges[].CidrIp", "IpPermissions[].FromPort"],
    pass_when: "No matching public ingress rule is declared.",
    fail_when: "A matching public ingress rule is declared.",
  };
  await page.addInitScript(() => sessionStorage.setItem("peaso.api-token", "synthetic-finding-token"));
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", connector_id: "c", created_at: "2026-01-01", categories: ["hardening"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) json = { items: [finding], total: 1, next_offset: null };
    if (path.endsWith("/findings/signed-large")) json = {
      download_url: "https://artifact.validation.test/large-finding?signature=synthetic", expires_in: 300, format: "json",
      remediation_details: {
        summary: "Narrow the flagged ingress rule to tested client sources.",
        steps: ["Inspect the matching rule and attached workload.", "Replace the broad source after client tests.", "Verify intended clients can still connect."],
        cli: [{ label: "Inspect ingress rule IDs", code: "aws ec2 describe-security-group-rules --filters Name=group-id,Values=sg-12345678" }],
        caveats: ["The approved client CIDR and rule ID are not inferred from evidence."],
        references: [{ title: "AWS security group rules", url: "https://docs.aws.amazon.com/vpc/latest/userguide/working-with-security-group-rules.html" }],
      },
    };
    await route.fulfill({ json });
  });
  let artifactHeaders: Record<string, string> = {};
  await page.route("https://artifact.validation.test/**", async (route) => {
    artifactHeaders = await route.request().allHeaders();
    await route.fulfill({ headers: { "Access-Control-Allow-Origin": "*" }, json: { ...finding, evidence: { native: "Complete large evidence", missing: null, placeholder: "Not supplied", enabled: false, rule_count: 0 } } });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByLabel("Group findings").selectOption("check_id");
  await page.getByRole("button", { name: "Broad ingress aws.gap.vpc.sg_world_any_common_ports" }).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByText("Technical evidence details").click();
  await expect(dialog.getByText("Complete large evidence", { exact: true })).toBeVisible();
  await expect(dialog.locator("pre.evidence")).toHaveCount(0);
  await expect(dialog.getByText("Inspect the matching rule and attached workload.", { exact: true })).toBeVisible();
  await dialog.getByText("How this check works").click();
  await expect(dialog.getByText(finding.description, { exact: true })).toBeVisible();
  await dialog.getByText("Evaluation details").click();
  await expect(dialog.getByText("IpPermissions[].IpRanges[].CidrIp", { exact: true })).toBeVisible();
  await expect(dialog.getByText("Inspect the matching rule and attached workload.", { exact: true })).toBeVisible();
  await expect(dialog.getByRole("link", { name: "AWS security group rules" })).toBeVisible();
  await dialog.getByText("Commands (1)").click();
  await expect(dialog.getByText("aws ec2 describe-security-group-rules --filters Name=group-id,Values=sg-12345678")).toBeVisible();
  await expect(dialog.getByText("Verify intended clients can still connect.", { exact: true })).toBeVisible();
  await expect(dialog.locator(".remediation-actions > li")).toHaveCount(3);
  await expect(dialog.getByText(/Remaining steps|More guidance & references|About this guidance|Before changing this/)).toHaveCount(0);
  await expect(dialog.getByText("Not supplied", { exact: true })).toHaveCount(0);
  await expect(dialog.locator(".evidence-fields dt").filter({ hasText: /^Missing$|^Placeholder$/ })).toHaveCount(0);
  await expect(dialog.locator(".evidence-field").filter({ hasText: /^Enabled/ })).toContainText("No");
  await expect(dialog.locator(".evidence-field").filter({ hasText: /^Rule count/ })).toContainText("0");
  const downloadPromise = page.waitForEvent("download");
  await dialog.getByRole("button", { name: "Download full evidence" }).click();
  const stream = await (await downloadPromise).createReadStream();
  const chunks: Buffer[] = [];
  for await (const chunk of stream!) chunks.push(Buffer.from(chunk));
  expect(JSON.parse(Buffer.concat(chunks).toString())).toMatchObject({ missing: null, placeholder: "Not supplied", enabled: false, rule_count: 0 });
  await dialog.getByText("Identifiers & frameworks").click();
  const label = await dialog.locator(".finding-detail-metadata dt").first().boundingBox();
  const value = await dialog.locator(".finding-detail-metadata dd").first().boundingBox();
  expect(Math.abs(label!.y - value!.y)).toBeLessThan(5);
  expect(value!.x).toBeGreaterThan(label!.x + label!.width);
  await expect(dialog.getByRole("link", { name: "AWS security group rules" })).toHaveAttribute("href", /^https:\/\/docs\.aws\.amazon\.com\//);
  expect(artifactHeaders.authorization).toBeUndefined();
  expect(artifactHeaders.cookie).toBeUndefined();
  expect(artifactHeaders.referer).toBeUndefined();
});

test("catalog choices survive empty results and evidence is concise, escaped and lazy", async ({ page }) => {
  const requested: URL[] = [];
  let detailCalls = 0;
  const finding = {
    id: "finding-1", category: "hardening", check_id: "native.check",
    title: "Review <storage>", provider: "aws", service: "s3",
    resource_id: "arn:aws:s3:::bucket", scope: "123456789012/us-east-1",
    severity: "high", status: "UNKNOWN", frameworks: ["HackTricks Cloud Best Practices"],
    framework_ids: ["cis_aws_1.5"],
  };
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", connector_id: "c", created_at: "2026-01-01", categories: ["hardening"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/catalog/frameworks")) json = {
      frameworks: [{ id: "CIS", name: "CIS" }, { id: "HackTricks Cloud Best Practices", name: "HackTricks Cloud Best Practices" }],
      framework_versions: [{ id: "cis_aws_1.5", name: "CIS AWS Foundations v1.5", provider: "aws", status: "partial" }],
    };
    if (path.endsWith("/findings")) {
      requested.push(url);
      json = { items: url.searchParams.get("framework") === "CIS" ? [] : [finding],
        total: url.searchParams.get("framework") === "CIS" ? 0 : 1, next_offset: null,
        facets: { frameworks: ["HackTricks Cloud Best Practices"] } };
    }
    if (path.endsWith("/findings/finding-1")) {
      detailCalls++;
      json = { ...finding, evidence: { reason: "Facts unavailable <img src=x onerror=alert(1)>", collection_status: "not_collected", config: { nested: true } }, remediation: "Review source" };
    }
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  const frameworks = page.getByLabel("Compliance framework");
  await page.getByLabel("Group findings").selectOption("check_id");
  await expect(frameworks).toHaveText("All compliance frameworks");
  await frameworks.click();
  await expect(page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option")).toHaveText(["All compliance frameworks", "CIS", "CIS AWS Foundations v1.5", "HackTricks Cloud Best Practices"]);
  await page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option", { name: "CIS", exact: true }).click();
  await expect(page.getByRole("heading", { name: "No findings match these filters" })).toBeVisible();
  await frameworks.click();
  await expect(page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option", { name: "CIS", exact: true })).toHaveCount(1);
  await page.getByLabel("Filter compliance frameworks").fill("foundations");
  await expect(page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option")).toHaveText(["CIS AWS Foundations v1.5"]);
  await page.getByRole("listbox", { name: "Compliance frameworks" }).getByRole("option", { name: "CIS AWS Foundations v1.5", exact: true }).click();
  await expect.poll(() => requested.at(-1)?.searchParams.get("framework")).toBe("cis_aws_1.5");
  await page.getByRole("button", { name: "Reset filters" }).click();
  await expect(page.getByRole("button", { name: "Review <storage> native.check" })).toBeVisible();
  expect(detailCalls).toBe(0);
  await page.getByRole("button", { name: "Review <storage> native.check" }).click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.locator("p").filter({ hasText: /Facts unavailable <img src=x onerror=alert\(1\)>/ })).toBeVisible();
  await expect(dialog.locator("img")).toHaveCount(0);
  await expect(dialog.locator("details:has(> summary:text-is('Technical evidence details'))")).not.toHaveAttribute("open");
  await expect(dialog.getByText("No observed evidence was supplied.")).toHaveCount(0);
  await expect(dialog.getByText("Technical evidence details")).toBeVisible();
  expect(detailCalls).toBe(1);
});

test("coverage is in completed Scan details and all finding columns sort", async ({ page }) => {
  const requests: URL[] = [];
  const finding = (id: string, provider: string, scope: string, resource_id: string) => ({
    id, category: "hardening", check_id: id, title: id, provider, service: "service",
    resource_id, scope, severity: "high", status: "PASS", frameworks: ["HackTricks Cloud Best Practices"],
    evidence: { enabled: true }, remediation: "Review",
  });
  const findings = [
    finding("aws", "aws", "123456789012/us-east-1", "arn:aws:iam::123456789012:role/test"),
    finding("gcp", "gcp", "projects/actual-project", "projects/actual-project/buckets/x"),
    finding("azure", "azure", "/subscriptions/sub-123/resourceGroups/rg", "azure-resource"),
    finding("k8s", "k8s", "cluster-a/namespace", "k8s://cluster-a/pod/x"),
  ];
  findings[0].evidence = { default_encryption_configuration: false, rule_count: 0 } as unknown as { enabled: boolean };
  findings[3].status = "UNKNOWN";
  findings[3].evidence = undefined as unknown as { enabled: boolean };
  await page.route("**/api/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    let json: unknown = { items: [] };
    if (path.endsWith("/me")) json = { tenant_id: "test", plan: "free" };
    if (path.endsWith("/scans")) json = { items: [{ id: "scan-1", status: "completed", connector_id: "c", created_at: "2026-01-01", categories: ["hardening"] }] };
    if (path.endsWith("/summary")) json = { provider: "aws", resources: [], findings: [], coverage: [], stats: {} };
    if (path.endsWith("/findings")) {
      requests.push(url);
      json = { items: findings, total: findings.length, next_offset: null };
    }
    if (path.endsWith("/coverage")) json = Number(url.searchParams.get("offset")) === 0
      ? { items: [{ check_id: "coverage-check", status: "denied", reason: "Collection permission denied" },
        ...Array.from({ length: 199 }, (_, i) => ({ check_id: `record-${i}`, status: "collected" }))],
        total: 201, next_offset: 200 }
      : { items: [{ check_id: "late-coverage", status: "unknown", reason: "Region was not collected" }],
        total: 201, next_offset: null };
    if (path.endsWith("/findings/aws")) json = findings[0];
    if (path.endsWith("/findings/gcp")) json = findings[1];
    if (path.endsWith("/findings/k8s")) json = findings[3];
    await route.fulfill({ json });
  });
  await page.goto("/#Hardening%20Findings");
  await page.getByLabel("Group findings").selectOption("check_id");
  await expect(page.getByRole("columnheader", { name: "Account" })).toBeVisible();
  for (const account of ["123456789012", "actual-project", "sub-123", "cluster-a"])
    await expect(page.getByRole("cell", { name: account, exact: true })).toBeVisible();
  await page.getByRole("button", { name: "aws aws" }).click();
  await expect(page.getByRole("dialog").getByText("Collected default encryption configuration is absent. 0 rules recorded.")).toBeVisible();
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.getByRole("button", { name: "gcp gcp" }).click();
  await expect(page.getByRole("dialog").locator(".finding-detail-observation > p").first()).toContainText("enabled is true.");
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.getByRole("button", { name: "k8s k8s" }).click();
  await expect(page.getByRole("dialog").getByText("No observed evidence was supplied for this undetermined result.")).toBeVisible();
  await page.getByRole("button", { name: "Close inspector" }).click();
  await expect(page.getByText("Coverage & limitations")).toHaveCount(0);
  for (const [heading, field] of [["Severity", "severity"], ["Finding / check", "title"], ["Service", "service"], ["Asset", "resource_id"], ["Account", "account"], ["Status", "status"]]) {
    const header = page.getByRole("columnheader", { name: heading });
    await header.getByRole("button").click();
    await expect(header).toHaveAttribute("aria-sort", "ascending");
    await expect.poll(() => requests.at(-1)?.searchParams.get("sort_by")).toBe(field);
    await expect.poll(() => requests.at(-1)?.searchParams.get("sort_order")).toBe("asc");
    await header.getByRole("button").click();
    await expect(header).toHaveAttribute("aria-sort", "descending");
    await expect.poll(() => requests.at(-1)?.searchParams.get("sort_order")).toBe("desc");
  }
  await page.getByRole("navigation").getByRole("button", { name: "Scans", exact: true }).click();
  await page.locator(".scan-row .scan-id").click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByText("Coverage & limitations")).toBeVisible();
  await expect(dialog.getByText("coverage-check")).toBeVisible();
  await expect(dialog.getByText("Collection permission denied")).toBeVisible();
  await expect(dialog.getByText("200 of 201 coverage records loaded")).toBeVisible();
  await dialog.getByRole("button", { name: "Load more coverage" }).click();
  await expect(dialog.getByText("late-coverage")).toBeVisible();
  await expect(dialog.getByText("Region was not collected")).toBeVisible();
});

test("framework picker defaults to all, sorts and searches versions, and selects failed security findings", async ({ page }) => {
  const requests: URL[] = [];
  await page.route("**/api/**", async route => {
    const url = new URL(route.request().url());
    let json: unknown = { items: [] };
    if (url.pathname.endsWith('/me')) json = { tenant_id: 'test', plan: 'free' };
    if (url.pathname.endsWith('/scans')) json = { items: [{ id: 'scan-1', status: 'completed' }] };
    if (url.pathname.endsWith('/summary')) json = { provider: 'aws', stats: {} };
    if (url.pathname.endsWith('/catalog/frameworks')) json = {
      frameworks: ['Zebra framework', 'HackTricks Cloud Best Practices', 'alpha framework'],
      framework_versions: [{ id: 'cis_aws', name: 'CIS AWS v2', provider: 'aws' }],
    };
    if (url.pathname.endsWith('/findings')) {
      requests.push(url); json = { items: [], total: 0, next_offset: null };
    }
    await route.fulfill({ json });
  });
  await page.goto('/#Hardening%20Findings');
  await expect(page.getByRole('heading', { name: 'Hardening & Compliance', exact: true })).toBeVisible();
  const picker = page.getByLabel('Compliance framework', { exact: true });
  await expect(picker).toHaveText('All compliance frameworks');
  const groupSelect = page.getByRole('combobox', { name: 'Group findings' });
  const typography = (control: typeof picker) => control.evaluate(element => {
    const { fontFamily, fontSize, fontWeight, lineHeight } = getComputedStyle(element);
    return { fontFamily, fontSize, fontWeight, lineHeight };
  });
  expect(await typography(picker)).toEqual(await typography(groupSelect));
  await picker.click();
  await expect(page.getByRole('listbox', { name: 'Compliance frameworks' }).getByRole('option')).toHaveText(['All compliance frameworks', 'alpha framework', 'CIS AWS v2', 'HackTricks Cloud Best Practices', 'Zebra framework']);
  await page.getByLabel('Filter compliance frameworks').fill('cis');
  await expect(page.getByRole('listbox', { name: 'Compliance frameworks' }).getByRole('option')).toHaveText(['CIS AWS v2']);
  await page.getByRole('listbox', { name: 'Compliance frameworks' }).getByRole('option', { name: 'CIS AWS v2', exact: true }).click();
  await expect.poll(() => requests.at(-1)?.searchParams.get('framework')).toBe('cis_aws');
  await page.getByLabel('Status', { exact: true }).selectOption('');
  await page.getByRole('button', { name: 'Show security failed', exact: true }).click();
  await expect(picker).toHaveText('HackTricks Cloud Best Practices');
  await expect(page.getByLabel('Status', { exact: true })).toHaveValue('FAIL');
  await expect.poll(() => requests.at(-1)?.searchParams.get('framework')).toBe('HackTricks Cloud Best Practices');
  await expect.poll(() => requests.at(-1)?.searchParams.get('status')).toBe('FAIL');
  await page.getByRole('button', { name: 'Reset filters', exact: true }).click();
  await expect(picker).toHaveText('All compliance frameworks');
});

test('Leaks navigation filters secret findings across categories and opens retained values and locations', async ({ page }) => {
  const requests: URL[] = [];
  const finding = { id: 'leak-1', category: 'hardening', check_id: 'aws.review.lambda.environment_literal_secret_indicators',
    title: 'Detected secret in Lambda configuration', finding_type: 'detected_leaks', provider: 'aws', service: 'lambda', scope: 'test-account/us-east-1',
    resource_id: 'lambda-1', status: 'FAIL', severity: 'high', frameworks: [], evidence_summary: 'A secret was detected in a selected environment value.' };
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()); let json: unknown = { items: [] };
    if (url.pathname.endsWith('/me')) json = { tenant_id: 'test', plan: 'free' };
    if (url.pathname.endsWith('/scans')) json = { items: [{ id: 'scan-1', status: 'completed' }] };
    if (url.pathname.endsWith('/summary')) json = { provider: 'aws', stats: {} };
    if (url.pathname.endsWith('/findings')) {
      requests.push(url);
      json = { items: [finding], total: 1, next_offset: null,
        service_groups: url.searchParams.has('service') ? [] : [{ service: 'lambda', count: 1, status_counts: { FAIL: 1 } }] };
    }
    if (url.pathname.endsWith('/findings/leak-1')) json = { ...finding, evidence: {}, remediation: 'Rotate the exposed value and remove it from source configuration.',
      secret_evidence: { status: 'available', complete: true, matches: [{ fingerprint: 'synthetic-ui-match', value: 'SYNTHETIC-SECRET-FOR-UI-ONLY', locations: [{ resource_id: 'lambda-1', scope: 'test-account/us-east-1', path: 'configuration.environment', field: 'DEMO_API_KEY', line: null }] }] } };
    await route.fulfill({ json });
  });
  await page.goto('/#Leaks');
  await expect(page.getByRole('heading', { name: 'Leaks', exact: true })).toBeVisible();
  await page.getByRole('button', { name: /lambda 1 finding/ }).click();
  await page.getByRole('button', { name: /Detected secret in Lambda configuration/ }).click();
  await expect(page.getByRole('dialog').getByText('SYNTHETIC-SECRET-FOR-UI-ONLY', { exact: true })).toBeVisible();
  await expect(page.getByRole('dialog').getByText('configuration.environment', { exact: true })).toBeVisible();
  await expect(page.getByRole('dialog').getByText('DEMO_API_KEY', { exact: true })).toBeVisible();
  const resultRequests = requests.filter(url => url.searchParams.get('group_by') === 'service');
  expect(resultRequests.length).toBeGreaterThanOrEqual(2);
  expect(resultRequests.every(url => url.searchParams.get('finding_type') === 'detected_leaks' && url.searchParams.get('status') === 'FAIL' && !url.searchParams.has('categories'))).toBe(true);
});
