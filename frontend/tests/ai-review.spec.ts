import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
async function setup(page: Page) {
  await page.route('**/api/**', route => route.fulfill({ json: { items: [] } }));
  await page.route('**/api/me', route => route.fulfill({ json: { tenant_id: 'fixture', auth_kind: 'user' } }));
  await page.route('**/api/ai/codex', route => route.fulfill({ json: { available: true, connected: false, platform_configured: true } }));
  await page.route('**/api/ai/configuration', route => route.fulfill({ json: { available: true, hosted: true, source: 'hacktricks', selection: null, codex_connected: false, isolation_available: true } }));
  await page.route('**/api/health', route => route.fulfill({ json: { auth_mode: 'local' } }));
  await page.route('**/api/connectors', route => route.fulfill({ json: { items: [{ id: 'account', name: 'Production AWS', provider: 'aws' }] } }));
}
test('AI defaults on and can be disabled for a scan', async ({ page }) => {
  await setup(page);
  const writes: Record<string, unknown>[] = [];
  await page.route('**/api/scans', route => {
    if (route.request().method() === 'POST') { writes.push(route.request().postDataJSON()); return route.fulfill({ status: 201, json: { id: 'scan', status: 'queued' } }); }
    return route.fulfill({ json: { items: [] } });
  });
  await page.goto('/#Scans');
  await page.getByRole('button', { name: 'Launch scan', exact: true }).click();
  const toggle = page.getByLabel('Use AI for Network analysis and prioritized actions');
  await expect(toggle).toBeChecked();
  await toggle.uncheck();
  await page.getByRole('dialog').getByRole('button', { name: 'Start scan', exact: true }).click();
  await expect.poll(() => writes.length).toBe(1);
  expect(writes[0].ai_enabled).toBe(false);
  await page.getByRole('button', { name: 'Add schedule', exact: true }).click();
  await expect(toggle).toBeChecked();
});
test('Settings starts and cancels personal Codex sign-in', async ({ page }) => {
  await setup(page);
  await page.route('**/api/ai/codex', route => route.request().method() === 'DELETE' ? route.fulfill({ status: 204 }) : route.fulfill({ json: { connected: false, platform_configured: true, available: true } }));
  await page.route('**/api/ai/codex/login', route => route.fulfill({ json: { user_code: 'TEST-123', verification_url: 'https://auth.openai.com/codex/device', interval: 5, expires_at: Date.now() / 1000 + 900 } }));
  await page.goto('/#Settings');
  await expect(page.getByLabel('AI provider').locator('option:checked')).toHaveText('HackTricks AI (default)');
  await page.getByLabel('AI provider').selectOption('codex');
  await page.getByRole('button', { name: 'Sign in with Codex', exact: true }).click();
  await expect(page.getByText('TEST-123', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Cancel sign-in', exact: true }).click();
  await expect(page.getByText('TEST-123', { exact: true })).toHaveCount(0);
});
test('Settings distinguishes missing isolation from a disconnected Codex account', async ({ page }) => {
  await setup(page);
  await page.route('**/api/ai/codex', route => route.fulfill({ json: { connected: true, available: false, isolation_available: false } }));
  await page.route('**/api/ai/configuration', route => route.fulfill({ json: { available: false, hosted: false, selection: null, codex_connected: true, isolation_available: false } }));
  await page.goto('/#Settings');
  await expect(page.getByText('AI review is unavailable until isolated agent execution is configured.', { exact: true })).toBeVisible();
  await expect(page.getByText('Your Codex connection is unavailable. Reconnect to enable AI review.', { exact: true })).toHaveCount(0);
});
test('Top 15 Actions shows prioritized plans without duplicate verification tables', async ({ page }) => {
  await setup(page);
  await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', connector_id: 'account', status: 'completed' }] } }));
  await page.route('**/api/scans/scan/ai?*', route => route.fulfill({ json: {
    status: 'partial', auth_source: 'platform', limitations: ['Review scope detail'], coverage: { reviewed: 1, total: 2 }, review_totals: { hardening: 1, exposure: 1 }, actions: [{ severity: 'high', effort: 'low', rank: 1, title: 'Require IMDSv2', resource_ids: ['i-123'], finding_ids: ['h1'], rationale: 'Reduce credential theft', steps: ['Check workload compatibility', 'Require metadata tokens'], verification: 'HttpTokens must be required' }],
    reviews: { hardening: [{ finding_id: 'h1', verdict: 'FAIL', reason: '' }], exposure: [{ finding_id: 'e1', verdict: 'UNKNOWN', reason: 'Route association was not collected' }] }
  } }));
  await page.goto('/#AI%20Review');
  await expect(page.getByText('Require IMDSv2', { exact: true })).toBeVisible();
  await expect(page.getByRole('columnheader', { name: 'Severity', exact: true })).toBeVisible();
  await expect(page.getByRole('columnheader', { name: 'Effort', exact: true })).toBeVisible();
  await expect(page.getByRole('row').filter({ has: page.getByRole('button', { name: 'Require IMDSv2', exact: true }) })).toContainText('high');
  await expect(page.getByRole('row').filter({ has: page.getByRole('button', { name: 'Require IMDSv2', exact: true }) })).toContainText('low');
  await expect(page.getByRole('columnheader', { name: 'Order', exact: true })).toHaveCount(0);
  await expect(page.getByRole('columnheader', { name: 'Plan', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: /View plan|Review plan:/ })).toHaveCount(0);
  await expect(page.getByText(/failed findings reached a conclusion/)).toHaveCount(0);
  await expect(page.getByText('Review scope detail', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Hardening verification', exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Exposure verification', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Next reviews', exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Require IMDSv2', exact: true }).click();
  await expect(page.getByText('Check workload compatibility', { exact: true })).toBeVisible();
  await page.screenshot({ path: '/tmp/cspm-ai-review.png', fullPage: true });
});

test('network findings have a separate page below Network Map', async ({ page }) => {
  await setup(page);
  await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', connector_id: 'account', status: 'completed' }] } }));
  await page.route('**/api/scans/scan/graphs/network**', route => route.fulfill({ json: { nodes: [], edges: [] } }));
  const paragraphs = ['Application VPC 10.0.0.0/16: public edge subnets contain the NAT gateway.', 'Private application subnets host API functions; database subnets host the RDS database. The API SG is the recorded database client.'];
  const explanation = paragraphs.join('\n\n');
  const network = { status: 'completed', explanation, total: 1, limitations: ['Required traffic must be confirmed.'], findings: [{
    id: 'network-finding', check_id: 'ai.network.example', category: 'network', title: 'Restrict backend security group sources',
    provider: 'aws', service: 'network', resource_id: 'sg-backend', resource_name: 'sg-123', native_resource_id: 'sg-123', scope: '123456789012/us-east-1',
    severity: 'medium', status: 'MANUAL', frameworks: [], description: 'The backend rule admits the full VPC range.',
    rationale: 'Reduce unnecessary cross-tier access after dependency validation.',
    evidence: { source: 'ai_network_review', summary: '10.0.0.0/8 is allowed.', resource_ids: ['sg-backend'], graph_refs: [], observations: ['All protocols are allowed.'], limitations: ['Legacy evidence disclaimer.'] },
    remediation: 'Validate dependencies, then allow the frontend SG on the required application port.',
    verification: 'Check effective rules and required application connectivity.',
  }] };
  await page.route('**/api/scans/scan/ai?*', route => route.fulfill({ json: { status: 'completed', actions: [], reviews: {}, network } }));
  await page.goto('/#Network%20Map');
  await expect(page.getByRole('heading', { name: 'Network Map', exact: true })).toBeVisible();
  await page.setViewportSize({ width: 2560, height: 1440 });
  const widths = await page.locator('#main-content').evaluate(main => ({ main: main.getBoundingClientRect().width, workspace: main.parentElement!.getBoundingClientRect().width }));
  expect(Math.abs(widths.main - widths.workspace)).toBeLessThanOrEqual(1);
  await page.setViewportSize({ width: 1440, height: 1080 });

  await expect(page.getByText(explanation, { exact: true })).toHaveCount(0);
  const nav = page.getByRole('navigation', { name: 'Primary navigation' });
  const labels = await nav.getByRole('button').evaluateAll(buttons => buttons.map(button => button.getAttribute('aria-label')));
  expect(labels[labels.findIndex(label => label === 'Scans') + 1]).toBe('Top 15 Actions');
  expect(labels[labels.findIndex(label => label === 'Top 15 Actions') + 1]).toBe('Hardening & Compliance');
  expect(labels[labels.findIndex(label => label === 'Network Map') + 1]).toBe('Network Architecture');
  await expect(nav.getByRole('button', { name: 'Network Architecture', exact: true }).locator('.feature-ai')).toHaveText('✦ AI');
  await nav.getByRole('button', { name: 'Network Architecture', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Network Architecture', exact: true })).toBeVisible();
  const summary = page.locator('details.network-summary');
  await expect(summary).not.toHaveAttribute('open', '');
  await expect(summary.locator('.network-summary-preview')).toHaveText(explanation.replace(/\s+/g, ' ').slice(0, 200) + '…');
  await expect(page.getByRole('region', { name: 'Network findings table' })).toBeVisible();
  await summary.locator('summary').click();
  await expect(summary).toHaveAttribute('open', '');
  for (const paragraph of paragraphs) await expect(page.getByText(paragraph, { exact: true })).toBeVisible();
  await expect(page.getByRole('region', { name: 'Network architecture' }).locator('p')).toHaveCount(2);
  await summary.locator('summary').click();
  await expect(page.getByRole('region', { name: 'Network architecture' })).toBeHidden();
  await expect(page.getByText('Required traffic must be confirmed.', { exact: true })).toHaveCount(0);
  await expect(page.getByText(/AI suggestions|Validate workload dependencies before changing connectivity/)).toHaveCount(0);
  const networkTable = page.getByRole('region', { name: 'Network findings table' });
  await expect(networkTable.locator('tbody tr')).toHaveCount(1);
  await expect(networkTable.getByText('sg-123', { exact: true })).toHaveCount(1);
  await expect(networkTable.getByText('10.0.0.0/8 is allowed.', { exact: true })).toBeVisible();
  await networkTable.getByRole('button', { name: 'Restrict backend security group sources', exact: true }).click();
  await expect(page.getByText(network.findings[0].remediation, { exact: true })).toBeVisible();
  await expect(page.getByText(network.findings[0].verification, { exact: true })).toBeVisible();
  await expect(page.getByRole('dialog').getByText('sg-123', { exact: true })).toHaveCount(1);
  await expect(page.getByText('Legacy evidence disclaimer.', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Close inspector' }).click();
  await expect(networkTable.getByRole('button', { name: network.findings[0].title, exact: true })).toBeFocused();
  await nav.getByRole('button', { name: 'Top 15 Actions', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Top 15 Actions', exact: true }).first()).toBeVisible();
  await expect(page.getByText(explanation, { exact: true })).toHaveCount(0);
});

for (const target of ['Network Architecture', 'Top 15 Actions', 'Top 15 Recommended Actions', 'AI Review']) {
  test(`AI sections are hidden and direct links fall back without Codex: ${target}`, async ({ page }) => {
    await setup(page);
    let resultReads = 0;
    await page.route('**/api/ai/codex', route => route.fulfill({ json: { available: false, connected: false, platform_configured: false } }));
    await page.route('**/api/scans/scan/ai?*', route => { resultReads += 1; return route.fulfill({json:{}}); });
    await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', status: 'completed' }] } }));
    await page.goto('/#' + encodeURIComponent(target));
    await expect(page.getByRole('heading', { name: 'Dashboard', exact: true })).toBeVisible();
    const nav = page.getByRole('navigation', { name: 'Primary navigation' });
    await expect(nav.getByRole('button', { name: 'Network Architecture', exact: true })).toHaveCount(0);
    await expect(nav.getByRole('button', { name: 'Top 15 Actions', exact: true })).toHaveCount(0);
    expect(resultReads).toBe(0);
  });
}

test('disconnecting personal Codex hides AI navigation without a reload', async ({ page }) => {
  await setup(page);
  let connected = true;
  await page.route('**/api/ai/configuration', route => route.fulfill({ json: { available: connected, hosted: false, source: connected ? 'personal' : null, selection: { provider: 'codex', model: 'gpt-5.3-codex', thinking: 'high', credential_saved: false }, codex_connected: connected, isolation_available: true } }));
  await page.route('**/api/ai/codex', route => {
    if (route.request().method() === 'DELETE') { connected = false; return route.fulfill({ status: 204 }); }
    return route.fulfill({ json: { connected, available: connected, platform_configured: false } });
  });
  await page.goto('/#Settings');
  const nav = page.getByRole('navigation', { name: 'Primary navigation' });
  await expect(nav.getByRole('button', { name: 'Network Architecture', exact: true })).toBeVisible();
  await expect(nav.getByRole('button', { name: 'Top 15 Actions', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Disconnect Codex', exact: true }).click();
  await expect(nav.getByRole('button', { name: 'Network Architecture', exact: true })).toHaveCount(0);
  await expect(nav.getByRole('button', { name: 'Top 15 Actions', exact: true })).toHaveCount(0);
});

test('platform Codex configuration shows AI pages without personal sign-in', async ({ page }) => {
  await setup(page);
  await page.route('**/api/ai/codex', route => route.fulfill({ json: { connected: false, available: false, platform_configured: true } }));
  await page.goto('/#Network%20Findings');
  await expect(page.getByRole('heading', { name: 'Network Architecture', exact: true })).toBeVisible();
  await expect(page.getByText('Select a completed scan.', { exact: true })).toBeVisible();
  await expect(page.getByRole('navigation', { name: 'Primary navigation' }).getByRole('button', { name: 'Top 15 Actions', exact: true })).toBeVisible();
});


for (const width of [1280, 390]) {
  test(`actions use readable findings-table columns and a searchable detail drawer at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await setup(page);
    await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', connector_id: 'account', status: 'completed' }] } }));
    const actions = Array.from({ length: 15 }, (_, index) => ({
      rank: index + 1,
      title: index === 0 ? 'Narrow third-party identity access to account administration' : `Action ${index + 1}: restrict unnecessary workload access`,
      resource_ids: [`resource-${index + 1}`], finding_ids: [`finding-${index + 1}`],
      rationale: 'A trusted external identity has an administrator grant. Limit the trust to the intended deployment identity and replace broad permissions with the workload permissions actually required. '.repeat(3),
      steps: ['Confirm the required deployment identity', 'Restrict the trust policy and validate the workload'],
      verification: 'Verify the allowed deployment succeeds and other identities are denied',
    }));
    await page.route('**/api/scans/scan/ai?*', route => route.fulfill({ json: { actions: [...actions].reverse() } }));
    await page.route('**/api/scans/scan/findings/finding-1', route => route.fulfill({ json: { id: 'finding-1', title: 'Related identity finding' } }));
    await page.goto('/#Top%2015%20Recommended%20Actions');
    const table = page.getByRole('region', { name: 'Prioritized actions' });
    await expect(table.locator('tbody tr')).toHaveCount(15);
    await expect(table.locator('tbody tr').first().getByRole('button', { name: actions[0].title, exact: true })).toBeVisible();
    const geometry = await table.evaluate(element => {
      const first = element.querySelector('th')!.getBoundingClientRect();
      const row = element.querySelector('tbody tr')!.getBoundingClientRect();
      return { actionWidth: first.width, rowHeight: row.height, pageWidth: document.documentElement.scrollWidth, viewport: innerWidth };
    });
    expect(geometry.actionWidth).toBeGreaterThanOrEqual(200);
    expect(geometry.rowHeight).toBeLessThanOrEqual(110);
    expect(geometry.pageWidth).toBeLessThanOrEqual(geometry.viewport + 1);
    if (width === 1280) await page.screenshot({ path: '/tmp/cspm-top-actions-table-desktop.png', fullPage: true });
    const title = table.getByRole('button', { name: actions[0].title, exact: true });
    await title.focus();
    await title.press('Enter');
    const dialog = page.getByRole('dialog');
    await expect(dialog.getByRole('heading', { name: actions[0].title, exact: true })).toBeVisible();
    await expect(dialog.getByText(actions[0].rationale, { exact: true })).toBeVisible();
    await expect(dialog.getByText(actions[0].steps[1], { exact: true })).toBeVisible();
    await expect(dialog.getByText(actions[0].verification, { exact: true })).toBeVisible();
    await dialog.getByText('Supporting evidence', { exact: true }).click();
    await expect(dialog.getByText('resource-1', { exact: true })).toHaveCount(0);
    await expect(dialog.getByRole('button', { name: 'Related identity finding', exact: true })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    await expect(title).toBeFocused();
    await page.getByRole('textbox', { name: 'Search actions' }).fill('finding-15');
    await expect(table.locator('tbody tr')).toHaveCount(1);
    await expect(page.getByText('1 / 15 actions', { exact: true })).toBeVisible();
    await table.getByRole('button', { name: actions[14].title, exact: true }).click();
    await expect(page.getByRole('dialog').getByRole('heading', { name: actions[14].title, exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Close inspector' }).click();
    await page.getByRole('textbox', { name: 'Search actions' }).fill('unmatched-search');
    await expect(table.getByText('No actions match your search.')).toBeVisible();
    await page.getByRole('button', { name: 'Clear search', exact: true }).click();
    await expect(table.locator('tbody tr')).toHaveCount(15);
    await expect(table.getByRole('columnheader', { name: 'Order' })).toHaveCount(0);
  });
}

for (const width of [1280, 390]) {
  test(`network findings support complete-set filtering, sorting, paging and evidence drawers at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await setup(page);
    await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', connector_id: 'account', status: 'completed' }] } }));
    const findings = Array.from({ length: 60 }, (_, index) => ({
      id: `network-${index}`, check_id: `ai.network.${index}`, category: 'network', provider: 'aws', service: 'ec2',
      resource_id: `resource-${index}`, resource_name: `Database control ${index}`, native_resource_id: `sg-${index}`, scope: '123456789012/us-east-1',
      title: `Restrict database tier access ${String(index).padStart(2, '0')}`, severity: index === 59 ? 'high' : 'medium', status: index === 59 ? 'MANUAL' : 'FAIL',
      description: 'The database control accepts all application subnet sources on TCP 5432.',
      rationale: 'Subnet-wide trust admits unrelated application workloads to the database tier.', frameworks: [],
      evidence_summary: `Control sg-${index} accepts 10.0.1.0/24 on TCP 5432.`,
      evidence: { summary: `Control sg-${index} accepts 10.0.1.0/24 on TCP 5432.`, source: 'ai_network_review', resource_ids: [`resource-${index}`], graph_refs: ['edge-db'], observations: ['IpPermissions[0] admits TCP 5432 from 10.0.1.0/24.'] },
      remediation: 'Replace subnet-wide trust with the approved API security group on TCP 5432 after confirming client dependencies.',
      verification: index === 59 ? 'Unique verification: approved API clients connect while unrelated workloads have no allowed database rule.' : 'Verify approved clients retain their database rule.',
    }));
    await page.route('**/api/scans/scan/ai?*', route => {
      const url = new URL(route.request().url());
      const offset = Number(url.searchParams.get('offset'));
      const limit = Number(url.searchParams.get('limit'));
      return route.fulfill({ json: { actions: [], network: { status: 'completed', explanation: 'Application VPC separates API and database subnet tiers.', total: findings.length, findings: findings.slice(offset, offset + limit) } } });
    });
    await page.goto('/#Network%20Findings');
    const table = page.getByRole('region', { name: 'Network findings table' });
    await expect(table.locator('table')).toHaveClass(/findings-table/);
    await expect(table.locator('tbody tr')).toHaveCount(25);
    await expect(table.getByRole('columnheader')).toHaveText(['Severity', 'Finding', 'Service', 'Asset', 'Scope', 'Status']);
    await expect(table.locator('tbody tr').first()).toContainText(findings[59].title);
    await page.getByRole('button', { name: 'Next page', exact: true }).click();
    await expect(page.getByText('26–50 of 60 findings', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Next page', exact: true }).click();
    await expect(table.locator('tbody tr')).toHaveCount(10);
    await page.getByLabel('Search network findings').fill('Unique verification');
    await expect(table.locator('tbody tr')).toHaveCount(1);
    await expect(table.locator('tbody')).toContainText(findings[59].title);
    await page.getByRole('button', { name: 'Reset filters', exact: true }).click();
    await page.getByLabel('Network finding status').selectOption('UNKNOWN,MANUAL');
    await expect(table.locator('tbody tr')).toHaveCount(1);
    await page.getByLabel('Network finding severity').selectOption('low');
    await expect(table.getByText('No network findings match your filters.', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Reset filters', exact: true }).click();
    await table.getByRole('columnheader', { name: 'Finding', exact: true }).getByRole('button').click();
    await expect(table.locator('tbody tr').first()).toContainText(findings[0].title);
    const title = table.getByRole('button', { name: findings[0].title, exact: true });
    await title.click();
    const drawer = page.getByRole('dialog');
    for (const text of [findings[0].resource_name, findings[0].native_resource_id, findings[0].description, findings[0].rationale, findings[0].evidence.observations[0], findings[0].remediation, findings[0].verification])
      await expect(drawer.getByText(text, { exact: true })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(drawer).toHaveCount(0);
    await expect(title).toBeFocused();
    const geometry = await table.evaluate(element => ({ pageWidth: document.documentElement.scrollWidth, viewport: innerWidth, width: element.clientWidth, content: element.scrollWidth, titleWidth: element.querySelectorAll("th")[1].getBoundingClientRect().width }));
    expect(geometry.pageWidth).toBeLessThanOrEqual(geometry.viewport + 1);
    expect(geometry.titleWidth).toBeGreaterThanOrEqual(260);
    if (width === 390) expect(geometry.content).toBeGreaterThan(geometry.width);
    await page.screenshot({ path: `/tmp/cspm-network-findings-table-${width}.png`, fullPage: true });
  });
}


test('network architecture expands above the findings table with clear network and tier sections', async ({ page }) => {
  await setup(page);
  await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', status: 'completed' }] } }));
  const explanation = '### Application VPC\n\nus-east-1 · 10.0.0.0/16. Hosts the API and its private database.\n\n#### Public edge\n\n- 10.0.101.0/24 hosts the NAT gateway; its route table sends internet traffic to the IGW.\n\n#### Private application tier\n\n- 10.0.1.0/24 hosts the API. Outbound traffic uses the NAT gateway.\n\n#### Database boundary\n\n- `10.0.21.0/24` hosts the **database**. Its SG permits TCP 5432 from the application SG.\n\n### Default networks\n\n- Regional default VPCs use 172.31.0.0/16 and IGW routes.\n- No attached workloads were collected.';
  await page.route('**/api/scans/scan/ai?*', route => route.fulfill({ json: { actions: [], network: { status: 'completed', explanation, findings: [] } } }));
  await page.goto('/#Network%20Findings');
  await page.locator('details.network-summary > summary').click();
  const architecture = page.getByRole('region', { name: 'Network architecture', exact: true });
  for (const name of ['Application VPC', 'Public edge', 'Private application tier', 'Database boundary', 'Default networks'])
    await expect(architecture.getByRole('heading', { name, exact: true })).toBeVisible();
  await expect(architecture.locator('li')).toHaveCount(5);
  await expect(architecture.locator('code')).toHaveText('10.0.21.0/24');
  await expect(architecture.locator('strong')).toHaveText('database');
  const table = page.getByRole('region', { name: 'Network findings table' });
  expect(await table.evaluate(element => Boolean(element.compareDocumentPosition(document.querySelector('section[aria-label="Network architecture"]')!) & Node.DOCUMENT_POSITION_PRECEDING))).toBe(true);
});

test('older dense architecture paragraphs become readable blocks without losing content', async ({ page }) => {
  await setup(page);
  await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', status: 'completed' }] } }));
  const sentences = ['The public edge tier hosts the NAT gateway.', 'Its route points to the internet gateway.', 'The private application tier hosts the API.', 'Outbound traffic uses NAT.', 'The database tier holds the database.', 'Only the approved API SG is allowed on TCP 5432.'];
  await page.route('**/api/scans/scan/ai?*', route => route.fulfill({ json: { actions: [], network: { status: 'completed', explanation: 'Application VPC — ' + sentences.join(' '), findings: [] } } }));
  await page.goto('/#Network%20Findings');
  await page.locator('details.network-summary > summary').click();
  const architecture = page.getByRole('region', { name: 'Network architecture', exact: true });
  await expect(architecture.getByRole('heading', { name: 'Application VPC', exact: true })).toBeVisible();
  await expect(architecture.locator('p')).toHaveCount(3);
  for (const name of ['Public edge tier', 'Private application tier', 'Database tier']) await expect(architecture.getByRole('heading', { name, exact: true })).toBeVisible();
  expect((await architecture.locator('p').allTextContents()).join(' ')).toBe(sentences.join(' '));
});

for (const closeWith of ['button', 'Escape']) {
  test(`supporting finding titles open details above the action plan and close with ${closeWith}`, async ({ page }) => {
    await setup(page);
    await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', connector_id: 'account', status: 'completed' }] } }));
    await page.route('**/api/scans/scan/ai?*', route => route.fulfill({ json: { actions: [{
      rank: 1, title: 'Require metadata tokens', resource_ids: ['legacy-resource-hidden'], finding_ids: ['h1'],
      rationale: 'Reduce credential theft.', steps: ['Require tokens after compatibility checks.'], verification: 'Read HttpTokens.'
    }] } }));
    await page.route('**/api/scans/scan/findings/h1', route => route.fulfill({ json: {
      id: 'h1', title: 'Instance requires IMDSv2 tokens', check_id: 'aws.ec2.imdsv2', category: 'hardening',
      severity: 'medium', status: 'FAIL', service: 'ec2', scope: 'test-account/us-east-1', provider: 'aws', resource_id: 'instance-1',
      description: 'Checks instance metadata token requirements.', evidence_summary: 'HttpTokens is optional.',
      evidence: {}, remediation: 'Require IMDSv2.', frameworks: [],
    } }));
    await page.goto('/#Top%2015%20Actions');
    await page.getByRole('button', { name: 'Require metadata tokens', exact: true }).click();
    const plan = page.locator('dialog.action-inspector');
    await plan.getByText('Supporting evidence', { exact: true }).click();
    await expect(plan.getByRole('heading', { name: 'Resources', exact: true })).toHaveCount(0);
    await expect(plan.getByText('legacy-resource-hidden', { exact: true })).toHaveCount(0);
    const related = plan.getByRole('button', { name: 'Instance requires IMDSv2 tokens', exact: true });
    await expect(related).toHaveCSS('text-decoration-line', 'underline');
    await related.click();
    const detail = page.locator('dialog.finding-inspector');
    await expect(detail.getByText(/HttpTokens is optional\./)).toBeVisible();
    await expect(plan).toHaveJSProperty('open', true);
    if (closeWith === 'Escape') await page.keyboard.press('Escape');
    else await detail.getByRole('button', { name: 'Close inspector', exact: true }).click();
    await expect(detail).toHaveCount(0);
    await expect(plan).toBeVisible();
    await expect(plan.getByText('Require tokens after compatibility checks.', { exact: true })).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'Primary navigation' }).getByRole('button', { name: 'Top 15 Actions', exact: true }).locator('.feature-ai')).toHaveText('✦ AI');
    await expect(related).toBeFocused();
    await expect(plan.locator('details.action-references')).toHaveAttribute('open', '');
  });
}

test('supporting evidence also opens AI network findings by title', async ({ page }) => {
  await setup(page);
  await page.route('**/api/scans', route => route.fulfill({ json: { items: [{ id: 'scan', connector_id: 'account', status: 'completed' }] } }));
  await page.route('**/api/scans/scan/ai?*', route => route.fulfill({ json: {
    actions: [{ rank: 1, title: 'Separate database clients', finding_ids: ['network-1'], rationale: 'Restrict tier access.', steps: ['Review client groups.'], verification: 'Check approved paths.' }],
    network: { status: 'completed', explanation: '', findings: [{
      id: 'network-1', title: 'Database group trusts the entire application subnet', check_id: 'ai.network.segmentation', category: 'network',
      severity: 'medium', status: 'MANUAL', service: 'ec2', provider: 'aws', scope: 'test-account/us-east-1', resource_id: 'sg-db',
      description: 'Review cross-tier trust.', evidence_summary: 'Database access allows the whole application subnet.', evidence: {}, remediation: 'Use approved client groups.', frameworks: [],
    }] },
  } }));
  let nativeRequests = 0;
  await page.route('**/api/scans/scan/findings/network-1', route => { nativeRequests++; return route.fulfill({ status: 404, json: {} }); });
  await page.goto('/#Top%2015%20Actions');
  await page.getByRole('button', { name: 'Separate database clients', exact: true }).click();
  await page.locator('dialog.action-inspector').getByText('Supporting evidence', { exact: true }).click();
  await page.getByRole('button', { name: 'Database group trusts the entire application subnet', exact: true }).click();
  await expect(page.locator('dialog.finding-inspector').getByText('Database access allows the whole application subnet.', { exact: true })).toBeVisible();
  await page.locator('dialog.finding-inspector').getByRole('button', { name: 'Close inspector', exact: true }).click();
  await expect(page.locator('dialog.action-inspector')).toBeVisible();
  expect(nativeRequests).toBe(0);
});
