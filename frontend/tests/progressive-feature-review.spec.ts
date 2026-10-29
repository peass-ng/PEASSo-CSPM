import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';

// Every native section is reviewable from the latest durable publication while
// the scan is still running; only the AI stages may report "in progress".
const scanId = 'demo-scan';
const digest = 'sha256:' + 'b'.repeat(64);
const leak = { id: 'leak-1', provider: 'aws', scope: '111122223333/us-east-1', category: 'exposure', status: 'FAIL',
  severity: 'high', service: 'lambda', resource_id: 'arn:aws:lambda:us-east-1:111122223333:function:demo',
  check_id: 'aws.lambda.secret_indicators', finding_type: 'detected_leaks', title: 'Saved leaked credential finding',
  frameworks: [], evidence: {} };
const imageRows = [{ id: 'img-1', provider: 'aws', scope: '111122223333/us-east-1',
  image_reference: `registry.example/app@${digest}`, image_digest: digest, severity: 'HIGH',
  vulnerability_id: 'CVE-2026-4242', package: 'openssl', installed_version: '1.0', fixed_versions: ['1.1'],
  affected_assets: [{ resource_id: 'task-1', kind: 'ecs_task' }], coverage: 'COMPLETE' }];

type State = { status: string; phase: string; state: 'partial' | 'final'; sequence: number; ai: unknown };

// Reuse the app's own fixture responses (served as an ES module by the dev
// server) from a separate unrouted page, so every tab gets realistic shapes.
async function fixtureSource(page: Page) {
  const helper = await page.context().newPage();
  await helper.goto('/src/fixtures.ts');
  return async (path: string) => helper.evaluate(async target => {
    const module = await import('/src/fixtures.ts');
    return module.demoRequest(target, {});
  }, path);
}

async function mock(page: Page, current: State, counts: Record<string, number>) {
  const demoRequest = await fixtureSource(page);
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    const path = url.pathname.replace(/^\/api/, '');
    counts[path] = (counts[path] || 0) + 1;
    let json: unknown;
    if (path === '/me') json = { tenant_id: 'progressive-test' };
    else if (path === '/ai/codex') json = { available: true };
    else if (path === '/scans') json = { items: [{ id: scanId, connector_id: 'demo-connector', status: current.status,
      result_available: true, ai_enabled: true, created_at: '2026-10-29T10:00:00Z',
      categories: ['hardening', 'exposure', 'least_privilege', 'network', 'iam_graph', 'privesc'] }] };
    else if (path.endsWith('/summary')) json = { ...(await demoRequest('/scans/demo-scan/summary') as object),
      publication: { state: current.state, phase: current.phase, sequence: current.sequence } };
    else if (path.endsWith('/ai')) json = current.ai;
    else if (path.endsWith('/image-findings')) json = { rows: imageRows, total: 1, vulnerability_count: 1, image_count: 1,
      offset: 0, next_offset: null, coverage: 'COMPLETE', complete: true, observations: 1, truncated: false,
      invalid_observations: 0, invalid_vulnerabilities: 0 };
    else if (path.endsWith('/findings') && url.searchParams.get('finding_type') === 'detected_leaks')
      json = { items: [leak], total: 1, offset: 0, limit: 500, next_offset: null, status_filter_total: 1,
        status_filter_counts: { FAIL: 1 }, facets: { services: ['lambda'], statuses: ['FAIL'], frameworks: [] } };
    else {
      try { json = await demoRequest(path + url.search); } catch { json = { items: [], total: 0, next_offset: null }; }
    }
    await route.fulfill({ json });
  });
}

const pendingAi = { status: 'in_progress', actions: [], reviews: {}, pending_stages: ['network', 'priorities'] };

async function open(page: Page, name: string) {
  await page.getByRole('navigation', { name: 'Primary navigation' }).getByRole('button', { name, exact: true }).click();
}

// Findings are grouped by service; open the group and expect the saved row.
async function expectFinding(page: Page, title: string) {
  await page.locator('.service-group-button').first().click();
  await expect(page.locator('.finding-title', { hasText: title }).first()).toBeVisible();
}

test('every native tab renders saved results while AI analysis is still running', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', error => errors.push(error.message));
  await mock(page, { status: 'analyzing', phase: 'analyzing', state: 'partial', sequence: 7, ai: pendingAi }, {});
  await page.goto('/#Dashboard');
  const banner = page.locator('.scan-running-banner');
  await expect(banner).toContainText('AI analysis in progress');
  await expect(page.locator('.metric').filter({ hasText: 'Observed assets' })).toBeVisible();

  await open(page, 'Hardening & Compliance');
  await expectFinding(page, 'Storage encryption requires review');
  await expect(banner).toContainText('Native results are saved and ready to review.');

  await open(page, 'Exposure');
  await expectFinding(page, 'Broad network ingress observed');

  await open(page, 'Leaks');
  await expectFinding(page, 'Saved leaked credential finding');

  await open(page, 'Images CVEs');
  await expect(page.getByRole('button', { name: 'CVE-2026-4242', exact: true })).toBeVisible();

  await open(page, 'Least Privilege');
  await expect(page.getByText('demo-app-role').first()).toBeVisible();

  await open(page, 'Network Map');
  await expect(page.locator('.network-node').first()).toBeVisible({ timeout: 30000 });

  await open(page, 'Privilege Escalation Map');
  await expect(page.locator('.pe-canvas .react-flow__node').first()).toBeVisible({ timeout: 30000 });

  // AI pages state that the model is still working instead of "not requested".
  await open(page, 'Top 15 Actions');
  await expect(page.getByRole('status').getByRole('heading', { name: 'AI analysis in progress' })).toBeVisible();
  await expect(page.getByText('No recommended actions are available for this scan.')).toHaveCount(0);
  await expect(page.getByLabel('Top 15 Actions total', { exact: true })).toHaveText('—');
  await open(page, 'Network Architecture');
  await expect(page.getByRole('status').getByRole('heading', { name: 'AI analysis in progress' })).toBeVisible();
  await expect(page.getByText(/Run a scan with AI enabled/)).toHaveCount(0);
  expect(errors).toEqual([]);
});

test('collection-phase results show the running indicator, not the AI one', async ({ page }) => {
  await mock(page, { status: 'collecting', phase: 'collecting', state: 'partial', sequence: 3, ai: pendingAi }, {});
  await page.goto('/#Hardening%20%26%20Compliance');
  await expectFinding(page, 'Storage encryption requires review');
  await expect(page.locator('.scan-running-banner')).toContainText('Scan still running');
  await expect(page.locator('.scan-running-banner')).not.toContainText('AI analysis');
});

test('completion refreshes the final report and removes the running indicator', async ({ page }) => {
  const current: State = { status: 'analyzing', phase: 'analyzing', state: 'partial', sequence: 7, ai: pendingAi };
  const counts: Record<string, number> = {};
  await mock(page, current, counts);
  await page.goto('/#Top%2015%20Actions');
  await expect(page.getByRole('status').getByRole('heading', { name: 'AI analysis in progress' })).toBeVisible();
  // The final report is visible only with the completed status, and the
  // partial summary poll stops at that same moment.
  current.status = 'completed';
  current.state = 'final';
  current.phase = 'completed';
  current.ai = { status: 'completed', reviews: {}, actions: [{ rank: 1, title: 'Final prioritized action', finding_ids: [],
    rationale: 'Reduces exposure.', steps: ['Apply the change.'], verification: 'Check the setting.' }] };
  await expect(page.getByRole('button', { name: 'Final prioritized action' })).toBeVisible({ timeout: 15000 });
  await expect(page.locator('.scan-running-banner')).toHaveCount(0);
  await expect(page.getByLabel('Top 15 Actions total', { exact: true })).toHaveText('1');
  // A stable final publication causes no refetch loop.
  const stable = counts['/scans/demo-scan/summary'] || 0;
  await page.waitForTimeout(1000);
  expect((counts['/scans/demo-scan/summary'] || 0) - stable).toBeLessThanOrEqual(1);
});
