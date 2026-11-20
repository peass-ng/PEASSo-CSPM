import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
const a = 'a'.repeat(32), b = 'b'.repeat(32), combined = 'c'.repeat(32);
const sources = [{ scan_id: a, connector_name: 'Production', provider: 'aws', created_at: '2026-11-19T10:00:00Z', version: '1'.repeat(64) },
  { scan_id: b, connector_name: 'Workloads', provider: 'k8s', created_at: '2026-11-20T10:00:00Z', version: '2'.repeat(64) }];
const original = { id: 'same-id', title: 'Source encryption issue', kind: 'vulnerability', severity: 'medium', status: 'confirmed',
  description: 'Preserved source configuration.', impact: 'Source data exposure.', recommendation: 'Enable disk encryption.', verification: 'Inspect disk settings.',
  references: [{ domain: 'findings', id: 'native-check' }] };
const merged = { ...original, id: 'merged', title: 'Insufficient encryption protections', description: 'Production disk prod-1 and Workloads volume workload-2 require encryption.',
  references: sources.map(source => ({ report_id: source.scan_id, issue_id: 'same-id' })) };

async function setup(page: Page) {
  let phase = 'none';
  const posts: Record<string, unknown>[] = [];
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url()), path = url.pathname;
    let response: unknown = { items: [] };
    if (path === '/api/me') response = { tenant_id: 'fixture', auth_kind: 'user' };
    if (path === '/api/health') response = { auth_mode: 'local' };
    if (path === '/api/ai/codex') response = { available: true };
    if (path === '/api/scans') response = { items: sources.map(source => ({ id: source.scan_id, connector_id: source.scan_id, status: 'completed', result_available: true, created_at: source.created_at })) };
    if (path === '/api/connectors') response = { items: sources.map(source => ({ id: source.scan_id, name: source.connector_name, provider: source.provider })) };
    if (path.endsWith('/summary')) response = { stats: {} };
    if (path.endsWith('/ai')) response = { actions: [], findings_report: { total: 1, status: 'completed' } };
    if (path.endsWith('/findings-report')) response = { status: 'completed', issues: [original], total: 1, can_launch: true };
    if (path === '/api/combined-reports/candidates') response = { items: sources.map(source => ({ ...source, status: 'completed', issue_count: 1 })) };
    const entry = { id: combined, name: 'All environments', sources, created: 1795170000, status: phase === 'ready' ? 'completed' : 'running' };
    if (path === '/api/combined-reports') {
      if (route.request().method() === 'POST') { posts.push(route.request().postDataJSON()); phase = 'running'; return route.fulfill({ status: 202, json: entry }); }
      response = { items: phase === 'none' ? [] : [entry, { ...entry, id: 'd'.repeat(32), name: 'Another combined report' }] };
    }
    if (path === '/api/combined-reports/'+combined) response = { ...entry, issues: phase === 'ready' ? [merged] : [], total: phase === 'ready' ? 1 : 0 };
    if (path.endsWith('/source-issue')) response = { source: sources.find(source => source.scan_id === url.searchParams.get('report_id')), issue: original };
    await route.fulfill({ json: response });
  });
  return { posts, complete: () => { phase = 'ready'; } };
}

test('combines selected report versions, displays merged assets and preserves each source entry', async ({ page }) => {
  const fixture = await setup(page);
  await page.goto('/#Findings%20Report');
  await page.getByRole('button', { name: 'Combine different reports', exact: true }).click();
  await expect(page.getByRole('dialog')).toBeVisible();
  await expect(page.getByRole('checkbox', { name: /^Select Production/ })).toBeChecked();
  await page.getByLabel('Combined report name').fill('All environments');
  await page.getByRole('checkbox', { name: /^Select Workloads/ }).check();
  await page.getByLabel('Search assessment reports').fill('Workloads');
  await page.getByRole('button', { name: 'Combine 2 reports', exact: true }).click();
  await expect(page.getByRole('status')).toHaveText('Combining the selected report issues…');
  expect(fixture.posts).toEqual([{ name: 'All environments', reports: sources.map(source => ({ scan_id: source.scan_id, version: source.version })) }]);
  fixture.complete();
  await page.getByRole('button', { name: 'Insufficient encryption protections', exact: true }).click();
  await expect(page.getByRole('dialog').getByText(merged.description, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Workloads · same-id', exact: true }).click();
  await expect(page.getByText('Preserved source configuration.', { exact: true })).toBeVisible();
  await expect(page.getByText('This issue is preserved from the report version used for this combination.')).toBeVisible();
  await page.getByRole('button', { name: 'Open assessment report', exact: true }).click();
  await expect(page.getByRole('tab', { name: 'Assessment report', exact: true })).toHaveAttribute('aria-selected', 'true');
  for (const scan of [b, a]) {
    await page.getByLabel('Selected assessment', { exact: true }).selectOption(scan);
    await page.getByRole('tab', { name: 'Combined reports', exact: true }).click();
    await expect(page.getByRole('button', { name: 'All environments', exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Another combined report', exact: true })).toBeVisible();
  }
});

test('navigation descriptions cover icon, text, count and keyboard focus', async ({ page }) => {
  await setup(page); await page.goto('/#Findings%20Report');
  const nav = page.getByRole('navigation', { name: 'Primary navigation' });
  const report = nav.getByRole('button', { name: 'Findings Report', exact: true });
  await report.locator('svg').hover();
  await expect(page.getByRole('tooltip')).toHaveText('Review and combine security reports from completed assessments.');
  await report.locator('.nav-label').hover(); await expect(page.getByRole('tooltip')).toBeVisible();
  await report.locator('.nav-count').hover(); await expect(page.getByRole('tooltip')).toBeVisible();
  const dashboard = nav.getByRole('button', { name: 'Dashboard', exact: true });
  await dashboard.focus();
  await expect(page.getByRole('tooltip')).toHaveText('See assessment posture, connected environments and recent scans.');
  await dashboard.press('Escape'); await expect(page.getByRole('tooltip')).toHaveCount(0);
  await nav.getByText('SECURITY INSIGHTS', { exact: true }).hover();
  await expect(page.getByRole('tooltip')).toHaveText('Review security findings, identity risks and network architecture.');
  for (const name of ['Exposure', 'Least Privilege', 'Settings']) {
    await nav.getByRole('button', { name, exact: true }).hover();
    await expect(page.getByRole('tooltip')).toBeVisible();
  }
});
