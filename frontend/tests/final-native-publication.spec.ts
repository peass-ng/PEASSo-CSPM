import { test, expect } from '@playwright/test';

test('final native publication refreshes cached findings while the scan is still analyzing', async ({ page }) => {
  let final = false;
  let finalFindingsRequests = 0;
  let summaryRequests = 0;
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname;
    let json: unknown = { items: [] };
    if (path.endsWith('/me')) json = { tenant_id: 'native-final-test' };
    if (path.endsWith('/health')) json = { status: 'ok' };
    if (path.endsWith('/scans')) json = { items: [{ id: 'native-final-scan', status: 'analyzing',
      result_available: true, created_at: '2026-10-24T10:00:00Z', categories: ['hardening'] }] };
    if (path.endsWith('/summary')) {
      summaryRequests++;
      json = { provider: 'aws', publication: { state: final ? 'final' : 'partial', sequence: final ? 2 : 1 },
        stats: { finding_count: 1, by_status: { FAIL: 1 }, by_category: { hardening: 1 } } };
    }
    if (path.endsWith('/findings')) {
      if (final) finalFindingsRequests++;
      json = { items: [{ id: 'native-finding', category: 'hardening', provider: 'aws', scope: '111111111111/us-east-1',
        severity: 'high', status: 'FAIL', service: 's3', resource_id: 'native-resource', check_id: 'native.fixture',
        title: final ? 'Final native finding' : 'Earlier native finding', frameworks: [] }], total: 1, next_offset: null };
    }
    await route.fulfill({ json });
  });
  await page.goto('/#Hardening%20%26%20Compliance');
  await page.getByRole('combobox', { name: 'Group findings' }).selectOption('check_id');
  await expect(page.locator('.finding-title')).toHaveText([/Earlier native finding/]);
  final = true;
  await expect(page.locator('.finding-title')).toHaveText([/Final native finding/]);
  expect(finalFindingsRequests).toBeGreaterThan(0);
  // Stable final metadata triggers no refetch feedback loop.
  const stable = summaryRequests;
  await page.waitForTimeout(500);
  expect(summaryRequests - stable).toBeLessThanOrEqual(1);
});
