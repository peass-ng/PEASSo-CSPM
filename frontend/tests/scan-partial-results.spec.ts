import { test, expect } from '@playwright/test';

for (const status of ['collecting', 'timed_out']) {
  test(`saved findings remain selectable while scan is ${status}`, async ({ page }) => {
    await page.route('**/api/**', async route => {
      const path = new URL(route.request().url()).pathname;
      let json: unknown = { items: [] };
      if (path.endsWith('/me')) json = { tenant_id: 'partial-test' };
      if (path.endsWith('/health')) json = { status: 'ok' };
      if (path.endsWith('/scans')) json = { items: [{ id: 'partial-scan', connector_id: 'c', status,
        result_available: true, created_at: '2026-10-22T10:00:00Z', categories: ['hardening'] }] };
      if (path.endsWith('/summary')) json = { provider: 'aws', publication: { state: 'partial', sequence: 1 },
        stats: { finding_count: 1, by_status: { FAIL: 1 }, by_severity: { high: 1 }, by_category: { hardening: 1 } } };
      await route.fulfill({ json });
    });
    await page.goto('/#Scans');
    await expect(page.getByRole('button', { name: 'Open partial results', exact: true })).toBeVisible();
    await expect(page.getByText(status === 'collecting' ? 'Assessment in progress' : 'Saved partial results', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Open partial results', exact: true }).click();
    await expect(page).toHaveURL(/Hardening/);
    await expect(page.getByText('Assessment in progress', { exact: true })).toHaveCount(0);
    await expect(page.getByText('Saved partial results', { exact: true })).toHaveCount(0);
    await expect(page.getByText('Completed evidence and findings are available. Coverage is still incomplete.')).toHaveCount(0);
    // A running scan names its state on every results page; a stopped one does not.
    if (status === 'collecting') await expect(page.locator('.scan-running-banner')).toContainText('Scan still running');
    else await expect(page.locator('.scan-running-banner')).toHaveCount(0);
  });
}
