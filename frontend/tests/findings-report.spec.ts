import { expect, test } from '@playwright/test';

const issue = (n: number) => ({ id: 'r' + n, title: `Report issue ${n}`, kind: n === 0 ? 'leaks' : 'vulnerability',
  severity: n === 0 ? 'high' : 'medium', status: 'confirmed', description: 'Observed restricted-scope configuration.',
  impact: 'Conditional access to sensitive data.', recommendation: 'Restrict the affected policy.',
  verification: 'Read back the expected policy.', references: [{ domain: 'findings', id: 'f' + n }] });

async function setup(page: import('@playwright/test').Page, status = 'completed') {
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    let json: unknown = { items: [] };
    if (path.endsWith('/me')) json = { tenant_id: 'test' };
    if (path.endsWith('/ai/codex')) json = { available: true };
    if (path.endsWith('/scans')) json = { items: [{ id: 's', result_available: true, status: status === 'in_progress' ? 'analyzing' : 'completed' }] };
    if (path.endsWith('/summary')) json = { stats: {} };
    if (path.endsWith('/ai')) json = { actions: [], findings_report: { status, total: status === 'partial' ? 2 : 26 } };
    if (path.endsWith('/findings-report')) {
      const offset = Number(url.searchParams.get('offset') || 0);
      const search = url.searchParams.get('search') || '';
      const allRows = status === 'partial' ? [issue(0), { ...issue(1), kind: 'image_cves' }] : Array.from({ length: 26 }, (_, i) => issue(i));
      const rows = allRows.filter(row => row.title.includes(search));
      const available = ['completed', 'partial'].includes(status);
      json = { status, summary: status === 'completed' ? 'Compiled account security issues.' : undefined,
        total: available ? rows.length : 0, issues: available ? rows.slice(offset, offset + 25) : [],
        exclusions: [], exclusion_count: 0, covered_count: 26, source_count: 26, limitations: ['Runtime exploitability was not verified.'] };
    }
    if (/\/findings\/f\d+$/.test(path)) json = { id: path.split('/').pop(), title: 'Original scan evidence', status: 'FAIL',
      severity: 'high', category: 'hardening', check_id: 'test', provider: 'aws', scope: '123456789012/us-east-1',
      resource_id: 'resource', service: 'iam', evidence: { observed: 'Captured policy.' }, remediation: 'Restrict policy.' };
    await route.fulfill({ json });
  });
}

test('compiled report pages, searches all issues and opens source evidence', async ({ page }) => {
  await setup(page); await page.goto('/#Findings%20Report');
  await expect(page.getByLabel('Findings Report total', { exact: true })).toHaveText('26');
  await expect(page.locator('.nav-group').filter({ hasText: 'SECURITY INSIGHTS' })).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'Report issue 0', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Report issue 25', exact: true })).toBeVisible();
  await page.getByLabel('Search report issues').fill('Report issue 25');
  await expect(page.locator('.findings-table tbody tr')).toHaveCount(1);
  await page.getByRole('button', { name: 'Report issue 25', exact: true }).click();
  await expect(page.getByRole('dialog').getByText('Conditional access to sensitive data.')).toBeVisible();
  await page.getByRole('button', { name: 'Check result f25', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Original scan evidence', exact: true })).toBeVisible();
});

test('unfinished reports explain that compilation follows the scan analyses', async ({ page }) => {
  await setup(page, 'in_progress'); await page.goto('/#Findings%20Report');
  await expect(page.getByText('The findings report will be compiled after the scan analyses finish.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Report issue 0', exact: true })).toHaveCount(0);
});

test('older scans explain how to get a report', async ({ page }) => {
  await setup(page, 'not_available'); await page.goto('/#Findings%20Report');
  await expect(page.getByText('This scan has no compiled report. Run a new scan with AI enabled.')).toBeVisible();
});


test('pre-generated leaks and CVE findings remain visible after agent failure', async ({ page }) => {
  await setup(page, 'partial'); await page.goto('/#Findings%20Report');
  await expect(page.getByLabel('Findings Report total', { exact: true })).toHaveText('2');
  await expect(page.getByText('Pre-generated findings are available. Compilation of remaining issues is incomplete.')).toBeVisible();
  await expect(page.locator('.findings-table tbody tr')).toHaveCount(2);
  await expect(page.locator('.findings-table').getByText('Leaks', { exact: true })).toBeVisible();
  await expect(page.locator('.findings-table').getByText('Image CVEs', { exact: true })).toBeVisible();
});


test('regeneration clears existing issues and displays a replacement report', async ({ page }) => {
  await setup(page);
  let stage = 'old';
  await page.route('**/api/scans/s/findings-report?**', async route => {
    const row = { ...issue(0), id: stage === 'old' ? 'old-generation' : 'new-generation', title: stage === 'old' ? 'Original issue' : 'Replacement issue' };
    await route.fulfill({ json: { status: stage === 'running' ? 'in_progress' : 'completed',
      generation: stage, can_launch: stage !== 'running', issues: stage === 'running' ? [] : [row],
      total: stage === 'running' ? 0 : 1, exclusions: [], exclusion_count: 0 } });
  });
  await page.route('**/api/scans/s/findings-report', async route => {
    expect(route.request().method()).toBe('POST'); stage = 'running';
    await route.fulfill({ status: 202, json: { status: 'queued', generation: 'new-generation' } });
  });
  await page.goto('/#Findings%20Report');
  await expect(page.getByRole('button', { name: 'Original issue', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Regenerate report', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Original issue', exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Generating report…', exact: true })).toBeDisabled();
  stage = 'new';
  await expect(page.getByRole('button', { name: 'Replacement issue', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Regenerate report', exact: true })).toBeEnabled();
});
