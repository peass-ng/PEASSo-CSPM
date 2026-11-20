import { expect, test } from '@playwright/test';

const issue = (n: number) => ({ id: 'r' + n, title: `Report issue ${n}`, kind: n === 0 ? 'leaks' : 'vulnerability',
  severity: n === 0 ? 'high' : 'medium', status: 'confirmed', description: 'Observed restricted-scope configuration.',
  impact: 'Conditional access to sensitive data.', recommendation: 'Restrict the affected policy.',
  permission_recommendations: n === 25 ? Array.from({ length: 6 }, (_, row) => ({
    principal: 'workload-identity', scope: 'production', value: `iam:TrackedAction${row}`, policy: 'workload-policy',
    source: 'AWS IAM action report', usage_window_end: '2026-11-18', confidence: 'tracked_without_observed_use',
  })) : [],
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
        covered_count: 26, source_count: 26, limitations: ['Runtime exploitability was not verified.'], exclusions: [{ reference: { domain: 'findings', id: 'excluded' }, reason: 'An excluded observation.' }], exclusion_count: 1 };
    }
    if (path.endsWith('/findings-report/evidence')) json = { items: Object.fromEntries(url.searchParams.getAll('finding_id').map(id => [id, `arn:cloud:identity::123456789012:role/${id}`])) };
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
  await expect(page.getByText('Runtime exploitability was not verified.')).toHaveCount(0);
  await expect(page.getByText('Evidence coverage', { exact: true })).toHaveCount(0);
  await expect(page.getByText('An excluded observation.')).toHaveCount(0);
  await expect(page.getByText('Compiled account security issues.')).toHaveCount(0);
  await page.getByRole('button', { name: 'Next page', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Report issue 25', exact: true })).toBeVisible();
  await page.getByLabel('Search report issues').fill('Report issue 25');
  await expect(page.locator('.findings-table tbody tr')).toHaveCount(1);
  await page.getByRole('button', { name: 'Report issue 25', exact: true }).click();
  await expect(page.getByRole('dialog').getByText('Conditional access to sensitive data.')).toBeVisible();
  const access = page.getByRole('dialog').getByRole('table');
  await expect(access.getByText('iam:TrackedAction0', { exact: true })).toBeVisible();
  await expect(access.getByText('iam:TrackedAction5', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Show 1 more', exact: true }).click();
  await expect(access.getByText('iam:TrackedAction5', { exact: true })).toBeVisible();
  await expect(access.getByText('Report completed 2026-11-18').first()).toBeVisible();
  await page.getByRole('button', { name: 'arn:cloud:identity::123456789012:role/f25', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Original scan evidence', exact: true })).toBeVisible();
});

test('running reports show generation only in the toolbar', async ({ page }) => {
  await setup(page, 'in_progress'); await page.goto('/#Findings%20Report');
  await expect(page.locator('.report-tabs').getByRole('button', { name: 'Generating report…', exact: true })).toBeDisabled();
  await expect(page.getByText('The findings report will be compiled after the scan analyses finish.')).toHaveCount(0);
  await expect(page.getByText('Generating a report replaces all current report issues.')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Report issue 0', exact: true })).toHaveCount(0);
});

test('older scans offer generation from the toolbar', async ({ page }) => {
  await setup(page, 'not_available'); await page.goto('/#Findings%20Report');
  await expect(page.locator('.report-tabs').getByRole('button', { name: 'Generate report', exact: true })).toBeEnabled();
});


test('pre-generated leaks and CVE findings remain visible after agent failure', async ({ page }) => {
  await setup(page, 'partial'); await page.goto('/#Findings%20Report');
  await expect(page.getByLabel('Findings Report total', { exact: true })).toHaveText('2');
  await expect(page.locator('.findings-table tbody tr')).toHaveCount(2);
  await expect(page.locator('.findings-table').getByText('Leaks', { exact: true })).toBeVisible();
  await expect(page.locator('.findings-table').getByText('Image CVEs', { exact: true })).toBeVisible();
});


test('regeneration preserves published issues until the revised report is ready', async ({ page }) => {
  await setup(page);
  let stage = 'old';
  let posts = 0;
  await page.route('**/api/scans/s/findings-report?**', async route => {
    const row = { ...issue(0), id: stage !== 'new' ? 'old-generation' : 'new-generation', title: stage !== 'new' ? 'Original issue' : 'Replacement issue' };
    await route.fulfill({ json: { status: 'completed', run_status: stage === 'running' ? 'running' : 'completed',
      generation: stage, can_launch: stage !== 'running', issues: [row],
      total: 1, exclusions: [], exclusion_count: 0 } });
  });
  await page.route('**/api/scans/s/findings-report', async route => {
    expect(route.request().method()).toBe('POST'); posts++; stage = 'running';
    await route.fulfill({ status: 202, json: { status: 'queued', generation: 'new-generation' } });
  });
  await page.goto('/#Findings%20Report');
  await expect(page.getByRole('button', { name: 'Original issue', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Regenerate report', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('current report stays available');
  expect(posts).toBe(0);
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  expect(posts).toBe(0);
  await expect(page.getByRole('button', { name: 'Original issue', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Regenerate report', exact: true }).click();
  await page.getByRole('button', { name: 'Update report', exact: true }).click();
  await expect.poll(() => posts).toBe(1);
  await expect(page.getByRole('button', { name: 'Original issue', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Generating report…', exact: true })).toBeDisabled();
  stage = 'new';
  await expect(page.getByRole('button', { name: 'Replacement issue', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Regenerate report', exact: true })).toBeEnabled();
});

test('first report generation also requires confirmation and Escape cancels it', async ({ page }) => {
  await setup(page, 'not_available');
  let posts = 0;
  await page.route('**/api/scans/s/findings-report', async route => {
    posts++;
    await route.fulfill({ status: 202, json: { status: 'queued', generation: 'new' } });
  });
  await page.goto('/#Findings%20Report');
  await page.getByRole('button', { name: 'Generate report', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('Generate a report from this assessment?');
  expect(posts).toBe(0);
  await page.getByRole('dialog').press('Escape');
  await expect(page.getByRole('dialog')).toHaveCount(0);
  expect(posts).toBe(0);
  await page.getByRole('button', { name: 'Generate report', exact: true }).click();
  await page.getByRole('dialog').getByRole('button', { name: 'Generate report', exact: true }).click();
  await expect.poll(() => posts).toBe(1);
});

test('generation control follows Combined reports and keeps its label when filters match nothing', async ({ page }) => {
  await setup(page); await page.goto('/#Findings%20Report');
  const toolbar = page.locator('.report-tabs');
  await expect(toolbar.getByRole('button')).toHaveText(['Regenerate report', 'Combine different reports']);
  const combined = await toolbar.getByRole('tab', { name: 'Combined reports', exact: true }).boundingBox();
  const generate = await toolbar.getByRole('button', { name: 'Regenerate report', exact: true }).boundingBox();
  const combine = await toolbar.getByRole('button', { name: 'Combine different reports', exact: true }).boundingBox();
  expect(combined!.x).toBeLessThan(generate!.x); expect(generate!.x).toBeLessThan(combine!.x);
  await page.getByLabel('Search report issues').fill('nonexistent issue');
  await expect(page.locator('.findings-table tbody')).toContainText('No issues match');
  await expect(toolbar.getByRole('button', { name: 'Regenerate report', exact: true })).toBeEnabled();
  await page.getByRole('tab', { name: 'Combined reports', exact: true }).click();
  await toolbar.getByRole('button', { name: 'Regenerate report', exact: true }).click();
  await expect(page.getByRole('dialog')).toContainText('current report stays available');
});

test('report prose renders Markdown safely and evidence expands after three identifiers', async ({ page }) => {
  await setup(page);
  const markdown = { ...issue(0), description: '**Broad access** lets `source-role` update `target-role` trust.\n\n- The target grants **administrator** access.',
    impact: '**Privilege escalation** to `target-role`.', recommendation: 'Remove `UpdateTrust` from **source-role**. <img src=x onerror=alert(1)>',
    references: Array.from({ length: 7 }, (_, i) => ({ domain: 'findings', id: 'f' + i })) };
  await page.route('**/api/scans/s/findings-report?**', route => route.fulfill({ json: { status: 'completed', issues: [markdown], total: 1 } }));
  await page.goto('/#Findings%20Report');
  await page.getByRole('button', { name: 'Report issue 0', exact: true }).click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByLabel('Issue description').locator('strong').first()).toHaveText('Broad access');
  await expect(dialog.getByLabel('Issue description').locator('code').first()).toHaveText('source-role');
  await expect(dialog.getByLabel('Issue impact').locator('strong')).toHaveText('Privilege escalation');
  await expect(dialog.getByLabel('Issue recommendation').locator('code')).toHaveText('UpdateTrust');
  await expect(dialog.locator('img')).toHaveCount(0);
  await expect(dialog.locator('.report-evidence li')).toHaveCount(3);
  await expect(dialog.getByRole('button', { name: 'arn:cloud:identity::123456789012:role/f0', exact: true })).toBeVisible();
  await expect(dialog.getByText(/Check result/)).toHaveCount(0);
  await dialog.getByRole('button', { name: 'Show 4 more evidence links', exact: true }).click();
  await expect(dialog.locator('.report-evidence li')).toHaveCount(7);
  await dialog.getByRole('button', { name: 'Show fewer evidence links', exact: true }).click();
  await expect(dialog.locator('.report-evidence li')).toHaveCount(3);
});

test('report search keeps severity and centered count on its right', async ({ page }) => {
  await setup(page);
  await page.goto('/#Findings%20Report');
  const search = page.getByRole('textbox', { name: 'Search report issues', exact: true });
  const severity = page.getByRole('combobox', { name: 'Report issue severity', exact: true });
  await expect(severity).toBeVisible();
  const [searchBox, severityBox] = await Promise.all([search.boundingBox(), severity.boundingBox()]);
  expect(severityBox!.x).toBeGreaterThan(searchBox!.x + searchBox!.width);
  expect(severityBox!.y).toBeCloseTo(searchBox!.y, 0);
  const filters = page.locator('.report-filters');
  await expect(filters.locator('.count-pill')).toHaveCSS('justify-content', 'center');
  const chevron = await filters.locator('svg').boundingBox();
  expect(chevron!.x + chevron!.width).toBeLessThan(severityBox!.x + severityBox!.width);
});
