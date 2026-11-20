import { test, expect } from '@playwright/test';
import type { Page } from '@playwright/test';
async function setup(page: Page) {
  const digest = 'sha256:' + 'a'.repeat(64);
  const rows = Array.from({ length: 80 }, (_, n) => ({ id: String(n), provider: 'aws', scope: '123/us-east-1',
    image_reference: `registry.example/app${n % 2}@${digest}`, image_digest: 'sha256:' + String(n % 2).repeat(64),
    severity: n === 0 ? 'CRITICAL' : 'HIGH', vulnerability_id: `CVE-2026-${1000 + n % 40}`, package: 'openssl',
    installed_version: '1.0', fixed_versions: ['1.1'], affected_assets: [{ resource_id: 'task-' + n, kind: 'ecs_task' }], coverage: 'COMPLETE' }));
  await page.route('**/api/**', async route => {
    const u = new URL(route.request().url()); const p = u.pathname;
    let json: unknown = { items: [] };
    if (p.endsWith('/me')) json = { tenant_id: 'test' };
    if (p.endsWith('/ai/codex')) json = { available: true };
    if (p.endsWith('/scans')) json = { items: [{ id: 's', status: 'completed' }] };
    if (p.endsWith('/summary')) json = { stats: { failed_by_category: { hardening: 12, exposure: 3 } } };
    if (p.endsWith('/findings')) json = { items: [], total: u.searchParams.get('finding_type') === 'detected_leaks' ? 4 : 99 };
    if (p.endsWith('/image-findings')) json = { rows, total: 80, vulnerability_count: 40, offset: 0, next_offset: null, coverage: 'COMPLETE', complete: true,
      observations: 2, truncated: false, invalid_observations: 0, invalid_vulnerabilities: 0 };
    if (p.endsWith('/least-privilege')) json = { items: [], total: 7, recommendation_total: 19 };
    if (p.endsWith('/graphs/privesc')) json = { nodes: [], edges: [{}], truncated: true, total_edges: 82 };
    if (p.endsWith('/graphs/network')) json = { nodes: [], total_nodes: 25 };
    if (p.endsWith('/ai')) json = { actions: [{ title: 'Action' }], network: { total: 6, findings: [] } };
    await route.fulfill({ json });
  });
}
test('sidebar shows complete totals, keeps tags beside names and orders leaks last', async ({ page }) => {
  await setup(page); await page.goto('/#Images%20CVEs');
  for (const [name, count] of Object.entries({ 'Hardening & Compliance': 12, Exposure: 3, Leaks: 4, 'Images CVEs': 40,
    'Least Privilege': 19, 'Privilege Escalation Map': 82, 'Network Map': 25, 'Network Architecture': 6, 'Top 15 Actions': 1 })) {
    await expect(page.getByLabel(`${name} total`, { exact: true })).toHaveText(String(count));
  }
  const nav = page.getByRole('navigation', { name: 'Primary navigation' });
  const names = await nav.getByRole('button').allTextContents();
  const network = names.findIndex(n => n.includes('Network Architecture'));
  expect(names.findIndex(n => n.includes('Leaks'))).toBe(network + 1);
  expect(names.findIndex(n => n.includes('Images CVEs'))).toBe(network + 2);
  await expect(nav.getByRole('button', { name: 'Attack Detection', exact: true }).locator('.nav-label')).toContainText('Beta');
  await expect(nav.getByRole('button', { name: 'Top 15 Actions', exact: true }).locator('.nav-label')).toContainText('AI');
});
test('CVE and image groups open the shared inspector and table scrolls internally', async ({ page }) => {
  await setup(page); await page.goto('/#Images%20CVEs');
  const table = page.getByRole('region', { name: 'Image CVE findings table' });
  await expect(table.locator('tbody tr')).toHaveCount(40);
  expect(await table.evaluate(e => e.clientHeight <= 620 && e.scrollHeight > e.clientHeight && getComputedStyle(e).overflowY === 'auto')).toBe(true);
  await page.getByRole('button', { name: 'CVE-2026-1000', exact: true }).click();
  const inspector = page.getByRole('dialog');
  await expect(inspector).toBeVisible();
  await expect(inspector.getByRole('link', { name: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1000', exact: true }).first()).toBeVisible();
  await expect(inspector.getByText('Fix', { exact: true })).toHaveCount(0);
  await expect(inspector.getByText('1.1', { exact: true }).first()).toBeVisible();
  await inspector.getByRole('button', { name: 'Close inspector' }).click();
  await page.getByLabel('Group image findings by').selectOption('image');
  await expect(table.locator('tbody tr')).toHaveCount(2);
  await table.locator('.finding-title').first().click();
  await expect(page.getByRole('dialog').getByRole('heading', { name: /CVE-2026-1000/ }).first()).toBeVisible();
});

for (const width of [1440, 390]) {
  test(`image detail typography follows its reading context at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1080 });
    await setup(page);
    await page.goto('/#Images%20CVEs');
    const font = (element: Element) => {
      const style = getComputedStyle(element);
      return { family: style.fontFamily, size: style.fontSize, lineHeight: style.lineHeight };
    };
    await page.getByRole('button', { name: 'CVE-2026-1000', exact: true }).click();
    const detail = page.getByRole('dialog').locator('.image-cve-detail').first();
    const summary = detail.locator('summary');
    await summary.click();
    await expect(detail.getByText('task-0', { exact: true })).toBeVisible();
    const reference = await detail.locator('a').first().evaluate(font);
    for (const selector of ['p', 'dt', 'dd', 'summary', 'li .images-findings-break', '.images-findings-secondary']) {
      expect(await detail.locator(selector).first().evaluate(font), selector).toEqual(reference);
    }
    expect(await detail.evaluate(el => el.scrollWidth <= el.clientWidth)).toBe(true);
    // Headings retain their hierarchy; body values do not inherit browser defaults.
    expect(await detail.locator('h3').evaluate(el => getComputedStyle(el).fontWeight)).not.toBe(
      await detail.locator('dd').first().evaluate(el => getComputedStyle(el).fontWeight));
    await summary.click();
    await expect(detail.getByText('task-0', { exact: true })).not.toBeVisible();
  });
}
