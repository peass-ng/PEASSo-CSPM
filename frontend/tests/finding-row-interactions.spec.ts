import { expect, test, type Page } from '@playwright/test';
const leaks = [0, 1].map(n => ({ id: `leak-${n}`, title: `Secret source ${n}`, check_id: `fixture.secret.${n}`,
  provider: 'aws', service: 'lambda', category: 'hardening', finding_type: 'detected_leaks', severity: 'high', status: 'FAIL',
  resource_id: `asset-${n}`, scope: '123456789012/us-east-1', frameworks: [], evidence_summary: 'Synthetic detected secret.', evidence: {} }));
const images = [0, 1].map(n => ({ id: `image-${n}`, provider: 'aws', scope: '123456789012/us-east-1',
  image_reference: `registry.example/app-${n}@sha256:${String(n).repeat(64)}`, image_digest: `sha256:${String(n).repeat(64)}`,
  severity: 'HIGH', vulnerability_id: `CVE-2026-${1000 + n}`, package: `package-${n}`, installed_version: '1.0',
  fixed_versions: ['1.1'], coverage: 'COMPLETE', affected_assets: [{ resource_id: `image-asset-${n}`, kind: 'ecr_image' }] }));
async function setup(page: Page, view: 'leaks' | 'images', grouped = true) {
  await page.route('**/api/**', async route => {
    const path = new URL(route.request().url()).pathname; let json: unknown = { items: [] };
    if (path.endsWith('/health')) json = { status: 'ok', auth_mode: 'local' };
    if (path.endsWith('/me')) json = { tenant_id: 'test', plan: 'free' };
    if (path.endsWith('/scans')) json = { items: [{ id: 'scan-1', status: 'completed' }] };
    if (path.endsWith('/summary')) json = { provider: 'aws', resources: [], findings: [], stats: {} };
    if (path.endsWith('/findings')) json = { items: leaks, total: 2, next_offset: null,
      ...(grouped ? { service_groups: [{ service: 'lambda', count: 2, status_counts: { FAIL: 2 } }] } : {}) };
    const leak = leaks.find(row => path.endsWith('/findings/' + row.id));
    if (leak) json = { ...leak, secret_evidence: { status: 'available', complete: true,
      matches: [{ fingerprint: leak.id, value: `SYNTHETIC-${leak.id}`, locations: [{ resource_id: leak.resource_id, path: '/fixture.env', line: 1 }] }] } };
    if (path.endsWith('/image-findings')) json = { rows: images, total: 2, next_offset: null, coverage: 'COMPLETE', complete: true,
      observations: 2, image_count: 2, invalid_observations: 0, invalid_vulnerabilities: 0, truncated: false };
    await route.fulfill({ json });
  });
  await page.goto(view === 'leaks' ? '/#Leaks' : '/#Images%20CVEs');
  if (view === 'leaks') {
    if (grouped) await page.getByRole('button', { name: /lambda 2 findings/ }).click();
    else await page.getByLabel('Group findings').selectOption('check_id');
  }
}
const dataRow = (page: Page, name: string | RegExp) => page.getByRole('row').filter({ has: page.getByRole('button', { name, exact: typeof name === 'string' }) });
for (const grouped of [true, false]) test(`every leak cell opens its details (${grouped ? 'service groups' : 'virtualized rows'})`, async ({ page }) => {
  await setup(page, 'leaks', grouped); const row = dataRow(page, /Secret source 0/);
  for (let n = 0; n < 6; n++) {
    await row.getByRole('cell').nth(n).click({ position: { x: 4, y: 4 } });
    await expect(page.getByRole('dialog').getByText('SYNTHETIC-leak-0', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Close inspector' }).click();
    await expect(row.getByRole('button', { name: /Secret source 0/ })).toBeFocused();
  }
  await dataRow(page, /Secret source 1/).getByRole('cell').last().click();
  await expect(page.getByRole('dialog').getByText('SYNTHETIC-leak-1', { exact: true })).toBeVisible();
});
for (const group of ['cve', 'image']) test(`every image cell opens its ${group} details`, async ({ page }) => {
  await setup(page, 'images'); await page.getByLabel('Group image findings by').selectOption(group);
  const title = group === 'cve' ? images[0].vulnerability_id : images[0].image_reference;
  const row = dataRow(page, title);
  for (let n = 0; n < 5; n++) {
    await row.getByRole('cell').nth(n).click({ position: { x: 4, y: 4 } });
    await expect(page.getByRole('dialog').getByRole('heading', { level: 2, name: title, exact: true })).toBeVisible();
    await expect(page.getByRole('dialog').getByRole('heading', { level: 3, name: 'CVE-2026-1000 · package-0', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Close inspector' }).click();
    await expect(row.getByRole('button', { name: title, exact: true })).toBeFocused();
  }
  const next = group === 'cve' ? images[1].vulnerability_id : images[1].image_reference;
  await dataRow(page, next).getByRole('cell').last().click();
  await expect(page.getByRole('dialog').getByRole('heading', { level: 2, name: next, exact: true })).toBeVisible();
});
for (const view of ['leaks', 'images'] as const) test(`${view} rows preserve selection, modifiers and keyboard buttons`, async ({ page }) => {
  await setup(page, view); const name = view === 'leaks' ? /Secret source 0/ : images[0].vulnerability_id;
  const row = dataRow(page, name); const cell = row.getByRole('cell').last();
  await cell.click({ modifiers: ['Control'] }); await expect(page.getByRole('dialog')).toHaveCount(0);
  await cell.evaluate(element => { const range = document.createRange(); range.selectNodeContents(element);
    const selection = window.getSelection()!; selection.removeAllRanges(); selection.addRange(range); });
  await cell.dispatchEvent('click', { button: 0 }); await expect(page.getByRole('dialog')).toHaveCount(0);
  await page.evaluate(() => window.getSelection()?.removeAllRanges());
  const button = row.getByRole('button', { name, exact: typeof name === 'string' });
  await button.focus(); await button.press('Enter'); await expect(page.getByRole('dialog')).toHaveCount(1);
  await page.keyboard.press('Escape'); await expect(button).toBeFocused();
  await button.focus(); await button.press('Space'); await expect(page.getByRole('dialog')).toHaveCount(1);
});
