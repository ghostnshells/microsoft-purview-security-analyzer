// Run against the local dev server: node tests/frontend.cjs
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
(async () => {
  const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH || '/usr/bin/chromium', headless: true, args: ['--no-sandbox'] });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    // Map tiles are external; the local interaction checks do not need them.
    await page.route('**/*.tile.openstreetmap.org/**', route => route.abort());
    await page.goto(process.env.TEST_URL || 'http://127.0.0.1:8000');
    assert.equal(await page.locator('.filter-controls > details').count(), 5);
    const positions = await page.locator('.filter-group').evaluateAll(els => els.map(e => e.getBoundingClientRect().top));
    assert(positions.every(y => y === positions[0]), 'Desktop filters share one horizontal row');
    await page.getByText('Risk Level', { exact: true }).click();
    await page.locator('#risk-levels input[value="Low"]').uncheck();
    await page.getByRole('button', { name: 'Reset All Filters' }).click();
    assert(await page.locator('#risk-levels input[value="Low"]').isChecked());
    const rows = ['CreationDate,Operation,UserId,AuditData'];
    for (let i = 0; i < 205; i++) {
      const audit = JSON.stringify({ ClientIP: '8.8.8.8' }).replaceAll('"', '""');
      rows.push(`2026-01-01T01:00:00Z,SoftDelete,test@example.test,"${audit}"`);
    }
    await page.locator('#file-input').setInputFiles({ name: 'audit.csv', mimeType: 'text/csv', buffer: Buffer.from(rows.join('\n')) });
    await page.waitForFunction(() => document.getElementById('m-total').textContent === '205');
    assert.equal(await page.locator('#location-select option').count(), 1);
    assert.equal(await page.locator('#table-location tbody tr').count(), 100);
    await page.locator('#table-location').getByRole('button', { name: 'Next' }).click();
    assert.match(await page.locator('#table-location .pager').innerText(), /Page 2 of 3/);
    const search = page.locator('#table-location input[type="search"]');
    await search.fill('no-match');
    assert.equal(await page.locator('#table-location tbody tr').count(), 0);
    await search.fill('');
    await page.locator('#map').scrollIntoViewIfNeeded();
    await page.waitForTimeout(300);
    const box = await page.locator('#map').boundingBox();
    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
    await page.waitForSelector('.activity-tooltip');
    assert.match(await page.locator('.activity-tooltip').innerText(), /205 events.*Latest:.*UTC.*SoftDelete/s);
    await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
    assert.equal(await page.locator('.leaflet-popup').count(), 0);
    await page.screenshot({ path: '/tmp/purview-desktop.png', fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.locator('#filters').scrollIntoViewIfNeeded();
    await page.getByText('Time Filter', { exact: true }).click();
    await page.locator('#time-enabled').check();
    await page.locator('#time-type').selectOption('Custom Range');
    assert(await page.locator('#start-time').isVisible());
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth));
    await page.getByRole('button', { name: 'Reset All Filters' }).click();
    assert(!(await page.locator('#time-enabled').isChecked()));
    assert.equal(errors.length, 0, errors.join('\n'));
    await page.screenshot({ path: '/tmp/purview-mobile.png', fullPage: true });
    console.log('PASS desktop/mobile toolbar, real CSV upload, paged/searchable location table, hover/click, reset, no page errors');
  } finally { await browser.close(); }
})().catch(e => { console.error(e); process.exitCode = 1; });
