// Drives Explore on an unpacked package from file:// in Chromium, Firefox and WebKit. The
// checks are cross-checks: a search and its negation must add up to every event, a facet's
// count must equal what filtering by it lists, an export must hold one row per result.
// Usage: npm run e2e -- <unpacked package dir>
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium, firefox, webkit } from 'playwright';

const directory = process.argv[2];
if (!directory) {
  console.error('usage: npm run e2e -- <unpacked package directory>');
  process.exit(2);
}
const url = pathToFileURL(path.resolve(directory, 'index.html')).href;

function check(condition, message) {
  if (!condition) throw new Error(message);
}

// The page's CSP forbids the eval that waitForFunction needs, so state is polled from outside.
async function poll(page, read, what, timeout = 120_000) {
  const started = Date.now();
  for (;;) {
    const value = await read();
    if (value) return value;
    if (Date.now() - started > timeout) throw new Error(`timed out waiting for ${what}`);
    await page.waitForTimeout(100);
  }
}

/** The settled result counts of the first list built after `state.build`. */
async function results(page, state) {
  const out = page.locator('#result-count');
  const next = await poll(page, async () => {
    const [build, busy, count, detected] = await Promise.all(
      ['data-build', 'data-busy', 'data-count', 'data-detected'].map((name) => out.getAttribute(name)),
    );
    if (busy !== 'false' || Number(build) <= state.build) return null;
    return { build: Number(build), count: Number(count), detected: Number(detected) };
  }, 'the results');
  state.build = next.build;
  return next;
}

async function search(page, state, text) {
  const input = page.locator('#search-input');
  await input.fill(text);
  await input.press('Enter');
  return results(page, state);
}

// Records, not lines: a quoted value may hold line breaks.
function csvRecords(text) {
  let records = 0;
  let quoted = false;
  for (const c of text) {
    if (c === '"') quoted = !quoted;
    else if (c === '\n' && !quoted) records++;
  }
  return records;
}

async function scenario(page, steps) {
  const state = { build: 0 };
  await page.goto(`${url}#/explore`);
  await poll(page, async () => /ready|error/.test(await page.title()), 'the viewer', 240_000);
  check((await page.title()) === 'Zircolite — ready', `the viewer reports: ${await page.title()}`);
  const expected = Number(await page.locator('#engine-check').getAttribute('data-expected'));
  // A package with an index must end up using it; a silent failure would leave every bare word on the slow scan.
  await poll(page, async () => (await page.locator('#engine-check').getAttribute('data-text-index')) === 'ready', 'the full-text index', 120_000);
  const chips = page.locator('ul[aria-label="Active filters"] li');

  let r = await results(page, state);
  check(r.count === expected, `the table lists ${r.count} events; the package holds ${expected}`);
  const withDetections = r.detected;
  steps.push('all events listed');

  const hit = await search(page, state, 'EventID:4688');
  check(hit.count > 0, 'EventID:4688 matched nothing; pick a field and value this package has');
  check(page.url().includes('q=EventID%3A4688'), 'the search is not in the URL');
  check((await chips.filter({ hasText: 'EventID: 4688' }).count()) === 1, 'the search has no chip');
  const miss = await search(page, state, '-EventID:4688');
  check(hit.count + miss.count === expected, `EventID:4688 (${hit.count}) and its negation (${miss.count}) do not add up to ${expected}`);
  await search(page, state, '');
  // A bare word runs through the index by now; it and its negation must still partition the events.
  const word = await search(page, state, '4688');
  const notWord = await search(page, state, '-4688');
  check(word.count > 0, 'the bare word 4688 matched nothing through the index');
  check(word.count + notWord.count === expected, `4688 (${word.count}) and its negation (${notWord.count}) do not add up to ${expected}`);
  await search(page, state, '');
  steps.push('search and negation partition the events');

  // A text input strips line breaks, so a query holding one must not be editable through it.
  const input = page.locator('#search-input');
  await page.goto(`${url}#/explore?q=${encodeURIComponent('Computer:"a\nb"')}`);
  await results(page, state);
  check(!(await input.isEditable()), 'the search box is editable while the search holds a line break');
  check(await page.locator('#search-locked').isVisible(), 'no note says why the search box is read-only');
  await chips.filter({ hasText: 'Computer:' }).getByRole('button').click();
  r = await results(page, state);
  check(await input.isEditable(), 'the search box stayed read-only after its last term was removed');
  check((await input.inputValue()) === '' && !page.url().includes('q='), 'removing the only chip left a search behind');
  check(r.count === expected, `removing the chip lists ${r.count} events, not ${expected}`);
  steps.push('line breaks: read-only search, chip removal');

  const detectionsOnly = page.getByRole('button', { name: 'Detections only' });
  await detectionsOnly.click();
  r = await results(page, state);
  check(r.count === withDetections, `Detections only lists ${r.count}; the counts bar said ${withDetections}`);
  await detectionsOnly.click();
  await results(page, state);
  steps.push('detections only');

  const box = await page.locator('#seismic-strip').boundingBox();
  check(box, 'the strip is not drawn');
  await page.mouse.move(box.x + box.width * 0.3, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width * 0.6, box.y + box.height / 2, { steps: 5 });
  await page.mouse.up();
  r = await results(page, state);
  check(r.count <= expected, 'the time range widened the results');
  check(page.url().includes('t='), 'the time range is not in the URL');
  check((await chips.filter({ hasText: 'UTC' }).count()) === 1, 'the time range has no chip');
  await page.goBack();
  r = await results(page, state);
  check(r.count === expected, `Back left ${r.count} events listed, not ${expected}`);
  steps.push('brush and Back');

  await page.locator('#field-filter').fill('Computer');
  await page.locator('#field-sidebar button.field').filter({ has: page.locator('.name', { hasText: /^Computer$/ }) }).click();
  const top = page.locator('#field-sidebar li[data-value]').first();
  await top.waitFor();
  const facetCount = Number(await top.getAttribute('data-count'));
  const facetValue = await top.getAttribute('data-value');
  await top.getByRole('button', { name: /^Filter for / }).click();
  r = await results(page, state);
  check(r.count === facetCount, `filtering by Computer ${facetValue} lists ${r.count}; its facet counted ${facetCount}`);
  steps.push('facet count equals its filter');

  const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export CSV' }).click()]);
  const csv = fs.readFileSync(await download.path(), 'utf8');
  check(csvRecords(csv) === r.count + 1, `the CSV holds ${csvRecords(csv) - 1} events; the results ${r.count}`);
  steps.push('CSV export');

  await search(page, state, '');
  await page.locator('#result-grid').focus();
  await page.keyboard.press('j');
  await page.keyboard.press('Enter');
  const drawer = page.getByRole('complementary', { name: 'Event details' });
  await drawer.waitFor();
  await poll(page, async () => (await drawer.locator('dt').count()) > 0, 'the event fields');
  check(page.url().includes('uid='), 'the open event is not in the URL');
  await page.keyboard.press('Escape');
  await drawer.waitFor({ state: 'detached' });
  steps.push('event view from the keyboard');

  // One Escape closes one layer, whether focus is on the page or in the search box.
  const help = page.locator('#search-help');
  const openDrawer = async () => {
    await page.locator('#result-grid').focus();
    await page.keyboard.press('Enter');
    await poll(page, async () => (await drawer.locator('dt').count()) > 0, 'the event fields');
  };
  // A closing drawer stays in the page for its 120 ms slide, so wait that out before looking.
  const drawerStayed = async (message) => {
    await page.waitForTimeout(400);
    check((await drawer.count()) === 1 && page.url().includes('uid='), message);
  };
  await openDrawer();
  await page.keyboard.press('?');
  await help.waitFor();
  await page.keyboard.press('Escape');
  await help.waitFor({ state: 'detached' });
  await drawerStayed('one Escape closed both the help and the event view');
  await page.keyboard.press('Escape');
  await drawer.waitFor({ state: 'detached' });
  await openDrawer();
  await page.getByRole('button', { name: 'Syntax', exact: true }).click();
  await help.waitFor();
  await input.focus();
  await input.press('Escape');
  await help.waitFor({ state: 'detached' });
  await drawerStayed('one Escape in the search box closed both the help and the event view');
  await input.press('Escape');
  await drawer.waitFor({ state: 'detached' });
  steps.push('one Escape closes one layer');

  await page.locator('#result-grid').focus();
  await page.keyboard.press('End');
  const last = page.locator(`#result-grid [role=row][aria-rowindex="${expected + 1}"]`);
  await last.waitFor();
  await poll(page, async () => (await last.locator('[role=gridcell]').first().textContent()) !== 'Loading', 'the last row');
  steps.push('last row reachable');

  await page.getByRole('button', { name: /^Theme:/ }).click();
  check((await page.locator('html').getAttribute('data-theme')) === 'light', 'the theme button did not switch to light');
  steps.push('theme switch');
}

let failed = false;
for (const [name, type] of [['chromium', chromium], ['firefox', firefox], ['webkit', webkit]]) {
  const browser = await type.launch();
  const started = Date.now();
  const steps = [];
  const errors = [];
  const requests = [];
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
    page.on('pageerror', (error) => errors.push(String(error)));
    page.on('console', (message) => {
      if (message.type() === 'error') errors.push(message.text());
    });
    page.on('request', (request) => {
      if (!/^(file|data|blob):/.test(request.url())) requests.push(request.url());
    });
    await scenario(page, steps);
    check(errors.length === 0, `the page reported errors: ${errors.join(' | ')}`);
    check(requests.length === 0, `the page made network requests: ${requests.join(' ')}`);
    console.log(JSON.stringify({ browser: name, ok: true, seconds: (Date.now() - started) / 1000, steps }));
  } catch (error) {
    failed = true;
    console.log(JSON.stringify({ browser: name, ok: false, seconds: (Date.now() - started) / 1000, steps, error: String(error), errors, requests }));
  } finally {
    await browser.close();
  }
}
process.exit(failed ? 1 : 0);
