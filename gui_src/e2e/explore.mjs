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

function readManifest() {
  const text = fs.readFileSync(path.join(directory, 'data/manifest.js'), 'utf8');
  return JSON.parse(text.slice(text.indexOf('(') + 1, text.lastIndexOf(')')));
}

const manifest = readManifest();

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

  // A link's search that does not compile matches nothing and says why; a bad draft says why until Escape.
  const searchError = page.locator('#search-error');
  await page.goto(`${url}#/explore?q=${encodeURIComponent('Comptuer:x')}`);
  r = await results(page, state);
  check(r.count === 0, `a search on a field the package lacks lists ${r.count} events, not none`);
  check(/No field named Comptuer/.test(await searchError.textContent()), 'a linked search that does not compile shows no error');
  await search(page, state, '');
  check((await searchError.count()) === 0, 'the error of a replaced search stayed');
  await input.fill('EventID:<x');
  await input.press('Enter');
  check((await searchError.count()) === 1 && !page.url().includes('q='), 'a draft that does not compile was committed, or said nothing');
  await input.press('Escape');
  check((await searchError.count()) === 0 && (await input.inputValue()) === '', 'Escape kept the draft or its error');
  steps.push('a search that does not compile says why');

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

  // Events without a parseable time cannot fall in any range, so the whole strip lists every other one.
  const timeless = manifest.parts.reduce((sum, part) => sum + part.time.missing + part.time.unparsed, 0);
  await page.mouse.move(box.x + 1, box.y + box.height / 2);
  await page.mouse.down();
  await page.mouse.move(box.x + box.width - 1, box.y + box.height / 2, { steps: 8 });
  await page.mouse.up();
  r = await results(page, state);
  check(r.count === expected - timeless, `brushing the whole strip lists ${r.count}; ${expected - timeless} events have a time`);
  await page.goBack();
  r = await results(page, state);
  steps.push('whole-strip brush selects every timed event');

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
  const uid = new URL(page.url()).hash.match(/uid=(\d+)/)[1];
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

  // A deep link opens the drawer with focus on the body: closing it must still land somewhere.
  await page.goto('about:blank');
  await page.goto(`${url}#/explore?uid=${uid}`);
  await poll(page, async () => /ready|error/.test(await page.title()), 'the viewer', 240_000);
  await drawer.waitFor();
  await poll(page, async () => (await drawer.locator('dt').count()) > 0, 'the event fields');
  await page.keyboard.press('Escape');
  await drawer.waitFor({ state: 'detached' });
  check((await page.evaluate(() => document.activeElement?.tagName)) !== 'BODY', 'closing a deep-linked event left focus on the body');
  steps.push('focus after a deep-linked event closes');

  // On a phone the Fields panel is a sheet and the exports are one menu; each is a layer one Escape closes.
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('about:blank');
  await page.goto(`${url}#/explore`);
  await poll(page, async () => /ready|error/.test(await page.title()), 'the viewer', 240_000);
  await results(page, { build: 0 });
  const focused = (selector) => page.evaluate((s) => document.activeElement === document.querySelector(s), selector);
  const sheet = page.locator('#field-sidebar');
  check(!(await sheet.isVisible()), 'the Fields sheet is open before it was asked for');
  await page.locator('#fields-toggle').click();
  await sheet.waitFor({ state: 'visible' });
  const sheetBox = await sheet.boundingBox();
  check(sheetBox && sheetBox.x === 0 && sheetBox.y === 0 && sheetBox.height >= 840, 'the Fields sheet does not cover the full height');
  await page.keyboard.press('Escape');
  await sheet.waitFor({ state: 'hidden' });
  check(await focused('#fields-toggle'), 'closing the Fields sheet did not return focus to its button');
  check(!(await page.locator('.exports').isVisible()), 'the two export buttons show on a phone');
  const summary = page.locator('.export-menu summary');
  await summary.click();
  const menuItem = page.locator('.export-menu .menu button').first();
  await menuItem.waitFor({ state: 'visible' });
  // The sheet under the menu must stay: one Escape, one layer.
  await page.keyboard.press('Escape');
  await menuItem.waitFor({ state: 'hidden' });
  check(await focused('.export-menu summary'), 'closing the Export menu did not return focus to its summary');
  // The menu is a light dismiss: tapping Fields closes it and opens the modal sheet, and one Escape closes the sheet.
  await summary.click();
  await menuItem.waitFor({ state: 'visible' });
  await page.locator('#fields-toggle').click();
  await sheet.waitFor({ state: 'visible' });
  check(!(await menuItem.isVisible()), 'the Export menu stayed open beside the Fields sheet');
  check(await page.evaluate(() => document.querySelector('#fields-toggle')?.closest('[inert]') !== null), 'the page behind the Fields sheet is not inert');
  check(await page.evaluate(() => document.querySelector('#field-sidebar')?.closest('[inert]') === null), 'the Fields sheet itself is inert');
  await page.keyboard.press('Escape');
  await sheet.waitFor({ state: 'hidden' });
  check(await focused('#fields-toggle'), 'closing the sheet over an open menu did not return focus to the Fields button');
  check(await page.evaluate(() => document.querySelector('[inert]') === null), 'the page stayed inert after the sheet closed');
  await page.locator('#fields-toggle').click();
  await sheet.waitFor({ state: 'visible' });
  await page.getByRole('button', { name: 'Close fields' }).click({ position: { x: 370, y: 400 } });
  await sheet.waitFor({ state: 'hidden' });
  check(await focused('#fields-toggle'), 'closing the sheet by its scrim did not return focus to the Fields button');
  // Choosing an export keeps focus on the page rather than dropping it to the body.
  await summary.click();
  await menuItem.click();
  await page.waitForTimeout(300);
  check((await page.evaluate(() => document.activeElement?.tagName)) !== 'BODY', 'choosing an export from the menu left focus on the body');
  await poll(page, async () => (await page.getByRole('button', { name: 'Cancel export' }).count()) === 0, 'the export to finish');
  await page.waitForTimeout(300);
  check((await page.evaluate(() => document.activeElement?.tagName)) !== 'BODY', 'a finished export left focus on the body');
  const legend = await page.locator('#strip-legend').boundingBox();
  const start = await page.locator('#strip-legend .start').boundingBox();
  const end = await page.locator('#strip-legend .end').boundingBox();
  const key = await page.locator('#strip-legend .key').boundingBox();
  check(start && end && key && legend && Math.abs(start.y - end.y) < 4 && key.y > start.y + 4, 'the strip legend does not put its start and end labels above the key');
  steps.push('phone: Fields sheet and Export menu close with one Escape each');
  await page.setViewportSize({ width: 1440, height: 900 });

  // Overview must agree with Explore: its tiles with the detected count, its top rule with the events that rule lists.
  await page.goto('about:blank');
  await page.goto(`${url}#/overview`);
  await poll(page, async () => /ready|error/.test(await page.title()), 'the viewer', 240_000);
  const tiles = page.locator('#overview-tiles');
  const total = Number(await poll(page, () => tiles.getAttribute('data-events'), 'the severity tiles'));
  check(total === withDetections, `the overview tiles hold ${total} events; Explore lists ${withDetections} with detections`);
  const rule = page.locator('#overview-rules button').first();
  const ruleEvents = Number(await poll(page, () => rule.getAttribute('data-events'), 'the top rules'));
  await rule.click();
  const listed = await results(page, { build: 0 });
  check(listed.count === ruleEvents, `the top rule counts ${ruleEvents} events; Explore lists ${listed.count}`);
  steps.push('overview agrees with explore');
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
