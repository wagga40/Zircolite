// Cross-checks the Overview, Detections and Timeline views, and full-text search through the index,
// on an unpacked package from file:// in Chromium, Firefox and WebKit. A bare word's count is checked
// against a scan of every field that @duckdb/node-api runs on the package's own Parquet.
// Usage: npm run views -- <unpacked package dir>
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { DuckDBInstance } from '@duckdb/node-api';
import { chromium, firefox, webkit } from 'playwright';

const directory = process.argv[2];
if (!directory) {
  console.error('usage: npm run views -- <unpacked package directory>');
  process.exit(2);
}
const url = pathToFileURL(path.resolve(directory, 'index.html')).href;
const WORD = 'powershell';

function readManifest() {
  const text = fs.readFileSync(path.join(directory, 'data/manifest.js'), 'utf8');
  return JSON.parse(text.slice(text.indexOf('(') + 1, text.lastIndexOf(')')));
}

const manifest = readManifest();
// A wildcard between letters of the text field most events have: the general matcher, on nearly every event.
const busiest = manifest.columns.filter((column) => column.type === 'VARCHAR').sort((a, b) => b.count - a.count)[0];
const SLOW = `"${busiest.name.replaceAll('\\', '\\\\').replaceAll('"', '\\"')}":*a*e*i*`;

function reassemble(name) {
  const file = manifest.files.find((entry) => entry.name === name);
  if (!file) throw new Error(`the package lists no ${name}`);
  return Buffer.concat(file.chunks.map((chunk) => {
    const match = /,"([A-Za-z0-9+/=]*)"\);\s*$/.exec(fs.readFileSync(path.join(directory, chunk), 'utf8'));
    if (!match) throw new Error(`${chunk} is not a chunk script`);
    return Buffer.from(match[1], 'base64');
  }));
}

/** How many events a scan of every field finds: the ground truth the index must agree with. */
async function scanCount(word) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'zl-views-')), 'events.parquet');
  fs.writeFileSync(file, reassemble('events.parquet'));
  const instance = await DuckDBInstance.create(':memory:');
  const conn = await instance.connect();
  try {
    const columns = manifest.columns.map((c) => `"${c.name.replaceAll('"', '""')}"`).join(', ');
    const sql = `SELECT count(*)::DOUBLE AS n FROM read_parquet('${file.replaceAll("'", "''")}') ` +
      `WHERE concat_ws(chr(31), ${columns}) ILIKE '%${word.replaceAll("'", "''")}%'`;
    return Number((await conn.runAndReadAll(sql)).getRowObjectsJS()[0].n);
  } finally {
    conn.closeSync();
    instance.closeSync();
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  }
}

function check(condition, message) {
  if (!condition) throw new Error(message);
}

// The page's CSP forbids the eval that waitForFunction needs, so state is polled from outside.
async function poll(page, read, what, timeout = 120_000) {
  const started = Date.now();
  for (;;) {
    const value = await read();
    if (value !== null && value !== undefined && value !== false) return value;
    if (Date.now() - started > timeout) throw new Error(`timed out waiting for ${what}`);
    await page.waitForTimeout(100);
  }
}

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

// The result list's build counter belongs to the Explore component, so it restarts every time Explore opens.
const reopened = (page, state) => {
  state.build = 0;
  return results(page, state);
};

async function search(page, state, text) {
  const input = page.locator('#search-input');
  await input.fill(text);
  await input.press('Enter');
  return results(page, state);
}

const nav = (page, name) => page.locator('nav[aria-label="Views"] button', { hasText: name }).click();
const number = async (locator, attribute) => {
  const value = await locator.getAttribute(attribute);
  return value === null || value === '' ? null : Number(value);
};

// Expands rules until one lists alerts, then opens an alert: its evidence list must hold the
// events it counted, or say how many it cut off.
async function correlationAlerts(page, state, steps) {
  await nav(page, 'Detections');
  await poll(page, () => number(page.locator('#detections-summary'), 'data-rules'), 'the detections');
  const rows = page.locator('button[data-key]');
  const alerts = page.locator('section[aria-label="Correlation alerts"] button.alert');
  const total = await rows.count();
  let found = false;
  for (let i = 0; i < total && !found; i++) {
    const row = rows.nth(i);
    await row.click();
    const section = page.locator('section[aria-label="Correlation alerts"]');
    if ((await section.count()) === 0) {
      await row.click();
      continue;
    }
    await poll(page, async () => (await section.locator('p.note', { hasText: 'Reading the alerts' }).count()) === 0, 'the alerts');
    if ((await alerts.count()) > 0) found = true;
    else await row.click();
  }
  check(found, `the package counts ${manifest.totals.alerts} alerts but no rule in Detections lists one`);
  const alert = alerts.first();
  const claimed = Number((await alert.locator('.n').textContent()).replace(/\D/g, ''));
  await alert.click();
  const items = page.locator('ol.evidence li');
  await poll(page, async () => (await page.locator('p.note', { hasText: 'Reading the evidence' }).count()) === 0, 'the evidence');
  const cut = page.locator('p.note', { hasText: /^First [\d,. ]+ of / });
  if (claimed > 500) {
    check((await cut.count()) === 1, `the alert counts ${claimed} events and its evidence does not say it was cut off`);
  } else {
    check((await items.count()) === claimed, `the alert counts ${claimed} events; its evidence lists ${await items.count()}`);
  }
  steps.push(`correlation alert opens with its ${claimed} events of evidence`);
}

async function scenario(page, open, steps, expectedText) {
  const state = { build: 0 };
  await page.goto(`${url}#/overview`);
  await poll(page, async () => /ready|error/.test(await page.title()), 'the viewer', 240_000);
  check((await page.title()) === 'Zircolite — ready', `the viewer reports: ${await page.title()}`);

  const tiles = await poll(page, () => number(page.locator('#overview-tiles'), 'data-events'), 'the overview');
  await nav(page, 'Explore');
  const all = await reopened(page, state);
  check(tiles === all.detected, `the overview tiles hold ${tiles} events; Explore says ${all.detected} have detections`);
  steps.push('overview tiles add up to the events with detections');

  await nav(page, 'Detections');
  const summary = page.locator('#detections-summary');
  const rules = await poll(page, () => number(summary, 'data-rules'), 'the detections');
  check(rules === manifest.totals.rules_matched, `Detections lists ${rules} rules; the run matched ${manifest.totals.rules_matched}`);
  const row = page.locator('button[data-key]').first();
  const expected = Number(await row.getAttribute('data-events'));
  await row.click();
  await page.getByRole('button', { name: 'Show events' }).first().click();
  const shown = await reopened(page, state);
  check(shown.count === expected, `the rule lists ${expected} events; Explore shows ${shown.count}`);
  steps.push('detections match the run, and a rule shows exactly its events');

  await search(page, state, '');
  await nav(page, 'Timeline');
  await poll(page, async () => ((await number(page.locator('#timeline-marks'), 'data-count')) ?? 0) > 0, 'timeline marks');
  await page.locator('#timeline-canvas').focus();
  await page.keyboard.press('+');
  await page.keyboard.press('+');
  await poll(page, async () => page.url().includes('#/timeline') && page.url().includes('t='), 'the zoom to reach the URL');
  await page.goBack();
  await poll(page, async () => page.url().includes('#/explore'), 'one Back to leave the timeline');
  steps.push('timeline draws, zooms, and keeps its zoom out of the history');

  // Leaving Explore while its search runs drops that search's queries, and Overview counts without them.
  // On a small package every query takes milliseconds, so this checks the answer, not the wait;
  // perf times the wait on a large one.
  await nav(page, 'Explore');
  await reopened(page, state);
  const input = page.locator('#search-input');
  await input.fill(SLOW);
  await input.press('Enter');
  await page.goto(`${url}#/overview`);
  const after = await poll(page, () => number(page.locator('#overview-tiles'), 'data-events'), 'the overview after leaving a search');
  check(after === tiles, `after leaving a search on Explore, the overview tiles hold ${after} events, not ${tiles}`);
  steps.push('leaving a search midway leaves the overview counts whole');

  if (manifest.totals.alerts > 0) await correlationAlerts(page, state, steps);
  else steps.push('correlation alerts skipped: this package has none');

  if (manifest.files.some((file) => file.kind === 'index')) {
    // A link opened before the index has loaded: the word goes onto the index from the first query.
    const fresh = await open();
    await fresh.goto(`${url}#/overview?q=${WORD}`);
    await poll(fresh, async () => /ready|error/.test(await fresh.title()), 'the viewer', 240_000);
    const linked = await poll(fresh, () => number(fresh.locator('#overview-tiles'), 'data-events'), 'the overview of a linked word');
    await nav(fresh, 'Explore');
    const listed = await reopened(fresh, { build: 0 });
    check(linked === listed.detected, `a link to "${WORD}" counts ${linked} events with detections on Overview; Explore says ${listed.detected}`);
    await fresh.close();
    steps.push('a linked word reads the index from the first query');

    await nav(page, 'Explore');
    await reopened(page, state);
    await poll(page, async () => (await page.locator('#engine-check').getAttribute('data-text-index')) === 'ready', 'the full-text index', 240_000);
    const found = await search(page, state, WORD);
    check(found.count === expectedText, `"${WORD}" finds ${found.count} events through the index; a scan finds ${expectedText}`);
    steps.push('full text through the index equals a scan');
  } else {
    steps.push('full text skipped: this package has no index');
  }
}

const expectedText = await scanCount(WORD);
let failed = false;
for (const [name, type] of [['chromium', chromium], ['firefox', firefox], ['webkit', webkit]]) {
  const browser = await type.launch();
  const started = Date.now();
  const steps = [];
  const errors = [];
  const requests = [];
  const open = async () => {
    const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
    page.on('pageerror', (error) => errors.push(String(error)));
    page.on('console', (message) => {
      if (message.type() === 'error') errors.push(message.text());
    });
    page.on('request', (request) => {
      if (!/^(file|data|blob):/.test(request.url())) requests.push(request.url());
    });
    return page;
  };
  try {
    await scenario(await open(), open, steps, expectedText);
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
