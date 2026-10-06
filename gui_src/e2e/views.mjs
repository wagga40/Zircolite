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

/** Writes the package's events.parquet to a temp directory and runs `fn(connection, file)` on it in node DuckDB. */
async function withEvents(fn, extra = []) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'zl-views-'));
  const file = path.join(dir, 'events.parquet');
  fs.writeFileSync(file, reassemble('events.parquet'));
  for (const name of extra) fs.writeFileSync(path.join(dir, name), reassemble(name));
  const instance = await DuckDBInstance.create(':memory:');
  const conn = await instance.connect();
  try {
    return await fn(conn, file, dir);
  } finally {
    conn.closeSync();
    instance.closeSync();
    fs.rmSync(path.dirname(file), { recursive: true, force: true });
  }
}

/** How many events a scan of every field finds: the ground truth the index must agree with. */
function scanCount(word) {
  return withEvents(async (conn, file) => {
    const columns = manifest.columns.map((c) => `"${c.name.replaceAll('"', '""')}"`).join(', ');
    const sql = `SELECT count(*)::DOUBLE AS n FROM read_parquet('${file.replaceAll("'", "''")}') ` +
      `WHERE concat_ws(chr(31), ${columns}) ILIKE '%${word.replaceAll("'", "''")}%'`;
    return Number((await conn.runAndReadAll(sql)).getRowObjectsJS()[0].n);
  });
}

/** Hit events whose rule carries a tactic, and a technique: what the ATT&CK matrix must be able to show. */
function taggedHits() {
  return withEvents(async (conn, _file, dir) => {
    const read = (name) => `read_parquet('${path.join(dir, name).replaceAll("'", "''")}')`;
    const row = (await conn.runAndReadAll(
      `SELECT count(*) FILTER (WHERE len(r.tactics) > 0)::DOUBLE AS tactics, count(*) FILTER (WHERE len(r.techniques) > 0)::DOUBLE AS techniques ` +
      `FROM ${read('hits.parquet')} h JOIN ${read('rules.parquet')} r ON r.rule_idx = h.rule_idx`,
    )).getRowObjectsJS()[0];
    return { tactics: Number(row.tactics), techniques: Number(row.techniques) };
  }, ['hits.parquet', 'rules.parquet']);
}

/** Process starts in the package, counted on its own Parquet: what the tree must count with no filter. */
async function processStarts() {
  const names = new Map(manifest.columns.map((c) => [c.key, c.name]));
  const channel = names.get('channel');
  const eventid = names.get('eventid');
  if (!channel || !eventid) return 0;
  const c = `lower(CAST("${channel.replaceAll('"', '""')}" AS VARCHAR))`;
  const e = `CAST("${eventid.replaceAll('"', '""')}" AS VARCHAR)`;
  return withEvents(async (conn, file) => Number((await conn.runAndReadAll(
    `SELECT count(*)::DOUBLE AS n FROM read_parquet('${file.replaceAll("'", "''")}') WHERE ` +
    `(${c} IN ('microsoft-windows-sysmon/operational', 'linux-sysmon/operational') AND ${e} = '1') OR (${c} = 'security' AND ${e} = '4688')`,
  )).getRowObjectsJS()[0].n));
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

// Expands rules until two list alerts (or every rule is tried), then opens an alert in each within one
// task, so neither request has run when the other is made: each evidence list must hold the events
// its alert counted, or say how many it cut off.
async function correlationAlerts(page, state, steps) {
  await nav(page, 'Detections');
  await poll(page, () => number(page.locator('#detections-summary'), 'data-rules'), 'the detections');
  const rows = page.locator('button[data-key]');
  const total = await rows.count();
  const listing = [];
  for (let i = 0; i < total && listing.length < 2; i++) {
    const row = rows.nth(i);
    const item = row.locator('xpath=..');
    await row.click();
    const section = item.locator('section[aria-label="Correlation alerts"]');
    if ((await section.count()) === 0) {
      await row.click();
      continue;
    }
    await poll(page, async () => (await section.locator('p.note', { hasText: 'Reading the alerts' }).count()) === 0, 'the alerts');
    if ((await section.locator('button.alert').count()) > 0) listing.push(item);
    else await row.click();
  }
  check(listing.length > 0, `the package counts ${manifest.totals.alerts} alerts but no rule in Detections lists one`);
  const opened = [];
  for (const item of listing) {
    const alert = item.locator('button.alert').first();
    opened.push({ item, claimed: Number((await alert.locator('.n').textContent()).replace(/\D/g, '')) });
  }
  await page.locator('button[data-key][aria-expanded="true"]').first().evaluate(() => {
    for (const section of document.querySelectorAll('section[aria-label="Correlation alerts"]')) section.querySelector('button.alert')?.click();
  });
  await poll(page, async () => (await page.locator('p.note', { hasText: 'Reading the evidence' }).count()) === 0, 'the evidence', 15_000);
  for (const { item, claimed } of opened) {
    const items = item.locator('ol.evidence li');
    const cut = item.locator('p.note', { hasText: /^First [\d,. ]+ of / });
    if (claimed > 500) {
      check((await cut.count()) === 1, `the alert counts ${claimed} events and its evidence does not say it was cut off`);
    } else {
      check((await items.count()) === claimed, `the alert counts ${claimed} events; its evidence lists ${await items.count()}`);
    }
  }
  steps.push(`correlation alerts of ${opened.length} rules open at once, with ${opened.map((o) => o.claimed).join(' and ')} events of evidence`);
}

async function phase4(page, state, steps, expectedStarts) {
  const route = (hash) => page.goto(`${url}#/${hash}`);
  const clickAndCount = async (target, what) => {
    const expected = Number(await target.getAttribute('data-events'));
    await target.click();
    const listed = await reopened(page, state);
    check(listed.count === expected, `${what} counts ${expected}; Explore lists ${listed.count}`);
  };

  // ATT&CK: a technique, a tactic and an hour each list exactly their events. Each target is picked only
  // once its own panel has answered, and a check may skip only when the package holds nothing for it.
  const checks = [
    {
      what: 'a technique', expected: tagged.techniques,
      wait: async () => (await page.locator('#attack-matrix button[data-technique]').count()) > 0 || null,
      pick: '#attack-matrix button[data-technique]:not([data-events="0"])',
    },
    {
      what: 'a tactic', expected: tagged.tactics,
      wait: async () => {
        const counts = await page.locator('#attack-matrix button[data-tactic]').evaluateAll((all) => all.map((b) => b.getAttribute('data-events')));
        return counts.length > 0 && counts.every((c) => c !== null && c !== '') || null;
      },
      pick: '#attack-matrix button[data-tactic]:not([data-events="0"])',
    },
    {
      what: 'an hour of the heatmap', expected: manifest.totals.hits,
      wait: async () => (await page.locator('table.heatmap button[data-day]').count()) > 0 || null,
      pick: 'table.heatmap button[data-day]:not([disabled])',
    },
  ];
  for (const { what, expected, wait, pick } of checks) {
    await route('attack');
    await poll(page, () => number(page.locator('#attack-matrix'), 'data-techniques'), 'the ATT&CK matrix');
    // An empty package part never renders the panel, so the wait is only for a package that has something to show.
    if (expected > 0) await poll(page, wait, `the panel for ${what}`);
    const target = page.locator(pick).first();
    if ((await target.count()) === 0) {
      check(expected === 0, `ATT&CK shows nothing to check for ${what}, but the package holds ${expected} matching detections`);
      steps.push(`ATT&CK: nothing to check for ${what}`);
      continue;
    }
    await clickAndCount(target, what);
  }
  steps.push('ATT&CK checks ran: each technique, tactic and hour listed exactly its events, or the package held none');

  // Entities: the first host and the first user list exactly their events.
  for (const label of ['Hosts', 'Users']) {
    await route('entities');
    await page.getByRole('button', { name: label, exact: true }).click();
    const table = page.locator('#entities-table');
    if ((await table.count()) === 0) {
      steps.push(`entities: this package has no field for ${label.toLowerCase()}`);
      continue;
    }
    const rows = await poll(page, () => number(table, 'data-rows'), `the ${label.toLowerCase()}`);
    if (!rows) {
      steps.push(`entities: the ${label.toLowerCase()} table is empty`);
      continue;
    }
    await clickAndCount(page.locator('#entities-table button.value').first(), `the first of the ${label.toLowerCase()}`);
  }
  steps.push('entities list exactly their events');

  // Processes: the tree counts every process start, and a start opens as its event.
  await route('processes');
  const tree = page.locator('#process-tree');
  if ((await tree.count()) > 0) {
    const starts = await poll(page, async () => {
      const value = await tree.getAttribute('data-starts');
      return value === null || value === '' ? null : Number(value);
    }, 'the process tree');
    check(starts === expectedStarts, `the tree counts ${starts} process starts; the package holds ${expectedStarts}`);
    if (starts > 0) {
      await page.locator('[role="treeitem"]').first().click();
      const heading = page.locator('aside[aria-label="Event details"] h2');
      // The heading reads "Event" until the event itself has been read.
      const title = await poll(page, async () => {
        const text = ((await heading.textContent()) ?? '').trim();
        return text === 'Event' ? null : text;
      }, 'the event to open');
      check(/^(Microsoft-Windows-Sysmon\/Operational|Linux-Sysmon\/Operational) 1$|^Security 4688$/i.test(title), `a process start opens as "${title}"`);
      await page.keyboard.press('Escape');
    }
  }
  steps.push('the process tree counts every process start');

  // SQL: it counts the events, and refuses to drop them.
  await route('sql');
  const editor = page.locator('#sql-editor');
  const runSql = async (text) => {
    await editor.fill(text);
    await page.getByRole('button', { name: 'Run', exact: true }).click();
  };
  const firstCell = async () => {
    await poll(page, () => number(page.locator('#sql-result'), 'data-rows'), 'the SQL result');
    return Number(await page.locator('#sql-result [role="cell"]').first().textContent());
  };
  await runSql('SELECT count(*) AS n FROM events');
  check((await firstCell()) === manifest.totals.events, 'the SQL console does not count the package\'s events');
  await runSql('DROP TABLE events');
  await page.locator('p[role="alert"]', { hasText: 'The query did not run' }).waitFor();
  await runSql('SELECT count(*) AS n FROM events');
  check((await firstCell()) === manifest.totals.events, 'the events changed after the console refused a DROP');
  steps.push('the SQL console counts the events and refuses to change them');

  // Timeline: a lane holds exactly the events of its tactic in the window drawn.
  await route('timeline');
  const marks = page.locator('#timeline-marks');
  await poll(page, async () => ((await number(marks, 'data-count')) ?? 0) > 0, 'timeline marks');
  const from = await number(marks, 'data-from');
  const to = await number(marks, 'data-to');
  check(from !== null && to !== null, 'the timeline marks do not report the window they were drawn for');
  await page.getByRole('button', { name: 'List the marks' }).click();
  const lane = page.locator('h2[data-lane]:not([data-lane=""])').first();
  let laneChecked = false;
  if ((await lane.count()) > 0) {
    const tactic = await lane.getAttribute('data-lane');
    const events = Number(await lane.getAttribute('data-events'));
    await page.goto(`${url}#/explore?q=${encodeURIComponent(`tactic:${tactic}`)}&t=${from}~${to}`);
    const listed = await reopened(page, state);
    check(listed.count === events, `the ${tactic} lane holds ${events} events; Explore lists ${listed.count} in its window`);
    laneChecked = true;
  } else {
    check(tagged.tactics === 0, `the timeline lists no named lane, but ${tagged.tactics} detections carry a tactic`);
  }
  steps.push(laneChecked ? 'a timeline lane holds exactly its tactic\'s events in the window' : 'timeline lane skipped: no named tactic');
  await page.goto(`${url}#/explore`);
  await reopened(page, state);
}

async function scenario(page, open, steps, expectedText, expectedStarts) {
  const state = { build: 0 };
  await page.goto(`${url}#/overview`);
  await poll(page, async () => /ready|error/.test(await page.title()), 'the viewer', 240_000);
  check((await page.title()) === 'Zircolite — ready', `the viewer reports: ${await page.title()}`);

  const tiles = await poll(page, () => number(page.locator('#overview-tiles'), 'data-events'), 'the overview');
  await nav(page, 'Explore');
  const all = await reopened(page, state);
  check(tiles === all.detected, `the overview tiles hold ${tiles} events; Explore says ${all.detected} have detections`);
  steps.push('overview tiles add up to the events with detections');

  await nav(page, 'Overview');
  const cells = page.locator('section.tactics button.cell');
  await poll(page, async () => (await cells.count()) === manifest.tactics.length, 'the tactic cells');
  const cell = page.locator('section.tactics button.cell:not(.none)').first();
  if ((await cell.count()) > 0) {
    const tactic = await cell.getAttribute('data-tactic');
    const claimed = Number((await cell.locator('.count').textContent()).replace(/\D/g, ''));
    await cell.click();
    const byTactic = await reopened(page, state);
    check(byTactic.count === claimed, `the ${tactic} cell counts ${claimed} events; Explore lists ${byTactic.count}`);
    await search(page, state, '');
    steps.push(`a tactic cell lists exactly its events (${tactic}, ${claimed})`);
  } else {
    steps.push('tactic cell skipped: no tactic has events in this package');
  }

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

  await phase4(page, state, steps, expectedStarts);

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
const expectedStarts = await processStarts();
const tagged = await taggedHits();
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
    await scenario(await open(), open, steps, expectedText, expectedStarts);
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
