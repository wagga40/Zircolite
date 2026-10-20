// Times loading, Explore's main interactions, every view and full-text search on a large
// package in Chromium, for the budgets in the design spec. Usage: npm run perf -- <unpacked package dir>
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';

const directory = process.argv[2];
if (!directory) {
  console.error('usage: npm run perf -- <unpacked package directory>');
  process.exit(2);
}

function readManifest() {
  const text = fs.readFileSync(path.join(directory, 'data/manifest.js'), 'utf8');
  return JSON.parse(text.slice(text.indexOf('(') + 1, text.lastIndexOf(')')));
}

async function poll(page, read, timeout = 300_000) {
  const started = Date.now();
  for (;;) {
    const value = await read();
    if (value) return value;
    if (Date.now() - started > timeout) throw new Error('timed out');
    await page.waitForTimeout(20);
  }
}

const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const out = page.locator('#result-count');
  let build = 0;
  const settled = async () => {
    await poll(page, async () => {
      const [b, busy] = await Promise.all([out.getAttribute('data-build'), out.getAttribute('data-busy')]);
      if (busy !== 'false' || Number(b) <= build) return false;
      build = Number(b);
      return true;
    });
  };
  const timed = async (act, until) => {
    const started = performance.now();
    await act();
    await until();
    return Math.round(performance.now() - started);
  };
  const search = (text) => timed(async () => {
    await page.locator('#search-input').fill(text);
    await page.locator('#search-input').press('Enter');
  }, settled);

  const report = {};
  const started = performance.now();
  const base = pathToFileURL(path.resolve(directory, 'index.html')).href;
  await page.goto(`${base}#/explore`);
  await poll(page, async () => /ready|error/.test(await page.title()));
  report.ready_ms = Math.round(performance.now() - started);
  report.title = await page.title();
  await settled();
  report.first_results_ms = Math.round(performance.now() - started);
  report.events = Number(await out.getAttribute('data-count'));
  const manifest = readManifest();
  const bytesOf = (name) => manifest.files.find((file) => file.name === name)?.bytes ?? null;
  report.events_parquet_bytes = bytesOf('events.parquet');
  report.text_parquet_bytes = bytesOf('text.parquet');

  // 1.87M rows at 28 px is far past the height cap, so a wheel turn must move rows, not thousands of them.
  // The position is the first rendered row plus how far the strip sits into the next one.
  const where = () => page.evaluate(() => {
    const scroller = document.querySelector('#result-grid');
    const rows = scroller.querySelector('.rows');
    const first = Math.min(...[...rows.children].map((row) => Number(row.getAttribute('aria-rowindex')) - 2));
    const lift = Number(/translateY\(([-\d.]+)px\)/.exec(rows.style.transform)?.[1] ?? 0);
    return first + (scroller.scrollTop - lift) / 28;
  });
  const wheel = (deltaY) => page.evaluate((delta) => {
    document.querySelector('#result-grid').dispatchEvent(new WheelEvent('wheel', { deltaY: delta, deltaMode: 0, bubbles: true, cancelable: true }));
  }, deltaY);
  const wheelStart = await where();
  await wheel(84);
  await page.waitForTimeout(100);
  const afterNotch = await where();
  report.wheel_notch_rows = Math.round((afterNotch - wheelStart) * 100) / 100;
  if (Math.abs(report.wheel_notch_rows - 3) > 1) throw new Error(`a 84 px wheel turn moved ${report.wheel_notch_rows} rows past the height cap, not about 3`);
  for (let i = 0; i < 20; i++) await wheel(1);
  await page.waitForTimeout(100);
  report.wheel_slow_rows = Math.round(((await where()) - afterNotch) * 100) / 100;
  // 20 px is 20/28 of a row; scrollTop holds whole pixels, which past the cap are 0.23 of a row each.
  if (report.wheel_slow_rows < 0.4 || report.wheel_slow_rows > 1.05) throw new Error(`twenty 1 px wheel turns moved ${report.wheel_slow_rows} rows past the height cap, not about 0.71`);

  report.field_search_ms = await search('EventID:4624');
  report.negated_search_ms = await search('-EventID:4624');
  report.clear_ms = await search('');
  report.detections_only_ms = await timed(() => page.getByRole('button', { name: 'Detections only' }).click(), settled);
  await page.getByRole('button', { name: 'Detections only' }).click();
  await settled();
  const box = await page.locator('#seismic-strip').boundingBox();
  // Real corpora hold a few events with stray years, so the middle of the strip can be empty. The
  // last tenth is where the events are; that is the brush a responder would make.
  report.brush_ms = await timed(async () => {
    await page.mouse.move(box.x + box.width * 0.9, box.y + 40);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width * 0.98, box.y + 40);
    await page.mouse.up();
  }, settled);
  report.brush_events = Number(await out.getAttribute('data-count'));
  if (!report.brush_events) throw new Error('the brush selected no event, so its time measures nothing');
  await page.goBack();
  await settled();
  await page.locator('#result-grid').focus();
  const drawer = page.getByRole('complementary', { name: 'Event details' });
  report.open_event_ms = await timed(() => page.keyboard.press('Enter'), () => poll(page, async () => (await drawer.locator('dt').count()) > 0));
  await page.keyboard.press('Escape');
  await page.locator('#result-grid').focus();
  const last = page.locator(`#result-grid [role=row][aria-rowindex="${report.events + 1}"]`);
  report.end_of_list_ms = await timed(() => page.keyboard.press('End'), () =>
    poll(page, async () => (await last.count()) > 0 && (await last.locator('[role=gridcell]').first().textContent()) !== 'Loading'));

  // Column filters, menus and sorts, on the columns a responder filters first. A cell applies on Enter.
  await page.goto(`${base}#/explore?cols=Computer,Channel,EventID,CommandLine,Message`);
  const cell = (name) => page.getByLabel(`Filter ${name}`, { exact: true });
  await cell('EventID').waitFor();
  const applyCell = (name, text) => timed(async () => {
    await cell(name).fill(text);
    await cell(name).press('Enter');
  }, settled);
  report.filter_cell_equals_ms = await applyCell('EventID', '=4624');
  await applyCell('EventID', '');
  report.filter_cell_contains_ms = await applyCell('CommandLine', 'powershell');
  // A person brushes once the strip has drawn the filtered events.
  await poll(page, async () => (await page.locator('#seismic-strip').getAttribute('aria-busy')) !== 'true'
    && (await page.locator('.plot[aria-busy="true"]').count()) === 0);
  report.brush_with_contains_ms = await timed(async () => {
    await page.mouse.move(box.x + box.width * 0.9, box.y + 40);
    await page.mouse.down();
    await page.mouse.move(box.x + box.width * 0.98, box.y + 40);
    await page.mouse.up();
  }, settled);
  await page.goBack();
  await settled();
  await applyCell('CommandLine', '');
  report.filter_cell_contains_long_ms = await applyCell('Message', 'error');
  await applyCell('Message', '');
  const menuValues = async (key) => timed(() => page.locator(`[data-column-funnel="${key}"]`).click(), () =>
    poll(page, async () => (await page.locator('[data-column-menu] li[data-value]').count()) > 0
      && (await page.locator('[data-column-menu] section[aria-busy="false"]').count()) > 0));
  report.column_values_ms = await menuValues('channel');
  await page.keyboard.press('Escape');
  report.column_values_wide_ms = await menuValues('commandline');
  await page.keyboard.press('Escape');
  const sortBy = (key) => timed(() => page.locator(`[data-field-key="${key}"] button.sort`).click(), settled);
  report.sort_text_ms = await sortBy('computer');
  report.sort_long_text_ms = await sortBy('commandline');
  report.sort_message_ms = await sortBy('message');
  report.sort_level_ms = await timed(() => page.locator('#result-grid button.sort', { hasText: 'Level' }).click(), settled);
  await timed(() => page.locator('#result-grid button.sort', { hasText: 'Time (UTC)' }).click(), settled);
  await page.goto(`${base}#/explore`);

  const nav = (name) => page.locator('nav[aria-label="Views"] button', { hasText: name }).click();
  const filled = (selector, attribute) => () => poll(page, async () => {
    const value = await page.locator(selector).getAttribute(attribute);
    return value !== null && value !== '';
  });
  report.overview_ms = await timed(() => nav('Overview'), filled('#overview-tiles', 'data-events'));
  report.detections_ms = await timed(() => nav('Detections'), filled('#detections-summary', 'data-rules'));
  report.timeline_ms = await timed(() => nav('Timeline'), filled('#timeline-marks', 'data-count'));
  report.attack_ms = await timed(() => nav('ATT&CK'), filled('#attack-matrix', 'data-techniques'));
  report.entities_ms = await timed(() => nav('Entities'), filled('#entities-table', 'data-rows'));
  report.processes_ms = await timed(() => nav('Processes'), filled('#process-tree', 'data-starts'));
  report.sql_count_ms = await timed(async () => {
    await nav('SQL');
    await page.locator('#sql-editor').fill('SELECT count(*) AS n FROM events');
    await page.getByRole('button', { name: 'Run', exact: true }).click();
  }, filled('#sql-result', 'data-rows'));
  // A table that answered: busy no more, with a row count. Tables clear the count as soon as they are asked again.
  const answered = (selector) => () => poll(page, async () => {
    const table = page.locator(selector);
    return (await table.getAttribute('aria-busy')) === 'false' && (await table.getAttribute('data-rows')) !== '';
  });
  const typeInCell = (label, text, selector) => timed(async () => {
    await page.getByLabel(`Filter ${label}`, { exact: true }).fill(text);
    await page.getByLabel(`Filter ${label}`, { exact: true }).press('Enter');
  }, answered(selector));
  await nav('Entities');
  await answered('#entities-table')();
  report.entities_filter_ms = await typeInCell('Events', '>=100', '#entities-table');
  report.sql_filter_ms = await (async () => {
    await nav('SQL');
    await page.locator('#sql-editor').fill('SELECT "Computer", "EventID", count(*) AS n FROM events GROUP BY ALL');
    await page.getByRole('button', { name: 'Run', exact: true }).click();
    await filled('#sql-result', 'data-rows')();
    return timed(async () => {
      await page.getByLabel('Filter n', { exact: true }).fill('>=100');
      await page.getByLabel('Filter n', { exact: true }).press('Enter');
    }, () => poll(page, async () => (await page.locator('#sql-result').getAttribute('aria-busy')) === 'false'
      && (await page.locator('#sql-result').getAttribute('data-rows')) !== ''));
  })();
  report.stack_one_ms = await timed(() => nav('Stacking'), answered('#stacking-table'));
  const pair = page.locator('[aria-label="Stack"] button', { hasText: '+' }).first();
  if (await pair.count()) {
    report.stack_two_fields = await pair.textContent();
    report.stack_two_ms = await timed(() => pair.click(), answered('#stacking-table'));
  }
  // In the order the view asks for them: one connection answers them one after the other, so each time is
  // when that table filled in.
  const logonTables = ['#lateral-table', '#logons-table', '#explicit-table', '#rdp-table', '#sessions-table'];
  const logonsStarted = performance.now();
  report.logons_tables_ms = {};
  report.logons_ms = await timed(() => nav('Logons'), async () => {
    for (const table of logonTables) {
      if (!(await page.locator(table).count())) continue;
      await answered(table)();
      report.logons_tables_ms[table.slice(1)] = Math.round(performance.now() - logonsStarted);
    }
  });
  await nav('Explore');
  build = 0;
  await settled();
  const indexStarted = performance.now();
  await poll(page, async () => (await page.locator('#engine-check').getAttribute('data-text-index')) === 'ready');
  report.text_index_wait_ms = Math.round(performance.now() - indexStarted);
  report.full_text_indexed_ms = await search('powershell');
  await page.locator('#search-input').fill('mimikatz');
  await page.locator('#search-input').press('Enter');
  await page.waitForTimeout(300);
  report.supersede_ms = await search('EventID:4624');
  report.supersede_events = Number(await out.getAttribute('data-count'));

  // Stop on searches the engine really needs seconds for. Not a budget: it shows whether Stop reaches the
  // engine or only the page. A wildcard between letters of a long text field is the slowest scan of the
  // events; a bare word is the slowest scan of the full-text index. The index keeps each word's matches, so
  // its reference and midway runs spell the same word as other patterns, which scan on their own.
  const stopButton = page.getByRole('button', { name: 'Stop', exact: true });
  const stopped = page.locator('p.stopped');
  const cheap = 'EventID:4624';
  const stopReport = {};
  // Both build their matches once, in slices, so stopping partway leaves the rest of the scan for Run again
  // to resume.
  // A field scan on a large column also keeps its matches, so its three runs spell one pattern three ways.
  const cases = [
    { name: 'wildcard', query: 'Message:*a*b*c*', reference: 'Message:**a*b*c*', again: 'Message:*a*b*c**', midway: 0.5 },
    { name: 'index', query: 'ntlm', reference: '*ntlm*', again: 'ntlm*', midway: 0.5 },
  ];
  for (const { name, query, reference = query, again = query, midway } of cases) {
    const entry = { query };
    stopReport[name] = entry;
    entry.full_ms = await search(reference);
    entry.events = Number(await out.getAttribute('data-count'));
    if (!entry.events) throw new Error(`${reference} matched nothing, so Run again has no count to agree with`);
    await search('');
    if (entry.full_ms < 1000) {
      entry.note = 'skipped: the search finished in under a second';
      continue;
    }
    const begin = async (text, waitMs) => {
      await page.locator('#search-input').fill(text);
      await page.locator('#search-input').press('Enter');
      await page.waitForTimeout(waitMs);
      await stopButton.waitFor({ timeout: 5000 }).catch((e) => { console.log(JSON.stringify({ name, text, waitMs, entry })); throw e; });
    };
    await begin(query, 200);
    const clicked = performance.now();
    await stopButton.click();
    await stopped.waitFor();
    entry.stop_ms = Math.round(performance.now() - clicked);
    // How long a cheap search waits after Stop: about full_ms means the engine kept running.
    entry.next_query_after_stop_ms = await search(cheap);
    await search('');
    // Stopped partway through its run, so Run again starts from a part-built state.
    entry.midway = midway;
    await begin(again, Math.round(entry.full_ms * midway));
    const clickedMidway = performance.now();
    await stopButton.click();
    await stopped.waitFor();
    entry.stop_midway_ms = Math.round(performance.now() - clickedMidway);
    entry.run_again_ms = await timed(() => stopped.getByRole('button', { name: 'Run again' }).click(), settled);
    entry.run_again_events = Number(await out.getAttribute('data-count'));
    if (entry.run_again_events !== entry.events) throw new Error(`Run again lists ${entry.run_again_events} events for ${query}; the search listed ${entry.events}`);
    await search('');
  }
  report.stop = stopReport;

  // Leaving Explore while a field scan runs, for an Overview with a cheap search it has not answered before,
  // so its queries go through the queue rather than the cache. The scan's table, strip and count each read
  // every event (stop.wildcard.full_ms for all three); Overview must not wait for them.
  await page.locator('#search-input').fill('Message:*c*b*a*');
  await page.locator('#search-input').press('Enter');
  await page.waitForTimeout(1000);
  report.leave_search_overview_ms = await timed(() => page.goto(`${base}#/overview?q=EventID%3A4625`), filled('#overview-tiles', 'data-events'));
  report.leave_search_overview_events = Number(await page.locator('#overview-tiles').getAttribute('data-events'));

  // The activity bar on a view with no Stop of its own: how soon it shows once the tree is asked for under a
  // search not answered before, and whether its Stop reaches the tree. Not a budget.
  const busy = page.locator('#page-busy');
  const treeStopped = page.locator('main.processes p.note', { hasText: 'Stopped.' });
  await poll(page, async () => (await busy.count()) === 0, 60_000);
  report.busy_bar_shown_ms = await timed(() => page.goto(`${base}#/processes?q=-EventID%3A4625`), () => busy.waitFor({ timeout: 10_000 }));
  report.busy_bar_stop_ms = await timed(() => busy.getByRole('button', { name: 'Stop' }).click(), () => treeStopped.waitFor({ timeout: 10_000 }));
  await poll(page, async () => (await busy.count()) === 0, 10_000);
  report.busy_bar_run_again_ms = await timed(() => page.locator('main.processes').getByRole('button', { name: 'Run again' }).click(),
    filled('#process-tree', 'data-starts'));
  await page.close();

  // A bookmark or Back with a bare word: the page opens on Overview before the index has loaded, and every
  // query of the view needs the word. Timed from opening the page until the severity tiles are counted.
  const fresh = await browser.newPage({ viewport: { width: 1440, height: 900 } });
  const reopened = performance.now();
  await fresh.goto(`${base}#/overview?q=powershell`);
  await poll(fresh, async () => {
    const value = await fresh.locator('#overview-tiles').getAttribute('data-events');
    return value !== null && value !== '';
  });
  report.overview_reload_bare_word_ms = Math.round(performance.now() - reopened);
  report.overview_reload_bare_word_events = Number(await fresh.locator('#overview-tiles').getAttribute('data-events'));
  console.log(JSON.stringify(report, null, 2));
} finally {
  await browser.close();
}
