// Times Explore's main interactions on a large package in Chromium, for the budgets in the
// design spec. Usage: npm run perf -- <unpacked package dir>
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';

const directory = process.argv[2];
if (!directory) {
  console.error('usage: npm run perf -- <unpacked package directory>');
  process.exit(2);
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
  await page.goto(pathToFileURL(path.resolve(directory, 'index.html')).href + '#/explore');
  await poll(page, async () => /ready|error/.test(await page.title()));
  report.ready_ms = Math.round(performance.now() - started);
  report.title = await page.title();
  await settled();
  report.first_results_ms = Math.round(performance.now() - started);
  report.events = Number(await out.getAttribute('data-count'));
  report.field_search_ms = await search('EventID:4624');
  report.negated_search_ms = await search('-EventID:4624');
  report.full_text_ms = await search('powershell');
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
  console.log(JSON.stringify(report, null, 2));
} finally {
  await browser.close();
}
