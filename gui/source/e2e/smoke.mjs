// Opens an unpacked package from file:// in Chromium, Firefox and WebKit and
// checks that the query engine holds the events the manifest lists, with no
// network request and no page error. Usage: npm run smoke -- <unpacked package dir>
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium, firefox, webkit } from 'playwright';

const directory = process.argv[2];
if (!directory) {
  console.error('usage: npm run smoke -- <unpacked package directory>');
  process.exit(2);
}
const url = pathToFileURL(path.resolve(directory, 'index.html')).href;
let failed = false;
for (const [name, type] of [['chromium', chromium], ['firefox', firefox], ['webkit', webkit]]) {
  const browser = await type.launch();
  try {
    const page = await browser.newPage();
    const errors = [];
    const requests = [];
    page.on('pageerror', (error) => errors.push(String(error)));
    page.on('request', (request) => {
      if (!/^(file|data|blob):/.test(request.url())) requests.push(request.url());
    });
    const started = Date.now();
    await page.goto(url);
    // The page's CSP forbids eval, which waitForFunction relies on: poll instead.
    let title = '';
    while (Date.now() - started < 180_000) {
      title = await page.title();
      if (/ready|error/.test(title)) break;
      await page.waitForTimeout(250);
    }
    const check = page.locator('#engine-check');
    const events = await check.getAttribute('data-events');
    const expected = await check.getAttribute('data-expected');
    const ok = title === 'Zircolite — ready' && events === expected && errors.length === 0 && requests.length === 0;
    console.log(JSON.stringify({ browser: name, ok, title, events, expected, seconds: (Date.now() - started) / 1000, errors, requests }));
    failed ||= !ok;
  } finally {
    await browser.close();
  }
}
process.exit(failed ? 1 : 0);
