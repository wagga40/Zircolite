// Screenshots an unpacked package in Chromium for visual review.
// Usage: npm run shot -- <unpacked dir> <out.png> [--width N] [--theme light|dark] [--hash '#/overview?...'] (default #/explore) [--open-first]
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { chromium } from 'playwright';

const [directory, out, ...rest] = process.argv.slice(2);
if (!directory || !out) {
  console.error('usage: npm run shot -- <unpacked dir> <out.png> [--width N] [--theme light|dark] [--hash H] [--open-first]');
  process.exit(2);
}
const option = (name, fallback) => {
  const at = rest.indexOf(name);
  return at >= 0 ? rest[at + 1] : fallback;
};
const width = Number(option('--width', '1440'));
const theme = option('--theme', 'light');
const hash = option('--hash', '#/explore');
const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width, height: width < 600 ? 844 : 900 }, colorScheme: theme });
  await page.goto(pathToFileURL(path.resolve(directory, 'index.html')).href + hash);
  // The CSP forbids the eval that waitForFunction needs: poll the title.
  const started = Date.now();
  while (!/ready|error/.test(await page.title())) {
    if (Date.now() - started > 180_000) throw new Error('the viewer did not become ready');
    await page.waitForTimeout(250);
  }
  // Before Task 7 there is no table to wait for.
  const count = page.locator('#result-count');
  while ((await count.count()) > 0 && (await count.getAttribute('data-busy')) !== 'false') {
    if (Date.now() - started > 180_000) throw new Error('the results did not settle');
    await page.waitForTimeout(100);
  }
  if (rest.includes('--open-first')) {
    const first = page.locator('#row-0 [role=gridcell]').first();
    while ((await first.count()) === 0 || (await first.textContent()) === 'Loading') {
      if (Date.now() - started > 180_000) throw new Error('the first row did not load');
      await page.waitForTimeout(100);
    }
    await page.locator('#result-grid').focus();
    await page.keyboard.press('Enter');
  }
  await page.waitForTimeout(1500);
  await page.screenshot({ path: out });
  console.log(out);
} finally {
  await browser.close();
}
