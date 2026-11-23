// The browsers the e2e scripts drive, and the runner that drives them side by
// side. Each browser gets its own pages and its own results, and the package is
// only read, so running them together changes nothing but the order of the
// output lines.
//
// Chromium and Firefox run by default; CI gives each its own job. WebKit is not
// driven in CI, but can still be named.
// ZL_BROWSERS=firefox picks the browsers, ZL_BROWSERS=webkit adds WebKit.
// ZL_BROWSER_JOBS=1 drives one browser at a time.
import { chromium, firefox, webkit } from 'playwright';

const KNOWN = { chromium, firefox, webkit };
const DEFAULT = ['chromium', 'firefox'];

export function selectedBrowsers(env = process.env) {
  const wanted = [...new Set((env.ZL_BROWSERS ?? '').split(',').map((name) => name.trim()).filter(Boolean))];
  const unknown = wanted.filter((name) => !Object.hasOwn(KNOWN, name));
  if (unknown.length) throw new Error(`ZL_BROWSERS names unknown browsers: ${unknown.join(', ')}`);
  return (wanted.length ? wanted : DEFAULT).map((name) => [name, KNOWN[name]]);
}

function browserJobs(env, count) {
  const value = env.ZL_BROWSER_JOBS;
  if (value === undefined || value === '') return count;
  // A typo must not leave zero workers, which would drive nothing and pass.
  if (!/^[1-9]\d*$/.test(value)) throw new Error(`ZL_BROWSER_JOBS must be a positive integer, not ${value}`);
  return Math.min(Number(value), count);
}

/** Runs `drive(name, browserType)` for every selected browser, at most ZL_BROWSER_JOBS at once. */
export async function forEachBrowser(drive, env = process.env) {
  const queue = selectedBrowsers(env);
  const jobs = browserJobs(env, queue.length);
  const worker = async () => {
    for (let next = queue.shift(); next; next = queue.shift()) await drive(...next);
  };
  await Promise.all(Array.from({ length: jobs }, worker));
}
