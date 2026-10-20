import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Activity } from '../src/engine/queries';
import { activityText, BusyClock, HIDE_AFTER, SHOW_AFTER } from '../src/ui/busy.svelte';
import { formatBytes, formatElapsed, formatPercent } from '../src/ui/format';
import { BOOT_STEPS, chunkWeights } from '../src/ui/loading';

const IDLE: Activity = { queries: 0, scan: null, waiting: false };

describe('the busy clock', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('shows the page busy only once it has worked for a while, so a quick answer does not flash it', () => {
    const clock = new BusyClock();
    clock.set(true);
    vi.advanceTimersByTime(SHOW_AFTER - 1);
    expect(clock.shown).toBe(false);
    vi.advanceTimersByTime(1);
    expect(clock.shown).toBe(true);
  });

  it('never shows a busy spell shorter than the delay, even one that ends just before it', () => {
    const clock = new BusyClock();
    clock.set(true);
    vi.advanceTimersByTime(SHOW_AFTER - 50);
    clock.set(false);
    vi.advanceTimersByTime(HIDE_AFTER + SHOW_AFTER);
    expect(clock.shown).toBe(false);
    expect(clock.since).toBeNull();
  });

  it('stays through the short gap between one query and the next it leads to, and keeps counting from the first', () => {
    const clock = new BusyClock();
    const start = Date.now();
    clock.set(true);
    vi.advanceTimersByTime(SHOW_AFTER + 100);
    clock.set(false);
    vi.advanceTimersByTime(HIDE_AFTER - 1);
    expect(clock.shown).toBe(true);
    clock.set(true);
    vi.advanceTimersByTime(HIDE_AFTER * 3);
    expect(clock.shown).toBe(true);
    expect(clock.since).toBe(start);
  });

  it('hides once the page has been idle for the gap, and starts over on the next query', () => {
    const clock = new BusyClock();
    clock.set(true);
    vi.advanceTimersByTime(SHOW_AFTER);
    clock.set(false);
    vi.advanceTimersByTime(HIDE_AFTER);
    expect(clock.shown).toBe(false);
    expect(clock.since).toBeNull();
    const again = Date.now();
    clock.set(true);
    expect(clock.since).toBe(again);
    expect(clock.shown).toBe(false);
  });

  it('shows at once when work resumes after the delay passed in a gap', () => {
    const clock = new BusyClock();
    clock.set(true);
    vi.advanceTimersByTime(SHOW_AFTER - 50);
    clock.set(false);
    vi.advanceTimersByTime(100);
    clock.set(true);
    vi.advanceTimersByTime(0);
    expect(clock.shown).toBe(true);
  });

  it('leaves no timer behind once disposed', () => {
    const clock = new BusyClock();
    clock.set(true);
    clock.dispose();
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('what the activity bar says', () => {
  const index = { loaded: 0, total: 0 };

  it('says the page works when it knows no more', () => {
    expect(activityText({ ...IDLE, queries: 3 }, index)).toEqual({ label: 'Working', fraction: null });
  });

  it('gives a scan of a whole file its label and how far it has got', () => {
    const scan = { label: 'Searching CommandLine', done: 3, total: 12 };
    expect(activityText({ ...IDLE, queries: 1, scan }, index)).toEqual({ label: 'Searching CommandLine', fraction: 0.25 });
  });

  it('says a query waits for the full-text index, and how much of it has loaded', () => {
    expect(activityText({ ...IDLE, queries: 1, waiting: true }, { loaded: 4, total: 10 })).toEqual({ label: 'Loading the full-text index', fraction: 0.4 });
    expect(activityText({ ...IDLE, queries: 1, waiting: true }, index)).toEqual({ label: 'Loading the full-text index', fraction: null });
  });
});

describe('progress formats', () => {
  it('writes elapsed time in seconds, then minutes, then hours', () => {
    expect(formatElapsed(999)).toBe('0 s');
    expect(formatElapsed(4_200)).toBe('4 s');
    expect(formatElapsed(65_000)).toBe('1 min 05 s');
    expect(formatElapsed(3_600_000 + 7 * 60_000)).toBe('1 h 07 min');
  });

  it('writes sizes in decimal units, with one decimal below ten', () => {
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1_500)).toBe('1.5 kB');
    expect(formatBytes(38_400_000)).toBe('38 MB');
    expect(formatBytes(2_340_000_000)).toBe('2.3 GB');
  });

  it('writes a fraction as a whole percentage that reaches 100 only when done', () => {
    expect(formatPercent(0)).toBe('0%');
    expect(formatPercent(0.999)).toBe('99%');
    expect(formatPercent(1)).toBe('100%');
  });
});

describe('the loading screen', () => {
  it('counts the data in bytes, each script of a file carrying its share', () => {
    const weights = chunkWeights([
      { name: 'events.parquet', kind: 'data', bytes: 300, chunks: ['data/e.0000.js', 'data/e.0001.js', 'data/e.0002.js'] },
      { name: 'text.parquet', kind: 'index', bytes: 999, chunks: ['data/t.0000.js'] },
      { name: 'duckdb-eh.wasm.gz', kind: 'engine', bytes: 5, chunks: ['data/r.0000.js'] },
    ]);
    expect([...weights]).toEqual([['data/e.0000.js', 100], ['data/e.0001.js', 100], ['data/e.0002.js', 100], ['data/r.0000.js', 5]]);
  });

  it('lists the steps in the order the page takes them', () => {
    expect(BOOT_STEPS).toEqual([
      'Reading the package', 'Loading the data', 'Starting the query engine', 'Loading Parquet support', 'Opening the data',
      'Linking detections to their events', 'Checking the package',
    ]);
  });
});
