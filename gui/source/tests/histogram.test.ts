import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  barHeight, binAt, type BinRow, binsSql, binSummary, DOMAIN_SQL, domainOf, fill, formatRange, formatWidth,
  layout, rangeOf, stripRequest, stripSeries, timelessCount,
} from '../src/explore/histogram';
import { EVENT_LEVELS_SQL } from '../src/engine/sql';
import { compile } from '../src/search/compile';
import { parse } from '../src/search/parse';
import { type Fixture, openFixture, schema } from './fixture';

const H = 3_600_000;
const SIX = Date.UTC(2021, 5, 3, 6);

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

describe('layout', () => {
  it('picks the finest step that fits', () => {
    expect(layout([SIX, SIX + 2 * H], 240)).toEqual({ start: SIX, width: 60_000, count: 121 });
  });

  it('aligns the first bin to the step', () => {
    expect(layout([SIX + 1234, SIX + 50_000], 100)).toEqual({ start: SIX + 1000, width: 1000, count: 50 });
  });

  it('gives a single instant one bin', () => {
    expect(layout([SIX, SIX], 100)).toEqual({ start: SIX, width: 1000, count: 1 });
  });

  it('a layout over a narrow range gives finer bins', () => {
    const whole = layout([SIX, SIX + 2 * H], 240);
    const zoomed = layout([SIX, SIX + 60_000 - 1], 240);
    expect(zoomed).toEqual({ start: SIX, width: 1000, count: 60 });
    expect(zoomed.width).toBeLessThan(whole.width);
  });
});

describe('domainOf', () => {
  it('domainOf returns null without times', () => {
    expect(domainOf(undefined)).toBeNull();
    expect(domainOf({ lo: null, hi: null })).toBeNull();
  });

  it('reads the range', async () => {
    const [row] = await db.rows(DOMAIN_SQL);
    expect(domainOf(row as { lo: number | null; hi: number | null })).toEqual([SIX, SIX + 2 * H]);
  });
});

describe('bins against DuckDB', () => {
  const bins = { start: SIX, width: H, count: 3 };

  it('counts events and their highest detection level per bin, leaving timeless events out', async () => {
    expect(layout([SIX, SIX + 2 * H], 3)).toEqual(bins);
    expect(await db.rows(binsSql(bins, 'TRUE'))).toEqual([
      { b: 0, n: 3, l0: 1, l1: 0, l2: 1, l3: 0, l4: 0, lu: 0 },
      { b: 1, n: 1, l0: 0, l1: 0, l2: 0, l3: 0, l4: 1, lu: 0 },
      { b: 2, n: 1, l0: 0, l1: 0, l2: 0, l3: 0, l4: 0, lu: 0 },
    ]);
  });

  it('applies the filters', async () => {
    const rows = await db.rows(binsSql(bins, compile(parse('Computer:ws02'), schema)));
    expect(rows.map((r) => [r.b, r.n])).toEqual([[0, 1], [1, 1]]);
  });

  it('fills a series and sums a range of it', async () => {
    const series = fill((await db.rows(binsSql(bins, 'TRUE'))) as unknown as BinRow[], bins);
    expect(Array.from(series.n)).toEqual([3, 1, 1]);
    expect(binSummary(series, 1, 0)).toEqual({ range: [SIX, SIX + 2 * H], events: 4, levels: [1, 0, 1, 0, 1], unknown: 0 });
  });

  it('bounds the query to the layout, so a zoomed strip never sees events outside it', async () => {
    const zoomed = { start: SIX, width: 1000, count: 60 };
    const rows = (await db.rows(binsSql(zoomed, 'TRUE'))) as unknown as BinRow[];
    expect(rows.map((r) => [r.b, r.n])).toEqual([[0, 1], [30, 1]]);
    expect(Array.from(fill(rows, zoomed).n).reduce((sum, n) => sum + n, 0)).toBe(2);
    const uids = await db.rows(
      `SELECT _zl_uid FROM events WHERE ${binsSql(zoomed, 'TRUE').split(' WHERE ')[1].split(' GROUP BY')[0]} ORDER BY _zl_uid`,
    );
    expect(uids.map((r) => r._zl_uid)).toEqual([1, 2]);
  });

  it('refuses a bin outside the layout', () => {
    expect(() => fill([{ b: 3, n: 1, l0: 0, l1: 0, l2: 0, l3: 0, l4: 0, lu: 0 }], bins)).toThrowError(/outside/);
  });
});

describe('strip requests', () => {
  const hours = { start: SIX, width: H, count: 3 };
  const minutes = { start: SIX, width: 60_000, count: 121 };

  it('fills each result with the bins it was asked with, whichever answers last', async () => {
    const coarse = stripRequest(hours, 'TRUE');
    const fine = stripRequest(minutes, 'TRUE');
    const fineRows = (await db.rows(fine.sql)) as unknown as BinRow[];
    const coarseRows = (await db.rows(coarse.sql)) as unknown as BinRow[];
    const a = stripSeries(coarse, coarseRows);
    const b = stripSeries(fine, fineRows);
    expect(a.bins).toBe(hours);
    expect(Array.from(a.n)).toEqual([3, 1, 1]);
    expect(b.bins).toBe(minutes);
    expect([b.n[0], b.n[5], b.n[60], b.n[120]]).toEqual([2, 1, 1, 1]);
  });

  it('a result read against another request\'s bins is refused, never drawn', async () => {
    const fine = stripRequest(minutes, 'TRUE');
    const rows = (await db.rows(fine.sql)) as unknown as BinRow[];
    expect(() => stripSeries(stripRequest(hours, 'TRUE'), rows)).toThrowError(/outside/);
  });
});

describe('pixels and labels', () => {
  it('maps pointer positions to bins, clamped', () => {
    expect([binAt(0, 300, 3), binAt(299.9, 300, 3), binAt(-5, 300, 3), binAt(400, 300, 3)]).toEqual([0, 2, 0, 2]);
  });

  it('turns bins into a half-open time range, in either drag direction', () => {
    expect(rangeOf({ start: SIX, width: H, count: 3 }, 2, 1)).toEqual([SIX + H, SIX + 3 * H]);
  });

  it('keeps small non-zero bars visible', () => {
    expect([barHeight(0, 10, 64, 1), barHeight(10, 10, 64, 1), barHeight(1, 1e6, 64, 1)]).toEqual([0, 64, 1]);
  });

  it('names bin widths and ranges', () => {
    expect([formatWidth(1000), formatWidth(60_000), formatWidth(900_000), formatWidth(H), formatWidth(7 * 86_400_000)])
      .toEqual(['1 second', '1 minute', '15 minutes', '1 hour', '7 days']);
    expect(formatRange([SIX, SIX + H])).toBe('2021-06-03 06:00:00 to 07:00:00');
    expect(formatRange([SIX, SIX + 24 * H])).toBe('2021-06-03 06:00:00 to 2021-06-04 06:00:00');
  });

  it('counts the events that have no time', () => {
    const parts = [{ time: { missing: 2, unparsed: 1 } }, { time: { missing: 0, unparsed: 0 } }];
    expect(timelessCount({ parts } as never)).toBe(3);
  });
});

describe('events whose rule has no level', () => {
  it('are carried beside the ranks, and summed with them', () => {
    const bins = { start: SIX, width: H, count: 2 };
    const series = fill([{ b: 0, n: 3, l0: 1, l1: 0, l2: 0, l3: 0, l4: 0, lu: 2 }, { b: 1, n: 1, l0: 0, l1: 0, l2: 0, l3: 0, l4: 0, lu: 1 }], bins);
    expect(Array.from(series.unknown)).toEqual([2, 1]);
    expect(binSummary(series, 0, 1).unknown).toBe(3);
  });

  it('are counted by the query', () => {
    expect(binsSql({ start: SIX, width: H, count: 2 }, 'TRUE')).toContain('FILTER (WHERE _zl_lvl = -1)::DOUBLE AS lu');
  });
});

describe('the strip against DuckDB with an unlevelled rule', () => {
  it('counts every detected event in exactly one level, unknown included', async () => {
    const fx = await openFixture();
    try {
      await fx.rows(`INSERT INTO rules VALUES (9, 'r-none', 'r-none', 'No level', NULL, -1, 'd', [], [], [], [], 'n.yml', 'match', 0)`);
      await fx.rows('INSERT INTO hits VALUES (9, 2)');
      await fx.rows('DROP TABLE event_levels');
      await fx.rows(EVENT_LEVELS_SQL.replace('TEMP ', ''));
      const rows = (await fx.rows(binsSql({ start: SIX, width: H, count: 3 }, 'TRUE'))) as unknown as BinRow[];
      expect(rows[0].lu).toBe(1);
      const detected = (await fx.rows('SELECT count(*)::DOUBLE AS n FROM events JOIN event_levels USING (_zl_uid) WHERE _zl_time IS NOT NULL'))[0].n;
      const counted = rows.reduce((sum, r) => sum + r.l0 + r.l1 + r.l2 + r.l3 + r.l4 + r.lu, 0);
      expect(counted).toBe(detected);
    } finally {
      fx.close();
    }
  });
});
