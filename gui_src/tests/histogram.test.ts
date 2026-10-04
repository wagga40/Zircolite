import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  barHeight, binAt, type BinRow, binsSql, binSummary, DOMAIN_SQL, domainOf, fill, formatRange, formatWidth,
  layout, rangeOf, timelessCount,
} from '../src/explore/histogram';
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
      { b: 0, n: 3, l0: 1, l1: 0, l2: 1, l3: 0, l4: 0 },
      { b: 1, n: 1, l0: 0, l1: 0, l2: 0, l3: 0, l4: 1 },
      { b: 2, n: 1, l0: 0, l1: 0, l2: 0, l3: 0, l4: 0 },
    ]);
  });

  it('applies the filters', async () => {
    const rows = await db.rows(binsSql(bins, compile(parse('Computer:ws02'), schema)));
    expect(rows.map((r) => [r.b, r.n])).toEqual([[0, 1], [1, 1]]);
  });

  it('fills a series and sums a range of it', async () => {
    const series = fill((await db.rows(binsSql(bins, 'TRUE'))) as unknown as BinRow[], bins);
    expect(Array.from(series.n)).toEqual([3, 1, 1]);
    expect(binSummary(series, 1, 0)).toEqual({ range: [SIX, SIX + 2 * H], events: 4, levels: [1, 0, 1, 0, 1] });
  });

  it('refuses a bin outside the layout', () => {
    expect(() => fill([{ b: 3, n: 1, l0: 0, l1: 0, l2: 0, l3: 0, l4: 0 }], bins)).toThrowError(/outside/);
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
