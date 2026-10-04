import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  bucketMs, EXTENT_SQL, formatTick, hit, laneLabel, lanes, laneY, type Mark, marksSql, PAD_L, pan, place, showFilter, tickStep,
  ticks, zoomAt,
} from '../src/timeline/timeline';
import { compile } from '../src/search/compile';
import { parse } from '../src/search/parse';
import { timePredicate } from '../src/state/where';
import { type Fixture, openFixture, schema, TACTICS } from './fixture';

const SIX = Date.UTC(2021, 5, 3, 6);
const H = 3_600_000;
const DAY = 24 * H;

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

describe('axis', () => {
  it('steps so about ten labels fit', () => {
    expect(tickStep(10 * 60_000)).toBe(60_000);
    expect(tickStep(3 * H)).toBe(1_800_000);
  });

  it('places ticks on round times, and never too many', () => {
    expect(ticks({ from: SIX + 1, to: SIX + 3 * H })).toEqual([1, 2, 3, 4, 5, 6].map((i) => SIX + i * 1_800_000));
    expect(ticks({ from: 0, to: 1e18 }).length).toBeLessThanOrEqual(40);
  });

  it('labels ticks in UTC at the precision the span needs', () => {
    expect(formatTick(SIX, 30_000)).toBe('06:00:00');
    expect(formatTick(SIX + 1_800_000, 3 * H)).toBe('06:30');
    expect(formatTick(SIX, 30 * DAY)).toBe('06-03');
    expect(formatTick(SIX, 800 * DAY)).toBe('2021-06-03');
  });
});

describe('zoom and pan', () => {
  const extent = { from: SIX, to: SIX + 2 * H };

  it('zoom is clamped', () => {
    expect(zoomAt(extent, SIX + H, 0.5, extent)).toEqual({ from: SIX + H / 2, to: SIX + 1.5 * H });
    const tight = zoomAt(extent, SIX, 1e-9, extent);
    expect(tight.to - tight.from).toBe(1000);
    const wide = zoomAt(extent, SIX + H, 1e6, extent);
    expect(wide.to - wide.from).toBe(8 * H);
  });

  it('panning stops half a window past the data', () => {
    expect(pan({ from: SIX, to: SIX + H }, -10 * H, extent)).toEqual({ from: SIX - H / 2, to: SIX + H / 2 });
  });

  it('sizes buckets to about four pixels, never under a millisecond', () => {
    expect(bucketMs({ from: 0, to: 400_000 }, 400)).toBe(4000);
    expect(bucketMs({ from: 0, to: 10 }, 400)).toBe(1);
  });
});

describe('marks against DuckDB', () => {
  it('reads the span of detections', async () => {
    expect(await db.rows(EXTENT_SQL)).toEqual([{ lo: SIX, hi: SIX + H }]);
  });

  it('lays detections out by tactic lane and time bucket', async () => {
    const rows = await db.rows(marksSql({ from: SIX, to: SIX + 3 * H }, H, 'TRUE'));
    expect(rows.map((r) => [r.lane, r.b, r.n, r.lvl, r.uid])).toEqual([
      ['discovery', 0, 1, 2, 3],
      ['execution', 1, 1, 3, 4294967297],
      ['initial-access', 0, 1, 0, 1],
      ['persistence', 1, 1, 4, 4294967297],
    ]);
  });

  it('marks are bounded by lanes times buckets', async () => {
    const many = await openFixture([
      `INSERT INTO events SELECT 100 + i, 0, TIMESTAMP '2021-06-03 06:10:00' + to_seconds(i), NULL, 'Security', 4624, 'DC09',
         NULL, NULL, NULL, NULL, NULL FROM range(500) t(i)`,
      'INSERT INTO hits SELECT 1, 100 + i FROM range(500) t(i)',
    ]);
    try {
      const rows = await many.rows(marksSql({ from: SIX, to: SIX + 3 * H }, 3 * H, 'TRUE'));
      expect(rows).toHaveLength(4);
      expect(rows.find((r) => r.lane === 'initial-access')?.n).toBe(501);
    } finally {
      many.close();
    }
  });

  it('applies the filters', async () => {
    const rows = await db.rows(marksSql({ from: SIX, to: SIX + 3 * H }, 3 * H, `"Channel" = 'Security'`));
    expect(rows.map((r) => [r.lane, r.n])).toEqual([['initial-access', 1]]);
  });
});

describe('canvas geometry', () => {
  it('places marks and finds the one under the pointer', () => {
    const marks: Mark[] = [{ lane: 'execution', b: 0, n: 1, lvl: 3, uid: 7, first: SIX, last: SIX }];
    const laneList = lanes(TACTICS);
    const placed = place(marks, { from: SIX, bucket: H }, { from: SIX, to: SIX + 2 * H }, laneList, PAD_L + 400 + 12);
    expect(placed).toHaveLength(1);
    expect(placed[0].x).toBe(PAD_L + 100);
    expect(placed[0].y).toBe(laneY(laneList.indexOf('execution')));
    expect(hit(placed, placed[0].x + 5, placed[0].y)?.uid).toBe(7);
    expect(hit(placed, placed[0].x + 9, placed[0].y)).toBeNull();
  });

  it('names lanes, with one for rules without a tactic', () => {
    expect(lanes(['execution'])).toEqual(['execution', '']);
    expect([laneLabel('initial-access'), laneLabel('')]).toEqual(['Initial access', 'No tactic']);
  });
});

describe('showing a mark in Explore', () => {
  // The page's own predicates, so a mark's count is compared with what Explore would count.
  async function explored(database: Fixture, mark: Mark): Promise<number> {
    const filter = showFilter(mark);
    if (!filter) throw new Error('no filter');
    const where = `${timePredicate(filter.t)} AND (${compile(parse(filter.term), schema)})`;
    return (await database.rows(`SELECT count(*)::DOUBLE AS n FROM events WHERE ${where}`))[0].n as number;
  }

  it('selects exactly the events a mark counts', async () => {
    const many = await openFixture([
      `INSERT INTO events SELECT 100 + i, 0, TIMESTAMP '2021-06-03 06:10:00' + to_milliseconds(i * 250), NULL, 'Security', 4624, 'DC09',
         NULL, NULL, NULL, NULL, NULL FROM range(40) t(i)`,
      'INSERT INTO hits SELECT 1, 100 + i FROM range(40) t(i)',
      // The same instant as the bucket edge below, and one just after it, in the same lane.
      `INSERT INTO events VALUES (500, 0, TIMESTAMP '2021-06-03 06:10:05', NULL, 'Security', 4624, 'DC09', NULL, NULL, NULL, NULL, NULL)`,
      'INSERT INTO hits VALUES (1, 500)',
    ]);
    try {
      for (const bucket of [1000, 2500, 7000]) {
        const marks = (await many.rows(marksSql({ from: SIX, to: SIX + 3 * H }, bucket, 'TRUE'))) as unknown as Mark[];
        expect(marks.length).toBeGreaterThan(1);
        for (const mark of marks.filter((m) => m.lane)) expect(await explored(many, mark)).toBe(mark.n);
      }
    } finally {
      many.close();
    }
  });

  it('offers nothing for rules without a tactic, which no search term selects', () => {
    expect(showFilter({ lane: '', b: 0, n: 3, lvl: 1, uid: 1, first: SIX, last: SIX + 5 })).toBeNull();
  });
});
