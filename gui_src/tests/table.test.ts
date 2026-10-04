import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Field } from '../src/engine/schema';
import { COUNT_SQL, ensureVisible, geometry, HEIGHT_CAP, idsSql, nextPage, PAGE, pageSql, ROW } from '../src/explore/table';
import { type Fixture, openFixture, schema } from './fixture';

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

const field = (name: string): Field => {
  const found = schema.find(name);
  if (!found) throw new Error(`fixture has no ${name}`);
  return found;
};
const order = async () => (await db.rows('SELECT _zl_uid FROM view_ids ORDER BY _zl_pos')).map((r) => r._zl_uid);

describe('result list', () => {
  it('timeless events sort last', async () => {
    await db.rows(idsSql('TRUE', false));
    expect(await order()).toEqual([1, 2, 3, 4294967297, 4294967299, 4294967298]);
    await db.rows(idsSql('TRUE', true));
    expect(await order()).toEqual([4294967299, 4294967297, 3, 2, 1, 4294967298]);
  });

  it('counts results and those with detections', async () => {
    await db.rows(idsSql(`"Computer" = 'DC01'`, false));
    expect(await db.rows(COUNT_SQL)).toEqual([{ n: 3, d: 1 }]);
  });

  it('reads a page as text, with time and level', async () => {
    await db.rows(idsSql('TRUE', false));
    expect(await db.rows(pageSql([field('Computer'), field('EventID'), field(`it's "odd"`)], 2, 4))).toEqual([
      { _zl_pos: 2, _zl_uid: 3, _zl_t: Date.UTC(2021, 5, 3, 6, 5), _zl_lvl: 2, _zl_v0: 'WS02', _zl_v1: '1', _zl_v2: null },
      { _zl_pos: 3, _zl_uid: 4294967297, _zl_t: Date.UTC(2021, 5, 3, 7), _zl_lvl: 4, _zl_v0: 'WS02', _zl_v1: '1', _zl_v2: 'x' },
    ]);
  });

  it('adds the spelling columns on request', async () => {
    await db.rows(idsSql('TRUE', false));
    expect(await db.rows(pageSql([field('Computer')], 5, 6, 'view_ids', true))).toEqual([
      { _zl_pos: 5, _zl_uid: 4294967298, _zl_t: null, _zl_lvl: null, _zl_part: 1, _zl_spelling: '["computer"]', _zl_v0: 'ws02' },
    ]);
  });
});

describe('geometry', () => {
  it('maps scrolling to rows one to one below the cap', () => {
    expect(geometry(100, 280, 0)).toEqual({ height: 2800, first: 0, top: 0, count: 11 });
    expect(geometry(100, 280, 56)).toEqual({ height: 2800, first: 2, top: 56, count: 11 });
    expect(geometry(5, 280, 0)).toEqual({ height: 140, first: 0, top: 0, count: 5 });
    expect(geometry(0, 280, 0)).toEqual({ height: 0, first: 0, top: 0, count: 0 });
  });

  it('geometry scales beyond the height cap', () => {
    const total = 2_000_000;
    const viewport = 560;
    const end = geometry(total, viewport, HEIGHT_CAP - viewport);
    expect(end.height).toBe(HEIGHT_CAP);
    expect(end.first + viewport / ROW).toBe(total);
    expect(end.first + end.count).toBe(total);
    const start = geometry(total, viewport, 0);
    expect([start.first, start.top]).toEqual([0, 0]);
  });

  it('scrolls just enough to show a row', () => {
    expect(ensureVisible(15, 0, 100, 280)).toBe(168);
    expect(ensureVisible(3, 168, 100, 280)).toBe(84);
    expect(ensureVisible(8, 168, 100, 280)).toBe(168);
    for (const position of [0, 1_000_000, 1_999_999]) {
      const slice = geometry(2_000_000, 560, ensureVisible(position, 0, 2_000_000, 560));
      expect(position).toBeGreaterThanOrEqual(slice.first);
      expect(position).toBeLessThan(slice.first + slice.count);
    }
  });
});

describe('nextPage', () => {
  it('asks for the first page the visible rows need that has not loaded', () => {
    expect(nextPage({ first: 0, count: 33 }, new Set())).toBe(0);
    expect(nextPage({ first: PAGE - 10, count: 33 }, new Set([0]))).toBe(1);
    expect(nextPage({ first: PAGE - 10, count: 33 }, new Set([1]))).toBe(0);
    expect(nextPage({ first: PAGE - 10, count: 33 }, new Set([0, 1]))).toBeNull();
  });

  it('skips the pages scrolled past', () => {
    expect(nextPage({ first: 1_000_000, count: 33 }, new Set([0, 1, 2]))).toBe(1_000_000 / PAGE);
  });

  it('takes a predicate and a page size', () => {
    expect(nextPage({ first: 25, count: 10 }, (page) => page === 2, 10)).toBe(3);
    expect(nextPage({ first: 25, count: 10 }, () => true, 10)).toBeNull();
  });

  it('asks for nothing when no row is visible', () => {
    expect(nextPage({ first: 0, count: 0 }, new Set())).toBeNull();
  });
});
