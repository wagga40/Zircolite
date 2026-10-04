import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { decode, EMPTY, encode } from '../src/state/hash';
import { combineWhere, DETECTIONS_PREDICATE, timePredicate } from '../src/state/where';
import { type Fixture, openFixture } from './fixture';

let db: Fixture;
beforeAll(async () => { db = await openFixture(); });
afterAll(() => db.close());

describe('hash', () => {
  const full = { q: 'host:"DC 01" & x', t: [1622700000000, 1622703600000] as [number, number], d: true,
    cols: ['Computer', 'a,b', 'it\'s "odd"'], uid: 4294967297, desc: true };

  it('round-trips every field', () => {
    expect(decode(encode(full))).toEqual(full);
  });

  it('writes nothing for defaults', () => {
    expect(encode(EMPTY)).toBe('#/explore');
    expect(decode('')).toEqual(EMPTY);
  });

  it('keeps an empty column list distinct from the default', () => {
    expect(decode(encode({ ...EMPTY, cols: [] })).cols).toEqual([]);
  });

  it('ignores malformed parts and keeps the rest', () => {
    expect(decode('#/explore?q=%E0%A4%A&d=1&t=9~3&uid=-4&uid=x')).toEqual({ ...EMPTY, d: true });
  });
});

describe('hash hardening', () => {
  it('reads only canonical integers for t and uid', () => {
    expect(decode('#/explore?t=~5')).toEqual(EMPTY);
    expect(decode('#/explore?t=1e3~2e3')).toEqual(EMPTY);
    expect(decode('#/explore?uid=0x10')).toEqual(EMPTY);
    expect(decode('#/explore?uid=')).toEqual(EMPTY);
    expect(decode('#/explore?uid=0').uid).toBe(0);
  });

  it('drops empty column names but keeps an empty list', () => {
    expect(decode('#/explore?cols=a,,b').cols).toEqual(['a', 'b']);
    expect(decode('#/explore?cols=').cols).toEqual([]);
  });

  it('replaces lone surrogates instead of throwing', () => {
    const hash = encode({ ...EMPTY, q: 'a\uD800b', cols: ['x\uDC00'] });
    expect(decode(hash)).toEqual({ ...EMPTY, q: 'a\uFFFDb', cols: ['x\uFFFD'] });
  });
});

describe('where', () => {
  it('limits time to a half-open range', async () => {
    const from = Date.UTC(2021, 5, 3, 6, 0, 0);
    const predicate = timePredicate([from, from + 5 * 60_000]) as string;
    expect(await db.uids(predicate)).toEqual([1, 2]);
    expect(timePredicate(null)).toBeNull();
  });

  it('keeps only events with a detection', async () => {
    expect(await db.uids(DETECTIONS_PREDICATE)).toEqual([1, 3, 4294967297]);
  });

  it('joins predicates and treats none as everything', () => {
    expect(combineWhere(undefined)).toBe('TRUE');
    expect(combineWhere([])).toBe('TRUE');
    expect(combineWhere(['a = 1', { toString: () => 'b = 2' }, true])).toBe('(a = 1) AND (b = 2)');
  });
});
