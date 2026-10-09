import { tableFromArrays } from 'apache-arrow';
import { describe, expect, it } from 'vitest';
import { isSuperseded, plain, QueryScheduler, type Sender } from '../src/engine/queries';
import { fakeConnection } from './connection';

describe('QueryScheduler', () => {
  it('runs one query at a time, in order', async () => {
    const c = fakeConnection();
    const s = new QueryScheduler(c.sender);
    const a = s.rows('A');
    const b = s.rows('B');
    await c.finish([{ n: 1 }]);
    expect(c.sent).toEqual(['A', 'B']);
    await c.finish([{ n: 2 }]);
    expect(await a).toEqual([{ n: 1 }]);
    expect(await b).toEqual([{ n: 2 }]);
  });

  it('answers repeated text from its cache unless told not to', async () => {
    const c = fakeConnection();
    const s = new QueryScheduler(c.sender);
    const first = s.rows('A');
    await c.finish([{ n: 1 }]);
    await first;
    expect(await s.rows('A')).toEqual([{ n: 1 }]);
    expect(c.sent).toEqual(['A']);
    const fresh = s.rows('A', { cache: false });
    await c.finish([{ n: 2 }]);
    expect(await fresh).toEqual([{ n: 2 }]);
    expect(c.sent).toEqual(['A', 'A']);
  });

  it('a newer request in the lane drops a queued one', async () => {
    const c = fakeConnection();
    const s = new QueryScheduler(c.sender);
    const blocker = s.rows('X');
    const old = s.rows('A', { lane: 'table' });
    const latest = s.rows('B', { lane: 'table' });
    await expect(old).rejects.toSatisfy(isSuperseded);
    await c.finish();
    await blocker;
    await c.finish([{ n: 2 }]);
    expect(await latest).toEqual([{ n: 2 }]);
    expect(c.sent).toEqual(['X', 'B']);
  });

  it('a newer request in the lane cancels the running query', async () => {
    const c = fakeConnection();
    const s = new QueryScheduler(c.sender);
    const old = s.rows('slow', { lane: 'table' });
    await new Promise((resolve) => setTimeout(resolve, 0));
    const latest = s.rows('fast', { lane: 'table' });
    await expect(old).rejects.toSatisfy(isSuperseded);
    expect(c.cancels()).toBe(1);
    await c.finish([{ n: 3 }]);
    expect(await latest).toEqual([{ n: 3 }]);
  });

  it('cancel() stops everything, queued and running', async () => {
    const c = fakeConnection();
    const s = new QueryScheduler(c.sender);
    const a = s.rows('A');
    await new Promise((resolve) => setTimeout(resolve, 0));
    const b = s.rows('B', { lane: 'x' });
    s.cancel();
    await expect(a).rejects.toSatisfy(isSuperseded);
    await expect(b).rejects.toSatisfy(isSuperseded);
  });

  it('a failed query rejects with its own error, and the next one runs', async () => {
    const c = fakeConnection();
    const s = new QueryScheduler(c.sender);
    const bad = s.rows('bad');
    const good = s.rows('good');
    // Watched before the failure, or the rejection is reported as unhandled while the test waits.
    const failed = expect(bad).rejects.toThrow('no such column');
    await c.fail(new Error('Binder Error: no such column'));
    await failed;
    await c.finish([{ ok: true }]);
    expect(await good).toEqual([{ ok: true }]);
  });

  it("cancel('a') leaves another lane's running query alone", async () => {
    const c = fakeConnection();
    const s = new QueryScheduler(c.sender);
    const b = s.rows('B', { lane: 'b' });
    await new Promise((resolve) => setTimeout(resolve, 0));
    s.cancel('a');
    expect(c.cancels()).toBe(0);
    await c.finish([{ n: 1 }]);
    expect(await b).toEqual([{ n: 1 }]);
  });

  it('cancel() cancels the engine once, and the next queued query still runs', async () => {
    const c = fakeConnection();
    const s = new QueryScheduler(c.sender);
    const a = s.rows('A', { lane: 'x' });
    await new Promise((resolve) => setTimeout(resolve, 0));
    s.cancel();
    await expect(a).rejects.toSatisfy(isSuperseded);
    expect(c.cancels()).toBe(1);
    const next = s.rows('N');
    await c.finish([{ n: 5 }]);
    expect(await next).toEqual([{ n: 5 }]);
    expect(c.sent).toEqual(['A', 'N']);
  });

  it('never sends a query cancelled before it reached the engine', async () => {
    const c = fakeConnection();
    const s = new QueryScheduler(c.sender);
    const first = s.rows('A', { lane: 'table' });
    const second = s.rows('B', { lane: 'table' });
    await expect(first).rejects.toSatisfy(isSuperseded);
    await c.finish([{ n: 2 }]);
    expect(await second).toEqual([{ n: 2 }]);
    expect(c.sent).toEqual(['B']);
  });

  it('cancelPrefix stops the queued and running queries of the lanes under it, and only those', async () => {
    const c = fakeConnection();
    const s = new QueryScheduler(c.sender);
    const running = s.rows('A', { lane: 'explore:results' });
    const watchedRunning = expect(running).rejects.toSatisfy(isSuperseded);
    await new Promise((resolve) => setTimeout(resolve, 0));
    const queued = s.rows('B', { lane: 'explore:strip' });
    const other = s.rows('C', { lane: 'overview:tiles' });
    const lookalike = s.rows('D', { lane: 'explorer:x' });
    s.cancelPrefix('explore:');
    await watchedRunning;
    await expect(queued).rejects.toSatisfy(isSuperseded);
    expect(c.cancels()).toBe(1);
    await c.finish([{ n: 1 }]);
    expect(await other).toEqual([{ n: 1 }]);
    await c.finish([{ n: 2 }]);
    expect(await lookalike).toEqual([{ n: 2 }]);
    expect(c.sent).toEqual(['A', 'C', 'D']);
  });

  it('a cancelled query that the engine still finishes is never answered with rows', async () => {
    const c = fakeConnection();
    const lost: Sender = { send: c.sender.send, cancelSent: async () => false };
    const s = new QueryScheduler(lost);
    const old = s.rows('slow', { lane: 'table' });
    const watched = expect(old).rejects.toSatisfy(isSuperseded);
    await new Promise((resolve) => setTimeout(resolve, 0));
    s.cancel('table');
    await c.finish([{ n: 9 }]);
    await watched;
  });

  it('does not cache a failed query', async () => {
    const c = fakeConnection();
    const s = new QueryScheduler(c.sender);
    const bad = s.rows('Q');
    const failed = expect(bad).rejects.toThrow('boom');
    await c.fail(new Error('boom'));
    await failed;
    const again = s.rows('Q');
    await c.finish([{ n: 1 }]);
    expect(await again).toEqual([{ n: 1 }]);
    expect(c.sent).toEqual(['Q', 'Q']);
  });

  it('exec drains the statement and resolves without rows', async () => {
    const c = fakeConnection();
    const s = new QueryScheduler(c.sender);
    const done = s.exec('CREATE TEMP TABLE t AS SELECT 1');
    await c.finish();
    await expect(done).resolves.toBeUndefined();
  });
});

describe('plain', () => {
  it('turns exact 64-bit integers into numbers and refuses the rest', () => {
    expect(plain(7n, 'n')).toBe(7);
    expect(() => plain(9007199254740993n, 'big')).toThrowError(/big/);
  });

  it('turns Arrow lists into arrays', () => {
    expect(plain({ toArray: () => BigInt64Array.from([1n, 2n]) }, 'l')).toEqual([1, 2]);
    expect(plain({ toArray: () => ['a', 'b'] }, 'l')).toEqual(['a', 'b']);
  });

  it('reads what apache-arrow hands back for a BIGINT column', () => {
    const table = tableFromArrays({ n: BigInt64Array.from([42n]) });
    const row = table.get(0)?.toJSON() as Record<string, unknown>;
    expect(plain(row.n, 'n')).toBe(42);
  });
});
