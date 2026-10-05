import { describe, expect, it } from 'vitest';
import type { Engine } from '../src/engine/boot';
import { type Db, openDb } from '../src/engine/db';
import { isSuperseded } from '../src/engine/queries';
import { EVENT_LEVELS_SQL } from '../src/engine/sql';
import { fakeConnection } from './connection';

function fakeEngine() {
  const sent: string[] = [];
  const registered: string[] = [];
  const conn = {
    async send(sql: string) {
      sent.push(sql);
      return (async function* () {
        yield { toArray: () => [{ toJSON: () => ({ n: 7n }) }] };
      })();
    },
    async cancelSent() {
      return false;
    },
  };
  const db = {
    async registerFileBuffer(name: string) {
      registered.push(name);
    },
  };
  return { engine: { db, conn } as unknown as Engine, sent, registered };
}

describe('openDb', () => {
  it('creates the event levels before anything else runs', async () => {
    const { engine, sent } = fakeEngine();
    await openDb(engine);
    expect(sent).toEqual([EVENT_LEVELS_SQL]);
  });

  it('returns plain rows, caches by text, and registers files', async () => {
    const { engine, sent, registered } = fakeEngine();
    const db = await openDb(engine);
    sent.length = 0;
    expect(await db.rows('SELECT 7 AS n')).toEqual([{ n: 7 }]);
    await db.rows('SELECT 7 AS n');
    expect(sent).toEqual(['SELECT 7 AS n']);
    await db.rows('SELECT 7 AS n', { cache: false });
    expect(sent).toHaveLength(2);
    await db.register('text.parquet', new Uint8Array([1]));
    expect(registered).toEqual(['text.parquet']);
  });
});

/** A Db over a connection whose queries finish when the test says so. */
async function heldDb() {
  const c = fakeConnection();
  const engine = { db: { async registerFileBuffer() {} }, conn: c.sender } as unknown as Engine;
  const opening = openDb(engine);
  await c.finish();
  const db: Db = await opening;
  c.sent.length = 0;
  return { db, c };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

describe('Db.scope', () => {
  it('puts every lane under the scope name', async () => {
    const { db, c } = await heldDb();
    const overview = db.scope('overview');
    const explore = db.scope('explore');
    const a = overview.rows('A', { lane: 'strip' });
    const b = explore.rows('B', { lane: 'strip' });
    await c.finish([{ n: 1 }]);
    await c.finish([{ n: 2 }]);
    expect([await a, await b]).toEqual([[{ n: 1 }], [{ n: 2 }]]);
    const first = overview.rows('C', { lane: 'tiles' });
    const second = overview.rows('D', { lane: 'tiles' });
    await expect(first).rejects.toSatisfy(isSuperseded);
    await c.finish([{ n: 4 }]);
    expect(await second).toEqual([{ n: 4 }]);
  });

  it('dispose cancels the queued and running queries of its scope only', async () => {
    const { db, c } = await heldDb();
    const explore = db.scope('explore');
    const overview = db.scope('overview');
    const running = explore.rows('slow', { lane: 'results' });
    const watched = expect(running).rejects.toSatisfy(isSuperseded);
    await tick();
    const queued = explore.exec('CREATE TEMP TABLE x AS SELECT 1', { lane: 'results-build' });
    const unlaned = explore.rows('E');
    const tiles = overview.rows('T', { lane: 'tiles' });
    explore.dispose();
    await watched;
    await expect(queued).rejects.toSatisfy(isSuperseded);
    await expect(unlaned).rejects.toSatisfy(isSuperseded);
    expect(c.cancels()).toBe(1);
    await c.finish([{ n: 7 }]);
    expect(await tiles).toEqual([{ n: 7 }]);
    expect(c.sent).toEqual(['slow', 'T']);
  });

  it('rejects every call made after dispose as superseded, without reaching the engine', async () => {
    const { db, c } = await heldDb();
    const facet = db.scope('explore').scope('facet-eventid');
    facet.dispose();
    await expect(facet.rows('A', { lane: 'values' })).rejects.toSatisfy(isSuperseded);
    await expect(facet.exec('B', { lane: 'values' })).rejects.toSatisfy(isSuperseded);
    expect(c.sent).toEqual([]);
  });

  it('a disposed scope takes its inner scopes with it', async () => {
    const { db, c } = await heldDb();
    const detections = db.scope('detections');
    const alerts = detections.scope('alerts-5');
    const evidence = alerts.rows('A', { lane: 'evidence' });
    const watched = expect(evidence).rejects.toSatisfy(isSuperseded);
    await tick();
    detections.dispose();
    await watched;
    await expect(alerts.rows('B', { lane: 'evidence' })).rejects.toSatisfy(isSuperseded);
    expect(c.sent).toEqual(['A']);
  });

  it('keeps scopes apart when a name holds the separator', async () => {
    const { db, c } = await heldDb();
    const explore = db.scope('explore');
    const plain = explore.scope('facet-a');
    const colon = explore.scope('facet-a:b');
    const kept = colon.rows('K', { lane: 'values' });
    plain.dispose();
    await c.finish([{ n: 1 }]);
    expect(await kept).toEqual([{ n: 1 }]);
  });

  it('cancels one lane of its own by name, and Stop with no lane still stops the whole page', async () => {
    const { db, c } = await heldDb();
    const explore = db.scope('explore');
    const drawer = db.rows('D', { lane: 'drawer' });
    const watchedDrawer = expect(drawer).rejects.toSatisfy(isSuperseded);
    await tick();
    const strip = explore.rows('S', { lane: 'strip' });
    const page = explore.rows('P', { lane: 'page' });
    explore.cancel('strip');
    await expect(strip).rejects.toSatisfy(isSuperseded);
    explore.cancel();
    await watchedDrawer;
    await expect(page).rejects.toSatisfy(isSuperseded);
  });
});

describe('lane names inside a scope', () => {
  it('cannot reach another scope with a colon', async () => {
    const { db, c } = await heldDb();
    const outer = db.scope('a');
    const inner = db.scope('a').scope('b');
    const running = db.rows('hold', { lane: 'other' });
    const watched = expect(running).resolves.toBeDefined();
    await tick();
    const kept = outer.rows('SELECT 1', { lane: 'b:x' });
    inner.dispose();
    await c.finish();
    await watched;
    await c.finish([{ n: 1 }]);
    expect(await kept).toEqual([{ n: 1 }]);
  });

  it('encodes the lane the same way for cancel', async () => {
    const { db, c } = await heldDb();
    const scope = db.scope('v');
    const running = scope.rows('slow', { lane: 'x:y' });
    const watched = expect(running).rejects.toSatisfy(isSuperseded);
    await tick();
    scope.cancel('x:y');
    await watched;
    expect(c.cancels()).toBe(1);
  });
});

describe('named and unnamed lanes of one scope', () => {
  it('a lane named like an unnamed one is cancelled on its own', async () => {
    const { db, c } = await heldDb();
    const scope = db.scope('v');
    const running = scope.rows('hold', { lane: 'hold' });
    await tick();
    const named = scope.rows('N', { lane: '#1' });
    const unnamed = scope.rows('U');
    scope.cancel('#1');
    await expect(named).rejects.toSatisfy(isSuperseded);
    await c.finish();
    await running;
    await c.finish([{ n: 2 }]);
    expect(await unnamed).toEqual([{ n: 2 }]);
  });
});
