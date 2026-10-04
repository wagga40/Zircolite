import { describe, expect, it } from 'vitest';
import type { Engine } from '../src/engine/boot';
import { openDb } from '../src/engine/db';
import { EVENT_LEVELS_SQL } from '../src/engine/sql';

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
