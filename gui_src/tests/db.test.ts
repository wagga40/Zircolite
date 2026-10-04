import { tableFromArrays, tableToIPC } from '@uwdata/flechette';
import { Coordinator } from '@uwdata/mosaic-core';
import { describe, expect, it } from 'vitest';
import type { Engine } from '../src/engine/boot';
import { openDb } from '../src/engine/db';
import { EVENT_LEVELS_SQL } from '../src/engine/sql';

/** An engine whose connection records every statement and answers with one Arrow row. */
function fakeEngine() {
  const sent: string[] = [];
  const bindings = {
    async runQuery(_conn: number, sql: string) {
      sent.push(sql);
      return tableToIPC(tableFromArrays({ n: [7] }), { format: 'stream' }) as Uint8Array;
    },
  };
  const conn = { useUnsafe: (run: (b: typeof bindings, c: number) => Promise<void>) => run(bindings, 0) };
  return { engine: { db: {}, conn } as unknown as Engine, sent };
}

describe('openDb', () => {
  it('builds a coordinator and creates the event levels through the shared connection', async () => {
    const { engine, sent } = fakeEngine();
    const db = await openDb(engine);

    expect(db.coordinator).toBeInstanceOf(Coordinator);
    expect(sent).toEqual([EVENT_LEVELS_SQL]);
  });

  it('returns rows as plain objects and honours cache: false', async () => {
    const { engine, sent } = fakeEngine();
    const db = await openDb(engine);
    sent.length = 0;

    expect(await db.rows('SELECT 7 AS n')).toEqual([{ n: 7 }]);
    await db.rows('SELECT 7 AS n');
    expect(sent).toEqual(['SELECT 7 AS n']);
    await db.rows('SELECT 7 AS n', { cache: false });
    expect(sent).toHaveLength(2);
  });
});
