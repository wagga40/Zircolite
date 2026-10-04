import { Coordinator, wasmConnector } from '@uwdata/mosaic-core';
import type { Engine } from './boot';
import { EVENT_LEVELS_SQL } from './sql';

export interface Db {
  coordinator: Coordinator;
  /**
   * Rows as plain objects. Queries whose text does not change when their
   * result does (pages of the view_ids temp table) must pass cache: false,
   * or Mosaic answers them from its cache.
   */
  rows<T = Record<string, unknown>>(sql: string, options?: { cache?: boolean }): Promise<T[]>;
  exec(sql: string): Promise<void>;
}

export async function openDb(engine: Engine): Promise<Db> {
  // Pre-aggregation indexes Mosaic's own query objects; the viewer's clients
  // send SQL text, so it could only add work.
  const coordinator = new Coordinator(wasmConnector({ duckdb: engine.db, connection: engine.conn }), {
    logger: null,
    preagg: { enabled: false },
  });
  const db: Db = {
    coordinator,
    async rows<T>(sql: string, options?: { cache?: boolean }) {
      const table = await coordinator.query(sql, { cache: options?.cache ?? true });
      return table.toArray() as T[];
    },
    async exec(sql: string) {
      await coordinator.exec(sql);
    },
  };
  await db.exec(EVENT_LEVELS_SQL);
  return db;
}
