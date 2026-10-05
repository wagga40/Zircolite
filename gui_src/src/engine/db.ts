import type { Engine } from './boot';
import { type QueryOptions, QueryScheduler, type Sender } from './queries';
import { EVENT_LEVELS_SQL } from './sql';
import type { TextSource } from './textMatches';

export interface Db {
  /** Rows as plain objects. Pass cache: false when the text stays the same but the data changed (pages of view_ids). */
  rows<T = Record<string, unknown>>(sql: string, options?: QueryOptions): Promise<T[]>;
  exec(sql: string, options?: { lane?: string }): Promise<void>;
  /** Stop the queries of one lane, or all of them. */
  cancel(lane?: string): void;
  /** Make bytes readable to the engine under a file name, as the boot does for the tables. */
  register(name: string, bytes: Uint8Array): Promise<void>;
  /** The full-text index is on its way: queries that read it wait for it, and the first opens its view. */
  useTextIndex(source: TextSource): void;
}

export async function openDb(engine: Engine): Promise<Db> {
  // DuckDB-WASM's reader is typed against its own Arrow classes; the scheduler needs only toArray and toJSON.
  const scheduler = new QueryScheduler(engine.conn as unknown as Sender);
  const db: Db = {
    rows: (sql, options) => scheduler.rows(sql, options),
    exec: (sql, options) => scheduler.exec(sql, options),
    cancel: (lane) => scheduler.cancel(lane),
    register: (name, bytes) => engine.db.registerFileBuffer(name, bytes),
    useTextIndex: (source) => scheduler.useTextIndex(source),
  };
  await db.exec(EVENT_LEVELS_SQL);
  return db;
}
