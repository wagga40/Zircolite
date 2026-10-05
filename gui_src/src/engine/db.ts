import type { Engine } from './boot';
import { type QueryOptions, QueryScheduler, type Sender, Superseded } from './queries';
import { EVENT_LEVELS_SQL } from './sql';
import type { TextSource } from './textMatches';

export interface Db {
  /** Rows as plain objects. Pass cache: false when the text stays the same but the data changed (pages of view_ids). */
  rows<T = Record<string, unknown>>(sql: string, options?: QueryOptions): Promise<T[]>;
  exec(sql: string, options?: { lane?: string }): Promise<void>;
  /** Stop the queries of one lane, or with no lane every query of the page: Stop means the page, wherever it is pressed. */
  cancel(lane?: string): void;
  /** Make bytes readable to the engine under a file name, as the boot does for the tables. */
  register(name: string, bytes: Uint8Array): Promise<void>;
  /** The full-text index is on its way: queries that read it wait for it, and the first opens its view. */
  useTextIndex(source: TextSource): void;
  /**
   * A Db whose lanes are all named `name:lane`, for one view or panel. The page has one connection,
   * and a view that is gone would otherwise keep it busy with queries nobody will read.
   */
  scope(name: string): ScopedDb;
}

export interface ScopedDb extends Db {
  /** Stop every query of the scope, queued or running; later calls reject as superseded. */
  dispose(): void;
}

// A name holding the separator would put one scope's lanes, or one lane, under another scope's prefix.
function segment(name: string): string {
  return name.replace(/[%:]/g, (c) => encodeURIComponent(c));
}

function over(scheduler: QueryScheduler, register: Db['register'], prefix: string, alive: () => boolean): ScopedDb {
  let disposed = false;
  let unnamed = 0;
  const live = () => !disposed && alive();
  // A query without a lane supersedes nothing, but inside a scope it still needs one for dispose to reach it.
  const lane = (name: string | undefined) =>
    name !== undefined ? prefix + segment(name) : prefix ? `${prefix}#${++unnamed}` : undefined;
  return {
    rows: (sql, options = {}) => (live() ? scheduler.rows(sql, { ...options, lane: lane(options.lane) }) : Promise.reject(new Superseded())),
    exec: (sql, options = {}) => (live() ? scheduler.exec(sql, { lane: lane(options.lane) }) : Promise.reject(new Superseded())),
    cancel: (name) => (name === undefined ? scheduler.cancel() : scheduler.cancel(prefix + segment(name))),
    register,
    useTextIndex: (source) => scheduler.useTextIndex(source),
    scope: (name) => over(scheduler, register, `${prefix}${segment(name)}:`, live),
    dispose: () => {
      disposed = true;
      if (prefix) scheduler.cancelPrefix(prefix);
    },
  };
}

export async function openDb(engine: Engine): Promise<Db> {
  // DuckDB-WASM's reader is typed against its own Arrow classes; the scheduler needs only toArray and toJSON.
  const scheduler = new QueryScheduler(engine.conn as unknown as Sender);
  const { dispose: _, ...db } = over(scheduler, (name, bytes) => engine.db.registerFileBuffer(name, bytes), '', () => true);
  await db.exec(EVENT_LEVELS_SQL);
  return db;
}
