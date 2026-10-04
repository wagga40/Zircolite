/** A query the page no longer wants: a newer one replaced it in its lane, or the page was stopped. */
export class Superseded extends Error {
  constructor() {
    super('This query was replaced by a newer one or stopped');
    this.name = 'Superseded';
  }
}

export function isSuperseded(error: unknown): boolean {
  return error instanceof Superseded;
}

type Batch = { toArray(): { toJSON(): Record<string, unknown> }[] };

/** What the scheduler needs from a DuckDB-WASM connection. */
export interface Sender {
  send(sql: string): Promise<AsyncIterable<Batch>>;
  cancelSent(): Promise<boolean>;
}

export interface QueryOptions {
  /** Identical text is answered from memory; pass false when the text stays the same but the data changed. */
  cache?: boolean;
  /** A newer request in the same lane supersedes this one, whether it is queued or running. */
  lane?: string;
}

interface Job {
  sql: string;
  lane: string | null;
  rows: boolean;
  cache: boolean;
  cancelled: boolean;
  resolve(rows: Record<string, unknown>[]): void;
  reject(error: unknown): void;
}

const CACHE_ENTRIES = 256;

/** A value as the views use it: exact 64-bit integers as numbers, lists as arrays. */
export function plain(value: unknown, column: string): unknown {
  if (typeof value === 'bigint') {
    const number = Number(value);
    if (!Number.isSafeInteger(number)) {
      throw new Error(`column ${column} holds ${value}, which JavaScript cannot hold exactly; select it as text`);
    }
    return number;
  }
  if (value !== null && typeof value === 'object' && typeof (value as { toArray?: unknown }).toArray === 'function') {
    return Array.from((value as { toArray(): ArrayLike<unknown> }).toArray(), (item) => plain(item, column));
  }
  return value;
}

/**
 * Every query of the page, one at a time on the single connection. Queries
 * go through send(), which cancelSent() can stop: a search over every field
 * of millions of events runs for a minute, and nothing else could run until it
 * ended if it could not be stopped.
 */
export class QueryScheduler {
  private readonly conn: Sender;
  private readonly queue: Job[] = [];
  private running: Job | null = null;
  private readonly cache = new Map<string, Record<string, unknown>[]>();

  constructor(conn: Sender) {
    this.conn = conn;
  }

  rows<T = Record<string, unknown>>(sql: string, options: QueryOptions = {}): Promise<T[]> {
    const lane = options.lane ?? null;
    this.supersede(lane);
    const cache = options.cache ?? true;
    const hit = cache ? this.cache.get(sql) : undefined;
    if (hit) {
      this.cache.delete(sql);
      this.cache.set(sql, hit);
      return Promise.resolve(hit as T[]);
    }
    return this.enqueue(sql, lane, true, cache) as Promise<T[]>;
  }

  exec(sql: string, options: { lane?: string } = {}): Promise<void> {
    const lane = options.lane ?? null;
    this.supersede(lane);
    return this.enqueue(sql, lane, false, false).then(() => undefined);
  }

  /** Stop the queued and running queries of a lane; with no lane, stop them all. */
  cancel(lane?: string): void {
    this.drop(lane === undefined ? () => true : (job) => job.lane === lane);
  }

  private supersede(lane: string | null): void {
    if (lane !== null) this.drop((job) => job.lane === lane);
  }

  private drop(match: (job: Job) => boolean): void {
    for (let i = this.queue.length - 1; i >= 0; i--) {
      const job = this.queue[i];
      if (match(job)) {
        this.queue.splice(i, 1);
        job.reject(new Superseded());
      }
    }
    const running = this.running;
    if (running && !running.cancelled && match(running)) {
      running.cancelled = true;
      // The job is already marked and will reject as superseded whatever happens;
      // a failed cancel only means the engine finishes the query first.
      this.conn.cancelSent().catch(() => false);
    }
  }

  private enqueue(sql: string, lane: string | null, rows: boolean, cache: boolean): Promise<Record<string, unknown>[]> {
    return new Promise((resolve, reject) => {
      this.queue.push({ sql, lane, rows, cache, cancelled: false, resolve, reject });
      void this.pump();
    });
  }

  private async pump(): Promise<void> {
    if (this.running || this.queue.length === 0) return;
    const job = this.queue.shift() as Job;
    this.running = job;
    try {
      const reader = await this.conn.send(job.sql);
      const out: Record<string, unknown>[] = [];
      for await (const batch of reader) {
        if (!job.rows) continue;
        for (const row of batch.toArray()) {
          const object = row.toJSON();
          const clean: Record<string, unknown> = {};
          for (const key of Object.keys(object)) clean[key] = plain(object[key], key);
          out.push(clean);
        }
      }
      if (job.cancelled) throw new Superseded();
      if (job.cache) this.remember(job.sql, out);
      job.resolve(out);
    } catch (error) {
      job.reject(job.cancelled ? new Superseded() : error);
    } finally {
      this.running = null;
      void this.pump();
    }
  }

  private remember(sql: string, rows: Record<string, unknown>[]): void {
    this.cache.set(sql, rows);
    while (this.cache.size > CACHE_ENTRIES) {
      const oldest = this.cache.keys().next().value;
      if (oldest === undefined) break;
      this.cache.delete(oldest);
    }
  }
}
