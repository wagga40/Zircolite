/**
 * Full-text matches, found once per search. A bare word becomes a predicate
 * over the index, and Strip, the table, the sidebar and the other views each
 * put that predicate in their own queries; scanned separately, one search
 * would read the whole index three times. The scheduler instead answers the
 * scan once, into a temp table, in slices that a Stop can interrupt between,
 * and rewrites each query to read that table.
 *
 * A table is a set of uids, and every reader tests membership with IN. A slice
 * that commits and then fails to report back can therefore leave its uids in
 * the table twice when the scan resumes, and no answer changes.
 *
 * The index loads after the page is ready, and a bare word compiles onto it
 * meanwhile: a scan queued while it loads would hold the single connection for
 * a minute per query on a large package. A query that needs the index waits
 * for the file, then opens the view itself, on the connection it already
 * holds; opened through the queue, the view would wait behind those queries.
 */
import { escapeClause, str } from './sql';

/** The registered name of the index file; its row groups are what the scan is sliced along. */
export const TEXT_FILE = 'text.parquet';

/** The view every full-text predicate reads. */
export const TEXT_VIEW_SQL = `CREATE OR REPLACE VIEW fulltext AS SELECT * FROM read_parquet(${str(TEXT_FILE)})`;

export type RunSql = (sql: string) => Promise<Record<string, unknown>[]>;

/** How the query being prepared learns that the page no longer wants it. */
export interface Stop {
  cancelled(): boolean;
  superseded(): Error;
  /** What the promise settles with, unless the query is given up first: then it rejects as superseded. */
  until<T>(promise: Promise<T>): Promise<T>;
}

/** The index file on its way to the engine. */
export interface TextSource {
  /** Settles once the file is registered with the engine, or rejects with why it never will be. */
  registered: Promise<void>;
  /** The file was registered, but the engine cannot open it. */
  failed(error: unknown): void;
}

/** The predicate compile() writes for a bare word; `like` is the lowercased pattern literal. */
export function textPredicate(like: string): string {
  return `_zl_uid IN (SELECT _zl_uid FROM fulltext WHERE _zl_text LIKE ${like}${escapeClause(like)})`;
}

// A bare word's pattern always opens and closes with %. Inside a string literal every quote is
// doubled, so lower('% cannot occur there, and a literal that spells the predicate is left as it is.
const PREDICATE = /_zl_uid IN \(SELECT _zl_uid FROM fulltext WHERE _zl_text LIKE (lower\('%(?:[^']|'')*%'\))(?: ESCAPE '\\')?\)/g;

/** Matches kept at once; each holds one row per matching event. */
const KEPT = 4;
/** Enough slices that a cancel waits seconds, not the whole scan, and few enough that each is worth its overhead. */
const SLICES = 12;

interface Entry {
  table: string;
  /** Slices already inserted, so a scan that was stopped resumes instead of starting over. */
  done: number;
  ready: boolean;
}

/** Lower bounds of the slices: every k-th row group's first uid, so each slice reads only its own row groups. */
export function sliceBounds(firstUids: number[], slices = SLICES): number[] {
  const starts = [...new Set(firstUids)].sort((a, b) => a - b);
  const step = Math.max(1, Math.ceil(starts.length / slices));
  return starts.filter((_, i) => i > 0 && i % step === 0);
}

export class TextMatches {
  private readonly entries = new Map<string, Entry>();
  private bounds: number[] | null = null;
  private counter = 0;
  /** Tables whose DROP did not go through, such as one a Stop cancelled; each is tried again on the next eviction. */
  private readonly undropped: string[] = [];
  /** Without a source the view is taken to exist already; a query over a missing view fails on its own. */
  private source: TextSource | null = null;
  private opened = false;

  constructor(private readonly run: RunSql) {}

  use(source: TextSource): void {
    this.source = source;
    this.opened = false;
  }

  /** The query with each full-text predicate answered from its table of matches, built first when it is missing. */
  async prepare(sql: string, stop: Stop): Promise<string> {
    const likes = [...new Set([...sql.matchAll(PREDICATE)].map((m) => m[1]))];
    if (likes.length === 0) return sql;
    await this.open(stop);
    for (const like of likes) await this.build(like, new Set(likes), stop);
    return sql.replace(PREDICATE, (_whole, like: string) => `_zl_uid IN (SELECT _zl_uid FROM ${(this.entries.get(like) as Entry).table})`);
  }

  private async open(stop: Stop): Promise<void> {
    const source = this.source;
    if (this.opened || source === null) return;
    await stop.until(source.registered);
    try {
      await this.run(TEXT_VIEW_SQL);
    } catch (error) {
      // A Stop that interrupted the statement says nothing about the file.
      if (stop.cancelled()) throw stop.superseded();
      source.failed(error);
      throw error;
    }
    if (this.source === source) this.opened = true;
  }

  private async build(like: string, wanted: Set<string>, stop: Stop): Promise<void> {
    let entry = this.entries.get(like);
    if (entry) {
      // Most recently used last, so the oldest is the one dropped.
      this.entries.delete(like);
      this.entries.set(like, entry);
      if (entry.ready) return;
    } else {
      entry = { table: `_zl_tm_${++this.counter}`, done: 0, ready: false };
      this.entries.set(like, entry);
      await this.evict(wanted);
    }
    const bounds = await this.sliceBounds(stop);
    while (entry.done <= bounds.length) {
      if (stop.cancelled()) throw stop.superseded();
      const low = entry.done > 0 ? ` AND _zl_uid >= ${bounds[entry.done - 1]}` : '';
      const high = entry.done < bounds.length ? ` AND _zl_uid < ${bounds[entry.done]}` : '';
      const select = `SELECT _zl_uid FROM fulltext WHERE _zl_text LIKE ${like}${escapeClause(like)}${low}${high}`;
      await this.run(entry.done === 0 ? `CREATE OR REPLACE TEMP TABLE ${entry.table} AS ${select}` : `INSERT INTO ${entry.table} ${select}`);
      entry.done += 1;
    }
    entry.ready = true;
  }

  private async sliceBounds(stop: Stop): Promise<number[]> {
    if (this.bounds) return this.bounds;
    let bounds: number[] = [];
    try {
      const rows = await this.run(
        `SELECT min(stats_min_value::BIGINT)::DOUBLE AS first FROM parquet_metadata('${TEXT_FILE}') WHERE path_in_schema = '_zl_uid' GROUP BY row_group_id`,
      );
      const firsts = rows.map((row) => Number(row.first));
      // Bounds that are not exact integers would drop events; without them the scan is one slice.
      if (firsts.every(Number.isSafeInteger)) bounds = sliceBounds(firsts);
    } catch (error) {
      // A cancelled lookup says nothing about the file, so it must not settle the question for good.
      if (stop.cancelled()) throw stop.superseded();
      bounds = [];
    }
    this.bounds = bounds;
    return bounds;
  }

  private async evict(wanted: Set<string>): Promise<void> {
    for (const [like, entry] of [...this.entries]) {
      if (this.entries.size <= KEPT) break;
      if (wanted.has(like)) continue;
      this.entries.delete(like);
      this.undropped.push(entry.table);
    }
    for (const table of [...this.undropped]) {
      try {
        await this.run(`DROP TABLE IF EXISTS ${table}`);
        this.undropped.splice(this.undropped.indexOf(table), 1);
      } catch {
        // Kept for the next eviction.
      }
    }
  }
}
