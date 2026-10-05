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
 */
import { escapeClause } from './sql';

/** The registered name of the index file; its row groups are what the scan is sliced along. */
export const TEXT_FILE = 'text.parquet';

export type RunSql = (sql: string) => Promise<Record<string, unknown>[]>;

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

  constructor(private readonly run: RunSql) {}

  /** The query with each full-text predicate answered from its table of matches, built first when it is missing. */
  async prepare(sql: string, cancelled: () => boolean, superseded: () => Error): Promise<string> {
    const likes = [...new Set([...sql.matchAll(PREDICATE)].map((m) => m[1]))];
    if (likes.length === 0) return sql;
    for (const like of likes) await this.build(like, new Set(likes), cancelled, superseded);
    return sql.replace(PREDICATE, (_whole, like: string) => `_zl_uid IN (SELECT _zl_uid FROM ${(this.entries.get(like) as Entry).table})`);
  }

  private async build(like: string, wanted: Set<string>, cancelled: () => boolean, superseded: () => Error): Promise<void> {
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
    const bounds = await this.sliceBounds(cancelled, superseded);
    while (entry.done <= bounds.length) {
      if (cancelled()) throw superseded();
      const low = entry.done > 0 ? ` AND _zl_uid >= ${bounds[entry.done - 1]}` : '';
      const high = entry.done < bounds.length ? ` AND _zl_uid < ${bounds[entry.done]}` : '';
      const select = `SELECT _zl_uid FROM fulltext WHERE _zl_text LIKE ${like}${escapeClause(like)}${low}${high}`;
      await this.run(entry.done === 0 ? `CREATE OR REPLACE TEMP TABLE ${entry.table} AS ${select}` : `INSERT INTO ${entry.table} ${select}`);
      entry.done += 1;
    }
    entry.ready = true;
  }

  private async sliceBounds(cancelled: () => boolean, superseded: () => Error): Promise<number[]> {
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
      if (cancelled()) throw superseded();
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
