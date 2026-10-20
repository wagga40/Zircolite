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
 * A page of the index that cannot be read fails the index the same way, and
 * the search goes back to the scan.
 */
import { escapeClause, str } from './sql';

/** The registered name of the index file; its row groups are what the scan is sliced along. */
export const TEXT_FILE = 'text.parquet';

/** The view every full-text predicate reads. */
export const TEXT_VIEW_SQL = `CREATE OR REPLACE VIEW fulltext AS SELECT * FROM read_parquet(${str(TEXT_FILE)})`;

export type RunSql = (sql: string) => Promise<Record<string, unknown>[]>;

/** How far a scan of a whole file has got: it runs in `total` slices, `done` of them already. */
export interface Scan {
  label: string;
  done: number;
  total: number;
}

/** How far the scan being built has got. */
export type Progress = (scan: Scan) => void;

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

// A bare word's pattern always opens and closes with %. Only a match that starts outside every
// literal and quoted name is a predicate: a value, or a field name taken from the logs, may spell one.
const PREDICATE = /_zl_uid IN \(SELECT _zl_uid FROM fulltext WHERE _zl_text LIKE (lower\('%(?:[^']|'')*%'\))(?: ESCAPE '\\')?\)/g;

// A field match compile() writes for a pattern that opens with %. A name's own quotes are doubled, so a
// match that starts outside every literal and quoted name reads the name and the pattern as compile wrote them.
const COLUMN = String.raw`(?:"(?:[^"]|"")+"|CAST\("(?:[^"]|"")+" AS VARCHAR\))`;
const OPEN_LITERAL = String.raw`'%(?:[^']|'')*'`;
const FIELD_PREDICATE = new RegExp(String.raw`_zl_uid IN \(SELECT _zl_uid FROM events WHERE (${COLUMN} ILIKE ${OPEN_LITERAL}(?: ESCAPE '\\')?)\)`, 'g');
// One run of text between two wildcards, with nothing escaped: a plain contains.
const PLAIN_CONTAINS = new RegExp(String.raw`^(${COLUMN}) ILIKE ('%(?:[^%_'\\]|'')*%')$`);

/**
 * A field predicate as a large column's scan runs it. lower() on both sides
 * is what ILIKE does, and the engine answers LIKE '%x%' with its contains(),
 * twice as fast over 3 GiB of messages; on short values, which ILIKE rejects
 * from their first characters, lowering every value costs more than it saves.
 */
export function largeScan(predicate: string): string {
  const plain = PLAIN_CONTAINS.exec(predicate);
  return plain ? `lower(${plain[1]}) LIKE lower(${plain[2]})` : predicate;
}

/** The registered name of the events file, whose row groups a field scan is sliced along. */
export const EVENTS_FILE = 'events.parquet';

/** Matches kept at once of each kind; each holds one row per matching event. */
const KEPT = 4;
/** Enough slices that a cancel waits seconds, not the whole scan, and few enough that each is worth its overhead. */
const SLICES = 12;

interface Entry {
  table: string;
  /** Slices already inserted, so a scan that was stopped resumes instead of starting over. */
  done: number;
  ready: boolean;
}

/**
 * Whether a position of a statement lies outside its string literals and
 * quoted names, each closed by its own quote with a doubled quote inside.
 */
export function outsideQuotes(sql: string): (index: number) => boolean {
  const quoted: [number, number][] = [];
  for (let i = 0; i < sql.length; i++) {
    const quote = sql[i];
    if (quote !== "'" && quote !== '"') continue;
    const start = i;
    for (i++; i < sql.length; i++) {
      if (sql[i] !== quote) continue;
      if (sql[i + 1] !== quote) break;
      i++;
    }
    quoted.push([start, i]);
  }
  return (index) => !quoted.some(([start, end]) => index >= start && index <= end);
}

/** Lower bounds of the slices: every k-th row group's first uid, so each slice reads only its own row groups. */
export function sliceBounds(firstUids: number[], slices = SLICES): number[] {
  const starts = [...new Set(firstUids)].sort((a, b) => a - b);
  const step = Math.max(1, Math.ceil(starts.length / slices));
  return starts.filter((_, i) => i > 0 && i % step === 0);
}

interface Kind {
  /** Finds each predicate; its first group tells two predicates apart. */
  pattern: RegExp;
  /** The prefix of the tables that hold the matches. */
  table: string;
  /** The Parquet file the scan reads, sliced along its row groups. */
  file: string;
  /** The scan of one predicate, before its slice bounds. */
  scan(key: string): string;
  /** What the page says while it scans. */
  label(key: string): string;
}

/** Predicates that scan a whole file, each answered once into a table of uids that every query then reads. */
class Matches {
  private readonly entries = new Map<string, Entry>();
  /** Each row group's first uid; empty when the file cannot say, and the scan is one slice. */
  private firsts: number[] | null = null;
  private counter = 0;
  /** Tables whose DROP did not go through, such as one a Stop cancelled; each is tried again on the next eviction. */
  private readonly undropped: string[] = [];

  constructor(
    protected readonly run: RunSql,
    private readonly kind: Kind,
    private readonly progress: Progress = () => {},
  ) {}

  /** The query with each predicate answered from its table of matches, built first when it is missing. */
  async prepare(sql: string, stop: Stop): Promise<string> {
    const pattern = this.kind.pattern;
    const free = outsideQuotes(sql);
    const keys = [...new Set([...sql.matchAll(pattern)].filter((m) => free(m.index)).map((m) => m[1]))];
    if (keys.length === 0) return sql;
    const tabled = new Set<string>();
    for (const key of keys) if (await this.worth(key, stop)) tabled.add(key);
    if (tabled.size > 0) await this.ready(stop);
    for (const key of tabled) await this.build(key, tabled, stop);
    return sql.replace(pattern, (whole: string, key: string, at: number) => {
      if (!free(at)) return whole;
      return tabled.has(key) ? `_zl_uid IN (SELECT _zl_uid FROM ${(this.entries.get(key) as Entry).table})` : `(${key})`;
    });
  }

  /** Whether a predicate is worth a table; one that is not is answered in place, as the same predicate. */
  protected async worth(_key: string, _stop: Stop): Promise<boolean> {
    return true;
  }

  /** Whatever must hold before a scan can run. */
  protected async ready(_stop: Stop): Promise<void> {}

  /** How many slices a predicate's scan is cut into. */
  protected slices(_key: string): number {
    return SLICES;
  }

  /** A scan failed for a reason of its own, not a Stop. */
  protected broken(_error: unknown): void {}

  private async build(key: string, wanted: Set<string>, stop: Stop): Promise<void> {
    let entry = this.entries.get(key);
    if (entry) {
      // Most recently used last, so the oldest is the one dropped.
      this.entries.delete(key);
      this.entries.set(key, entry);
      if (entry.ready) return;
    } else {
      entry = { table: `${this.kind.table}${++this.counter}`, done: 0, ready: false };
      this.entries.set(key, entry);
      await this.evict(wanted, stop);
    }
    const bounds = sliceBounds(await this.rowGroups(stop), this.slices(key));
    const scan = (done: number) => this.progress({ label: this.kind.label(key), done, total: bounds.length + 1 });
    while (entry.done <= bounds.length) {
      if (stop.cancelled()) throw stop.superseded();
      scan(entry.done);
      const low = entry.done > 0 ? ` AND _zl_uid >= ${bounds[entry.done - 1]}` : '';
      const high = entry.done < bounds.length ? ` AND _zl_uid < ${bounds[entry.done]}` : '';
      const select = `${this.kind.scan(key)}${low}${high}`;
      try {
        await this.run(entry.done === 0 ? `CREATE OR REPLACE TEMP TABLE ${entry.table} AS ${select}` : `INSERT INTO ${entry.table} ${select}`);
      } catch (error) {
        if (stop.cancelled()) throw stop.superseded();
        this.broken(error);
        throw error;
      }
      entry.done += 1;
    }
    scan(entry.done);
    entry.ready = true;
  }

  private async rowGroups(stop: Stop): Promise<number[]> {
    if (this.firsts) return this.firsts;
    if (stop.cancelled()) throw stop.superseded();
    let firsts: number[] = [];
    try {
      const rows = await this.run(
        `SELECT min(stats_min_value::BIGINT)::DOUBLE AS first FROM parquet_metadata(${str(this.kind.file)}) WHERE path_in_schema = '_zl_uid' GROUP BY row_group_id`,
      );
      const found = rows.map((row) => Number(row.first));
      // Bounds that are not exact integers would drop events; without them the scan is one slice.
      if (found.every(Number.isSafeInteger)) firsts = found;
    } catch (error) {
      // A cancelled lookup says nothing about the file, so it must not settle the question for good.
      if (stop.cancelled()) throw stop.superseded();
    }
    this.firsts = firsts;
    return firsts;
  }

  private async evict(wanted: Set<string>, stop: Stop): Promise<void> {
    for (const [key, entry] of [...this.entries]) {
      if (this.entries.size <= KEPT) break;
      if (wanted.has(key)) continue;
      this.entries.delete(key);
      this.undropped.push(entry.table);
    }
    for (const table of [...this.undropped]) {
      if (stop.cancelled()) return;
      try {
        await this.run(`DROP TABLE IF EXISTS ${table}`);
        this.undropped.splice(this.undropped.indexOf(table), 1);
      } catch {
        // Kept for the next eviction.
      }
    }
  }
}

export class TextMatches extends Matches {
  /** Without a source the view is taken to exist already; a query over a missing view fails on its own. */
  private source: TextSource | null = null;
  private opened = false;

  constructor(run: RunSql, progress?: Progress) {
    super(run, {
      pattern: PREDICATE,
      table: '_zl_tm_',
      file: TEXT_FILE,
      scan: (like) => `SELECT _zl_uid FROM fulltext WHERE _zl_text LIKE ${like}${escapeClause(like)}`,
      label: () => 'Searching every field',
    }, progress);
  }

  use(source: TextSource): void {
    this.source = source;
    this.opened = false;
  }

  protected override async ready(stop: Stop): Promise<void> {
    const source = this.source;
    if (this.opened || source === null) return;
    await stop.until(source.registered);
    // Given up while the file was on its way: the view can be opened by whoever asks next.
    if (stop.cancelled()) throw stop.superseded();
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

  protected override broken(error: unknown): void {
    // The file registered and opened but a page of it cannot be read: the scan still can.
    this.source?.failed(error);
  }
}

/**
 * A column smaller than this, as the file stores it, is scanned in place.
 * Measured on 1.87M events: a table of matches costs about half a second to
 * build and join, more than a few scans of a column of names or paths take,
 * and saves half a minute on 3 GiB of rendered messages.
 */
export const LARGE_COLUMN = 64 * 1024 * 1024;
/** About a second of reading a column in the browser: each slice of a field scan reads this much, so a Stop waits about that long. */
const SLICE_BYTES = 256 * 1024 * 1024;

/** The predicate's first quoted name is its column: a literal comes after it, in single quotes. */
function columnOf(predicate: string): string | undefined {
  return /"((?:[^"]|"")+)"/.exec(predicate)?.[1].replaceAll('""', '"');
}

/**
 * Field matches that open with a wildcard, such as CommandLine:*powershell*:
 * the engine reads the whole column for each, and the list, the strip and the
 * counts of one search would each read it again. Only a large column's are
 * worth a table.
 */
export class FieldMatches extends Matches {
  private sizes: Map<string, number> | null = null;

  constructor(
    run: RunSql,
    private readonly large = LARGE_COLUMN,
    private readonly sliceBytes = SLICE_BYTES,
    progress?: Progress,
  ) {
    super(run, {
      pattern: FIELD_PREDICATE,
      table: '_zl_fm_',
      file: EVENTS_FILE,
      // Parenthesised, so the slice bounds appended after it bind to the whole predicate.
      scan: (predicate) => `SELECT _zl_uid FROM events WHERE (${largeScan(predicate)})`,
      label: (predicate) => `Searching ${columnOf(predicate) ?? 'a field'}`,
    }, progress);
  }

  protected override async worth(predicate: string, stop: Stop): Promise<boolean> {
    await this.columnSizes(stop);
    return this.sizeOf(predicate) >= this.large;
  }

  protected override slices(predicate: string): number {
    // A slice costs a statement; a column read in a second or two needs no more than one.
    return Math.min(SLICES, Math.max(1, Math.round(this.sizeOf(predicate) / this.sliceBytes)));
  }

  private sizeOf(predicate: string): number {
    const name = columnOf(predicate);
    return name === undefined ? 0 : (this.sizes?.get(name) ?? 0);
  }

  private async columnSizes(stop: Stop): Promise<Map<string, number>> {
    if (this.sizes) return this.sizes;
    if (stop.cancelled()) throw stop.superseded();
    let sizes = new Map<string, number>();
    try {
      const rows = await this.run(
        `SELECT path_in_schema AS c, sum(total_uncompressed_size)::DOUBLE AS b FROM parquet_metadata(${str(EVENTS_FILE)}) GROUP BY path_in_schema`,
      );
      sizes = new Map(rows.map((row) => [String(row.c), Number(row.b)]));
    } catch {
      // A cancelled lookup says nothing about the file; one that failed leaves every match in place, which is exact.
      if (stop.cancelled()) throw stop.superseded();
    }
    this.sizes = sizes;
    return sizes;
  }
}
