import { isSuperseded } from '../engine/queries';
import { str } from '../engine/sql';

/*
 * Why the console needs no filter on the person's text: it reaches the engine only as one string
 * literal, built with str(), handed to DuckDB's query() table function. query() parses the string
 * itself and accepts exactly one SELECT (WITH, VALUES and FROM-first included), so a second
 * statement or anything but a SELECT is refused and a break-out cannot end the literal early.
 * A SELECT can still call DuckDB's logging and checkpoint table functions, which change this
 * session's logging and in-memory files, never the package's tables; runQuery switches logging
 * back off after each run.
 */

/** Rows the console shows; past this, it says there are more. */
export const SQL_ROW_LIMIT = 10_000;

/** The query without the trailing semicolons a console habitually gets: query() takes one statement. */
export function trimStatement(text: string): string {
  return text.trim().replace(/[\s;]+$/, '');
}

export function describeSql(text: string): string {
  return `DESCRIBE SELECT * FROM query(${str(text)})`;
}

/** Every column as text, named by position: 64-bit values stay exact, and two columns of one name stay two. */
export function resultSql(text: string, columns: number, limit = SQL_ROW_LIMIT + 1): string {
  const names = Array.from({ length: columns }, (_, i) => `c${i}`);
  return `SELECT ${names.map((n) => `CAST(${n} AS VARCHAR) AS ${n}`).join(', ')} FROM query(${str(text)}) AS _zl_q(${names.join(', ')}) LIMIT ${limit}`;
}

/** A query the console will not run, with why. */
export class SqlRefused extends Error {}

export interface Column {
  name: string;
  type: string;
}

export interface Result {
  columns: Column[];
  rows: (string | null)[][];
  more: boolean;
}

export type Rows = (sql: string) => Promise<Record<string, unknown>[]>;

const REFUSAL = /Expected a single SELECT statement/;
// DuckDB quotes the line it failed on, and that line is the console's wrapper, not the person's text.
const LINE_EXCERPT = /\s*LINE \d+:[\s\S]*$/;

function explain(error: unknown): Error {
  if (isSuperseded(error)) return error as Error;
  const why = (error instanceof Error ? error.message : String(error)).replace(LINE_EXCERPT, '').trim();
  return REFUSAL.test(why)
    ? new SqlRefused('only one SELECT query runs here (WITH, VALUES and FROM-first too; a PIVOT needs its IN list)')
    : new Error(why);
}

// The setting reads as 0 and 1 here and may read as a boolean elsewhere.
export const LOGGING_SQL = "SELECT CAST(current_setting('enable_logging') AS VARCHAR) IN ('1', 'true') AS on";

/** A query may have switched logging on; it is session state that nothing in the viewer reads. */
async function switchOffLogging(rows: Rows): Promise<void> {
  const [state] = await rows(LOGGING_SQL);
  if (String(state?.on) === 'true') await rows('SELECT * FROM disable_logging()');
}

/** Describe and run one query through query(), then leave logging off. */
export async function runQuery(rows: Rows, input: string): Promise<Result> {
  const text = trimStatement(input);
  if (!text) throw new SqlRefused('the query is empty');
  let superseded = false;
  try {
    let described: Record<string, unknown>[];
    try {
      described = await rows(describeSql(text));
    } catch (error) {
      throw explain(error);
    }
    const columns = described.map((d) => ({ name: String(d.column_name), type: String(d.column_type) }));
    let raw: Record<string, unknown>[];
    try {
      raw = await rows(resultSql(text, columns.length));
    } catch (error) {
      throw explain(error);
    }
    return {
      columns,
      rows: raw.slice(0, SQL_ROW_LIMIT).map((row) => columns.map((_, i) => (row[`c${i}`] ?? null) as string | null)),
      more: raw.length > SQL_ROW_LIMIT,
    };
  } catch (error) {
    superseded = isSuperseded(error);
    throw error;
  } finally {
    if (!superseded) await switchOffLogging(rows);
  }
}

/** The package's tables and their columns, for the list beside the editor. */
export const TABLES_SQL =
  "SELECT table_name AS t, column_name AS c, data_type AS type FROM information_schema.columns " +
  "WHERE table_name IN ('events', 'rules', 'hits', 'alerts', 'alert_events') ORDER BY table_name, ordinal_position";

/** Whether a column's type is a number, so a negative value in a CSV cell is not taken for a formula. Lists are not. */
export function numericType(type: string): boolean {
  return /^(TINYINT|SMALLINT|INTEGER|BIGINT|HUGEINT|UTINYINT|USMALLINT|UINTEGER|UBIGINT|UHUGEINT|FLOAT|DOUBLE|DECIMAL(\(\d+,\s*\d+\))?)$/.test(type);
}

/** Column widths in characters, from the header and every row shown, so they do not move while scrolling. */
export function columnWidths(columns: Column[], rows: (string | null)[][]): number[] {
  return columns.map((column, i) => {
    let longest = column.name.length;
    for (const row of rows) longest = Math.max(longest, (row[i] ?? 'NULL').length);
    return Math.min(60, Math.max(8, longest + 2));
  });
}
