import { isSuperseded } from '../engine/queries';
import { str } from '../engine/sql';
import type { LocalColumn } from '../ui/localFilters';

/*
 * Why the console needs no filter on the person's text: it reaches the engine only as one string
 * literal, built with str(), handed to DuckDB's query() table function. query() parses the string
 * itself and accepts exactly one SELECT (WITH, VALUES and FROM-first included), so a second
 * statement or anything but a SELECT is refused and a break-out cannot end the literal early.
 * A SELECT can still call DuckDB's logging and checkpoint table functions, which change this
 * session's logging and in-memory files, never the package's tables; runQuery switches logging
 * back off after each run, whether or not anyone still waits for the run.
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

/** The result columns' own filters and order, as SQL over their positional names; empty for none. */
export interface Narrowing {
  filter: string;
  order: string;
}

/** The result columns as the filter cells read them: a number column compares, any other is text, as shown. */
export function consoleColumns(columns: Column[]): LocalColumn[] {
  return columns.map((column, i) => ({ name: `c${i}`, type: numericType(column.type) ? 'number' : 'text' }));
}

/**
 * Every column as text, named by position: 64-bit values stay exact, and two
 * columns of one name stay two. With a narrowing, the query is filtered and
 * ordered in the engine over all its rows, numbers as numbers and everything
 * else as the text the table shows, before the limit.
 */
export function resultSql(text: string, columns: Column[] | number, limit = SQL_ROW_LIMIT + 1, narrow: Narrowing | null = null): string {
  const types = typeof columns === 'number' ? Array.from({ length: columns }, () => '') : columns.map((column) => column.type);
  const names = types.map((_, i) => `c${i}`);
  const shown = names.map((n) => `CAST(${n} AS VARCHAR) AS ${n}`).join(', ');
  const source = `query(${str(text)}) AS _zl_q(${names.join(', ')})`;
  if (narrow === null || (narrow.filter === 'TRUE' && !narrow.order)) return `SELECT ${shown} FROM ${source} LIMIT ${limit}`;
  const typed = names.map((n, i) => (numericType(types[i]) ? n : `CAST(${n} AS VARCHAR) AS ${n}`)).join(', ');
  const order = narrow.order ? ` ORDER BY ${narrow.order}` : '';
  // Filtered, ordered and cut below the text cast, where an ORDER BY name means the typed column, not the shown text.
  return `SELECT ${shown} FROM (SELECT * FROM (SELECT ${typed} FROM ${source}) _zl_r WHERE ${narrow.filter}${order} LIMIT ${limit}) _zl_s`;
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

/**
 * Describe and run one query through query(), then leave logging off. The reset goes through
 * `reset`, which must reach the page's connection outside the console's own scope: a run stopped,
 * superseded or left behind by its view may have switched logging on before it ended.
 */
export async function runQuery(rows: Rows, input: string, reset: Rows = rows, narrow: Narrowing | null = null): Promise<Result> {
  const text = trimStatement(input);
  if (!text) throw new SqlRefused('the query is empty');
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
      raw = await rows(resultSql(text, columns, SQL_ROW_LIMIT + 1, narrow));
    } catch (error) {
      throw explain(error);
    }
    return {
      columns,
      rows: raw.slice(0, SQL_ROW_LIMIT).map((row) => columns.map((_, i) => (row[`c${i}`] ?? null) as string | null)),
      more: raw.length > SQL_ROW_LIMIT,
    };
  } finally {
    try {
      await switchOffLogging(reset);
    } catch {
      // A leftover logging flag matters less than the answer; the next run resets it.
    }
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

/** Wide enough for a column's filter cell to show a short comparison, such as >=1000. */
const MIN_WIDTH = 12;

/** Column widths in characters, from the header and every row shown, so they do not move while scrolling. */
export function columnWidths(columns: Column[], rows: (string | null)[][]): number[] {
  return columns.map((column, i) => {
    let longest = column.name.length;
    for (const row of rows) longest = Math.max(longest, (row[i] ?? 'NULL').length);
    return Math.min(60, Math.max(MIN_WIDTH, longest + 2));
  });
}
