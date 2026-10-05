import { isSuperseded } from '../engine/queries';
import { str } from '../engine/sql';

/*
 * Why the console needs no filter on the person's text: it reaches the engine only as one string
 * literal, built with str(), handed to DuckDB's query() table function. query() parses the string
 * itself and accepts exactly one SELECT (WITH, VALUES and FROM-first included), so a second
 * statement or a write is a parse error and a break-out cannot end the literal early.
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

/** Describe and run one query through query(). */
export async function runQuery(rows: Rows, input: string): Promise<Result> {
  const text = trimStatement(input);
  if (!text) throw new SqlRefused('the query is empty');
  let described: Record<string, unknown>[];
  try {
    described = await rows(describeSql(text));
  } catch (error) {
    if (isSuperseded(error)) throw error;
    const why = error instanceof Error ? error.message : String(error);
    throw new SqlRefused(`only one SELECT query runs here (WITH, VALUES and FROM-first too); DuckDB says: ${why}`);
  }
  const columns = described.map((d) => ({ name: String(d.column_name), type: String(d.column_type) }));
  const raw = await rows(resultSql(text, columns.length));
  return {
    columns,
    rows: raw.slice(0, SQL_ROW_LIMIT).map((row) => columns.map((_, i) => (row[`c${i}`] ?? null) as string | null)),
    more: raw.length > SQL_ROW_LIMIT,
  };
}

/** The package's tables and their columns, for the list beside the editor. */
export const TABLES_SQL =
  "SELECT table_name AS t, column_name AS c, data_type AS type FROM information_schema.columns " +
  "WHERE table_name IN ('events', 'rules', 'hits', 'alerts', 'alert_events') ORDER BY table_name, ordinal_position";

/** Whether a column's type is a number, so a negative value in a CSV cell is not taken for a formula. */
export function numericType(type: string): boolean {
  return /^(TINYINT|SMALLINT|INTEGER|BIGINT|HUGEINT|UTINYINT|USMALLINT|UINTEGER|UBIGINT|UHUGEINT|FLOAT|DOUBLE|DECIMAL)/.test(type);
}
