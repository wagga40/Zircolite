/**
 * Column filters for a table of its own rows, such as Entities or the SQL
 * console's results. They use the cell syntax and the search grammar of the
 * events table, kept in the table's own filter text rather than the page's
 * search, and compiled against the table's columns into an outer WHERE.
 */
import { Schema } from '../engine/schema';
import { asciiLower, ident } from '../engine/sql';
import { type Applied, applyFilter } from '../explore/header';
import { compile } from '../search/compile';
import { type Bound, CellError, type ColumnFilter, cellText, columnState, parseCell } from '../search/filters';
import { parse } from '../search/parse';
import { isoTime } from './format';

export const TEXT_HINT = 'Contains this text; a whole number is exact. =x is exact, * a wildcard, "…" literal, >5 compares, ! leaves out; Enter applies';
const NUMBER_HINT = '>=10 or >=1 <10 compares, 5 is exact, * has a value, ! leaves out; Enter applies';
const TIME_HINT = '>=2021-06-03 or <2021-06-03 08:00 compares, in UTC; * has a value, ! leaves out; Enter applies';

export function cellHint(type: LocalType): string {
  return type === 'time' ? TIME_HINT : type === 'number' ? NUMBER_HINT : TEXT_HINT;
}

/** Times are epoch milliseconds, shown and typed as UTC dates. */
export type LocalType = 'text' | 'number' | 'time';

export interface LocalColumn {
  /** The column's name in the table's SQL. */
  name: string;
  type: LocalType;
}

/** A column as a table shows it: its name in the SQL, its header, and how a cell reads when not as its value. */
export interface TableColumn<Row> {
  column: LocalColumn;
  label: string;
  show?: (row: Row) => string;
}

export interface LocalSort {
  column: string;
  desc: boolean;
}

/** The table's columns as the compiler reads fields; a quoted name keeps a shortcut's name a column. */
export function localSchema(columns: LocalColumn[]): Schema {
  return new Schema(
    columns.map((column) => ({ name: column.name, key: asciiLower(column.name), type: column.type === 'text' ? 'VARCHAR' : 'DOUBLE', count: 0 })),
    [],
  );
}

export function localWhere(filters: string, schema: Schema): string {
  return filters ? compile(parse(filters), schema) : 'TRUE';
}

const DATE = /^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?)?Z?$/;

/** A UTC date as typed in a cell, in milliseconds; null when it is no such date. */
function dateMs(text: string): number | null {
  const match = DATE.exec(text);
  if (!match) return null;
  const [year, month, day, hour = '0', minute = '0', second = '0', fraction = '0'] = match.slice(1);
  const ms = Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second), Number(fraction.padEnd(3, '0')));
  // Date.UTC rolls 2021-13-40 over into 2022; such a date was a typing mistake.
  return isoTime(ms).startsWith(`${year}-${month}-${day}`) ? ms : null;
}

/** A time as a cell shows it: the date, then the time when there is one, to the millisecond when it has them. */
function dateText(ms: number): string {
  const full = isoTime(ms);
  if (full.endsWith(' 00:00:00.000')) return full.slice(0, 10);
  if (full.endsWith(':00.000')) return full.slice(0, 16);
  return full.endsWith('.000') ? full.slice(0, 19) : full;
}

function timeFilter(text: string): ColumnFilter | null {
  // A comparison with no spaces in its dates, so the bounds split where the next operator starts.
  const filter = parseCell(text.replace(/([<>]=?)\s+/g, '$1').replace(/(\d)[T ](\d)/g, '$1T$2'), true);
  if (filter === null || filter.op === 'present') return filter;
  if (filter.op !== 'compare') throw new CellError('Compare a time with >= or <, as in >=2021-06-03 or <2021-06-03 08:00 (UTC)');
  const bounds = filter.bounds.map((bound): Bound => {
    const ms = dateMs(bound.value);
    if (ms === null) throw new CellError(`A time is written 2021-06-03 or 2021-06-03 08:00, in UTC, not "${bound.value}"`);
    return { op: bound.op, value: String(ms) };
  });
  return { ...filter, bounds };
}

/** What typing in a column's cell does to the table's filters. */
export function applyLocalCell(filters: string, column: LocalColumn, text: string, schema: Schema): Applied {
  let filter: ColumnFilter | null;
  try {
    filter = column.type === 'time' ? timeFilter(text) : parseCell(text, column.type === 'number');
  } catch (problem) {
    if (problem instanceof CellError) return { problem: problem.message };
    throw problem;
  }
  return applyFilter(filters, column.name, filter, schema);
}

export function localCellText(filters: string, column: LocalColumn): string {
  const state = columnState(filters, column.name);
  if (column.type !== 'time' || state.kind !== 'filter' || state.filter.op !== 'compare') return cellText(state, column.type !== 'text');
  const filter = state.filter;
  return `${filter.negate ? '!' : ''}${filter.bounds.map((bound) => `${bound.op}${dateText(Number(bound.value))}`).join(' ')}`;
}

/** The ORDER BY for a table: the chosen column, missing values last, then the table's own order as ties. */
export function sortClause(sort: LocalSort | null, ties: string[]): string {
  const first = sort ? [`${ident(sort.column)} ${sort.desc ? 'DESC' : 'ASC'} NULLS LAST`] : [];
  return [...first, ...ties].join(', ');
}
