import type { Db } from '../engine/db';
import type { Manifest } from '../engine/manifest';
import { nameResolver } from '../engine/names';
import type { Field, FieldType } from '../engine/schema';
import { formatCount, isoTime, levelName } from '../ui/format';
import { type PageRow, pageSql } from './table';

/** Beyond this the export would hold too much in the browser's memory: refuse and say why. */
export const EXPORT_LIMIT = 500_000;
/** JSON carries every field of every event, several times a CSV row's size. */
export const JSON_EXPORT_LIMIT = 100_000;
/** The text an export may build, as UTF-16 bytes; past it a tab is likely to run out of memory. */
export const EXPORT_BUDGET = 400_000_000;

export class ExportTooLarge extends Error {
  constructor() {
    super('The export would exceed 400 MB, which the browser may not hold. Narrow the search or the time range first.');
    this.name = 'ExportTooLarge';
  }
}

/** Why an export of this many events is refused before it starts, or null when it may run. */
export function limitNote(kind: 'csv' | 'json', count: number): string | null {
  if (kind === 'json' && count > JSON_EXPORT_LIMIT) {
    return `A JSON export holds at most ${formatCount(JSON_EXPORT_LIMIT)} events and these results have ${formatCount(count)}. ` +
      `Narrow the search or the time range first, or export CSV, which holds up to ${formatCount(EXPORT_LIMIT)}.`;
  }
  if (count > EXPORT_LIMIT) {
    return `An export holds at most ${formatCount(EXPORT_LIMIT)} events and these results have ${formatCount(count)}. Narrow the search or the time range first.`;
  }
  return null;
}

/** Counts what a part costs against the budget; a part that would pass it ends the export. */
function spend(used: number, part: string, budget: number): number {
  const next = used + part.length * 2;
  if (next > budget) throw new ExportTooLarge();
  return next;
}
export const SNAPSHOT_SQL = 'CREATE OR REPLACE TEMP TABLE export_ids AS SELECT * FROM view_ids';

type Reader = Pick<Db, 'rows' | 'exec'>;

/** Freeze the results for one export, so changing the filters meanwhile cannot mix two lists; returns their count. */
export async function prepareExport(db: Reader): Promise<number> {
  await db.exec(SNAPSHOT_SQL);
  const [row] = await db.rows<{ n: number }>('SELECT count(*)::DOUBLE AS n FROM export_ids', { cache: false });
  return row.n;
}

// Log text is attacker-controlled: a cell starting with one of these runs as a formula in a spreadsheet.
const FORMULA = /^[=+\-@\t\r]/;

const PLAIN_NUMBER = /^-?\d+(\.\d+)?([eE][+-]?\d+)?$/;

/** A value from a numeric column that is plainly a number stays one: a negative is not a formula. */
export function csvCell(value: string | null, numeric = false): string {
  if (value === null) return '';
  const text = FORMULA.test(value) && !(numeric && PLAIN_NUMBER.test(value)) ? `'${value}` : value;
  return /[",\r\n]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
}

export function csvLine(values: (string | null)[], numeric: boolean[] = []): string {
  return `${values.map((value, i) => csvCell(value, numeric[i] ?? false)).join(',')}\r\n`;
}

const JSON_NUMBER = /^-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?$/;

export interface JsonEntry {
  name: string;
  type: FieldType;
  text: string;
}

/** One event as JSON text; numbers are copied digit for digit, so 64-bit values stay exact. */
export function eventJson(entries: JsonEntry[], pretty = false): string {
  if (entries.length === 0) return '{}';
  const parts = entries.map((entry) => {
    const value = entry.type !== 'VARCHAR' && JSON_NUMBER.test(entry.text) ? entry.text : JSON.stringify(entry.text);
    return `${JSON.stringify(entry.name)}:${pretty ? ' ' : ''}${value}`;
  });
  return pretty ? `{\n  ${parts.join(',\n  ')}\n}` : `{${parts.join(',')}}`;
}

export async function csvExport(
  db: Reader,
  columns: Field[],
  total: number,
  progress: (done: number) => void,
  cancelled: () => boolean,
  batch = 10_000,
  budget = EXPORT_BUDGET,
): Promise<BlobPart[] | null> {
  // The byte order mark makes Excel read the file as UTF-8.
  const head = `\uFEFF${csvLine(['Time (UTC)', 'Level', ...columns.map((c) => c.name)])}`;
  let used = spend(0, head, budget);
  const parts: BlobPart[] = [head];
  for (let from = 0; from < total; from += batch) {
    if (cancelled()) return null;
    const rows = await db.rows<PageRow>(pageSql(columns, from, from + batch, 'export_ids'), { cache: false });
    const part = rows.map((row) => csvLine([isoTime(row._zl_t), levelName(row._zl_lvl), ...columns.map((_, i) => row[`_zl_v${i}`] ?? null)], [false, false, ...columns.map((c) => c.type !== 'VARCHAR')])).join('');
    used = spend(used, part, budget);
    parts.push(part);
    progress(Math.min(total, from + batch));
  }
  return parts;
}

export async function jsonExport(
  db: Reader,
  fields: Field[],
  manifest: Pick<Manifest, 'parts'>,
  total: number,
  progress: (done: number) => void,
  cancelled: () => boolean,
  batch = 5_000,
  budget = EXPORT_BUDGET,
): Promise<BlobPart[] | null> {
  const parts: BlobPart[] = [];
  let used = 0;
  const resolvers = new Map<string, (field: Field) => string>();
  for (let from = 0; from < total; from += batch) {
    if (cancelled()) return null;
    const rows = await db.rows<PageRow>(pageSql(fields, from, from + batch, 'export_ids', true), { cache: false });
    const part = rows
      .map((row) => {
        const key = `${row._zl_part}\u0000${row._zl_spelling ?? ''}`;
        let name = resolvers.get(key);
        if (!name) {
          name = nameResolver(manifest, row._zl_part ?? null, row._zl_spelling ?? null);
          resolvers.set(key, name);
        }
        const resolve = name;
        const entries = fields.flatMap((field, i) => {
          const text = row[`_zl_v${i}`];
          return text === null || text === undefined ? [] : [{ name: resolve(field), type: field.type, text }];
        });
        return `${eventJson(entries)}\n`;
      })
      .join('');
    used = spend(used, part, budget);
    parts.push(part);
    progress(Math.min(total, from + batch));
  }
  return parts;
}
