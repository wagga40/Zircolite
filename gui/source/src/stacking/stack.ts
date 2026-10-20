import type { Field, Schema } from '../engine/schema';
import { ident } from '../engine/sql';
import { fieldTerm, fieldToken } from '../search/edit';
import type { LocalColumn } from '../ui/localFilters';

/** Stacked at once: past three fields, almost every combination is its own row. */
export const STACK_FIELDS = 3;
/** Rows the table shows; the rest are reached through the column filters. */
export const STACK_LIMIT = 1000;

// Each slot names the fields that hold one thing, first match wins, so a preset fits Sysmon and Security alike.
const PRESETS: readonly (readonly string[])[][] = [
  [['Image', 'NewProcessName']],
  [['CommandLine']],
  [['ParentImage', 'ParentProcessName'], ['Image', 'NewProcessName']],
  [['Image', 'NewProcessName'], ['User', 'TargetUserName', 'SubjectUserName']],
  [['ServiceName'], ['ImagePath']],
  [['TaskName']],
  [['QueryName']],
  [['DestinationIp'], ['DestinationPort']],
  [['TargetFilename']],
];

/** The stacks worth a click in this package: those whose every field it has. */
export function stackPresets(schema: Schema): Field[][] {
  return PRESETS.flatMap((preset) => {
    const fields = preset.map((names) => names.map((name) => schema.find(name)).find((field) => field !== undefined));
    return fields.every((field) => field !== undefined) ? [fields as Field[]] : [];
  });
}

export interface StackRow {
  /** The stacked values, v0 to v2, null where the event has no such field. */
  [value: `v${number}`]: string | null;
  events: number;
  /** Distinct hosts, or null when the package has no host field. */
  hosts: number | null;
  detections: number;
  first: number | null;
  last: number | null;
  /** Rows under the filters and the column filters, before the limit. */
  total: number;
}

/** The table's columns, which its filter cells and sorts name. */
export function STACK_COLUMNS(fields: number): LocalColumn[] {
  return [
    ...Array.from({ length: fields }, (_, i): LocalColumn => ({ name: `v${i}`, type: 'text' })),
    { name: 'events', type: 'number' },
    { name: 'hosts', type: 'number' },
    { name: 'detections', type: 'number' },
    { name: 'first', type: 'time' },
    { name: 'last', type: 'time' },
  ];
}

/** Rarest first: values seen in few events on few hosts are where unusual activity hides. */
export const STACK_ORDER = ['"events" ASC', '"hosts" ASC NULLS LAST', 'lower("v0")', '"v0"'];

export interface StackOptions {
  /** Keep events that lack a stacked field, as a value of their own. */
  missing?: boolean;
  /** The table's own column filters, over the grouped rows. */
  filter?: string;
  order?: string;
  limit?: number;
}

/**
 * Each combination of the fields' values among the filtered events, grouped
 * ignoring case as the search compares them, with how many events and hosts
 * carry it, how many of those a rule matched, and when it was first and last seen.
 */
export function stackSql(fields: Field[], where: string, host: Field | null, options: StackOptions = {}): string {
  const { missing = false, filter = 'TRUE', order = STACK_ORDER.join(', '), limit = STACK_LIMIT } = options;
  const values = fields.map((field, i) => `CAST(${ident(field.name)} AS VARCHAR) AS f${i}`);
  const present = missing ? '' : ` AND ${fields.map((field) => `${ident(field.name)} IS NOT NULL`).join(' AND ')}`;
  const hostValue = host ? `CAST(${ident(host.name)} AS VARCHAR)` : 'NULL::VARCHAR';
  const firsts = fields.map((_, i) => `min(f${i}) AS v${i}`);
  const groups = fields.map((_, i) => `lower(f${i})`);
  return (
    `WITH x AS (SELECT _zl_uid, _zl_time, ${values.join(', ')}, ${hostValue} AS h FROM events WHERE (${where})${present}), ` +
    `g AS (SELECT ${firsts.join(', ')}, count(*)::DOUBLE AS events, ` +
    `${host ? 'count(DISTINCT lower(h))::DOUBLE' : 'NULL::DOUBLE'} AS hosts, count(l._zl_uid)::DOUBLE AS detections, ` +
    'epoch_ms(min(_zl_time))::DOUBLE AS first, epoch_ms(max(_zl_time))::DOUBLE AS last ' +
    `FROM x LEFT JOIN event_levels l ON l._zl_uid = x._zl_uid GROUP BY ${groups.join(', ')}) ` +
    `SELECT *, (count(*) OVER ())::DOUBLE AS total FROM g WHERE ${filter} ORDER BY ${order} LIMIT ${Math.max(1, Math.floor(limit))}`
  );
}

/** The search that lists exactly a row's events: each field's value, or its absence. */
export function stackTerms(fields: Field[], row: StackRow): string {
  return fields.map((field, i) => {
    const value = row[`v${i}`];
    return value === null ? `-${fieldToken(field.name)}:*` : fieldTerm(field.name, value);
  }).join(' ');
}
