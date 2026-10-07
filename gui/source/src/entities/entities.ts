import type { Field, Schema } from '../engine/schema';
import { escapeClause, ident, likeEscape, str } from '../engine/sql';
import { fieldTerm } from '../search/edit';
import { findShortcut } from '../search/shortcuts';

export type EntityKindName = 'hosts' | 'users' | 'ips' | 'processes' | 'hashes' | 'domains';

export interface EntityKind {
  kind: EntityKindName;
  label: string;
  /** What the values are, for "This package has no field for …". */
  noun: string;
  /** Log fields that hold the kind, as Zircolite's field mappings name them; the package's are used. */
  fields: readonly string[];
}

export const ENTITY_KINDS: readonly EntityKind[] = [
  { kind: 'hosts', label: 'Hosts', noun: 'host names', fields: findShortcut('host')?.fields ?? [] },
  { kind: 'users', label: 'Users', noun: 'account names', fields: findShortcut('user')?.fields ?? [] },
  { kind: 'ips', label: 'IP addresses', noun: 'IP addresses', fields: ['SourceIp', 'DestinationIp', 'IpAddress', 'SourceAddress', 'DestAddress', 'ClientAddress'] },
  { kind: 'processes', label: 'Processes', noun: 'executables', fields: ['Image', 'NewProcessName', 'ParentImage', 'ProcessName'] },
  // Zircolite's field mappings split Sysmon's Hashes into one field per algorithm.
  { kind: 'hashes', label: 'Hashes', noun: 'file hashes', fields: ['SHA256', 'SHA1', 'MD5', 'IMPHASH'] },
  { kind: 'domains', label: 'Domains', noun: 'domain names', fields: ['QueryName', 'DestinationHostname'] },
];

/**
 * The kind's fields this package has, as text. A field Zircolite stored as a
 * number holds no names or addresses; its term would compare numbers, not
 * the text the table groups.
 */
export function entityFields(kind: EntityKind, schema: Schema): Field[] {
  const found = new Map<string, Field>();
  for (const name of kind.fields) {
    const field = schema.find(name);
    if (field && field.type === 'VARCHAR') found.set(field.key, field);
  }
  return [...found.values()];
}

export type EntityOrder = 'events' | 'detections' | 'first' | 'last';

/** Rows the table shows; the rest are reached through the filter. */
export const ENTITY_LIMIT = 500;

const ORDER: Record<EntityOrder, string> = {
  events: 'events DESC',
  detections: 'detections DESC, events DESC',
  first: 'first ASC NULLS LAST',
  last: 'last DESC NULLS LAST',
};

export interface EntityRow {
  v: string;
  events: number;
  detections: number;
  first: number | null;
  last: number | null;
  /** Values of the kind under the filters, before the limit. */
  total: number;
}

/**
 * Each value of the kind's fields among the filtered events, grouped ignoring
 * case as the search compares them. An event that holds the value in two
 * fields, or in two spellings, counts once.
 */
export function entitiesSql(fields: Field[], where: string, filter: string, order: EntityOrder, limit = ENTITY_LIMIT): string {
  const values = fields.map((field) => `CAST(${ident(field.name)} AS VARCHAR)`).join(', ');
  const literal = str(`%${likeEscape(filter)}%`);
  const narrow = filter ? ` AND v ILIKE ${literal}${escapeClause(literal)}` : '';
  return (
    `WITH x AS (SELECT _zl_uid, _zl_time, unnest([${values}]) AS v FROM events WHERE ${where}), ` +
    `y AS (SELECT DISTINCT _zl_uid, _zl_time, v FROM x WHERE v IS NOT NULL${narrow}) ` +
    'SELECT min(y.v) AS v, count(DISTINCT y._zl_uid)::DOUBLE AS events, ' +
    'count(DISTINCT y._zl_uid) FILTER (WHERE l._zl_uid IS NOT NULL)::DOUBLE AS detections, ' +
    'epoch_ms(min(y._zl_time))::DOUBLE AS first, epoch_ms(max(y._zl_time))::DOUBLE AS last, ' +
    '(count(*) OVER ())::DOUBLE AS total ' +
    'FROM y LEFT JOIN event_levels l ON l._zl_uid = y._zl_uid GROUP BY lower(y.v) ' +
    `ORDER BY ${ORDER[order]}, min(y.v) LIMIT ${Math.max(1, Math.floor(limit))}`
  );
}

/** The search that lists exactly an entity's events: the value in any of the kind's fields. */
export function entityTerm(fields: Field[], value: string): string {
  const terms = fields.map((field) => fieldTerm(field.name, value));
  return terms.length === 1 ? terms[0] : `(${terms.join(' OR ')})`;
}
