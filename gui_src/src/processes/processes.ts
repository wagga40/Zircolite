import type { Schema } from '../engine/schema';
import { ident } from '../engine/sql';

/** Starts the tree reads at once, earliest first; the summary says when there are more. */
export const PROCESS_LIMIT = 20_000;
/** Ancestors added for context, beyond the starts the filters keep. */
export const ANCESTOR_LIMIT = 5_000;

// Each value the tree needs, by the field Zircolite's mappings give it.
const COLUMNS = {
  host: 'Computer',
  guid: 'ProcessGuid',
  pguid: 'ParentProcessGuid',
  pid: 'ProcessId',
  ppid: 'ParentProcessId',
  newpid: 'NewProcessId',
  image: 'Image',
  newimage: 'NewProcessName',
  pimage: 'ParentImage',
  pname: 'ParentProcessName',
  cmd: 'CommandLine',
  user: 'User',
  subject: 'SubjectUserName',
} as const;

/** Sysmon event 1 (Windows and Linux) and Security event 4688: the events that record a process start. */
export function creationPredicate(schema: Schema): string | null {
  const channel = schema.find('Channel');
  const eventid = schema.find('EventID');
  if (!channel || !eventid) return null;
  const c = `lower(CAST(${ident(channel.name)} AS VARCHAR))`;
  const e = `CAST(${ident(eventid.name)} AS VARCHAR)`;
  return `((${c} IN ('microsoft-windows-sysmon/operational', 'linux-sysmon/operational') AND ${e} = '1') OR (${c} = 'security' AND ${e} = '4688'))`;
}

function projection(schema: Schema): string {
  const channel = schema.find('Channel');
  const values = Object.entries(COLUMNS).map(([alias, name]) => {
    const field = schema.find(name);
    return field ? `CAST(e.${ident(field.name)} AS VARCHAR) AS ${alias}` : `NULL::VARCHAR AS ${alias}`;
  });
  return [
    'e._zl_uid',
    'epoch_ms(e._zl_time)::DOUBLE AS _zl_t',
    channel ? `lower(CAST(e.${ident(channel.name)} AS VARCHAR)) <> 'security' AS sysmon` : 'TRUE AS sysmon',
    ...values,
    'l._zl_lvl::INTEGER AS lvl',
    '(SELECT count(*) FROM hits h WHERE h._zl_uid = e._zl_uid)::DOUBLE AS hits',
  ].join(', ');
}

function starts(creation: string, where: string, limit: number): string {
  return `SELECT _zl_uid FROM events WHERE ${creation} AND (${where}) ORDER BY _zl_time NULLS LAST, _zl_uid LIMIT ${Math.max(1, Math.floor(limit))}`;
}

export function processCountSql(schema: Schema, where: string): string | null {
  const creation = creationPredicate(schema);
  return creation ? `SELECT count(*)::DOUBLE AS n FROM events WHERE ${creation} AND (${where})` : null;
}

export function processRowsSql(schema: Schema, where: string, limit = PROCESS_LIMIT): string | null {
  const creation = creationPredicate(schema);
  if (!creation) return null;
  return (
    `WITH m AS (${starts(creation, where, limit)}) SELECT ${projection(schema)}, FALSE AS context ` +
    'FROM events e JOIN m ON m._zl_uid = e._zl_uid LEFT JOIN event_levels l ON l._zl_uid = e._zl_uid ' +
    'ORDER BY e._zl_time NULLS LAST, e._zl_uid'
  );
}

/**
 * The starts above the filtered ones, by ProcessGuid, however far up: a search
 * that keeps only whoami.exe still shows which shell started it. UNION drops
 * guids already in the chain, so a loop in the data ends the recursion.
 */
export function ancestorsSql(schema: Schema, where: string, limit = PROCESS_LIMIT, ancestors = ANCESTOR_LIMIT): string | null {
  const creation = creationPredicate(schema);
  const guid = schema.find('ProcessGuid');
  const parent = schema.find('ParentProcessGuid');
  if (!creation || !guid || !parent) return null;
  return (
    `WITH RECURSIVE c AS (SELECT _zl_uid, lower(CAST(${ident(guid.name)} AS VARCHAR)) AS g, ` +
    `lower(CAST(${ident(parent.name)} AS VARCHAR)) AS pg FROM events WHERE ${creation}), ` +
    `m AS (${starts(creation, where, limit)}), ` +
    'chain(g) AS (SELECT c.pg FROM c JOIN m ON m._zl_uid = c._zl_uid WHERE c.pg IS NOT NULL ' +
    'UNION SELECT c.pg FROM c JOIN chain ON c.g = chain.g WHERE c.pg IS NOT NULL), ' +
    `a AS (SELECT c._zl_uid FROM c WHERE c.g IN (SELECT g FROM chain) AND c._zl_uid NOT IN (SELECT _zl_uid FROM m) ORDER BY c._zl_uid LIMIT ${Math.max(1, Math.floor(ancestors))}) ` +
    `SELECT ${projection(schema)}, TRUE AS context FROM events e JOIN a ON a._zl_uid = e._zl_uid LEFT JOIN event_levels l ON l._zl_uid = e._zl_uid`
  );
}
