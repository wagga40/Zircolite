import type { Schema } from '../engine/schema';
import { ident, str } from '../engine/sql';

/** Starts the tree reads at once, earliest first; the summary says when there are more. */
export const PROCESS_LIMIT = 20_000;
/** Ancestors added for context, beyond the starts the filters keep. */
export const ANCESTOR_LIMIT = 5_000;
/** Generations walked up from a kept start; it ends a cycle in the data, and no real chain is this deep. */
export const ANCESTOR_DEPTH = 64;

// Each value the tree needs, by the field Zircolite's mappings give it.
const COLUMNS = {
  host: 'Computer',
  guid: 'ProcessGuid',
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
  target: 'TargetUserName',
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

/** A field as text, or NULL where the package lacks it. */
function text(schema: Schema, name: string): string {
  const field = schema.find(name);
  return field ? `CAST(${ident(field.name)} AS VARCHAR)` : 'NULL::VARCHAR';
}

// The forms pidText reads as a number. TRY_CAST alone would also take 1_000, 1e3 and 0b101.
const PID_FORM = str('^\\s*(0[xX][0-9a-fA-F]+|[0-9]+)\\s*$');

function pidKey(value: string): string {
  return `TRY_CAST(regexp_extract(${value}, ${PID_FORM}, 1) AS BIGINT)`;
}

/**
 * Each start's parent, over every start in the package rather than the ones
 * the filters keep: a filter must not decide lineage. A parent guid links
 * exactly, so a start that names one is never linked any other way. A start
 * without one links to the latest earlier start of its parent PID on the
 * same host, PIDs read as toProcess reads them: PIDs come back after a
 * process ends. A start whose parent PID is its own PID links to nothing by
 * PID, as the parent was alive when the child took that PID.
 */
function parents(schema: Schema, creation: string): string {
  const channel = schema.find('Channel');
  const sysmon = channel ? `lower(CAST(${ident(channel.name)} AS VARCHAR)) <> 'security'` : 'TRUE';
  const guid = (name: string) => `nullif(lower(trim(${text(schema, name)})), '')`;
  const pid = (sysmonField: string, securityField: string) =>
    `CASE WHEN ${sysmon} THEN ${pidKey(text(schema, sysmonField))} ELSE ${pidKey(text(schema, securityField))} END`;
  return (
    `_zl_pc AS MATERIALIZED (SELECT _zl_uid, _zl_time AS _zl_t, nullif(lower(${text(schema, 'Computer')}), '') AS _zl_host, ` +
    `${guid('ProcessGuid')} AS _zl_guid, ${guid('ParentProcessGuid')} AS _zl_pguid, ` +
    `${pid('ProcessId', 'NewProcessId')} AS _zl_pid, ${pid('ParentProcessId', 'ProcessId')} AS _zl_ppid FROM events WHERE ${creation}), ` +
    // A guid logged twice names its first start.
    '_zl_byguid AS (SELECT _zl_guid, first(_zl_uid ORDER BY _zl_t NULLS LAST, _zl_uid) AS _zl_uid FROM _zl_pc WHERE _zl_guid IS NOT NULL GROUP BY _zl_guid), ' +
    // Two starts of one PID at one instant on one host would leave ASOF free to pick either.
    '_zl_bypid AS (SELECT _zl_host, _zl_pid, _zl_t, max(_zl_uid) AS _zl_uid FROM _zl_pc ' +
    'WHERE _zl_host IS NOT NULL AND _zl_pid IS NOT NULL AND _zl_t IS NOT NULL GROUP BY ALL), ' +
    '_zl_link AS MATERIALIZED (SELECT c._zl_uid, g._zl_uid AS _zl_parent FROM _zl_pc c JOIN _zl_byguid g ON g._zl_guid = c._zl_pguid ' +
    'WHERE g._zl_uid <> c._zl_uid UNION ALL SELECT c._zl_uid, p._zl_uid FROM ' +
    '(SELECT * FROM _zl_pc WHERE _zl_pguid IS NULL AND _zl_ppid IS DISTINCT FROM _zl_pid) c ' +
    'ASOF JOIN _zl_bypid p ON c._zl_host = p._zl_host AND c._zl_ppid = p._zl_pid AND c._zl_t >= p._zl_t)'
  );
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
    `WITH ${parents(schema, creation)}, m AS (${starts(creation, where, limit)}) ` +
    `SELECT ${projection(schema)}, k._zl_parent, FALSE AS context FROM events e JOIN m ON m._zl_uid = e._zl_uid ` +
    'LEFT JOIN _zl_link k ON k._zl_uid = e._zl_uid LEFT JOIN event_levels l ON l._zl_uid = e._zl_uid ' +
    'ORDER BY e._zl_time NULLS LAST, e._zl_uid'
  );
}

/**
 * The starts above the filtered ones, however far up, nearest first: a
 * search that keeps only whoami.exe still shows which shell started it. Each
 * generation is one step up the resolved parents; the depth bound ends a
 * cycle in the data.
 */
export function ancestorsSql(schema: Schema, where: string, limit = PROCESS_LIMIT, ancestors = ANCESTOR_LIMIT): string | null {
  const creation = creationPredicate(schema);
  if (!creation) return null;
  return (
    `WITH RECURSIVE ${parents(schema, creation)}, m AS MATERIALIZED (${starts(creation, where, limit)}), ` +
    '_zl_up(_zl_uid, _zl_depth) AS (SELECT k._zl_parent, 1 FROM _zl_link k JOIN m ON m._zl_uid = k._zl_uid ' +
    `UNION SELECT k._zl_parent, u._zl_depth + 1 FROM _zl_link k JOIN _zl_up u ON k._zl_uid = u._zl_uid WHERE u._zl_depth < ${ANCESTOR_DEPTH}), ` +
    'a AS (SELECT _zl_uid, min(_zl_depth) AS _zl_depth FROM _zl_up WHERE _zl_uid NOT IN (SELECT _zl_uid FROM m) GROUP BY _zl_uid ' +
    // One row past the limit tells the tree it stopped there.
    `ORDER BY _zl_depth, _zl_uid LIMIT ${Math.max(1, Math.floor(ancestors)) + 1}) ` +
    `SELECT ${projection(schema)}, k._zl_parent, TRUE AS context FROM events e JOIN a ON a._zl_uid = e._zl_uid ` +
    'LEFT JOIN _zl_link k ON k._zl_uid = e._zl_uid LEFT JOIN event_levels l ON l._zl_uid = e._zl_uid ' +
    'ORDER BY a._zl_depth, e._zl_uid'
  );
}

/** The ancestors the tree shows: the nearest up to the limit, and whether more were cut off. */
export function keepAncestors<T>(rows: T[], limit = ANCESTOR_LIMIT): { rows: T[]; capped: boolean } {
  return rows.length > limit ? { rows: rows.slice(0, limit), capped: true } : { rows, capped: false };
}
