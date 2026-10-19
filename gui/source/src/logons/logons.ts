/**
 * Windows logons, explicit credentials and remote desktop sessions, as a
 * responder reads them for lateral movement: who reached which host, from
 * where, how, and how often it failed. Every field is looked up in the
 * package: one it lacks is left out of the query and of every pivot, so a
 * pivot always compiles and lists exactly the row's events.
 */
import type { Field, Schema } from '../engine/schema';
import { ident, str } from '../engine/sql';
import { fieldTerm, fieldToken } from '../search/edit';
import type { LocalColumn } from '../ui/localFilters';

const SECURITY = 'Security';
const RCM = 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational';
const LSM = 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational';

/** Rows each table shows; the rest are reached through the column filters. */
export const LOGON_LIMIT = 1000;

const NAMES = [
  'Channel', 'EventID', 'Computer', 'TargetUserName', 'TargetDomainName', 'LogonType', 'IpAddress', 'WorkstationName', 'TargetLogonId',
  'Status', 'SubStatus', 'SubjectUserName', 'SubjectDomainName', 'TargetServerName', 'ProcessName', 'Param1', 'Param2', 'Param3',
  'AccountName', 'AccountDomain', 'ClientName', 'ClientAddress', 'User', 'Address', 'SubjectLogonId', 'LogonId', 'PrivilegeList',
] as const;

export type LogonFieldName = (typeof NAMES)[number];

export interface LogonFields {
  field: Partial<Record<LogonFieldName, Field>>;
  /** Fields without which nothing here can be found. */
  missing: LogonFieldName[];
}

export function logonFields(schema: Schema): LogonFields {
  const field: Partial<Record<LogonFieldName, Field>> = {};
  for (const name of NAMES) {
    const found = schema.find(name);
    if (found) field[name] = found;
  }
  return { field, missing: (['EventID', 'Computer'] as const).filter((name) => !field[name]) };
}

/** Windows logon types by number. */
export const LOGON_TYPES: Record<string, string> = {
  '0': 'System', '2': 'Interactive', '3': 'Network', '4': 'Batch', '5': 'Service', '7': 'Unlock', '8': 'NetworkCleartext',
  '9': 'NewCredentials', '10': 'RemoteInteractive', '11': 'CachedInteractive', '12': 'CachedRemoteInteractive', '13': 'CachedUnlock',
};

/** Why a logon failed, by the NTSTATUS code in 4625's SubStatus, or Status when that says nothing. */
export const FAILURE_REASONS: Record<string, string> = {
  '0xc000006a': 'bad password', '0xc0000064': 'no such user', '0xc000006d': 'bad user name or password', '0xc0000234': 'locked out',
  '0xc0000072': 'disabled', '0xc000006f': 'outside logon hours', '0xc0000070': 'workstation not allowed', '0xc0000071': 'password expired',
  '0xc0000193': 'account expired', '0xc0000224': 'password must change', '0xc000015b': 'logon type not granted',
  '0xc0000133': 'clock skew', '0xc000018c': 'trust failure', '0xc0000413': 'authentication firewall', '0xc0000022': 'access denied',
  '0xc000005e': 'no logon servers', '0xc0000192': 'Netlogon not started', '0xc000015c': 'no such logon session',
};

function text(field: Field | undefined): string {
  return field ? `CAST(${ident(field.name)} AS VARCHAR)` : 'NULL::VARCHAR';
}

/** One of the event ids, compared as the package stores EventID: as numbers, or as the text a mixed package keeps. */
function eventIs(field: Field, ids: number[]): string {
  return field.type === 'VARCHAR' ? `trim(${ident(field.name)}) IN (${ids.map((id) => str(String(id))).join(', ')})` : `${ident(field.name)} IN (${ids.join(', ')})`;
}

/** Events of one channel; a package without Channel is matched on the event id alone. */
function channelIs(field: Field | undefined, channel: string): string {
  return field ? `${text(field)} ILIKE ${str(channel)}` : 'TRUE';
}

function named(value: string, names: Record<string, string>): string {
  return `CASE lower(${value}) ${Object.entries(names).map(([code, name]) => `WHEN ${str(code)} THEN ${str(`${code} ${name}`)}`).join(' ')} ELSE ${value} END`;
}

function reasonNamed(value: string): string {
  return `CASE ${value} ${Object.entries(FAILURE_REASONS).map(([code, name]) => `WHEN ${str(code)} THEN ${str(name)}`).join(' ')} ELSE ${value} END`;
}

/** domain\user, or whichever of the two the event has. */
function account(domain: string, user: string): string {
  return `nullif(concat_ws('\\', ${domain}, ${user}), '')`;
}

export interface TableOptions {
  filter?: string;
  order?: string;
  limit?: number;
}

function tail(options: TableOptions, order: string[]): string {
  const { filter = 'TRUE', limit = LOGON_LIMIT } = options;
  return `SELECT *, (count(*) OVER ())::DOUBLE AS total FROM g WHERE ${filter} ORDER BY ${options.order || order.join(', ')} LIMIT ${Math.max(1, Math.floor(limit))}`;
}

function term(field: Field | undefined, value: string | null): string | null {
  if (!field) return null;
  return value === null ? `-${fieldToken(field.name)}:*` : fieldTerm(field.name, value);
}

function terms(...parts: (string | null)[]): string {
  return parts.filter((part): part is string => part !== null).join(' ');
}

function channelTerm(fields: LogonFields, channel: string): string | null {
  return fields.field.Channel ? fieldTerm(fields.field.Channel.name, channel) : null;
}

function idTerm(fields: LogonFields, ids: number[]): string {
  const name = fieldToken((fields.field.EventID as Field).name);
  const each = ids.map((id) => `${name}:${id}`);
  return each.length === 1 ? each[0] : `(${each.join(' OR ')})`;
}

// Logons ---------------------------------------------------------------------------------------------------------

export interface LogonOptions extends TableOptions {
  /** Network and remote interactive logons only: types 3 and 10. */
  remoteOnly?: boolean;
  /** Leave out computer accounts, whose names end in $. */
  hideMachines?: boolean;
}

export interface LogonRow {
  host: string | null;
  domain: string | null;
  user: string | null;
  account: string | null;
  type: string | null;
  type_name: string | null;
  ip: string | null;
  workstation: string | null;
  successes: number;
  failures: number;
  reasons: string | null;
  sessions: number;
  first: number | null;
  last: number | null;
  total: number;
}

export const LOGON_COLUMNS: LocalColumn[] = [
  { name: 'host', type: 'text' }, { name: 'account', type: 'text' }, { name: 'type_name', type: 'text' }, { name: 'ip', type: 'text' },
  { name: 'workstation', type: 'text' }, { name: 'successes', type: 'number' }, { name: 'failures', type: 'number' },
  { name: 'reasons', type: 'text' }, { name: 'sessions', type: 'number' }, { name: 'first', type: 'time' }, { name: 'last', type: 'time' },
];

/** Failures first: a run of them is what a responder looks for before anything else. */
export const LOGON_ORDER = ['"failures" DESC', '"successes" DESC', 'lower("host")', 'lower("account")', 'lower("type_name")', 'lower("ip")'];

/** The toggles' conditions, over a logon's type and account; each needs its field, and the view says when one is missing. */
function narrowing(f: LogonFields['field'], options: LogonOptions, type: string, user: string): string {
  const remote = options.remoteOnly && f.LogonType ? ` AND ${type} IN ('3', '10')` : '';
  const machines = options.hideMachines && f.TargetUserName ? ` AND coalesce(${user}, '') NOT LIKE '%$'` : '';
  return remote + machines;
}

/** Successful (4624) and failed (4625) logons, grouped by target host, account, logon type and source. */
export function logonsSql(fields: LogonFields, where: string, options: LogonOptions): string | null {
  const f = fields.field;
  if (!f.EventID || !f.Computer) return null;
  const narrow = narrowing(f, options, `trim(${text(f.LogonType)})`, text(f.TargetUserName));
  const reason = `coalesce(nullif(lower(${text(f.SubStatus)}), '0x0'), lower(${text(f.Status)}))`;
  return (
    `WITH x AS (SELECT _zl_time, trim(CAST(${ident(f.EventID.name)} AS VARCHAR)) AS id, ${text(f.Computer)} AS host, ${text(f.TargetDomainName)} AS domain, ` +
    `${text(f.TargetUserName)} AS "user", trim(${text(f.LogonType)}) AS type, ${text(f.IpAddress)} AS ip, ${text(f.WorkstationName)} AS workstation, ` +
    `${text(f.TargetLogonId)} AS session, ${reason} AS reason FROM events ` +
    `WHERE (${where}) AND ${channelIs(f.Channel, SECURITY)} AND ${eventIs(f.EventID, [4624, 4625])}${narrow}), ` +
    'g AS (SELECT min(host) AS host, min(domain) AS domain, min("user") AS "user", ' +
    `${account('min(domain)', 'min("user")')} AS account, min(type) AS type, ${named('min(type)', LOGON_TYPES)} AS type_name, ` +
    'min(ip) AS ip, min(workstation) AS workstation, ' +
    `count(*) FILTER (WHERE id = '4624')::DOUBLE AS successes, count(*) FILTER (WHERE id = '4625')::DOUBLE AS failures, ` +
    `string_agg(DISTINCT ${reasonNamed('reason')}, ', ' ORDER BY ${reasonNamed('reason')}) FILTER (WHERE id = '4625') AS reasons, ` +
    `count(DISTINCT lower(session)) FILTER (WHERE id = '4624')::DOUBLE AS sessions, ` +
    'epoch_ms(min(_zl_time))::DOUBLE AS first, epoch_ms(max(_zl_time))::DOUBLE AS last ' +
    'FROM x GROUP BY lower(host), lower(domain), lower("user"), lower(type), lower(ip), lower(workstation)) ' +
    tail(options, LOGON_ORDER)
  );
}

/** The search that lists exactly a row's logons and failures. */
export function logonTerms(fields: LogonFields, row: LogonRow): string {
  const f = fields.field;
  return terms(
    idTerm(fields, [4624, 4625]), channelTerm(fields, SECURITY), term(f.Computer, row.host), term(f.TargetDomainName, row.domain),
    term(f.TargetUserName, row.user), term(f.LogonType, row.type), term(f.IpAddress, row.ip), term(f.WorkstationName, row.workstation),
  );
}

// Explicit credentials ---------------------------------------------------------------------------------------------

export interface ExplicitRow {
  host: string | null;
  subject_domain: string | null;
  subject_user: string | null;
  subject: string | null;
  domain: string | null;
  user: string | null;
  account: string | null;
  server: string | null;
  process: string | null;
  events: number;
  first: number | null;
  last: number | null;
  total: number;
}

export const EXPLICIT_COLUMNS: LocalColumn[] = [
  { name: 'host', type: 'text' }, { name: 'subject', type: 'text' }, { name: 'account', type: 'text' }, { name: 'server', type: 'text' },
  { name: 'process', type: 'text' }, { name: 'events', type: 'number' }, { name: 'first', type: 'time' }, { name: 'last', type: 'time' },
];

export const EXPLICIT_ORDER = ['"events" DESC', 'lower("host")', 'lower("subject")', 'lower("account")', 'lower("server")'];

/** 4648: credentials a process used for another account, logged on the host they were used from. */
export function explicitSql(fields: LogonFields, where: string, options: TableOptions): string | null {
  const f = fields.field;
  if (!f.EventID || !f.Computer) return null;
  return (
    `WITH x AS (SELECT _zl_time, ${text(f.Computer)} AS host, ${text(f.SubjectDomainName)} AS subject_domain, ${text(f.SubjectUserName)} AS subject_user, ` +
    `${text(f.TargetDomainName)} AS domain, ${text(f.TargetUserName)} AS "user", ${text(f.TargetServerName)} AS server, ${text(f.ProcessName)} AS process ` +
    `FROM events WHERE (${where}) AND ${channelIs(f.Channel, SECURITY)} AND ${eventIs(f.EventID, [4648])}), ` +
    'g AS (SELECT min(host) AS host, min(subject_domain) AS subject_domain, min(subject_user) AS subject_user, ' +
    `${account('min(subject_domain)', 'min(subject_user)')} AS subject, min(domain) AS domain, min("user") AS "user", ` +
    `${account('min(domain)', 'min("user")')} AS account, min(server) AS server, min(process) AS process, count(*)::DOUBLE AS events, ` +
    'epoch_ms(min(_zl_time))::DOUBLE AS first, epoch_ms(max(_zl_time))::DOUBLE AS last FROM x ' +
    'GROUP BY lower(host), lower(subject_domain), lower(subject_user), lower(domain), lower("user"), lower(server), lower(process)) ' +
    tail(options, EXPLICIT_ORDER)
  );
}

export function explicitTerms(fields: LogonFields, row: ExplicitRow): string {
  const f = fields.field;
  return terms(
    idTerm(fields, [4648]), channelTerm(fields, SECURITY), term(f.Computer, row.host), term(f.SubjectDomainName, row.subject_domain),
    term(f.SubjectUserName, row.subject_user), term(f.TargetDomainName, row.domain), term(f.TargetUserName, row.user),
    term(f.TargetServerName, row.server), term(f.ProcessName, row.process),
  );
}

// Remote desktop -------------------------------------------------------------------------------------------------

interface RdpKind {
  id: number;
  channel: string;
  label: string;
  /** The fields that hold the account, its domain, the source address and the client name in this kind of event. */
  user: LogonFieldName;
  domain?: LogonFieldName;
  source?: LogonFieldName;
  client?: LogonFieldName;
}

// Each kind keeps the account and the source in fields of its own, so kinds are never merged into one row.
const RDP_KINDS: RdpKind[] = [
  { id: 1149, channel: RCM, label: '1149 RDP authentication', user: 'Param1', domain: 'Param2', source: 'Param3' },
  { id: 21, channel: LSM, label: '21 RDP logon', user: 'User', source: 'Address' },
  { id: 22, channel: LSM, label: '22 RDP shell start', user: 'User', source: 'Address' },
  { id: 24, channel: LSM, label: '24 RDP session disconnected', user: 'User', source: 'Address' },
  { id: 25, channel: LSM, label: '25 RDP session reconnected', user: 'User', source: 'Address' },
  { id: 4778, channel: SECURITY, label: '4778 RDP session reconnected', user: 'AccountName', domain: 'AccountDomain', source: 'ClientAddress', client: 'ClientName' },
  { id: 4779, channel: SECURITY, label: '4779 RDP session disconnected', user: 'AccountName', domain: 'AccountDomain', source: 'ClientAddress', client: 'ClientName' },
];

export interface RdpRow {
  kind: string;
  host: string | null;
  domain: string | null;
  user: string | null;
  account: string | null;
  source: string | null;
  client: string | null;
  events: number;
  first: number | null;
  last: number | null;
  total: number;
}

export const RDP_COLUMNS: LocalColumn[] = [
  { name: 'kind', type: 'text' }, { name: 'host', type: 'text' }, { name: 'account', type: 'text' }, { name: 'source', type: 'text' },
  { name: 'client', type: 'text' }, { name: 'events', type: 'number' }, { name: 'first', type: 'time' }, { name: 'last', type: 'time' },
];

export const RDP_ORDER = ['lower("host")', '"kind"', 'lower("account")', 'lower("source")'];

/** The remote desktop kinds this package can read: those whose account field it has. */
function rdpKinds(fields: LogonFields): RdpKind[] {
  return RDP_KINDS.filter((kind) => fields.field[kind.user] && (fields.field.Channel || kind.channel === SECURITY));
}

/** Remote desktop authentications, logons, disconnections and reconnections, by kind, host, account and source. */
export function rdpSql(fields: LogonFields, where: string, options: TableOptions): string | null {
  const f = fields.field;
  if (!f.EventID || !f.Computer) return null;
  const kinds = rdpKinds(fields);
  if (kinds.length === 0) return null;
  const parts = kinds.map((kind) =>
    `SELECT _zl_time, ${str(kind.label)} AS kind, ${text(f.Computer)} AS host, ${text(kind.domain && f[kind.domain])} AS domain, ` +
    `${text(f[kind.user])} AS "user", ${text(kind.source && f[kind.source])} AS source, ${text(kind.client && f[kind.client])} AS client ` +
    `FROM events WHERE (${where}) AND ${channelIs(f.Channel, kind.channel)} AND ${eventIs(f.EventID as Field, [kind.id])}`);
  return (
    `WITH x AS (${parts.join(' UNION ALL ')}), ` +
    'g AS (SELECT kind, min(host) AS host, min(domain) AS domain, min("user") AS "user", ' +
    `${account('min(domain)', 'min("user")')} AS account, min(source) AS source, min(client) AS client, count(*)::DOUBLE AS events, ` +
    'epoch_ms(min(_zl_time))::DOUBLE AS first, epoch_ms(max(_zl_time))::DOUBLE AS last FROM x ' +
    'GROUP BY kind, lower(host), lower(domain), lower("user"), lower(source), lower(client)) ' +
    tail(options, RDP_ORDER)
  );
}

export function rdpTerms(fields: LogonFields, row: RdpRow): string {
  const f = fields.field;
  const kind = RDP_KINDS.find((k) => k.label === row.kind) as RdpKind;
  return terms(
    channelTerm(fields, kind.channel), idTerm(fields, [kind.id]), term(f.Computer, row.host), term(kind.domain && f[kind.domain], row.domain),
    term(f[kind.user], row.user), term(kind.source && f[kind.source], row.source), term(kind.client && f[kind.client], row.client),
  );
}

// Lateral movement -----------------------------------------------------------------------------------------------

const NETWORK_LINK = '3 Network logon';
const RDP_LINK = '10 Remote Desktop logon';
const EXPLICIT_LINK = '4648 Explicit credentials';

export interface LateralRow {
  source: string;
  target: string;
  kind: string;
  accounts: number;
  /** The accounts with the most events on the link, up to three. */
  account_list: string | null;
  events: number;
  first: number | null;
  last: number | null;
  total: number;
}

export const LATERAL_COLUMNS: LocalColumn[] = [
  { name: 'source', type: 'text' }, { name: 'target', type: 'text' }, { name: 'kind', type: 'text' }, { name: 'accounts', type: 'number' },
  { name: 'account_list', type: 'text' }, { name: 'events', type: 'number' }, { name: 'first', type: 'time' }, { name: 'last', type: 'time' },
];

export const LATERAL_ORDER = ['"events" DESC', 'lower("source")', 'lower("target")', '"kind"'];

// A source or target naming the host itself, or nobody, is no movement.
const NOWHERE = ['', '-', '::1', '127.0.0.1', 'localhost'];

function somewhere(value: string): string {
  return `${value} IS NOT NULL AND lower(trim(${value})) NOT IN (${NOWHERE.map((v) => str(v)).join(', ')})`;
}

/**
 * Who reached which host: network (3) and Remote Desktop (10) logons from
 * their source address to the host that logged them, and explicit
 * credentials (4648) from the host that used them to the target server.
 * A 4648 for the host itself, by name or short name, is left out.
 */
export function lateralSql(fields: LogonFields, where: string, options: LogonOptions): string | null {
  const f = fields.field;
  if (!f.EventID || !f.Computer) return null;
  const host = text(f.Computer);
  const acct = account(text(f.TargetDomainName), text(f.TargetUserName));
  const machines = options.hideMachines && f.TargetUserName ? ` AND coalesce(${text(f.TargetUserName)}, '') NOT LIKE '%$'` : '';
  const from = `FROM events WHERE (${where}) AND ${channelIs(f.Channel, SECURITY)} AND ${host} IS NOT NULL${machines}`;
  const parts: string[] = [];
  if (f.LogonType && f.IpAddress) {
    const type = `trim(${text(f.LogonType)})`;
    parts.push(
      `SELECT _zl_time, CASE ${type} WHEN '10' THEN ${str(RDP_LINK)} ELSE ${str(NETWORK_LINK)} END AS kind, ${text(f.IpAddress)} AS source, ` +
      `${host} AS target, ${acct} AS acct ${from} AND ${eventIs(f.EventID, [4624])} AND ${type} IN ('3', '10') AND ${somewhere(text(f.IpAddress))}`);
  }
  if (f.TargetServerName) {
    const server = text(f.TargetServerName);
    parts.push(
      `SELECT _zl_time, ${str(EXPLICIT_LINK)} AS kind, ${host} AS source, ${server} AS target, ${acct} AS acct ${from} ` +
      `AND ${eventIs(f.EventID, [4648])} AND ${somewhere(server)} AND split_part(lower(${server}), '.', 1) <> split_part(lower(${host}), '.', 1)`);
  }
  if (parts.length === 0) return null;
  return (
    `WITH x AS (${parts.join(' UNION ALL ')}), ` +
    'y AS (SELECT kind, lower(source) AS sk, lower(target) AS tk, min(source) AS source, min(target) AS target, min(acct) AS acct, count(*) AS n, ' +
    'min(_zl_time) AS first, max(_zl_time) AS last FROM x GROUP BY kind, lower(source), lower(target), lower(acct)), ' +
    'g AS (SELECT min(source) AS source, min(target) AS target, kind, count(acct)::DOUBLE AS accounts, ' +
    "array_to_string(list_slice(list(acct ORDER BY n DESC, lower(acct)) FILTER (WHERE acct IS NOT NULL), 1, 3), ', ') AS account_list, " +
    'sum(n)::DOUBLE AS events, epoch_ms(min(first))::DOUBLE AS first, epoch_ms(max(last))::DOUBLE AS last FROM y GROUP BY kind, sk, tk) ' +
    tail(options, LATERAL_ORDER)
  );
}

/** The search that lists exactly a link's events. */
export function lateralTerms(fields: LogonFields, row: LateralRow, options: LogonOptions): string {
  const f = fields.field;
  const machines = options.hideMachines && f.TargetUserName ? `-${fieldToken(f.TargetUserName.name)}:*$` : null;
  if (row.kind === EXPLICIT_LINK) {
    return terms(idTerm(fields, [4648]), channelTerm(fields, SECURITY), term(f.Computer, row.source), term(f.TargetServerName, row.target), machines);
  }
  return terms(
    idTerm(fields, [4624]), channelTerm(fields, SECURITY), term(f.LogonType, row.kind === RDP_LINK ? '10' : '3'), term(f.IpAddress, row.source),
    term(f.Computer, row.target), machines,
  );
}

// Sessions -------------------------------------------------------------------------------------------------------

export interface SessionRow {
  host: string | null;
  domain: string | null;
  user: string | null;
  account: string | null;
  type: string | null;
  type_name: string | null;
  ip: string | null;
  session: string;
  start: number;
  /** The logoff, or null when none came before the next logon with the id or the end of the logs. */
  end: number | null;
  minutes: number | null;
  /** The special privileges (4672) given to the session, or null when it was given none. */
  privileges: string | null;
  privileged_at: number | null;
  /**
   * Where the next logon on the host with the same id begins, with its
   * special privileges or the logon itself: a session without a logoff ended
   * by then at the latest.
   */
  next_logon: number | null;
  /** The package's last event time: where an open session's activity is looked for up to. */
  horizon: number;
  total: number;
}

export const SESSION_COLUMNS: LocalColumn[] = [
  { name: 'host', type: 'text' }, { name: 'account', type: 'text' }, { name: 'type_name', type: 'text' }, { name: 'ip', type: 'text' },
  { name: 'session', type: 'text' }, { name: 'start', type: 'time' }, { name: 'end', type: 'time' }, { name: 'minutes', type: 'number' },
  { name: 'privileges', type: 'text' },
];

export const SESSION_ORDER = ['"start" ASC', 'lower("host")', 'lower("session")'];

/**
 * The special privileges (4672) each paired logon was given, joined as
 * granted(pt, list). Windows writes them with the logon, up to a few seconds
 * before it on a busy domain controller; the closest one in that window is
 * the logon's, so a reused logon id never inherits an older session's.
 */
function granted(fields: LogonFields, security: string): string {
  const f = fields.field;
  if (!f.EventID || !f.Computer || !f.SubjectLogonId || !f.PrivilegeList) {
    return 'granted AS (SELECT paired.*, NULL::TIMESTAMP AS pt, NULL::VARCHAR AS list FROM paired)';
  }
  const id = text(f.SubjectLogonId);
  const near = 'priv.t >= paired.t - INTERVAL 5 SECOND';
  return (
    `priv AS (SELECT _zl_time AS t, lower(${text(f.Computer)}) AS hk, lower(${id}) AS sk, ${text(f.PrivilegeList)} AS list FROM events ` +
    `WHERE ${security} AND ${eventIs(f.EventID, [4672])} AND ${id} IS NOT NULL AND _zl_time IS NOT NULL), ` +
    `granted AS (SELECT paired.*, CASE WHEN ${near} THEN priv.t END AS pt, CASE WHEN ${near} THEN priv.list END AS list FROM paired ` +
    'ASOF LEFT JOIN priv ON paired.hk = priv.hk AND paired.sk = priv.sk AND paired.late >= priv.t)'
  );
}

/**
 * Each successful logon (4624) as a session, closed by the first logoff
 * (4634 or 4647) on its host with its logon id. A logon id is used again
 * after a reboot, so a logoff that comes after the next logon with the same
 * id belongs to that one. The page's filters choose the logons; logoffs are
 * read from every event, since a 4647 has no logon type or source to match.
 */
export function sessionsSql(fields: LogonFields, where: string, options: LogonOptions): string | null {
  const f = fields.field;
  if (!f.EventID || !f.Computer || !f.TargetLogonId) return null;
  const security = channelIs(f.Channel, SECURITY);
  const id = text(f.TargetLogonId);
  const host = text(f.Computer);
  return (
    `WITH logon AS (SELECT _zl_uid, _zl_time AS t, ${host} AS host, lower(${host}) AS hk, ${text(f.TargetDomainName)} AS domain, ` +
    `${text(f.TargetUserName)} AS "user", trim(${text(f.LogonType)}) AS type, ${text(f.IpAddress)} AS ip, ${id} AS session, lower(${id}) AS sk, ` +
    `lead(_zl_time) OVER (PARTITION BY lower(${host}), lower(${id}) ORDER BY _zl_time) AS next, _zl_time + INTERVAL 2 SECOND AS late ` +
    `FROM events WHERE ${security} AND ${eventIs(f.EventID, [4624])} AND ${id} IS NOT NULL AND _zl_time IS NOT NULL), ` +
    `off AS (SELECT _zl_time AS t, lower(${host}) AS hk, lower(${id}) AS sk FROM events ` +
    `WHERE ${security} AND ${eventIs(f.EventID, [4634, 4647])} AND ${id} IS NOT NULL AND _zl_time IS NOT NULL), ` +
    'paired AS (SELECT logon.*, CASE WHEN next IS NULL OR off.t < next THEN off.t END AS stop FROM logon ' +
    'ASOF LEFT JOIN off ON logon.hk = off.hk AND logon.sk = off.sk AND logon.t <= off.t), ' +
    `${granted(fields, security)}, ` +
    'began AS (SELECT granted.*, lead(CASE WHEN pt < t THEN pt ELSE t END) OVER (PARTITION BY hk, sk ORDER BY t) AS next_begin FROM granted), ' +
    `g AS (SELECT host, domain, "user", ${account('domain', '"user"')} AS account, type, ${named('type', LOGON_TYPES)} AS type_name, ip, session, ` +
    'epoch_ms(t)::DOUBLE AS start, epoch_ms(stop)::DOUBLE AS "end", round(epoch_ms(stop - t) / 60000, 1)::DOUBLE AS minutes, ' +
    // PrivilegeList puts each privilege on a line of its own, indented with tabs.
    "regexp_replace(trim(regexp_replace(list, '\\s+', ' ', 'g')), ' ', ', ', 'g') AS privileges, epoch_ms(pt)::DOUBLE AS privileged_at, " +
    'epoch_ms(next_begin)::DOUBLE AS next_logon, ' +
    '(SELECT epoch_ms(max(_zl_time)) FROM events)::DOUBLE AS horizon ' +
    // Narrowed after the pairing: a hidden logon still ends the session before it.
    `FROM began WHERE _zl_uid IN (SELECT _zl_uid FROM events WHERE ${where})${narrowing(f, options, 'type', '"user"')}) ` +
    tail(options, SESSION_ORDER)
  );
}

/**
 * A session's activity: events on its host that carry its logon id, from its
 * special privileges or logon to its logoff. Without a logoff it runs to
 * where the next logon with the same id begins, or to the end of the logs.
 */
export function sessionActivity(fields: LogonFields, row: SessionRow): { q: string; t: [number, number] } {
  const f = fields.field;
  const ids = [f.TargetLogonId, f.SubjectLogonId, f.LogonId]
    .filter((field, i, all): field is Field => field !== undefined && all.findIndex((other) => other?.key === field.key) === i)
    .map((field) => fieldTerm(field.name, row.session));
  const anyId = ids.length === 1 ? ids[0] : `(${ids.join(' OR ')})`;
  // The range is half-open: the logoff and the last event of the logs belong to the session, the next logon does not.
  const end = row.end !== null ? row.end + 1 : (row.next_logon ?? row.horizon + 1);
  const start = row.privileged_at !== null && row.privileged_at < row.start ? row.privileged_at : row.start;
  return { q: terms(term(f.Computer, row.host), anyId), t: [start, end] };
}
