import type { Manifest } from '../engine/manifest';
import type { Field, Schema } from '../engine/schema';
import { asciiLower, ident } from '../engine/sql';
import { findShortcut } from '../search/shortcuts';

export interface Head {
  _zl_part: number;
  _zl_spelling: string | null;
  _zl_t: number | null;
  _zl_channel: string | null;
  _zl_eventid: string | null;
}

function eventId(uid: number): number {
  if (!Number.isSafeInteger(uid) || uid < 0) throw new Error(`${uid} is not an event id`);
  return uid;
}

/** Enough of one event to pick its family. Channel and EventID are compared as the text Stage 1 recorded. */
export function headSql(schema: Schema, uid: number): string {
  const text = (field: Field | undefined) => (field ? `CAST(${ident(field.name)} AS VARCHAR)` : 'NULL::VARCHAR');
  return (
    `SELECT _zl_part, _zl_spelling, epoch_ms(_zl_time)::DOUBLE AS _zl_t, ${text(schema.find('Channel'))} AS _zl_channel, ` +
    `${text(schema.find('EventID'))} AS _zl_eventid FROM events WHERE _zl_uid = ${eventId(uid)}`
  );
}

/**
 * The columns events of this kind carry. Reading only these is what keeps
 * one event at tens of milliseconds instead of a second; an unknown family
 * reads every column, slower but complete.
 */
export function familyFields(manifest: Pick<Manifest, 'families'>, schema: Schema, channel: string | null, eventid: string | null): Field[] {
  const family = manifest.families.find((f) => f.channel === channel && f.eventid === eventid);
  if (!family) return schema.fields;
  return family.columns.flatMap((name) => {
    const field = schema.find(name);
    return field ? [field] : [];
  });
}

export function valuesSql(fields: Field[], uid: number): string {
  const values = fields.map((field, i) => `CAST(${ident(field.name)} AS VARCHAR) AS _zl_v${i}`);
  return `SELECT ${values.length ? values.join(', ') : 'NULL AS _zl_none'} FROM events WHERE _zl_uid = ${eventId(uid)}`;
}

export interface RuleRow {
  rule_idx: number;
  id: string | null;
  title: string;
  level: string;
  level_rank: number;
  tactics: string[] | null;
  techniques: string[] | null;
}

export function rulesSql(uid: number): string {
  return (
    'SELECT r.rule_idx, r.id, r.title, r.level, r.level_rank, r.tactics, r.techniques FROM hits h ' +
    `JOIN rules r ON r.rule_idx = h.rule_idx WHERE h._zl_uid = ${eventId(uid)} ORDER BY r.level_rank DESC, r.title, r.rule_idx`
  );
}

export interface Entry {
  field: Field;
  /** The name as this event spells it. */
  name: string;
  value: string;
}

// Checked in order against the ASCII-lowercased field name; the first match wins.
export const GROUPS: { name: string; pattern: RegExp }[] = [
  {
    name: 'System',
    pattern: /^(channel|eventid|computer|hostname|provider_?name|provider_?guid|eventsourcename|level|task|opcode|keywords|eventrecordid|version|qualifiers|systemtime|utctime|timecreated|rulename|type|node|msg|timestamp)$/,
  },
  {
    name: 'User',
    pattern: /(user|^logontype$|^(target|subject)?logonid$|domainname$|^(target|member|logon)?sid$|^account(name|domain)$|^(a|e|s|fs)?uid$|^e?gid$|^ses$|^privilegelist$|^authenticationpackagename$|^logonprocessname$|^workstationname$)/,
  },
  {
    name: 'Process',
    pattern: /(process|image(loaded)?$|commandline|^parent|currentdirectory|integritylevel|^hashes$|^(md5|sha1|sha256|imphash)$|originalfilename|^product$|^company$|^fileversion$|^description$|^exe$|^comm$|^p?pid$|^proctitle$|^cwd$|^calltrace$|^grantedaccess$|^start(module|function|address)$|^signed$|^signature(status)?$)/,
  },
  {
    name: 'Network',
    pattern: /(^(source|destination)(ip|port|hostname|isipv6|portname)$|ipaddress|^ipport$|^protocol$|^query(name|results|status)$|^initiated$|^(laddr|saddr|daddr|addr)$)/,
  },
  {
    name: 'File and registry',
    pattern: /(file|^targetobject$|^details$|^object(name|type|server)$|^path$|^name$|^newname$|^eventtype$|registry|^key|^value|creationutctime$|^archived$|^isexecutable$|^sharename$|^relativetargetname$)/,
  },
];

export function groupEntries(entries: Entry[]): { name: string; entries: Entry[] }[] {
  const groups = [...GROUPS.map((group) => group.name), 'Other'].map((name) => ({ name, entries: [] as Entry[] }));
  for (const entry of entries) {
    const at = GROUPS.findIndex((group) => group.pattern.test(entry.field.key));
    groups[at < 0 ? GROUPS.length : at].entries.push(entry);
  }
  return groups
    .filter((group) => group.entries.length > 0)
    .map((group) => ({ ...group, entries: group.entries.sort((a, b) => a.name.localeCompare(b.name, 'en')) }));
}

const HOST_KEYS = (findShortcut('host')?.fields ?? []).map(asciiLower);

/** The field naming the event's host, in the host: shortcut's order of preference. */
export function hostEntry(entries: Entry[]): Entry | null {
  for (const key of HOST_KEYS) {
    const found = entries.find((entry) => entry.field.key === key && entry.value !== '');
    if (found) return found;
  }
  return null;
}

export function nearbyRange(t: number, minutes = 5): [number, number] {
  return [t - minutes * 60_000, t + minutes * 60_000];
}
