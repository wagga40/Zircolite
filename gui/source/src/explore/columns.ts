import type { Manifest } from '../engine/manifest';
import type { Field, Schema } from '../engine/schema';
import { asciiLower, ident } from '../engine/sql';
import { type Node, parse } from '../search/parse';
import { findShortcut } from '../search/shortcuts';
import { GROUPS } from './detail';

// Fields that tell Windows, Sysmon for Linux and auditd events apart at a glance.
const PREFERRED = ['Channel', 'EventID', 'Computer', 'Hostname', 'TargetUserName', 'SubjectUserName', 'User', 'Image', 'CommandLine', 'type', 'exe', 'comm'];
const DEFAULT_COUNT = 6;

export function defaultColumns(schema: Schema): string[] {
  const chosen = PREFERRED.map((name) => schema.find(name)).filter((field): field is Field => field !== undefined);
  const rest = [...schema.fields]
    .filter((field) => !chosen.includes(field))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name, 'en'));
  return [...chosen, ...rest].slice(0, DEFAULT_COUNT).map((field) => field.name);
}

/** The table's columns: the user's choice when there is one, minus names this package lacks. */
export function shownColumns(cols: string[] | null, schema: Schema): Field[] {
  const seen = new Set<string>();
  return (cols ?? defaultColumns(schema)).flatMap((name) => {
    const field = schema.find(name);
    if (!field || seen.has(field.key)) return [];
    seen.add(field.key);
    return [field];
  });
}

export function toggleColumn(names: string[], name: string): string[] {
  const key = asciiLower(name);
  return names.some((n) => asciiLower(n) === key) ? names.filter((n) => asciiLower(n) !== key) : [...names, name];
}

export function moveColumn(names: string[], name: string, delta: -1 | 1): string[] {
  const key = asciiLower(name);
  const from = names.findIndex((n) => asciiLower(n) === key);
  const to = from + delta;
  if (from < 0 || to < 0 || to >= names.length) return names;
  const next = [...names];
  [next[from], next[to]] = [next[to], next[from]];
  return next;
}

/** The list with a column dropped into a gap between columns: gap 0 is before the first, gap n after the last. */
export function placeColumn(names: string[], name: string, gap: number): string[] {
  const key = asciiLower(name);
  const from = names.findIndex((n) => asciiLower(n) === key);
  if (from < 0) return names;
  const rest = names.filter((_, i) => i !== from);
  const at = Math.min(rest.length, Math.max(0, gap > from ? gap - 1 : gap));
  return [...rest.slice(0, at), names[from], ...rest.slice(at)];
}

type Family = Manifest['families'][number];

/** What an analyst reads first in one kind of event: who, where, which program, what it touched. */
const FAMILY_PREFERRED = [
  'Computer', 'User', 'TargetUserName', 'TargetDomainName', 'SubjectUserName', 'LogonType', 'IpAddress', 'WorkstationName',
  'Image', 'CommandLine', 'ParentImage', 'ParentCommandLine', 'TargetFilename', 'TargetObject', 'Details', 'EventType',
  'QueryName', 'QueryResults', 'DestinationIp', 'DestinationPort', 'DestinationHostname', 'SourceIp', 'SourcePort',
  'ImageLoaded', 'Signed', 'ServiceName', 'ImagePath', 'TaskName', 'TaskContent', 'ScriptBlockText', 'NewProcessName',
  'ParentProcessName', 'ProcessName', 'ObjectName', 'ShareName', 'RelativeTargetName', 'IntegrityLevel', 'Hashes',
  'OriginalFileName', 'CurrentDirectory', 'ProcessId', 'ParentProcessId',
].map(asciiLower);
const FAMILY_COUNT = 10;
const SYSTEM = GROUPS[0].pattern;

function exactValue(item: Node, key: string): string | null {
  if (item.kind !== 'term' || item.field === null || item.op !== '=' || item.starBefore || item.starAfter) return null;
  if (asciiLower(item.field) !== key || (!item.fieldQuoted && findShortcut(item.field))) return null;
  return !item.quoted && item.value.includes('*') ? null : item.value;
}

/**
 * The one kind of event the search keeps, when its own terms say so: an
 * exact EventID, and an exact Channel when several channels share that id.
 * Read from the text, it costs no query.
 */
export function familyOf(query: string, families: readonly Family[]): Family | null {
  let tree: Node | null;
  try {
    tree = parse(query);
  } catch {
    return null;
  }
  if (tree === null) return null;
  const items = tree.kind === 'and' ? tree.items : [tree];
  const ids = items.map((item) => exactValue(item, 'eventid')).filter((v): v is string => v !== null);
  const channels = items.map((item) => exactValue(item, 'channel')).filter((v): v is string => v !== null);
  if (ids.length !== 1 || channels.length > 1) return null;
  const found = families.filter((family) =>
    family.eventid === ids[0] && (channels.length === 0 || (family.channel !== null && asciiLower(family.channel) === asciiLower(channels[0]))));
  return found.length === 1 ? found[0] : null;
}

/** A family's columns worth showing: its host first, then what tells its events apart; never the fields every event has. */
export function familyColumns(family: Family, schema: Schema): Field[] {
  const fields = family.columns.flatMap((name) => {
    const field = schema.find(name);
    return field && (field.key === 'computer' || !SYSTEM.test(field.key)) ? [field] : [];
  });
  const rank = (field: Field) => {
    const preferred = FAMILY_PREFERRED.indexOf(field.key);
    if (preferred >= 0) return preferred;
    const group = GROUPS.findIndex((g) => g.pattern.test(field.key));
    return FAMILY_PREFERRED.length + (group < 0 ? GROUPS.length : group);
  };
  return [...new Set(fields)]
    .sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name, 'en'))
    .slice(0, FAMILY_COUNT);
}

export function familyLabel(family: Pick<Family, 'channel' | 'eventid'>): string {
  if (family.channel === null) return `event ${family.eventid}`;
  return `${family.channel.replace(/^Microsoft-Windows-/, '')} ${family.eventid}`;
}

/** Up to two families of the shown results, as text the way the manifest records them; null without the fields to tell. */
export function familyProbeSql(schema: Schema): string | null {
  const channel = schema.find('Channel');
  const eventid = schema.find('EventID');
  if (!channel || !eventid) return null;
  return (
    `SELECT DISTINCT CAST(e.${ident(channel.name)} AS VARCHAR) AS c, CAST(e.${ident(eventid.name)} AS VARCHAR) AS i ` +
    'FROM view_ids v JOIN events e ON e._zl_uid = v._zl_uid LIMIT 2'
  );
}
