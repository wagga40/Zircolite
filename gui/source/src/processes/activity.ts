/**
 * What a process did, as Sysmon records it under its ProcessGuid: network
 * connections, DNS queries, files created and registry changes. Every count
 * comes with the search that lists exactly its events.
 */
import type { Schema } from '../engine/schema';
import { ident, str } from '../engine/sql';
import { fieldTerm } from '../search/edit';

export interface Activity {
  network: number;
  dns: number;
  files: number;
  registry: number;
}

export const ACTIVITY: readonly { key: keyof Activity; label: string; ids: readonly number[] }[] = [
  { key: 'network', label: 'Network', ids: [3] },
  { key: 'dns', label: 'DNS', ids: [22] },
  { key: 'files', label: 'Files', ids: [11] },
  { key: 'registry', label: 'Registry', ids: [12, 13, 14] },
];

const CHANNELS = ['Microsoft-Windows-Sysmon/Operational', 'Linux-Sysmon/Operational'];

function fields(schema: Schema) {
  const guid = schema.find('ProcessGuid');
  const channel = schema.find('Channel');
  const eventid = schema.find('EventID');
  return guid && channel && eventid ? { guid, channel, eventid } : null;
}

// Compared as the search compares them, so a count and its search agree: the id as text, the channel and
// the guid ignoring case.
function counts(eventid: string): string {
  return ACTIVITY.map(({ key, ids }) => `count(*) FILTER (WHERE ${eventid} IN (${ids.map((id) => str(String(id))).join(', ')}))::DOUBLE AS ${key}`).join(', ');
}

function sysmon(schema: Schema): string | null {
  const f = fields(schema);
  if (!f) return null;
  const ids = ACTIVITY.flatMap((kind) => kind.ids).map((id) => str(String(id)));
  return `lower(CAST(${ident(f.channel.name)} AS VARCHAR)) IN (${CHANNELS.map((c) => str(c.toLowerCase())).join(', ')}) ` +
    `AND CAST(${ident(f.eventid.name)} AS VARCHAR) IN (${ids.join(', ')})`;
}

/** One process's activity; null when the package lacks the fields to tell. */
export function activitySql(schema: Schema, guid: string): string | null {
  const f = fields(schema);
  const where = sysmon(schema);
  if (!f || !where) return null;
  return `SELECT ${counts(`CAST(${ident(f.eventid.name)} AS VARCHAR)`)} FROM events ` +
    `WHERE ${where} AND lower(CAST(${ident(f.guid.name)} AS VARCHAR)) = lower(${str(guid)})`;
}

/** Every process's activity by lowercased guid, for the tree to join: a CTE named _zl_act, or null. */
export function activityCte(schema: Schema): string | null {
  const f = fields(schema);
  const where = sysmon(schema);
  if (!f || !where) return null;
  return `_zl_act AS (SELECT lower(CAST(${ident(f.guid.name)} AS VARCHAR)) AS g, ${counts(`CAST(${ident(f.eventid.name)} AS VARCHAR)`)} ` +
    `FROM events WHERE ${where} AND ${ident(f.guid.name)} IS NOT NULL GROUP BY 1)`;
}

/** The search listing exactly the events one count counts. */
export function activityTerms(schema: Schema, guid: string, key: keyof Activity): string | null {
  const f = fields(schema);
  const kind = ACTIVITY.find((k) => k.key === key);
  if (!f || !kind) return null;
  const channels = `(${CHANNELS.map((c) => fieldTerm(f.channel.name, c)).join(' OR ')})`;
  const ids = kind.ids.map((id) => `${fieldTerm(f.eventid.name, String(id))}`);
  return `${fieldTerm(f.guid.name, guid)} ${channels} ${ids.length === 1 ? ids[0] : `(${ids.join(' OR ')})`}`;
}

const SHORT: Record<keyof Activity, string> = { network: 'net', dns: 'dns', files: 'file', registry: 'reg' };

/** The kinds of activity a process has, as the tree's column shows them. */
export function activitySummary(activity: Activity | null): string {
  if (!activity) return '';
  return ACTIVITY.filter(({ key }) => activity[key] > 0).map(({ key }) => `${activity[key]} ${SHORT[key]}`).join(' · ');
}
