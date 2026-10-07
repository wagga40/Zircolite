import { LEVELS } from '../engine/levels';
import type { Field, Schema } from '../engine/schema';
import { ident } from '../engine/sql';
import { findShortcut } from '../search/shortcuts';

export interface RuleRow {
  rule_idx: number;
  key: string;
  id: string;
  title: string;
  level: string;
  level_rank: number;
  description: string;
  tags: string[];
  falsepositives: string[];
  tactics: string[];
  techniques: string[];
  sigmafile: string;
  result_type: string;
  alert_count: number;
  events: number;
}

export interface KeyRow {
  key: string;
  events: number;
}

export interface SectionRow {
  rank: number;
  events: number;
}

function matched(where: string): string {
  return `WITH m AS (SELECT _zl_uid FROM events WHERE ${where})`;
}

/** Every matched ruleset entry, with how many of the filtered events it matched. */
export function ruleRowsSql(where: string): string {
  return (
    `${matched(where)} SELECT r.rule_idx, r.key, r.id, r.title, r.level, r.level_rank, r.description, r.tags, ` +
    'r.falsepositives, r.tactics, r.techniques, r.sigmafile, r.result_type, r.alert_count::DOUBLE AS alert_count, ' +
    'count(m._zl_uid)::DOUBLE AS events FROM rules r LEFT JOIN hits h ON h.rule_idx = r.rule_idx ' +
    'LEFT JOIN m ON m._zl_uid = h._zl_uid GROUP BY ALL ORDER BY r.rule_idx'
  );
}

/** Each rule key's filtered events, counted once: a rule's Sysmon and Generic variants can match the same event. */
export function keyRowsSql(where: string): string {
  return (
    `${matched(where)} SELECT r.key, count(DISTINCT m._zl_uid)::DOUBLE AS events FROM rules r ` +
    'JOIN hits h ON h.rule_idx = r.rule_idx JOIN m ON m._zl_uid = h._zl_uid GROUP BY r.key'
  );
}

/** Each level's filtered events, counted once, where a key belongs to the highest level among its entries. */
export function sectionRowsSql(where: string): string {
  return (
    `${matched(where)}, k AS (SELECT key, max(level_rank) AS rank FROM rules GROUP BY key) ` +
    'SELECT k.rank::INTEGER AS rank, count(DISTINCT m._zl_uid)::DOUBLE AS events FROM rules r JOIN k ON k.key = r.key ' +
    'JOIN hits h ON h.rule_idx = r.rule_idx JOIN m ON m._zl_uid = h._zl_uid GROUP BY k.rank'
  );
}

/** The filtered events with at least one detection. */
export function totalSql(where: string): string {
  return `${matched(where)} SELECT count(*)::DOUBLE AS events FROM m JOIN event_levels l ON l._zl_uid = m._zl_uid`;
}

export interface RuleGroup {
  key: string;
  title: string;
  rank: number;
  events: number;
  tactics: string[];
  techniques: string[];
  correlation: boolean;
  variants: RuleRow[];
}

export function groupRules(rows: RuleRow[], keys: KeyRow[]): RuleGroup[] {
  const counts = new Map(keys.map((k) => [k.key, k.events]));
  const groups = new Map<string, RuleGroup>();
  for (const row of [...rows].sort((a, b) => a.rule_idx - b.rule_idx)) {
    let group = groups.get(row.key);
    if (!group) {
      group = { key: row.key, title: row.title, rank: row.level_rank, events: counts.get(row.key) ?? 0, tactics: [], techniques: [], correlation: false, variants: [] };
      groups.set(row.key, group);
    }
    group.rank = Math.max(group.rank, row.level_rank);
    group.correlation ||= row.result_type === 'correlation';
    for (const tactic of row.tactics ?? []) if (!group.tactics.includes(tactic)) group.tactics.push(tactic);
    for (const technique of row.techniques ?? []) if (!group.techniques.includes(technique)) group.techniques.push(technique);
    group.variants.push(row);
  }
  return [...groups.values()];
}

export interface LevelSection {
  rank: number;
  events: number;
  rules: RuleGroup[];
}

/** Sections from critical down; a rule with no event under the filters shows only when asked. */
export function sections(groups: RuleGroup[], rows: SectionRow[], showEmpty: boolean): LevelSection[] {
  const counts = new Map(rows.map((r) => [r.rank, r.events]));
  const ranks = [...new Set(groups.map((g) => g.rank))].sort((a, b) => b - a);
  return ranks.flatMap((rank) => {
    const rules = groups
      .filter((g) => g.rank === rank && (showEmpty || g.events > 0))
      .sort((a, b) => b.events - a.events || a.title.localeCompare(b.title, 'en'));
    return rules.length ? [{ rank, events: counts.get(rank) ?? 0, rules }] : [];
  });
}

export function levelLabel(rank: number): string {
  const name = LEVELS[rank];
  return name ? name[0].toUpperCase() + name.slice(1) : 'Unknown level';
}

export interface AlertRow {
  alert_idx: number;
  alert_id: string | null;
  group_keys: string | null;
  occurrence: number | null;
  window_start: number | null;
  window_end: number | null;
  metric_name: string | null;
  metric_value: number | null;
  event_count: number;
  /** Every alert of these rules, however many the limit lets through. */
  total: number;
}

export function alertsSql(ruleIdx: number[], limit = 200): string {
  const list = ruleIdx.filter((i) => Number.isSafeInteger(i)).join(', ');
  if (!list) return 'SELECT * FROM alerts WHERE FALSE';
  return (
    'SELECT alert_idx, alert_id, group_keys, epoch_ms(occurrence_time)::DOUBLE AS occurrence, ' +
    'epoch_ms(window_start)::DOUBLE AS window_start, epoch_ms(window_end)::DOUBLE AS window_end, metric_name, ' +
    `metric_value, event_count::DOUBLE AS event_count, (count(*) OVER ())::DOUBLE AS total FROM alerts WHERE rule_idx IN (${list}) ` +
    `ORDER BY occurrence_time NULLS LAST, alert_idx LIMIT ${Math.max(1, Math.floor(limit))}`
  );
}

export interface EvidenceRow {
  ord: number;
  _zl_uid: number;
  _zl_t: number | null;
  host: string | null;
  eventid: string | null;
}

function firstField(names: readonly string[], schema: Schema): Field | undefined {
  return names.map((name) => schema.find(name)).find((field): field is Field => field !== undefined);
}

export function evidenceSql(alertIdx: number, schema: Schema): string {
  if (!Number.isSafeInteger(alertIdx) || alertIdx < 0) throw new Error(`${alertIdx} is not an alert`);
  const host = firstField(findShortcut('host')?.fields ?? [], schema);
  const eventid = schema.find('EventID');
  const text = (field: Field | undefined) => (field ? `CAST(e.${ident(field.name)} AS VARCHAR)` : 'NULL::VARCHAR');
  return (
    `SELECT ae.ord, ae._zl_uid, epoch_ms(e._zl_time)::DOUBLE AS _zl_t, ${text(host)} AS host, ${text(eventid)} AS eventid ` +
    `FROM alert_events ae JOIN events e ON e._zl_uid = ae._zl_uid WHERE ae.alert_idx = ${alertIdx} ORDER BY ae.ord LIMIT 500`
  );
}

/** A correlation's group keys as "name = value" pairs; anything else as its own text. */
export function groupKeysText(text: string | null): string {
  if (text === null) return '';
  try {
    const value: unknown = JSON.parse(text);
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return Object.entries(value as Record<string, unknown>).map(([k, v]) => `${k} = ${typeof v === 'string' ? v : JSON.stringify(v)}`).join(', ');
    }
  } catch {
    // Not JSON: shown as the text it is.
  }
  return text;
}
