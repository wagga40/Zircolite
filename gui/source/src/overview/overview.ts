import { tacticName } from '../attack/catalog';
import { levelLabel } from '../detections/rules';
import { LEVELS } from '../engine/levels';
import type { Field, Schema } from '../engine/schema';
import { findShortcut } from '../search/shortcuts';

function matched(where: string): string {
  return `WITH m AS (SELECT _zl_uid FROM events WHERE ${where})`;
}

/** Filtered events by their highest detection level: each event in exactly one tile. */
export function tileEventsSql(where: string): string {
  return `${matched(where)} SELECT l._zl_lvl::INTEGER AS rank, count(*)::DOUBLE AS events FROM m JOIN event_levels l ON l._zl_uid = m._zl_uid GROUP BY l._zl_lvl ORDER BY rank`;
}

/** Rule keys with a filtered event, by the highest level among each key's entries. */
export function tileRulesSql(where: string): string {
  return (
    `${matched(where)}, k AS (SELECT key, max(level_rank) AS rank FROM rules GROUP BY key) ` +
    'SELECT k.rank::INTEGER AS rank, count(DISTINCT r.key)::DOUBLE AS rules FROM rules r JOIN k ON k.key = r.key ' +
    'JOIN hits h ON h.rule_idx = r.rule_idx JOIN m ON m._zl_uid = h._zl_uid GROUP BY k.rank ORDER BY rank'
  );
}

export interface Tile {
  rank: number;
  level: string;
  label: string;
  /** The search that lists exactly the tile's events. */
  term: string;
  events: number;
  rules: number;
}

/**
 * One tile per Sigma level, critical first, and an Unknown level tile when some events are detected
 * only by rules whose level is none of Sigma's (rank -1): without it the tiles would not add up.
 */
export function tiles(events: { rank: number; events: number }[], rules: { rank: number; rules: number }[]): Tile[] {
  const byEvents = new Map(events.map((row) => [row.rank, row.events]));
  const byRules = new Map(rules.map((row) => [row.rank, row.rules]));
  const tile = (rank: number, level: string, term: string): Tile =>
    ({ rank, level, label: levelLabel(rank), term, events: byEvents.get(rank) ?? 0, rules: byRules.get(rank) ?? 0 });
  const known = LEVELS.map((level, rank) => tile(rank, level, `level:${level}`)).reverse();
  // Below informational there is only the unknown rank.
  return byEvents.get(-1) ? [...known, tile(-1, 'unknown', 'level:<informational')] : known;
}

export function tacticsSql(where: string): string {
  return (
    `${matched(where)} SELECT x.tactic, count(DISTINCT h._zl_uid)::DOUBLE AS events FROM hits h ` +
    'JOIN m ON m._zl_uid = h._zl_uid JOIN (SELECT rule_idx, unnest(tactics) AS tactic FROM rules) x ON x.rule_idx = h.rule_idx ' +
    'GROUP BY x.tactic'
  );
}

export interface TacticCell {
  tactic: string;
  label: string;
  events: number;
  /** sqrt(events / busiest), so a single hit is still visible beside thousands. */
  share: number;
}

// The cells come from manifest.tactics, the list the rules' tactics are written from, so no counted tactic goes unlisted.
export function tacticCells(tactics: string[], rows: { tactic: string; events: number }[]): TacticCell[] {
  const counts = new Map(rows.map((row) => [row.tactic, row.events]));
  const busiest = Math.max(0, ...rows.map((row) => row.events));
  return tactics.map((tactic) => {
    const events = counts.get(tactic) ?? 0;
    return { tactic, label: tacticName(tactic), events, share: busiest > 0 ? Math.sqrt(events / busiest) : 0 };
  });
}

export function topRulesSql(where: string, limit = 10): string {
  return (
    `${matched(where)} SELECT r.key, arg_min(r.title, r.rule_idx) AS title, max(r.level_rank)::INTEGER AS rank, ` +
    'count(DISTINCT m._zl_uid)::DOUBLE AS events FROM rules r JOIN hits h ON h.rule_idx = r.rule_idx ' +
    `JOIN m ON m._zl_uid = h._zl_uid GROUP BY r.key ORDER BY events DESC, title LIMIT ${Math.max(1, Math.floor(limit))}`
  );
}

/** The first field the host: or user: shortcut would search that this package has. */
export function entityField(kind: 'host' | 'user', schema: Schema): Field | undefined {
  return (findShortcut(kind)?.fields ?? []).map((name) => schema.find(name)).find((field): field is Field => field !== undefined);
}
