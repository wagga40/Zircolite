import { CATALOG, isActive, replacement, subTechniques, type Technique } from './catalog';

function matched(where: string): string {
  return `WITH m AS (SELECT _zl_uid FROM events WHERE ${where})`;
}

/**
 * Events detected under each technique tag, counted as technique:<id> counts
 * them: an event once per ID, and a parent ID once more for its
 * sub-techniques' events, so T1059 holds every event of T1059 and T1059.*.
 */
export function techniqueCountsSql(where: string): string {
  return (
    `${matched(where)}, t AS (SELECT DISTINCT h._zl_uid, x.t FROM hits h JOIN m ON m._zl_uid = h._zl_uid ` +
    'JOIN (SELECT rule_idx, unnest(techniques) AS t FROM rules) x ON x.rule_idx = h.rule_idx) ' +
    'SELECT id, count(DISTINCT _zl_uid)::DOUBLE AS events FROM (SELECT t AS id, _zl_uid FROM t ' +
    "UNION ALL SELECT split_part(t, '.', 1) AS id, _zl_uid FROM t WHERE contains(t, '.')) GROUP BY id"
  );
}

/** Every technique tag the package's rules carry, whatever the filters. */
export const STORED_TECHNIQUES_SQL = 'SELECT DISTINCT unnest(techniques) AS id FROM rules ORDER BY id';

export type MatrixMode = 'detected' | 'full';

export interface Cell {
  id: string;
  name: string;
  events: number;
  /** sqrt(events / busiest), so a single event still shows beside thousands. */
  share: number;
  subs: Cell[];
}

export interface Column {
  tactic: string;
  id: string;
  name: string;
  cells: Cell[];
}

/** The heat of a cell, as the Overview's tactic strip draws it; none for an empty one. */
export function heatInk(share: number): string | undefined {
  return share > 0 ? `color-mix(in srgb, var(--signal) ${Math.round(12 + 40 * share)}%, var(--panel))` : undefined;
}

/**
 * One column per tactic, in ATT&CK's order. A technique sits under every
 * tactic ATT&CK puts it under, with the same count in each, as the ATT&CK
 * Navigator shows it.
 */
export function matrix(counts: ReadonlyMap<string, number>, mode: MatrixMode): Column[] {
  const busiest = Math.max(0, ...CATALOG.techniques.map((t) => counts.get(t.id) ?? 0));
  const order = (a: Cell, b: Cell) =>
    mode === 'detected' ? b.events - a.events || a.name.localeCompare(b.name, 'en') : a.name.localeCompare(b.name, 'en');
  const keep = (cell: Cell) => mode === 'full' || cell.events > 0;
  const cell = (t: Technique, tactic: string, subs: Cell[]): Cell => {
    const events = counts.get(t.id) ?? 0;
    return { id: t.id, name: t.name, events, share: busiest > 0 ? Math.sqrt(events / busiest) : 0, subs };
  };
  return CATALOG.tactics.map((tactic) => {
    const cells = CATALOG.techniques
      .filter((t) => !t.id.includes('.') && t.tactics.includes(tactic.shortname))
      .map((t) => {
        const subs = subTechniques(t.id)
          .filter((s) => s.tactics.includes(tactic.shortname))
          .map((s) => cell(s, tactic.shortname, []))
          .filter(keep)
          .sort(order);
        return cell(t, tactic.shortname, subs);
      })
      .filter(keep)
      .sort(order);
    return { tactic: tactic.shortname, id: tactic.id, name: tactic.name, cells };
  });
}

/** Detected techniques, counted once each, sub-techniques within their parent. */
export function detectedTechniques(counts: ReadonlyMap<string, number>): number {
  return CATALOG.techniques.filter((t) => !t.id.includes('.') && (counts.get(t.id) ?? 0) > 0).length;
}

export interface Unlisted {
  id: string;
  events: number;
  replacement: Technique | null;
  status: 'revoked' | 'retired' | 'unknown';
}

/**
 * Tags the catalogue holds no active technique for, with their events under
 * the filters: a rule written before ATT&CK revoked its technique still
 * detects, and its events must not vanish from the view.
 */
export function unlisted(stored: readonly string[], counts: ReadonlyMap<string, number>): Unlisted[] {
  return [...new Set(stored)]
    .filter((id) => !isActive(id))
    .map((id): Unlisted => {
      const next = replacement(id) ?? null;
      const status = next ? 'revoked' : CATALOG.deprecated.includes(id) ? 'retired' : 'unknown';
      return { id, events: counts.get(id) ?? 0, replacement: next, status };
    })
    .filter((u) => u.events > 0)
    .sort((a, b) => b.events - a.events || a.id.localeCompare(b.id));
}

export const WEEKDAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'] as const;

/** Events with detections by UTC weekday (1 is Monday) and hour; events without a time cannot be placed. */
export function heatmapSql(where: string): string {
  return (
    'SELECT isodow(_zl_time)::INTEGER AS day, hour(_zl_time)::INTEGER AS hour, count(*)::DOUBLE AS events FROM events ' +
    `WHERE (${where}) AND _zl_uid IN (SELECT _zl_uid FROM event_levels) AND _zl_time IS NOT NULL GROUP BY ALL`
  );
}

export interface HeatCell {
  day: number;
  hour: number;
  events: number;
  share: number;
}

export function heatmap(rows: { day: number; hour: number; events: number }[]): { cells: HeatCell[][]; busiest: number } {
  const counts = new Map(rows.map((r) => [`${r.day}:${r.hour}`, r.events]));
  const busiest = Math.max(0, ...rows.map((r) => r.events));
  const cells = WEEKDAYS.map((_, i) =>
    Array.from({ length: 24 }, (_, hour): HeatCell => {
      const events = counts.get(`${i + 1}:${hour}`) ?? 0;
      return { day: i + 1, hour, events, share: busiest > 0 ? Math.sqrt(events / busiest) : 0 };
    }));
  return { cells, busiest };
}

/** The search that, with Detections only, lists exactly a heatmap cell's events. */
export function heatTerm(day: number, hour: number): string {
  return `weekday:${WEEKDAYS[day - 1].slice(0, 3).toLowerCase()} hour:${hour}`;
}
