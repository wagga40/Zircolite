import { LEVELS } from '../engine/levels';
import type { Manifest } from '../engine/manifest';
import { timePredicate } from '../state/where';

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** Bin widths a reader can name, finest first. */
export const STEPS = [
  SECOND, 5 * SECOND, 15 * SECOND, 30 * SECOND, MINUTE, 5 * MINUTE, 15 * MINUTE, 30 * MINUTE,
  HOUR, 3 * HOUR, 6 * HOUR, 12 * HOUR, DAY, 2 * DAY, 7 * DAY, 14 * DAY, 30 * DAY, 90 * DAY, 365 * DAY,
];

export interface Bins {
  /** Epoch milliseconds where bin 0 starts, a multiple of width. */
  start: number;
  width: number;
  count: number;
}

export function layout([lo, hi]: [number, number], maxBins: number): Bins {
  let bins: Bins = { start: lo, width: STEPS[0], count: 1 };
  for (const width of STEPS) {
    const start = Math.floor(lo / width) * width;
    bins = { start, width, count: Math.floor((hi - start) / width) + 1 };
    if (bins.count <= maxBins) break;
  }
  return bins;
}

export const DOMAIN_SQL = 'SELECT epoch_ms(min(_zl_time))::DOUBLE AS lo, epoch_ms(max(_zl_time))::DOUBLE AS hi FROM events';

export function domainOf(row: { lo: number | null; hi: number | null } | undefined): [number, number] | null {
  if (!row || row.lo === null || row.hi === null || !Number.isFinite(row.lo) || !Number.isFinite(row.hi)) return null;
  return [row.lo, row.hi];
}

export interface BinRow {
  b: number;
  n: number;
  l0: number;
  l1: number;
  l2: number;
  l3: number;
  l4: number;
  lu: number;
}

export interface Series {
  bins: Bins;
  n: Float64Array;
  /** levels[rank][bin]: events whose highest detection has that level. */
  levels: Float64Array[];
  /** Events whose rule has no Sigma level (rank -1); the ranks above do not hold them. */
  unknown: Float64Array;
}

/**
 * Events per bin. The query covers exactly the layout's span: a strip zoomed
 * into a range would otherwise count events outside it into bins it does not have.
 */
export function binsSql(bins: Bins, where: string): string {
  const span = timePredicate([bins.start, bins.start + bins.width * bins.count]);
  if (span === null) throw new Error(`the histogram layout ${JSON.stringify(bins)} is not in whole milliseconds`);
  const levels = [...LEVELS.map((_, rank) => `count(*) FILTER (WHERE _zl_lvl = ${rank})::DOUBLE AS l${rank}`), 'count(*) FILTER (WHERE _zl_lvl = -1)::DOUBLE AS lu'].join(', ');
  return (
    `SELECT floor((epoch_ms(_zl_time) - ${bins.start}) / ${bins.width})::INTEGER AS b, count(*)::DOUBLE AS n, ${levels} ` +
    `FROM events LEFT JOIN event_levels USING (_zl_uid) WHERE ${span} AND (${where}) GROUP BY b ORDER BY b`
  );
}

export function fill(rows: BinRow[], bins: Bins): Series {
  const n = new Float64Array(bins.count);
  const levels = LEVELS.map(() => new Float64Array(bins.count));
  const unknown = new Float64Array(bins.count);
  for (const row of rows) {
    // The query is bounded to the layout, so a bin outside it means the
    // query and the layout disagree: drawing it anyway would misplace counts.
    if (!(row.b >= 0 && row.b < bins.count)) throw new Error(`histogram bin ${row.b} is outside 0..${bins.count - 1}`);
    n[row.b] = row.n;
    levels.forEach((series, rank) => {
      series[row.b] = row[`l${rank}` as keyof BinRow];
    });
    unknown[row.b] = row.lu;
  }
  return { bins, n, levels, unknown };
}

export function binAt(x: number, width: number, count: number): number {
  return Math.min(count - 1, Math.max(0, Math.floor((x / width) * count)));
}

/** The half-open time range covering bins a to b, whichever way the drag went. */
export function rangeOf(bins: Bins, a: number, b: number): [number, number] {
  return [bins.start + Math.min(a, b) * bins.width, bins.start + (Math.max(a, b) + 1) * bins.width];
}

export function binSummary(series: Series, a: number, b: number): { range: [number, number]; events: number; levels: number[]; unknown: number } {
  const from = Math.min(a, b);
  const to = Math.max(a, b);
  let events = 0;
  const levels = LEVELS.map(() => 0);
  let unknown = 0;
  for (let i = from; i <= to; i++) {
    events += series.n[i];
    series.levels.forEach((counts, rank) => {
      levels[rank] += counts[i];
    });
    unknown += series.unknown[i];
  }
  return { range: rangeOf(series.bins, from, to), events, levels, unknown };
}

/** Square-root height, so quiet bins stay visible beside a burst; non-zero never rounds away. */
export function barHeight(value: number, max: number, full: number, least: number): number {
  if (value <= 0 || max <= 0) return 0;
  return Math.max(least, Math.sqrt(value / max) * full);
}

export function formatRange([start, end]: [number, number]): string {
  const a = new Date(start).toISOString();
  const b = new Date(end).toISOString();
  const sameDay = a.slice(0, 10) === b.slice(0, 10);
  return `${a.slice(0, 10)} ${a.slice(11, 19)} to ${sameDay ? '' : `${b.slice(0, 10)} `}${b.slice(11, 19)}`;
}

const UNITS: [number, string][] = [[DAY, 'day'], [HOUR, 'hour'], [MINUTE, 'minute'], [SECOND, 'second']];

export function formatWidth(ms: number): string {
  const [size, unit] = UNITS.find(([size]) => ms % size === 0 && ms >= size) ?? [1, 'millisecond'];
  const count = ms / size;
  return `${count} ${unit}${count === 1 ? '' : 's'}`;
}

export function timelessCount(manifest: Pick<Manifest, 'parts'>): number {
  return manifest.parts.reduce((sum, part) => sum + part.time.missing + part.time.unparsed, 0);
}

/** One histogram query and the layout it was built for, kept together so its answer is always drawn on that layout. */
export interface StripRequest {
  bins: Bins;
  sql: string;
}

export function stripRequest(bins: Bins, where: string): StripRequest {
  return { bins, sql: binsSql(bins, where) };
}

export function stripSeries(request: StripRequest, rows: BinRow[]): Series {
  return fill(rows, request.bins);
}
