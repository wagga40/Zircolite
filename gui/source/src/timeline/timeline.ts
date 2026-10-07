import { tacticName } from '../attack/catalog';
import { TIME_LIMIT } from '../state/hash';
import { timePredicate } from '../state/where';

export const LANE_H = 24;
export const LANE_GAP = 2;
export const AXIS_H = 26;
export const PAD_L = 148;
export const PAD_R = 12;
export const PAD_T = 8;
/** The label gutter narrows on a phone, where the plot needs the width more. */
export function padLeft(width: number): number {
  return width < 560 ? 112 : PAD_L;
}
export const MIN_SPAN = 1000;
const MAX_SPAN_FACTOR = 4;
const HIT_PX = 6;
const BUCKET_PX = 4;
const MAX_GRIDLINES = 40;
const DAY = 86_400_000;
const YEAR = 365 * DAY;
const TICKS = [1e3, 5e3, 15e3, 30e3, 60e3, 3e5, 9e5, 18e5, 36e5, 108e5, 216e5, DAY, 7 * DAY, 31 * DAY, 92 * DAY, 183 * DAY, YEAR, 10 * YEAR];

export interface Span {
  from: number;
  to: number;
}

export function tickStep(span: number): number {
  for (const step of TICKS) if (span / step <= 10) return step;
  // Past the ladder the step is derived, so no span can make the tick loop run away.
  return Math.max(TICKS[TICKS.length - 1], Math.ceil(span / 10));
}

const DATE_RANGE = 8.64e15;

function monthStart(index: number): number {
  const date = new Date(0);
  date.setUTCFullYear(Math.floor(index / 12), ((index % 12) + 12) % 12, 1);
  return date.getTime();
}

/** Ticks on calendar boundaries once a step is a week or more; sub-day steps are already aligned to UTC. */
export function ticks(span: Span): number[] {
  const step = tickStep(span.to - span.from);
  const out: number[] = [];
  const inRange = Math.abs(span.from) < DATE_RANGE && Math.abs(span.to) < DATE_RANGE;
  if (step < 7 * DAY || !inRange) {
    for (let t = Math.ceil(span.from / step) * step; t <= span.to && out.length < MAX_GRIDLINES; t += step) out.push(t);
    return out;
  }
  if (step < 28 * DAY) {
    // Weeks begin on Monday: the epoch day was a Thursday.
    const day = Math.ceil(span.from / DAY) * DAY;
    const weekday = (Math.floor(day / DAY) + 3) % 7;
    for (let t = day + (((7 - weekday) % 7) + 7) % 7 * DAY; t <= span.to && out.length < MAX_GRIDLINES; t += 7 * DAY) out.push(t);
    return out;
  }
  const months = step >= YEAR ? 12 * Math.max(1, Math.round(step / YEAR)) : step >= 183 * DAY ? 6 : step >= 92 * DAY ? 3 : 1;
  const first = new Date(span.from);
  let index = Math.floor((first.getUTCFullYear() * 12 + first.getUTCMonth()) / months) * months;
  while (monthStart(index) < span.from) index += months;
  for (; monthStart(index) <= span.to && out.length < MAX_GRIDLINES; index += months) out.push(monthStart(index));
  return out;
}

/**
 * Axis labels in UTC, as every time in the viewer is. Given the window being
 * drawn, a label never leaves the year open: months and days carry it where
 * the window could make it ambiguous.
 */
export function formatTick(ms: number, span: number, window?: Span): string {
  const iso = new Date(ms).toISOString();
  if (window) {
    const step = tickStep(span);
    if (step >= YEAR) return iso.slice(0, 4);
    if (step >= 28 * DAY) return iso.slice(0, 7);
    const crosses = new Date(window.from).getUTCFullYear() !== new Date(window.to).getUTCFullYear();
    if (step >= DAY) return crosses ? iso.slice(0, 10) : iso.slice(5, 10);
    if (span >= DAY) return `${crosses ? iso.slice(0, 10) : iso.slice(5, 10)} ${iso.slice(11, 16)}`;
    return iso.slice(11, step < 60_000 ? 19 : 16);
  }
  if (span < 60_000) return iso.slice(11, 19);
  if (span < DAY) return iso.slice(11, 16);
  if (span < YEAR) return iso.slice(5, 10);
  return iso.slice(0, 10);
}

/** One lane per tactic in kill-chain order, and a last one for rules that name none. */
export function lanes(tactics: readonly string[]): string[] {
  return [...tactics, ''];
}

export function laneLabel(lane: string): string {
  return lane ? tacticName(lane) : 'No tactic';
}

export function laneY(index: number): number {
  return PAD_T + index * (LANE_H + LANE_GAP) + LANE_H / 2;
}

export function height(laneCount: number): number {
  return PAD_T + Math.max(1, laneCount) * (LANE_H + LANE_GAP) + AXIS_H;
}

/** Keep a window from drifting more than half its width past the data. */
export function clamp(span: Span, extent: Span): Span {
  const width = span.to - span.from;
  const lo = extent.from - width / 2;
  const hi = extent.to + width / 2;
  let from = Math.max(span.from, lo);
  if (from + width > hi) from = hi - width;
  // The page's time range cannot hold a time past TIME_LIMIT, so the window stops there and always matches it.
  from = Math.min(Math.max(from, -TIME_LIMIT), TIME_LIMIT - width);
  return { from, to: from + width };
}

/** Zoom by a factor about an anchor time, which stays under the pointer. */
export function zoomAt(span: Span, anchor: number, factor: number, extent: Span): Span {
  const current = span.to - span.from;
  const limit = Math.max(MIN_SPAN, (extent.to - extent.from) * MAX_SPAN_FACTOR);
  const width = Math.min(limit, Math.max(MIN_SPAN, current * factor));
  const fraction = current > 0 ? (anchor - span.from) / current : 0.5;
  const from = anchor - width * fraction;
  return clamp({ from, to: from + width }, extent);
}

export function pan(span: Span, delta: number, extent: Span): Span {
  return clamp({ from: span.from + delta, to: span.to + delta }, extent);
}

/** Bucket width in whole milliseconds, about four pixels of the plot. */
export function bucketMs(span: Span, plotWidth: number): number {
  return Math.max(1, Math.ceil((span.to - span.from) / Math.max(1, plotWidth / BUCKET_PX)));
}

export const EXTENT_SQL =
  'SELECT epoch_ms(min(e._zl_time))::DOUBLE AS lo, epoch_ms(max(e._zl_time))::DOUBLE AS hi FROM events e ' +
  'WHERE e._zl_uid IN (SELECT _zl_uid FROM hits)';

/** Events with detections under the filters that have no time: the timeline has nowhere to put them. */
export function timelessSql(where: string): string {
  return `SELECT count(*)::DOUBLE AS n FROM events WHERE _zl_time IS NULL AND _zl_uid IN (SELECT _zl_uid FROM hits) AND (${where})`;
}

export interface Mark {
  lane: string;
  b: number;
  n: number;
  lvl: number;
  /** The earliest event of the mark: the one a click opens. */
  uid: number;
  first: number;
  last: number;
}

/**
 * Detections per tactic lane and time bucket. One row per lane and bucket,
 * however many detections fall in it, so a quarter of a million detections
 * arrive as at most a few thousand marks.
 */
export function marksSql(span: Span, bucket: number, where: string): string {
  const from = Math.floor(span.from);
  const to = Math.ceil(span.to);
  const range = timePredicate([from, to]);
  if (range === null || !Number.isSafeInteger(bucket) || bucket < 1) throw new Error(`the timeline window ${from}..${to} cannot be queried`);
  return (
    `WITH m AS (SELECT _zl_uid, epoch_ms(_zl_time) AS t FROM events WHERE ${range} AND (${where})), ` +
    'd AS (SELECT h._zl_uid, r.level_rank, coalesce(x.tactic, \'\') AS lane FROM hits h JOIN rules r ON r.rule_idx = h.rule_idx ' +
    'LEFT JOIN (SELECT rule_idx, unnest(tactics) AS tactic FROM rules) x ON x.rule_idx = h.rule_idx) ' +
    `SELECT d.lane, floor((m.t - ${from}) / ${bucket})::INTEGER AS b, count(DISTINCT m._zl_uid)::DOUBLE AS n, ` +
    'max(d.level_rank)::INTEGER AS lvl, arg_min(m._zl_uid, m.t) AS uid, min(m.t)::DOUBLE AS first, max(m.t)::DOUBLE AS last ' +
    'FROM m JOIN d ON d._zl_uid = m._zl_uid GROUP BY d.lane, b ORDER BY d.lane, b'
  );
}

export interface Placed extends Mark {
  x: number;
  y: number;
  r: number;
}

/** Marks of a query over `query.from` with `query.bucket`, drawn in the window `view` on a canvas `width` wide. */
export function place(marks: Mark[], query: { from: number; bucket: number }, view: Span, laneList: string[], width: number): Placed[] {
  const pad = padLeft(width);
  const plot = Math.max(1, width - pad - PAD_R);
  const span = view.to - view.from;
  return marks.flatMap((mark) => {
    const index = laneList.indexOf(mark.lane);
    if (index < 0 || span <= 0) return [];
    const time = query.from + (mark.b + 0.5) * query.bucket;
    const x = pad + ((time - view.from) / span) * plot;
    if (x < pad - 8 || x > width - PAD_R + 8) return [];
    return [{ ...mark, x, y: laneY(index), r: 3.5 + Math.min(3, 2 * Math.log10(Math.max(1, mark.n))) }];
  });
}

export function hit(placed: Placed[], x: number, y: number): Placed | null {
  let best: Placed | null = null;
  let distance = HIT_PX;
  for (const mark of placed) {
    if (Math.abs(mark.y - y) > LANE_H / 2) continue;
    const dx = Math.abs(mark.x - x);
    if (dx <= distance) {
      distance = dx;
      best = mark;
    }
  }
  return best;
}

/**
 * The Explore filter that selects exactly the events a mark counts: its own
 * time range (end exclusive, like the page's) and its tactic. A lane for rules
 * without a tactic has no search term, so it offers none rather than a
 * filter that would count other events too.
 */
export function showFilter(mark: Mark): { t: [number, number]; term: string } | null {
  if (!mark.lane) return null;
  return { t: [mark.first, mark.last + 1], term: `tactic:${mark.lane}` };
}
