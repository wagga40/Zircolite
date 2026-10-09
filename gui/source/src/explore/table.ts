import type { Field } from '../engine/schema';
import { ident } from '../engine/sql';

export const ROW = 28;
/** The sticky header row, which sits inside the scroller above the rows. */
export const HEAD = 32;
export const PAGE = 200;
/** Under every browser's limit on an element's height; Firefox's, near 17.9M px, is the lowest. */
export const HEIGHT_CAP = 8_000_000;

/** The ordered result list every page, count and export reads, rebuilt once per filter change. */
export function idsSql(where: string, desc: boolean): string {
  const order = desc ? 'DESC' : 'ASC';
  // NULLS LAST in both directions keeps events without a time at the end, listed rather than lost.
  return (
    `CREATE OR REPLACE TEMP TABLE view_ids AS SELECT (row_number() OVER (ORDER BY _zl_time ${order} NULLS LAST, ` +
    `_zl_uid ${order}) - 1)::BIGINT AS _zl_pos, _zl_uid FROM events WHERE ${where}`
  );
}

export const COUNT_SQL =
  'SELECT count(*)::DOUBLE AS n, count(l._zl_lvl)::DOUBLE AS d FROM view_ids v LEFT JOIN event_levels l ON l._zl_uid = v._zl_uid';

export interface PageRow {
  _zl_pos: number;
  _zl_uid: number;
  _zl_t: number | null;
  _zl_lvl: number | null;
  _zl_part?: number | null;
  _zl_spelling?: string | null;
  [value: `_zl_v${number}`]: string | null;
}

/**
 * Rows from..to-1 of a result list. Values come back as text, so 64-bit
 * integers reach JavaScript exactly, and under positional aliases, so no
 * field name can collide with another or with the viewer's own columns.
 */
export function pageSql(fields: Field[], from: number, to: number, source: 'view_ids' | 'export_ids' = 'view_ids', names = false): string {
  const values = fields.map((field, i) => `CAST(e.${ident(field.name)} AS VARCHAR) AS _zl_v${i}`);
  const spelling = names ? ['e._zl_part', 'e._zl_spelling'] : [];
  const columns = ['v._zl_pos', 'v._zl_uid', 'epoch_ms(e._zl_time)::DOUBLE AS _zl_t', 'l._zl_lvl', ...spelling, ...values];
  return (
    `SELECT ${columns.join(', ')} FROM ${source} v JOIN events e ON e._zl_uid = v._zl_uid ` +
    `LEFT JOIN event_levels l ON l._zl_uid = v._zl_uid WHERE v._zl_pos >= ${from} AND v._zl_pos < ${to} ORDER BY v._zl_pos`
  );
}

export interface Slice {
  /** Height of the scrolled content. */
  height: number;
  first: number;
  /** Offset of the first rendered row within the scrolled content. */
  top: number;
  count: number;
}

/**
 * Which rows to render for a scroll position. Past HEIGHT_CAP the content
 * stops growing and scrolling maps proportionally onto row positions, so the
 * last of millions of rows is still reachable.
 */
export function geometry(total: number, viewport: number, scrollTop: number, row = ROW, cap = HEIGHT_CAP): Slice {
  const visible = Math.ceil(viewport / row) + 1;
  const full = total * row;
  if (full <= cap) {
    const first = Math.min(Math.max(0, Math.floor(scrollTop / row)), Math.max(0, total - 1));
    return { height: full, first, top: first * row, count: Math.max(0, Math.min(visible, total - first)) };
  }
  const exact = progressOf(scrollTop, viewport, cap) * Math.max(0, total - viewport / row);
  const first = Math.floor(exact);
  return { height: cap, first, top: scrollTop - (exact - first) * row, count: Math.min(visible, total - first) };
}

/**
 * The page to load next: the first one the visible rows need that has not
 * loaded. One page is requested at a time, so a fast scroll leaves at most
 * one stale request queued ahead of the rows it stops on.
 */
export function nextPage(slice: Pick<Slice, 'first' | 'count'>, loaded: Set<number> | ((page: number) => boolean), size = PAGE): number | null {
  if (slice.count <= 0) return null;
  const has = typeof loaded === 'function' ? loaded : (page: number) => loaded.has(page);
  const last = Math.floor((slice.first + slice.count - 1) / size);
  for (let page = Math.floor(slice.first / size); page <= last; page++) {
    if (!has(page)) return page;
  }
  return null;
}

function progressOf(scrollTop: number, viewport: number, cap: number): number {
  const range = cap - viewport;
  return range > 0 ? Math.min(1, Math.max(0, scrollTop / range)) : 0;
}

/** The scroll position that brings a row into view, moving as little as possible. */
export function ensureVisible(position: number, scrollTop: number, total: number, viewport: number, row = ROW, cap = HEIGHT_CAP): number {
  const slice = geometry(total, viewport, scrollTop, row, cap);
  const rowTop = slice.top + (position - slice.first) * row - scrollTop;
  if (rowTop >= 0 && rowTop + row <= viewport) return scrollTop;
  if (total * row <= cap) return rowTop < 0 ? position * row : position * row + row - viewport;
  const span = Math.max(1, total - viewport / row);
  const exact = rowTop < 0 ? position : position + 1 - viewport / row;
  return Math.min(1, Math.max(0, exact / span)) * (cap - viewport);
}

/**
 * Where a wheel turn leaves the list. Below the height cap it is the
 * browser's own scrolling; past it, scroll positions map to rows
 * proportionally, so a notch would jump thousands of rows. It moves the rows
 * the notch would move below the cap instead.
 */
export function wheelScroll(scrollTop: number, deltaY: number, total: number, viewport: number, row = ROW, cap = HEIGHT_CAP): number {
  if (total * row <= cap) return scrollTop + deltaY;
  const range = cap - viewport;
  const span = Math.max(1, total - viewport / row);
  const exact = Math.min(1, Math.max(0, scrollTop / range)) * span + deltaY / row;
  return Math.min(1, Math.max(0, exact / span)) * range;
}

/** A wheel event's vertical travel in pixels: lines count as rows, pages as the viewport. */
export function wheelDelta(event: { deltaY: number; deltaMode: number }, viewport: number, row = ROW): number {
  if (event.deltaMode === 1) return event.deltaY * row;
  if (event.deltaMode === 2) return event.deltaY * viewport;
  return event.deltaY;
}

/**
 * The next unrounded scroll position of a wheel turn. A scrollTop holds whole
 * pixels, and past the height cap a row is a few pixels, so a slow trackpad's
 * 1 px deltas would round away one by one. The unrounded position is kept
 * between turns and dropped when the real scrollTop moved by other means.
 */
export function wheelPosition(kept: number | null, scrollTop: number, deltaY: number, total: number, viewport: number): number {
  const from = kept !== null && Math.abs(Math.round(kept) - scrollTop) < 1 ? kept : scrollTop;
  return wheelScroll(from, deltaY, total, viewport);
}
