export const DETECTIONS_PREDICATE = '_zl_uid IN (SELECT _zl_uid FROM hits)';

export function timePredicate(range: [number, number] | null): string | null {
  if (!range) return null;
  const [start, end] = range;
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end)) return null;
  return `_zl_time >= make_timestamp(${start * 1000}) AND _zl_time < make_timestamp(${end * 1000})`;
}

/** One WHERE clause from the predicates Mosaic resolves for a client. */
export function combineWhere(filter: unknown): string {
  const list = Array.isArray(filter) ? filter : filter === null || filter === undefined ? [] : [filter];
  const parts = list
    .filter((p) => p !== true && p !== null && p !== undefined && `${p}`.trim() !== '')
    .map((p) => `(${p})`);
  return parts.length ? parts.join(' AND ') : 'TRUE';
}
