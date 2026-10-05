/** The rows a fixed-height list renders for a scroll position: the visible ones and a few either side. */
export function windowOf(scrollTop: number, viewport: number, total: number, row = 28, overscan = 8): { first: number; count: number; top: number } {
  if (total <= 0) return { first: 0, count: 0, top: 0 };
  const first = Math.max(0, Math.min(total - 1, Math.floor(scrollTop / row) - overscan));
  const last = Math.min(total, Math.ceil((scrollTop + viewport) / row) + overscan);
  return { first, count: Math.max(0, last - first), top: first * row };
}
