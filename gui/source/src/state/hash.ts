export type Route = 'overview' | 'detections' | 'explore' | 'timeline' | 'attack' | 'entities' | 'processes' | 'sql';

/** The views, in the order the nav rail lists them. */
export const ROUTES: readonly Route[] = ['overview', 'detections', 'explore', 'timeline', 'attack', 'entities', 'processes', 'sql'];

export interface ViewHash {
  route: Route;
  q: string;
  /** Epoch milliseconds, start inclusive, end exclusive. */
  t: [number, number] | null;
  d: boolean;
  /** null means the default columns; [] means the user removed them all. */
  cols: string[] | null;
  uid: number | null;
  desc: boolean;
}

export const EMPTY: ViewHash = { route: 'overview', q: '', t: null, d: false, cols: null, uid: null, desc: false };

/**
 * JavaScript dates end at ±8.64e15 ms. The strip and the timeline lay bins
 * out past a range's ends by up to a year, so a range from a link must stay
 * that far inside, or drawing it throws and the page stops.
 */
export const TIME_LIMIT = 8_640_000_000_000_000 - 400 * 86_400_000;

const INTEGER = /^-?\d+$/;
const HASH = /^#\/([a-z]+)(?:\?(.*))?$/;

// encodeURIComponent throws on a lone surrogate, which would break the hash-writing effect.
function wellFormed(text: string): string {
  return text.replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '\uFFFD');
}

export function encode(state: ViewHash): string {
  const parts: string[] = [];
  if (state.q) parts.push(`q=${encodeURIComponent(wellFormed(state.q))}`);
  if (state.t) parts.push(`t=${state.t[0]}~${state.t[1]}`);
  if (state.d) parts.push('d=1');
  if (state.cols) parts.push(`cols=${state.cols.map((c) => encodeURIComponent(wellFormed(c))).join(',')}`);
  if (state.uid !== null) parts.push(`uid=${state.uid}`);
  if (state.desc) parts.push('desc=1');
  const path = `#/${state.route}`;
  return parts.length ? `${path}?${parts.join('&')}` : path;
}

export function decode(hash: string): ViewHash {
  const state: ViewHash = { ...EMPTY };
  const match = HASH.exec(hash);
  if (!match) return state;
  // A view this viewer does not have opens as the overview, with the link's filters kept.
  if ((ROUTES as readonly string[]).includes(match[1])) state.route = match[1] as Route;
  for (const part of (match[2] ?? '').split('&')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq);
    const raw = part.slice(eq + 1);
    try {
      if (key === 'q') {
        state.q = decodeURIComponent(raw);
      } else if (key === 't') {
        const bounds = raw.split('~');
        if (bounds.length === 2 && bounds.every((b) => INTEGER.test(b))) {
          const [start, end] = bounds.map(Number);
          if (Math.abs(start) <= TIME_LIMIT && Math.abs(end) <= TIME_LIMIT && start < end) state.t = [start, end];
        }
      } else if (key === 'd') {
        state.d = raw === '1';
      } else if (key === 'cols') {
        state.cols = raw === '' ? [] : raw.split(',').filter((c) => c !== '').map(decodeURIComponent);
      } else if (key === 'uid') {
        const uid = Number(raw);
        if (INTEGER.test(raw) && Number.isSafeInteger(uid) && uid >= 0) state.uid = uid;
      } else if (key === 'desc') {
        state.desc = raw === '1';
      }
    } catch {
      // A malformed part from a hand-edited link is ignored; the rest still applies.
    }
  }
  return state;
}

/** Back steps through what a person asked and the views they visited, not through every event they read. */
export function historyMode(previous: ViewHash, next: ViewHash): 'push' | 'replace' {
  if (previous.route !== next.route || previous.q !== next.q || previous.d !== next.d) return 'push';
  if (encode({ ...EMPTY, t: previous.t }) !== encode({ ...EMPTY, t: next.t })) return 'push';
  if ((previous.uid === null) !== (next.uid === null)) return 'push';
  return 'replace';
}
