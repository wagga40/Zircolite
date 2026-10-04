export interface ViewHash {
  q: string;
  /** Epoch milliseconds, start inclusive, end exclusive. */
  t: [number, number] | null;
  d: boolean;
  /** null means the default columns; [] means the user removed them all. */
  cols: string[] | null;
  uid: number | null;
  desc: boolean;
}

export const EMPTY: ViewHash = { q: '', t: null, d: false, cols: null, uid: null, desc: false };

const PREFIX = '#/explore';

export function encode(state: ViewHash): string {
  const parts: string[] = [];
  if (state.q) parts.push(`q=${encodeURIComponent(state.q)}`);
  if (state.t) parts.push(`t=${state.t[0]}~${state.t[1]}`);
  if (state.d) parts.push('d=1');
  if (state.cols) parts.push(`cols=${state.cols.map(encodeURIComponent).join(',')}`);
  if (state.uid !== null) parts.push(`uid=${state.uid}`);
  if (state.desc) parts.push('desc=1');
  return parts.length ? `${PREFIX}?${parts.join('&')}` : PREFIX;
}

export function decode(hash: string): ViewHash {
  const state: ViewHash = { ...EMPTY };
  const query = hash.startsWith(PREFIX) ? hash.slice(PREFIX.length).replace(/^\?/, '') : '';
  for (const part of query.split('&')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const key = part.slice(0, eq);
    const raw = part.slice(eq + 1);
    try {
      if (key === 'q') {
        state.q = decodeURIComponent(raw);
      } else if (key === 't') {
        const [start, end] = raw.split('~').map(Number);
        if (Number.isSafeInteger(start) && Number.isSafeInteger(end) && start < end) state.t = [start, end];
      } else if (key === 'd') {
        state.d = raw === '1';
      } else if (key === 'cols') {
        state.cols = raw === '' ? [] : raw.split(',').map(decodeURIComponent);
      } else if (key === 'uid') {
        const uid = Number(raw);
        if (Number.isSafeInteger(uid) && uid >= 0 && raw !== '') state.uid = uid;
      } else if (key === 'desc') {
        state.desc = raw === '1';
      }
    } catch {
      // A malformed part from a hand-edited link is ignored; the rest still applies.
    }
  }
  return state;
}
