import { decode, EMPTY, encode, type ViewHash } from './hash';

export class View {
  q = $state(EMPTY.q);
  t = $state<[number, number] | null>(EMPTY.t);
  d = $state(EMPTY.d);
  cols = $state<string[] | null>(EMPTY.cols);
  uid = $state<number | null>(EMPTY.uid);
  desc = $state(EMPTY.desc);

  snapshot(): ViewHash {
    return { q: this.q, t: this.t, d: this.d, cols: this.cols, uid: this.uid, desc: this.desc };
  }

  apply(next: ViewHash): void {
    // Assign only what changed: a fresh but equal array would re-run every query.
    if (next.q !== this.q) this.q = next.q;
    if (encode({ ...EMPTY, t: next.t }) !== encode({ ...EMPTY, t: this.t })) this.t = next.t;
    if (next.d !== this.d) this.d = next.d;
    if (encode({ ...EMPTY, cols: next.cols }) !== encode({ ...EMPTY, cols: this.cols })) this.cols = next.cols;
    if (next.uid !== this.uid) this.uid = next.uid;
    if (next.desc !== this.desc) this.desc = next.desc;
  }
}

export const view = new View();

/** Keep the view and the URL hash in step, so Back and bookmarks restore an investigation. */
export function bindHash(target: View): () => void {
  const fromHash = () => target.apply(decode(location.hash));
  fromHash();
  const initial = encode(target.snapshot());
  if (location.hash !== initial) location.replace(initial);
  window.addEventListener('hashchange', fromHash);
  const stop = $effect.root(() => {
    $effect(() => {
      const next = encode(target.snapshot());
      if (next !== location.hash) location.hash = next;
    });
  });
  return () => {
    window.removeEventListener('hashchange', fromHash);
    stop();
  };
}
