import type { Activity } from '../engine/queries';

/** The page says it is busy only past this, so a quick answer does not flash the bar. */
export const SHOW_AFTER = 300;
/** It stays busy through gaps this short: an answer often leads straight to the next query. */
export const HIDE_AFTER = 200;

/** Whether the page has been working long enough to say so, and since when. */
export class BusyClock {
  shown = $state(false);
  since = $state<number | null>(null);
  #show: ReturnType<typeof setTimeout> | null = null;
  #hide: ReturnType<typeof setTimeout> | null = null;

  set(busy: boolean): void {
    if (busy) {
      this.#clearHide();
      if (this.since === null) this.since = Date.now();
      if (!this.shown && this.#show === null) {
        const wait = Math.max(0, SHOW_AFTER - (Date.now() - this.since));
        this.#show = setTimeout(() => {
          this.#show = null;
          // Idle when the delay ran out: the spell may yet end within the gap, unseen.
          if (this.#hide === null) this.shown = true;
        }, wait);
      }
    } else if (this.since !== null && this.#hide === null) {
      this.#hide = setTimeout(() => {
        this.#hide = null;
        this.#clearShow();
        this.shown = false;
        this.since = null;
      }, HIDE_AFTER);
    }
  }

  dispose(): void {
    this.#clearShow();
    this.#clearHide();
  }

  #clearShow(): void {
    if (this.#show !== null) clearTimeout(this.#show);
    this.#show = null;
  }

  #clearHide(): void {
    if (this.#hide !== null) clearTimeout(this.#hide);
    this.#hide = null;
  }
}

/** What the bar says the page is doing, and how far it has got when it can tell. */
export function activityText(activity: Activity, index: { loaded: number; total: number }): { label: string; fraction: number | null } {
  if (activity.waiting) return { label: 'Loading the full-text index', fraction: index.total > 0 ? index.loaded / index.total : null };
  // A scan in one part cannot say how far it got until it ends.
  if (activity.scan) return { label: activity.scan.label, fraction: activity.scan.total > 1 ? activity.scan.done / activity.scan.total : null };
  return { label: 'Working', fraction: null };
}

/** What the page's queries are doing, as the scheduler last told. */
export const activity = $state<Activity>({ queries: 0, scan: null, waiting: false });
