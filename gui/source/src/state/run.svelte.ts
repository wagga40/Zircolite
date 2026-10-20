import { untrack } from 'svelte';
import type { Db } from '../engine/db';

/**
 * Whether the person stopped the page's queries. A stopped panel says so
 * instead of staying busy; Run again re-issues every query.
 */
export const run = $state({ stopped: false, generation: 0, ownStops: 0 });

/**
 * A view shows a Stop of its own beside what it runs, and the page's Stop stands aside meanwhile: two
 * buttons doing one thing would read as two. Returns the release, which an effect can return as its cleanup.
 */
export function holdStop(): () => void {
  // Untracked: an effect that holds a Stop must not depend on the count it changes.
  untrack(() => (run.ownStops += 1));
  let held = true;
  return () => {
    if (!held) return;
    held = false;
    untrack(() => (run.ownStops -= 1));
  };
}

export function stopAll(db: Pick<Db, 'cancel'>): void {
  run.stopped = true;
  db.cancel();
}

export function runAgain(): void {
  run.stopped = false;
  run.generation += 1;
}
