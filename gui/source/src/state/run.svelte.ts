import type { Db } from '../engine/db';

/**
 * Whether the person stopped the page's queries. A stopped panel says so
 * instead of staying busy; Run again re-issues every query.
 */
export const run = $state({ stopped: false, generation: 0 });

export function stopAll(db: Pick<Db, 'cancel'>): void {
  run.stopped = true;
  db.cancel();
}

export function runAgain(): void {
  run.stopped = false;
  run.generation += 1;
}
