import { onDestroy } from 'svelte';
import type { Db, ScopedDb } from '../engine/db';

/**
 * A Db for the component being created, its lanes under `name`. When the
 * component goes, so do its queries, queued or running, and the view that
 * replaces it does not wait behind them.
 */
export function ownScope(db: Db, name: string): ScopedDb {
  const scope = db.scope(name);
  onDestroy(() => scope.dispose());
  return scope;
}
