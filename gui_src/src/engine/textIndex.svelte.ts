import { type ChunkStore, loadScripts } from './chunks';
import type { Db } from './db';
import type { Manifest } from './manifest';
import { isSuperseded } from './queries';
import { str } from './sql';
import { TEXT_FILE } from './textMatches';

export type TextIndexStatus = 'absent' | 'loading' | 'ready' | 'failed';

export const textIndex = $state<{ status: TextIndexStatus; error: string | null }>({ status: 'absent', error: null });

const LANE = 'text-index';

/**
 * Load the full-text index once the page is ready. Until it is, a bare-word
 * search scans every column, slowly but correctly; once it is, the search
 * recompiles onto it.
 */
export async function loadTextIndex(
  manifest: Pick<Manifest, 'files'>,
  store: Pick<ChunkStore, 'take'>,
  db: Pick<Db, 'register' | 'exec'>,
  load: (sources: string[], loaded: () => void) => Promise<void> = loadScripts,
): Promise<void> {
  const file = manifest.files.find((entry) => entry.kind === 'index' && entry.name === TEXT_FILE);
  textIndex.error = null;
  if (!file) {
    textIndex.status = 'absent';
    return;
  }
  textIndex.status = 'loading';
  try {
    await load(file.chunks, () => undefined);
    await db.register(file.name, new Uint8Array(await store.take(file).arrayBuffer()));
    const view = `CREATE OR REPLACE VIEW fulltext AS SELECT * FROM read_parquet(${str(file.name)})`;
    for (;;) {
      try {
        await db.exec(view, { lane: LANE });
        break;
      } catch (error) {
        // Stop cancels every lane; opening a view is instant, and each Stop cancels only what is in flight
        // then, so trying again beats leaving the index unused.
        if (!isSuperseded(error)) throw error;
      }
    }
    textIndex.status = 'ready';
  } catch (error) {
    textIndex.status = 'failed';
    textIndex.error = error instanceof Error ? error.message : String(error);
  }
}
