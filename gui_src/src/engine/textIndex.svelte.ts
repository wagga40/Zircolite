import { type ChunkStore, loadScripts } from './chunks';
import type { Db } from './db';
import type { Manifest, PackageFile } from './manifest';
import { TEXT_FILE } from './textMatches';

export type TextIndexStatus = 'absent' | 'loading' | 'ready' | 'failed';

export const textIndex = $state<{ status: TextIndexStatus; error: string | null }>({ status: 'absent', error: null });

/** The package's full-text index file, when it has one. */
export function textIndexFile(manifest: Pick<Manifest, 'files'>): PackageFile | undefined {
  return manifest.files.find((entry) => entry.kind === 'index' && entry.name === TEXT_FILE);
}

/**
 * Load the full-text index once the page is ready. A bare word compiles onto
 * the index from the start, and its queries wait for the file; if it cannot
 * be loaded, the search falls back to scanning every column.
 */
export async function loadTextIndex(
  manifest: Pick<Manifest, 'files'>,
  store: Pick<ChunkStore, 'take'>,
  db: Pick<Db, 'register' | 'useTextIndex'>,
  load: (sources: string[], loaded: () => void) => Promise<void> = loadScripts,
): Promise<void> {
  const file = textIndexFile(manifest);
  textIndex.error = null;
  if (!file) {
    textIndex.status = 'absent';
    return;
  }
  const fail = (error: unknown) => {
    textIndex.status = 'failed';
    textIndex.error = error instanceof Error ? error.message : String(error);
  };
  let settle: { resolve(): void; reject(error: unknown): void } = { resolve() {}, reject() {} };
  const registered = new Promise<void>((resolve, reject) => {
    settle = { resolve, reject };
  });
  // With no query waiting, a failed load is told by the status alone.
  registered.catch(() => undefined);
  // Set before the first await, so the views compile onto the index from their first query.
  textIndex.status = 'loading';
  db.useTextIndex({ registered, failed: fail });
  try {
    await load(file.chunks, () => undefined);
    await db.register(file.name, new Uint8Array(await store.take(file).arrayBuffer()));
    textIndex.status = 'ready';
    settle.resolve();
  } catch (error) {
    // The status changes first, so the views recompile onto the scan and supersede what was waiting.
    fail(error);
    settle.reject(error);
  }
}
