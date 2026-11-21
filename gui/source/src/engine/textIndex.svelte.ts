import type { Db } from './db';
import type { Manifest, PackageFile } from './manifest';
import { TEXT_FILE } from './textMatches';

export type TextIndexStatus = 'absent' | 'available' | 'loading' | 'ready' | 'failed';

/** loaded and total count the index file's scripts, for the page to say how far the load has got. */
export const textIndex = $state<{ status: TextIndexStatus; error: string | null; loaded: number; total: number }>({
  status: 'absent', error: null, loaded: 0, total: 0,
});

/** The package's full-text index file, when it has one. */
export function textIndexFile(manifest: Pick<Manifest, 'files'>): PackageFile | undefined {
  return manifest.files.find((entry) => entry.kind === 'index' && entry.name === TEXT_FILE);
}

/** Route bare-word queries onto the package index before the views mount, including a word in the URL. */
export function configureTextIndex(
  manifest: Pick<Manifest, 'files'>,
  db: Pick<Db, 'register' | 'useTextIndex'>,
  read: (file: PackageFile, loaded: () => void) => Promise<Uint8Array>,
): void {
  const file = textIndexFile(manifest);
  textIndex.error = null;
  textIndex.loaded = 0;
  textIndex.total = file?.chunks.length ?? 0;
  textIndex.status = file ? 'available' : 'absent';
  if (!file) return;

  const failed = (error: unknown) => {
    textIndex.status = 'failed';
    textIndex.error = error instanceof Error ? error.message : String(error);
  };
  const register = async () => {
    textIndex.status = 'loading';
    try {
      const bytes = await read(file, () => {
        textIndex.loaded += 1;
      });
      await db.register(file.name, bytes);
      textIndex.status = 'ready';
    } catch (error) {
      failed(error);
      throw error;
    }
  };
  // Stop releases the waiting query. A later search can reuse the same in-flight or registered file.
  let registration: Promise<void> | undefined;
  db.useTextIndex({ load: () => registration ??= register(), failed });
}
