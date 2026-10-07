import { describe, expect, it } from 'vitest';
import type { TextSource } from '../src/engine/textMatches';
import { loadTextIndex, textIndex, textIndexFile } from '../src/engine/textIndex.svelte';

const FILE = { name: 'text.parquet', kind: 'index' as const, bytes: 3, sha256: 'x', chunks: ['data/text.parquet.0000.js'] };

function fakes() {
  const loaded: string[][] = [];
  const registered: string[] = [];
  const sources: TextSource[] = [];
  return {
    loaded, registered, sources,
    store: { take: () => new Blob([new Uint8Array([1, 2, 3])]) },
    db: {
      async register(name: string) { registered.push(name); },
      useTextIndex(source: TextSource) { sources.push(source); },
    },
    load: async (sources: string[]) => { loaded.push(sources); },
  };
}

describe('loadTextIndex', () => {
  it('says so when the package has no index', async () => {
    const f = fakes();
    await loadTextIndex({ files: [] }, f.store as never, f.db, f.load);
    expect(textIndex.status).toBe('absent');
    expect(f.loaded).toEqual([]);
    expect(f.sources).toEqual([]);
    expect(textIndexFile({ files: [] })).toBeUndefined();
  });

  it('is loading, and has told the queries, before its first await', () => {
    const f = fakes();
    const done = loadTextIndex({ files: [FILE] }, f.store as never, f.db, () => new Promise(() => {}));
    expect(textIndex.status).toBe('loading');
    expect(f.sources).toHaveLength(1);
    void done;
  });

  it('loads the chunks, registers the file and lets the waiting queries go', async () => {
    const f = fakes();
    await loadTextIndex({ files: [FILE] }, f.store as never, f.db, f.load);
    expect(f.loaded).toEqual([FILE.chunks]);
    expect(f.registered).toEqual(['text.parquet']);
    expect(textIndex.status).toBe('ready');
    await expect(f.sources[0].registered).resolves.toBeUndefined();
  });

  it('reports a failed load, and the waiting queries get its reason', async () => {
    const f = fakes();
    await loadTextIndex({ files: [FILE] }, f.store as never, f.db, async () => {
      throw new Error('data/text.parquet.0000.js could not be loaded');
    });
    expect(textIndex.status).toBe('failed');
    expect(textIndex.error).toContain('could not be loaded');
    await expect(f.sources[0].registered).rejects.toThrow('could not be loaded');
  });

  it('fails the index when the engine cannot open the registered file', async () => {
    const f = fakes();
    await loadTextIndex({ files: [FILE] }, f.store as never, f.db, f.load);
    f.sources[0].failed(new Error('No magic bytes found at end of file'));
    expect(textIndex.status).toBe('failed');
    expect(textIndex.error).toBe('No magic bytes found at end of file');
  });
});
