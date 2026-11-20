import { describe, expect, it } from 'vitest';
import type { PackageFile } from '../src/engine/manifest';
import type { TextSource } from '../src/engine/textMatches';
import { configureTextIndex, textIndex, textIndexFile } from '../src/engine/textIndex.svelte';

const FILE = { name: 'text.parquet', kind: 'index' as const, bytes: 3, sha256: 'x', chunks: ['data/text.parquet.0000.js'] };

function fakes() {
  const loaded: string[][] = [];
  const registered: string[] = [];
  const sources: TextSource[] = [];
  return {
    loaded, registered, sources,
    db: {
      async register(name: string) { registered.push(name); },
      useTextIndex(source: TextSource) { sources.push(source); },
    },
    read: async (file: PackageFile) => {
      loaded.push(file.chunks);
      return new Uint8Array([1, 2, 3]);
    },
  };
}

describe('configureTextIndex', () => {
  it('says so when the package has no index', () => {
    const f = fakes();
    configureTextIndex({ files: [] }, f.db, f.read);
    expect(textIndex.status).toBe('absent');
    expect(f.loaded).toEqual([]);
    expect(f.sources).toEqual([]);
    expect(textIndexFile({ files: [] })).toBeUndefined();
  });

  it('offers the index to the scheduler without reading any chunks', () => {
    const f = fakes();
    configureTextIndex({ files: [FILE] }, f.db, f.read);
    expect(textIndex.status).toBe('available');
    expect(f.sources).toHaveLength(1);
    expect(f.loaded).toEqual([]);
  });

  it('loads the chunks, registers the file and lets the waiting queries go', async () => {
    const f = fakes();
    configureTextIndex({ files: [FILE] }, f.db, f.read);
    await Promise.all([f.sources[0].load(), f.sources[0].load()]);
    expect(f.loaded).toEqual([FILE.chunks]);
    expect(f.registered).toEqual(['text.parquet']);
    expect(textIndex.status).toBe('ready');
  });

  it('reports a failed load, and the waiting queries get its reason', async () => {
    const f = fakes();
    configureTextIndex({ files: [FILE] }, f.db, async () => {
      throw new Error('data/text.parquet.0000.js could not be loaded');
    });
    await expect(f.sources[0].load()).rejects.toThrow('could not be loaded');
    expect(textIndex.status).toBe('failed');
    expect(textIndex.error).toContain('could not be loaded');
  });

  it('fails the index when the engine cannot open the registered file', async () => {
    const f = fakes();
    configureTextIndex({ files: [FILE] }, f.db, f.read);
    await f.sources[0].load();
    f.sources[0].failed(new Error('No magic bytes found at end of file'));
    expect(textIndex.status).toBe('failed');
    expect(textIndex.error).toBe('No magic bytes found at end of file');
  });
});
