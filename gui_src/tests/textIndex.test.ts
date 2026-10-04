import { describe, expect, it } from 'vitest';
import { Superseded } from '../src/engine/queries';
import { loadTextIndex, textIndex } from '../src/engine/textIndex.svelte';

const FILE = { name: 'text.parquet', kind: 'index' as const, bytes: 3, sha256: 'x', chunks: ['data/text.parquet.0000.js'] };

function fakes() {
  const loaded: string[][] = [];
  const statements: string[] = [];
  const registered: string[] = [];
  return {
    loaded, statements, registered,
    store: { take: () => new Blob([new Uint8Array([1, 2, 3])]) },
    db: {
      async register(name: string) { registered.push(name); },
      async exec(sql: string) { statements.push(sql); },
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
  });

  it('loads the chunks, registers the file and opens a view on it', async () => {
    const f = fakes();
    await loadTextIndex({ files: [FILE] }, f.store as never, f.db, f.load);
    expect(f.loaded).toEqual([FILE.chunks]);
    expect(f.registered).toEqual(['text.parquet']);
    expect(f.statements).toEqual(["CREATE OR REPLACE VIEW fulltext AS SELECT * FROM read_parquet('text.parquet')"]);
    expect(textIndex.status).toBe('ready');
  });

  it('reports a failure and leaves search on the scan', async () => {
    const f = fakes();
    await loadTextIndex({ files: [FILE] }, f.store as never, f.db, async () => {
      throw new Error('data/text.parquet.0000.js could not be loaded');
    });
    expect(textIndex.status).toBe('failed');
    expect(textIndex.error).toContain('could not be loaded');
  });

  it('opens the view again when a Stop cancelled it, instead of failing', async () => {
    const f = fakes();
    let calls = 0;
    const db = {
      register: f.db.register,
      async exec(sql: string) {
        calls += 1;
        if (calls === 1) throw new Superseded();
        f.statements.push(sql);
      },
    };
    await loadTextIndex({ files: [FILE] }, f.store as never, db, f.load);
    expect(textIndex.status).toBe('ready');
    expect(f.statements).toHaveLength(1);
  });
});
