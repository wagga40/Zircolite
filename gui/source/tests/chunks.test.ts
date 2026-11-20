import { describe, expect, it } from 'vitest';
import { ChunkStore, decodeBase64, gunzip } from '../src/engine/chunks';
import type { PackageFile } from '../src/engine/manifest';

const file = (name: string, chunks: number, bytes: number): PackageFile =>
  ({ name, kind: 'data', bytes, sha256: '', chunks: Array.from({ length: chunks }, (_, i) => `data/${name}.${i}.js`) });

describe('decodeBase64', () => {
  it('decodes with and without the native decoder', () => {
    expect(Array.from(decodeBase64('AP8='))).toEqual([0, 255]);
    const native = (Uint8Array as unknown as { fromBase64?: unknown }).fromBase64;
    (Uint8Array as unknown as { fromBase64?: unknown }).fromBase64 = undefined;
    try {
      expect(Array.from(decodeBase64('AP8='))).toEqual([0, 255]);
    } finally {
      (Uint8Array as unknown as { fromBase64?: unknown }).fromBase64 = native;
    }
  });
});

describe('ChunkStore', () => {
  it('reassembles chunks that arrive out of order', async () => {
    const store = new ChunkStore();
    store.add('a', 1, btoa('def'));
    store.add('a', 0, btoa('abc'));
    expect(await store.take(file('a', 2, 6)).text()).toBe('abcdef');
  });

  it('hands the engine contiguous bytes in sequence and releases the decoded chunks', () => {
    for (const parts of [[], ['abc'], ['abc', 'd', 'ef']]) {
      const store = new ChunkStore();
      const f = file('a', parts.length, parts.join('').length);
      for (let i = parts.length - 1; i >= 0; i--) store.add('a', i, btoa(parts[i]));
      expect(new TextDecoder().decode(store.takeBytes(f))).toBe(parts.join(''));
      if (parts.length) expect(() => store.takeBytes(f)).toThrow(/did not load/);
    }
  });

  it('reports a chunk that is not base64 as the cause', () => {
    const store = new ChunkStore();
    store.add('a', 0, '***not base64***');
    expect(() => store.take(file('a', 1, 3))).toThrow(/a: chunk 0 could not be decoded/);
  });

  it('refuses a file with a chunk missing', () => {
    const store = new ChunkStore();
    store.add('a', 1, btoa('def'));
    expect(() => store.take(file('a', 2, 6))).toThrow(/chunk 0 of 2/);
  });

  it('refuses a file of the wrong size', () => {
    const store = new ChunkStore();
    store.add('a', 0, btoa('abc'));
    expect(() => store.take(file('a', 1, 4))).toThrow(/3 bytes loaded, 4 listed/);
  });
});

describe('gunzip', () => {
  it('restores gzip data', async () => {
    const packed = await new Response(new Blob(['hello']).stream().pipeThrough(new CompressionStream('gzip'))).blob();
    expect(await (await gunzip(packed, 'text/plain')).text()).toBe('hello');
  });
});
