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
