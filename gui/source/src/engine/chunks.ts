import type { PackageFile } from './manifest';

type Bytes = Uint8Array<ArrayBuffer>;

export function decodeBase64(text: string): Bytes {
  const native = (Uint8Array as unknown as { fromBase64?: (value: string) => Bytes }).fromBase64;
  if (native) return native(text);
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Chunks as the package's scripts deliver them, reassembled per file. */
export class ChunkStore {
  private readonly parts = new Map<string, Bytes[]>();
  // A chunk script's callback cannot throw to the loader, so a bad chunk is
  // remembered here and reported when its file is taken.
  private readonly broken = new Map<string, Error>();

  add(name: string, sequence: number, text: string): void {
    let list = this.parts.get(name);
    if (list === undefined) {
      list = [];
      this.parts.set(name, list);
    }
    try {
      list[sequence] = decodeBase64(text);
    } catch (error) {
      if (!this.broken.has(name)) {
        const reason = error instanceof Error ? error.message : String(error);
        this.broken.set(name, new Error(`${name}: chunk ${sequence} could not be decoded (${reason})`));
      }
    }
  }

  private takeParts(file: PackageFile): Bytes[] {
    const list = this.parts.get(file.name) ?? [];
    const problem = this.broken.get(file.name);
    this.parts.delete(file.name);
    this.broken.delete(file.name);
    if (problem !== undefined) throw problem;
    for (let i = 0; i < file.chunks.length; i++) {
      if (list[i] === undefined) throw new Error(`${file.name}: chunk ${i} of ${file.chunks.length} did not load`);
    }
    if (list.length !== file.chunks.length) throw new Error(`${file.name}: ${list.length} chunks loaded, ${file.chunks.length} listed`);
    const size = list.reduce((sum, bytes) => sum + bytes.length, 0);
    if (size !== file.bytes) throw new Error(`${file.name}: ${size} bytes loaded, ${file.bytes} listed`);
    return list;
  }

  /** Engine assets need a Blob for decompression, data URLs or worker scripts. */
  take(file: PackageFile, type = 'application/octet-stream'): Blob {
    return new Blob(this.takeParts(file), { type });
  }

  /** DuckDB takes ownership of a contiguous buffer. Avoid a Blob copy and a subsequent arrayBuffer copy. */
  takeBytes(file: PackageFile): Bytes {
    const parts = this.takeParts(file);
    if (parts.length === 1) return parts[0];
    const bytes = new Uint8Array(file.bytes);
    let offset = 0;
    for (const part of parts) {
      bytes.set(part, offset);
      offset += part.length;
    }
    return bytes;
  }

  async readBytes(file: PackageFile, loaded: (source: string) => void): Promise<Bytes> {
    try {
      await loadScripts(file.chunks, loaded);
      return this.takeBytes(file);
    } catch (error) {
      this.parts.delete(file.name);
      this.broken.delete(file.name);
      throw error;
    }
  }
}

export function loadScript(source: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = source;
    script.onload = () => {
      script.remove();
      resolve();
    };
    script.onerror = () => {
      script.remove();
      reject(new Error(`${source} could not be loaded; extract the whole archive before opening index.html`));
    };
    document.head.appendChild(script);
  });
}

export async function loadScripts(sources: string[], loaded: (source: string) => void, concurrency = 6): Promise<void> {
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < sources.length) {
      const source = sources[next++];
      try {
        await loadScript(source);
        loaded(source);
      } catch (error) {
        next = sources.length;
        throw error;
      }
    }
  };
  // Let scripts already in flight finish before the caller releases this file's decoded chunks.
  const results = await Promise.allSettled(Array.from({ length: Math.min(concurrency, sources.length) }, worker));
  for (const result of results) if (result.status === 'rejected') throw result.reason;
}

export async function gunzip(blob: Blob, type: string): Promise<Blob> {
  const stream = blob.stream().pipeThrough(new DecompressionStream('gzip'));
  return new Blob([await new Response(stream).arrayBuffer()], { type });
}

export function blobToDataUrl(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result as string);
    reader.onerror = () => reject(reader.error ?? new Error('the engine could not be read'));
    reader.readAsDataURL(blob);
  });
}
