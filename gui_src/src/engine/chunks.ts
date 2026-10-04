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

  add(name: string, sequence: number, text: string): void {
    let list = this.parts.get(name);
    if (list === undefined) {
      list = [];
      this.parts.set(name, list);
    }
    list[sequence] = decodeBase64(text);
  }

  /** The whole file, checked against the manifest; its chunks are released. */
  take(file: PackageFile, type = 'application/octet-stream'): Blob {
    const list = this.parts.get(file.name) ?? [];
    this.parts.delete(file.name);
    for (let i = 0; i < file.chunks.length; i++) {
      if (list[i] === undefined) throw new Error(`${file.name}: chunk ${i} of ${file.chunks.length} did not load`);
    }
    if (list.length !== file.chunks.length) throw new Error(`${file.name}: ${list.length} chunks loaded, ${file.chunks.length} listed`);
    const blob = new Blob(list, { type });
    if (blob.size !== file.bytes) throw new Error(`${file.name}: ${blob.size} bytes loaded, ${file.bytes} listed`);
    return blob;
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
    script.onerror = () => reject(new Error(`${source} could not be loaded; extract the whole archive before opening index.html`));
    document.head.appendChild(script);
  });
}

export async function loadScripts(sources: string[], loaded: () => void, concurrency = 6): Promise<void> {
  let next = 0;
  const worker = async (): Promise<void> => {
    while (next < sources.length) {
      const source = sources[next++];
      await loadScript(source);
      loaded();
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, sources.length) }, worker));
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
