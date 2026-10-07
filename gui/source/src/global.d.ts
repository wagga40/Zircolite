import type { Manifest } from './engine/manifest';

declare global {
  interface Window {
    __zircolite: {
      manifest(manifest: Manifest): void;
      chunk(name: string, sequence: number, text: string): void;
    };
  }
}

export {};
