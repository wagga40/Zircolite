import { LEVELS } from '../engine/levels';
import type { Manifest } from '../engine/manifest';

const COUNT = new Intl.NumberFormat('en-US');

export function formatCount(n: number): string {
  return COUNT.format(n);
}

export function isoTime(ms: number | null | undefined, withMs = true): string {
  if (ms === null || ms === undefined || !Number.isFinite(ms)) return '';
  const iso = new Date(ms).toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, withMs ? 23 : 19)}`;
}

export function levelName(rank: number | null | undefined): string | null {
  if (rank === null || rank === undefined || rank < 0) return null;
  return LEVELS[rank] ?? null;
}

/** Inputs, not parts: one unified database is a single part holding many files. */
export function inputCount(manifest: Pick<Manifest, 'parts'>): number {
  return new Set(manifest.parts.flatMap((part) => part.sources)).size;
}
