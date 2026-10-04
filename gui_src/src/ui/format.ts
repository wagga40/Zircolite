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

/** Part time stats are microseconds; the text is UTC. */
export function timeRange(parts: { time: { min: number | null; max: number | null } }[]): string {
  const starts = parts.map((p) => p.time.min).filter((v): v is number => v !== null);
  const ends = parts.map((p) => p.time.max).filter((v): v is number => v !== null);
  if (!starts.length || !ends.length) return 'No event has a time';
  return `${isoTime(Math.min(...starts) / 1000, false)} to ${isoTime(Math.max(...ends) / 1000, false)} UTC`;
}

/** Inputs, not parts: one unified database is a single part holding many files. */
export function inputCount(manifest: { parts: Pick<Manifest['parts'][number], 'sources'>[] }): number {
  return new Set(manifest.parts.flatMap((part) => part.sources)).size;
}
