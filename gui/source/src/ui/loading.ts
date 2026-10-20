import type { PackageFile } from '../engine/manifest';

/** What the page does before it can show the package, in order. */
export const BOOT_STEPS = [
  'Reading the package',
  'Loading the data',
  'Starting the query engine',
  'Loading Parquet support',
  'Opening the data',
  'Linking detections to their events',
  'Checking the package',
] as const;

export type BootStep = (typeof BOOT_STEPS)[number];

/**
 * The bytes each script brings, for the loading bar: a file is cut into
 * scripts of one size, so each carries an equal share of it. The full-text
 * index loads after the page is ready and counts for nothing here.
 */
export function chunkWeights(files: Pick<PackageFile, 'name' | 'kind' | 'bytes' | 'chunks'>[]): Map<string, number> {
  const weights = new Map<string, number>();
  for (const file of files) {
    if (file.kind === 'index') continue;
    for (const chunk of file.chunks) weights.set(chunk, file.bytes / file.chunks.length);
  }
  return weights;
}
