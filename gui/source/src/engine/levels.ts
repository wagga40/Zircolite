/** Sigma levels in rank order; rules.parquet stores the index as level_rank. */
export const LEVELS = ['informational', 'low', 'medium', 'high', 'critical'] as const;
export type Level = (typeof LEVELS)[number];

/**
 * The custom property holding a level's ink. A rule without a Sigma level is
 * stored at rank -1; it has its own ink rather than borrowing informational's,
 * and an undefined property would paint nothing at all.
 */
export function levelVar(rank: number | null | undefined): string {
  return rank !== null && rank !== undefined && Number.isInteger(rank) && rank >= 0 && rank < LEVELS.length ? `--sev-${rank}` : '--sev-unknown';
}

export function levelInk(rank: number | null | undefined): string {
  return `var(${levelVar(rank)})`;
}
