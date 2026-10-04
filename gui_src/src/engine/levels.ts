/** Sigma levels in rank order; rules.parquet stores the index as level_rank. */
export const LEVELS = ['informational', 'low', 'medium', 'high', 'critical'] as const;
export type Level = (typeof LEVELS)[number];
