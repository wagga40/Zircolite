// The only place SQL text is assembled from values. Everything that reaches a
// query from the logs or from the user passes through one of these.

/** Fold a name the way SQLite and DuckDB compare column names: ASCII letters only. */
export function asciiLower(name: string): string {
  return name.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

/** A SQL identifier. */
export function ident(name: string): string {
  return `"${name.replaceAll('"', '""')}"`;
}

/** A SQL string literal. DuckDB reads backslashes literally, so only quotes double. */
export function str(text: string): string {
  return `'${text.replaceAll("'", "''")}'`;
}

/** Make LIKE metacharacters match themselves; pair the pattern with ESCAPE '\'. */
export function likeEscape(text: string): string {
  return text.replace(/[\\%_]/g, (c) => `\\${c}`);
}

/**
 * The ESCAPE clause a LIKE needs, or nothing. DuckDB has no default escape
 * character, so a pattern without a backslash means the same either way, and
 * leaving the clause off keeps DuckDB on its fast contains() path; with it
 * every row goes through the general matcher.
 */
export function escapeClause(literal: string): string {
  return literal.includes('\\') ? " ESCAPE '\\'" : '';
}

/** Each event's highest detection level, read by the strip, the table and the drawer. */
export const EVENT_LEVELS_SQL =
  'CREATE OR REPLACE TEMP TABLE event_levels AS SELECT h._zl_uid, max(r.level_rank) AS _zl_lvl ' +
  'FROM hits h JOIN rules r ON r.rule_idx = h.rule_idx GROUP BY h._zl_uid';
