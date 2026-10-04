import type { Field } from '../engine/schema';
import { ident, likeEscape, str } from '../engine/sql';

export function suggestValuesSql(field: Field, prefix: string, limit = 8): string {
  const text = `CAST(${ident(field.name)} AS VARCHAR)`;
  return `SELECT DISTINCT ${text} AS v FROM events WHERE ${text} ILIKE ${str(`${likeEscape(prefix)}%`)} ESCAPE '\\' ORDER BY v LIMIT ${limit}`;
}
