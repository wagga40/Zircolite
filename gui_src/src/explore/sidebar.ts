import type { Field } from '../engine/schema';
import { asciiLower, ident, likeEscape, str } from '../engine/sql';

export function suggestValuesSql(field: Field, prefix: string, limit = 8): string {
  const text = `CAST(${ident(field.name)} AS VARCHAR)`;
  return `SELECT DISTINCT ${text} AS v FROM events WHERE ${text} ILIKE ${str(`${likeEscape(prefix)}%`)} ESCAPE '\\' ORDER BY v LIMIT ${limit}`;
}

/**
 * A field's most common values in the results, with how many results carry
 * the field at all. Values group ignoring case, as the search compares them,
 * so a value's count is exactly what filtering by it lists.
 */
export function topValuesSql(field: Field, where: string, limit = 10): string {
  const column = ident(field.name);
  return (
    `WITH f AS (SELECT CAST(${column} AS VARCHAR) AS v FROM events WHERE ${column} IS NOT NULL AND (${where})) ` +
    'SELECT min(v) AS v, count(*)::DOUBLE AS n, count(DISTINCT v)::DOUBLE AS spellings, (SELECT count(*) FROM f)::DOUBLE AS total ' +
    `FROM f GROUP BY lower(v) ORDER BY n DESC, min(v) LIMIT ${limit}`
  );
}

/** How a value reads in the list and in button labels, so the two never differ. */
export function valueLabel(value: string): string {
  return value === '' ? 'empty text' : value;
}

/** A share as a whole percent that never rounds a few events to 0% or most of them to 100%. */
export function percent(part: number, whole: number): string {
  if (whole <= 0 || part <= 0) return '0%';
  if (part >= whole) return '100%';
  const value = (part / whole) * 100;
  if (value < 1) return '<1%';
  if (value > 99) return '>99%';
  return `${Math.round(value)}%`;
}

export function filterFields(fields: Field[], text: string, shown: string[]): Field[] {
  const wanted = asciiLower(text.trim());
  const order = new Map(shown.map((name, i) => [asciiLower(name), i]));
  return fields
    .filter((field) => field.key.includes(wanted))
    .sort((a, b) => {
      const ai = order.get(a.key) ?? Infinity;
      const bi = order.get(b.key) ?? Infinity;
      if (ai !== bi) return ai - bi;
      return b.count - a.count || a.name.localeCompare(b.name, 'en');
    });
}
