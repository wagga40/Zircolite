import type { Field, Schema } from '../engine/schema';
import { asciiLower } from '../engine/sql';

// Fields that tell Windows, Sysmon for Linux and auditd events apart at a glance.
const PREFERRED = ['Channel', 'EventID', 'Computer', 'Hostname', 'TargetUserName', 'SubjectUserName', 'User', 'Image', 'CommandLine', 'type', 'exe', 'comm'];
const DEFAULT_COUNT = 6;

export function defaultColumns(schema: Schema): string[] {
  const chosen = PREFERRED.map((name) => schema.find(name)).filter((field): field is Field => field !== undefined);
  const rest = [...schema.fields]
    .filter((field) => !chosen.includes(field))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name, 'en'));
  return [...chosen, ...rest].slice(0, DEFAULT_COUNT).map((field) => field.name);
}

/** The table's columns: the user's choice when there is one, minus names this package lacks. */
export function shownColumns(cols: string[] | null, schema: Schema): Field[] {
  const seen = new Set<string>();
  return (cols ?? defaultColumns(schema)).flatMap((name) => {
    const field = schema.find(name);
    if (!field || seen.has(field.key)) return [];
    seen.add(field.key);
    return [field];
  });
}

export function toggleColumn(names: string[], name: string): string[] {
  const key = asciiLower(name);
  return names.some((n) => asciiLower(n) === key) ? names.filter((n) => asciiLower(n) !== key) : [...names, name];
}

export function moveColumn(names: string[], name: string, delta: -1 | 1): string[] {
  const key = asciiLower(name);
  const from = names.findIndex((n) => asciiLower(n) === key);
  const to = from + delta;
  if (from < 0 || to < 0 || to >= names.length) return names;
  const next = [...names];
  [next[from], next[to]] = [next[to], next[from]];
  return next;
}

/** The list with a column dropped into a gap between columns: gap 0 is before the first, gap n after the last. */
export function placeColumn(names: string[], name: string, gap: number): string[] {
  const key = asciiLower(name);
  const from = names.findIndex((n) => asciiLower(n) === key);
  if (from < 0) return names;
  const rest = names.filter((_, i) => i !== from);
  const at = Math.min(rest.length, Math.max(0, gap > from ? gap - 1 : gap));
  return [...rest.slice(0, at), names[from], ...rest.slice(at)];
}
