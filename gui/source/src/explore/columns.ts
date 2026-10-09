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
