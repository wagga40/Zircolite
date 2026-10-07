import type { Manifest } from './manifest';
import type { Field } from './schema';
import { asciiLower } from './sql';

/**
 * How one event spells its fields: its own recorded spelling, else its part's,
 * else the package's. Together they reproduce the names detected_events.json
 * prints for the same event.
 */
export function nameResolver(manifest: Pick<Manifest, 'parts'>, part: number | null, spelling: string | null): (field: Field) => string {
  const partSpellings = manifest.parts.find((p) => p.part === part)?.spellings ?? {};
  const own = new Map<string, string>();
  if (spelling) {
    // Stage 1 wrote this record and checked it; a bad one means a damaged package, which must not pass unnoticed.
    const names: unknown = JSON.parse(spelling);
    if (!Array.isArray(names)) throw new Error(`an event's spelling record is not a list: ${spelling}`);
    for (const name of names) if (typeof name === 'string') own.set(asciiLower(name), name);
  }
  return (field) => own.get(field.key) ?? partSpellings[field.key] ?? field.name;
}
