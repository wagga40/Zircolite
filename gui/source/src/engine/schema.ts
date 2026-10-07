import type { Manifest } from './manifest';
import { asciiLower } from './sql';

export type FieldType = 'BIGINT' | 'DOUBLE' | 'VARCHAR';

export interface Field {
  name: string;
  key: string;
  type: FieldType;
  count: number;
}

export class Schema {
  readonly fields: Field[];
  /** ATT&CK tactic short names as the rules table stores them, in ATT&CK's order. */
  readonly tactics: string[];
  private readonly byKey: Map<string, Field>;

  constructor(fields: Field[], tactics: string[] = []) {
    this.fields = fields;
    this.tactics = tactics;
    this.byKey = new Map(fields.map((field) => [field.key, field]));
  }

  static fromManifest(manifest: Manifest): Schema {
    return new Schema(manifest.columns.map((c) => ({ name: c.name, key: c.key, type: c.type, count: c.count })), manifest.tactics);
  }

  find(name: string): Field | undefined {
    return this.byKey.get(asciiLower(name));
  }

  /** The field names nearest a mistyped one, for the error message. */
  suggest(name: string, limit = 3): string[] {
    const wanted = asciiLower(name);
    const ceiling = Math.max(2, Math.floor(wanted.length / 2));
    return this.fields
      .map((field) => ({ name: field.name, score: distance(wanted, field.key) - (field.key.startsWith(wanted) ? 2 : 0) }))
      .filter((candidate) => candidate.score <= ceiling)
      .sort((a, b) => a.score - b.score || a.name.localeCompare(b.name))
      .slice(0, limit)
      .map((candidate) => candidate.name);
  }
}

function distance(a: string, b: string): number {
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const current = [i];
    for (let j = 1; j <= b.length; j++) {
      current[j] = Math.min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    previous = current;
  }
  return previous[b.length];
}
