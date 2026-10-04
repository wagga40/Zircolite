import { LEVELS } from '../engine/levels';
import type { Field, Schema } from '../engine/schema';
import { ident, likeEscape, str } from '../engine/sql';
import type { Node } from './parse';
import { findShortcut, SHORTCUTS } from './shortcuts';
import { SearchError } from './tokens';

type Term = Extract<Node, { kind: 'term' }>;

const NUMBER = /^-?\d+(\.\d+)?$/;
const HIT_RULES = 'SELECT h._zl_uid FROM hits h JOIN rules r ON r.rule_idx = h.rule_idx';
// Zircolite stores tactics hyphenated, and maps the retired Defense Evasion to Stealth.
const TACTIC_ALIASES: Record<string, string> = { 'defense-evasion': 'stealth' };

export interface CompileOptions {
  textIndex?: boolean;
}

export function compile(tree: Node | null, schema: Schema, options: CompileOptions = {}): string {
  return tree === null ? 'TRUE' : node(tree, schema, options);
}

function node(n: Node, schema: Schema, options: CompileOptions): string {
  switch (n.kind) {
    case 'and':
      return `(${n.items.map((item) => node(item, schema, options)).join(' AND ')})`;
    case 'or':
      return `(${n.items.map((item) => node(item, schema, options)).join(' OR ')})`;
    case 'not':
      // A missing field compares as NULL, and NOT NULL would drop the very
      // events a negation is meant to keep.
      return `NOT coalesce(${node(n.item, schema, options)}, FALSE)`;
    case 'term':
      return term(n, schema, options);
  }
}

function term(t: Term, schema: Schema, options: CompileOptions): string {
  if (t.field === null) return fullText(t, schema, options);
  const shortcut = t.fieldQuoted ? undefined : findShortcut(t.field);
  if (shortcut) return SHORTCUT_COMPILERS[shortcut.name](t, schema);
  const field = schema.find(t.field);
  if (!field) {
    const near = schema.suggest(t.field);
    throw new SearchError(`No field named ${t.field}${near.length ? `; did you mean ${near.join(', ')}?` : ''}`, t.start, t.end);
  }
  return fieldMatch(field, t);
}

function exactOnly(t: Term): void {
  if (t.op !== '=') throw new SearchError(`${t.field}: matches exactly; only level compares with ${t.op}`, t.start, t.end);
}

function pattern(t: Term, contains: boolean): string {
  const escaped = likeEscape(t.value);
  const body = t.quoted ? escaped : escaped.replaceAll('*', '%');
  return str(contains ? `%${body}%` : body);
}

function fieldMatch(field: Field, t: Term): string {
  const column = ident(field.name);
  const numeric = field.type !== 'VARCHAR';
  if (t.op !== '=') {
    if (!numeric) throw new SearchError(`${t.op} compares numbers, and ${field.name} holds text`, t.start, t.end);
    if (!NUMBER.test(t.value)) throw new SearchError(`${t.op} compares numbers; ${field.name} needs a number, not "${t.value}"`, t.start, t.end);
    return `${column} ${t.op} ${t.value}`;
  }
  if (numeric && NUMBER.test(t.value)) return `${column} = ${t.value}`;
  const text = numeric ? `CAST(${column} AS VARCHAR)` : column;
  return `${text} ILIKE ${pattern(t, false)} ESCAPE '\\'`;
}

function fullText(t: Term, schema: Schema, options: CompileOptions): string {
  if (schema.fields.length === 0) return 'FALSE';
  if (options.textIndex) {
    // The index holds each event's values lowercased and joined by chr(31), as the scan below joins them,
    // so a pattern matches there exactly when it matches here.
    return `_zl_uid IN (SELECT _zl_uid FROM fulltext WHERE _zl_text LIKE lower(${pattern(t, true)}) ESCAPE '\\')`;
  }
  // chr(31) separates the fields, so a quoted phrase cannot match across two of them; an unquoted * still can.
  const all = schema.fields.map((field) => ident(field.name)).join(', ');
  return `concat_ws(chr(31), ${all}) ILIKE ${pattern(t, true)} ESCAPE '\\'`;
}

/**
 * The tactics a term names, from the package's list. A name the rules never
 * carry would match nothing without a word of why, so it is refused instead.
 */
function tacticNames(t: Term, tactics: readonly string[]): string[] {
  if (tactics.length === 0) throw new SearchError('This package lists no ATT&CK tactics', t.start, t.end);
  const known = `tactics are: ${tactics.join(', ')}`;
  const wanted = t.value.trim().toLowerCase().replace(/[\s_]+/g, '-');
  if (!t.quoted && wanted.includes('*')) {
    const pattern = new RegExp(`^${wanted.split('*').map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*')}$`);
    const found = tactics.filter((tactic) => pattern.test(tactic));
    if (found.length === 0) throw new SearchError(`No tactic matches ${t.value}; ${known}`, t.start, t.end);
    return found;
  }
  const name = TACTIC_ALIASES[wanted] ?? wanted;
  if (!tactics.includes(name)) throw new SearchError(`No tactic named ${t.value}; ${known}`, t.start, t.end);
  return [name];
}

function anyField(names: readonly string[], label: string) {
  return (t: Term, schema: Schema): string => {
    const found = new Map<string, Field>();
    for (const name of names) {
      const field = schema.find(name);
      if (field) found.set(field.key, field);
    }
    if (found.size === 0) throw new SearchError(`This package has no ${label} field (looked for ${names.join(', ')})`, t.start, t.end);
    return `(${[...found.values()].map((field) => fieldMatch(field, t)).join(' OR ')})`;
  };
}

const SHORTCUT_COMPILERS: Record<string, (t: Term, schema: Schema) => string> = {
  rule: (t) => {
    exactOnly(t);
    const p = pattern(t, false);
    return `_zl_uid IN (${HIT_RULES} WHERE r.title ILIKE ${p} ESCAPE '\\' OR r.id ILIKE ${p} ESCAPE '\\')`;
  },
  rulekey: (t) => {
    exactOnly(t);
    return `_zl_uid IN (${HIT_RULES} WHERE r.key = ${str(t.value)})`;
  },
  level: (t) => {
    const rank = LEVELS.indexOf(t.value.toLowerCase() as (typeof LEVELS)[number]);
    if (rank < 0) throw new SearchError(`level is one of ${LEVELS.join(', ')}`, t.start, t.end);
    return `_zl_uid IN (SELECT _zl_uid FROM event_levels WHERE _zl_lvl ${t.op} ${rank})`;
  },
  tactic: (t, schema) => {
    exactOnly(t);
    const names = tacticNames(t, schema.tactics);
    const test = names.length === 1 ? `list_contains(r.tactics, ${str(names[0])})` : `list_has_any(r.tactics, [${names.map(str).join(', ')}])`;
    return `_zl_uid IN (${HIT_RULES} WHERE ${test})`;
  },
  technique: (t) => {
    exactOnly(t);
    const id = t.value.toUpperCase();
    if (!/^T\d{4}(\.\d{3})?$/.test(id)) throw new SearchError('A technique looks like T1234 or T1234.001', t.start, t.end);
    return `_zl_uid IN (SELECT h._zl_uid FROM hits h JOIN (SELECT rule_idx, unnest(techniques) AS t FROM rules) r ` +
      `ON r.rule_idx = h.rule_idx WHERE r.t = ${str(id)} OR r.t LIKE ${str(`${id}.%`)})`;
  },
  host: anyField(SHORTCUTS.find((s) => s.name === 'host')?.fields ?? [], 'host'),
  user: anyField(SHORTCUTS.find((s) => s.name === 'user')?.fields ?? [], 'user'),
};

// A shortcut listed for help but not compiled would fail only when typed.
for (const shortcut of SHORTCUTS) {
  if (!(shortcut.name in SHORTCUT_COMPILERS)) throw new Error(`shortcut ${shortcut.name} has no compiler`);
}
