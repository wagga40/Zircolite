import type { Schema } from '../engine/schema';
import { asciiLower } from '../engine/sql';
import { type Node, parse } from './parse';
import { findShortcut, SHORTCUTS } from './shortcuts';
import { tokenize } from './tokens';

export interface Chip {
  label: string;
  negated: boolean;
  start: number;
  end: number;
}

/** The field terms of a query that can be removed one at a time. */
export function chips(input: string): Chip[] {
  let tree: Node | null;
  try {
    tree = parse(input);
  } catch {
    return [];
  }
  if (tree === null) return [];
  const items = tree.kind === 'and' ? tree.items : [tree];
  return items.flatMap((item) => {
    const negated = item.kind === 'not';
    const inner = item.kind === 'not' ? item.item : item;
    if (inner.kind !== 'term' || inner.field === null) return [];
    const op = inner.op === '=' ? '' : inner.op;
    return [{ label: `${inner.field}: ${op}${inner.value}`, negated, start: item.start, end: item.end }];
  });
}

/** Cut one span out of the query, tidying only the spaces around the cut. */
export function removeSpan(input: string, start: number, end: number): string {
  const before = input.slice(0, start).replace(/\s+$/, '');
  const after = input.slice(end).replace(/^\s+/, '');
  return before && after ? `${before} ${after}` : `${before}${after}`;
}

export function quoteValue(value: string): string {
  return `"${value.replace(/["\\]/g, (c) => `\\${c}`)}"`;
}

const PLAIN_FIELD = /^[A-Za-z0-9_.@-]+$/;

/** The query plus one exact field term: what the sidebar and the event view add. */
export function appendTerm(input: string, field: string, value: string, negate: boolean): string {
  const name = PLAIN_FIELD.test(field) && !findShortcut(field) ? field : quoteValue(field);
  return appendRaw(input, `${negate ? '-' : ''}${name}:${quoteValue(value)}`);
}

/** The query plus a term that is already valid syntax, such as a shortcut. */
export function appendRaw(input: string, term: string): string {
  const base = input.trim();
  if (!base) return term;
  let tree: Node | null = null;
  try {
    tree = parse(base);
  } catch {
    // The user's text is kept as typed; the search bar reports its error.
  }
  // Appended to a top-level OR, the term would bind to its last branch only.
  return `${tree?.kind === 'or' ? `(${base})` : base} ${term}`;
}

export type Completion =
  | { kind: 'field'; prefix: string; start: number; end: number }
  | { kind: 'value'; field: string; prefix: string; start: number; end: number };

export function completionAt(input: string, caret: number): Completion | null {
  if (caret === 0 || /\s/.test(input[caret - 1])) return null;
  let tokens;
  try {
    tokens = tokenize(input.slice(0, caret));
  } catch {
    return null;
  }
  const last = tokens[tokens.length - 1];
  if (!last || last.end !== caret) return null;
  const fieldBefore = (index: number) => {
    const token = tokens[index];
    return token && (token.kind === 'word' || token.kind === 'quoted') ? token.text : null;
  };
  if (last.kind === 'colon') {
    const field = fieldBefore(tokens.length - 2);
    return field === null ? null : { kind: 'value', field, prefix: '', start: caret, end: caret };
  }
  if (last.kind !== 'word') return null;
  const previous = tokens[tokens.length - 2];
  if (previous?.kind === 'colon' || previous?.kind === 'op') {
    const colonAt = previous.kind === 'op' ? tokens.length - 3 : tokens.length - 2;
    const field = fieldBefore(colonAt - 1);
    return field === null ? null : { kind: 'value', field, prefix: last.text, start: last.start, end: last.end };
  }
  return { kind: 'field', prefix: last.text, start: last.start, end: last.end };
}

export function fieldSuggestions(prefix: string, schema: Schema, limit = 8): string[] {
  const wanted = asciiLower(prefix);
  const names = [...SHORTCUTS.map((s) => s.name), ...schema.fields.map((f) => f.name)];
  return names.filter((name) => {
    const key = asciiLower(name);
    return key.startsWith(wanted) && key !== wanted;
  }).slice(0, limit);
}
