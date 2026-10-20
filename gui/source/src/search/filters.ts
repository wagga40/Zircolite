/**
 * Column filters, kept as ordinary search terms. A table's filter row and
 * header menus write a column's filter into the search text and read it back
 * from there, so chips, links, Back and every view see one filter, whichever
 * control set it. A column owns the top-level terms that name only it; the
 * rest of the search is left exactly as typed.
 */
import { asciiLower } from '../engine/sql';
import { appendRaw, fieldToken, quoteValue, removeSpans } from './edit';
import { type Node, parse } from './parse';
import { findShortcut } from './shortcuts';

export type Bound = { op: '>' | '>=' | '<' | '<='; value: string };

export type ColumnFilter =
  | { op: 'contains' | 'equals' | 'prefix' | 'suffix' | 'pattern'; value: string; negate: boolean }
  | { op: 'compare'; bounds: Bound[]; negate: boolean }
  | { op: 'present'; negate: boolean }
  | { op: 'oneOf'; values: string[]; negate: boolean };

export type ColumnState =
  | { kind: 'none' }
  | { kind: 'invalid' }
  | { kind: 'filter'; filter: ColumnFilter; spans: [number, number][] }
  /** Terms on the column that no single filter describes, such as two contains: shown, cleared, never rewritten. */
  | { kind: 'custom'; text: string; spans: [number, number][] };

export interface ColumnOptions {
  /** The column is a search shortcut, such as level, rather than a log field. */
  shortcut?: boolean;
}

type Term = Extract<Node, { kind: 'term' }>;
type Shape = ColumnFilter extends infer F ? (F extends unknown ? Omit<F, 'negate'> : never) : never;

const LOWER = new Set(['>', '>=']);

/** A value the search reads back unchanged without quotes. */
function plain(value: string): boolean {
  return value !== '' && !/[\s"()*]/.test(value) && !/^[<>=]/.test(value);
}

function equalsTerm(name: string, value: string): string {
  return `${name}:${plain(value) ? value : quoteValue(value)}`;
}

/** The search terms of one column filter, in the grammar the search bar reads. */
export function toTerms(field: string, filter: ColumnFilter, options: ColumnOptions = {}): string {
  const name = options.shortcut ? field : fieldToken(field);
  const not = filter.negate ? '-' : '';
  switch (filter.op) {
    case 'contains':
      return `${not}${name}:${plain(filter.value) ? `*${filter.value}*` : `*${quoteValue(filter.value)}*`}`;
    case 'equals':
      return `${not}${equalsTerm(name, filter.value)}`;
    case 'prefix':
      return `${not}${name}:${plain(filter.value) ? filter.value : quoteValue(filter.value)}*`;
    case 'suffix':
      return `${not}${name}:*${plain(filter.value) ? filter.value : quoteValue(filter.value)}`;
    case 'pattern':
      return `${not}${name}:${filter.value}`;
    case 'present':
      return `${not}${name}:*`;
    case 'compare': {
      // A bound that is not one plain word is quoted, so the search refuses it rather than reading it as more terms.
      const terms = filter.bounds.map((bound) => `${name}:${bound.op}${plain(bound.value) ? bound.value : quoteValue(bound.value)}`).join(' ');
      return filter.negate && filter.bounds.length > 1 ? `-(${terms})` : `${not}${terms}`;
    }
    case 'oneOf':
      if (filter.values.length === 1) return `${not}${equalsTerm(name, filter.values[0])}`;
      return `${not}(${filter.values.map((value) => equalsTerm(name, value)).join(' OR ')})`;
  }
}

function refersTo(node: Node, key: string, options: ColumnOptions): node is Term {
  if (node.kind !== 'term' || node.field === null || asciiLower(node.field) !== key) return false;
  const shortcut = !node.fieldQuoted && findShortcut(node.field) !== undefined;
  return options.shortcut ? shortcut : !shortcut;
}

/** A top-level item that names only this column: a term, or a group of its terms, maybe negated. */
function owned(item: Node, key: string, options: ColumnOptions): boolean {
  const inner = item.kind === 'not' ? item.item : item;
  if (inner.kind === 'and' || inner.kind === 'or') return inner.items.every((child) => refersTo(child, key, options));
  return refersTo(inner, key, options);
}

function starred(t: Term): boolean {
  return t.starBefore === true || t.starAfter === true;
}

function termShape(t: Term): Shape | null {
  if (t.op !== '=') return starred(t) ? null : { op: 'compare', bounds: [{ op: t.op, value: t.value }] };
  const value = t.value;
  if (t.quoted) {
    if (t.starBefore && t.starAfter) return { op: 'contains', value };
    if (t.starAfter) return { op: 'prefix', value };
    if (t.starBefore) return { op: 'suffix', value };
    return { op: 'equals', value };
  }
  return wildcardShape(value);
}

/** An unquoted value: * alone means the field is present, and a * at either end only is an affix. */
function wildcardShape(value: string): Shape {
  if (value === '*') return { op: 'present' };
  if (!value.includes('*')) return { op: 'equals', value };
  if (/^\*[^*]+\*$/.test(value)) return { op: 'contains', value: value.slice(1, -1) };
  if (/^[^*]+\*$/.test(value)) return { op: 'prefix', value: value.slice(0, -1) };
  if (/^\*[^*]+$/.test(value)) return { op: 'suffix', value: value.slice(1) };
  return { op: 'pattern', value };
}

/** One lower and one upper bound, the only pair of terms a single column filter writes. */
function range(items: Node[]): Shape | null {
  if (items.length !== 2) return null;
  const bounds = items.map((item) => (item.kind === 'term' ? termShape(item) : null));
  if (!bounds.every((shape) => shape?.op === 'compare')) return null;
  const pair = bounds.flatMap((shape) => (shape as Extract<Shape, { op: 'compare' }>).bounds);
  if (LOWER.has(pair[0].op) === LOWER.has(pair[1].op)) return null;
  return { op: 'compare', bounds: pair };
}

function shapeOf(items: Node[]): ColumnFilter | null {
  const pair = range(items);
  if (pair) return { ...pair, negate: false } as ColumnFilter;
  if (items.length !== 1) return null;
  const item = items[0];
  const negate = item.kind === 'not';
  const inner = item.kind === 'not' ? item.item : item;
  let shape: Shape | null = null;
  if (inner.kind === 'term') shape = termShape(inner);
  else if (inner.kind === 'and') shape = range(inner.items);
  else if (inner.kind === 'or') {
    const values = inner.items.map((child) => (child.kind === 'term' ? termShape(child) : null));
    if (values.every((value) => value?.op === 'equals')) {
      shape = { op: 'oneOf', values: values.map((value) => (value as { value: string }).value) };
    }
  }
  return shape === null ? null : ({ ...shape, negate } as ColumnFilter);
}

/** What the search says about one column. */
export function columnState(query: string, field: string, options: ColumnOptions = {}): ColumnState {
  let tree: Node | null;
  try {
    tree = parse(query);
  } catch {
    return { kind: 'invalid' };
  }
  if (tree === null) return { kind: 'none' };
  const key = asciiLower(field);
  const items = (tree.kind === 'and' ? tree.items : [tree]).filter((item) => owned(item, key, options));
  if (items.length === 0) return { kind: 'none' };
  const spans = items.map((item): [number, number] => [item.start, item.end]);
  const filter = shapeOf(items);
  if (filter) return { kind: 'filter', filter, spans };
  return { kind: 'custom', text: spans.map(([start, end]) => query.slice(start, end)).join(' '), spans };
}

/**
 * The search with one column's filter replaced, or removed when the filter
 * is null. Its terms take the place of the column's first term; everything
 * else stays as typed.
 */
export function setColumnFilter(query: string, field: string, filter: ColumnFilter | null, options: ColumnOptions = {}): string {
  const state = columnState(query, field, options);
  if (state.kind === 'invalid') throw new Error('The search does not parse, so a column filter cannot change it');
  const text = filter === null ? '' : toTerms(field, filter, options);
  const spans = state.kind === 'none' ? [] : state.spans;
  if (spans.length === 0) return text ? appendRaw(query, text) : query;
  if (!text) return removeSpans(query, spans);
  const [first, ...rest] = spans;
  const kept = removeSpans(query, rest);
  return `${kept.slice(0, first[0])}${text}${kept.slice(first[1])}`;
}

export function withoutColumn(query: string, field: string, options: ColumnOptions = {}): string {
  return setColumnFilter(query, field, null, options);
}

/** Why a filter cell's text cannot be applied. */
export class CellError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CellError';
  }
}

const NUMBER = /^-?\d+(\.\d+)?$/;
const WHOLE = /^-?\d+$/;
const BOUND = /^(>=|<=|>|<)\s*([^\s<>=]+)\s*/;

function unquote(text: string): { value: string; rest: string } {
  let value = '';
  let i = 1;
  while (i < text.length && text[i] !== '"') {
    if (text[i] === '\\' && (text[i + 1] === '"' || text[i + 1] === '\\')) {
      value += text[i + 1];
      i += 2;
    } else {
      value += text[i];
      i++;
    }
  }
  if (i >= text.length) throw new CellError('This quote is never closed');
  return { value, rest: text.slice(i + 1) };
}

function bounds(text: string): Bound[] {
  const found: Bound[] = [];
  let rest = text;
  while (rest) {
    const match = BOUND.exec(rest);
    if (!match) throw new CellError('A comparison is an operator and a number, as in >=4600 or >=1 <10');
    found.push({ op: match[1] as Bound['op'], value: match[2] });
    rest = rest.slice(match[0].length);
  }
  if (found.length > 2 || (found.length === 2 && LOWER.has(found[0].op) === LOWER.has(found[1].op))) {
    throw new CellError('A range takes one lower and one upper bound, as in >=1 <10');
  }
  return found;
}

/**
 * The filter a cell's text asks for, or null for an empty cell. Plain text
 * is contained in the value and a whole number matches exactly; = matches
 * exactly, * is a wildcard, quotes keep text literal, > >= < <= compare and
 * ! leaves matches out.
 */
export function parseCell(input: string, numeric: boolean): ColumnFilter | null {
  let text = input.trim();
  if (!text) return null;
  const negate = text.startsWith('!');
  if (negate) {
    text = text.slice(1).trimStart();
    if (!text) throw new CellError('Nothing to leave out after !');
  }
  if (text === '*') return { op: 'present', negate };
  if (text.startsWith('=')) {
    const rest = text.slice(1).trim();
    if (!rest) throw new CellError('Nothing to match after =');
    if (rest.startsWith('"')) {
      const quoted = unquote(rest);
      if (quoted.rest.trim()) throw new CellError('Only the quoted value can follow =');
      return { op: 'equals', value: quoted.value, negate };
    }
    return { op: 'equals', value: rest, negate };
  }
  if (/^[<>]/.test(text)) return { op: 'compare', bounds: bounds(text), negate };
  if (text.startsWith('"') || text.startsWith('*"')) {
    const before = text.startsWith('*');
    const quoted = unquote(before ? text.slice(1) : text);
    if (quoted.rest !== '' && quoted.rest !== '*') throw new CellError('After the closing quote, only a * may follow');
    const after = quoted.rest === '*';
    const op = before === after ? 'contains' : after ? 'prefix' : 'suffix';
    return { op, value: quoted.value, negate };
  }
  if (text.includes('*')) {
    if (/\s/.test(text)) throw new CellError('A pattern with * cannot hold spaces; quote the words instead, as in "net user"*');
    if (/["()]/.test(text)) throw new CellError('A pattern with * cannot hold quotes or parentheses');
    return { ...wildcardShape(text), negate } as ColumnFilter;
  }
  // A whole number alone is an id, a port, a logon type: exact, even where the package stores the column as text,
  // as it does EventID when its sources mixed numbers and text. Contained digits are written *4624*.
  if (WHOLE.test(text) || (numeric && NUMBER.test(text))) return { op: 'equals', value: text, negate };
  return { op: 'contains', value: text, negate };
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value === null || typeof value !== 'object') return value;
  const object = value as Record<string, unknown>;
  return Object.fromEntries(Object.keys(object).sort().map((key) => [key, canonical(object[key])]));
}

function same(a: ColumnFilter | null, b: ColumnFilter): boolean {
  return JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
}

function readsBack(text: string, filter: ColumnFilter, numeric: boolean): boolean {
  try {
    return same(parseCell(text, numeric), filter);
  } catch {
    return false;
  }
}

/** The text a cell shows for a column's state: what parseCell reads back as the same filter. */
export function cellText(state: ColumnState, numeric: boolean): string {
  if (state.kind === 'none' || state.kind === 'invalid') return '';
  if (state.kind === 'custom') return state.text;
  const filter = state.filter;
  const not = filter.negate ? '!' : '';
  if (filter.op === 'oneOf') return `${filter.negate ? 'not ' : ''}${filter.values.length} values`;
  const candidates: string[] = [];
  switch (filter.op) {
    case 'contains':
      candidates.push(filter.value, `*${filter.value}*`, quoteValue(filter.value));
      break;
    case 'equals':
      candidates.push(`=${filter.value}`, `=${quoteValue(filter.value)}`);
      break;
    case 'prefix':
      candidates.push(`${filter.value}*`, `${quoteValue(filter.value)}*`);
      break;
    case 'suffix':
      candidates.push(`*${filter.value}`, `*${quoteValue(filter.value)}`);
      break;
    case 'pattern':
      candidates.push(filter.value);
      break;
    case 'present':
      candidates.push('*');
      break;
    case 'compare':
      candidates.push(filter.bounds.map((bound) => `${bound.op}${bound.value}`).join(' '));
      break;
  }
  const text = candidates.map((candidate) => `${not}${candidate}`).find((candidate) => readsBack(candidate, filter, numeric));
  return text ?? candidates[candidates.length - 1];
}
